#!/usr/bin/env python3
"""Wazuh -> n8n integration.

Wazuh's integrator daemon runs this script for every alert that matches the
<integration> block in ossec.conf, and passes:

    argv[1]  path to a temp file with the alert as JSON
    argv[2]  the <api_key> value (used here as the shared webhook secret)
    argv[3]  the <hook_url> value (the n8n webhook URL)

The script:
  1. Drops repeats of the same rule + agent + source IP within a cooldown
     window (edge deduplication, safe for bursts thanks to a file lock).
  2. POSTs the alert JSON to n8n with the secret in the X-Wazuh-Token header,
     adding how many repeats were dropped since the last forwarded copy.

It uses only the Python standard library, so it runs on the Python that ships
with Wazuh. Settings are read from custom-n8n.conf next to this script.
"""
import fcntl
import json
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.environ.get("WAZUH_N8N_LOG", "/var/ossec/logs/integrations.log")
STATE_FILE = os.environ.get("WAZUH_N8N_STATE", "/var/ossec/logs/custom-n8n-state.json")
CONF_FILE = os.environ.get("WAZUH_N8N_CONF", os.path.join(HERE, "custom-n8n.conf"))
DEFAULT_WINDOW_SECONDS = 600
TIMEOUT_SECONDS = 10
RETRIES = 3
DAY_SECONDS = 86400


def log(message):
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as fh:
            fh.write(f"{stamp} custom-n8n: {message}\n")
    except OSError:
        pass


def parse_args(argv):
    """Return (alert_file, secret, hook_url) and tolerate missing/extra args."""
    args = argv[1:]
    if not args:
        return None, "", None
    alert_file = args[0]
    hook_url = next((a for a in args[1:] if a.startswith(("http://", "https://"))), None)
    secret = ""
    if len(args) > 1 and not args[1].startswith(("http://", "https://")) and args[1] != "debug":
        secret = args[1]
    return alert_file, secret, hook_url


def window_seconds():
    """Read DEDUP_WINDOW_SECONDS from custom-n8n.conf (KEY=VALUE lines)."""
    try:
        with open(CONF_FILE, encoding="utf-8") as fh:
            for line in fh:
                key, _, value = line.partition("=")
                if key.strip() == "DEDUP_WINDOW_SECONDS":
                    return max(0, int(value.strip()))
    except (OSError, ValueError):
        pass
    return DEFAULT_WINDOW_SECONDS


def fingerprint(alert):
    rule = alert.get("rule") or {}
    agent = alert.get("agent") or {}
    data = alert.get("data") or {}
    return "|".join(
        str(x) for x in (rule.get("id", "?"), agent.get("id") or agent.get("name") or "-", data.get("srcip") or "-")
    )


def _update_state(change):
    """Run change(state) under an exclusive file lock and save the result."""
    with open(STATE_FILE + ".lock", "a", encoding="utf-8") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            with open(STATE_FILE, encoding="utf-8") as fh:
                state = json.load(fh)
        except (OSError, json.JSONDecodeError):
            state = {}
        result = change(state)
        tmp = f"{STATE_FILE}.{os.getpid()}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(state, fh)
        os.replace(tmp, STATE_FILE)
        return result


def dedup_check(fp, window, now=None):
    """Return (forward, suppressed_before). Repeats inside the window are counted, not sent."""
    if window <= 0:
        return True, 0
    now = time.time() if now is None else now

    def change(state):
        for key in list(state):
            entry = state[key]
            age = now - entry.get("last", 0)
            if age > DAY_SECONDS or (entry.get("suppressed", 0) == 0 and age > 2 * window):
                del state[key]
        entry = state.get(fp)
        if entry and now - entry["last"] < window:
            entry["suppressed"] = entry.get("suppressed", 0) + 1
            return False, 0
        state[fp] = {"last": now, "suppressed": 0}
        return True, entry.get("suppressed", 0) if entry else 0

    return _update_state(change)


def dedup_forget(fp):
    """Undo a forward that failed, so the next copy of the alert is tried again."""
    _update_state(lambda state: state.pop(fp, None))


def post(hook_url, payload, secret):
    headers = {"Content-Type": "application/json", "User-Agent": "wazuh-n8n-integration/1.1"}
    if secret:
        headers["X-Wazuh-Token"] = secret
    request = urllib.request.Request(hook_url, data=payload, headers=headers, method="POST")
    with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
        return response.status


def send(hook_url, payload, secret, rule_id):
    for attempt in range(1, RETRIES + 1):
        try:
            status = post(hook_url, payload, secret)
            if 200 <= status < 300:
                return True
            log(f"rule {rule_id}: n8n answered HTTP {status} (attempt {attempt})")
        except urllib.error.HTTPError as exc:
            log(f"rule {rule_id}: n8n answered HTTP {exc.code} (attempt {attempt})")
            if exc.code == 404:
                log("hint: is the workflow published/active in n8n, and is the webhook path right?")
                return False
        except (urllib.error.URLError, OSError) as exc:
            log(f"rule {rule_id}: cannot reach {hook_url}: {exc} (attempt {attempt})")
        time.sleep(attempt)
    return False


def main(argv):
    alert_file, secret, hook_url = parse_args(argv)
    if not alert_file or not hook_url:
        log("usage: custom-n8n <alert_file> <secret> <hook_url>")
        return 2

    try:
        with open(alert_file, encoding="utf-8") as fh:
            alert = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        log(f"cannot read alert file {alert_file}: {exc}")
        return 1

    fp = fingerprint(alert)
    try:
        forward, suppressed = dedup_check(fp, window_seconds())
    except OSError as exc:  # never lose an alert because of the dedup state file
        log(f"dedup state unavailable ({exc}); forwarding without dedup")
        forward, suppressed = True, 0
    if not forward:
        return 0

    alert["wazuh_n8n"] = {"duplicates_suppressed": suppressed}
    payload = json.dumps(alert).encode("utf-8")
    if send(hook_url, payload, secret, alert.get("rule", {}).get("id", "?")):
        return 0
    try:
        dedup_forget(fp)
    except OSError:
        pass
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
