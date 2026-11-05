#!/usr/bin/env python3
"""Wazuh -> n8n integration.

Wazuh's integrator daemon runs this script for every alert that matches the
<integration> block in ossec.conf, and passes:

    argv[1]  path to a temp file with the alert as JSON
    argv[2]  the <api_key> value (used here as the shared webhook secret)
    argv[3]  the <hook_url> value (the n8n webhook URL)

The script:
  1. Deduplicates (see "dedup contract" below; the n8n workflow uses the same one).
  2. POSTs the alert JSON to n8n with the secret in the X-Wazuh-Token header,
     adding how many similar alerts were dropped since the last forwarded one.
  3. If sending fails, saves the alert in a spool folder instead of losing it.
     Spooled alerts are re-sent on the next run (oldest first), or with --flush.
     Alerts that still fail after MAX_SPOOL_ATTEMPTS runs or MAX_SPOOL_AGE_SECONDS
     are moved to spool/failed/ and logged as ERROR, so a person can act on them.

Dedup contract:
  event key  manager + agent + alert id. The same alert again is a re-delivery:
             dropped and NOT counted as a new repeat.
  group key  manager + agent + rule + level + a subject that depends on the alert
             family: file path + event for FIM, IP + user + logon type for Windows,
             source IP otherwise. Without a subject there is no group key, and the
             alert is never grouped with others (better a duplicate than a lost alert).

It uses only the Python standard library, so it runs on the Python that ships
with Wazuh. Settings are read from custom-n8n.conf next to this script.

Manual flush (for example from cron, when no new alerts arrive):
    sudo /var/ossec/integrations/custom-n8n --flush
reads hook_url and api_key from the wazuh-ai-triage block in ossec.conf.
"""
import fcntl
import ipaddress
import json
import os
import random
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.environ.get("WAZUH_N8N_LOG", "/var/ossec/logs/integrations.log")
STATE_FILE = os.environ.get("WAZUH_N8N_STATE", "/var/ossec/logs/custom-n8n-state.json")
SPOOL_DIR = os.environ.get("WAZUH_N8N_SPOOL", "/var/ossec/logs/custom-n8n-spool")
CONF_FILE = os.environ.get("WAZUH_N8N_CONF", os.path.join(HERE, "custom-n8n.conf"))
OSSEC_CONF = os.environ.get("WAZUH_N8N_OSSEC_CONF", os.path.join(HERE, "..", "etc", "ossec.conf"))
DEFAULT_WINDOW_SECONDS = 600
TIMEOUT_SECONDS = 10
RETRIES = 3
DAY_SECONDS = 86400
MAX_SPOOL_FILES = 1000
MAX_SPOOL_ATTEMPTS = 50
SPOOL_RETRY_BASE_SECONDS = 30
SPOOL_RETRY_MAX_SECONDS = 3600
MAX_SPOOL_AGE_SECONDS = 3 * DAY_SECONDS
FLUSH_BATCH = 50
# Errors that a retry in a few seconds will not fix (wrong secret, wrong URL, bad data).
PERMANENT_HTTP = {400, 401, 403, 404, 405, 413, 422}
CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


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


# ---------- dedup keys (same contract as the n8n "Sanitize & Validate" node) ----------


def _js_string(value):
    """str() that matches JavaScript's String() for JSON values."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value)


def key_part(value):
    return CONTROL_CHARS.sub("", _js_string(value)).strip()[:256]


def canonical_ip(value):
    """Canonical text form of an IP address, or '' if it is not one."""
    text = CONTROL_CHARS.sub("", _js_string(value))[:64].strip()
    if not text or "%" in text or "/" in text:
        return ""
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return ""
    if ip.version == 4:
        return str(ip)
    # Compress by hand: newer Pythons print ::ffff:1.2.3.4 for IPv4-mapped
    # addresses, older ones ::ffff:102:304. Always use the pure-hex form.
    value = int(ip)
    groups = [format((value >> (112 - 16 * k)) & 0xFFFF, "x") for k in range(8)]
    best_start, best_len, i = -1, 0, 0
    while i < 8:
        if groups[i] != "0":
            i += 1
            continue
        j = i
        while j < 8 and groups[j] == "0":
            j += 1
        if j - i > best_len:
            best_start, best_len = i, j - i
        i = j
    if best_len < 2:
        return ":".join(groups)
    return ":".join(groups[:best_start]) + "::" + ":".join(groups[best_start + best_len :])


def dedup_keys(alert):
    """Return (event_key, group_key). Either can be None."""
    rule = alert.get("rule") or {}
    agent = alert.get("agent") or {}
    data = alert.get("data") or {}
    manager = key_part((alert.get("manager") or {}).get("name") or "-") or "-"
    agent_key = key_part(agent.get("id") or agent.get("name") or "-") or "-"
    alert_id = key_part(alert.get("id"))
    event_key = "|".join(("evt", manager, agent_key, alert_id)) if alert_id else None

    sys_check = alert.get("syscheck") or {}
    win = (data.get("win") or {}).get("eventdata") if isinstance(data.get("win"), dict) else None
    subject = ""
    if isinstance(sys_check, dict) and key_part(sys_check.get("path")):
        subject = f"fim:{key_part(sys_check.get('path'))}:{key_part(sys_check.get('event'))}"
    elif win is not None:
        win = win if isinstance(win, dict) else {}
        ip = canonical_ip(win.get("ipAddress")) or canonical_ip(data.get("srcip")) or canonical_ip(data.get("src_ip"))
        user = key_part(win.get("targetUserName")).lower()
        if ip or user:
            subject = f"win:{ip}:{user}:{key_part(win.get('logonType'))}"
    else:
        ip = canonical_ip(data.get("srcip")) or canonical_ip(data.get("src_ip"))
        if ip:
            subject = f"ip:{ip}"
    group_key = None
    if subject:
        group_key = "|".join(
            ("grp", manager, agent_key, key_part(rule.get("id")) or "?", key_part(rule.get("level")) or "?", subject)
        )
    return event_key, group_key


# ---------- state ----------


def _update_state(change):
    """Run change(state) under an exclusive file lock and save the result."""
    with open(STATE_FILE + ".lock", "a", encoding="utf-8") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            with open(STATE_FILE, encoding="utf-8") as fh:
                state = json.load(fh)
        except (OSError, json.JSONDecodeError):
            state = {}
        if not isinstance(state.get("groups"), dict) or not isinstance(state.get("events"), dict):
            state = {"groups": {}, "events": {}}  # first run, or the old format
        result = change(state)
        tmp = f"{STATE_FILE}.{os.getpid()}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(state, fh)
        os.replace(tmp, STATE_FILE)
        return result


def dedup_check(event_key, group_key, window, now=None):
    """Return (forward, suppressed_before).

    A re-delivered event is dropped without counting. A similar alert inside the
    window is dropped and counted; the count is handed to the next forwarded alert
    of the same group.
    """
    now = time.time() if now is None else now

    def change(state):
        groups, events = state["groups"], state["events"]
        for key in list(groups):
            entry = groups[key]
            age = now - entry.get("last", 0)
            if age > DAY_SECONDS or (entry.get("suppressed", 0) == 0 and age > 2 * max(window, 30)):
                del groups[key]
        for key in list(events):
            if now - events[key] > DAY_SECONDS:
                del events[key]

        if event_key:
            if event_key in events:
                return False, 0
            events[event_key] = now
        if not group_key or window <= 0:
            return True, 0
        entry = groups.get(group_key)
        if entry and now - entry["last"] < window:
            entry["suppressed"] = entry.get("suppressed", 0) + 1
            return False, 0
        groups[group_key] = {"last": now, "suppressed": 0}
        return True, entry.get("suppressed", 0) if entry else 0

    return _update_state(change)


# ---------- sending ----------


class PermanentError(Exception):
    """n8n refused the alert in a way that retrying now will not fix."""


def post(hook_url, payload, secret):
    headers = {"Content-Type": "application/json", "User-Agent": "wazuh-n8n-integration/2.0"}
    if secret:
        headers["X-Wazuh-Token"] = secret
    request = urllib.request.Request(hook_url, data=payload, headers=headers, method="POST")
    with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
        return response.status


def backoff(attempt):
    """Exponential backoff with jitter: about 1s, 2s, 4s ..."""
    return (2 ** (attempt - 1)) * (0.5 + random.random())


def send(hook_url, payload, secret, label, retries=RETRIES):
    """Return True when n8n accepted the alert (HTTP 2xx).

    Retries network errors, HTTP 429 and 5xx. Raises PermanentError for answers
    that need a config fix (wrong secret, unknown webhook, rejected data).
    """
    for attempt in range(1, retries + 1):
        try:
            status = post(hook_url, payload, secret)
            if 200 <= status < 300:
                return True
            log(f"{label}: n8n answered HTTP {status} (attempt {attempt})")
        except urllib.error.HTTPError as exc:
            log(f"{label}: n8n answered HTTP {exc.code} (attempt {attempt})")
            if exc.code in PERMANENT_HTTP:
                hints = {
                    401: "the secret does not match WEBHOOK_SECRET in n8n's .env",
                    404: "is the workflow published/active in n8n, and is the webhook path right?",
                    503: "WEBHOOK_SECRET is empty in n8n's .env",
                }
                if exc.code in hints:
                    log(f"hint: {hints[exc.code]}")
                raise PermanentError(f"HTTP {exc.code}") from exc
            if exc.code == 503:
                log("hint: n8n may be starting, or WEBHOOK_SECRET is empty in n8n's .env")
        except (urllib.error.URLError, OSError) as exc:
            log(f"{label}: cannot reach {hook_url}: {exc} (attempt {attempt})")
        if attempt < retries:
            time.sleep(backoff(attempt))
    return False


# ---------- spool (alerts that could not be sent yet) ----------


def _spool_name(alert, now):
    alert_id = re.sub(r"[^A-Za-z0-9._-]", "_", str(alert.get("id") or "noid"))[:80]
    return f"{int(now * 1000):015d}-{os.getpid()}-{alert_id}.json"


def spool_put(alert, reason, now=None):
    """Save an alert that could not be sent. Returns the file path or None."""
    now = time.time() if now is None else now
    try:
        os.makedirs(os.path.join(SPOOL_DIR, "failed"), exist_ok=True)
        pending = [n for n in os.listdir(SPOOL_DIR) if n.endswith(".json")]
        folder = SPOOL_DIR
        if len(pending) >= MAX_SPOOL_FILES:
            folder = os.path.join(SPOOL_DIR, "failed")
            log(f"ERROR spool is full ({MAX_SPOOL_FILES} alerts); alert {alert.get('id')} goes straight to {folder}")
        entry = {
            "alert": alert,
            "attempts": 1,
            "first_failed_at": now,
            "next_try_at": now + SPOOL_RETRY_BASE_SECONDS,
            "last_error": reason,
        }
        path = os.path.join(folder, _spool_name(alert, now))
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(entry, fh)
        os.replace(tmp, path)
        return path
    except OSError as exc:
        log(f"ERROR cannot spool alert {alert.get('id')}: {exc}; it is lost for this pipeline (still in Wazuh)")
        return None


def _give_up(path, entry, why):
    target = os.path.join(SPOOL_DIR, "failed", os.path.basename(path))
    entry["gave_up_because"] = why
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(entry, fh)
    os.replace(path, target)
    log(f"ERROR alert {entry['alert'].get('id')} was not delivered ({why}); kept in {target}")


def spool_flush(hook_url, secret, now=None, batch=FLUSH_BATCH, force=False):
    """Re-send spooled alerts, oldest first. Returns (sent, still_pending).

    Only one process flushes at a time; others skip. Stops at the first failure,
    because n8n is most likely still down. Without force, an alert is retried only
    when its backoff time has passed (30s, 1m, 2m ... up to 1h between tries), so
    a burst of alerts during an outage does not use up all attempts at once.
    """
    now = time.time() if now is None else now
    if not os.path.isdir(SPOOL_DIR):
        return 0, 0
    sent = 0
    with open(os.path.join(SPOOL_DIR, ".flush.lock"), "a", encoding="utf-8") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            return 0, -1  # someone else is flushing
        names = sorted(n for n in os.listdir(SPOOL_DIR) if n.endswith(".json"))
        for name in names[:batch]:
            path = os.path.join(SPOOL_DIR, name)
            try:
                with open(path, encoding="utf-8") as fh:
                    entry = json.load(fh)
                alert = entry["alert"]
            except (OSError, ValueError, KeyError, TypeError):
                os.makedirs(os.path.join(SPOOL_DIR, "failed"), exist_ok=True)
                os.replace(path, os.path.join(SPOOL_DIR, "failed", name))
                log(f"ERROR unreadable spool file moved to failed/: {name}")
                continue
            if not force and entry.get("next_try_at", 0) > now:
                break
            alert.setdefault("wazuh_n8n", {})["replayed"] = True
            payload = json.dumps(alert).encode("utf-8")
            label = f"replay of alert {alert.get('id')}"
            error = ""
            try:
                ok = send(hook_url, payload, secret, label, retries=1)
                error = "" if ok else "n8n unreachable or busy"
            except PermanentError as exc:
                ok, error = False, str(exc)
            if ok:
                os.unlink(path)
                sent += 1
                log(f"{label}: delivered after {entry.get('attempts', 1)} failed attempt(s)")
                continue
            entry["attempts"] = entry.get("attempts", 1) + 1
            entry["last_error"] = error
            if entry["attempts"] > MAX_SPOOL_ATTEMPTS:
                _give_up(path, entry, f"{entry['attempts'] - 1} attempts, last error: {error}")
            elif now - entry.get("first_failed_at", now) > MAX_SPOOL_AGE_SECONDS:
                _give_up(path, entry, f"older than {MAX_SPOOL_AGE_SECONDS // 3600} hours, last error: {error}")
            else:
                delay = SPOOL_RETRY_BASE_SECONDS * 2 ** min(entry["attempts"] - 1, 10)
                entry["next_try_at"] = now + min(SPOOL_RETRY_MAX_SECONDS, delay)
                with open(path + ".tmp", "w", encoding="utf-8") as fh:
                    json.dump(entry, fh)
                os.replace(path + ".tmp", path)
            break
        pending = len([n for n in os.listdir(SPOOL_DIR) if n.endswith(".json")])
    return sent, pending


def read_ossec_conf():
    """Return (hook_url, secret) from the wazuh-ai-triage block in ossec.conf."""
    try:
        with open(OSSEC_CONF, encoding="utf-8") as fh:
            text = fh.read()
    except OSError:
        return None, ""
    block = re.search(r"<!-- wazuh-ai-triage:start -->(.*?)<!-- wazuh-ai-triage:end -->", text, re.S)
    if not block:
        return None, ""
    url = re.search(r"<hook_url>\s*(.*?)\s*</hook_url>", block.group(1), re.S)
    key = re.search(r"<api_key>\s*(.*?)\s*</api_key>", block.group(1), re.S)
    return (url.group(1) if url else None), (key.group(1) if key else "")


def main(argv):
    if argv[1:2] == ["--flush"]:
        hook_url, secret = read_ossec_conf()
        if not hook_url:
            print(f"no wazuh-ai-triage block with a hook_url in {OSSEC_CONF}", file=sys.stderr)
            return 2
        sent, pending = spool_flush(hook_url, secret, batch=MAX_SPOOL_FILES, force=True)
        print(f"re-sent {sent} alert(s), {max(pending, 0)} still waiting")
        return 0 if pending <= 0 else 1

    alert_file, secret, hook_url = parse_args(argv)
    if not alert_file or not hook_url:
        log("usage: custom-n8n <alert_file> <secret> <hook_url>")
        return 2

    try:
        with open(alert_file, encoding="utf-8") as fh:
            alert = json.load(fh)
        if not isinstance(alert, dict):
            raise ValueError("alert is not a JSON object")
    except (OSError, ValueError) as exc:
        log(f"cannot read alert file {alert_file}: {exc}")
        return 1

    event_key, group_key = dedup_keys(alert)
    try:
        forward, suppressed = dedup_check(event_key, group_key, window_seconds())
    except OSError as exc:  # never lose an alert because of the dedup state file
        log(f"dedup state unavailable ({exc}); forwarding without dedup")
        forward, suppressed = True, 0

    code = 0
    delivered_now = False
    if forward:
        alert["wazuh_n8n"] = {"duplicates_suppressed": suppressed}
        payload = json.dumps(alert).encode("utf-8")
        label = f"rule {(alert.get('rule') or {}).get('id', '?')} alert {alert.get('id')}"
        try:
            ok = send(hook_url, payload, secret, label)
            reason = "" if ok else "n8n unreachable or busy"
        except PermanentError as exc:
            ok, reason = False, str(exc)
        delivered_now = ok
        if not ok:
            where = spool_put(alert, reason)
            if where:
                log(f"{label}: not delivered ({reason}); saved to the spool for a later retry")
            code = 1
    # Try to deliver what earlier runs could not. If n8n just took an alert, it is up,
    # so the backoff wait is skipped.
    if code == 0:
        try:
            spool_flush(hook_url, secret, force=delivered_now)
        except OSError as exc:
            log(f"spool flush failed: {exc}")
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv))
