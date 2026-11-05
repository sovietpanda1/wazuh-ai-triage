#!/usr/bin/env python3
"""Send sample Wazuh alerts to the n8n webhook, to test the workflow.

Examples:
  python3 scripts/send_alert.py                                   # SSH brute force sample
  python3 scripts/send_alert.py samples/alerts/02-web-sql-injection.json
  python3 scripts/send_alert.py --all --url http://192.168.1.20:5678/webhook/wazuh-alert

The secret comes from --secret, the WEBHOOK_SECRET environment variable, or .env.

Each send gets a fresh alert id, so n8n sees a new event (the same id twice is a
re-delivery and is always dropped). The same sample sent again within
DEDUP_WINDOW_SECONDS is still grouped with the first one on purpose; use
--keep-id to send the file exactly as it is.

HTTP 202 means n8n accepted the alert for analysis. It does not mean the analysis
finished or that Telegram got a message: check n8n > Executions for that.
"""
import argparse
import json
import os
import pathlib
import sys
import time
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
DEFAULT_FILE = ROOT / "samples" / "alerts" / "01-ssh-bruteforce.json"


def secret_from_env_file():
    env_file = ROOT / ".env"
    if not env_file.exists():
        return ""
    for line in env_file.read_text(encoding="utf-8").splitlines():
        key, _, value = line.partition("=")
        if key.strip() == "WEBHOOK_SECRET":
            return value.strip()
    return ""


HINTS = {
    401: "the secret does not match WEBHOOK_SECRET in n8n's .env",
    404: "is the workflow imported and published, and is the URL right?",
    503: "WEBHOOK_SECRET is empty in n8n's .env (the webhook refuses everything until it is set)",
}


def send(path, url, secret, keep_id=False):
    headers = {"Content-Type": "application/json"}
    if secret:
        headers["X-Wazuh-Token"] = secret
    data = path.read_bytes()
    if not keep_id:
        alert = json.loads(data)
        alert["id"] = f"test-{time.time_ns()}"
        data = json.dumps(alert).encode("utf-8")
    request = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            note = "accepted for analysis" if response.status == 202 else "answered"
            print(f"OK   {path.name} -> HTTP {response.status} ({note})")
            return True
    except urllib.error.HTTPError as exc:
        print(f"FAIL {path.name} -> HTTP {exc.code}: {exc.read().decode(errors='replace')[:200]}")
        if exc.code in HINTS:
            print(f"     hint: {HINTS[exc.code]}")
    except urllib.error.URLError as exc:
        print(f"FAIL {path.name} -> {exc.reason}")
    return False


def main():
    parser = argparse.ArgumentParser(description="Send sample Wazuh alerts to n8n.")
    parser.add_argument("files", nargs="*", type=pathlib.Path, help="alert JSON files")
    parser.add_argument("--all", action="store_true", help="send every file in samples/alerts")
    parser.add_argument("--url", default="http://localhost:5678/webhook/wazuh-alert")
    parser.add_argument("--secret", default=os.environ.get("WEBHOOK_SECRET") or secret_from_env_file())
    parser.add_argument("--keep-id", action="store_true", help="send the alert id from the file unchanged")
    args = parser.parse_args()

    files = sorted((ROOT / "samples" / "alerts").glob("*.json")) if args.all else (args.files or [DEFAULT_FILE])
    results = [send(path, args.url, args.secret, args.keep_id) for path in files]
    print("Check n8n > Executions for the results.")
    sys.exit(0 if all(results) else 1)


if __name__ == "__main__":
    main()
