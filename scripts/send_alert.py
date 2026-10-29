#!/usr/bin/env python3
"""Send sample Wazuh alerts to the n8n webhook, to test the workflow.

Examples:
  python3 scripts/send_alert.py                                   # SSH brute force sample
  python3 scripts/send_alert.py samples/alerts/02-web-sql-injection.json
  python3 scripts/send_alert.py --all --url http://192.168.1.20:5678/webhook/wazuh-alert

The secret comes from --secret, the WEBHOOK_SECRET environment variable, or .env.
The same alert sent twice within DEDUP_WINDOW_SECONDS is dropped on purpose.
"""
import argparse
import os
import pathlib
import sys
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


def send(path, url, secret):
    headers = {"Content-Type": "application/json"}
    if secret:
        headers["X-Wazuh-Token"] = secret
    request = urllib.request.Request(url, data=path.read_bytes(), headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            print(f"OK   {path.name} -> HTTP {response.status}")
            return True
    except urllib.error.HTTPError as exc:
        print(f"FAIL {path.name} -> HTTP {exc.code}: {exc.read().decode(errors='replace')[:200]}")
    except urllib.error.URLError as exc:
        print(f"FAIL {path.name} -> {exc.reason}")
    return False


def main():
    parser = argparse.ArgumentParser(description="Send sample Wazuh alerts to n8n.")
    parser.add_argument("files", nargs="*", type=pathlib.Path, help="alert JSON files")
    parser.add_argument("--all", action="store_true", help="send every file in samples/alerts")
    parser.add_argument("--url", default="http://localhost:5678/webhook/wazuh-alert")
    parser.add_argument("--secret", default=os.environ.get("WEBHOOK_SECRET") or secret_from_env_file())
    args = parser.parse_args()

    files = sorted((ROOT / "samples" / "alerts").glob("*.json")) if args.all else (args.files or [DEFAULT_FILE])
    results = [send(path, args.url, args.secret) for path in files]
    print("Check n8n > Executions for the results.")
    sys.exit(0 if all(results) else 1)


if __name__ == "__main__":
    main()
