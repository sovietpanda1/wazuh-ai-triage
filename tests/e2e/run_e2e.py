#!/usr/bin/env python3
"""End-to-end test: the real n8n workflow against the mock LLM / AbuseIPDB / Telegram.

It starts tests/mock_services.py and a throw-away n8n (own data folder, own port),
imports and publishes workflows/wazuh-ai-triage.json, sends alerts to the webhook and
checks HTTP answers, Telegram messages and execution results.

    python3 tests/e2e/run_e2e.py                    # uses `n8n` from PATH (or N8N_BIN)
    python3 tests/e2e/run_e2e.py --docker           # uses the n8n Docker image

Nothing here talks to the internet: every outside call goes to the local mock.
This checks wiring and behaviour, not how good a real model is (see scripts/evaluate.js).
"""
import argparse
import json
import os
import pathlib
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[2]
SAMPLES = ROOT / "samples" / "alerts"
MOCK_PORT = 8999
N8N_PORT = 5690
SECRET = "e2e-test-secret-0123456789"  # gitleaks:allow (test placeholder)
WORKFLOW_ID = "wazuhAiTriageE2E"
N8N_VERSION = os.environ.get("N8N_VERSION", "2.45.6")
N8N_IMAGE = os.environ.get("N8N_IMAGE", "docker.n8n.io/n8nio/n8n")
# A global address, so the AbuseIPDB / block path runs. It only ever goes to the local mock.
PUBLIC_TEST_IP = "8.8.8.8"

failures = []


def check(condition, message):
    print(("  ok   " if condition else "  FAIL ") + message, flush=True)
    if not condition:
        failures.append(message)


OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # local calls never use a proxy


def http(method, url, body=None, headers=None, timeout=15):
    """Return (status, text). Status 0 means no connection."""
    data = json.dumps(body).encode() if body is not None and not isinstance(body, bytes) else body
    request = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    if data is not None:
        request.add_header("Content-Type", "application/json")
    try:
        with OPENER.open(request, timeout=timeout) as response:
            return response.status, response.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()
    except OSError:
        return 0, ""


def mock(path, body=None):
    method = "GET" if body is None else "POST"
    return json.loads(http(method, f"http://127.0.0.1:{MOCK_PORT}{path}", body)[1])


def telegram_messages():
    return [r["body"]["text"] for r in mock("/_requests") if r["path"].endswith("/sendMessage") and r["body"]]


def wait_for(predicate, timeout=60, step=0.5):
    end = time.time() + timeout
    while time.time() < end:
        result = predicate()
        if result:
            return result
        time.sleep(step)
    return predicate()


def sample(name, **changes):
    alert = json.loads((SAMPLES / name).read_text())
    for key, value in changes.items():
        target = alert
        *parents, last = key.split(".")
        for part in parents:
            target = target.setdefault(part, {})
        target[last] = value
    return alert


class N8n:
    def __init__(self, docker, folder, env):
        self.docker = docker
        self.folder = folder
        self.env = env
        self.proc = None
        self.container = "wazuh-ai-triage-e2e"

    def cli(self, *args):
        if self.docker:
            cmd = ["docker", "exec", self.container, "n8n", *args]
            return subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        n8n = os.environ.get("N8N_BIN") or shutil.which("n8n")
        return subprocess.run([n8n, *args], capture_output=True, text=True, timeout=180, env=self.env)

    def start(self):
        if self.docker:
            subprocess.run(["docker", "rm", "-f", self.container], capture_output=True)
            os.chmod(self.folder, 0o777)
            prefixes = ("N8N_", "WEBHOOK_", "LLM_", "ABUSEIPDB_", "TELEGRAM_", "DEDUP_", "BLOCK_", "WHITELIST_")
            env_args = [a for k, v in self.env.items()
                        if k.startswith(prefixes) and k != "N8N_USER_FOLDER" for a in ("-e", f"{k}={v}")]
            subprocess.run(["docker", "run", "-d", "--name", self.container, "--network", "host",
                            "-v", f"{self.folder}:/data", "-e", "N8N_USER_FOLDER=/data", *env_args,
                            f"{N8N_IMAGE}:{N8N_VERSION}"], check=True, capture_output=True)
        else:
            n8n = os.environ.get("N8N_BIN") or shutil.which("n8n")
            if not n8n:
                sys.exit("n8n not found: install it (npm i -g n8n) or use --docker")
            self.log = open(self.folder / "n8n.log", "w")
            self.proc = subprocess.Popen([n8n, "start"], env=self.env, stdout=self.log, stderr=subprocess.STDOUT)

    def wait_ready(self):
        ok = wait_for(lambda: self._healthy(), timeout=180, step=1)
        if not ok:
            self.dump_log()
            sys.exit("n8n did not become ready")

    def _healthy(self):
        return http("GET", f"http://127.0.0.1:{N8N_PORT}/healthz", timeout=2)[0] == 200

    def stop(self):
        if self.docker:
            subprocess.run(["docker", "rm", "-f", self.container], capture_output=True)
        elif self.proc:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                self.proc.kill()

    def dump_log(self):
        if self.docker:
            out = subprocess.run(["docker", "logs", "--tail", "80", self.container], capture_output=True, text=True)
            print(out.stdout[-6000:], out.stderr[-6000:])
        else:
            print((self.folder / "n8n.log").read_text()[-6000:])

    def executions(self):
        db = self.folder / ".n8n" / "database.sqlite"
        if not db.exists():
            db = self.folder / "database.sqlite"
        con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        try:
            return con.execute("SELECT id, status FROM execution_entity ORDER BY id").fetchall()
        finally:
            con.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--docker", action="store_true", help="run n8n from the Docker image")
    args = parser.parse_args()

    tmp = pathlib.Path(tempfile.mkdtemp(prefix="n8n-e2e-"))
    mock_url = f"http://127.0.0.1:{MOCK_PORT}"
    env = {
        **os.environ,
        "N8N_USER_FOLDER": str(tmp),
        "N8N_PORT": str(N8N_PORT),
        "N8N_LISTEN_ADDRESS": "127.0.0.1",
        "N8N_RUNNERS_BROKER_LISTEN_ADDRESS": "127.0.0.1",
        "N8N_RUNNERS_BROKER_PORT": str(N8N_PORT + 1),
        "N8N_DIAGNOSTICS_ENABLED": "false",
        "N8N_BLOCK_ENV_ACCESS_IN_NODE": "false",
        "N8N_CONCURRENCY_PRODUCTION_LIMIT": "1",
        "N8N_PAYLOAD_SIZE_MAX": "1",
        "WEBHOOK_SECRET": SECRET,
        "LLM_BASE_URL": f"{mock_url}/v1",
        "LLM_MODEL": "mock",
        "ABUSEIPDB_API_URL": f"{mock_url}/api/v2/check",
        "ABUSEIPDB_API_KEY": "placeholder-key",
        "TELEGRAM_API_BASE": mock_url,
        "TELEGRAM_BOT_TOKEN": "123456:placeholder",
        "TELEGRAM_CHAT_ID": "1",
        "DEDUP_WINDOW_SECONDS": "600",
        "BLOCK_THRESHOLD": "80",
    }

    mock_proc = subprocess.Popen([sys.executable, str(ROOT / "tests" / "mock_services.py"), "--port", str(MOCK_PORT)])
    n8n = N8n(args.docker, tmp, env)
    try:
        wait_for(lambda: http("GET", f"{mock_url}/_requests", timeout=2)[0] == 200, timeout=10)

        workflow = json.loads((ROOT / "workflows" / "wazuh-ai-triage.json").read_text())
        workflow["id"] = WORKFLOW_ID
        (tmp / "workflow.json").write_text(json.dumps(workflow))
        n8n.start()
        n8n.wait_ready()
        wf_path = "/data/workflow.json" if args.docker else str(tmp / "workflow.json")
        for step in (("import:workflow", f"--input={wf_path}"), ("publish:workflow", f"--id={WORKFLOW_ID}")):
            out = n8n.cli(*step)
            if out.returncode != 0:
                print(out.stdout, out.stderr)
                sys.exit(f"n8n {step[0]} failed")
        # Published workflows are picked up on start: restart n8n.
        n8n.stop()
        n8n.start()
        n8n.wait_ready()

        hook = f"http://127.0.0.1:{N8N_PORT}/webhook/wazuh-alert"
        auth = {"X-Wazuh-Token": SECRET}
        ready = wait_for(lambda: http("POST", hook, {}, auth)[0] != 404, timeout=60)
        check(ready, "webhook is registered")

        print("F3: authentication and input checks")
        check(http("POST", hook, sample("01-ssh-bruteforce.json"))[0] == 401, "no token -> 401")
        check(http("POST", hook, sample("01-ssh-bruteforce.json"), {"X-Wazuh-Token": "wrong"})[0] == 401, "wrong token -> 401")
        check(http("POST", hook, {"hello": "world"}, auth)[0] == 400, "not a Wazuh alert -> 400")
        time.sleep(2)
        check(telegram_messages() == [], "rejected requests produce no message")
        mock("/_reset", {})

        print("Happy path with a not-public (TEST-NET) source IP")
        status, body = http("POST", hook, sample("01-ssh-bruteforce.json"), auth)
        check(status == 202 and json.loads(body).get("accepted") is True, f"valid alert -> 202 accepted ({status})")
        msgs = wait_for(lambda: telegram_messages(), timeout=60)
        check(len(msgs) == 1, "one Telegram message")
        if msgs:
            check("source IP is not public" in msgs[0], "TEST-NET IP is not treated as public")
        check(not any(r["path"].startswith("/api/v2/check") for r in mock("/_requests")), "no AbuseIPDB lookup")

        print("F1: dedup (same event again, different files)")
        mock("/_reset", {})
        http("POST", hook, sample("01-ssh-bruteforce.json"), auth)
        time.sleep(4)
        check(telegram_messages() == [], "same alert id again -> no new message")
        http("POST", hook, sample("03-fim-sshd-config.json", id="e2e.fim.1"), auth)
        http("POST", hook, sample("03-fim-sshd-config.json", id="e2e.fim.2", **{"syscheck.path": "/etc/sudoers"}), auth)
        msgs = wait_for(lambda: len(telegram_messages()) >= 2 and telegram_messages(), timeout=60) or []
        check(len(msgs) == 2, "two different files -> two messages")
        check(any("/etc/sudoers" in m for m in msgs), "the sudoers change is reported")

        print("Public IP path: AbuseIPDB + dry-run block recommendation")
        mock("/_reset", {})
        http("POST", hook, sample("01-ssh-bruteforce.json", id="e2e.pub.1", **{"data.srcip": PUBLIC_TEST_IP}), auth)
        msgs = wait_for(lambda: telegram_messages(), timeout=60) or []
        check(any(r["path"].startswith("/api/v2/check") for r in mock("/_requests")), "AbuseIPDB was called")
        check(bool(msgs) and f"would block {PUBLIC_TEST_IP} (dry-run)" in msgs[0], "dry-run block recommendation")

        print("F2: a schema-breaking model answer is a failed analysis")
        mock("/_reset", {})
        mock("/_config", {"llm": "invalid"})
        http("POST", hook, sample("01-ssh-bruteforce.json", id="e2e.bad.1", **{"data.srcip": "8.8.4.4"}), auth)
        msgs = wait_for(lambda: telegram_messages(), timeout=60) or []
        check(bool(msgs) and "analysis failed" in msgs[0], "message says the analysis failed")
        check(bool(msgs) and "would block" not in msgs[0], "no block recommendation without a valid answer")

        print("F5: a Telegram failure is retried and then fails the execution")
        mock("/_reset", {})
        mock("/_config", {"telegram": "fail"})
        before = len(n8n.executions())
        http("POST", hook, sample("02-web-sql-injection.json", id="e2e.tg.1"), auth)
        attempts = wait_for(lambda: len([r for r in mock("/_requests") if r["path"].endswith("/sendMessage")]) >= 3, timeout=60)
        check(bool(attempts), "Telegram was tried 3 times")
        statuses = wait_for(lambda: [s for _, s in n8n.executions()[before:] if s in ("error", "crashed")], timeout=30)
        check(bool(statuses), "the execution is marked as failed (not silently successful)")
        mock("/_reset", {})
    finally:
        if failures:
            n8n.dump_log()
        n8n.stop()
        mock_proc.terminate()
        shutil.rmtree(tmp, ignore_errors=True)

    print(f"\n{'FAILED' if failures else 'PASSED'}: {len(failures)} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
