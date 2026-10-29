"""Tests for wazuh/integrations/custom-n8n.py (run: python3 -m unittest discover tests)."""
import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "wazuh" / "integrations" / "custom-n8n.py"
SAMPLE = ROOT / "samples" / "alerts" / "01-ssh-bruteforce.json"
OTHER_SAMPLE = ROOT / "samples" / "alerts" / "02-web-sql-injection.json"

spec = importlib.util.spec_from_file_location("custom_n8n", SCRIPT)
custom_n8n = importlib.util.module_from_spec(spec)
spec.loader.exec_module(custom_n8n)


class Receiver(BaseHTTPRequestHandler):
    received = []
    status = 200
    lock = threading.Lock()

    def log_message(self, *args):
        pass

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        with Receiver.lock:
            Receiver.received.append({"path": self.path, "headers": dict(self.headers), "body": json.loads(body)})
        self.send_response(Receiver.status)
        self.end_headers()


class IntegrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Receiver)
        cls.url = f"http://127.0.0.1:{cls.server.server_address[1]}/webhook/wazuh-alert"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.tmp = tempfile.TemporaryDirectory()
        tmp = pathlib.Path(cls.tmp.name)
        cls.env = {
            "WAZUH_N8N_LOG": str(tmp / "integrations.log"),
            "WAZUH_N8N_STATE": str(tmp / "state.json"),
            "WAZUH_N8N_CONF": str(tmp / "custom-n8n.conf"),
        }
        os.environ.update(cls.env)
        custom_n8n.LOG_FILE = cls.env["WAZUH_N8N_LOG"]
        custom_n8n.STATE_FILE = cls.env["WAZUH_N8N_STATE"]
        custom_n8n.CONF_FILE = cls.env["WAZUH_N8N_CONF"]
        custom_n8n.time.sleep = lambda _seconds: None  # no waiting between retries in tests

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.tmp.cleanup()

    def setUp(self):
        Receiver.received = []
        Receiver.status = 200
        pathlib.Path(self.env["WAZUH_N8N_STATE"]).unlink(missing_ok=True)
        self.set_window(600)

    def set_window(self, seconds):
        pathlib.Path(self.env["WAZUH_N8N_CONF"]).write_text(f"DEDUP_WINDOW_SECONDS={seconds}\n")

    def run_main(self, sample=SAMPLE, secret="s3cret-value-123456"):
        return custom_n8n.main(["custom-n8n", str(sample), secret, self.url])

    # --- sending ---

    def test_posts_alert_with_secret(self):
        self.assertEqual(self.run_main(), 0)
        self.assertEqual(len(Receiver.received), 1)
        got = Receiver.received[0]
        self.assertEqual(got["path"], "/webhook/wazuh-alert")
        self.assertEqual(got["headers"]["X-Wazuh-Token"], "s3cret-value-123456")
        self.assertEqual(got["body"]["rule"]["id"], "5712")
        self.assertEqual(got["body"]["wazuh_n8n"], {"duplicates_suppressed": 0})

    def test_works_without_secret(self):
        self.assertEqual(self.run_main(secret=""), 0)
        self.assertNotIn("X-Wazuh-Token", Receiver.received[0]["headers"])

    def test_finds_hook_url_when_api_key_missing(self):
        alert_file, secret, hook_url = custom_n8n.parse_args(["custom-n8n", "/tmp/a.alert", self.url, "debug"])
        self.assertEqual((alert_file, secret, hook_url), ("/tmp/a.alert", "", self.url))

    def test_404_stops_retrying(self):
        Receiver.status = 404
        self.assertEqual(self.run_main(), 1)
        self.assertEqual(len(Receiver.received), 1)
        self.assertIn("published", pathlib.Path(self.env["WAZUH_N8N_LOG"]).read_text())

    def test_server_error_retries(self):
        Receiver.status = 500
        self.assertEqual(self.run_main(), 1)
        self.assertEqual(len(Receiver.received), custom_n8n.RETRIES)

    def test_bad_alert_file(self):
        self.assertEqual(custom_n8n.main(["custom-n8n", "/nonexistent.alert", "", self.url]), 1)

    def test_missing_args(self):
        self.assertEqual(custom_n8n.main(["custom-n8n"]), 2)

    # --- deduplication ---

    def test_repeats_are_dropped_and_counted(self):
        fp = custom_n8n.fingerprint(json.loads(SAMPLE.read_text()))
        self.assertEqual(custom_n8n.dedup_check(fp, 600, now=1000), (True, 0))
        self.assertEqual(custom_n8n.dedup_check(fp, 600, now=1010), (False, 0))
        self.assertEqual(custom_n8n.dedup_check(fp, 600, now=1020), (False, 0))
        # after the window the alert goes through and reports the 2 dropped repeats
        self.assertEqual(custom_n8n.dedup_check(fp, 600, now=1700), (True, 2))

    def test_different_alerts_are_not_merged(self):
        self.assertEqual(self.run_main(SAMPLE), 0)
        self.assertEqual(self.run_main(OTHER_SAMPLE), 0)
        self.assertEqual(len(Receiver.received), 2)

    def test_window_zero_disables_dedup(self):
        self.set_window(0)
        for _ in range(3):
            self.run_main()
        self.assertEqual(len(Receiver.received), 3)

    def test_failed_send_does_not_block_next_copy(self):
        Receiver.status = 500
        self.assertEqual(self.run_main(), 1)
        Receiver.status = 200
        Receiver.received = []
        self.assertEqual(self.run_main(), 0)
        self.assertEqual(len(Receiver.received), 1)

    def test_burst_of_parallel_processes_sends_once(self):
        """Wazuh can start many copies at once; the file lock must let only one through."""
        env = {**os.environ, **self.env}
        procs = [
            subprocess.Popen([sys.executable, str(SCRIPT), str(SAMPLE), "s3cret-value-123456", self.url], env=env)
            for _ in range(20)
        ]
        codes = [p.wait(timeout=60) for p in procs]
        self.assertEqual(codes, [0] * 20)
        self.assertEqual(len(Receiver.received), 1)
        state = json.loads(pathlib.Path(self.env["WAZUH_N8N_STATE"]).read_text())
        self.assertEqual(list(state.values())[0]["suppressed"], 19)


if __name__ == "__main__":
    unittest.main()
