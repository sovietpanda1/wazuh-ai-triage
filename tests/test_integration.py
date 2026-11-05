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
FIM_SAMPLE = ROOT / "samples" / "alerts" / "03-fim-sshd-config.json"
DEDUP_CASES = ROOT / "tests" / "fixtures" / "dedup_cases.json"
SECRET = "s3cret-value-123456"

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
        cls.dir = pathlib.Path(cls.tmp.name)
        cls.env = {
            "WAZUH_N8N_LOG": str(cls.dir / "integrations.log"),
            "WAZUH_N8N_STATE": str(cls.dir / "state.json"),
            "WAZUH_N8N_CONF": str(cls.dir / "custom-n8n.conf"),
            "WAZUH_N8N_SPOOL": str(cls.dir / "spool"),
            "WAZUH_N8N_OSSEC_CONF": str(cls.dir / "ossec.conf"),
            "NO_PROXY": "127.0.0.1",
            "no_proxy": "127.0.0.1",
        }
        os.environ.update(cls.env)
        custom_n8n.LOG_FILE = cls.env["WAZUH_N8N_LOG"]
        custom_n8n.STATE_FILE = cls.env["WAZUH_N8N_STATE"]
        custom_n8n.CONF_FILE = cls.env["WAZUH_N8N_CONF"]
        custom_n8n.SPOOL_DIR = cls.env["WAZUH_N8N_SPOOL"]
        custom_n8n.OSSEC_CONF = cls.env["WAZUH_N8N_OSSEC_CONF"]
        custom_n8n.time.sleep = lambda _seconds: None  # no waiting between retries in tests

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.tmp.cleanup()

    def setUp(self):
        Receiver.received = []
        Receiver.status = 200
        pathlib.Path(self.env["WAZUH_N8N_STATE"]).unlink(missing_ok=True)
        pathlib.Path(self.env["WAZUH_N8N_LOG"]).unlink(missing_ok=True)
        subprocess.run(["rm", "-rf", self.env["WAZUH_N8N_SPOOL"]], check=True)
        self.set_window(600)

    def set_window(self, seconds):
        pathlib.Path(self.env["WAZUH_N8N_CONF"]).write_text(f"DEDUP_WINDOW_SECONDS={seconds}\n")

    def alert_file(self, source=SAMPLE, **changes):
        """Write a copy of a sample with some fields changed, return its path."""
        alert = json.loads(source.read_text())
        for key, value in changes.items():
            target = alert
            *parents, last = key.split(".")
            for part in parents:
                target = target.setdefault(part, {})
            target[last] = value
        fd, path = tempfile.mkstemp(suffix=".alert", dir=self.dir)
        with os.fdopen(fd, "w") as fh:
            json.dump(alert, fh)
        return path

    def run_main(self, sample=SAMPLE, secret=SECRET):
        return custom_n8n.main(["custom-n8n", str(sample), secret, self.url])

    def spool_files(self, sub=""):
        folder = pathlib.Path(self.env["WAZUH_N8N_SPOOL"]) / sub
        return sorted(folder.glob("*.json")) if folder.exists() else []

    def log_text(self):
        path = pathlib.Path(self.env["WAZUH_N8N_LOG"])
        return path.read_text() if path.exists() else ""

    # --- sending ---

    def test_posts_alert_with_secret(self):
        self.assertEqual(self.run_main(), 0)
        self.assertEqual(len(Receiver.received), 1)
        got = Receiver.received[0]
        self.assertEqual(got["path"], "/webhook/wazuh-alert")
        self.assertEqual(got["headers"]["X-Wazuh-Token"], SECRET)
        self.assertEqual(got["body"]["rule"]["id"], "5712")
        self.assertEqual(got["body"]["wazuh_n8n"], {"duplicates_suppressed": 0})

    def test_works_without_secret(self):
        self.assertEqual(self.run_main(secret=""), 0)
        self.assertNotIn("X-Wazuh-Token", Receiver.received[0]["headers"])

    def test_finds_hook_url_when_api_key_missing(self):
        alert_file, secret, hook_url = custom_n8n.parse_args(["custom-n8n", "/tmp/a.alert", self.url, "debug"])
        self.assertEqual((alert_file, secret, hook_url), ("/tmp/a.alert", "", self.url))

    def test_404_stops_retrying_and_keeps_the_alert(self):
        Receiver.status = 404
        self.assertEqual(self.run_main(), 1)
        self.assertEqual(len(Receiver.received), 1)
        self.assertIn("published", self.log_text())
        self.assertEqual(len(self.spool_files()), 1)

    def test_wrong_secret_is_not_retried_and_says_why(self):
        Receiver.status = 401
        self.assertEqual(self.run_main(), 1)
        self.assertEqual(len(Receiver.received), 1)
        self.assertIn("does not match WEBHOOK_SECRET", self.log_text())
        self.assertEqual(len(self.spool_files()), 1)

    def test_server_error_retries_with_backoff(self):
        Receiver.status = 500
        self.assertEqual(self.run_main(), 1)
        self.assertEqual(len(Receiver.received), custom_n8n.RETRIES)
        for attempt in (1, 2, 3):
            delay = custom_n8n.backoff(attempt)
            self.assertGreaterEqual(delay, 0.5 * 2 ** (attempt - 1))
            self.assertLessEqual(delay, 1.5 * 2 ** (attempt - 1))

    def test_bad_alert_file(self):
        self.assertEqual(custom_n8n.main(["custom-n8n", "/nonexistent.alert", "", self.url]), 1)

    def test_missing_args(self):
        self.assertEqual(custom_n8n.main(["custom-n8n"]), 2)

    # --- dedup contract (F1) ---

    def test_dedup_keys_match_the_shared_fixtures(self):
        for case in json.loads(DEDUP_CASES.read_text())["cases"]:
            with self.subTest(case["name"]):
                self.assertEqual(custom_n8n.dedup_keys(case["alert"]), (case["event_key"], case["group_key"]))

    def test_similar_alerts_are_dropped_and_counted(self):
        group = "grp|m|000|5712|10|ip:8.8.8.8"
        self.assertEqual(custom_n8n.dedup_check("evt|1", group, 600, now=1000), (True, 0))
        self.assertEqual(custom_n8n.dedup_check("evt|2", group, 600, now=1010), (False, 0))
        self.assertEqual(custom_n8n.dedup_check("evt|3", group, 600, now=1020), (False, 0))
        # after the window the next alert goes through and reports the 2 dropped ones
        self.assertEqual(custom_n8n.dedup_check("evt|4", group, 600, now=1700), (True, 2))

    def test_same_event_again_is_dropped_but_not_counted(self):
        group = "grp|m|000|5712|10|ip:8.8.8.8"
        self.assertEqual(custom_n8n.dedup_check("evt|1", group, 600, now=1000), (True, 0))
        self.assertEqual(custom_n8n.dedup_check("evt|1", group, 600, now=1001), (False, 0))
        self.assertEqual(custom_n8n.dedup_check("evt|1", group, 600, now=1002), (False, 0))
        self.assertEqual(custom_n8n.dedup_check("evt|2", group, 600, now=1700), (True, 0))

    def test_different_files_are_not_merged(self):
        self.assertEqual(self.run_main(self.alert_file(FIM_SAMPLE, id="a")), 0)
        self.assertEqual(self.run_main(self.alert_file(FIM_SAMPLE, id="b", **{"syscheck.path": "/etc/sudoers"})), 0)
        self.assertEqual(len(Receiver.received), 2)

    def test_alerts_without_a_subject_are_never_grouped(self):
        for alert_id in ("a", "b", "c"):
            self.assertEqual(self.run_main(self.alert_file(OTHER_SAMPLE, id=alert_id, data={})), 0)
        self.assertEqual(len(Receiver.received), 3)

    def test_different_alerts_are_not_merged(self):
        self.assertEqual(self.run_main(SAMPLE), 0)
        self.assertEqual(self.run_main(OTHER_SAMPLE), 0)
        self.assertEqual(len(Receiver.received), 2)

    def test_window_zero_disables_grouping_but_not_redelivery_checks(self):
        self.set_window(0)
        for alert_id in ("a", "b", "c"):
            self.run_main(self.alert_file(id=alert_id))
        self.run_main(self.alert_file(id="c"))
        self.assertEqual(len(Receiver.received), 3)

    def test_old_state_format_is_replaced(self):
        pathlib.Path(self.env["WAZUH_N8N_STATE"]).write_text('{"5712|000|1.2.3.4": {"last": 1, "suppressed": 0}}')
        self.assertEqual(self.run_main(), 0)
        state = json.loads(pathlib.Path(self.env["WAZUH_N8N_STATE"]).read_text())
        self.assertEqual(set(state), {"groups", "events"})

    def test_burst_of_parallel_processes_sends_once_and_counts_the_rest(self):
        """Wazuh can start many copies at once; the file lock must let only one through."""
        env = {**os.environ, **self.env}
        files = [self.alert_file(id=f"burst.{i}") for i in range(20)]
        procs = [subprocess.Popen([sys.executable, str(SCRIPT), f, SECRET, self.url], env=env) for f in files]
        codes = [p.wait(timeout=60) for p in procs]
        self.assertEqual(codes, [0] * 20)
        self.assertEqual(len(Receiver.received), 1)
        state = json.loads(pathlib.Path(self.env["WAZUH_N8N_STATE"]).read_text())
        self.assertEqual(list(state["groups"].values())[0]["suppressed"], 19)

    def test_parallel_redeliveries_of_one_alert_are_not_counted(self):
        env = {**os.environ, **self.env}
        procs = [subprocess.Popen([sys.executable, str(SCRIPT), str(SAMPLE), SECRET, self.url], env=env) for _ in range(10)]
        self.assertEqual([p.wait(timeout=60) for p in procs], [0] * 10)
        self.assertEqual(len(Receiver.received), 1)
        state = json.loads(pathlib.Path(self.env["WAZUH_N8N_STATE"]).read_text())
        self.assertEqual(list(state["groups"].values())[0]["suppressed"], 0)

    # --- spool: failed sends are kept and re-sent (F5) ---

    def test_failed_alert_is_spooled_and_replayed_when_n8n_is_back(self):
        Receiver.status = 500
        self.assertEqual(self.run_main(self.alert_file(id="first")), 1)
        self.assertEqual(len(self.spool_files()), 1)
        Receiver.status = 200
        Receiver.received = []
        self.assertEqual(self.run_main(self.alert_file(OTHER_SAMPLE, id="second")), 0)
        ids = [r["body"]["id"] for r in Receiver.received]
        self.assertEqual(ids, ["second", "first"])
        self.assertTrue(Receiver.received[1]["body"]["wazuh_n8n"]["replayed"])
        self.assertEqual(self.spool_files(), [])
        self.assertIn("delivered after", self.log_text())

    def test_count_of_alerts_dropped_during_an_outage_is_not_lost(self):
        """The review's scenario: the first send fails while a copy is being suppressed."""
        Receiver.status = 500
        self.assertEqual(self.run_main(self.alert_file(id="a")), 1)
        Receiver.status = 200
        self.assertEqual(self.run_main(self.alert_file(id="b")), 0)  # same group, inside the window
        Receiver.received = []
        state_path = pathlib.Path(self.env["WAZUH_N8N_STATE"])
        state = json.loads(state_path.read_text())
        for entry in state["groups"].values():
            entry["last"] -= 601
        state_path.write_text(json.dumps(state))
        self.assertEqual(self.run_main(self.alert_file(id="c")), 0)
        by_id = {r["body"]["id"]: r["body"] for r in Receiver.received}
        self.assertEqual(by_id["c"]["wazuh_n8n"]["duplicates_suppressed"], 1)
        self.assertIn("a", by_id)  # the alert from the outage was delivered too

    def test_suppressed_runs_respect_the_spool_backoff(self):
        Receiver.status = 500
        self.run_main(self.alert_file(id="a"))
        Receiver.status = 200
        Receiver.received = []
        custom_n8n.spool_flush(self.url, SECRET)  # not due yet: nothing is sent
        self.assertEqual(Receiver.received, [])
        entry = json.loads(self.spool_files()[0].read_text())
        sent, pending = custom_n8n.spool_flush(self.url, SECRET, now=entry["next_try_at"] + 1)
        self.assertEqual((sent, pending), (1, 0))

    def test_alert_that_keeps_failing_ends_in_failed_folder_with_an_error(self):
        Receiver.status = 500
        self.run_main(self.alert_file(id="doomed"))
        for _ in range(custom_n8n.MAX_SPOOL_ATTEMPTS + 1):
            custom_n8n.spool_flush(self.url, SECRET, force=True)
        self.assertEqual(self.spool_files(), [])
        failed = self.spool_files("failed")
        self.assertEqual(len(failed), 1)
        self.assertIn("gave_up_because", json.loads(failed[0].read_text()))
        self.assertIn("ERROR alert doomed was not delivered", self.log_text())

    def test_flush_command_reads_ossec_conf(self):
        Receiver.status = 500
        self.run_main(self.alert_file(id="later"))
        Receiver.status = 200
        Receiver.received = []
        pathlib.Path(self.env["WAZUH_N8N_OSSEC_CONF"]).write_text(
            "<ossec_config></ossec_config>\n<!-- wazuh-ai-triage:start -->\n<ossec_config><integration>"
            f"<name>custom-n8n</name><hook_url>{self.url}</hook_url><api_key>{SECRET}</api_key>"
            "</integration></ossec_config>\n<!-- wazuh-ai-triage:end -->\n"
        )
        self.assertEqual(custom_n8n.main(["custom-n8n", "--flush"]), 0)
        self.assertEqual([r["body"]["id"] for r in Receiver.received], ["later"])
        self.assertEqual(Receiver.received[0]["headers"]["X-Wazuh-Token"], SECRET)


if __name__ == "__main__":
    unittest.main()
