"""Static checks for the n8n workflow files (run: python3 -m unittest discover tests).

The logic of the Code nodes is tested in tests/js/ (node --test "tests/js/*.test.js") and the
whole workflow on a real n8n in tests/e2e/run_e2e.py.
"""
import json
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKFLOWS = sorted((ROOT / "workflows").glob("*.json"))
NODE = shutil.which("node")


class WorkflowTest(unittest.TestCase):
    def test_workflows_exist(self):
        self.assertTrue(WORKFLOWS, "no workflow files found")

    def test_structure(self):
        for path in WORKFLOWS:
            with self.subTest(workflow=path.name):
                wf = json.loads(path.read_text(encoding="utf-8"))
                names = [n["name"] for n in wf["nodes"]]
                self.assertEqual(len(names), len(set(names)), "duplicate node names")
                for source, outputs in wf["connections"].items():
                    self.assertIn(source, names)
                    for branch in outputs["main"]:
                        for target in branch:
                            self.assertIn(target["node"], names, f"{source} -> unknown node")

    def test_generated_workflow_is_up_to_date(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "build_workflow.py"), "--check"], capture_output=True, text=True
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_webhook_answers_through_the_acknowledge_node(self):
        """F3: the HTTP answer must come from the Acknowledge node (202/400/401/503), not n8n's default 200."""
        wf = json.loads((ROOT / "workflows" / "wazuh-ai-triage.json").read_text(encoding="utf-8"))
        nodes = {n["name"]: n for n in wf["nodes"]}
        self.assertEqual(nodes["Wazuh Webhook"]["parameters"]["responseMode"], "responseNode")
        self.assertEqual(nodes["Acknowledge"]["type"], "n8n-nodes-base.respondToWebhook")
        self.assertEqual(wf["connections"]["Sanitize & Validate"]["main"][0][0]["node"], "Acknowledge")

    def test_no_hardcoded_secrets_in_tracked_files(self):
        """A light check; CI also runs gitleaks over the whole history."""
        patterns = [
            re.compile(r"\b\d{8,10}:AA[A-Za-z0-9_-]{30,}"),  # Telegram bot token
            re.compile(r"\b[0-9a-f]{80}\b"),  # AbuseIPDB key
            re.compile(r"sk-[A-Za-z0-9]{20,}"),  # OpenAI-style key
        ]
        try:
            files = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True).stdout.split()
        except (OSError, subprocess.CalledProcessError):
            self.skipTest("not a git checkout")
        for name in files:
            path = ROOT / name
            if not path.is_file():
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
            for pattern in patterns:
                self.assertIsNone(pattern.search(text), f"{name} looks like it contains a secret")

    def test_every_sample_has_a_label(self):
        labels = json.loads((ROOT / "samples" / "labels.json").read_text(encoding="utf-8"))
        samples = {p.name for p in (ROOT / "samples" / "alerts").glob("*.json")}
        self.assertEqual({k for k in labels if not k.startswith("_")}, samples)

    @unittest.skipUnless(NODE, "node is not installed")
    def test_code_nodes_are_valid_javascript(self):
        for path in WORKFLOWS:
            wf = json.loads(path.read_text(encoding="utf-8"))
            for node in wf["nodes"]:
                if node["type"] != "n8n-nodes-base.code":
                    continue
                with self.subTest(workflow=path.name, node=node["name"]):
                    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as fh:
                        fh.write("(async () => {\n" + node["parameters"]["jsCode"] + "\n})();\n")
                    result = subprocess.run([NODE, "--check", fh.name], capture_output=True, text=True)
                    pathlib.Path(fh.name).unlink()
                    self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
