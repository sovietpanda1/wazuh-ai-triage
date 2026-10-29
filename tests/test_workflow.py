"""Static checks for the n8n workflow files (run: python3 -m unittest discover tests)."""
import json
import pathlib
import re
import shutil
import subprocess
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

    def test_no_hardcoded_secrets(self):
        patterns = [
            re.compile(r"bot\d{6,}:[A-Za-z0-9_-]{20,}"),  # Telegram bot token
            re.compile(r"\b[0-9a-f]{80}\b"),  # AbuseIPDB key
            re.compile(r"sk-[A-Za-z0-9]{20,}"),  # OpenAI-style key
        ]
        for path in WORKFLOWS:
            text = path.read_text(encoding="utf-8")
            for pattern in patterns:
                self.assertIsNone(pattern.search(text), f"{path.name} looks like it contains a secret")

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
