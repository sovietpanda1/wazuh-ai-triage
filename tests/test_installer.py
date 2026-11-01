"""Sandbox tests for wazuh/install-integration.sh (needs root, uses a fake Wazuh folder).

Run: sudo python3 -m unittest tests.test_installer
"""
import os
import pathlib
import re
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
INSTALLER = ROOT / "wazuh" / "install-integration.sh"
URL = "http://192.0.2.10:5678/webhook/wazuh-alert"
ORIGINAL_CONF = "<ossec_config>\n  <global/>\n</ossec_config>\n"

FAKE_SYSTEMCTL = """#!/bin/sh
echo "$@" >> "$(dirname "$0")/calls.log"
if [ "$1" = "is-active" ] && [ -f "$(dirname "$0")/fail" ]; then exit 3; fi
exit 0
"""


@unittest.skipUnless(hasattr(os, "geteuid") and os.geteuid() == 0, "installer tests need root (sudo)")
class InstallerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self.tmp.name)
        self.wazuh = self.dir / "ossec"
        (self.wazuh / "etc").mkdir(parents=True)
        (self.wazuh / "integrations").mkdir()
        self.conf = self.wazuh / "etc" / "ossec.conf"
        self.conf.write_text(ORIGINAL_CONF)
        self.systemctl = self.dir / "systemctl"
        self.systemctl.write_text(FAKE_SYSTEMCTL)
        self.systemctl.chmod(0o755)

    def tearDown(self):
        self.tmp.cleanup()

    def install(self, *args, **env):
        base = {k: v for k, v in os.environ.items() if k not in ("WEBHOOK_SECRET", "ROTATE_SECRET")}
        full_env = {**base, "WAZUH_DIR": str(self.wazuh), "WAZUH_GROUP": "root", "SYSTEMCTL": str(self.systemctl), **env}
        return subprocess.run(["bash", str(INSTALLER), *args], env=full_env, capture_output=True, text=True)

    def secret_in_conf(self):
        return re.search(r"<api_key>(.*)</api_key>", self.conf.read_text()).group(1)

    def test_fresh_install_generates_a_secret(self):
        result = self.install(URL, "7")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("WEBHOOK_SECRET=", result.stdout)
        self.assertRegex(self.secret_in_conf(), r"^[0-9a-f]{48}$")
        self.assertTrue((self.wazuh / "integrations" / "custom-n8n.py").exists())
        self.assertIn("DEDUP_WINDOW_SECONDS=600", (self.wazuh / "integrations" / "custom-n8n.conf").read_text())

    def test_rerun_keeps_the_existing_secret(self):
        self.install(URL)
        first = self.secret_in_conf()
        result = self.install(URL, "10")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.secret_in_conf(), first)
        self.assertIn("was kept", result.stdout)
        self.assertNotIn("WEBHOOK_SECRET=", result.stdout)
        self.assertEqual(self.conf.read_text().count("wazuh-ai-triage:start"), 1)
        self.assertIn("<level>10</level>", self.conf.read_text())

    def test_rotate_secret_makes_a_new_one(self):
        self.install(URL)
        first = self.secret_in_conf()
        self.install(URL, ROTATE_SECRET="1")
        self.assertNotEqual(self.secret_in_conf(), first)

    def test_explicit_secret_wins(self):
        self.install(URL)
        self.install(URL, WEBHOOK_SECRET="explicit-secret-123456")  # gitleaks:allow (test placeholder)
        self.assertEqual(self.secret_in_conf(), "explicit-secret-123456")

    def test_failed_restart_restores_config_and_scripts(self):
        old_script = self.wazuh / "integrations" / "custom-n8n.py"
        old_script.write_text("# version from an earlier install\n")
        (self.dir / "fail").write_text("")
        result = self.install(URL)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Restoring the backup", result.stderr)
        self.assertEqual(self.conf.read_text(), ORIGINAL_CONF)
        self.assertEqual(old_script.read_text(), "# version from an earlier install\n")
        self.assertFalse((self.wazuh / "integrations" / "custom-n8n").exists(), "new files are removed")

    def test_rejects_bad_input_before_changing_anything(self):
        for args, env in (((), {}), (("not-a-url",), {}), ((URL, "99"), {}), ((URL,), {"WEBHOOK_SECRET": "short"})):
            result = self.install(*args, **env)
            self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.conf.read_text(), ORIGINAL_CONF)
        self.assertEqual(list((self.wazuh / "integrations").iterdir()), [])


if __name__ == "__main__":
    unittest.main()
