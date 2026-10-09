"""Unit tests for the policy.yaml gate (scripts/validation/policy.py,
Ctx.flag in scripts/validation/common.py): enable/disable and
warning/error severity for best-practice checks."""
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


class PolicyTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.repo = self.tmp / "repo"
        shutil.copytree(REPO, self.repo, ignore=shutil.ignore_patterns(".git", ".terraform*", ".state", ".export", ".audit"))
        self.d = self.repo / "domains" / "bad.example"
        shutil.copytree(self.repo / "domains" / "_template", self.d)
        (self.d / "README.md").unlink()
        (self.d / "domain.yaml").write_text(
            'name: bad.example\nzone_id: "0123456789abcdef0123456789abcdef"\nplan: free\n')
        # A zone setting that trips ssl_not_weak by default.
        (self.d / "settings" / "zone.yaml").write_text('ssl: flexible\n')

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def set_policy(self, text):
        (self.repo / "policy.yaml").write_text(text)

    def run_validate(self):
        p = subprocess.run([sys.executable, str(self.repo / "scripts" / "validate.py"), str(self.d)],
                           capture_output=True, text=True)
        return p.returncode, p.stdout

    def test_default_is_warning_not_error(self):
        code, out = self.run_validate()
        self.assertIn("WARNING", out)
        self.assertIn("sends traffic to your origin unencrypted", out)
        self.assertEqual(code, 0, out)

    def test_severity_error_fails_validation(self):
        self.set_policy("ssl_not_weak: { enabled: true, severity: error }\n")
        code, out = self.run_validate()
        self.assertIn("ERROR", out)
        self.assertIn("sends traffic to your origin unencrypted", out)
        self.assertEqual(code, 1, out)

    def test_disabled_check_is_silent(self):
        self.set_policy("ssl_not_weak: { enabled: false }\n")
        code, out = self.run_validate()
        self.assertNotIn("sends traffic to your origin unencrypted", out)
        self.assertEqual(code, 0, out)

    def test_missing_policy_yaml_keeps_default_severity(self):
        (self.repo / "policy.yaml").unlink()
        code, out = self.run_validate()
        self.assertIn("WARNING", out)
        self.assertEqual(code, 0, out)

    def test_unlisted_check_defaults_to_enabled_warning(self):
        # policy.yaml exists but doesn't mention ssl_not_weak at all.
        self.set_policy("dmarc_has_rua: { enabled: false }\n")
        code, out = self.run_validate()
        self.assertIn("WARNING", out)
        self.assertIn("sends traffic to your origin unencrypted", out)
        self.assertEqual(code, 0, out)

    def test_record_without_doc_block_warns(self):
        (self.d / "dns" / "a.yaml").write_text('root:\n  name: "@"\n  content: 203.0.113.10\n  proxied: true\n')
        code, out = self.run_validate()
        self.assertIn("'root' has no '##' documentation block", out)
        self.assertIn("Owner, Purpose, Impact, Proxy missing", out)
        self.assertEqual(code, 0, out)  # default severity is warning

    def test_record_with_full_doc_block_is_silent(self):
        (self.d / "dns" / "a.yaml").write_text(
            "## Owner: platform-team\n"
            "## Purpose: primary website\n"
            "## Impact: changing content moves live traffic\n"
            "## Proxy: on -- public web host\n"
            'root:\n  name: "@"\n  content: 203.0.113.10\n  proxied: true\n')
        code, out = self.run_validate()
        self.assertNotIn("documentation block", out)
        self.assertEqual(code, 0, out)

    def test_record_type_without_proxied_does_not_require_proxy_line(self):
        (self.d / "dns" / "mx.yaml").write_text(
            "## Owner: platform-team\n"
            "## Purpose: primary mail exchanger\n"
            "## Impact: removing this stops mail from arriving\n"
            'm365:\n  name: "@"\n  content: example-com.mail.protection.outlook.com\n  priority: 0\n')
        code, out = self.run_validate()
        self.assertNotIn("documentation block", out)
        self.assertEqual(code, 0, out)

    def test_doc_block_severity_error_fails_validation(self):
        self.set_policy("record_has_doc_block: { enabled: true, severity: error }\n")
        (self.d / "dns" / "a.yaml").write_text('root:\n  name: "@"\n  content: 203.0.113.10\n  proxied: true\n')
        code, out = self.run_validate()
        self.assertIn("ERROR", out)
        self.assertIn("documentation block", out)
        self.assertEqual(code, 1, out)


if __name__ == "__main__":
    unittest.main()
