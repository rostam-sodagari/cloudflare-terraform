import tempfile
import unittest
from pathlib import Path

from scripts.compliance_audit import audit_domain, workflow_has_schedule


class ComplianceAuditTest(unittest.TestCase):
    def _tls_status(self, ssl_mode):
        with tempfile.TemporaryDirectory() as tmp:
            domain = Path(tmp) / "example.test"
            (domain / "settings").mkdir(parents=True)
            (domain / "domain.yaml").write_text("plan: pro\n", encoding="utf-8")
            (domain / "settings" / "zone.yaml").write_text(
                f"ssl: {ssl_mode}\n", encoding="utf-8"
            )
            results, _, _ = audit_domain(domain)
            return next(result for result in results if result.id == "TLS-01").status

    def test_strict_ssl_is_reported_as_pass(self):
        self.assertEqual(self._tls_status("strict"), "PASS")

    def test_full_ssl_is_not_reported_as_strict(self):
        self.assertEqual(self._tls_status("full"), "FAIL")

    def test_origin_pull_is_not_treated_as_zone_ssl_mode(self):
        self.assertEqual(self._tls_status("origin_pull"), "FAIL")

    def test_schedule_requires_yaml_schedule_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "workflow.yml"
            path.write_text(
                "# schedule: this comment is not a trigger\n"
                "name: example\n"
                "on:\n"
                "  workflow_dispatch:\n",
                encoding="utf-8",
            )
            self.assertFalse(workflow_has_schedule(path))

            path.write_text(
                "name: example\n"
                "on:\n"
                "  schedule:\n"
                "    - cron: '0 6 * * 1-5'\n",
                encoding="utf-8",
            )
            self.assertTrue(workflow_has_schedule(path))


if __name__ == "__main__":
    unittest.main()
