import tempfile
import unittest
from pathlib import Path

from scripts.compliance_audit import workflow_has_schedule


class ComplianceAuditTest(unittest.TestCase):
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
