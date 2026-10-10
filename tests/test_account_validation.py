"""Account validation must report malformed input without losing other checks."""
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))

from validation.account import validate_account  # noqa: E402
from validation.common import Report  # noqa: E402


class AccountValidationTest(unittest.TestCase):
    def setUp(self):
        self.workspace = tempfile.TemporaryDirectory()
        self.addCleanup(self.workspace.cleanup)
        self.account_dir = Path(self.workspace.name) / "account"
        self.write("account.yaml", 'account_id: "0123456789abcdef0123456789abcdef"\nplan: enterprise\n')

    def write(self, relative_file, content):
        config_file = self.account_dir / relative_file
        config_file.parent.mkdir(parents=True, exist_ok=True)
        config_file.write_text(content, encoding="utf-8")

    def validate(self):
        report = Report()
        list_names = validate_account(report, self.account_dir)
        return report, list_names

    def test_invalid_plan_reports_error_and_checks_independent_settings(self):
        self.write("account.yaml", 'account_id: "0123456789abcdef0123456789abcdef"\nplan: invalid\n')
        self.write("settings/turnstile.yaml", "widget:\n  domains: [example.com]\n  mode: invalid\n")
        report, _ = self.validate()
        self.assertEqual([item[3] for item in report.errors], [
            "plan has invalid value 'invalid'.", "widget.mode has invalid value 'invalid'.",
        ])

    def test_null_list_reports_missing_items_and_keeps_list_name(self):
        self.write("lists/ip.yaml", "my_list: null\n")
        report, list_names = self.validate()
        self.assertEqual(list_names, {"my_list"})
        self.assertEqual([item[3] for item in report.errors], ["my_list is missing required field 'items'."])

    def test_wrong_items_shape_reports_type_error_and_continues(self):
        for invalid_items in ("123", "true", "text", "{ip: 192.0.2.1}"):
            with self.subTest(items=invalid_items):
                self.write("lists/ip.yaml", f"broken:\n  items: {invalid_items}\nvalid:\n  items: [not-an-ip]\n")
                report, list_names = self.validate()
                self.assertEqual(list_names, {"broken", "valid"})
                self.assertEqual([item[3] for item in report.errors], [
                    "broken.items must be a list.", "'not-an-ip' is not an IP address or range.",
                ])

    def test_null_turnstile_reports_both_required_fields(self):
        self.write("settings/turnstile.yaml", "widget: null\n")
        report, _ = self.validate()
        self.assertEqual([item[3] for item in report.errors], [
            "widget is missing required field 'domains'.", "widget is missing required field 'mode'.",
        ])

    def test_scalar_and_mapping_items_have_the_same_duplicate_identity(self):
        self.write("lists/ip.yaml", "trusted:\n  items:\n    - 192.0.2.1\n    - ip: 192.0.2.1\n      comment: repeated\n")
        report, list_names = self.validate()
        self.assertEqual(list_names, {"trusted"})
        self.assertEqual([item[3] for item in report.errors], ["duplicate item '192.0.2.1'."])
        self.assertEqual(report.errors[0][2], 4)


if __name__ == "__main__":
    unittest.main()
