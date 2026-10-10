"""Protect DNS normalization, cross-file collection and diagnostic order."""
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))

from validation.common import Report  # noqa: E402
from validation.dns import validate_dns  # noqa: E402


class DnsValidationTest(unittest.TestCase):
    def setUp(self):
        self.workspace = tempfile.TemporaryDirectory()
        self.addCleanup(self.workspace.cleanup)
        self.domain_dir = Path(self.workspace.name) / "example.com"
        (self.domain_dir / "dns").mkdir(parents=True)

    def write(self, filename, content):
        (self.domain_dir / "dns" / filename).write_text(content, encoding="utf-8")

    def validate(self):
        report = Report()
        validate_dns(report, self.domain_dir, "pro", "example.com")
        return report.errors

    def test_cross_file_errors_follow_individual_file_errors(self):
        self.write("a.yaml", "web:\n  content: not-an-ip\n")
        self.write("cname.yaml", "mail:\n  content: destination.example.net\n")
        self.write("spf.yaml", "mail:\n  includes: [sender.example.net]\n")
        self.write("dnssec.yaml", "status: invalid\n")
        errors = self.validate()
        self.assertEqual([item[3] for item in errors], [
            "'not-an-ip' is not an IPv4 address.",
            "status has invalid value 'invalid'.",
            "mail.example.com has a CNAME and other records (TXT in spf.yaml).",
        ])
        self.assertEqual([Path(item[1]).name for item in errors], ["a.yaml", "dnssec.yaml", "cname.yaml"])

    def test_quoted_and_plain_txt_values_share_duplicate_identity(self):
        self.write("txt.yaml", 'plain:\n  name: mail\n  content: example\nquoted:\n  name: mail.example.com\n  content: \'"example"\'\n')
        errors = self.validate()
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0][3], "duplicate TXT record mail.example.com -> example (also 'plain' in txt.yaml).")
        self.assertEqual(errors[0][2], 5)

    def test_apex_cname_can_coexist_with_structured_spf(self):
        self.write("cname.yaml", 'root:\n  name: "@"\n  content: destination.example.net\n')
        self.write("spf.yaml", '"@":\n  includes: [sender.example.net]\n')
        self.assertEqual(self.validate(), [])


if __name__ == "__main__":
    unittest.main()
