"""Unit tests for scripts/validate.py: a broken domain must produce the
right error on the right line; the shipped examples must stay valid."""
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


class ValidateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.repo = self.tmp / "repo"
        shutil.copytree(REPO, self.repo, ignore=shutil.ignore_patterns(".git", ".terraform*", ".state", ".export"))
        self.d = self.repo / "domains" / "bad.example"
        shutil.copytree(self.repo / "domains" / "_template", self.d)
        (self.d / "README.md").unlink()

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def write(self, rel, text):
        (self.d / rel).write_text(textwrap.dedent(text).lstrip())

    def run_validate(self):
        p = subprocess.run([sys.executable, str(self.repo / "scripts" / "validate.py"), str(self.d)],
                           capture_output=True, text=True)
        return p.returncode, p.stdout

    def domain(self, plan="free"):
        self.write("domain.yaml", f'name: bad.example\nzone_id: "0123456789abcdef0123456789abcdef"\nplan: {plan}\n')

    def test_examples_are_valid(self):
        p = subprocess.run([sys.executable, str(REPO / "scripts" / "validate.py"), "--all"], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stdout)

    def test_empty_template_is_valid(self):
        self.domain()
        code, out = self.run_validate()
        self.assertEqual(code, 0, out)

    def test_duplicate_key(self):
        self.domain()
        self.write("dns/a.yaml", """
            www:
              content: 192.0.2.1
            www:
              content: 192.0.2.2
        """)
        code, out = self.run_validate()
        self.assertEqual(code, 1)
        self.assertIn("dns/a.yaml:3: duplicate key 'www'", out)

    def test_typo_suggestion_and_wrong_ip(self):
        self.domain()
        self.write("dns/a.yaml", """
            www:
              name: www
              content: 2001:db8::1
              proxed: true
        """)
        code, out = self.run_validate()
        self.assertIn("unknown field 'proxed'", out)
        self.assertIn("did you mean 'proxied'", out)
        self.assertIn("is not an IPv4 address", out)

    def test_on_off_trap(self):
        self.domain()
        self.write("settings/zone.yaml", "always_use_https: on\nmin_tls_version: 1.2\n")
        code, out = self.run_validate()
        self.assertIn('expects the text "on"', out)
        self.assertIn('put it in quotes: "1.2"', out)

    def test_plan_gates(self):
        self.domain("pro")
        self.write("waf/custom-rules.yaml", """
            - ref: r1
              expression: (http.request.uri.path matches "^/x")
              action: log
        """)
        self.write("waf/managed-rules.yaml", "owasp:\n  action: log\n")
        code, out = self.run_validate()
        self.assertIn("need Business or Enterprise", out)
        self.assertIn("the log action is Enterprise only", out)
        self.assertGreaterEqual(out.count("Enterprise only"), 2)

    def test_cname_conflict_and_list_reference(self):
        self.domain()
        self.write("dns/a.yaml", "api:\n  name: api\n  content: 192.0.2.1\n")
        self.write("dns/cname.yaml", "api:\n  name: api\n  content: other.example.net\n")
        self.write("waf/custom-rules.yaml", "- ref: r\n  expression: (ip.src in $missing_list)\n  action: block\n")
        code, out = self.run_validate()
        self.assertIn("has a CNAME and other records", out)
        self.assertIn("list $missing_list, which is not defined", out)

    def test_account_notification_webhook_reference(self):
        self.domain()
        (self.repo / "account" / "notifications.yaml").write_text(
            "ddos_alerts:\n  alert_type: dos_attack_l7\n  mechanisms:\n    webhooks: [missing_hook]\n")
        code, out = self.run_validate()
        self.assertIn("'missing_hook' is not defined in notification-webhooks.yaml", out)
        self.assertEqual(code, 1)

    def test_account_waf_reuses_zone_waf_validator(self):
        self.domain()
        (self.repo / "account" / "waf").mkdir(exist_ok=True)
        (self.repo / "account" / "waf" / "custom-rules.yaml").write_text(
            "- ref: r1\n  expression: (ip.src eq 1.1.1.1)\n  action: not_a_real_action\n")
        code, out = self.run_validate()
        self.assertIn("has invalid value 'not_a_real_action'", out)
        self.assertEqual(code, 1)

    def test_zone_hold_requires_enabled(self):
        self.domain()
        self.write("security/zone-hold.yaml", "include_subdomains: true\n")
        code, out = self.run_validate()
        self.assertIn("missing required field 'enabled'", out)
        self.assertEqual(code, 1)

    def test_apex_cname_flattening(self):
        """Cloudflare flattens a CNAME at the zone apex, so MX/NS/TXT may
        coexist with it there even though that's an error everywhere else."""
        self.domain()
        self.write("dns/cname.yaml", 'root:\n  name: "@"\n  content: other.example.net\n')
        self.write("dns/mx.yaml", 'mail:\n  name: "@"\n  content: mail.other.example.net\n  priority: 10\n')
        code, out = self.run_validate()
        self.assertEqual(code, 0, out)
        self.assertNotIn("has a CNAME and other records", out)

    def test_dkim_name_override(self):
        self.domain()
        self.write("dns/dkim.yaml", """
            mailgun:
              name: mta._domainkey.mg
              content: v=DKIM1; k=rsa; p=MIIB
            bad:
              name: not-a-dkim-name
              content: v=DKIM1; k=rsa; p=MIIB
        """)
        code, out = self.run_validate()
        self.assertIn("does not contain _domainkey", out)
        self.assertEqual(out.count("does not contain _domainkey"), 1)

    def test_rule_schema(self):
        self.domain()
        self.write("rules/response-headers.yaml", """
            - ref: h
              expression: "true"
              action_parameters:
                headers:
                  X-Test:
                    operation: replace
                    value: x
        """)
        code, out = self.run_validate()
        self.assertIn("operation has invalid value 'replace'", out)


class QuotedTxtTest(ValidateTest):
    """Cloudflare stores TXT content in double quotes; copied values must pass."""

    def test_quoted_values_from_cloudflare(self):
        self.domain()
        self.write("dns/spf.yaml", """
            "@":
              raw: '"v=spf1 include:_spf.google.com ~all"'
            mail:
              raw: '"v=spf1 include:a.example" " ~all"'
        """)
        self.write("dns/dmarc.yaml", """
            "@":
              raw: '"v=DMARC1; p=none; rua=mailto:d@bad.example"'
        """)
        self.write("dns/dkim.yaml", """
            google:
              content: '"v=DKIM1; k=rsa; p=MIIB" "AQAB"'
        """)
        self.write("dns/txt.yaml", """
            verify:
              name: "@"
              content: '"google-site-verification=abc"'
            legacy:
              name: legacy
              content: unquoted-value
              quoted: false
        """)
        code, out = self.run_validate()
        self.assertEqual(code, 0, out)

    def test_broken_quotes_and_spf_in_txt(self):
        self.domain()
        self.write("dns/txt.yaml", """
            broken:
              name: broken
              content: '"unterminated'
            spf:
              name: x
              content: '"v=spf1 -all"'
        """)
        code, out = self.run_validate()
        self.assertIn("not a list of quoted strings", out)
        self.assertIn("SPF record found in txt.yaml", out)


if __name__ == "__main__":
    unittest.main()
