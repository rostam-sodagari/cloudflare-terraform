"""Unit tests for scripts/plan_summary.py using small hand-written plans
in Terraform's documented JSON plan format."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "plan_summary.py"


def rc(address, rtype, actions, before=None, after=None, **extra):
    return {"address": address, "mode": "managed", "type": rtype,
            "change": {"actions": actions, "before": before, "after": after, "after_unknown": {}, **extra}}


def run(plan, *args):
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(plan, f)
    p = subprocess.run([sys.executable, str(SCRIPT), f.name, "--root", "t.example", *args],
                       capture_output=True, text=True)
    return p.returncode, p.stdout


DNS = 'module.domain.module.dns.cloudflare_dns_record.this["a/www"]'
RS = "module.domain.module.waf.cloudflare_ruleset.custom[0]"
LIST = 'module.lists.cloudflare_list.this["blocked_ips"]'


class PlanSummaryTest(unittest.TestCase):
    def test_no_changes(self):
        code, out = run({"resource_changes": [rc(DNS, "cloudflare_dns_record", ["no-op"], {"a": 1}, {"a": 1})]})
        self.assertEqual(code, 0)
        self.assertIn("Nothing will change", out)

    def test_adopt_only_is_not_a_change(self):
        r = rc(DNS, "cloudflare_dns_record", ["no-op"], {"type": "A", "name": "www.t.example", "content": "192.0.2.1"},
               {"type": "A", "name": "www.t.example", "content": "192.0.2.1"}, importing={"id": "z/r"})
        code, out = run({"resource_changes": [r]})
        self.assertEqual(code, 0)
        self.assertIn("ADOPT", out)
        self.assertIn("1 TO ADOPT", out)

    def test_replace_and_reason(self):
        b = {"type": "A", "name": "www.t.example", "content": "192.0.2.1"}
        a = {"type": "AAAA", "name": "www.t.example", "content": "2001:db8::1"}
        code, out = run({"resource_changes": [rc(DNS, "cloudflare_dns_record", ["delete", "create"], b, a,
                                                 replace_paths=[["type"]])]})
        self.assertEqual(code, 2)
        self.assertIn("REPLACE", out)
        self.assertIn("replaced because `type`", out)
        self.assertIn("deleted and recreated", out)

    def test_ruleset_delete_warns(self):
        b = {"phase": "http_request_firewall_custom", "rules": [{"ref": "x", "action": "block", "expression": "true"}]}
        code, out = run({"resource_changes": [rc(RS, "cloudflare_ruleset", ["delete"], b, None)]})
        self.assertIn("WARNINGS", out)
        self.assertIn("removes the rules in this phase", out)

    def test_rule_add_remove_change_move(self):
        b = {"rules": [{"ref": "a", "action": "block", "expression": "e1"},
                       {"ref": "b", "action": "block", "expression": "e2"},
                       {"ref": "c", "action": "block", "expression": "e3"}]}
        a = {"rules": [{"ref": "b", "action": "managed_challenge", "expression": "e2"},
                       {"ref": "a", "action": "block", "expression": "e1"},
                       {"ref": "d", "action": "block", "expression": "e4"}]}
        code, out = run({"resource_changes": [rc(RS, "cloudflare_ruleset", ["update"], b, a)]})
        self.assertIn("add rule `d`", out)
        self.assertIn("remove rule `c`", out)
        self.assertIn("rule `b`: action `block` -> `managed_challenge`", out)
        self.assertIn("moves from position 2 to 1", out)

    def test_deviation_and_revert(self):
        live = {"type": "A", "name": "www.t.example", "content": "192.0.2.9"}
        last = {"type": "A", "name": "www.t.example", "content": "192.0.2.1"}
        plan = {"resource_drift": [rc(DNS, "cloudflare_dns_record", ["update"], last, live)],
                "resource_changes": [rc(DNS, "cloudflare_dns_record", ["update"], live, last)]}
        code, out = run(plan)
        self.assertEqual(code, 2)
        self.assertIn("CHANGED OUTSIDE GIT", out)
        self.assertIn("this undoes the dashboard change", out)
        code, md = run(plan, "--format", "md")
        self.assertIn("#### Changed outside Git", md)

    def test_noise_is_hidden(self):
        b = {"type": "A", "name": "www.t.example", "content": "192.0.2.1", "modified_on": "x", "meta": {"a": 1}}
        a = {"type": "A", "name": "www.t.example", "content": "192.0.2.2", "modified_on": "y", "meta": {"a": 2}}
        code, out = run({"resource_changes": [rc(DNS, "cloudflare_dns_record", ["update"], b, a)]})
        self.assertIn("content: `192.0.2.1` -> `192.0.2.2`", out)
        self.assertNotIn("modified_on", out)
        self.assertNotIn("meta", out)

    def test_ruleset_rule_noise_is_hidden(self):
        # "categories" is computed by Cloudflare on managed-ruleset rules, never set by us.
        b = {"rules": [{"ref": "a", "action": "block", "expression": "e1", "categories": ["foo"]}]}
        a = {"rules": [{"ref": "a", "action": "managed_challenge", "expression": "e1", "categories": ["bar"]}]}
        code, out = run({"resource_changes": [rc(RS, "cloudflare_ruleset", ["update"], b, a)]})
        self.assertIn("action `block` -> `managed_challenge`", out)
        self.assertNotIn("categories", out)

    def test_list_noise_is_hidden(self):
        # num_items/num_referencing_filters are computed by Cloudflare, never set by us.
        b = {"name": "blocked_ips", "kind": "ip", "num_items": 1, "num_referencing_filters": 2,
             "items": [{"ip": "203.0.113.1"}]}
        a = {"name": "blocked_ips", "kind": "ip", "num_items": 2, "num_referencing_filters": 2,
             "items": [{"ip": "203.0.113.1"}, {"ip": "203.0.113.2"}]}
        code, out = run({"resource_changes": [rc(LIST, "cloudflare_list", ["update"], b, a)]})
        self.assertIn("add item", out)
        self.assertIn("203.0.113.2", out)
        self.assertNotIn("num_items", out)
        self.assertNotIn("num_referencing_filters", out)


if __name__ == "__main__":
    unittest.main()
