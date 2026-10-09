"""
Tests the mass-deletion brake: cf.py refuses an unusually destructive plan
unless CF_ALLOW_DESTRUCTIVE=1, and plan_summary.py warns in the summary a
reviewer approves. Cloudflare has no undo for a deleted DNS record.
"""
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def load_cf():
    """cf.py is a script, not a package; load it under its own module name."""
    spec = importlib.util.spec_from_file_location("cf_under_test", REPO / "cf.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class DestructiveBrakeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cf = load_cf()
        cls.limit = cls.cf.MAX_DESTRUCTIVE_CHANGES

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        os.environ.pop("CF_ALLOW_DESTRUCTIVE", None)

    def tearDown(self):
        os.environ.pop("CF_ALLOW_DESTRUCTIVE", None)

    def root(self, deletes=0, replaces=0, extra=()):
        changes = [{"address": f'm.dns.this["d{i}"]', "mode": "managed",
                    "change": {"actions": ["delete"]}} for i in range(deletes)]
        changes += [{"address": f'm.dns.this["r{i}"]', "mode": "managed",
                     "change": {"actions": ["delete", "create"]}} for i in range(replaces)]
        changes += list(extra)
        (self.tmp / "plan.json").write_text(json.dumps({"resource_changes": changes}), encoding="utf-8")
        return types.SimpleNamespace(dir=self.tmp, name="example.com")

    def test_counts_deletes_and_replaces_separately(self):
        deletes, replaces = self.cf.destructive_changes(self.root(deletes=3, replaces=2))
        self.assertEqual((len(deletes), len(replaces)), (3, 2))

    def test_creates_and_data_reads_are_not_destructive(self):
        extra = [{"address": "m.dns.this[\"new\"]", "mode": "managed", "change": {"actions": ["create"]}},
                 {"address": "m.dns.this[\"same\"]", "mode": "managed", "change": {"actions": ["no-op"]}},
                 {"address": "data.cloudflare_zone.z", "mode": "data", "change": {"actions": ["read"]}}]
        self.assertEqual(self.cf.destructive_changes(self.root(extra=extra)), ([], []))

    def test_unreadable_plan_json_does_not_crash(self):
        (self.tmp / "plan.json").write_text("not json at all", encoding="utf-8")
        r = types.SimpleNamespace(dir=self.tmp, name="example.com")
        self.assertEqual(self.cf.destructive_changes(r), ([], []))

    def test_at_the_limit_is_allowed(self):
        self.cf.check_destructive(self.root(deletes=self.limit))  # must not raise

    def test_over_the_limit_refuses(self):
        with self.assertRaises(SystemExit) as cm:
            self.cf.check_destructive(self.root(deletes=self.limit + 1))
        self.assertEqual(cm.exception.code, 1)

    def test_replaces_count_towards_the_limit(self):
        """A replace deletes the live object before recreating it."""
        with self.assertRaises(SystemExit):
            self.cf.check_destructive(self.root(deletes=self.limit - 1, replaces=2))

    def test_override_allows_a_deliberate_bulk_change(self):
        os.environ["CF_ALLOW_DESTRUCTIVE"] = "1"
        self.cf.check_destructive(self.root(deletes=self.limit + 50))  # must not raise

    def test_summary_warns_before_anyone_approves(self):
        changes = [{"address": f'm.dns.this["d{i}"]', "mode": "managed", "type": "cloudflare_dns_record",
                    "change": {"actions": ["delete"], "before": {"name": f"d{i}", "type": "A"}, "after": None}}
                   for i in range(self.limit + 4)]
        plan = self.tmp / "plan.json"
        plan.write_text(json.dumps({"resource_changes": changes}), encoding="utf-8")
        out = subprocess.run([sys.executable, str(REPO / "scripts" / "plan_summary.py"),
                              str(plan), "--root", "example.com", "--format", "md"],
                             capture_output=True, text=True)
        self.assertEqual(out.returncode, 2, out.stderr)
        self.assertIn(f"destroys {self.limit + 4} objects", out.stdout)
        self.assertIn("CF_ALLOW_DESTRUCTIVE=1", out.stdout)
        # It must be the first thing in the warnings, above the per-record notes.
        warnings = out.stdout.split("#### WARNINGS: read these first", 1)[1]
        self.assertTrue(warnings.lstrip().startswith(f"- This plan destroys {self.limit + 4}"),
                        f"the threshold warning is not first:\n{warnings[:300]}")

    def test_summary_stays_quiet_below_the_limit(self):
        changes = [{"address": 'm.dns.this["d0"]', "mode": "managed", "type": "cloudflare_dns_record",
                    "change": {"actions": ["delete"], "before": {"name": "d0", "type": "TXT"}, "after": None}}]
        plan = self.tmp / "plan.json"
        plan.write_text(json.dumps({"resource_changes": changes}), encoding="utf-8")
        out = subprocess.run([sys.executable, str(REPO / "scripts" / "plan_summary.py"),
                              str(plan), "--root", "example.com"], capture_output=True, text=True)
        self.assertNotIn("CF_ALLOW_DESTRUCTIVE", out.stdout)


if __name__ == "__main__":
    unittest.main()
