"""
Tests for scripts/record_docs.py: the '##' record documentation blocks people
write above each DNS record must survive a re-export, because export_zone.py
rebuilds the YAML from a data dict and yaml.safe_dump cannot keep comments.

The simulate_export() helper below does exactly what the exporter does to a
DNS file -- re-dump the parsed data under the template header -- so these
tests fail if the exporter ever stops stripping comments (in which case the
whole carry-across mechanism can be reconsidered) or if the carry-across
itself regresses. Run: python3 -m unittest discover -s tests
"""
import shutil
import tempfile
import unittest
from pathlib import Path

from scripts.record_docs import DNS_FILES, harvest, lost, reinject

REPO = Path(__file__).resolve().parent.parent
SOURCE = REPO / "domains" / "example.com"
TEMPLATE = REPO / "domains" / "_template"


class RecordDocsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.live = self.tmp / "example.com"
        shutil.copytree(SOURCE, self.live, ignore=shutil.ignore_patterns(".terraform*"))
        self.before = harvest(self.live)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def simulate_export(self, folder, drop_key=None, empty_file=None):
        """Rewrite each DNS file the way export_zone.py does: parsed data
        re-dumped under the template header, so every comment is lost."""
        from scripts.yamlio import dump_with_header, header_of, load_with_lines
        for kind in DNS_FILES:
            f = folder / "dns" / f"{kind}.yaml"
            if not f.exists():
                continue
            if empty_file == kind:
                f.write_text("# every record removed in Cloudflare\n", encoding="utf-8")
                continue
            data = load_with_lines(f)[0] or {}
            if drop_key:
                data = {k: v for k, v in data.items() if k != drop_key}
            dump_with_header(f, data, header_of(TEMPLATE / "dns" / f"{kind}.yaml"),
                             "--- Exported from Cloudflare. Your data starts below this line. ---")

    def copy_live(self, name):
        d = self.tmp / name
        shutil.copytree(self.live, d)
        return d

    def test_fixture_has_documentation_to_lose(self):
        self.assertTrue(self.before, "example.com has no '##' blocks; these tests prove nothing")
        self.assertIn("dns/a.yaml", self.before)

    def test_export_strips_blocks_and_reinject_restores_them(self):
        d = self.copy_live("roundtrip")
        self.simulate_export(d)
        self.assertEqual(harvest(d), {}, "the exporter should have stripped every block")
        reinject(d, self.before)
        self.assertEqual(harvest(d), self.before)
        self.assertEqual(lost(self.before, d), [])

    def test_reinject_is_idempotent(self):
        d = self.copy_live("idempotent")
        self.simulate_export(d)
        reinject(d, self.before)
        self.assertEqual(reinject(d, self.before), 0, "a second pass must not duplicate blocks")
        self.assertEqual(harvest(d), self.before)

    def test_reinject_leaves_record_data_untouched(self):
        from scripts.yamlio import load_with_lines
        d = self.copy_live("data")
        self.simulate_export(d)
        reinject(d, self.before)
        for kind in DNS_FILES:
            a, b = self.live / "dns" / f"{kind}.yaml", d / "dns" / f"{kind}.yaml"
            if a.exists():
                self.assertEqual(load_with_lines(a)[0], load_with_lines(b)[0], f"{kind}.yaml data changed")

    def test_stripped_export_is_reported_as_lost(self):
        d = self.copy_live("stripped")
        self.simulate_export(d)   # no reinject: this is the bug being guarded against
        self.assertEqual(len(lost(self.before, d)), sum(len(v) for v in self.before.values()))

    def test_partial_loss_is_reported_precisely(self):
        d = self.copy_live("partial")
        self.simulate_export(d)
        reinject(d, {k: v for k, v in self.before.items() if k != "dns/a.yaml"})
        self.assertEqual(lost(self.before, d), ["dns/a.yaml:api", "dns/a.yaml:root", "dns/a.yaml:vpn"])

    def test_record_deleted_in_cloudflare_is_not_lost_documentation(self):
        """A record removed upstream takes its block with it legitimately --
        flagging that would block every resync that drops a record."""
        d = self.copy_live("deleted-record")
        self.simulate_export(d, drop_key="api")
        reinject(d, self.before)
        self.assertEqual(lost(self.before, d), [])
        self.assertNotIn("api", harvest(d).get("dns/a.yaml", {}))

    def test_file_emptied_in_cloudflare_is_not_lost_documentation(self):
        d = self.copy_live("emptied-file")
        self.simulate_export(d, empty_file="mx")
        reinject(d, self.before)
        self.assertEqual(lost(self.before, d), [])

    def test_blocks_are_matched_by_key_not_by_position(self):
        """example.com's own blocks are all identical 'change-me' placeholders,
        so they cannot show this. Distinct blocks plus a record dropped from
        the front -- which shifts every key below it -- can."""
        d = self.copy_live("by-key")
        (d / "dns" / "a.yaml").write_text(
            "# dns/a.yaml header\n"
            "## Owner: team-root\nroot:\n  name: '@'\n  content: 203.0.113.10\n"
            "## Owner: team-api\napi:\n  name: api\n  content: 203.0.113.20\n"
            "## Owner: team-vpn\nvpn:\n  name: vpn\n  content: 198.51.100.5\n",
            encoding="utf-8", newline="\n")
        before = harvest(d)
        self.assertEqual(before["dns/a.yaml"]["api"], ["## Owner: team-api"])

        self.simulate_export(d, drop_key="root")
        reinject(d, before)

        blocks = harvest(d)["dns/a.yaml"]
        self.assertEqual(set(blocks), {"api", "vpn"})
        self.assertEqual(blocks["api"], ["## Owner: team-api"])
        self.assertEqual(blocks["vpn"], ["## Owner: team-vpn"])
        self.assertEqual(lost(before, d), [])


if __name__ == "__main__":
    unittest.main()
