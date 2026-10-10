"""
Offline test for scripts/export_zone.py: replays recorded API responses,
exports into a temporary copy of the repo, then runs the validator on the
result. Run: python3 -m unittest discover -s tests
"""
import json
import importlib.util
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
ZONE = "0123456789abcdef0123456789abcdee"
ACCOUNT = "a" * 32


class ExportTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        cls.repo = cls.tmp / "repo"
        shutil.copytree(REPO, cls.repo, ignore=shutil.ignore_patterns(".venv", "graphify-out", "__pycache__", "backend.hcl", ".env", ".env.*", ".git", ".terraform*", ".state", ".export"))
        sys.path.insert(0, str(cls.repo / "scripts"))
        spec = importlib.util.spec_from_file_location("fixture_exporter", cls.repo / "scripts/export_zone.py")
        ez = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(ez)
        cls.ez = ez
        data = json.loads((REPO / "tests" / "fixtures" / "zone_api.json").read_text())

        def get(self, path, params=None):
            if path not in data:
                raise ez.NotFound(path)
            res = data[path]
            return {"result": res, "result_info": {"total_pages": 1}}
        ez.Client.get = get

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp)

    def run_main(self, *args):
        sys.argv = ["export_zone.py", *args]
        with self.assertRaises(SystemExit) as cm:
            self.ez.main()
        return cm.exception.code

    def test_1_zone_export(self):
        import os
        os.environ["CLOUDFLARE_API_TOKEN"] = "test"
        rc = self.run_main("--zone-id", ZONE, "--domain", "acme.example")
        self.assertEqual(rc, 0, "validator should accept the export")
        d = self.repo / "domains" / "acme.example"
        import yaml
        mx = yaml.safe_load((d / "dns" / "mx.yaml").read_text())
        self.assertEqual(len(mx), 2)
        spf = yaml.safe_load((d / "dns" / "spf.yaml").read_text())
        self.assertEqual(spf["@"]["includes"], ["_spf.google.com"])
        self.assertIn("raw", spf["mail"])  # ordering differs, kept verbatim
        # Cloudflare stores TXT content in quotes: parsed from inside the
        # quotes, re-quoted by the module, so nothing changes on adoption.
        self.assertNotIn("quoted", spf["@"])
        self.assertEqual(spf["mail"]["quoted"], False)   # live record was unquoted
        dmarc = yaml.safe_load((d / "dns" / "dmarc.yaml").read_text())
        self.assertEqual(dmarc["@"]["policy"], "reject")
        dkim = yaml.safe_load((d / "dns" / "dkim.yaml").read_text())
        self.assertTrue(dkim["google"]["content"].startswith('"v=DKIM1'))  # split strings kept verbatim
        txt = yaml.safe_load((d / "dns" / "txt.yaml").read_text())
        self.assertEqual(txt["root"]["content"], "google-site-verification=abc")
        self.assertEqual(txt["legacy"], {"name": "legacy", "content": "legacy-unquoted-value", "quoted": False})
        srv = yaml.safe_load((d / "dns" / "srv.yaml").read_text())
        self.assertEqual(srv["sip_tls"]["priority"], 100)
        managed = yaml.safe_load((d / "waf" / "managed-rules.yaml").read_text())
        self.assertEqual(len(managed["raw_rules"]), 3)
        self.assertNotIn("version", managed["raw_rules"][1]["action_parameters"])
        cache = yaml.safe_load((d / "cache" / "cache-rules.yaml").read_text())
        self.assertNotIn("made_up_api_field", cache[0]["action_parameters"])
        bots = yaml.safe_load((d / "security" / "bot-management.yaml").read_text())
        self.assertNotIn("fight_mode", bots)                # not a Pro field
        self.assertNotIn("sbfm_likely_automated", bots)     # Business+
        settings = yaml.safe_load((d / "settings" / "zone.yaml").read_text())
        self.assertNotIn("0rtt", settings)                  # not editable
        self.assertEqual(settings["browser_cache_ttl"], 14400)
        ip_rules = yaml.safe_load((d / "security" / "ip-access-rules.yaml").read_text())
        self.assertEqual(list(ip_rules), ["geo_challenge"])  # account rule skipped
        # every service file keeps its documentation header
        for f in d.rglob("*.yaml"):
            self.assertTrue(f.read_text().startswith("#"), f"{f} lost its header")
        imports = (d / "imports.tf").read_text()
        self.assertEqual(imports.count("import {"), 28)
        self.assertNotIn('"r13"', imports)                   # apex NS skipped
        self.assertIn("PTR", (self.repo / ".export" / "acme.example" / "EXPORT_REPORT.md").read_text())

    def test_2_refuses_to_overwrite(self):
        import os
        os.environ["CLOUDFLARE_API_TOKEN"] = "test"
        rc = self.run_main("--zone-id", ZONE, "--domain", "acme.example")
        self.assertIn("already exists", str(rc))
        rc = self.run_main("--zone-id", ZONE, "--domain", "acme.example", "--force")
        self.assertEqual(rc, 0)
        self.assertTrue(any((self.repo / ".export" / "acme.example").glob("backup-*")))

    def test_3_account_export(self):
        import os
        os.environ["CLOUDFLARE_API_TOKEN"] = "test"
        rc = self.run_main("--account-id", ACCOUNT, "--plan", "pro")
        self.assertEqual(rc, 0)
        import yaml
        ip = yaml.safe_load((self.repo / "account" / "lists" / "ip.yaml").read_text())
        self.assertEqual(ip["blocked_ips"]["items"][0], "192.0.2.4")
        red = yaml.safe_load((self.repo / "account" / "lists" / "redirect.yaml").read_text())
        self.assertNotIn("subpath_matching", red["campaign"]["items"][0])

    def test_4_permission_failure_stops_zone_export(self):
        original = self.ez.ZoneExport.dns
        try:
            self.ez.ZoneExport.dns = lambda _export: (_ for _ in ()).throw(
                PermissionError("token cannot read /zones/example/dns_records")
            )
            export = self.ez.ZoneExport(self.ez.Client("test"), ZONE, "blocked.example", "pro")
            with self.assertRaisesRegex(PermissionError, "DNS export failed"):
                export.run()
        finally:
            self.ez.ZoneExport.dns = original


if __name__ == "__main__":
    unittest.main()
