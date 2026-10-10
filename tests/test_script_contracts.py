"""Output contracts for configuration export and Terraform plan summaries."""
import argparse
import contextlib
import copy
import importlib.util
import io
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))
spec = importlib.util.spec_from_file_location("contract_exporter", REPO / "scripts" / "export_zone.py")
exporter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(exporter)
import plan_summary as summary

GOLDEN = REPO / "tests" / "golden" / "script_contracts.json"


def export_outputs():
    fixture = json.loads((REPO / "tests" / "fixtures" / "zone_api.json").read_text())
    class FixtureClient:
        def get(self, path, params=None):
            if path not in fixture:
                raise exporter.NotFound(path)
            return {"result": copy.deepcopy(fixture[path]), "result_info": {"total_pages": 1}}
        def result(self, path, params=None):
            return self.get(path, params)["result"]
        def pages(self, path, per_page=100):
            return self.result(path)
    client = FixtureClient()
    zone = exporter.ZoneExport(client, "0123456789abcdef0123456789abcdee", "acme.example", "pro")
    with contextlib.redirect_stdout(io.StringIO()):
        zone.run()
    output = {"zone": {"files": zone.files, "imports": zone.imports, "notes": zone.notes, "counts": dict(zone.counts)}}
    with tempfile.TemporaryDirectory() as workspace:
        root = Path(workspace)
        shutil.copytree(REPO / "account", root / "account")
        args = argparse.Namespace(account_id="a" * 32, plan="enterprise")
        with patch.object(exporter, "ROOT", root), patch.object(exporter, "run_validator", return_value=0), contextlib.redirect_stdout(io.StringIO()):
            exporter.export_account(client, args)
        output["account"] = {path.relative_to(root / "account").as_posix(): yaml.safe_load(path.read_text(encoding="utf-8")) for path in sorted((root / "account").rglob("*.yaml"))}
        output["account_imports"] = (root / "account" / "imports.tf").read_text(encoding="utf-8")
    return output


def summary_outputs():
    address = 'module.domain.module.dns.cloudflare_dns_record.this["a/www"]'
    def resource(actions, before, after, **extra):
        return {"address": address, "mode": "managed", "type": "cloudflare_dns_record", "change": {"actions": actions, "before": before, "after": after, "after_unknown": {}, **extra}}
    before = {"type": "A", "name": "www.example.com", "content": "192.0.2.1"}
    live = {**before, "content": "192.0.2.9"}
    plans = {"empty": {}, "adopt": {"resource_changes": [resource(["no-op"], before, before, importing={"id": "zone/record"})]}, "revert": {"resource_changes": [resource(["update"], live, before)], "resource_drift": [resource(["update"], before, live)]}, "replace": {"resource_changes": [resource(["delete", "create"], before, {**before, "type": "AAAA", "content": "2001:db8::1"}, replace_paths=[["type"]])]}}
    return {f"{name}/{fmt}/{deviation_only}": summary.render("example.com", *summary.summarise(plan, deviation_only), fmt, deviation_only) for name, plan in plans.items() for fmt in ("text", "md") for deviation_only in (False, True)}


class ScriptContractsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.baseline = json.loads(GOLDEN.read_text(encoding="utf-8"))
    def test_export_yaml_import_addresses_notes_and_counts(self):
        self.assertEqual(json.loads(json.dumps(export_outputs())), self.baseline["export"])
    def test_plan_text_and_markdown(self):
        self.assertEqual(summary_outputs(), self.baseline["summary"])


if __name__ == "__main__":
    unittest.main()
