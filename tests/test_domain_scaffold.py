"""New zones must be usable without deploying the repository's test examples."""
import argparse
import contextlib
import importlib.util
import io
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

import yaml

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))
spec = importlib.util.spec_from_file_location("scaffold_cli", REPO / "cf.py")
cf = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cf)
from domain_scaffold import personalize_zone
from validation.domain import validate_domain
from validation.reporting import Report
from workflow.testing import fixture_roots


class DomainScaffoldTest(unittest.TestCase):
    def test_new_zone_has_inactive_samples_and_personalized_deployment_guide(self):
        with tempfile.TemporaryDirectory() as workspace:
            repository = Path(workspace)
            shutil.copytree(REPO / "domains" / "_template", repository / "domains" / "_template")
            args = argparse.Namespace(domain="fresh.example", zone_id="a" * 32, plan="pro")
            with patch.object(cf, "ROOT", repository), contextlib.redirect_stdout(io.StringIO()):
                cf.cmd_new(args)
            domain = repository / "domains" / args.domain
            metadata = yaml.safe_load((domain / "domain.yaml").read_text(encoding="utf-8"))
            self.assertEqual(metadata["name"], args.domain)
            self.assertEqual(metadata["zone_id"], args.zone_id)
            self.assertNotIn("example", metadata)
            self.assertTrue((domain / "domain.yaml").read_text(encoding="utf-8").startswith("#"))
            guide = (domain / "README.md").read_text(encoding="utf-8")
            for command in ("validate", "plan", "apply"):
                self.assertIn(f"python cf.py {command} fresh.example", guide)
            self.assertNotIn("{{DOMAIN}}", guide)
            for config_file in domain.rglob("*.yaml"):
                if config_file.name != "domain.yaml":
                    self.assertIsNone(yaml.safe_load(config_file.read_text(encoding="utf-8")), str(config_file))
            report = Report()
            validate_domain(report, domain, set())
            self.assertEqual([item for item in report.items if item[0] == "error"], [])

    def test_personalization_keeps_exported_data_unchanged(self):
        with tempfile.TemporaryDirectory() as workspace:
            directory = Path(workspace)
            path = directory / "cname.yaml"
            path.write_text("# Example: www.example.com\nexternal:\n  content: external.example.com\n", encoding="utf-8")
            before = yaml.safe_load(path.read_text(encoding="utf-8"))
            personalize_zone(directory, "fresh.example")
            self.assertIn("www.fresh.example", path.read_text(encoding="utf-8"))
            self.assertEqual(yaml.safe_load(path.read_text(encoding="utf-8")), before)

    def test_mock_fixtures_are_isolated_from_deployable_roots(self):
        with tempfile.TemporaryDirectory() as workspace:
            repository = Path(workspace)
            for name in ("modules", "account", "domains", "tests/fixtures/domains/sample.example"):
                (repository / name).mkdir(parents=True)
            fixture = repository / "tests/fixtures/domains/sample.example/main.tf"
            fixture.write_text("# fixture\n", encoding="utf-8")
            with patch.object(cf, "ROOT", repository):
                self.assertEqual(cf.domains(), [])
            with fixture_roots(repository) as roots:
                self.assertEqual([root.name for root in roots], ["sample.example"])
                scratch_root = roots[0].dir
                (scratch_root / "main.tf").write_text("# modified\n", encoding="utf-8")
            self.assertFalse(scratch_root.exists())
            self.assertEqual(fixture.read_text(encoding="utf-8"), "# fixture\n")


if __name__ == "__main__":
    unittest.main()
