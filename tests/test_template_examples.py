"""Check commented examples as configuration, rather than just as prose."""
import contextlib
import io
from pathlib import Path
import re
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

import yaml

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))
import gen_template
from validation.account import validate_account
from validation.domain import validate_domain
from validation.reporting import Report


def examples(text):
    """Read complete, labeled examples; partial optional blocks need their parent."""
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if not re.match(r"# (?:EXAMPLES?|RECOMMENDED BASELINE).*:", line):
            continue
        if "optional" in line.lower():
            continue
        block = []
        for config_line in lines[index + 1:]:
            if not config_line.startswith("# "):
                break
            block.append(config_line[2:])
        if block:
            yield line, "\n".join(block) + "\n"


class TemplateExamplesTest(unittest.TestCase):
    def test_zone_examples_validate_when_uncommented(self):
        for relative_path, text in gen_template.FILES.items():
            if relative_path == "domain.yaml":
                continue
            snippets = list(examples(text))
            self.assertTrue(snippets, f"{relative_path} needs a labeled example")
            for label, snippet in snippets:
                with self.subTest(file=relative_path, example=label), tempfile.TemporaryDirectory() as workspace:
                    zone = Path(workspace) / "sample.example"
                    zone.mkdir()
                    plan = "pro" if "Pro/Business" in label or relative_path == "waf/managed-rules.yaml" else "free"
                    (zone / "domain.yaml").write_text(
                        f'name: sample.example\nzone_id: "{"a" * 32}"\nplan: {plan}\n', encoding="utf-8")
                    path = zone / relative_path
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text(snippet, encoding="utf-8")
                    report = Report()
                    validate_domain(report, zone, set())
                    self.assertEqual([item for item in report.items if item[0] == "error"], [])

    def test_account_examples_validate_when_uncommented(self):
        for path in sorted((REPO / "account").rglob("*.yaml")):
            relative_path = path.relative_to(REPO / "account")
            snippets = list(examples(path.read_text(encoding="utf-8")))
            self.assertTrue(snippets, f"account/{relative_path} needs a labeled example")
            for label, snippet in snippets:
                with self.subTest(file=relative_path, example=label), tempfile.TemporaryDirectory() as workspace:
                    account = Path(workspace) / "account"
                    account.mkdir()
                    (account / "account.yaml").write_text(
                        f'account_id: "{"a" * 32}"\nplan: enterprise\n', encoding="utf-8")
                    path = account / relative_path
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text(snippet, encoding="utf-8")
                    report = Report()
                    validate_account(report, account)
                    self.assertEqual([item for item in report.items if item[0] == "error"], [])

    def test_regeneration_preserves_data_and_does_not_activate_samples(self):
        with tempfile.TemporaryDirectory() as workspace:
            repository = Path(workspace)
            shutil.copytree(REPO / "account", repository / "account")
            initial = {path.relative_to(repository): yaml.safe_load(path.read_text(encoding="utf-8"))
                       for path in (repository / "account").rglob("*.yaml")}
            with patch.object(gen_template, "ROOT", repository), patch.object(
                gen_template, "T", repository / "domains/_template"
            ), patch.object(sys, "argv", ["gen_template.py"]), contextlib.redirect_stdout(io.StringIO()):
                gen_template.main()
                first_run = {path.relative_to(repository): path.read_bytes()
                             for path in repository.rglob("*.yaml")}
                gen_template.main()
            self.assertEqual(first_run, {path.relative_to(repository): path.read_bytes()
                                        for path in repository.rglob("*.yaml")})
            for relative_path, data in initial.items():
                self.assertEqual(yaml.safe_load((repository / relative_path).read_text(encoding="utf-8")), data)
            for path in (repository / "domains/_template").rglob("*.yaml"):
                if path.name != "domain.yaml":
                    self.assertIsNone(yaml.safe_load(path.read_text(encoding="utf-8")), str(path))


if __name__ == "__main__":
    unittest.main()
