"""Ensure package moves preserve path isolation and saved-plan inputs."""
import importlib.util
import sys
import tempfile
import types
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))
from repository_paths import repository_root
from workflow.integrity import plan_input_digests


class PackagePathsTest(unittest.TestCase):
    def test_nested_modules_resolve_each_repository_copy(self):
        with tempfile.TemporaryDirectory() as workspace:
            roots = [Path(workspace) / name for name in ("first", "second")]
            for root in roots:
                (root / "scripts" / "exporting").mkdir(parents=True)
                (root / "cf.py").write_text("", encoding="utf-8")
                source = root / "scripts" / "exporting" / "client.py"
                source.write_text("", encoding="utf-8")
                self.assertEqual(repository_root(source), root)
                self.assertEqual(repository_root(root / "cf.py"), root)

    def test_package_file_changes_are_in_saved_plan_inputs(self):
        with tempfile.TemporaryDirectory() as workspace:
            repository = Path(workspace)
            source = repository / "scripts" / "exporting" / "client.py"
            source.parent.mkdir(parents=True)
            source.write_text("VALUE = 1\n", encoding="utf-8")
            root_dir = repository / "domains" / "example.com"
            root_dir.mkdir(parents=True)
            root = types.SimpleNamespace(dir=root_dir)
            before = plan_input_digests(root, repository)
            source.write_text("VALUE = 2\n", encoding="utf-8")
            after = plan_input_digests(root, repository)
            self.assertIn(source, before)
            self.assertNotEqual(before[source], after[source])

    def test_legacy_resync_and_audit_imports_keep_patchable_module_identity(self):
        import compliance_audit
        import deviation_autofix
        from audit import cli
        from workflow import resync
        self.assertIs(compliance_audit, cli)
        self.assertIs(deviation_autofix, resync)


if __name__ == "__main__":
    unittest.main()
