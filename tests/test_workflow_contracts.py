"""Protect saved-plan safety, apply ordering and shared-change selection."""
import argparse
import contextlib
import importlib.util
import io
import json
import os
import sys
import subprocess
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))
spec = importlib.util.spec_from_file_location("workflow_under_test", REPO / "cf.py")
cf = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cf)


class WorkflowContractsTest(unittest.TestCase):
    def setUp(self):
        workspace = tempfile.TemporaryDirectory()
        self.addCleanup(workspace.cleanup)
        self.repository = Path(workspace.name)
        self.root = types.SimpleNamespace(name="example.com", dir=self.repository / "domains" / "example.com")
        self.root.dir.mkdir(parents=True)
        (self.root.dir / "plan.bin").write_bytes(b"plan")
        (self.root.dir / "plan.json").write_text("{}", encoding="utf-8")
        self.args = argparse.Namespace(domain="example.com", backend="local", yes=True, deviation_exit=True)
        self.environment = patch.dict(os.environ, {}, clear=True)
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def test_cli_help_and_flags_match_original(self):
        expected = json.loads((REPO / "tests" / "golden" / "workflow_help.json").read_text(encoding="utf-8"))
        for command, help_text in expected.items():
            arguments = [command] + ([] if command == "help" else ["--help"])
            with self.subTest(command=command):
                result = subprocess.run([sys.executable, str(REPO / "cf.py"), *arguments], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                # argparse versions wrap long usage lines differently.
                # Preserve every option and the rest of the help verbatim.
                def normalize_usage(text):
                    usage, body = text.split("\n\n", 1)
                    return " ".join(usage.split()) + "\n\n" + body
                self.assertEqual(normalize_usage(result.stdout), normalize_usage(help_text))

    def test_terminal_help_lists_every_command_without_running_handlers(self):
        class TerminalOutput(io.StringIO):
            def isatty(self):
                return True

        output = TerminalOutput()
        parser = cf.build_parser(vars(cf), cf.__doc__)
        with patch.dict(os.environ, {"NO_COLOR": "1"}), contextlib.redirect_stdout(output):
            parser.print_help()
        help_text = output.getvalue()
        for group, commands in cf.terminal.COMMAND_GROUPS:
            self.assertIn(group, help_text)
            for command, _ in commands:
                self.assertIn(command, help_text)
        self.assertIn("<command> --help", help_text)
        self.assertNotIn("\033[", help_text)

    def test_machine_readable_commands_stay_plain_in_a_terminal(self):
        class TerminalOutput(io.StringIO):
            def isatty(self):
                return True

        for command in ("domains", "changed-domains"):
            with self.subTest(command=command):
                output = TerminalOutput()
                with patch.object(sys, "argv", ["cf.py", command]), patch.object(cf, "domains", return_value=["example.com"]), patch.object(cf, "changed_roots", return_value=["example.com"]), contextlib.redirect_stdout(output):
                    cf.main()
                expected = "example.com\n" if command == "domains" else '["example.com"]\n'
                self.assertEqual(output.getvalue(), expected)

    def test_terminal_colour_respects_stream_and_environment(self):
        terminal_stream = Mock()
        terminal_stream.isatty.return_value = True
        self.assertEqual(cf.terminal.colour(36, "message", terminal_stream), "\033[36mmessage\033[0m")
        with patch.dict(os.environ, {"NO_COLOR": "1"}):
            self.assertEqual(cf.terminal.colour(36, "message", terminal_stream), "message")
        with patch.dict(os.environ, {"TERM": "dumb"}):
            self.assertEqual(cf.terminal.colour(36, "message", terminal_stream), "message")
        self.assertEqual(cf.terminal.colour(36, "message", io.StringIO()), "message")

    def test_deviation_show_failure_never_writes_report_or_runs_summary(self):
        previous = self.root.dir / "deviation.json"
        previous.write_text('{"existing": true}', encoding="utf-8")
        success = types.SimpleNamespace(returncode=0, stdout="plan", stderr="")
        failure = types.SimpleNamespace(returncode=1, stdout="", stderr="unreadable plan")
        with patch.object(cf, "Rt", return_value=self.root), patch.object(cf, "tf_init"), patch.object(cf, "run_tf", side_effect=[success, failure]), patch.object(cf, "run_py") as summary, contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                cf.cmd_deviation_check(self.args)
        summary.assert_not_called()
        self.assertEqual(previous.read_text(encoding="utf-8"), '{"existing": true}')

    def test_shared_inputs_select_every_root_even_with_domain_changes(self):
        for filename in ("cf.py", "requirements.txt", "backend.hcl", "scripts/workflow/integrity.py"):
            with self.subTest(filename=filename), patch.object(cf, "all_roots", return_value=["account", "one.example", "two.example"]), patch.object(cf, "_git_diff", return_value=f"domains/one.example/dns/a.yaml\n{filename}\n"):
                self.assertEqual(cf.changed_roots(None, False), ["account", "one.example", "two.example"])

    def test_domain_changes_select_only_that_domain(self):
        with patch.object(cf, "all_roots", return_value=["account", "one.example", "two.example"]), patch.object(cf, "_git_diff", return_value="domains/one.example/dns/a.yaml\n"):
            self.assertEqual(cf.changed_roots(None, False), ["one.example"])

    def test_apply_checks_run_before_terraform_and_cleanup(self):
        events = []
        (self.root.dir / "plan.bin").write_bytes(b"plan")
        callbacks = {name: (lambda *args, name=name, **kwargs: events.append(name)) for name in ("validate", "check_plan_fingerprint", "verify_plan_json", "summarise", "forget")}
        def run(*args, **kwargs):
            events.append("apply")
            return types.SimpleNamespace(returncode=0)
        with patch.object(cf, "Rt", return_value=self.root), patch.multiple(cf, **callbacks), patch.object(cf, "run_tf", side_effect=run), contextlib.redirect_stdout(io.StringIO()):
            cf.cmd_apply(self.args)
        self.assertEqual(events, ["validate", "check_plan_fingerprint", "verify_plan_json", "summarise", "apply", "forget"])

    def test_failed_apply_guard_prevents_terraform(self):
        (self.root.dir / "plan.bin").write_bytes(b"plan")
        for guard in ("validate", "check_plan_fingerprint", "verify_plan_json", "summarise"):
            callbacks = {name: Mock() for name in ("validate", "check_plan_fingerprint", "verify_plan_json", "summarise")}
            callbacks[guard].side_effect = SystemExit(1)
            with self.subTest(guard=guard), patch.object(cf, "Rt", return_value=self.root), patch.multiple(cf, **callbacks), patch.object(cf, "run_tf") as terraform:
                with self.assertRaises(SystemExit):
                    cf.cmd_apply(self.args)
                terraform.assert_not_called()

    def test_new_script_invalidates_saved_plan(self):
        with patch.object(cf, "ROOT", self.repository), patch.object(cf, "plan_revision", return_value="revision"), contextlib.redirect_stderr(io.StringIO()):
            cf.save_plan_fingerprint(self.root, "local")
            scripts = self.repository / "scripts"
            scripts.mkdir()
            (scripts / "new_helper.py").write_text("VALUE = 1\n", encoding="utf-8")
            with self.assertRaises(SystemExit):
                cf.check_plan_fingerprint(self.root, "local")

    def test_revision_and_backend_changes_invalidate_saved_plan(self):
        with patch.object(cf, "ROOT", self.repository), patch.object(cf, "plan_revision", return_value="first"), contextlib.redirect_stderr(io.StringIO()):
            cf.save_plan_fingerprint(self.root, "local")
            with self.assertRaises(SystemExit):
                cf.check_plan_fingerprint(self.root, "r2")
            with patch.object(cf, "plan_revision", return_value="second"):
                with self.assertRaises(SystemExit):
                    cf.check_plan_fingerprint(self.root, "local")

    def test_missing_fingerprint_or_revision_is_refused(self):
        with patch.object(cf, "ROOT", self.repository), patch.object(cf, "plan_revision", return_value="revision"), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                cf.check_plan_fingerprint(self.root, "local")
            cf.save_plan_fingerprint(self.root, "local")
            (self.root.dir / ".plan-revision").unlink()
            with self.assertRaises(SystemExit):
                cf.check_plan_fingerprint(self.root, "local")

    def test_each_modified_artifact_is_refused(self):
        with patch.object(cf, "ROOT", self.repository), patch.object(cf, "plan_revision", return_value="revision"), contextlib.redirect_stderr(io.StringIO()):
            for name in ("plan.bin", "plan.json"):
                cf.save_plan_fingerprint(self.root, "local")
                artifact = self.root.dir / name
                artifact.write_bytes(artifact.read_bytes() + b"changed")
                with self.subTest(name=name), self.assertRaises(SystemExit):
                    cf.check_plan_fingerprint(self.root, "local")

    def test_binary_json_mismatch_and_show_failure_are_refused(self):
        for returncode, text in ((0, '{"different": true}'), (1, ""), (0, "invalid")):
            result = types.SimpleNamespace(returncode=returncode, stdout=text)
            with self.subTest(returncode=returncode, text=text), patch.object(cf, "run_tf", return_value=result), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    cf.verify_plan_json(self.root)

    def test_json_verification_accepts_equivalent_serialization(self):
        (self.root.dir / "plan.json").write_text('{"a": 1, "b": 2}')
        result = types.SimpleNamespace(returncode=0, stdout='{"b":2,"a":1}')
        with patch.object(cf, "run_tf", return_value=result):
            cf.verify_plan_json(self.root)


if __name__ == "__main__":
    unittest.main()
