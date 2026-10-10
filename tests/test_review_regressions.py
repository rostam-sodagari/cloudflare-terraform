"""Behavior regressions discovered by the project review."""
import argparse
import contextlib
import io
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))
import yaml
from exporting import publish
from exporting.client import NotFound
from validation.account import validate_account
from validation.domain import validate_domain
from validation.reporting import Report
from workflow import resync
from workflow.files import configuration_transaction, resolve_root, confined_path


class EmptyAccountClient:
    def pages(self, endpoint):
        return self.result(endpoint)

    def result(self, endpoint):
        if endpoint.endswith('/rules/lists') or endpoint.endswith('/logpush/jobs'):
            return []
        raise NotFound(endpoint)


class ReviewRegressionsTest(unittest.TestCase):
    def setUp(self):
        workspace = tempfile.TemporaryDirectory()
        self.addCleanup(workspace.cleanup)
        self.repository = Path(workspace.name)

    def account(self):
        account = self.repository / 'account'
        shutil.copytree(REPO / 'account', account, ignore=shutil.ignore_patterns('.terraform', 'imports.tf', '.imports.tf.skip'))
        return account

    def test_authoritative_empty_account_services_clear_stale_yaml(self):
        account = self.account()
        stale = ('waf/custom-rules.yaml', 'waf/rate-limits.yaml', 'waf/managed-rules.yaml', 'settings/logpush.yaml')
        for filename in stale:
            (account / filename).write_text('old: true\n')
        args = argparse.Namespace(account_id='a' * 32, plan='enterprise')
        with contextlib.redirect_stdout(io.StringIO()):
            result = publish.export_account(EmptyAccountClient(), args, repository_root=self.repository, validator=lambda _: 0)
        self.assertEqual(result, 0)
        for filename in stale:
            self.assertIsNone(yaml.safe_load((account / filename).read_text()))

    def test_account_validation_failure_preserves_all_configuration(self):
        account = self.account()
        before = {path.relative_to(account): path.read_bytes() for path in account.rglob('*') if path.is_file()}
        args = argparse.Namespace(account_id='a' * 32, plan='enterprise')
        checked = []
        def reject(candidate):
            checked.append(candidate)
            self.assertNotEqual(candidate, account)
            return 1
        with contextlib.redirect_stdout(io.StringIO()):
            result = publish.export_account(EmptyAccountClient(), args, repository_root=self.repository, validator=reject)
        self.assertEqual(result, 1)
        self.assertEqual(len(checked), 1)
        self.assertEqual(before, {path.relative_to(account): path.read_bytes() for path in account.rglob('*') if path.is_file()})

    def test_unreadable_logpush_preserves_existing_configuration(self):
        class Client(EmptyAccountClient):
            def result(self, endpoint):
                if endpoint.endswith('/logpush/jobs'):
                    raise PermissionError('not readable')
                return super().result(endpoint)
        account = self.account()
        target = account / 'settings/logpush.yaml'
        original = target.read_bytes()
        with contextlib.redirect_stdout(io.StringIO()):
            publish.export_account(Client(), argparse.Namespace(account_id='a' * 32, plan='enterprise'), repository_root=self.repository, validator=lambda _: 0)
        self.assertEqual(target.read_bytes(), original)

    def test_transaction_restores_changed_deleted_and_new_configuration(self):
        directory = self.repository / 'example.test'
        directory.mkdir()
        old = directory / 'old.yaml'
        main = directory / 'main.tf'
        old.write_bytes(b'original\r\n')
        main.write_bytes(b'original terraform')
        with self.assertRaises(SystemExit):
            with configuration_transaction(directory):
                old.write_bytes(b'changed')
                main.unlink()
                (directory / 'new.yaml').write_text('new')
                raise SystemExit('guard failed')
        self.assertEqual(old.read_bytes(), b'original\r\n')
        self.assertEqual(main.read_bytes(), b'original terraform')
        self.assertFalse((directory / 'new.yaml').exists())

    def test_committed_configuration_is_kept_if_push_fails(self):
        target = self.repository / 'file.yaml'
        target.write_text('before')
        with self.assertRaises(SystemExit):
            with configuration_transaction(self.repository, committed=lambda: True):
                target.write_text('committed')
                raise SystemExit('push failed')
        self.assertEqual(target.read_text(), 'committed')

    def test_failed_git_add_never_commits_or_pushes(self):
        calls = []
        def git(*arguments):
            calls.append(arguments)
            return argparse.Namespace(returncode=int(arguments[0] == 'add'), stdout='', stderr='failed')
        args = argparse.Namespace(root='account', bot_name='bot', bot_email='bot@example.test', branch='main')
        with patch.object(resync, 'git', side_effect=git), self.assertRaises(SystemExit):
            resync._commit_resync(args, 'account', ' M account/file.yaml')
        self.assertFalse(any(arguments[0] in {'commit', 'push'} for arguments in calls))

    def test_root_paths_reject_absolute_traversal_and_scratch_escape(self):
        for name in ('../outside', str(self.repository), 'a/b', '..', '/tmp/outside'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                resolve_root(self.repository, name)
        with self.assertRaises(ValueError):
            confined_path(self.repository / '.export', '..', 'outside')
        self.assertEqual(resolve_root(self.repository, 'example.test'), self.repository / 'domains/example.test')

    def test_empty_export_manifest_clears_managed_zone_service(self):
        stage, live = self.repository / 'stage', self.repository / 'live'
        for directory in (stage, live):
            (directory / 'waf').mkdir(parents=True)
        (stage / 'waf/custom-rules.yaml').write_text('# empty\n')
        (stage / '.exported-files.json').write_text(json.dumps(['waf/custom-rules.yaml']))
        (live / 'waf/custom-rules.yaml').write_text('- ref: old\n')
        resync.copy_yaml(stage, live)
        self.assertIsNone(yaml.safe_load((live / 'waf/custom-rules.yaml').read_text()))

    def test_symlinked_service_cannot_publish_outside_its_root(self):
        stage, live, outside = (self.repository / name for name in ('stage', 'live', 'outside'))
        (stage / 'waf').mkdir(parents=True)
        live.mkdir()
        outside.mkdir()
        try:
            (live / 'waf').symlink_to(outside, target_is_directory=True)
        except OSError:
            self.skipTest('directory symlinks are unavailable for this Windows user')
        target = outside / 'custom-rules.yaml'
        target.write_text('outside configuration')
        (stage / 'waf/custom-rules.yaml').write_text('- ref: replacement\n')
        with self.assertRaises(ValueError):
            resync.copy_yaml(stage, live)
        self.assertEqual(target.read_text(), 'outside configuration')

    def test_nested_malformed_domain_inputs_report_errors_without_crashing(self):
        cases = {
            'security/ip-access-rules.yaml': {'bad': None},
            'security/ct-alerting.yaml': {'enabled': True, 'emails': 123},
            'waf/managed-rules.yaml': {'exceptions': 123},
            'waf/custom-rules.yaml': [{'ref': 'r', 'expression': 'true', 'action': 'skip', 'skip': {'phases': 123}}],
            'dns/spf.yaml': {'@': {'ip4': 123, 'extra': 123}},
            'dns/dmarc.yaml': {'@': None},
            'dns/caa.yaml': {'bad': {'value': 123, 'tag': 'issue', 'flags': 0}},
            'dns/email-routing.yaml': {'enabled': True, 'rules': [None, {'ref': [], 'matchers': 123, 'actions': 123}]},
        }
        domain = self.repository / 'example.test'
        domain.mkdir()
        (domain / 'domain.yaml').write_text('name: example.test\nzone_id: "' + 'a' * 32 + '"\nplan: enterprise\n')
        for filename, value in cases.items():
            target = domain / filename
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(yaml.safe_dump(value))
        report = Report()
        validate_domain(report, domain, set())
        error_files = {Path(item[1]).relative_to(domain).as_posix() for item in report.errors}
        # Null DMARC means defaults and may emit policy warnings; all invalid
        # typed children must still have their own error diagnostics.
        self.assertTrue(set(cases) - {'dns/dmarc.yaml'} <= error_files)

    def test_null_account_notification_and_logpush_entries_do_not_crash(self):
        account = self.account()
        for filename in ('settings/logpush.yaml', 'settings/notifications.yaml'):
            (account / filename).write_text('bad: null\n')
        report = Report()
        validate_account(report, account)
        self.assertTrue(report.errors)


if __name__ == '__main__':
    unittest.main()
