"""Production invariants: complete reads, identity, review, and state-only writes."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))
from exporting.client import Client, NotFound, retry_delay
from exporting.identities import Identities
from validation.schema import check_rule_schema
from validation.reporting import Ctx, Report
from workflow.coverage import services
from workflow.inventory import canonical, collect, differences, record, require_complete
from workflow.semantics import bindings, effects, state_only
from workflow import reconciliation
from workflow.journal import Journal, Conflict
from workflow.inventory import unresolved, require_preserved
from workflow.semantics import digest
from workflow.semantics import sensitive_pair, reported_effects
from exporting.services import ZoneExport
from exporting.secrets import sensitive_destination
import change_gate
import ci_review


class ProductionContractsTest(unittest.TestCase):
    def test_development_countdown_does_not_hide_real_setting_changes(self):
        original = {"id": "development_mode", "value": "on", "time_remaining": 100}
        later = {**original, "time_remaining": 90}
        self.assertEqual(canonical(original), canonical(later))
        self.assertNotEqual(canonical(original), canonical({**later, "value": "off"}))
        self.assertIn("time_remaining", canonical({"id": "other_setting", "time_remaining": 100}))

    def test_certificate_deployment_status_is_retained_without_configuration_drift(self):
        pack = {"id": "pack", "type": "universal", "hosts": ["example.com"], "status": "active",
                "certificates": [{"id": "certificate", "status": "active"}]}
        class Fake:
            def result(self, path):
                if path.endswith("/ssl/certificate_packs"):
                    return [pack]
                raise NotFound(path)
            pages = result
        root = REPO / "tests/fixtures/domains/example.com"
        before = collect(Fake(), root)
        pack["status"] = "pending_deployment"
        pack["certificates"][0]["status"] = "pending_deployment"
        after = collect(Fake(), root)
        self.assertEqual(before["digest"], after["digest"])
        self.assertEqual(differences(after, record(before)), [])
        self.assertEqual(after["runtime"]["certificate-packs"][0]["status"], "pending_deployment")
        pack["hosts"] = ["changed.example.com"]
        changed = collect(Fake(), root)
        self.assertEqual(differences(changed, record(before)), ["certificate-packs"])
        self.assertNotEqual(canonical({"status": "active"}), canonical({"status": "disabled"}))

    def journal(self, current=None):
        journal = object.__new__(Journal)
        journal.owner = 'new-run'
        journal.verify_conditions = lambda: None
        storage = {'value': current or {}, 'tag': 'version-1' if current else None}
        def request(method, value=None, condition=None):
            if method == 'GET':
                return copy.deepcopy(storage['value']), storage['tag']
            self.assertEqual(condition, storage['tag'] or '*')
            storage.update(value=copy.deepcopy(value), tag='version-2')
            return {}, storage['tag']
        journal.request = request
        return journal, storage

    def test_storage_probe_detects_ignored_conditions_without_touching_state_or_journal(self):
        for honors_conditions in (True, False):
            journal = object.__new__(Journal)
            journal.key = 'operations/domain.json'
            storage = {}
            def request(method, value=None, condition=None):
                key = journal_request_owner[0].key
                if method == 'GET':
                    value = storage.get(key)
                    return value, digest(value) if value else None
                if method == 'DELETE':
                    storage.pop(key, None)
                    return {}, None
                existing = storage.get(key)
                if honors_conditions and ((condition == '*' and existing is not None) or
                        (condition != '*' and condition != digest(existing))):
                    raise Conflict('conditional conflict')
                storage[key] = value
                return {}, digest(value)
            # Bind the request to each copied probe so its isolated key is used.
            from types import MethodType
            def bound_request(owner, *args):
                journal_request_owner[0] = owner
                return request(*args)
            journal_request_owner = [journal]
            journal.request = MethodType(bound_request, journal)
            with patch('workflow.journal.copy.copy', side_effect=lambda original: self.copy_journal(original, bound_request)):
                if honors_conditions:
                    journal.verify_conditions()
                else:
                    with self.assertRaisesRegex(RuntimeError, 'ignored a conditional'):
                        journal.verify_conditions()
            self.assertEqual(storage, {})

    @staticmethod
    def copy_journal(original, request):
        from types import MethodType
        result = object.__new__(Journal)
        result.__dict__.update(original.__dict__)
        result.request = MethodType(request, result)
        return result

    def test_failed_apply_blocks_resync_but_accepts_a_newly_reviewed_recovery(self):
        current = {'phase': 'apply-failed', 'updated': '2026-10-10T12:00:00Z', 'owner': 'previous'}
        journal, storage = self.journal(current)
        with self.assertRaisesRegex(RuntimeError, 'incomplete approved deployment'):
            journal.start('resync')
        with self.assertRaisesRegex(RuntimeError, 'newly reviewed'):
            journal.start('apply', reviewed_at='2026-10-10T11:00:00Z')
        self.assertEqual(storage['value'], current)
        journal.start('pending', reviewed_at='2026-10-10T13:00:00Z')
        self.assertEqual(storage['value']['phase'], 'approved-pending')
        journal.start('apply', reviewed_at='2026-10-10T13:00:00Z')
        self.assertEqual(storage['value']['phase'], 'applying')
        journal.finish('complete', observed={'hash': 'current'})
        self.assertEqual(storage['value']['observed'], {'hash': 'current'})

    def test_journal_cannot_finish_another_runs_operation(self):
        journal, storage = self.journal({'owner': 'other', 'phase': 'applying'})
        with self.assertRaisesRegex(RuntimeError, 'different run'):
            journal.finish('complete')
        self.assertEqual(storage['value']['phase'], 'applying')

    def test_journal_rejects_existing_objects_without_etags(self):
        journal, _ = self.journal()
        journal.request = lambda *args: ({'phase': 'complete'}, None)
        with self.assertRaisesRegex(RuntimeError, 'ETag'):
            journal.start('resync')

    def test_interrupted_workflow_is_checked_before_any_recovery_write(self):
        journal, storage = self.journal({'owner': '123', 'repository': 'org/repo',
                                        'phase': 'applying', 'updated': '2026-10-10T12:00:00Z'})
        from types import SimpleNamespace
        for status in ('in_progress', 'completed'):
            with patch('workflow.journal.subprocess.run', return_value=SimpleNamespace(returncode=0, stdout=json.dumps({'status': status}))):
                with self.assertRaises(RuntimeError):
                    journal.start('resync')
        self.assertEqual(storage['value']['owner'], '123')

    def test_inventory_excludes_supported_entrypoints_and_runtime_managed_rulesets_from_gaps(self):
        class Fake:
            def result(self, path):
                if path.endswith('/rulesets'):
                    return [{'id': 'supported', 'phase': 'http_request_firewall_custom', 'kind': 'zone'},
                            {'id': 'managed', 'kind': 'managed'}, {'id': 'unsupported', 'kind': 'custom'}]
                if path.endswith('/rulesets/unsupported'):
                    return {'id': 'unsupported', 'rules': [{'action': 'block'}]}
                raise NotFound(path)
            pages = result
        snapshot = collect(Fake(), REPO / 'tests/fixtures/domains/example.com')
        self.assertEqual(snapshot['observations']['other-rulesets']['value'][0]['id'], 'unsupported')
        self.assertEqual(unresolved(snapshot), ['other-rulesets'])

    def test_pipeline_baseline_does_not_report_its_own_changes(self):
        snapshot = {'identity': 'zone', 'observations': {'dns': {'status': 'ok', 'exportable': True, 'value': [{'id': 'record', 'content': '192.0.2.2'}]}}}
        self.assertEqual(differences(snapshot, record(snapshot)), [])

    def test_unsupported_fields_and_record_types_remain_visible_after_baselining(self):
        from workflow.inventory import gaps
        snapshot = {'identity': 'zone', 'observations': {'dns': {'status': 'ok', 'exportable': True,
            'value': [{'id': 'record', 'type': 'A', 'tags': ['keep']}, {'id': 'other', 'type': 'HTTPS'}]}}}
        self.assertEqual(differences(snapshot, record(snapshot)), [])
        self.assertEqual(len(gaps(snapshot)), 2)
        self.assertIn('unsupported fields', gaps(snapshot)[0])
        self.assertIn('unsupported record type HTTPS', gaps(snapshot)[1])

    def test_journal_signs_conditional_headers_and_classifies_conflicts(self):
        import urllib.error
        journal = object.__new__(Journal)
        journal.endpoint, journal.bucket, journal.key = 'https://storage.example.com', 'state', 'operations/root.json'
        with patch.dict('os.environ', {'AWS_ACCESS_KEY_ID': 'fixture-key', 'AWS_SECRET_ACCESS_KEY': 'fixture-secret'}):
            for condition, header in (('*', 'If-none-match'), ('"version"', 'If-match')):
                error = urllib.error.HTTPError('https://storage.example.com', 412, 'precondition', {}, None)
                with patch('workflow.journal.urllib.request.urlopen', side_effect=error) as request:
                    with self.assertRaises(Conflict):
                        journal.request('PUT', {'phase': 'applying'}, condition)
                signed = request.call_args.args[0]
                self.assertEqual(signed.get_header(header), condition)
                self.assertIn(header.lower(), signed.get_header('Authorization'))
                self.assertEqual(signed.full_url, 'https://storage.example.com/state/operations/root.json')
                self.assertEqual(json.loads(signed.data), {'phase': 'applying'})
                self.assertNotIn('fixture-secret', signed.get_header('Authorization'))

    def test_merged_deployment_requires_matching_artifact_inputs_inventory_and_effects(self):
        from types import SimpleNamespace
        pull = {'number': 7, 'head': {'sha': 'reviewed-head'}, 'user': {'login': 'author'}}
        reviewer = {'user': {'login': 'second-user'}, 'state': 'APPROVED', 'commit_id': 'reviewed-head',
                    'submitted_at': '2026-10-10T12:01:00Z'}
        reviewed = {'root': 'account', 'pr': '7', 'head': 'reviewed-head', 'created': '2026-10-10T12:00:00Z',
                    'inventory': 'live-inventory', 'inputs': {}, 'effects_digest': digest([])}
        for mismatch in (None, 'inputs', 'inventory', 'effects_digest', 'head'):
            with self.subTest(mismatch=mismatch), tempfile.TemporaryDirectory() as directory:
                root = Path(directory) / 'account'
                root.mkdir()
                (root / 'plan.json').write_text('{}')
                (root / '.plan-input.sha256').write_text('{"artifacts": {}}')
                artifact = copy.deepcopy(reviewed)
                if mismatch:
                    artifact[mismatch] = {'different': 'input'} if mismatch == 'inputs' else 'different'
                def download(arguments, **kwargs):
                    (Path(arguments[-1]) / '.review.json').write_text(json.dumps(artifact))
                    return SimpleNamespace(returncode=0)
                evidence = [
                    [{'workflow_runs': [{'id': 100, 'conclusion': 'success', 'head_sha': 'reviewed-head',
                                         'pull_requests': [{'number': 7}]}]}],
                    [{'artifacts': [{'name': 'review-7-reviewed-head-account', 'expired': False}]}],
                    [[reviewer]], {'permission': 'write'},
                ]
                snapshot = {'digest': 'live-inventory', 'identity': 'account-id', 'observations': {}, 'problems': []}
                with patch.dict('os.environ', {'GITHUB_REPOSITORY': 'owner/repo', 'GITHUB_SHA': 'merged-sha', 'CLOUDFLARE_API_TOKEN': 'fixture'}), \
                     patch.object(ci_review, 'ROOT', Path(directory)), patch.object(ci_review, 'merged_pr', return_value=pull), \
                     patch.object(ci_review, 'gh', side_effect=evidence), patch.object(ci_review.subprocess, 'run', side_effect=download), \
                     patch.object(ci_review, 'collect', return_value=snapshot), patch.object(ci_review, 'schema', return_value={'provider_schemas': {}}), \
                     patch.object(ci_review, 'plan_input_digests', return_value={}), patch('workflow.journal.Journal') as journal:
                    if mismatch:
                        with self.assertRaises(RuntimeError):
                            ci_review.verify(root)
                        journal.assert_not_called()
                    else:
                        ci_review.verify(root)
                        journal.return_value.start.assert_called_once_with('pending', revision='merged-sha', reviewed_at=reviewed['created'])

    def test_short_server_pages_use_total_count_without_losing_records(self):
        client = Client('fixture')
        with patch.object(client, 'get', side_effect=[{'result': [{'id': 'one'}], 'result_info': {'total_count': 2}},
                                                    {'result': [{'id': 'two'}], 'result_info': {'total_count': 2}}]):
            self.assertEqual(len(client.pages('/records')), 2)

    def test_state_reconciliation_imports_and_removes_bindings_without_mutations(self):
        with tempfile.TemporaryDirectory() as directory:
            empty = {'resource_changes': []}
            imported = {'resource_changes': [{'change': {'actions': ['no-op'], 'importing': {'id': 'new-dashboard-record'}}}]}
            with patch.object(reconciliation, 'execute') as execute, patch.object(reconciliation, 'terraform', side_effect=[
                    json.dumps({'lineage': 'existing-lineage', 'serial': 9}), json.dumps(imported), json.dumps(empty)]):
                reconciliation.reconcile(Path(directory))
            applies = [call.args[1] for call in execute.call_args_list if call.args[1][0] == 'apply']
            self.assertEqual([command[-1] for command in applies], ['.refresh.bin', '.reconcile.bin'])
            checkpoint = json.loads((Path(directory) / '.reconciliation.json').read_text())
            self.assertEqual(checkpoint['lineage'], 'existing-lineage')
            self.assertEqual(checkpoint['phase'], 'state-reconciled')

    def test_a_record_update_cannot_discard_unsupported_dashboard_fields(self):
        snapshot = {'observations': {'dns': {'status': 'ok', 'value': [{'id': 'record', 'tags': ['owner:team']}]}}}
        with self.assertRaisesRegex(RuntimeError, 'unsupported configuration'):
            require_preserved(snapshot, {'resource_changes': [{'address': 'record', 'change': {'actions': ['update'], 'before': {'id': 'record'}}}]})

    def test_logpush_credentials_are_not_exported_as_yaml_values(self):
        self.assertTrue(sensitive_destination('https://logs.example.com?token=private'))
        self.assertTrue(sensitive_destination('https://user:password@logs.example.com'))
        self.assertFalse(sensitive_destination('s3://bucket/path?region=eu-west-2'))

    def test_sensitive_summaries_keep_real_change_visibility_without_exposing_values(self):
        before, after = sensitive_pair({'endpoint': 'old-secret'}, {'endpoint': 'new-secret'}, {'endpoint': True}, {'endpoint': True})
        self.assertNotEqual(before, after)
        self.assertNotIn('secret', json.dumps([before, after]))
        before, after = sensitive_pair({'endpoint': 'same-secret'}, {'endpoint': 'same-secret'}, {'endpoint': True}, {'endpoint': True})
        self.assertEqual(before, after)
        self.assertIsNone(sensitive_pair({'name': 'deleted'}, None)[1])
        values = sensitive_pair(None, [{'endpoint': 'private'}], False, [{'endpoint': True}])
        self.assertNotIn('private', json.dumps(values))
        import plan_summary
        plan = {'resource_changes': [{'address': 'hook', 'type': 'cloudflare_notification_policy_webhooks',
                                      'change': {'actions': ['update'], 'before': {'url': 'old-private'},
                                                 'after': {'url': 'new-private'}, 'before_sensitive': {'url': True},
                                                 'after_sensitive': {'url': True}}}]}
        report = str(plan_summary.summarise(plan))
        self.assertNotIn('old-private', report)
        self.assertNotIn('new-private', report)
        self.assertIn('url', report)
        self.assertIn('redacted before', report)

    def test_webhook_delivery_activity_is_not_configuration_drift(self):
        before = {'name': 'hook', 'last_success': 'before', 'last_failure': None, 'url': 'https://example.com/hook'}
        self.assertEqual(canonical(before), canonical({**before, 'last_success': 'after', 'last_failure': 'now'}))
        self.assertNotEqual(canonical(before), canonical({**before, 'url': 'https://other.example.com/hook'}))

    def test_registrar_mutations_are_blocked_when_the_api_cannot_verify_them(self):
        with self.assertRaisesRegex(RuntimeError, 'Registrar changes cannot be verified'):
            require_preserved({'observations': {}}, {'resource_changes': [{'type': 'cloudflare_registrar_domain', 'change': {'actions': ['update']}}]})

    def test_change_gate_checks_exact_identity_and_real_timezones(self):
        import datetime
        now = datetime.datetime(2026, 10, 10, 12, tzinfo=datetime.timezone.utc)
        change = {'id': 123, 'approval_status': 1, 'planned_start_date': '2026-10-10T12:30:00+01:00',
                  'planned_end_date': '2026-10-10T13:30:00+01:00'}
        change_gate.validate('CHG-00123', {'change': change}, now)
        for invalid in ({**change, 'id': 124}, {**change, 'approval_status': 0},
                        {**change, 'planned_start_date': '2026-10-10T11:30:00'}, {**change, 'planned_end_date': '2026-10-10T11:00:00Z'}):
            with self.assertRaises(ValueError):
                change_gate.validate('CHG-00123', {'change': invalid}, now)

    def test_every_service_yaml_has_declared_coverage(self):
        for account in (False, True):
            directory = REPO / "account" if account else REPO / "domains/_template"
            files = {path.relative_to(directory).as_posix() for path in directory.rglob("*.yaml")}
            files.discard("account.yaml" if account else "domain.yaml")
            self.assertEqual(files, {file for service in services(account) for file in service.files})

    def test_existing_ids_reserve_keys_before_new_records_are_exported(self):
        identities = Identities({"zone/old": 'module.dns.cloudflare_dns_record.this["a/www"]'})
        used = set()
        self.assertEqual(identities.key("a", "www", "zone/new", used), "www_2")
        self.assertEqual(identities.key("a", "www", "zone/old", used), "www")
        self.assertEqual(identities.key("a", "www", "zone/third", used), "www_3")

    def test_nested_primitive_collections_validate_their_elements(self):
        for value in ({"unexpected": "mapping"}, [True], ["valid", {}]):
            report = Report()
            check_rule_schema(Ctx(report, "fixture.yaml", {}, "free"), (), value, '["list", "string"]')
            self.assertTrue(report.errors)
        report = Report()
        check_rule_schema(Ctx(report, "fixture.yaml", {}, "free"), (), {"group": ["a"]}, '["map", ["list", "string"]]')
        self.assertFalse(report.errors)

    def test_failed_reads_are_not_empty_configuration(self):
        class Unreadable:
            def result(self, path):
                raise PermissionError("no read permission")
            pages = result
        snapshot = collect(Unreadable(), REPO / "tests/fixtures/domains/example.com")
        self.assertTrue(snapshot["problems"])
        self.assertTrue(all(item["status"] == "unreadable" for item in snapshot["observations"].values()))
        with self.assertRaises(RuntimeError):
            require_complete(snapshot)

    def test_timestamp_noise_does_not_hide_writable_fields(self):
        before = {"id": "same", "modified_on": "before", "enabled": False, "rules": [{"expression": "a", "version": "1"}]}
        after = {**before, "modified_on": "after"}
        self.assertEqual(canonical(before), canonical(after))
        self.assertNotEqual(canonical(before), canonical({**after, "enabled": True}))
        self.assertNotEqual(canonical(before), canonical({**after, "rules": [{"expression": "a", "version": "2"}]}))

    def test_inventory_record_retains_no_secret_values(self):
        snapshot = {"identity": "id", "observations": {"webhooks": {
            "status": "ok", "exportable": False, "value": {"secret": "private-value"}}}}
        baseline = record(snapshot)
        self.assertNotIn("private-value", json.dumps(baseline))
        self.assertEqual(differences(snapshot, baseline), [])
        changed = copy.deepcopy(snapshot)
        changed["observations"]["webhooks"]["value"]["secret"] = "rotated"
        self.assertEqual(differences(changed, baseline), ["webhooks"])

    def test_paginated_reads_reject_repeated_pages_and_wrong_counts(self):
        client = Client("fixture")
        with patch.object(client, "get", return_value={"result": [{"id": "one"}], "result_info": {"total_pages": 2}}):
            with self.assertRaisesRegex(RuntimeError, "repeated page"):
                client.pages("/records", 1)
        with patch.object(client, "get", return_value={"result": [], "result_info": {"total_pages": 1, "total_count": 2}}):
            with self.assertRaisesRegex(RuntimeError, "count"):
                client.pages("/records")
        with patch.object(client, 'get', side_effect=[
            {'result': [{'id': 'one'}, {'id': 'two'}], 'result_info': {'total_pages': 2, 'total_count': 4}},
            {'result': [{'id': 'two'}, {'id': 'three'}], 'result_info': {'total_pages': 2, 'total_count': 4}},
        ]):
            with self.assertRaisesRegex(RuntimeError, 'overlapping object IDs'):
                client.pages('/records', 2)

    def test_cursor_inventory_rejects_overlapping_ids(self):
        from workflow.inventory import cursor_items
        client = Client('fixture')
        with patch.object(client, 'get', side_effect=[
            {'result': [{'id': 'one'}], 'result_info': {'cursors': {'after': 'next'}}},
            {'result': [{'id': 'one'}]},
        ]):
            with self.assertRaisesRegex(RuntimeError, 'overlapping object IDs'):
                cursor_items(client, '/items')

    def test_import_addresses_escape_quotes_and_hcl_interpolation(self):
        from exporting.output import indexed, write_imports
        key = 'name"${private}%{directive}'
        address = indexed('module.notifications.cloudflare_notification_policy_webhooks.this', key)
        self.assertIn('\\"$${private}%%{directive}', address)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'imports.tf'
            write_imports(path, [(address, 'account/${private}')])
            self.assertIn('account/$${private}', path.read_text())

    def test_disabled_email_is_forgotten_only_when_live_state_confirms_same_zone(self):
        deletion = {'resource_changes': [{'address': 'module.email.cloudflare_email_routing_settings.this[0]',
            'type': 'cloudflare_email_routing_settings', 'mode': 'managed',
            'change': {'actions': ['delete'], 'before': {'zone_id': 'zone'}}}]}
        for enabled, identity, allowed in ((False, 'zone', True), (True, 'zone', False), (False, 'other', False)):
            with self.subTest(enabled=enabled, identity=identity), tempfile.TemporaryDirectory() as directory:
                snapshot = {'identity': identity, 'observations': {'email-settings': {'status': 'ok', 'value': {'enabled': enabled}}}}
                responses = [json.dumps({}), json.dumps(deletion)] + ([json.dumps({}), json.dumps({})] if allowed else [])
                with patch.object(reconciliation, 'execute') as execute, patch.object(reconciliation, 'terraform', side_effect=responses):
                    if allowed:
                        reconciliation.reconcile(Path(directory), snapshot)
                    else:
                        with self.assertRaisesRegex(RuntimeError, 'would change Cloudflare'):
                            reconciliation.reconcile(Path(directory), snapshot)
                removals = [call.args[1] for call in execute.call_args_list if call.args[1][:2] == ['state', 'rm']]
                self.assertEqual(bool(removals), allowed)

    def test_retry_after_is_bounded(self):
        self.assertEqual(retry_delay("999999", 0), 30)
        self.assertEqual(retry_delay("-100", 0), 0)
        self.assertEqual(retry_delay("invalid", 2), 4)

    def test_state_only_rejects_import_and_update(self):
        change = {"mode": "managed", "change": {"actions": ["update"], "importing": {"id": "existing"}}}
        self.assertFalse(state_only({"resource_changes": [change]}))
        change["change"]["actions"] = ["no-op"]
        self.assertTrue(state_only({"resource_changes": [change]}))

    def test_reconciliation_never_applies_a_mutation_plan(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan = {"resource_changes": [{"mode": "managed", "change": {"actions": ["delete"]}}]}
            with patch.object(reconciliation, "execute") as execute, patch.object(reconciliation, "terraform", return_value=json.dumps(plan)):
                with self.assertRaisesRegex(RuntimeError, "would change Cloudflare"):
                    reconciliation.reconcile(root)
                self.assertFalse(any(call.args[1][-1] == ".reconcile.bin" and call.args[1][0] == "apply" for call in execute.call_args_list))
            self.assertEqual(json.loads((root / ".reconciliation.json").read_text())["phase"], "blocked-live-mutation")

    def test_only_a_second_users_current_review_can_authorize(self):
        pull = {"user": {"login": "author"}, "head": {"sha": "current"}}
        review = {"user": {"login": "reviewer"}, "state": "APPROVED", "commit_id": "current", "submitted_at": "2026-10-10T12:01:00Z"}
        self.assertEqual(ci_review.approvers(pull, [review], "2026-10-10T12:00:00Z"), ["reviewer"])
        for invalid in ({**review, "user": {"login": "author"}}, {**review, "commit_id": "old"},
                        {**review, "submitted_at": "2026-10-10T11:00:00Z"}, {**review, "state": "DISMISSED"}):
            with self.assertRaises(RuntimeError):
                ci_review.approvers(pull, [invalid], "2026-10-10T12:00:00Z")

    def test_computed_fields_are_filtered_only_by_provider_schema(self):
        attributes = {"id": {"computed": True}, "enabled": {"optional": True}, "settings": {"optional": True}, "tags": {"optional": True}}
        schema = {"provider_schemas": {"provider": {"resource_schemas": {"resource": {"block": {"attributes": attributes}}}}}}
        change = {"provider_name": "provider", "type": "resource", "address": "one", "change": {
            "actions": ["update"], "before": {"id": "old", "enabled": False, "settings": {}, "tags": []},
            "after": {"id": "new", "enabled": True, "settings": {"ipv4_only": True}, "tags": ["team"]}}}
        result = effects({"resource_changes": [change]}, schema)[0]
        self.assertNotIn("id", result["after"])
        self.assertEqual(result["after"]["settings"], {"ipv4_only": True})
        self.assertEqual(result["after"]["tags"], ["team"])
        self.assertTrue(result["after"]["enabled"])

    def test_bindings_include_full_import_identity(self):
        state = {"values": {"root_module": {"resources": [{"address": "record", "mode": "managed", "values": {"id": "object", "zone_id": "zone"}}]}}}
        self.assertEqual(bindings(state)["zone/object"], "record")

    def test_workflow_cancelled_dependencies_cannot_authorize_domains(self):
        import yaml
        workflow = yaml.safe_load((REPO / ".github/workflows/cloudflare.yml").read_text())
        condition = workflow["jobs"]["apply-domains"]["if"]
        self.assertIn("needs.apply-account.result == 'success'", condition)
        self.assertNotIn("!= 'failure'", condition)
        self.assertIn("deployable == 'true'", condition)


if __name__ == "__main__":
    unittest.main()
