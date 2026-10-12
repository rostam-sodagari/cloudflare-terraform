"""Local deployment regressions: truthful effects, complete reads, and recovery."""
import copy
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))
from workflow import local_review, recovery
from workflow.inventory import redact
from workflow.semantics import require_valid_plan, state_only
import plan_summary

PROVIDER = "registry.terraform.io/cloudflare/cloudflare"
TYPE = "cloudflare_dns_record"
ATTRIBUTES = {key: {"optional": True} for key in ("name", "type", "content", "ttl", "comment", "proxied")}
ATTRIBUTES["id"] = {"computed": True}
SCHEMA = {"provider_schemas": {PROVIDER: {"resource_schemas": {TYPE: {"block": {"attributes": ATTRIBUTES}}}}}}


def inventory(records):
    return {"root": "example.com", "observations": {"dns": {"status": "ok", "value": records}}}


def plan(before, after, actions=None, resource_type=TYPE):
    return {"complete": True, "errored": False, "resource_changes": [{
        "address": "example", "type": resource_type, "provider_name": PROVIDER, "mode": "managed",
        "change": {"actions": actions or ["update"], "before": before, "after": after, "after_unknown": {}}}]}


def state(value):
    return {"values": {"root_module": {"resources": [{"address": "example", "values": value}]}}}


class LocalOperationsTest(unittest.TestCase):
    def test_ruleset_dry_run_cannot_publish_and_preserves_diagnostics(self):
        import io
        from contextlib import redirect_stdout
        from workflow.rules_validation import validate_rulesets
        values = {"zone_id": "a" * 32, "name": "test", "kind": "zone", "phase": "http_request_firewall_custom", "rules": []}
        candidate = plan(None, values, ["create"], "cloudflare_ruleset")
        attributes = {key: {"required": True} for key in values}
        schema = {"provider_schemas": {PROVIDER: {"resource_schemas": {
            "cloudflare_ruleset": {"block": {"attributes": attributes}}}}}}
        response = Mock(status=200)
        response.read.return_value = b'{"success":true,"result":null,"messages":[{"message":"important diagnostic"}]}'
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        with patch("urllib.request.urlopen", return_value=response) as request, redirect_stdout(io.StringIO()) as output:
            validate_rulesets(SimpleNamespace(token="private"), candidate, schema, {"root": "example.com", "identity": "a" * 32})
        sent = request.call_args.args[0]
        self.assertTrue(sent.full_url.endswith("?dry_run=true"))
        self.assertEqual(sent.method, "POST")
        self.assertNotIn("zone_id", json.loads(sent.data))
        self.assertIn("important diagnostic", output.getvalue())

    def test_ruleset_validation_failure_stops_before_apply(self):
        import io
        import urllib.error
        from workflow.rules_validation import validate_rulesets
        values = {"name": "test"}
        candidate = plan(None, values, ["create"], "cloudflare_ruleset")
        schema = {"provider_schemas": {PROVIDER: {"resource_schemas": {
            "cloudflare_ruleset": {"block": {"attributes": {"name": {"required": True}}}}}}}}
        failure = urllib.error.HTTPError("https://example.invalid", 400, "invalid", {}, io.BytesIO(b'{"errors":[{"message":"reserved header"}]}'))
        with patch("urllib.request.urlopen", side_effect=failure), self.assertRaisesRegex(RuntimeError, "reserved header"):
            validate_rulesets(SimpleNamespace(token="private"), candidate, schema, {"root": "example.com", "identity": "a" * 32})

    def test_unknown_rule_configuration_is_blocked_but_computed_metadata_is_allowed(self):
        from workflow.rules_validation import unknown_configuration
        attributes = {"expression": {"required": True}, "id": {"computed": True},
                      "rules": {"optional": True, "nested_type": {"nesting_mode": "list",
                          "attributes": {"expression": {"required": True}, "id": {"computed": True}}}}}
        self.assertTrue(unknown_configuration({"expression": True}, attributes))
        self.assertTrue(unknown_configuration({"rules": [{"expression": True}]}, attributes))
        self.assertFalse(unknown_configuration({"rules": [{"id": True}], "id": True}, attributes))

    def test_zero_rtt_cannot_silently_change_an_unreviewed_tls_setting(self):
        baseline = {"root": "example.com", "observations": {"zone-settings": {"status": "ok", "value": [
            {"id": "0rtt", "value": "off"}, {"id": "tls_1_3", "value": "on"}]}}}
        candidate = plan({"setting_id": "0rtt", "value": "off"}, {"setting_id": "0rtt", "value": "on"}, resource_type="cloudflare_zone_setting")
        self.assertEqual(local_review.setting_side_effects(candidate, baseline), [
            {"setting": "tls_1_3", "before": "on", "after": "zrt"}])
        companion = copy.deepcopy(candidate["resource_changes"][0])
        companion["address"] = "tls"
        companion["change"]["after"] = {"setting_id": "tls_1_3", "value": "zrt"}
        candidate["resource_changes"].append(companion)
        with self.assertRaisesRegex(RuntimeError, "same Cloudflare feature"):
            local_review.require_compatible(candidate, baseline)

    def test_tls_linked_api_effect_must_match_the_reviewed_value(self):
        resource_type = "cloudflare_zone_setting"
        old = {"id": "tls_1_3", "setting_id": "tls_1_3", "value": "on"}
        new = {**old, "value": "zrt"}
        before = {"root": "example.com", "observations": {"zone-settings": {"status": "ok", "value": [
            {"id": "tls_1_3", "value": "on"}, {"id": "0rtt", "value": "off"}, {"id": "ssl", "value": "full"}]}}}
        after = copy.deepcopy(before)
        from workflow.inventory import canonical
        after["observations"]["zone-settings"]["value"] = canonical([
            {"id": "tls_1_3", "value": "zrt"}, {"id": "0rtt", "value": "on"}, {"id": "ssl", "value": "full"}], unordered=True)
        before["observations"]["zone-settings"]["value"] = canonical(before["observations"]["zone-settings"]["value"], unordered=True)
        attributes = {"id": {"computed": True}, "setting_id": {"required": True}, "value": {"required": True}}
        schema = {"provider_schemas": {PROVIDER: {"resource_schemas": {resource_type: {"block": {"attributes": attributes}}}}}}
        candidate = plan(old, new, resource_type=resource_type)
        self.assertEqual(local_review.verify(before, after, candidate, schema, state(new)), [])
        next(item for item in after["observations"]["zone-settings"]["value"] if item["id"] == "0rtt")["value"] = "off"
        self.assertTrue(any("reviewed secondary effect" in issue for issue in local_review.verify(before, after, candidate, schema, state(new))))

    def setUp(self):
        self.old = {"id": "record", "type": "A", "name": "www.example.com", "content": "192.0.2.1", "ttl": 300}
        self.new = {**self.old, "content": "192.0.2.2"}

    def test_rate_limit_omitted_default_is_false_but_true_is_preserved(self):
        attributes = {key: {"optional": True} for key in ("requests_to_origin", "characteristics")}
        desired = {"characteristics": ["ip.src"], "requests_to_origin": False}
        actual = local_review._view({"characteristics": ["ip.src"]}, attributes)
        self.assertTrue(local_review._known_matches(actual, desired, {}))
        actual = local_review._view({**desired, "requests_to_origin": True}, attributes)
        self.assertFalse(local_review._known_matches(actual, desired, {}))

    def verify(self, records, desired=None):
        return local_review.verify(inventory([self.old]), inventory(records), plan(self.old, desired or self.new), SCHEMA, state(self.new))

    def test_exact_dns_update_passes(self):
        self.assertEqual(self.verify([self.new]), [])

    def test_origin_certificate_cannot_write_outside_the_reviewed_zone(self):
        snapshot = {"root": "example.com", "identity": "zone", "observations": {}}
        candidate = plan(None, {"hostnames": ["example.com", "*.example.com"]}, ["create"], "cloudflare_origin_ca_certificate")
        local_review.require_compatible(candidate, snapshot)
        candidate["resource_changes"][0]["change"]["after"]["hostnames"].append("other.example.net")
        with self.assertRaisesRegex(RuntimeError, "other zones need separate inventories"):
            local_review.require_compatible(candidate, snapshot)

    def test_structured_dns_updates_check_derived_content_instead_of_stale_provider_text(self):
        schema = copy.deepcopy(SCHEMA)
        schema["provider_schemas"][PROVIDER]["resource_schemas"][TYPE]["block"]["attributes"]["data"] = {"optional": True}
        cases = [("CAA", {"flags": 0, "tag": "issue", "value": "letsencrypt.org"},
                  {"flags": 0, "tag": "issue", "value": "pki.goog"}, '0 issue "letsencrypt.org"', '0 issue "pki.goog"'),
                 ("SRV", {"weight": 5, "port": 8443, "target": "www.example.com"},
                  {"weight": 10, "port": 9443, "target": "www.example.com"},
                  "5 8443 www.example.com", "10 9443 www.example.com")]
        for record_type, old_data, new_data, old_content, new_content in cases:
            with self.subTest(record_type=record_type):
                old = {**self.old, "type": record_type, "data": old_data, "content": old_content}
                desired = {**old, "data": new_data}
                actual = {**desired, "content": new_content}
                self.assertEqual(local_review.verify(inventory([old]), inventory([actual]), plan(old, desired), schema, state(actual)), [])
                incorrect = {**actual, "content": old_content}
                self.assertTrue(local_review.verify(inventory([old]), inventory([incorrect]), plan(old, desired), schema, state(actual)))

    def test_dns_omitted_disabled_flags_are_equivalent_but_enabled_flags_are_detected(self):
        attributes = {"include_shadow_metadata": {"optional": True}, "type": {"required": True},
                      "settings": {"optional": True}}
        desired = {"type": "CNAME", "settings": {"flatten_cname": False, "ipv4_only": False, "ipv6_only": False}}
        view = local_review._view({"type": "CNAME", "settings": {"flatten_cname": False}}, attributes)
        self.assertTrue(local_review._known_matches(view, desired, {}))
        nullable = {"type": "A", "settings": {"flatten_cname": None, "ipv4_only": None, "ipv6_only": None}}
        self.assertTrue(local_review._known_matches(local_review._view({"type": "A", "settings": {}}, attributes),
                                                   local_review._dns_planned_values(nullable), {}))
        view = local_review._view({"type": "CNAME", "settings": {"ipv4_only": True}}, attributes)
        self.assertFalse(local_review._known_matches(view, desired, {}))

    def test_certificate_timestamp_noise_is_not_configuration_drift(self):
        from workflow.inventory import canonical
        before = {"hosts": ["example.com"], "certificates": [{"uploaded_on": "one", "certificate_authority": "google"}]}
        after = {"hosts": ["example.com"], "certificates": [{"uploaded_on": "two", "certificate_authority": "google"}]}
        self.assertEqual(canonical(before), canonical(after))
        after["hosts"] = ["other.example.com"]
        self.assertNotEqual(canonical(before), canonical(after))

    def test_caa_accepts_current_issuer_with_parameters_and_checks_effective_dns(self):
        from validation.dns import _validate_caa
        from validation.reporting import Report
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            (directory / "dns").mkdir()
            path = directory / "dns/caa.yaml"
            path.write_text("issuer:\n  tag: issue\n  value: 'ssl.com; validationmethods=dns-01'\n", encoding="utf-8")
            report = Report()
            _validate_caa(report, directory, "free")
            self.assertFalse(report.items)
            path.write_text("issuer:\n  tag: issue\n  value: certainly.com\n", encoding="utf-8")
            report = Report()
            _validate_caa(report, directory, "free")
            self.assertIn("effective DNS CAA", report.items[0][4])

    def test_query_only_provider_field_is_not_an_api_value(self):
        schema = copy.deepcopy(SCHEMA)
        schema["provider_schemas"][PROVIDER]["resource_schemas"][TYPE]["block"]["attributes"]["include_shadow_metadata"] = {"optional": True, "computed": True}
        desired = {**self.new, "include_shadow_metadata": False}
        self.assertEqual(local_review.verify(inventory([self.old]), inventory([self.new]), plan(self.old, desired), schema, state(desired)), [])

    def test_confirmation_cannot_authorize_a_new_dashboard_change(self):
        context = {"client": Mock(), "before": inventory([self.old]), "plan": {}}
        with patch.object(local_review, "snapshot", return_value=inventory([self.new])):
            with self.assertRaisesRegex(RuntimeError, "awaiting confirmation"):
                local_review.recheck(SimpleNamespace(dir=Path("unused")), context)

    def test_readback_failure_is_retained_and_cannot_report_success(self):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            context = {"client": Mock(), "before": inventory([self.old]), "plan": {}}
            with patch.object(local_review, "snapshot", side_effect=RuntimeError("API unavailable")):
                with self.assertRaisesRegex(RuntimeError, "Dashboard verification failed"):
                    local_review.finish(SimpleNamespace(dir=directory), directory, context, Mock())
            outcome = json.loads((directory / "dashboard-outcome.json").read_text())
            self.assertIn("API unavailable", outcome["issues"])
            self.assertIsNone(outcome["after"])

    def test_dashboard_must_stay_stable_during_followup_verification(self):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            after = inventory([self.new])
            final = inventory([{**self.new, "ttl": 60}])
            context = {"client": Mock(), "before": inventory([self.old]), "plan": plan(self.old, self.new), "schema": SCHEMA}
            results = [SimpleNamespace(returncode=0, stdout=json.dumps(state(self.new))),
                       SimpleNamespace(returncode=0, stdout="", stderr=""),
                       SimpleNamespace(returncode=0, stdout=json.dumps({"complete": True, "resource_changes": []}))]
            with patch.object(local_review, "snapshot", side_effect=[after, final]):
                with self.assertRaisesRegex(RuntimeError, "changed during post-apply"):
                    local_review.finish(SimpleNamespace(dir=directory), directory, context, Mock(side_effect=results))
            outcome = json.loads((directory / "dashboard-outcome.json").read_text())
            self.assertTrue(outcome["issues"])

    def test_failed_apply_retains_partial_dashboard_effects(self):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            context = {"client": Mock(), "before": inventory([self.old]), "plan": {}}
            with patch.object(local_review, "snapshot", return_value=inventory([self.new])):
                local_review.failed(SimpleNamespace(dir=directory), directory, context)
            outcome = json.loads((directory / "dashboard-outcome.json").read_text())
            self.assertEqual(outcome["after"], inventory([self.new]))
            self.assertTrue(outcome["issues"])

    def test_cross_zone_operations_need_separate_review(self):
        candidate = plan({**self.old, "zone_id": "different-zone"}, self.new)
        with self.assertRaisesRegex(RuntimeError, "changing zone/account scope"):
            local_review.require_compatible(candidate, {**inventory([self.old]), "identity": "zone"})

    def test_replacement_cannot_hide_a_provider_no_op_delete(self):
        candidate = plan({"setting_id": "ssl"}, {"setting_id": "tls_1_3"}, ["delete", "create"], "cloudflare_zone_setting")
        with self.assertRaisesRegex(RuntimeError, "leaves the previous dashboard setting intact"):
            local_review.require_compatible(candidate, inventory([]))

    def test_write_only_secret_change_is_blocked_before_apply(self):
        candidate = plan({"secret": "before"}, {"secret": "after"}, resource_type="cloudflare_notification_policy_webhooks")
        with self.assertRaisesRegex(RuntimeError, "write-only"):
            local_review.require_compatible(candidate, inventory([]))

    def test_unavailable_paid_service_cannot_be_changed(self):
        candidate = plan(None, {"value": "on"}, ["create"], "cloudflare_zone_cache_reserve")
        snapshot = {**inventory([]), "identity": "zone"}
        snapshot["observations"]["cache-reserve"] = {"status": "unavailable-plan"}
        with self.assertRaisesRegex(RuntimeError, "unavailable for the zone plan"):
            local_review.require_compatible(candidate, snapshot)

    def test_extra_record_and_extra_field_are_detected(self):
        extra = {**self.new, "id": "other", "name": "extra.example.com"}
        self.assertTrue(any("outside the planned objects" in issue for issue in self.verify([self.new, extra])))
        issues = self.verify([{**self.new, "ttl": 60}])
        self.assertTrue(any("planned values" in issue for issue in issues))
        self.assertTrue(any("unplanned change to ttl" in issue for issue in issues))

    def test_optional_field_removal_must_reach_the_dashboard(self):
        self.old["comment"] = "remove this"
        desired = {**self.new, "comment": None}
        self.assertTrue(self.verify([{**self.new, "comment": "remove this"}], desired))
        self.assertEqual(self.verify([self.new], desired), [])

    def test_new_record_and_deleted_record_leave_no_residual_difference(self):
        adding = plan(None, self.new, ["create"])
        self.assertEqual(local_review.verify(inventory([]), inventory([self.new]), adding, SCHEMA, state(self.new)), [])
        deleting = plan(self.old, None, ["delete"])
        self.assertEqual(local_review.verify(inventory([self.old]), inventory([]), deleting, SCHEMA, state({})), [])
        self.assertTrue(local_review.verify(inventory([self.old]), inventory([self.old]), deleting, SCHEMA, state({})))

    def test_incomplete_and_errored_plans_are_not_convergence(self):
        for value in ({"complete": False}, {"errored": True}, {"deferred_changes": [{"reason": "unknown"}]}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                state_only(value)

    def test_setting_removal_is_stop_managing(self):
        value = {"zone_id": "zone", "setting_id": "ssl", "id": "ssl", "value": "strict"}
        changes, adopts, warnings, deviations, counts = plan_summary.summarise(plan(value, None, ["delete"], "cloudflare_zone_setting"))
        self.assertEqual(changes[0][0], "STOP MANAGING")
        self.assertIn("without sending a dashboard request", changes[0][2][0])
        self.assertEqual(counts["delete"], 0)
        self.assertEqual(counts["forget"], 1)

    def test_destination_redaction_keeps_destination_but_masks_credentials(self):
        result = redact({"destination_conf": "s3://access:secret@bucket/path?region=auto&access-key=hidden&arbitrary=value"})["destination_conf"]
        self.assertIn("bucket/path", result)
        self.assertIn("region=auto", result)
        for secret in ("access:secret", "hidden", "arbitrary=value"):
            self.assertNotIn(secret, result)
        self.assertEqual(redact({"destination_conf": "s3://other/path"}), {"destination_conf": "s3://other/path"})

    def test_known_provider_adoption_and_pagination_failures_are_blocked(self):
        for resource_type in ("cloudflare_account_dns_settings", "cloudflare_authenticated_origin_pulls"):
            candidate = plan({}, {}, ["no-op"], resource_type)
            candidate["resource_changes"][0]["change"]["importing"] = {"id": "existing"}
            with self.subTest(resource_type=resource_type), self.assertRaisesRegex(RuntimeError, "verified provider fix"):
                local_review.require_compatible(candidate, inventory([]))
        candidate = plan({}, {"members": [{"id": str(index)} for index in range(101)]}, ["create"], "cloudflare_user_group_members")
        with self.assertRaisesRegex(RuntimeError, "pagination fix"):
            local_review.require_compatible(candidate, inventory([]))

    def test_recovery_preserves_fallback_even_when_backend_read_fails(self):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            root = SimpleNamespace(name="example.com", dir=directory / "domain")
            root.dir.mkdir()
            evidence = directory / "recovery"
            evidence.mkdir()
            fallback = root.dir / "errored.tfstate"
            fallback.write_text('{"serial": 2, "lineage": "same"}', encoding="utf-8")
            run_tf = Mock(return_value=SimpleNamespace(returncode=1, stderr="backend unavailable", stdout=""))
            recovery.finish(root, evidence, run_tf)
            self.assertEqual((evidence / "errored.tfstate").read_bytes(), fallback.read_bytes())
            self.assertTrue((evidence / "state-read-error.txt").exists())
            with self.assertRaisesRegex(RuntimeError, "Recover it"):
                recovery.start(directory, root, run_tf, {})

    def test_backend_failure_is_not_treated_as_empty_state(self):
        with tempfile.TemporaryDirectory() as name:
            root = SimpleNamespace(dir=Path(name))
            run_tf = Mock(return_value=SimpleNamespace(returncode=1, stderr="access denied", stdout=""))
            with self.assertRaisesRegex(RuntimeError, "Cannot back up"):
                recovery.save_state(root, root.dir / "before.tfstate", run_tf, allow_empty=True)

    def test_new_local_backend_can_have_successful_empty_state_pull(self):
        with tempfile.TemporaryDirectory() as name:
            root = SimpleNamespace(dir=Path(name))
            run_tf = Mock(return_value=SimpleNamespace(returncode=0, stdout="", stderr=""))
            recovery.save_state(root, root.dir / "before.tfstate", run_tf, allow_empty=True)
            self.assertFalse((root.dir / "before.tfstate").exists())
            with self.assertRaises(ValueError):
                recovery.save_state(root, root.dir / "before.tfstate", run_tf)

    def test_initial_import_prior_state_does_not_require_existing_backend(self):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            root = SimpleNamespace(dir=directory, name="example.com")
            (directory / "plan.json").write_text("{}")
            candidate = {"prior_state": {"values": {"root_module": {"resources": [
                {"address": "cloudflare_dns_record.imported", "mode": "managed"}]}}},
                "resource_changes": [{"address": "cloudflare_dns_record.imported",
                                      "change": {"importing": {"id": "record-id"}}}]}
            run_tf = Mock(return_value=SimpleNamespace(returncode=0, stdout="", stderr=""))
            evidence = recovery.start(directory, root, run_tf, candidate)
            self.assertTrue((evidence / "plan.json").exists())
            candidate["prior_state"]["values"]["root_module"]["resources"].append(
                {"address": "cloudflare_dns_record.existing", "mode": "managed"})
            with self.assertRaises(ValueError):
                recovery.start(directory, root, run_tf, candidate)

    def test_email_secondary_effects_must_match_exact_records(self):
        required = {"type": "MX", "name": "example.com", "content": "route.mx.cloudflare.net", "priority": 10, "ttl": 1}
        left, right = inventory([])["observations"], inventory([{**required, "id": "email-mx"}])["observations"]
        candidate = plan({}, {}, ["create"], "cloudflare_email_routing_settings")
        baseline = {"root": "example.com", "email_dns_records": [required]}
        self.assertEqual(local_review._verify_email_dns(left, right, baseline, candidate), [])
        self.assertEqual(right["dns"]["value"], [])
        right = inventory([{**required, "content": "unexpected.example"}])["observations"]
        self.assertTrue(local_review._verify_email_dns(left, right, baseline, candidate))


if __name__ == "__main__":
    unittest.main()
