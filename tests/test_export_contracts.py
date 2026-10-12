"""Transport failure contracts and deliberate account/zone export differences."""
import importlib.util
import io
import json
import sys
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))
from exporting import client as export_client
ORIGINAL_GET = export_client.Client.get
from exporting.services import ZoneExport
from validation.common import Ctx, Report
spec = importlib.util.spec_from_file_location("transport_exporter", REPO / "scripts" / "export_zone.py")
exporter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(exporter)


class ExportClientTest(unittest.TestCase):
    def test_export_uses_tls_as_the_single_writer_for_zero_rtt(self):
        class Fake:
            def pages(self, path):
                return [{"id": "0rtt", "value": "on", "editable": True},
                        {"id": "tls_1_3", "value": "zrt", "editable": True}]
        zone = ZoneExport(Fake(), "a" * 32, "example.com", "free")
        zone.settings()
        self.assertEqual(zone.files["settings/zone.yaml"], {"tls_1_3": "zrt"})
        self.assertEqual(len(zone.imports), 1)
        self.assertTrue(zone.imports[0][1].endswith("/tls_1_3"))

    def setUp(self):
        transport = patch.object(export_client.Client, "get", ORIGINAL_GET)
        transport.start()
        self.addCleanup(transport.stop)

    def test_retry_after_then_success(self):
        failure = urllib.error.HTTPError("https://example.test", 429, "rate limit", {"Retry-After": "3"}, io.BytesIO(b"limited"))
        success = io.BytesIO(b'{"result": [1]}')
        with patch.object(export_client.urllib.request, "urlopen", side_effect=[failure, success]) as request, patch.object(export_client.time, "sleep") as sleep:
            self.assertEqual(export_client.Client("fixture-token").result("/zones/example"), [1])
        self.assertEqual(request.call_count, 2)
        sleep.assert_called_once_with(3)

    def test_network_retry_exhaustion(self):
        with patch.object(export_client.urllib.request, "urlopen", side_effect=urllib.error.URLError("offline")) as request, patch.object(export_client.time, "sleep") as sleep:
            with self.assertRaisesRegex(RuntimeError, "cannot reach.*offline"):
                export_client.Client("fixture-token").get("/zones/example")
        self.assertEqual(request.call_count, 5)
        self.assertEqual([call.args[0] for call in sleep.call_args_list], [1, 2, 4, 8])

    def test_not_found_and_permission_errors_do_not_retry(self):
        for code, expected in ((404, export_client.NotFound), (403, PermissionError)):
            error = urllib.error.HTTPError("https://example.test", code, "failed", {}, io.BytesIO(b"failure"))
            with self.subTest(code=code), patch.object(export_client.urllib.request, "urlopen", side_effect=error) as request, patch.object(export_client.time, "sleep") as sleep:
                with self.assertRaises(expected):
                    export_client.Client("fixture-token").get("/zones/example/dns_records")
                request.assert_called_once()
                sleep.assert_not_called()
            error.close()

    def test_explicit_cache_plan_denial_is_distinct_from_authentication(self):
        cases = [(1135, export_client.UnavailableForPlan), (10000, PermissionError)]
        for code, exception in cases:
            body = json.dumps({"errors": [{"code": code}]}).encode()
            error = urllib.error.HTTPError("https://example.test", 403, "denied", {}, io.BytesIO(body))
            with self.subTest(code=code), patch.object(export_client.urllib.request, "urlopen", side_effect=error):
                with self.assertRaises(exception):
                    export_client.Client("fixture-token").result("/zones/example/cache/variants")

    def test_argo_setting_denial_is_distinct_from_an_invalid_token(self):
        cases = [(1015, "The request is not authorized to access this setting. Cause(s): smart_routing", export_client.SettingUnavailable),
                 (10000, "Authentication error", PermissionError),
                 (1015, "Other authorization error", PermissionError)]
        for code, message, exception in cases:
            body = json.dumps({"errors": [{"code": code, "message": message}]}).encode()
            error = urllib.error.HTTPError("https://example.test", 401, "denied", {}, io.BytesIO(body))
            with self.subTest(code=code, message=message), patch.object(export_client.urllib.request, "urlopen", side_effect=error):
                with self.assertRaises(exception):
                    export_client.Client("fixture-token").result("/zones/example/argo/smart_routing")

    def test_pagination_collects_all_pages_in_order(self):
        client = export_client.Client("fixture-token")
        with patch.object(client, "get", side_effect=[{"result": ["first"], "result_info": {"total_pages": 2}}, {"result": ["second"], "result_info": {"total_pages": 2}}]) as get:
            self.assertEqual(client.pages("/records", per_page=2), ["first", "second"])
        self.assertEqual([call.args[1] for call in get.call_args_list], [{"page": 1, "per_page": 2}, {"page": 2, "per_page": 2}])

    def test_rulesets_follow_cursors_even_for_short_pages(self):
        client = export_client.Client("fixture-token")
        pages = [{"result": [{"id": "first"}], "result_info": {"cursors": {"after": "next"}}},
                 {"result": [{"id": "second"}], "result_info": {}}]
        with patch.object(client, "get", side_effect=pages) as get:
            self.assertEqual(client.pages("/zones/example/rulesets"), [{"id": "first"}, {"id": "second"}])
        self.assertEqual([call.args[1] for call in get.call_args_list], [{"per_page": 50}, {"per_page": 50, "cursor": "next"}])

    def test_inconsistent_counts_retry_a_complete_read_without_accepting_partial_results(self):
        client = export_client.Client("fixture-token")
        stale = {"result": [{"id": "one"}], "result_info": {"total_pages": 1, "total_count": 2}}
        complete = {"result": [{"id": "one"}, {"id": "two"}], "result_info": {"total_pages": 1, "total_count": 2}}
        with patch.object(client, "get", side_effect=[stale, complete]) as get, patch.object(export_client.time, "sleep") as sleep:
            self.assertEqual(client.pages("/zones/example/dns_records"), complete["result"])
            self.assertEqual(get.call_count, 2)
            sleep.assert_called_once_with(1)
        with patch.object(client, "get", return_value=stale) as get, patch.object(export_client.time, "sleep"):
            with self.assertRaisesRegex(export_client.InventoryChanged, "count"):
                client.pages("/zones/example/dns_records")
            self.assertEqual(get.call_count, 4)

    def test_rulesets_reject_cursor_overlap_and_repetition(self):
        for second in ({"result": [{"id": "first"}]},
                       {"result": [{"id": "second"}], "result_info": {"cursors": {"after": "next"}}}):
            first = {"result": [{"id": "first"}], "result_info": {"cursors": {"after": "next"}}}
            client = export_client.Client("fixture-token")
            with self.subTest(second=second), patch.object(client, "get", side_effect=[first, second]):
                with self.assertRaisesRegex(RuntimeError, "overlapping|repeated cursor"):
                    client.pages("/accounts/example/rulesets")

    def test_ct_alerting_export_uses_the_documented_endpoint(self):
        from workflow.coverage import ZONE_SERVICES
        self.assertEqual(next(service.endpoint for service in ZONE_SERVICES if service.name == "ct-alerting"), "ct/alerting")
        requests = []
        class Client:
            def result(self, path):
                requests.append(path)
                if path.endswith("/ct/alerting"):
                    return {"enabled": True, "emails": ["security@example.com"]}
                raise exporter.NotFound(path)
        zone = ZoneExport(Client(), "zone", "example.com", "free")
        zone.extended()
        self.assertEqual(zone.files["security/ct-alerting.yaml"], {"enabled": True, "emails": ["security@example.com"]})

    def test_email_catch_all_is_not_imported_as_an_ordinary_rule_or_renamed(self):
        catch = {"id": "catch", "name": "", "enabled": False,
                 "matchers": [{"type": "all"}], "actions": [{"type": "drop"}]}
        ordinary = {"id": "ordinary", "name": "route", "enabled": True,
                    "matchers": [{"type": "literal", "field": "to", "value": "route@example.com"}],
                    "actions": [{"type": "drop"}]}
        class Client:
            def result(self, path):
                if path.endswith('/email/routing'):
                    return {"enabled": False}
                if path.endswith('/catch_all'):
                    return catch
                raise exporter.NotFound(path)
            def pages(self, path):
                return [catch, ordinary]
        zone = ZoneExport(Client(), "zone", "example.com", "free")
        zone.extended()
        value = zone.files['dns/email-routing.yaml']
        self.assertEqual(value['catch_all']['name'], '')
        self.assertEqual(len(value['rules']), 1)
        self.assertEqual(value['rules'][0]['name'], 'route')
        self.assertEqual(len(zone.imports), 2)
        self.assertFalse(any(identity == 'zone/catch' for _, identity in zone.imports))

    def test_account_and_zone_preserve_supported_rule_fields(self):
        custom = {"id": "custom", "rules": [{"id": "skip", "expression": "true", "action": "skip", "action_parameters": {"ruleset": "current"}, "logging": {"enabled": False}}]}
        rate = {"id": "rate", "rules": [{"id": "limit", "expression": "true", "action": "block", "enabled": False, "ratelimit": {"requests_per_period": 10, "counting_expression": "true", "requests_to_origin": False}, "action_parameters": {"response": {"content": "blocked", "status_code": 403}}}]}
        class Client:
            def result(self, path):
                if "http_request_firewall_custom" in path:
                    return custom
                if "http_ratelimit" in path:
                    return rate
                raise exporter.NotFound(path)
        client = Client()
        zone = ZoneExport(client, "zone", "example.com", "enterprise")
        zone.waf()
        account = exporter._collect_account_waf(client, "account", [], [])
        self.assertEqual(zone.files["waf/custom-rules.yaml"][0]["skip"], {"ruleset": "current", "log": False})
        self.assertEqual(account["waf/custom-rules.yaml"][0]["skip"], {"ruleset": "current", "log": False})
        zone_rule = zone.files["waf/rate-limits.yaml"][0]
        account_rule = account["waf/rate-limits.yaml"][0]
        self.assertEqual(zone_rule["counting_expression"], "true")
        self.assertIs(zone_rule["requests_to_origin"], False)
        self.assertEqual(zone_rule["response"], {"content": "blocked", "status_code": 403})
        for field in ("counting_expression", "requests_to_origin", "response"):
            self.assertEqual(account_rule[field], zone_rule[field])
        self.assertIs(account_rule["enabled"], False)


class InjectedPolicyTest(unittest.TestCase):
    def test_contexts_can_use_independent_policies(self):
        class Gate:
            def __init__(self, severity):
                self.value = severity
            def severity(self, check_id):
                return self.value
        report = Report()
        for severity in ("error", "warning", None):
            Ctx(report, "fixture.yaml", {}, "pro", gate=Gate(severity)).flag("check", (), "message")
        self.assertEqual([item[0] for item in report.items], ["error", "warning"])


if __name__ == "__main__":
    unittest.main()
