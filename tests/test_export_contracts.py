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

    def test_pagination_collects_all_pages_in_order(self):
        client = export_client.Client("fixture-token")
        with patch.object(client, "get", side_effect=[{"result": ["first"], "result_info": {"total_pages": 2}}, {"result": ["second"], "result_info": {"total_pages": 2}}]) as get:
            self.assertEqual(client.pages("/records", per_page=2), ["first", "second"])
        self.assertEqual([call.args[1] for call in get.call_args_list], [{"page": 1, "per_page": 2}, {"page": 2, "per_page": 2}])

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
