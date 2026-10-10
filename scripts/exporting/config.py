"""Constants describing exportable Cloudflare services."""
import json
import os
from repository_paths import repository_root

API = os.environ.get("CLOUDFLARE_API_BASE_URL", "https://api.cloudflare.com/client/v4")
ROOT = repository_root(__file__)
TEMPLATE = ROOT / "domains" / "_template"
RULE_SCHEMA = json.loads((ROOT / "scripts" / "data" / "ruleset_rule_schema.json").read_text())["rule"]

# Which token permission each endpoint needs, for clear error messages.
PERMISSIONS = [
    ("/dns_records", "Zone > DNS > Read"),
    ("/dnssec", "Zone > DNS > Read"),
    ("/rulesets/phases/http_request_firewall", "Zone > Zone WAF > Read"),
    ("/rulesets/phases/http_ratelimit", "Zone > Zone WAF > Read"),
    ("/rulesets/phases/http_request_cache", "Zone > Cache Rules > Read"),
    ("/rulesets/phases/http_request_dynamic_redirect", "Zone > Single Redirect > Read"),
    ("/rulesets/phases/http_request_transform", "Zone > Transform Rules > Read"),
    ("/rulesets/phases/http_request_late_transform", "Zone > Transform Rules > Read"),
    ("/rulesets/phases/http_response_headers_transform", "Zone > Transform Rules > Read"),
    ("/rulesets/phases/http_request_origin", "Zone > Origin Rules > Read"),
    ("/rulesets/phases/http_config_settings", "Zone > Config Rules > Read"),
    ("/rulesets/phases/http_response_compression", "Zone > Response Compression > Read"),
    ("/settings", "Zone > Zone Settings > Read"),
    ("/bot_management", "Zone > Bot Management > Read"),
    ("/access_rules", "Zone > Firewall Services > Read"),
    ("/cache/", "Zone > Cache Settings > Read"),
    ("/argo/", "Zone > Argo Smart Routing > Read"),
    ("/rules/lists", "Account > Account Filter Lists > Read"),
    ("/rulesets/phases/http_request_redirect", "Account > Mass URL Redirects > Read"),
]

DNS_FILES = {"A": "a", "AAAA": "aaaa", "CNAME": "cname", "MX": "mx", "TXT": "txt", "NS": "ns"}
RULE_FILES = {  # module key: (phase, file)
    "cache": ("http_request_cache_settings", "cache/cache-rules.yaml"),
    "redirects": ("http_request_dynamic_redirect", "rules/redirects.yaml"),
    "url_rewrites": ("http_request_transform", "rules/url-rewrites.yaml"),
    "request_headers": ("http_request_late_transform", "rules/request-headers.yaml"),
    "response_headers": ("http_response_headers_transform", "rules/response-headers.yaml"),
    "origin": ("http_request_origin", "rules/origin.yaml"),
    "config": ("http_config_settings", "rules/config.yaml"),
    "compression": ("http_response_compression", "rules/compression.yaml"),
}
SETTINGS = [
    "ssl", "min_tls_version", "tls_1_3", "always_use_https", "automatic_https_rewrites",
    "opportunistic_encryption", "security_level", "browser_check", "email_obfuscation",
    "browser_cache_ttl", "cache_level", "brotli", "early_hints", "http3", "0rtt",
]
BOT_FIELDS_BY_PLAN = {
    "free": ["fight_mode", "enable_js", "ai_bots_protection", "crawler_protection", "is_robots_txt_managed"],
    "pro": ["sbfm_definitely_automated", "sbfm_verified_bots", "sbfm_static_resource_protection",
            "optimize_wordpress", "enable_js", "ai_bots_protection", "crawler_protection", "is_robots_txt_managed"],
}
BOT_FIELDS_BY_PLAN["business"] = BOT_FIELDS_BY_PLAN["pro"] + ["sbfm_likely_automated"]
BOT_FIELDS_BY_PLAN["enterprise"] = BOT_FIELDS_BY_PLAN["business"] + [
    "auto_update_model", "suppress_session_score", "bm_cookie_enabled"]
MANAGED_IDS = {"efb7b8c949ac4650a09736fc376e9aee": "cloudflare_managed", "4814384a9e5d4991b9815dcfc25d2f1f": "owasp"}
BENIGN_DROPS = {"id", "version", "last_updated", "categories"}
CUSTOM_ACTIONS = ("block", "managed_challenge", "js_challenge", "challenge", "log", "skip")
