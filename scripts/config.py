"""
Tunable values: Cloudflare plan limits, regex patterns, known zone settings,
bot fields and the thresholds behind policy.yaml.

These are what someone changes when Cloudflare changes a limit or adds a
setting -- not business logic. The checks that use them live in
scripts/validation/; import from here directly rather than through
validation.common.
"""
import re

# ---- plans and limits ----------------------------------------------------
# Checked against Cloudflare's docs (docs/references.md). Keep in step with
# modules/waf/main.tf and modules/rules/main.tf, which enforce the same limits.

PLANS = ["free", "pro", "business", "enterprise"]

LIMITS = {
    "custom_rules": {"free": 5, "pro": 20, "business": 100, "enterprise": 1000},
    "rate_limits": {"free": 1, "pro": 2, "business": 5, "enterprise": 100},
    "rules": {"free": 10, "pro": 25, "business": 50, "enterprise": 300},
}

RL_PERIODS = [10, 60, 120, 300, 600, 3600]
RL_TIMEOUTS = [0, 10, 60, 120, 300, 600, 3600, 86400]
RL_MAX_PERIOD = {"free": 10, "pro": 60, "business": 600, "enterprise": 3600}
RL_MAX_TIMEOUT = {"free": 10, "pro": 3600, "business": 86400, "enterprise": 86400}
RL_CHARS = {
    "free": {"ip.src", "cf.colo.id"},
    "pro": {"ip.src", "cf.colo.id"},
    "business": {"ip.src", "cf.colo.id", "cf.unique_visitor_id"},
}

# ---- regex patterns ------------------------------------------------------

HOST_RE = re.compile(r"^(?=.{1,253}$)(\*\.)?([A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9])?$")
NAME_RE = re.compile(r"^(@|\*|(\*\.)?[A-Za-z0-9_](?:[A-Za-z0-9_.-]{0,251}[A-Za-z0-9_])?)$")
KEY_RE = re.compile(r"^[A-Za-z0-9_@.\-]+$")
REF_RE = re.compile(r"^[A-Za-z0-9_\-]{1,120}$")
EMAIL_RE = re.compile(r"^(mailto:)?[^@\s]+@[^@\s]+\.[^@\s]+$")
HEX32 = re.compile(r"^[0-9a-f]{32}$")

REGEX_RE = re.compile(r"(\bmatches\b|\s~\s|\bregex_replace\s*\()")
LIST_REF_RE = re.compile(r"\$([a-z0-9_]+)")

DOC_BLOCK_RE = re.compile(r"^##\s*([A-Za-z]+)\s*:\s*\S")

# ---- thresholds behind policy.yaml ---------------------------------------
# Changing one of these changes what a check flags; see docs/40-policy.md.

DKIM_MIN_RSA_BITS = 2048  # Ed25519 keys (k=ed25519) have no bit count and are always skipped
DEPRECATED_TLS_VERSIONS = ("1.0", "1.1")
WEAK_SSL_MODES = ("off", "flexible")  # both send traffic to the origin unencrypted
OWASP_SCORE_THRESHOLDS = (25, 40, 60)  # Cloudflare's documented levels: 60 low, 40 medium, 25 high
OWASP_PARANOIA_LEVELS = (1, 2, 3, 4)  # structural, not policy-gated: the API accepts only 1-4
DOC_BLOCK_REQUIRED = ("owner", "purpose", "impact")  # "proxy" is added per record type at the call site

# cf.py refuses an apply that destroys more than this unless
# CF_ALLOW_DESTRUCTIVE=1. Cloudflare has no undo for a deleted record.
MAX_DESTRUCTIVE_CHANGES = 10

# ---- zone settings -------------------------------------------------------
# Keep KNOWN_SETTINGS/SETTING_ENUMS in step with Cloudflare's zone settings
# API when a new setting is added.

KNOWN_SETTINGS = {
    "0rtt", "advanced_ddos", "aegis", "always_online", "always_use_https", "automatic_https_rewrites",
    "automatic_platform_optimization", "brotli", "browser_cache_ttl", "browser_check", "cache_level",
    "challenge_ttl", "ciphers", "cname_flattening", "development_mode", "early_hints", "ech",
    "email_obfuscation", "fonts", "h2_prioritization", "hotlink_protection", "http2", "http3",
    "image_resizing", "ip_geolocation", "ipv6", "max_upload", "min_tls_version", "mirage", "nel",
    "opportunistic_encryption", "opportunistic_onion", "orange_to_orange", "origin_error_page_pass_thru",
    "origin_h2_max_streams", "origin_max_http_version", "polish", "prefetch_preload", "privacy_pass",
    "proxy_read_timeout", "pseudo_ipv4", "replace_insecure_js", "response_buffering", "rocket_loader",
    "security_level", "server_side_exclude", "sort_query_string_for_cache", "speed_brain", "ssl",
    "ssl_recommender", "tls_1_2_only", "tls_1_3", "tls_client_auth", "true_client_ip_header", "waf",
    "webp", "websockets",
}

SETTING_ENUMS = {
    "ssl": ["off", "flexible", "full", "strict"],
    "min_tls_version": ["1.0", "1.1", "1.2", "1.3"],
    "security_level": ["off", "essentially_off", "low", "medium", "high", "under_attack"],
    "cache_level": ["basic", "simplified", "aggressive"],
    "tls_1_3": ["on", "off", "zrt"],
}

ON_OFF_SETTINGS = {
    "0rtt", "always_online", "always_use_https", "automatic_https_rewrites", "brotli", "browser_check",
    "development_mode", "early_hints", "email_obfuscation", "hotlink_protection", "http2", "http3",
    "ip_geolocation", "ipv6", "mirage", "opportunistic_encryption", "opportunistic_onion",
    "origin_error_page_pass_thru", "prefetch_preload", "privacy_pass", "response_buffering",
    "rocket_loader", "server_side_exclude", "sort_query_string_for_cache", "tls_client_auth",
    "true_client_ip_header", "waf", "websockets", "speed_brain", "fonts",
}

# Which rule-engine phase each rule file maps to.
RULE_FILES = {
    "cache/cache-rules.yaml": "set_cache_settings",
    "rules/redirects.yaml": "redirect",
    "rules/url-rewrites.yaml": "rewrite",
    "rules/request-headers.yaml": "rewrite",
    "rules/response-headers.yaml": "rewrite",
    "rules/origin.yaml": "route",
    "rules/config.yaml": "set_config",
    "rules/compression.yaml": "compress_response",
}

# ---- bot management ------------------------------------------------------
# field: (allowed values or type, plans it is available on)
BOT_FIELDS = {
    "fight_mode": (bool, {"free"}),
    "enable_js": (bool, set(PLANS)),
    "sbfm_definitely_automated": (["allow", "block", "managed_challenge"], {"pro", "business", "enterprise"}),
    "sbfm_likely_automated": (["allow", "block", "managed_challenge"], {"pro", "business", "enterprise"}),
    "sbfm_verified_bots": (["allow", "block"], {"pro", "business", "enterprise"}),
    "sbfm_static_resource_protection": (bool, {"pro", "business", "enterprise"}),
    "optimize_wordpress": (bool, {"pro", "business", "enterprise"}),
    "ai_bots_protection": (["block", "disabled", "only_on_ad_pages"], set(PLANS)),
    "crawler_protection": (["enabled", "disabled"], set(PLANS)),
    "is_robots_txt_managed": (bool, set(PLANS)),
    "auto_update_model": (bool, {"enterprise"}),
    "suppress_session_score": (bool, {"enterprise"}),
    "bm_cookie_enabled": (bool, {"enterprise"}),
}
