"""Known zone settings (settings/zone.yaml), their allowed enum values, and
which ones are plain on/off -- plus the rule-engine phase each rule file
maps to. Keep KNOWN_SETTINGS/SETTING_ENUMS in step with Cloudflare's zone
settings API when a new setting is added."""

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
