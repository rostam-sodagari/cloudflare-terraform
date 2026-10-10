"""Essential guidance for generated zone and account YAML headers."""

EDITING = """#
# Uncomment one example's config lines; keep indentation and replace sample values.
# Syntax: docs/configuration.md. Validate and review the plan before applying."""

DOMAIN_GUIDANCE = {
    "dns/mx.yaml": "priority: integer 0-65535; lower is preferred. MX records are DNS only.",
    "dns/txt.yaml": "quoted defaults to true; false preserves legacy unquoted TXT values.",
    "dns/spf.yaml": """extra: optional list of advanced mechanisms. raw overrides the builder.
ttl: 1 = automatic; comment: optional text; quoted defaults to true.""",
    "dns/dmarc.yaml": """Optional: subdomain_policy, pct (0-100), ruf, adkim/aspf (r or s), fo.
raw overrides the builder. ttl: 1 = automatic; comment: text; quoted defaults to true.""",
    "dns/dkim.yaml": "Replace the entire sample key, including '...', with your provider's real key.",
    "dns/caa.yaml": "name defaults to '@'; flags defaults to 0 (integer 0-255). ttl/comment are optional.",
    "dns/srv.yaml": "priority/weight/port: integers 0-65535. Lower priority is preferred; weight shares traffic.",
    "dns/email-routing.yaml": """forward destinations must be verified; worker value is a Worker name; drop omits value.
Catch-all forward/worker require destination. priority is optional; lower numbers run first.
catch_all accepts name and enabled (default true).""",
    'security/authenticated-origin-pulls.yaml': 'With hostname, zone_enabled optionally controls the zone default separately.',
    "waf/custom-rules.yaml": """Required: ref, description, expression, action. enabled defaults to true.
response needs block on a paid plan; skip requires a skip section.""",
    "waf/rate-limits.yaml": """Required: ref, description, expression, requests_per_period (integer >= 1).
period/mitigation_timeout default to 10 seconds. Free requires 10/10.
Advanced counting and custom responses: docs/yaml-fields.md.""",
    "waf/managed-rules.yaml": """Defaults: rulesets enabled; OWASP paranoia_level 1, score_threshold 40.
Omit action for default actions. raw_rules replaces the simple form.
Exceptions and raw examples: docs/rule-examples.md.""",
    "security/hsts.yaml": "max_age defaults to one year if omitted; set 300 explicitly when first enabling.",
    "security/bot-management.yaml": """sbfm automated actions: allow/block/managed_challenge; verified bots: allow/block.
ai_bots_protection: block/disabled/only_on_ad_pages; crawler_protection: enabled/disabled.
Other flags are booleans; choose the example for your plan.

EXAMPLE (Free):
fight_mode: true

EXAMPLE (Pro/Business):
sbfm_definitely_automated: managed_challenge
sbfm_verified_bots: allow
enable_js: true""",
    "security/ip-access-rules.yaml": "ASN value: AS64496; country value: GB. notes explains why the rule exists.",
    "security/origin-cert.yaml": "Replace the complete sample CSR; the '...' placeholder cannot be submitted.",
    "security/authenticated-origin-pulls.yaml": "Configure the origin to verify the client certificate; hostname scope needs cert_id.",
    "cache/cache-rules.yaml": "TTL defaults are seconds; override_origin needs default. Extra options: docs/rule-examples.md.",
    "rules/redirects.yaml": "Choose target_url.value OR target_url.expression, not both. status_code also accepts 303.",
    "rules/url-rewrites.yaml": "Choose value OR expression for each path/query. A query has no leading '?'.",
    "rules/request-headers.yaml": "remove needs no value; set uses value OR expression, not both.",
    "rules/response-headers.yaml": "remove needs no value; set/add uses value OR expression, not both.",
    "rules/origin.yaml": "port: 1-65535. Enterprise sni uses {value: hostname}; omit unchanged overrides.",
    "rules/config.yaml": "Per-request toggles use true/false, unlike quoted zone switches.",
    "rules/compression.yaml": "Use algorithms: [{name: none}] to disable compression.",
    "settings/zone.yaml": "All recognized setting values and examples: docs/zone-settings.md.",
}


def comment(text):
    """Make prose or an example inactive inside a YAML header."""
    return "\n".join("# " + line if line else "#" for line in text.splitlines())
