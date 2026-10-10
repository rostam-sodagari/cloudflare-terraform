"""
Characterization corpus for scripts/validation/: fire every diagnostic the
validator can emit, and snapshot the exact output.

This is the gate for refactoring the validator. Two tests:

  test_every_site_is_covered   every ctx.error/warn/flag and report.add call
                               site in scripts/validation/ is reached by at
                               least one case (measured by tracing executed
                               lines, so it cannot drift out of date)
  test_golden_diagnostics      the (level, file, line, message, hint) of every
                               diagnostic matches tests/golden/ exactly

Comparison is order-insensitive on purpose: nothing sorts Report.items, so
output order is discovery order, and splitting a validator into smaller
functions legitimately reorders it. A sorted list (not a set) still catches
accidental duplicates.

Regenerate the golden file after an intended change:
    python3 tests/test_validator_corpus.py --write-golden
"""
import ast
import base64
import shutil
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
GOLDEN = Path(__file__).resolve().parent / "golden" / "validator_diagnostics.txt"
sys.path.insert(0, str(REPO / "scripts"))

from validation.account import validate_account  # noqa: E402
from validation.common import Report  # noqa: E402
from validation.domain import validate_domain  # noqa: E402

DOMAIN = "bad.example"
ZONE = '"0123456789abcdef0123456789abcdef"'


def domain_yaml(plan="free", name=DOMAIN):
    return f"name: {name}\nzone_id: {ZONE}\nplan: {plan}\n"


def _der(tag, body):
    if len(body) < 0x80:
        return bytes([tag, len(body)]) + body
    n = (len(body).bit_length() + 7) // 8
    return bytes([tag, 0x80 | n]) + len(body).to_bytes(n, "big") + body


def rsa_p_value(bits):
    """base64 DER SubjectPublicKeyInfo for an RSA key of `bits`, the form DKIM's
    p= holds. Built here rather than pasted as a blob so the key size the
    dkim_key_size_strong check reads is visible in the fixture."""
    modulus = b"\x00" + ((1 << (bits - 1)) | 1).to_bytes(bits // 8, "big")
    rsa = _der(0x30, _der(0x02, modulus) + _der(0x02, b"\x01\x00\x01"))
    algid = _der(0x30, _der(0x06, bytes([42, 134, 72, 134, 247, 13, 1, 1, 1])) + _der(0x05, b""))
    return base64.b64encode(_der(0x30, algid + _der(0x03, b"\x00" + rsa))).decode()


class Case:
    """One fixture: files to write into a throwaway domain folder."""

    def __init__(self, name, files, plan="free", domain_file=None, extra=None):
        self.name, self.files, self.plan, self.domain_file = name, files, plan, domain_file
        self.extra = extra or {}   # files outside the template, e.g. imports.tf


class AccountCase:
    """One fixture for validate_account(): files to write into a copy of account/."""

    def __init__(self, name, files):
        self.name, self.files = name, files


def _path(key):
    """dns__a -> dns/a.yaml, waf__custom_rules -> waf/custom-rules.yaml.
    Keyword names cannot hold '/' or '-', so '__' is the separator and a single
    '_' is a hyphen. run_case() checks every path against the template, so a
    name that does not match a real config file fails loudly instead of writing
    a file nothing reads."""
    folder, _, rest = key.partition("__")
    return f"{folder}/{rest.replace('_', '-')}.yaml"


def C(name, plan="free", **files):
    return Case(name, {_path(k): v for k, v in files.items()}, plan)


# ---------------------------------------------------------------------------
# The corpus. Each case writes a minimal valid domain plus the broken file(s)
# under test. Diagnostics are compared against the reviewed snapshot.
# ---------------------------------------------------------------------------
CASES = [
    C("email_subaddress_unsupported", dns__email_routing="enabled: true\nsupport_subaddress: true\n"),
    # ---- domain.yaml (domain.py) -----------------------------------------
    Case("domain_missing", {}, domain_file=""),
    Case("domain_bad_zone_id", {}, domain_file=f"name: {DOMAIN}\nzone_id: \"nothex\"\nplan: free\n"),
    Case("domain_name_mismatch", {}, domain_file="name: other.example\nzone_id: " + ZONE + "\nplan: free\n"),

    # ---- generic type and field checks (common.py) -----------------------
    C("type_bool_as_text", dns__a="www:\n  name: www\n  content: true\n"),
    C("type_number_as_text", dns__txt="t:\n  name: t\n  content: 12345\n"),
    C("type_not_text", dns__a="www:\n  name: www\n  content: [1, 2]\n"),
    C("type_not_int", dns__a="www:\n  name: www\n  content: 192.0.2.1\n  ttl: abc\n"),
    C("type_not_bool", dns__a="www:\n  name: www\n  content: 192.0.2.1\n  proxied: maybe\n"),
    C("type_not_list", waf__custom_rules="not: a list\n"),
    C("type_not_mapping", dns__a="- just\n- a list\n"),
    C("unknown_field", dns__a="www:\n  name: www\n  content: 192.0.2.1\n  nope: 1\n"),
    C("missing_required_field", dns__mx="m:\n  name: '@'\n  priority: 10\n"),
    C("ttl_out_of_range", dns__a="www:\n  name: www\n  content: 192.0.2.1\n  ttl: 3\n"),
    C("duplicate_yaml_key", dns__a="www:\n  content: 192.0.2.1\nwww:\n  content: 192.0.2.2\n"),
    C("yaml_syntax_error", dns__a="www:\n\tcontent: bad-tab\n"),

    # ---- DNS records (dns.py) --------------------------------------------
    C("dns_bad_key_chars", dns__a="we!rd:\n  name: www\n  content: 192.0.2.1\n"),
    C("dns_empty_record", dns__a="www:\n"),
    C("dns_bad_record_name", dns__a="www:\n  name: 'not a name!'\n  content: 192.0.2.1\n"),
    C("dns_bad_ipv4", dns__a="www:\n  name: www\n  content: 999.1.1.1\n"),
    C("dns_bad_ipv6", dns__aaaa="www:\n  name: www\n  content: not-v6\n"),
    C("dns_mx_priority", dns__mx="m:\n  name: '@'\n  content: mail.example.com\n  priority: 99999\n"),
    C("dns_apex_ns", dns__ns="n:\n  name: '@'\n  content: ns1.example.com\n"),
    C("dns_spf_in_txt", dns__txt="t:\n  name: '@'\n  content: v=spf1 -all\n"),
    C("dns_dmarc_in_txt", dns__txt="t:\n  name: _dmarc\n  content: v=DMARC1; p=none\n"),
    C("dns_txt_too_long", dns__txt="t:\n  name: t\n  content: " + "x" * 2100 + "\n"),
    C("dns_proxied_ttl", dns__a="www:\n  name: www\n  content: 192.0.2.1\n  proxied: true\n  ttl: 300\n"),
    C("dns_cname_self", dns__cname="c:\n  name: www\n  content: www.bad.example\n"),
    C("dns_comment_too_long", dns__a="www:\n  name: www\n  content: 192.0.2.1\n  comment: " + "c" * 150 + "\n"),
    C("dns_cname_and_other", dns__cname="c:\n  name: dup\n  content: a.example.com\n",
      dns__a="a:\n  name: dup\n  content: 192.0.2.1\n"),
    C("dns_duplicate_record", dns__a="one:\n  name: same\n  content: 192.0.2.1\ntwo:\n  name: same\n  content: 192.0.2.1\n"),
    C("dns_srv_bad_name", dns__srv="s:\n  name: nounderscore\n  priority: 1\n  weight: 1\n  port: 1\n  target: t.example.com\n"),
    C("dns_srv_range", dns__srv="s:\n  name: _sip._tcp\n  priority: 1\n  weight: 99999\n  port: 1\n  target: t.example.com\n"),
    C("dns_bad_host", dns__cname="c:\n  name: www\n  content: 'not a host!'\n"),

    # ---- quoted TXT handling (dns.py top) --------------------------------
    C("txt_unbalanced_quotes", dns__txt='t:\n  name: t\n  content: \'"abc\'\n'),
    C("txt_inner_quote", dns__txt='t:\n  name: t\n  content: \'a"b\'\n  quoted: false\n'),
    C("txt_chunk_too_long", dns__txt='t:\n  name: t\n  content: \'"' + "y" * 300 + '"\'\n'),

    # ---- SPF (dns.py) ----------------------------------------------------
    C("spf_plus_all", dns__spf="'@':\n  all: '+all'\n"),
    C("spf_bad_ip4", dns__spf="'@':\n  ip4: ['999.1.1.1']\n"),
    C("spf_bad_ip6", dns__spf="'@':\n  ip6: ['not-v6']\n"),
    C("spf_include_prefix", dns__spf="'@':\n  includes: ['include:_spf.google.com']\n"),
    C("spf_raw_prefix", dns__spf="'@':\n  raw: 'not-spf'\n"),
    C("spf_raw_and_fields", dns__spf="'@':\n  raw: 'v=spf1 -all'\n  all: '-all'\n"),
    C("spf_too_many_lookups", dns__spf="'@':\n  includes: " +
      str([f"s{i}.example.com" for i in range(12)]) + "\n"),

    # ---- DMARC (dns.py) --------------------------------------------------
    C("dmarc_pct_range", dns__dmarc="'@':\n  policy: reject\n  pct: 500\n  rua: [d@bad.example]\n"),
    C("dmarc_bad_email", dns__dmarc="'@':\n  policy: reject\n  rua: ['not-an-email']\n"),
    C("dmarc_raw_prefix", dns__dmarc="'@':\n  raw: 'nope'\n"),
    C("dmarc_no_rua", dns__dmarc="'@':\n  policy: reject\n"),
    C("dmarc_policy_none", dns__dmarc="'@':\n  policy: none\n  rua: [d@bad.example]\n"),

    # ---- DKIM (dns.py) ---------------------------------------------------
    C("dkim_no_domainkey", dns__dkim="k:\n  name: selector1\n  content: 'v=DKIM1; p=abc'\n"),
    C("dkim_no_p_tag", dns__dkim="k:\n  name: s1._domainkey\n  content: 'v=DKIM1; k=rsa'\n"),

    # ---- CAA / email routing (dns.py) ------------------------------------
    C("caa_untrusted", dns__caa="c:\n  name: '@'\n  tag: issue\n  value: example-ca.net\n"),
    C("email_routing_forward_no_dest", dns__email_routing="rules:\n  r1:\n    matcher: a@bad.example\n    action: forward\n"),
    C('email_literal_missing_fields', dns__email_routing='enabled: true\nrules:\n  - ref: route\n    matchers: [{type: literal}]\n    actions: [{type: drop}]\n'),
    C('email_worker_missing_value', dns__email_routing='enabled: true\nrules:\n  - ref: route\n    matchers: [{type: all}]\n    actions: [{type: worker}]\n'),
    C("dns_ref_twice", dns__email_routing="rules:\n  r1:\n    matcher: a@bad.example\n    action: drop\n  r2:\n    matcher: b@bad.example\n    action: drop\n"),

    # ---- zone settings (settings.py) -------------------------------------
    C("settings_hsts_here", settings__zone="security_header: on\n"),
    C("settings_unknown", settings__zone="not_a_setting: on\n"),
    C("settings_bool_as_text", settings__zone="ssl: true\n"),
    C("settings_number_read", settings__zone="min_tls_version: 1.2\n"),
    C("settings_cache_ttl", settings__zone="browser_cache_ttl: fast\n"),
    C("settings_weak_ssl", settings__zone="ssl: flexible\n"),
    C("settings_old_tls", settings__zone="min_tls_version: '1.0'\n"),

    # ---- security (security.py) ------------------------------------------
    C("hsts_max_age", security__hsts="enabled: true\nmax_age: 99999999\n"),
    C('origin_pulls_cert_scope', security__authenticated_origin_pulls='enabled: true\ncert_id: uploaded\n'),
    C("hsts_preload_requires", security__hsts="enabled: true\nmax_age: 31536000\npreload: true\n"),
    C("ct_bad_email", security__ct_alerting="enabled: true\nemails: ['nope']\n"),
    C("csr_not_pem", security__origin_cert="csr: 'not a csr'\n"),
    C("csr_is_private_key", security__origin_cert="csr: \"-----BEGIN PRIVATE KEY-----\\nabc\\n-----END PRIVATE KEY-----\"\n"),
    C("bot_unknown_setting", security__bot_management="not_a_bot_field: true\n"),
    C("bot_wrong_plan", security__bot_management="sbfm_verified_bots: allow\n"),
    C("bot_likely_automated_pro", plan="pro", security__bot_management="sbfm_likely_automated: block\n"),
    C("ip_rule_bad_value", security__ip_access_rules="r:\n  mode: block\n  target: ip\n  value: 'not-an-ip'\n  notes: why\n"),
    C("ip_rule_country", security__ip_access_rules="r:\n  mode: block\n  target: country\n  value: GB\n  notes: why\n"),
    C("ip_rule_no_notes", security__ip_access_rules="r:\n  mode: block\n  target: ip\n  value: 192.0.2.1\n"),
    C("ip_rule_same_target", security__ip_access_rules=
      "a:\n  mode: block\n  target: ip\n  value: 192.0.2.1\n  notes: x\n"
      "b:\n  mode: challenge\n  target: ip\n  value: 192.0.2.1\n  notes: y\n"),

    # ---- WAF (waf.py) ----------------------------------------------------
    C("waf_too_many_rules", waf__custom_rules="".join(
      f"- ref: r{i}\n  expression: 'ip.src eq 192.0.2.{i}'\n  action: block\n" for i in range(8))),
    C("waf_log_action", waf__custom_rules="- ref: r1\n  expression: 'ip.src eq 192.0.2.1'\n  action: log\n"),
    C("waf_skip_without_skip", waf__custom_rules=
      "- ref: r1\n  expression: 'ip.src eq 192.0.2.1'\n  action: block\n  skip:\n    phases: [http_ratelimit]\n"),
    C("waf_skip_needs_section", waf__custom_rules="- ref: r1\n  expression: 'ip.src eq 192.0.2.1'\n  action: skip\n"),
    C("waf_expression_empty", waf__custom_rules="- ref: r1\n  expression: ''\n  action: block\n"),
    C("waf_regex_on_free", waf__custom_rules=
      '- ref: r1\n  expression: \'http.request.uri.path matches "^/a"\'\n  action: block\n'),
    C("waf_unbalanced", waf__custom_rules="- ref: r1\n  expression: '(ip.src eq 192.0.2.1'\n  action: block\n"),
    C("waf_undefined_list", waf__custom_rules="- ref: r1\n  expression: 'ip.src in $nope'\n  action: block\n"),
    C("waf_bad_ref_chars", waf__custom_rules="- ref: 'bad ref!'\n  expression: 'ip.src eq 192.0.2.1'\n  action: block\n"),
    C("waf_ref_twice", waf__custom_rules=
      "- ref: same\n  expression: 'ip.src eq 192.0.2.1'\n  action: block\n"
      "- ref: same\n  expression: 'ip.src eq 192.0.2.2'\n  action: block\n"),
    C("rl_too_many", plan="free", waf__rate_limits="".join(
      f"- ref: rl{i}\n  expression: 'http.host eq \"bad.example\"'\n  action: block\n"
      f"  period: 10\n  requests_per_period: 10\n  mitigation_timeout: 10\n"
      f"  characteristics: [ip.src, cf.colo.id]\n" for i in range(3))),
    C("rl_bad_period", waf__rate_limits=
      "- ref: rl\n  expression: 'http.host eq \"bad.example\"'\n  action: block\n"
      "  period: 7\n  requests_per_period: 10\n  mitigation_timeout: 10\n"
      "  characteristics: [ip.src, cf.colo.id]\n"),
    C("rl_period_plan", plan="free", waf__rate_limits=
      "- ref: rl\n  expression: 'http.host eq \"bad.example\"'\n  action: block\n"
      "  period: 60\n  requests_per_period: 10\n  mitigation_timeout: 10\n"
      "  characteristics: [ip.src, cf.colo.id]\n"),
    C("rl_bad_timeout", waf__rate_limits=
      "- ref: rl\n  expression: 'http.host eq \"bad.example\"'\n  action: block\n"
      "  period: 10\n  requests_per_period: 10\n  mitigation_timeout: 7\n"
      "  characteristics: [ip.src, cf.colo.id]\n"),
    C("rl_zero_requests", waf__rate_limits=
      "- ref: rl\n  expression: 'http.host eq \"bad.example\"'\n  action: block\n"
      "  period: 10\n  requests_per_period: 0\n  mitigation_timeout: 10\n"
      "  characteristics: [ip.src, cf.colo.id]\n"),
    C("rl_missing_colo", waf__rate_limits=
      "- ref: rl\n  expression: 'http.host eq \"bad.example\"'\n  action: block\n"
      "  period: 10\n  requests_per_period: 10\n  mitigation_timeout: 10\n"
      "  characteristics: [ip.src]\n"),
    C("rl_bad_characteristic", waf__rate_limits=
      "- ref: rl\n  expression: 'http.host eq \"bad.example\"'\n  action: block\n"
      "  period: 10\n  requests_per_period: 10\n  mitigation_timeout: 10\n"
      "  characteristics: [ip.src, cf.colo.id, cf.unique_visitor_id]\n"),
    C("rl_counting_expression", waf__rate_limits=
      "- ref: rl\n  expression: 'http.host eq \"bad.example\"'\n  action: block\n"
      "  period: 10\n  requests_per_period: 10\n  mitigation_timeout: 10\n"
      "  characteristics: [ip.src, cf.colo.id]\n  counting_expression: 'http.host eq \"x\"'\n"),
    C("managed_on_free", waf__managed_rules="cloudflare_managed:\n  enabled: true\n"),
    C("owasp_threshold", plan="pro", waf__managed_rules=
      "owasp:\n  enabled: true\n  score_threshold: 33\n"),
    C("managed_bad_ruleset", plan="pro", waf__managed_rules=
      "exceptions:\n  - ref: e1\n    expression: 'ip.src eq 192.0.2.1'\n    ruleset: nonsense\n"),
    C("managed_raw_and_structured", plan="pro", waf__managed_rules=
      "cloudflare_managed:\n  enabled: true\nraw_rules:\n  - action: execute\n    expression: 'true'\n"),
    C("waf_custom_response_action", waf__custom_rules=
      "- ref: r1\n  expression: 'ip.src eq 192.0.2.1'\n  action: challenge\n"
      "  response:\n    status_code: 403\n    content_type: text/plain\n    content: nope\n"),
    C("waf_custom_response_free", waf__custom_rules=
      "- ref: r1\n  expression: 'ip.src eq 192.0.2.1'\n  action: block\n"
      "  response:\n    status_code: 403\n    content_type: text/plain\n    content: nope\n"),
    C("waf_bad_status_code", plan="pro", waf__custom_rules=
      "- ref: r1\n  expression: 'ip.src eq 192.0.2.1'\n  action: block\n"
      "  response:\n    status_code: 700\n    content_type: text/plain\n    content: nope\n"),

    # ---- rule files (rules.py) -------------------------------------------
    C("rules_too_many", rules__redirects="".join(
      f"- ref: rr{i}\n  expression: 'http.host eq \"bad.example\"'\n"
      f"  action_parameters:\n    from_value:\n      target_url:\n        value: https://a.example/{i}\n"
      for i in range(12))),
    C("rules_unknown_field", rules__redirects=
      "- ref: r1\n  expression: 'true'\n  nope: 1\n  action_parameters:\n"
      "    from_value:\n      target_url:\n        value: https://a.example/\n"),
    C("rules_missing_required", rules__redirects="- expression: 'true'\n"),
    C("rules_wrong_action", rules__redirects=
      "- ref: r1\n  expression: 'true'\n  action: block\n  action_parameters:\n"
      "    from_value:\n      target_url:\n        value: https://a.example/\n"),
    C("rules_no_action_parameters", rules__redirects="- ref: r1\n  expression: 'true'\n"),
    # ---- gaps the coverage tracer found after the first pass --------------
    Case("imports_tf_present", {}, extra={"imports.tf": "# adopt\n"}),
    C("enum_invalid_value", security__ip_access_rules=
      "r:\n  mode: nonsense\n  target: ip\n  value: 192.0.2.1\n  notes: why\n"),
    C("spf_raw_with_includes", dns__spf="'@':\n  raw: 'v=spf1 -all'\n  includes: ['a.example.com']\n"),
    C("dkim_weak_rsa", dns__dkim=
      "k:\n  name: s1._domainkey\n  content: 'v=DKIM1; k=rsa; p=" + rsa_p_value(512) + "'\n"),
    C("email_routing_ref_twice", dns__email_routing=
      "rules:\n"
      "  - ref: same\n    matchers: [{field: to, type: literal, value: a@bad.example}]\n"
      "    actions: [{type: drop}]\n"
      "  - ref: same\n    matchers: [{field: to, type: literal, value: b@bad.example}]\n"
      "    actions: [{type: drop}]\n"),
    C("email_routing_catch_all", dns__email_routing="catch_all:\n  action: forward\n"),
    C("waf_skip_section_empty", waf__custom_rules=
      "- ref: r1\n  expression: 'ip.src eq 192.0.2.1'\n  action: skip\n  skip:\n    phases: []\n"),
    C("rl_log_action", waf__rate_limits=
      "- ref: rl\n  expression: 'http.host eq \"bad.example\"'\n  action: log\n"
      "  period: 10\n  requests_per_period: 10\n  mitigation_timeout: 10\n"
      "  characteristics: [ip.src, cf.colo.id]\n"),
    C("rl_timeout_plan", plan="free", waf__rate_limits=
      "- ref: rl\n  expression: 'http.host eq \"bad.example\"'\n  action: block\n"
      "  period: 10\n  requests_per_period: 10\n  mitigation_timeout: 60\n"
      "  characteristics: [ip.src, cf.colo.id]\n"),
    C("managed_bad_rulesets", plan="pro", waf__managed_rules=
      "exceptions:\n  - ref: e1\n    expression: 'ip.src eq 192.0.2.1'\n    rulesets: [nonsense]\n"),
    C("managed_override_log", plan="pro", waf__managed_rules=
      "cloudflare_managed:\n  enabled: true\n  action: log\n"),
    C("raw_rules_log", plan="pro", waf__managed_rules=
      "raw_rules:\n  - action: log\n    expression: 'true'\n"),
    C("origin_host_header_ent", rules__origin=
      "- ref: r1\n  expression: 'true'\n  action_parameters:\n    host_header: a.example.com\n"),
    C("origin_host_override_ent", rules__origin=
      "- ref: r1\n  expression: 'true'\n  action_parameters:\n    origin:\n      host: a.example.com\n"),

    # Numeric enums: a typo in any of these used to crash validate.py with a
    # TypeError from suggest() instead of reporting the error. One case per
    # call site so the fix cannot regress.
    C("numeric_enum_caa_flags", dns__caa=
      "c:\n  name: '@'\n  tag: issue\n  value: letsencrypt.org\n  flags: notanumber\n"),
    C("numeric_enum_validity_days", security__origin_cert="validity_days: notanumber\n"),

    # check_rule_schema's type branches (common.py:305-345)
    C("schema_not_text", rules__config=
      "- ref: r1\n  expression: 'true'\n  action_parameters:\n    content: true\n"),
    C("schema_bad_enum", rules__config=
      "- ref: r1\n  expression: 'true'\n  action_parameters:\n    content_type: nonsense\n"),
    C("schema_not_number", rules__redirects=
      "- ref: r1\n  expression: 'true'\n  action_parameters:\n    from_value:\n"
      "      status_code: notanumber\n      target_url:\n        value: https://a.example/\n"),
    C("schema_not_bool", rules__config=
      "- ref: r1\n  expression: 'true'\n  action_parameters:\n    cache: maybe\n"),
    C("schema_not_list", rules__config=
      "- ref: r1\n  expression: 'true'\n  action_parameters:\n    additional_cacheable_ports: 80\n"),
    C("schema_not_item_list", rules__config=
      "- ref: r1\n  expression: 'true'\n  action_parameters:\n    algorithms: nope\n"),
    C("schema_not_map", rules__response_headers=
      "- ref: r1\n  expression: 'true'\n  action_parameters:\n    headers: nope\n"),
    C("schema_not_fields", rules__redirects=
      "- ref: r1\n  expression: 'true'\n  action_parameters:\n    from_value: nope\n"),
    C("schema_unknown_field", rules__config=
      "- ref: r1\n  expression: 'true'\n  action_parameters:\n    madeupfield: 1\n"),

    C("rules_regex_replace_free", rules__url_rewrites=
      "- ref: r1\n  expression: 'true'\n  action_parameters:\n    uri:\n      path:\n"
      "        expression: 'regex_replace(http.request.uri.path, \"a\", \"b\")'\n"),
]

ACCOUNT_CASES = [
    AccountCase("account_bad_id", {"account.yaml": "account_id: nothex\nplan: enterprise\n"}),
    AccountCase('logpush_destination_missing', {'settings/logpush.yaml': 'delivery:\n  dataset: http_requests\n'}),
    AccountCase('webhook_destination_missing', {'settings/notification-webhooks.yaml': 'delivery: {}\n'}),
    AccountCase("account_no_plan", {"account.yaml": f"account_id: {ZONE}\n"}),
    AccountCase("lists_enterprise_only", {
        "account.yaml": f"account_id: {ZONE}\nplan: pro\n",
        "lists/hostname.yaml": "hosts:\n  items: [a.example.com]\n"}),
    AccountCase("list_bad_name", {"lists/ip.yaml": "Bad Name!:\n  items: [192.0.2.1]\n"}),
    AccountCase("list_name_twice", {
        "lists/ip.yaml": "shared:\n  items: [192.0.2.1]\n",
        "lists/asn.yaml": "shared:\n  items: [64512]\n"}),
    AccountCase("list_bad_ip", {"lists/ip.yaml": "ips:\n  items: [not-an-ip]\n"}),
    AccountCase("list_bad_asn", {"lists/asn.yaml": "asns:\n  items: [notanasn]\n"}),
    AccountCase("list_duplicate_item", {"lists/ip.yaml": "ips:\n  items: [192.0.2.1, 192.0.2.1]\n"}),
    AccountCase("redirect_source_scheme", {"lists/redirect.yaml":
        "r:\n  items:\n    - source_url: https://a.example/x\n      target_url: https://b.example/y\n"}),
    AccountCase("redirect_target_scheme", {"lists/redirect.yaml":
        "r:\n  items:\n    - source_url: a.example/x\n      target_url: b.example/y\n"}),
    AccountCase("redirect_preserve_suffix", {"lists/redirect.yaml":
        "r:\n  items:\n    - source_url: a.example/x\n      target_url: https://b.example/y\n"
        "      preserve_path_suffix: true\n"}),
    AccountCase("too_many_lists", {
        "account.yaml": f"account_id: {ZONE}\nplan: free\n",
        "lists/ip.yaml": "".join(f"l{i}:\n  items: [192.0.2.{i}]\n" for i in range(12))}),
    AccountCase("too_many_redirect_lists", {
        "account.yaml": f"account_id: {ZONE}\nplan: enterprise\n",
        "lists/redirect.yaml": "".join(
            f"r{i}:\n  items:\n    - source_url: a.example/{i}\n      target_url: https://b.example/{i}\n"
            for i in range(26))}),
    AccountCase("too_many_items", {
        "account.yaml": f"account_id: {ZONE}\nplan: free\n",
        "lists/ip.yaml": "ips:\n  items: ["
                         + ", ".join(f"192.0.{i // 250}.{i % 250}" for i in range(11000)) + "]\n"}),
    AccountCase("numeric_enum_redirect_status", {"lists/redirect.yaml":
        "r:\n  items:\n    - source_url: a.example/x\n      target_url: https://b.example/y\n"
        "      status_code: notanumber\n"}),
    AccountCase("notification_no_mechanism", {"settings/notifications.yaml":
        "p:\n  alert_type: universal_ssl_event_type\n  mechanisms: {}\n"}),
    AccountCase("notification_unknown_webhook", {"settings/notifications.yaml":
        "p:\n  alert_type: universal_ssl_event_type\n  mechanisms:\n    webhooks: [nope]\n"}),
]

# Sites that cannot be reached through validate_domain()/validate_account():
# cli.py's "no such domain folder" lives in the command-line entry point and is
# covered by tests/test_validate.py instead.
UNREACHABLE = {("cli.py", 52)}


# ---------------------------------------------------------------------------
def diagnostic_sites():
    """{(filename, lineno)} for every ctx.error/warn/flag and report.add call
    in scripts/validation/ -- the coverage denominator."""
    out = {}
    for f in sorted((REPO / "scripts" / "validation").glob("*.py")):
        for n in ast.walk(ast.parse(f.read_text(encoding="utf-8"))):
            if not isinstance(n, ast.Call) or not isinstance(n.func, ast.Attribute):
                continue
            base, attr = getattr(n.func.value, "id", None), n.func.attr
            if (base == "ctx" and attr in ("error", "warn", "flag")) or (base == "report" and attr == "add"):
                out[(str(f), n.lineno)] = (f.name, n.lineno)
    return out


class Corpus:
    """Runs every case once, collecting diagnostics and executed lines."""

    def __init__(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.template = REPO / "domains" / "_template"
        self.sites = diagnostic_sites()
        self.watched = {path for path, _ in self.sites}
        self.fired = set()
        self.diagnostics = []
        self._list_names = validate_account(Report(), REPO / "account")

    def _trace(self, frame, event, arg):
        if event == "call":
            return self._trace if frame.f_code.co_filename in self.watched else None
        if event == "line":
            self.fired.add((frame.f_code.co_filename, frame.f_lineno))
        return self._trace

    def run_case(self, case):
        d = self.tmp / DOMAIN
        if d.exists():
            shutil.rmtree(d)
        shutil.copytree(self.template, d)
        (d / "README.md").unlink(missing_ok=True)
        text = domain_yaml(case.plan) if case.domain_file is None else case.domain_file
        if text:
            (d / "domain.yaml").write_text(text, encoding="utf-8", newline="\n")
        else:
            (d / "domain.yaml").unlink()
        for rel, body in case.extra.items():
            (d / rel).write_text(body, encoding="utf-8", newline="\n")
        for rel, body in case.files.items():
            p = d / rel
            if not p.exists():
                raise AssertionError(
                    f"case {case.name!r} writes {rel}, which is not a file in domains/_template -- "
                    f"check the name (a wrong path would be silently ignored by the validator)")
            p.write_text(textwrap.dedent(body), encoding="utf-8", newline="\n")

        report = Report()
        sys.settrace(self._trace)
        try:
            validate_domain(report, d, self._list_names)
        finally:
            sys.settrace(None)
        for level, file, line, msg, hint in report.items:
            rel = Path(file).name if Path(file).is_absolute() else str(file)
            try:
                rel = str(Path(file).relative_to(d)).replace("\\", "/")
            except ValueError:
                pass
            self.diagnostics.append((case.name, level, rel, line, msg, hint or ""))

    def run_account_case(self, case):
        a = self.tmp / "account"
        if a.exists():
            shutil.rmtree(a)
        shutil.copytree(REPO / "account", a)
        for rel, body in case.files.items():
            p = a / rel
            if not p.exists():
                raise AssertionError(
                    f"account case {case.name!r} writes {rel}, which is not a file in account/")
            p.write_text(textwrap.dedent(body), encoding="utf-8", newline="\n")

        report = Report()
        sys.settrace(self._trace)
        try:
            validate_account(report, a)
        finally:
            sys.settrace(None)
        for level, file, line, msg, hint in report.items:
            try:
                rel = str(Path(file).relative_to(a)).replace("\\", "/")
            except ValueError:
                rel = Path(file).name
            self.diagnostics.append((case.name, level, rel, line, msg, hint or ""))

    def run_all(self):
        for case in CASES:
            self.run_case(case)
        for case in ACCOUNT_CASES:
            self.run_account_case(case)
        return self

    def cleanup(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def uncovered(self):
        return sorted(label for site, label in self.sites.items()
                      if site not in self.fired and label not in UNREACHABLE)

    def golden_text(self):
        rows = sorted(f"{c}\t{lv}\t{f}:{ln}\t{m}\t{h}" for c, lv, f, ln, m, h in self.diagnostics)
        return "\n".join(rows) + "\n"


_corpus = None


def corpus():
    global _corpus
    if _corpus is None:
        _corpus = Corpus().run_all()
    return _corpus


class ValidatorCorpusTest(unittest.TestCase):
    @classmethod
    def tearDownClass(cls):
        if _corpus:
            _corpus.cleanup()

    def test_every_site_is_covered(self):
        missing = corpus().uncovered()
        self.assertEqual(missing, [], f"{len(missing)} diagnostic site(s) no case reaches: {missing}")

    def test_golden_diagnostics(self):
        self.assertTrue(GOLDEN.exists(),
                        f"no golden file; create it with: python3 {Path(__file__).name} --write-golden")
        self.assertEqual(corpus().golden_text(), GOLDEN.read_text(encoding="utf-8"),
                         "validator output changed; review the diff, then regenerate with --write-golden")

    def test_corpus_actually_produces_diagnostics(self):
        self.assertGreater(len(corpus().diagnostics), 100)


if __name__ == "__main__":
    if "--write-golden" in sys.argv:
        c = corpus()
        GOLDEN.parent.mkdir(parents=True, exist_ok=True)
        GOLDEN.write_text(c.golden_text(), encoding="utf-8", newline="\n")
        print(f"wrote {GOLDEN} ({len(c.diagnostics)} diagnostics from {len(CASES)} cases)")
        print(f"coverage: {len(c.sites) - len(c.uncovered())}/{len(c.sites)} sites")
        for label in c.uncovered():
            print(f"  UNCOVERED {label[0]}:{label[1]}")
        c.cleanup()
    else:
        unittest.main()
