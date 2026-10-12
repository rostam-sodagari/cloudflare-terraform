"""HSTS, bot management, IP access rules, and the cache/settings.yaml
(tiered cache) toggle."""
import ipaddress
import re

from config import BOT_FIELDS
from .common import Ctx, check_enum, check_fields, check_type, is_cidr, is_ip, load, suggest, list_values


def validate_security(report, d, plan):
    domain_dir = d
    _validate_hsts(report, domain_dir, plan)
    _validate_authenticated_origin_pulls(report, domain_dir, plan)
    _validate_total_tls(report, domain_dir, plan)
    _validate_ct_alerting(report, domain_dir, plan)
    _validate_origin_cert(report, domain_dir, plan)
    _validate_certificate_pack(report, domain_dir, plan)
    _validate_bot_management(report, domain_dir, plan)
    _validate_ip_access_rules(report, domain_dir, plan)
    _validate_settings(report, domain_dir, plan)
    _validate_variants(report, domain_dir, plan)


def _validate_hsts(report, domain_dir, plan):
    file_path = domain_dir / "security" / "hsts.yaml"
    data, lines = load(report, file_path)
    if data in (None, "ERROR"):
        return
    ctx = Ctx(report, file_path, lines, plan)
    field_types = {"enabled": "bool", "max_age": "int", "include_subdomains": "bool", "preload": "bool", "nosniff": "bool"}
    if not check_fields(ctx, (), data, field_types):
        return
    max_age = data.get("max_age", 31536000)
    if isinstance(max_age, int) and not (0 <= max_age <= 31536000):
        ctx.error(("max_age",), "max_age must be 0 to 31536000 (one year).")
    if data.get("preload") and (not data.get("include_subdomains") or (isinstance(max_age, int) and max_age < 31536000)):
        ctx.error(("preload",), "preload requires include_subdomains: true and max_age: 31536000.")
    if data.get("preload"):
        ctx.flag("hsts_preload_risk", ("preload",), "preload is very hard to undo; browsers enforce HTTPS for months after removal.")


def _validate_authenticated_origin_pulls(report, domain_dir, plan):
    file_path = domain_dir / "security" / "authenticated-origin-pulls.yaml"
    data, lines = load(report, file_path)
    if data in (None, "ERROR"):
        return
    ctx = Ctx(report, file_path, lines, plan)
    if check_fields(ctx, (), data, {"enabled": "bool", "hostname": "str", "cert_id": "str", 'zone_enabled': 'bool'}, ["enabled"]):
        if ('cert_id' in data or 'zone_enabled' in data) and not data.get('hostname'):
            ctx.error(('hostname',), 'hostname is required with cert_id or zone_enabled.')


def _validate_total_tls(report, domain_dir, plan):
    file_path = domain_dir / "security" / "total-tls.yaml"
    data, lines = load(report, file_path)
    if data in (None, "ERROR"):
        return
    ctx = Ctx(report, file_path, lines, plan)
    if not check_fields(ctx, (), data, {"enabled": "bool", "certificate_authority": "str"}, ["enabled"]):
        return
    check_enum(ctx, ("certificate_authority",), data.get("certificate_authority"),
               ["lets_encrypt", "google", "ssl_com"])


def _validate_ct_alerting(report, domain_dir, plan):
    file_path = domain_dir / "security" / "ct-alerting.yaml"
    data, lines = load(report, file_path)
    if data in (None, "ERROR"):
        return
    ctx = Ctx(report, file_path, lines, plan)
    if not check_fields(ctx, (), data, {"enabled": "bool", "emails": "list"}, ["enabled"]):
        return
    for index, email in enumerate(list_values(data.get("emails"))):
        if "@" not in str(email):
            ctx.error(("emails", index), f"'{email}' is not an e-mail address.")


def _validate_origin_cert(report, domain_dir, plan):
    file_path = domain_dir / "security" / "origin-cert.yaml"
    data, lines = load(report, file_path)
    if data in (None, "ERROR"):
        return
    ctx = Ctx(report, file_path, lines, plan)
    if not check_fields(ctx, (), data, {"csr": "str", "hostnames": "list", "request_type": "str",
                                    "requested_validity": "int"}, ["csr", "hostnames", "request_type"]):
        return
    check_enum(ctx, ("request_type",), data.get("request_type"), ["origin-rsa", "origin-ecc"])
    if isinstance(data.get("csr"), str) and "BEGIN CERTIFICATE REQUEST" not in data["csr"]:
        ctx.error(("csr",), "this does not look like a PEM certificate signing request.",
                  "it should contain -----BEGIN CERTIFICATE REQUEST-----")
    if isinstance(data.get("csr"), str) and "PRIVATE KEY" in data["csr"]:
        ctx.error(("csr",), "this looks like a private key, not a CSR.",
                  "never put a private key in this repo -- only the CSR (public) belongs here")


def _validate_certificate_pack(report, domain_dir, plan):
    file_path = domain_dir / "security" / "certificate-pack.yaml"
    data, lines = load(report, file_path)
    if data in (None, "ERROR"):
        return
    ctx = Ctx(report, file_path, lines, plan)
    if not check_fields(ctx, (), data, {"certificate_authority": "str", "type": "str", "validation_method": "str",
                                    "validity_days": "int", "hosts": "list", "cloudflare_branding": "bool"},
                    ["certificate_authority", "type", "validation_method", "validity_days"]):
        return
    check_enum(ctx, ("certificate_authority",), data.get("certificate_authority"),
               ["lets_encrypt", "google", "ssl_com"])
    check_enum(ctx, ("type",), data.get("type"), ["advanced", "custom"])
    check_enum(ctx, ("validation_method",), data.get("validation_method"), ["txt", "http", "email"])
    check_enum(ctx, ("validity_days",), data.get("validity_days"), [14, 30, 90, 365])


def _validate_bot_management(report, domain_dir, plan):
    file_path = domain_dir / "security" / "bot-management.yaml"
    data, lines = load(report, file_path)
    if data in (None, "ERROR"):
        return
    ctx = Ctx(report, file_path, lines, plan)
    if not check_type(ctx, (), data, "dict"):
        return
    if data.get("fight_mode") is True and data.get("enable_js") is False:
        ctx.error(("enable_js",), "Bot Fight Mode requires enable_js: true.")
    for setting_name, value in data.items():
        if setting_name not in BOT_FIELDS:
            ctx.error((setting_name,), f"unknown bot setting '{setting_name}'.", suggest(setting_name, BOT_FIELDS))
            continue
        allowed_values, supported_plans = BOT_FIELDS[setting_name]
        if allowed_values is bool:
            check_type(ctx, (setting_name,), value, "bool")
        else:
            check_enum(ctx, (setting_name,), value, allowed_values)
        if plan not in supported_plans:
            ctx.error((setting_name,), f"{setting_name} is not available on the {plan} plan.",
                      "Free uses fight_mode; Pro and Business use sbfm_*; auto_update_model etc. need Enterprise Bot Management")
        if setting_name == "sbfm_likely_automated" and plan == "pro":
            ctx.warn((setting_name,), "likely automated is a Business feature in Super Bot Fight Mode; Pro may reject it.")


def _validate_ip_access_rules(report, domain_dir, plan):
    file_path = domain_dir / "security" / "ip-access-rules.yaml"
    data, lines = load(report, file_path)
    if data in (None, "ERROR"):
        return
    ctx = Ctx(report, file_path, lines, plan)
    field_types = {"mode": "str", "target": "str", "value": "str", "notes": "str"}
    if not check_type(ctx, (), data, "dict"):
        return
    rules_by_target = {}
    for key, rule in data.items():
        path = (key,)
        _validate_ip_access_rule(ctx, path, rule, field_types, plan, rules_by_target, key)


def _validate_settings(report, domain_dir, plan):
    file_path = domain_dir / "cache" / "settings.yaml"
    data, lines = load(report, file_path)
    if data in (None, "ERROR"):
        return
    ctx = Ctx(report, file_path, lines, plan)
    field_types = {"smart_tiered_cache": "str", "argo_tiered_caching": "str", "cache_reserve": "str",
            "argo_smart_routing": "str", "regional_tiered_cache": "str"}
    if not check_fields(ctx, (), data, field_types):
        return
    for setting_name in data:
        check_enum(ctx, (setting_name,), data[setting_name], ["on", "off"])


def _validate_variants(report, domain_dir, plan):
    file_path = domain_dir / "cache" / "variants.yaml"
    data, lines = load(report, file_path)
    if data in (None, "ERROR"):
        return
    ctx = Ctx(report, file_path, lines, plan)
    formats = {"avif": "list", "bmp": "list", "gif": "list", "jp2": "list", "jpeg": "list", "jpg": "list",
               "jpg2": "list", "png": "list", "tif": "list", "tiff": "list", "webp": "list"}
    check_fields(ctx, (), data, formats)


def _validate_ip_access_rule(ctx, path, rule, field_types, plan, rules_by_target, key):
    rule = {} if rule is None else rule
    if not check_fields(ctx, path, rule or {}, field_types, ["mode", "target", "value"]):
        return
    check_enum(ctx, path + ("mode",), rule.get("mode"), ["block", "challenge", "managed_challenge", "js_challenge", "whitelist"])
    target, value = rule.get("target"), str(rule.get("value"))
    check_enum(ctx, path + ("target",), target, ["ip", "ip6", "ip_range", "asn", "country"])
    value_validator = {"ip": lambda candidate: is_ip(candidate, 4), "ip6": lambda candidate: is_ip(candidate, 6),
          "ip_range": lambda candidate: "/" in candidate and is_cidr(candidate) and (
              (ipaddress.ip_network(candidate, strict=False).version == 4 and ipaddress.ip_network(candidate, strict=False).prefixlen in (16, 24))
              or (ipaddress.ip_network(candidate, strict=False).version == 6 and ipaddress.ip_network(candidate, strict=False).prefixlen in (32, 48, 64))),
          "asn": lambda candidate: bool(re.match(r"^AS\d+$", candidate)),
          "country": lambda candidate: bool(re.match(r"^([A-Z]{2}|T1|XX)$", candidate))}.get(target) if isinstance(target, str) else None
    if value_validator and not value_validator(value):
        hints = {"ip": "an IPv4 address like 203.0.113.7", "ip6": "an IPv6 address",
                 "ip_range": "a /16 or /24 IPv4 range, or /32, /48 or /64 IPv6 range", "asn": "AS followed by digits, e.g. AS64496",
                 "country": "a two-letter country code in capitals, e.g. GB"}
        ctx.error(path + ("value",), f"'{value}' is not valid for target {target}.", f"use {hints[target]}")
    if target == "country" and rule.get("mode") == "block" and plan != "enterprise":
        ctx.error(path + ("mode",), "blocking a whole country is Enterprise only.",
                  "use managed_challenge, or a WAF custom rule with ip.src.country")
    if not rule.get("notes"):
        ctx.flag("ip_access_rule_has_notes", path, "no notes: say why this rule exists so it can be removed safely later.")
    target_identity = (str(target), value)
    if target_identity in rules_by_target:
        ctx.error(path, f"same target as '{rules_by_target[target_identity]}'.", "remove one of them")
    rules_by_target[target_identity] = key
