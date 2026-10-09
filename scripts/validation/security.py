"""HSTS, bot management, IP access rules, and the cache/settings.yaml
(tiered cache) toggle."""
import ipaddress
import re

from .common import BOT_FIELDS, Ctx, check_enum, check_fields, check_type, is_cidr, is_ip, load, suggest


def validate_security(report, d, plan):
    f = d / "security" / "hsts.yaml"
    data, lines = load(report, f)
    if data not in (None, "ERROR"):
        ctx = Ctx(report, f, lines, plan)
        spec = {"enabled": "bool", "max_age": "int", "include_subdomains": "bool", "preload": "bool", "nosniff": "bool"}
        if check_fields(ctx, (), data, spec):
            ma = data.get("max_age", 31536000)
            if isinstance(ma, int) and not (0 <= ma <= 31536000):
                ctx.error(("max_age",), "max_age must be 0 to 31536000 (one year).")
            if data.get("preload") and (not data.get("include_subdomains") or (isinstance(ma, int) and ma < 31536000)):
                ctx.error(("preload",), "preload requires include_subdomains: true and max_age: 31536000.")
            if data.get("preload"):
                ctx.flag("hsts_preload_risk", ("preload",), "preload is very hard to undo; browsers enforce HTTPS for months after removal.")

    f = d / "security" / "authenticated-origin-pulls.yaml"
    data, lines = load(report, f)
    if data not in (None, "ERROR"):
        ctx = Ctx(report, f, lines, plan)
        check_fields(ctx, (), data, {"enabled": "bool", "hostname": "str", "cert_id": "str"}, ["enabled"])

    f = d / "security" / "total-tls.yaml"
    data, lines = load(report, f)
    if data not in (None, "ERROR"):
        ctx = Ctx(report, f, lines, plan)
        if check_fields(ctx, (), data, {"enabled": "bool", "certificate_authority": "str"}, ["enabled"]):
            check_enum(ctx, ("certificate_authority",), data.get("certificate_authority"),
                       ["lets_encrypt", "google", "ssl_com"])

    f = d / "security" / "ct-alerting.yaml"
    data, lines = load(report, f)
    if data not in (None, "ERROR"):
        ctx = Ctx(report, f, lines, plan)
        if check_fields(ctx, (), data, {"enabled": "bool", "emails": "list"}, ["enabled"]):
            for i, e in enumerate(data.get("emails") or []):
                if "@" not in str(e):
                    ctx.error(("emails", i), f"'{e}' is not an e-mail address.")

    f = d / "security" / "origin-cert.yaml"
    data, lines = load(report, f)
    if data not in (None, "ERROR"):
        ctx = Ctx(report, f, lines, plan)
        if check_fields(ctx, (), data, {"csr": "str", "hostnames": "list", "request_type": "str",
                                        "requested_validity": "int"}, ["csr", "hostnames", "request_type"]):
            check_enum(ctx, ("request_type",), data.get("request_type"), ["origin-rsa", "origin-ecc"])
            if isinstance(data.get("csr"), str) and "BEGIN CERTIFICATE REQUEST" not in data["csr"]:
                ctx.error(("csr",), "this does not look like a PEM certificate signing request.",
                          "it should contain -----BEGIN CERTIFICATE REQUEST-----")
            if isinstance(data.get("csr"), str) and "PRIVATE KEY" in data["csr"]:
                ctx.error(("csr",), "this looks like a private key, not a CSR.",
                          "never put a private key in this repo -- only the CSR (public) belongs here")

    f = d / "security" / "certificate-pack.yaml"
    data, lines = load(report, f)
    if data not in (None, "ERROR"):
        ctx = Ctx(report, f, lines, plan)
        if check_fields(ctx, (), data, {"certificate_authority": "str", "type": "str", "validation_method": "str",
                                        "validity_days": "int", "hosts": "list", "cloudflare_branding": "bool"},
                        ["certificate_authority", "type", "validation_method", "validity_days"]):
            check_enum(ctx, ("certificate_authority",), data.get("certificate_authority"),
                       ["lets_encrypt", "google", "ssl_com"])
            check_enum(ctx, ("type",), data.get("type"), ["advanced", "custom"])
            check_enum(ctx, ("validation_method",), data.get("validation_method"), ["txt", "http", "email"])
            check_enum(ctx, ("validity_days",), data.get("validity_days"), [14, 30, 90, 365])

    f = d / "security" / "bot-management.yaml"
    data, lines = load(report, f)
    if data not in (None, "ERROR"):
        ctx = Ctx(report, f, lines, plan)
        if check_type(ctx, (), data, "dict"):
            for k, v in data.items():
                if k not in BOT_FIELDS:
                    ctx.error((k,), f"unknown bot setting '{k}'.", suggest(k, BOT_FIELDS))
                    continue
                allowed, plans = BOT_FIELDS[k]
                if allowed is bool:
                    check_type(ctx, (k,), v, "bool")
                else:
                    check_enum(ctx, (k,), v, allowed)
                if plan not in plans:
                    ctx.error((k,), f"{k} is not available on the {plan} plan.",
                              "Free uses fight_mode; Pro and Business use sbfm_*; auto_update_model etc. need Enterprise Bot Management")
                if k == "sbfm_likely_automated" and plan == "pro":
                    ctx.warn((k,), "likely automated is a Business feature in Super Bot Fight Mode; Pro may reject it.")

    f = d / "security" / "ip-access-rules.yaml"
    data, lines = load(report, f)
    if data not in (None, "ERROR"):
        ctx = Ctx(report, f, lines, plan)
        spec = {"mode": "str", "target": "str", "value": "str", "notes": "str"}
        if check_type(ctx, (), data, "dict"):
            seen = {}
            for key, r in data.items():
                p = (key,)
                if not check_fields(ctx, p, r or {}, spec, ["mode", "target", "value"]):
                    continue
                check_enum(ctx, p + ("mode",), r.get("mode"), ["block", "challenge", "managed_challenge", "js_challenge", "whitelist"])
                t, v = r.get("target"), str(r.get("value"))
                check_enum(ctx, p + ("target",), t, ["ip", "ip6", "ip_range", "asn", "country"])
                ok = {"ip": lambda x: is_ip(x, 4), "ip6": lambda x: is_ip(x, 6),
                      "ip_range": lambda x: "/" in x and is_cidr(x) and (
                          (ipaddress.ip_network(x, strict=False).version == 4 and ipaddress.ip_network(x, strict=False).prefixlen in (16, 24))
                          or (ipaddress.ip_network(x, strict=False).version == 6 and ipaddress.ip_network(x, strict=False).prefixlen in (32, 48, 64))),
                      "asn": lambda x: bool(re.match(r"^AS\d+$", x)),
                      "country": lambda x: bool(re.match(r"^([A-Z]{2}|T1|XX)$", x))}.get(t)
                if ok and not ok(v):
                    hints = {"ip": "an IPv4 address like 203.0.113.7", "ip6": "an IPv6 address",
                             "ip_range": "a /16 or /24 IPv4 range, or /32, /48 or /64 IPv6 range", "asn": "AS followed by digits, e.g. AS64496",
                             "country": "a two-letter country code in capitals, e.g. GB"}
                    ctx.error(p + ("value",), f"'{v}' is not valid for target {t}.", f"use {hints[t]}")
                if t == "country" and r.get("mode") == "block" and plan != "enterprise":
                    ctx.error(p + ("mode",), "blocking a whole country is Enterprise only.",
                              "use managed_challenge, or a WAF custom rule with ip.src.country")
                if not r.get("notes"):
                    ctx.flag("ip_access_rule_has_notes", p, "no notes: say why this rule exists so it can be removed safely later.")
                sig = (t, v)
                if sig in seen:
                    ctx.error(p, f"same target as '{seen[sig]}'.", "remove one of them")
                seen[sig] = key

    f = d / "cache" / "settings.yaml"
    data, lines = load(report, f)
    if data not in (None, "ERROR"):
        ctx = Ctx(report, f, lines, plan)
        spec = {"smart_tiered_cache": "str", "argo_tiered_caching": "str", "cache_reserve": "str",
                "argo_smart_routing": "str", "regional_tiered_cache": "str"}
        if check_fields(ctx, (), data, spec):
            for k in data:
                check_enum(ctx, (k,), data[k], ["on", "off"])

    f = d / "cache" / "variants.yaml"
    data, lines = load(report, f)
    if data not in (None, "ERROR"):
        ctx = Ctx(report, f, lines, plan)
        formats = {"avif": "list", "bmp": "list", "gif": "list", "jp2": "list", "jpeg": "list", "jpg": "list",
                   "jpg2": "list", "png": "list", "tif": "list", "tiff": "list", "webp": "list"}
        check_fields(ctx, (), data, formats)
