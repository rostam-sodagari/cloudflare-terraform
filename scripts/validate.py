#!/usr/bin/env python3
"""
Check the YAML in a domain folder (or account/) before Terraform sees it.

    python3 scripts/validate.py domains/example.com
    python3 scripts/validate.py account
    python3 scripts/validate.py --all

Every problem is reported with file, line, what is wrong and how to fix it.
Inside GitHub Actions the same messages appear as annotations on the PR.
Exit code 1 means at least one error; warnings never fail.

What it checks
  1. YAML syntax and duplicate keys (YAML silently keeps the last one).
  2. Unknown fields, with "did you mean" suggestions for typos.
  3. Types and allowed values, including the on/off and number-as-ID traps.
  4. IPs, CIDRs, hostnames, TTLs, ports, priorities, e-mail addresses.
  5. Plan limits and plan-only features, per Cloudflare's documentation.
  6. Cross-file rules: CNAME conflicts, duplicate records, SPF in txt.yaml,
     $list references that do not exist in account/lists.
  7. Rule action_parameters against the provider schema
     (scripts/data/ruleset_rule_schema.json).
"""
import argparse
import difflib
import ipaddress
import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    import yaml  # noqa: F401
    from yamlio import DuplicateKeyError, line_for, load_with_lines, unquote_txt
except ImportError:
    sys.exit("PyYAML is required: pip install -r requirements.txt")

ROOT = Path(__file__).resolve().parent.parent
RULE_SCHEMA = json.loads((ROOT / "scripts" / "data" / "ruleset_rule_schema.json").read_text())["rule"]
PLANS = ["free", "pro", "business", "enterprise"]

# --------------------------------------------------------------------------
# Plan facts (Cloudflare docs, checked October 2026). Keep in sync with
# modules/waf/main.tf and modules/rules/main.tf.
# --------------------------------------------------------------------------
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
REGEX_RE = re.compile(r"(\bmatches\b|\s~\s|\bregex_replace\s*\()")
LIST_REF_RE = re.compile(r"\$([a-z0-9_]+)")

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

BOT_FIELDS = {
    # field: (allowed values or type, plans)
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

HOST_RE = re.compile(r"^(?=.{1,253}$)(\*\.)?([A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9])?$")
NAME_RE = re.compile(r"^(@|\*|(\*\.)?[A-Za-z0-9_](?:[A-Za-z0-9_.-]{0,251}[A-Za-z0-9_])?)$")
KEY_RE = re.compile(r"^[A-Za-z0-9_@.\-]+$")
REF_RE = re.compile(r"^[A-Za-z0-9_\-]{1,120}$")
EMAIL_RE = re.compile(r"^(mailto:)?[^@\s]+@[^@\s]+\.[^@\s]+$")
HEX32 = re.compile(r"^[0-9a-f]{32}$")


# --------------------------------------------------------------------------
class Report:
    def __init__(self):
        self.items = []

    def add(self, level, file, line, msg, hint=None):
        self.items.append((level, str(file), line or 1, msg, hint))

    @property
    def errors(self):
        return [i for i in self.items if i[0] == "error"]

    def print(self):
        gha = os.environ.get("GITHUB_ACTIONS") == "true"
        for level, file, line, msg, hint in self.items:
            rel = os.path.relpath(file, ROOT) if os.path.isabs(file) else file
            rel = rel.replace(os.sep, "/")
            full = msg + (f" Fix: {hint}" if hint else "")
            if gha:
                print(f"::{level} file={rel},line={line}::{full}")
            colour = "\033[31m" if level == "error" else "\033[33m"
            reset = "\033[0m" if sys.stdout.isatty() else ""
            colour = colour if sys.stdout.isatty() else ""
            print(f"{colour}{level.upper()}{reset} {rel}:{line}: {msg}")
            if hint:
                print(f"    fix: {hint}")


class Ctx:
    """File-scoped helper so checks can say ctx.error(path, msg)."""

    def __init__(self, report, file, lines, plan):
        self.r, self.file, self.lines, self.plan = report, file, lines, plan

    def error(self, path, msg, hint=None):
        self.r.add("error", self.file, line_for(self.lines, path), msg, hint)

    def warn(self, path, msg, hint=None):
        self.r.add("warning", self.file, line_for(self.lines, path), msg, hint)


def suggest(word, options):
    m = difflib.get_close_matches(str(word), list(options), n=1, cutoff=0.6)
    return f"did you mean '{m[0]}'?" if m else f"allowed: {', '.join(sorted(options))}"


def fmt_path(path):
    """('www', 'content') -> www.content ; (0, 'expression') -> #1.expression"""
    return ".".join(f"#{p + 1}" if isinstance(p, int) else str(p) for p in path) or "(top level)"


# ---- typed field checks ------------------------------------------------------
def check_type(ctx, path, value, kind):
    """kind: str, int, bool, list, dict. Returns True when the type is right."""
    label = fmt_path(path)
    if kind == "str":
        if isinstance(value, bool):
            ctx.error(path, f"{label} is a yes/no value but must be text.",
                      f'put it in quotes, e.g. "{"on" if value else "off"}" or "{str(value).lower()}"')
            return False
        if isinstance(value, (int, float)):
            ctx.error(path, f"{label} was read as a number but must be text.", f'put it in quotes: "{value}"')
            return False
        if not isinstance(value, str):
            ctx.error(path, f"{label} must be text.")
            return False
        return True
    if kind == "int":
        if isinstance(value, bool) or not isinstance(value, int):
            ctx.error(path, f"{label} must be a whole number, got {value!r}.", "remove the quotes")
            return False
        return True
    if kind == "bool":
        if not isinstance(value, bool):
            ctx.error(path, f"{label} must be true or false, got {value!r}.", "write true or false without quotes")
            return False
        return True
    if kind == "list":
        if not isinstance(value, list):
            ctx.error(path, f"{label} must be a list.", "use [a, b] or one '- item' per line")
            return False
        return True
    if kind == "dict":
        if not isinstance(value, dict):
            ctx.error(path, f"{label} must be a set of 'field: value' lines.")
            return False
        return True
    return True


def check_fields(ctx, path, obj, spec, required=()):
    """spec: {field: kind}. Reports unknown and missing fields."""
    if not check_type(ctx, path, obj, "dict"):
        return False
    for k in obj:
        if k not in spec:
            ctx.error(path + (k,), f"unknown field '{k}' in {fmt_path(path)}.", suggest(k, spec))
    for k in required:
        if k not in obj or obj[k] is None:
            ctx.error(path, f"{fmt_path(path)} is missing required field '{k}'.")
    for k, kind in spec.items():
        if k in obj and obj[k] is not None:
            check_type(ctx, path + (k,), obj[k], kind)
    return True


def check_enum(ctx, path, value, allowed):
    if value is not None and value not in allowed:
        ctx.error(path, f"{fmt_path(path)} has invalid value '{value}'.", suggest(value, allowed))
        return False
    return True


def check_ttl(ctx, path, ttl, plan):
    if ttl is None or not isinstance(ttl, int) or isinstance(ttl, bool):
        return
    low = 30 if plan == "enterprise" else 60
    if ttl != 1 and not (low <= ttl <= 86400):
        ctx.error(path, f"ttl {ttl} is out of range.", f"use 1 (automatic) or {low} to 86400 seconds")


def is_ip(v, version):
    try:
        return ipaddress.ip_address(v).version == version
    except ValueError:
        return False


def is_cidr(v, version=None):
    try:
        n = ipaddress.ip_network(v, strict=False)
        return version is None or n.version == version
    except ValueError:
        return False


def check_host(ctx, path, v, what="hostname"):
    if isinstance(v, str) and (v.endswith(".") or not HOST_RE.match(v)):
        ctx.error(path, f"'{v}' is not a valid {what}.",
                  "no trailing dot, no scheme (https://) and no path" if v.endswith(".") or "/" in v else None)


def load(report, file):
    try:
        return load_with_lines(file)
    except DuplicateKeyError as e:
        report.add("error", file, e.line, f"duplicate key '{e.key}' (also on line {e.first_line}).",
                   "every key in a file must be unique; rename one of them")
    except Exception as e:  # yaml syntax
        mark = getattr(e, "problem_mark", None)
        report.add("error", file, (mark.line + 1) if mark else 1, f"YAML syntax error: {getattr(e, 'problem', e)}",
                   "check indentation (spaces, not tabs) and that every 'key: value' has a space after the colon")
    return "ERROR", {}


# ==========================================================================
# DNS
# ==========================================================================
REC_FIELDS = {"name": "str", "content": "str", "proxied": "bool", "ttl": "int", "comment": "str", "priority": "int",
              "quoted": "bool"}


def txt_text(ctx, path, value):
    """Check TXT quoting and return the text inside the quotes (or None)."""
    if not isinstance(value, str):
        return None
    plain, quoted = unquote_txt(value)
    if quoted is None:
        ctx.error(path, "this starts with a double quote but is not a list of quoted strings.",
                  'write the text without quotes (they are added for you), or as "part one" "part two"')
        return None
    if quoted is False and '"' in value:
        ctx.error(path, "text contains a double quote.", 'write it as "..." with each inner quote as \\"')
        return None
    if quoted:
        for part in re.findall(r'"((?:[^"\\]|\\.)*)"', value):
            if len(part) > 255:
                ctx.error(path, "a quoted string is longer than 255 characters.",
                          "split it into several quoted strings, or remove the quotes and they are split for you")
    return plain


def validate_dns(report, d, plan, zone):
    records = []  # (fqdn, type, content, file, key, lines)

    def fqdn(name):
        name = str(name)
        if name in ("@", zone):
            return zone
        return name if name.endswith("." + zone) else f"{name}.{zone}"

    for kind, rtype in [("a", "A"), ("aaaa", "AAAA"), ("cname", "CNAME"), ("mx", "MX"), ("txt", "TXT"), ("ns", "NS")]:
        f = d / "dns" / f"{kind}.yaml"
        data, lines = load(report, f)
        if data in (None, "ERROR"):
            continue
        ctx = Ctx(report, f, lines, plan)
        if not check_type(ctx, (), data, "dict"):
            continue
        fields = dict(REC_FIELDS)
        if rtype != "MX":
            fields.pop("priority")
        if rtype != "TXT":
            fields.pop("quoted")
        if rtype not in ("A", "AAAA", "CNAME"):
            fields.pop("proxied")
        for key, r in data.items():
            p = (key,)
            if not KEY_RE.match(str(key)):
                ctx.error(p, f"key '{key}' contains characters that are not allowed.", "use letters, digits, _ - . or @")
            if r is None:
                ctx.error(p, f"'{key}' has no fields.", "add at least name and content")
                continue
            if not check_fields(ctx, p, r, fields, required=["content"] + (["priority"] if rtype == "MX" else [])):
                continue
            name = r.get("name", key)
            if isinstance(name, str) and not NAME_RE.match(name):
                ctx.error(p + ("name",), f"'{name}' is not a valid record name.",
                          'use "@" for the apex, a label like "www", or a full name without a trailing dot')
            c = r.get("content")
            if not isinstance(c, str):
                continue
            if rtype == "A" and not is_ip(c, 4):
                ctx.error(p + ("content",), f"'{c}' is not an IPv4 address.", "AAAA records go in aaaa.yaml")
            if rtype == "AAAA" and not is_ip(c, 6):
                ctx.error(p + ("content",), f"'{c}' is not an IPv6 address.", "A records go in a.yaml")
            if rtype in ("CNAME", "MX", "NS"):
                check_host(ctx, p + ("content",), c)
            if rtype == "MX" and isinstance(r.get("priority"), int) and not (0 <= r["priority"] <= 65535):
                ctx.error(p + ("priority",), "MX priority must be 0 to 65535.")
            if rtype == "NS" and str(name) in ("@", zone):
                ctx.error(p + ("name",), "apex NS records are managed by Cloudflare.", "ns.yaml is for delegating a subdomain")
            if rtype == "TXT":
                c = txt_text(ctx, p + ("content",), c) or ""
                if c.startswith("v=spf1"):
                    ctx.error(p + ("content",), "SPF record found in txt.yaml.", "move it to spf.yaml")
                if c.startswith("v=DMARC1"):
                    ctx.error(p + ("content",), "DMARC record found in txt.yaml.", "move it to dmarc.yaml")
                if len(c) > 2048:
                    ctx.error(p + ("content",), "TXT content is longer than 2048 characters.")
            if r.get("proxied") is True and isinstance(r.get("ttl"), int) and r["ttl"] != 1:
                ctx.warn(p + ("ttl",), "ttl is ignored for proxied records (Cloudflare uses automatic).", "remove ttl")
            if rtype == "CNAME" and isinstance(name, str) and fqdn(c) == fqdn(name):
                ctx.error(p + ("content",), "CNAME points to itself.")
            check_ttl(ctx, p + ("ttl",), r.get("ttl"), plan)
            if isinstance(r.get("comment"), str) and len(r["comment"]) > (100 if plan == "free" else 500):
                ctx.error(p + ("comment",), "comment is too long for this plan (Free 100, paid 500 characters).")
            records.append((fqdn(name).lower(), rtype, c, f, key, lines))

    # SPF
    f = d / "dns" / "spf.yaml"
    data, lines = load(report, f)
    if data not in (None, "ERROR"):
        ctx = Ctx(report, f, lines, plan)
        spec = {"includes": "list", "ip4": "list", "ip6": "list", "a": "bool", "mx": "bool", "extra": "list",
                "all": "str", "raw": "str", "ttl": "int", "comment": "str", "quoted": "bool"}
        if check_type(ctx, (), data, "dict"):
            for host, s in data.items():
                p = (host,)
                if s is None:
                    s = {}
                if not check_fields(ctx, p, s, spec):
                    continue
                check_enum(ctx, p + ("all",), s.get("all"), ["-all", "~all", "?all", "+all"])
                if s.get("all") == "+all":
                    ctx.warn(p + ("all",), "+all lets anyone send mail as this domain.", 'use "-all" or "~all"')
                for i, ip in enumerate(s.get("ip4") or []):
                    if not is_cidr(str(ip), 4):
                        ctx.error(p + ("ip4", i), f"'{ip}' is not an IPv4 address or range.")
                for i, ip in enumerate(s.get("ip6") or []):
                    if not is_cidr(str(ip), 6):
                        ctx.error(p + ("ip6", i), f"'{ip}' is not an IPv6 address or range.")
                for i, inc in enumerate(s.get("includes") or []):
                    check_host(ctx, p + ("includes", i), str(inc).removeprefix("include:"), "domain")
                    if str(inc).startswith("include:"):
                        ctx.error(p + ("includes", i), "write only the domain; 'include:' is added for you.")
                raw = txt_text(ctx, p + ("raw",), s.get("raw")) if s.get("raw") else None
                if raw:
                    if not raw.startswith("v=spf1"):
                        ctx.error(p + ("raw",), "raw SPF must start with v=spf1.")
                    if any(k in s for k in ("includes", "ip4", "ip6", "a", "mx", "extra")):
                        ctx.warn(p + ("raw",), "raw is set, so the other fields are ignored.")
                    content = raw
                else:
                    parts = ["v=spf1"] + (["a"] if s.get("a") else []) + (["mx"] if s.get("mx") else [])
                    parts += [f"ip4:{x}" for x in s.get("ip4") or []] + [f"ip6:{x}" for x in s.get("ip6") or []]
                    parts += [f"include:{x}" for x in s.get("includes") or []] + list(s.get("extra") or [])
                    parts.append(s.get("all", "-all"))
                    content = " ".join(map(str, parts))
                lookups = len([t for t in content.split()
                               if re.match(r"^[-~?+]?(include:|a$|a:|a/|mx$|mx:|mx/|ptr|exists:|redirect=)", t)])
                if lookups > 10:
                    ctx.error(p, f"this SPF needs {lookups} DNS lookups; the limit is 10 (RFC 7208), so receivers will reject it.",
                              "remove senders you no longer use, or replace includes with ip4 ranges")
                check_ttl(ctx, p + ("ttl",), s.get("ttl"), plan)
                records.append(((zone if host == "@" else f"{host}.{zone}").lower(), "TXT", content, f, host, lines))

    # DMARC
    f = d / "dns" / "dmarc.yaml"
    data, lines = load(report, f)
    if data not in (None, "ERROR"):
        ctx = Ctx(report, f, lines, plan)
        spec = {"policy": "str", "subdomain_policy": "str", "pct": "int", "rua": "list", "ruf": "list",
                "adkim": "str", "aspf": "str", "fo": "str", "raw": "str", "ttl": "int", "comment": "str", "quoted": "bool"}
        if check_type(ctx, (), data, "dict"):
            for host, m in data.items():
                p = (host,)
                if not check_fields(ctx, p, m or {}, spec):
                    continue
                m = m or {}
                check_enum(ctx, p + ("policy",), m.get("policy"), ["none", "quarantine", "reject"])
                check_enum(ctx, p + ("subdomain_policy",), m.get("subdomain_policy"), ["none", "quarantine", "reject"])
                check_enum(ctx, p + ("adkim",), m.get("adkim"), ["r", "s"])
                check_enum(ctx, p + ("aspf",), m.get("aspf"), ["r", "s"])
                if isinstance(m.get("pct"), int) and not (0 <= m["pct"] <= 100):
                    ctx.error(p + ("pct",), "pct must be 0 to 100.")
                for fld in ("rua", "ruf"):
                    for i, a in enumerate(m.get(fld) or []):
                        if not EMAIL_RE.match(str(a)):
                            ctx.error(p + (fld, i), f"'{a}' is not an e-mail address.")
                if m.get("raw") and not (txt_text(ctx, p + ("raw",), m["raw"]) or "").startswith("v=DMARC1"):
                    ctx.error(p + ("raw",), "raw DMARC must start with v=DMARC1.")
                if not m.get("raw") and not m.get("rua"):
                    ctx.warn(p, "no rua address, so you will not receive DMARC reports.", "add rua: [dmarc@yourdomain]")
                check_ttl(ctx, p + ("ttl",), m.get("ttl"), plan)

    # DKIM
    f = d / "dns" / "dkim.yaml"
    data, lines = load(report, f)
    if data not in (None, "ERROR"):
        ctx = Ctx(report, f, lines, plan)
        if check_type(ctx, (), data, "dict"):
            for sel, k in data.items():
                p = (sel,)
                if not check_fields(ctx, p, k or {},
                                    {"content": "str", "name": "str", "ttl": "int", "comment": "str", "quoted": "bool"},
                                    ["content"]):
                    continue
                name = k.get("name")
                if isinstance(name, str):
                    check_host(ctx, p + ("name",), name)
                    if "_domainkey" not in name:
                        ctx.error(p + ("name",), f"'{name}' does not contain _domainkey.",
                                  'use "<selector>._domainkey" or "<selector>._domainkey.<subdomain>"')
                if isinstance(k.get("content"), str) and "p=" not in (txt_text(ctx, p + ("content",), k["content"]) or ""):
                    ctx.warn(p + ("content",), "this does not look like a DKIM key (no p= tag).")
                check_ttl(ctx, p + ("ttl",), k.get("ttl"), plan)

    # CAA
    f = d / "dns" / "caa.yaml"
    data, lines = load(report, f)
    if data not in (None, "ERROR"):
        ctx = Ctx(report, f, lines, plan)
        spec = {"name": "str", "flags": "int", "tag": "str", "value": "str", "ttl": "int", "comment": "str"}
        if check_type(ctx, (), data, "dict"):
            tags = set()
            for key, c in data.items():
                p = (key,)
                if not check_fields(ctx, p, c or {}, spec, ["tag", "value"]):
                    continue
                check_enum(ctx, p + ("tag",), c.get("tag"), ["issue", "issuewild", "iodef"])
                check_enum(ctx, p + ("flags",), c.get("flags"), [0, 128])
                tags.add((c.get("value") or "").lower())
                check_ttl(ctx, p + ("ttl",), c.get("ttl"), plan)
            if data and not ({"letsencrypt.org", "pki.goog"} & tags):
                ctx.warn((), "CAA records exist but neither letsencrypt.org nor pki.goog is allowed.",
                         "Cloudflare Universal SSL uses these CAs; without them edge certificates cannot renew")

    # SRV
    f = d / "dns" / "srv.yaml"
    data, lines = load(report, f)
    if data not in (None, "ERROR"):
        ctx = Ctx(report, f, lines, plan)
        spec = {"name": "str", "priority": "int", "weight": "int", "port": "int", "target": "str", "ttl": "int", "comment": "str"}
        if check_type(ctx, (), data, "dict"):
            for key, r in data.items():
                p = (key,)
                if not check_fields(ctx, p, r or {}, spec, ["name", "priority", "weight", "port", "target"]):
                    continue
                if isinstance(r.get("name"), str) and not re.match(r"^_[A-Za-z0-9-]+\._(tcp|udp|tls)(\.|$)", r["name"]):
                    ctx.error(p + ("name",), f"'{r['name']}' is not an SRV name.", "format: _service._tcp (or ._udp / ._tls)")
                for fld, hi in (("priority", 65535), ("weight", 65535), ("port", 65535)):
                    if isinstance(r.get(fld), int) and not (0 <= r[fld] <= hi):
                        ctx.error(p + (fld,), f"{fld} must be 0 to {hi}.")
                if isinstance(r.get("target"), str):
                    check_host(ctx, p + ("target",), r["target"])

    # DNSSEC
    f = d / "dns" / "dnssec.yaml"
    data, lines = load(report, f)
    if data not in (None, "ERROR"):
        ctx = Ctx(report, f, lines, plan)
        if check_fields(ctx, (), data, {"status": "str"}, ["status"]):
            check_enum(ctx, ("status",), data.get("status"), ["active", "disabled"])

    # Cross-file: CNAME conflicts and duplicates
    by_name = {}
    for fq, t, c, f, key, lines in records:
        by_name.setdefault(fq, []).append((t, c, f, key, lines))
    for fq, recs in by_name.items():
        types = {t for t, *_ in recs}
        # Cloudflare flattens a CNAME at the zone apex (serves it as A/AAAA),
        # which is exactly why MX/TXT/NS can coexist with a root CNAME --
        # the usual "CNAME excludes everything else" DNS rule only applies
        # below the apex.
        if "CNAME" in types and len(recs) > 1 and fq != zone:
            t, c, f, key, lines = [r for r in recs if r[0] == "CNAME"][0]
            others = ", ".join(sorted(f"{x[0]} in {x[2].name}" for x in recs if x[3] != key or x[2] != f))
            report.add("error", f, line_for(lines, (key,)), f"{fq} has a CNAME and other records ({others}).",
                       "a name with a CNAME cannot have any other record")
        seen = {}
        for t, c, f, key, lines in recs:
            sig = (t, c)
            if sig in seen:
                report.add("error", f, line_for(lines, (key,)),
                           f"duplicate {t} record {fq} -> {c} (also '{seen[sig][1]}' in {seen[sig][0].name}).",
                           "remove one of them")
            seen[sig] = (f, key)


# ==========================================================================
# WAF
# ==========================================================================
def expression_checks(ctx, path, expr, plan, list_names):
    if not isinstance(expr, str):
        return
    if not expr.strip():
        ctx.error(path, "expression is empty.")
    if plan in ("free", "pro") and REGEX_RE.search(expr):
        ctx.error(path, "regular expressions (matches, ~, regex_replace) need Business or Enterprise.",
                  "use wildcard, starts_with, ends_with or contains instead")
    if expr.count("(") != expr.count(")"):
        ctx.error(path, "unbalanced brackets in expression.")
    if list_names is not None:
        for name in LIST_REF_RE.findall(expr):
            if name not in list_names:
                ctx.error(path, f"expression uses list ${name}, which is not defined in account/lists/.",
                          "add the list in account/lists/ (and apply account first) or fix the name")


def validate_waf(report, d, plan, list_names, refs):
    # custom rules
    f = d / "waf" / "custom-rules.yaml"
    data, lines = load(report, f)
    if data not in (None, "ERROR"):
        ctx = Ctx(report, f, lines, plan)
        spec = {"ref": "str", "description": "str", "expression": "str", "action": "str", "enabled": "bool",
                "skip": "dict", "response": "dict"}
        if check_type(ctx, (), data, "list"):
            if len(data) > LIMITS["custom_rules"][plan]:
                ctx.error((), f"{len(data)} custom rules, but the {plan} plan allows {LIMITS['custom_rules'][plan]}.")
            for i, r in enumerate(data):
                p = (i,)
                if not check_fields(ctx, p, r, spec, ["ref", "expression", "action"]):
                    continue
                check_ref(ctx, p, r.get("ref"), refs, f)
                a = r.get("action")
                check_enum(ctx, p + ("action",), a, ["block", "managed_challenge", "js_challenge", "challenge", "log", "skip"])
                if a == "log" and plan != "enterprise":
                    ctx.error(p + ("action",), "the log action is Enterprise only.", "use managed_challenge while testing")
                expression_checks(ctx, p + ("expression",), r.get("expression"), plan, list_names)
                if "skip" in r:
                    if a != "skip":
                        ctx.error(p + ("skip",), "skip settings only apply when action is skip.")
                    sk = r["skip"] or {}
                    if check_fields(ctx, p + ("skip",), sk, {"ruleset": "str", "phases": "list", "products": "list", "log": "bool"}):
                        check_enum(ctx, p + ("skip", "ruleset"), sk.get("ruleset"), ["current"])
                        for j, ph in enumerate(sk.get("phases") or []):
                            check_enum(ctx, p + ("skip", "phases", j), ph,
                                       ["http_ratelimit", "http_request_firewall_managed", "http_request_sbfm"])
                        for j, pr in enumerate(sk.get("products") or []):
                            check_enum(ctx, p + ("skip", "products", j), pr,
                                       ["bic", "hot", "rateLimit", "securityLevel", "uaBlock", "waf", "zoneLockdown"])
                        if not any(sk.get(k) for k in ("ruleset", "phases", "products")):
                            ctx.error(p + ("skip",), "skip needs ruleset, phases or products.")
                elif a == "skip":
                    ctx.error(p, "action skip needs a skip: section.", "e.g. skip: { ruleset: current }")
                if "response" in r:
                    check_response(ctx, p + ("response",), r["response"], a, plan)

    # rate limits
    f = d / "waf" / "rate-limits.yaml"
    data, lines = load(report, f)
    if data not in (None, "ERROR"):
        ctx = Ctx(report, f, lines, plan)
        spec = {"ref": "str", "description": "str", "expression": "str", "action": "str", "enabled": "bool",
                "characteristics": "list", "period": "int", "requests_per_period": "int", "mitigation_timeout": "int",
                "counting_expression": "str", "requests_to_origin": "bool", "response": "dict"}
        if check_type(ctx, (), data, "list"):
            if len(data) > LIMITS["rate_limits"][plan]:
                ctx.error((), f"{len(data)} rate limiting rules, but the {plan} plan allows {LIMITS['rate_limits'][plan]}.")
            for i, r in enumerate(data):
                p = (i,)
                if not check_fields(ctx, p, r, spec, ["ref", "expression", "requests_per_period"]):
                    continue
                check_ref(ctx, p, r.get("ref"), refs, f)
                a = r.get("action", "block")
                check_enum(ctx, p + ("action",), a, ["block", "managed_challenge", "js_challenge", "challenge", "log"])
                if a == "log" and plan != "enterprise":
                    ctx.error(p + ("action",), "the log action is Enterprise only.")
                expression_checks(ctx, p + ("expression",), r.get("expression"), plan, list_names)
                period, timeout = r.get("period", 10), r.get("mitigation_timeout", 10)
                if isinstance(period, int):
                    if period not in RL_PERIODS:
                        ctx.error(p + ("period",), f"period {period} is not a supported value.", f"use one of {RL_PERIODS}")
                    elif period > RL_MAX_PERIOD[plan]:
                        ctx.error(p + ("period",), f"the {plan} plan allows a period up to {RL_MAX_PERIOD[plan]} seconds.")
                if isinstance(timeout, int):
                    if timeout not in RL_TIMEOUTS:
                        ctx.error(p + ("mitigation_timeout",), f"mitigation_timeout {timeout} is not a supported value.",
                                  f"use one of {RL_TIMEOUTS}")
                    elif timeout > RL_MAX_TIMEOUT[plan] or (plan == "free" and timeout != 10):
                        ctx.error(p + ("mitigation_timeout",),
                                  f"the {plan} plan allows mitigation_timeout up to {RL_MAX_TIMEOUT[plan]} seconds"
                                  + (" (exactly 10 on Free)." if plan == "free" else "."))
                if isinstance(r.get("requests_per_period"), int) and r["requests_per_period"] < 1:
                    ctx.error(p + ("requests_per_period",), "requests_per_period must be at least 1.")
                chars = r.get("characteristics")
                if isinstance(chars, list):
                    if "cf.colo.id" not in chars:
                        ctx.error(p + ("characteristics",), "characteristics must include cf.colo.id.",
                                  "e.g. [ip.src, cf.colo.id]")
                    if plan in RL_CHARS:
                        extra = set(map(str, chars)) - RL_CHARS[plan]
                        if extra:
                            ctx.error(p + ("characteristics",),
                                      f"{', '.join(sorted(extra))} not available on {plan}; it counts by IP only.",
                                      "use [ip.src, cf.colo.id]")
                if r.get("counting_expression") and plan in ("free", "pro"):
                    ctx.error(p + ("counting_expression",), "counting_expression needs Business or Enterprise.")
                if "response" in r:
                    check_response(ctx, p + ("response",), r["response"], a, plan)

    # managed
    f = d / "waf" / "managed-rules.yaml"
    data, lines = load(report, f)
    if data not in (None, "ERROR"):
        ctx = Ctx(report, f, lines, plan)
        spec = {"cloudflare_managed": "dict", "owasp": "dict", "exceptions": "list", "raw_rules": "list"}
        if check_fields(ctx, (), data, spec):
            if plan == "free":
                ctx.error((), "managed rulesets need Pro or above; on Free Cloudflare applies its Free Managed Ruleset itself.",
                          "comment out this file for Free zones")
            cm = data.get("cloudflare_managed")
            if cm is not None and check_fields(ctx, ("cloudflare_managed",), cm, {"enabled": "bool", "action": "str"}):
                check_action_override(ctx, ("cloudflare_managed", "action"), cm.get("action"), plan)
            ow = data.get("owasp")
            if ow is not None and check_fields(ctx, ("owasp",), ow, {"enabled": "bool", "action": "str",
                                                                     "paranoia_level": "int", "score_threshold": "int"}):
                check_action_override(ctx, ("owasp", "action"), ow.get("action"), plan)
                check_enum(ctx, ("owasp", "paranoia_level"), ow.get("paranoia_level"), [1, 2, 3, 4])
                st = ow.get("score_threshold")
                if isinstance(st, int) and st not in (25, 40, 60):
                    ctx.warn(("owasp", "score_threshold"), f"{st} is not one of Cloudflare's levels.", "60 low, 40 medium, 25 high")
            for i, e in enumerate(data.get("exceptions") or []):
                p = ("exceptions", i)
                if check_fields(ctx, p, e, {"ref": "str", "description": "str", "expression": "str", "rulesets": "list"},
                                ["ref", "expression", "rulesets"]):
                    check_ref(ctx, p, e.get("ref"), refs, f)
                    expression_checks(ctx, p + ("expression",), e.get("expression"), plan, list_names)
                    for j, rs in enumerate(e.get("rulesets") or []):
                        if rs not in ("owasp", "cloudflare_managed") and not HEX32.match(str(rs)):
                            ctx.error(p + ("rulesets", j), f"'{rs}' is not a ruleset.", "use owasp, cloudflare_managed or a 32-character ruleset ID")
            if data.get("raw_rules"):
                if any(k in data for k in ("cloudflare_managed", "owasp", "exceptions")):
                    ctx.warn(("raw_rules",), "raw_rules is set, so cloudflare_managed, owasp and exceptions are ignored.")
                for i, r in enumerate(data["raw_rules"]):
                    check_rule_schema(ctx, ("raw_rules", i), r, RULE_SCHEMA)
                    if isinstance(r, dict):
                        if r.get("action") == "log" and plan != "enterprise":
                            ctx.error(("raw_rules", i, "action"), "the log action is Enterprise only.")


def check_action_override(ctx, path, action, plan):
    if action is None:
        return
    check_enum(ctx, path, action, ["block", "managed_challenge", "js_challenge", "challenge", "log"])
    if action == "log" and plan != "enterprise":
        ctx.error(path, "the log action is Enterprise only.",
                  "remove action to use Cloudflare's default, or use managed_challenge while tuning")


def check_response(ctx, path, resp, action, plan):
    if action != "block":
        ctx.error(path, "a custom response only works with action: block.")
    if plan == "free":
        ctx.error(path, "custom block responses need a paid plan.")
    if check_fields(ctx, path, resp, {"status_code": "int", "content_type": "str", "content": "str"}, ["content"]):
        sc = resp.get("status_code")
        if isinstance(sc, int) and not (400 <= sc <= 499):
            ctx.error(path + ("status_code",), "status_code must be 400 to 499.")
        check_enum(ctx, path + ("content_type",), resp.get("content_type"),
                   ["text/html", "text/plain", "application/json", "text/xml"])


def check_ref(ctx, path, ref, refs, f):
    if not isinstance(ref, str):
        return
    if not REF_RE.match(ref):
        ctx.error(path + ("ref",), f"ref '{ref}' must be letters, digits, _ or - only (max 120).")
    key = (str(f.parent), ref)
    if key in refs:
        ctx.error(path + ("ref",), f"ref '{ref}' is used twice ({refs[key]}).", "each ref must be unique")
    refs[key] = f"{f.name} line {line_for(ctx.lines, path)}"


# ==========================================================================
# Rule files (cache, redirects, transforms, origin, config, compression)
# ==========================================================================
def check_rule_schema(ctx, path, value, schema):
    """Recursively check a value against the provider rule schema."""
    if isinstance(schema, str):
        base, _, enum = schema.partition("|")
        if base == "string":
            if isinstance(value, bool) or not isinstance(value, (str, int, float)):
                ctx.error(path, f"{fmt_path(path)} must be text, got {value!r}.", "put it in quotes")
            elif enum and str(value) not in enum.split(","):
                ctx.error(path, f"{fmt_path(path)} has invalid value '{value}'.", suggest(value, enum.split(",")))
        elif base == "number":
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                ctx.error(path, f"{fmt_path(path)} must be a number, got {value!r}.", "remove the quotes")
        elif base == "bool":
            if not isinstance(value, bool):
                ctx.error(path, f"{fmt_path(path)} must be true or false, got {value!r}.")
        elif base.startswith("["):
            if not isinstance(value, (list, dict)):
                ctx.error(path, f"{fmt_path(path)} must be a list.", "use [a, b]")
        return
    if "__list__" in schema:
        if not isinstance(value, list):
            ctx.error(path, f"{fmt_path(path)} must be a list ('- ' items).")
            return
        for i, v in enumerate(value):
            check_rule_schema(ctx, path + (i,), v, schema["__list__"])
        return
    if "__map__" in schema:
        if not isinstance(value, dict):
            ctx.error(path, f"{fmt_path(path)} must be a set of 'name: settings' entries.")
            return
        for k, v in value.items():
            check_rule_schema(ctx, path + (k,), v, schema["__map__"])
        return
    if not isinstance(value, dict):
        ctx.error(path, f"{fmt_path(path)} must be a set of 'field: value' lines.")
        return
    for k, v in value.items():
        if k not in schema:
            ctx.error(path + (k,), f"unknown field '{k}' in {fmt_path(path)}.", suggest(k, schema))
        elif v is not None:
            check_rule_schema(ctx, path + (k,), v, schema[k])


def validate_rule_files(report, d, plan, list_names, refs):
    allowed_top = {"ref", "description", "expression", "action_parameters", "enabled", "action"}
    for rel, expected_action in RULE_FILES.items():
        f = d / rel
        data, lines = load(report, f)
        if data in (None, "ERROR"):
            continue
        ctx = Ctx(report, f, lines, plan)
        if not check_type(ctx, (), data, "list"):
            continue
        if len(data) > LIMITS["rules"][plan]:
            ctx.error((), f"{len(data)} rules, but the {plan} plan allows {LIMITS['rules'][plan]} in this file.")
        for i, r in enumerate(data):
            p = (i,)
            if not check_type(ctx, p, r, "dict"):
                continue
            for k in r:
                if k not in allowed_top:
                    ctx.error(p + (k,), f"unknown field '{k}'.", suggest(k, allowed_top))
            for k in ("ref", "expression"):
                if k not in r:
                    ctx.error(p, f"rule is missing required field '{k}'.")
            if "action" in r and r["action"] != expected_action:
                ctx.error(p + ("action",), f"this file only holds '{expected_action}' rules.", "remove the action line; it is set for you")
            check_ref(ctx, p, r.get("ref"), refs, f)
            if "enabled" in r:
                check_type(ctx, p + ("enabled",), r["enabled"], "bool")
            if "description" in r:
                check_type(ctx, p + ("description",), r["description"], "str")
            expression_checks(ctx, p + ("expression",), r.get("expression"), plan, list_names)
            ap = r.get("action_parameters")
            if ap is None:
                ctx.error(p, "rule has no action_parameters, so it would do nothing.")
                continue
            check_rule_schema(ctx, p + ("action_parameters",), ap, RULE_SCHEMA["action_parameters"])
            if not isinstance(ap, dict):
                continue
            if rel == "rules/origin.yaml" and plan != "enterprise":
                for k in ("host_header", "sni"):
                    if k in ap:
                        ctx.error(p + ("action_parameters", k), f"{k} override is Enterprise only.")
                if isinstance(ap.get("origin"), dict) and "host" in ap["origin"]:
                    ctx.error(p + ("action_parameters", "origin", "host"), "DNS record override (origin.host) is Enterprise only.",
                              "on other plans only origin.port can be changed")
            if plan in ("free", "pro") and REGEX_RE.search(json.dumps(ap)):
                ctx.error(p + ("action_parameters",), "regex_replace needs Business or Enterprise.",
                          "use wildcard_replace instead")
            if rel == "rules/redirects.yaml":
                fv = ap.get("from_value") or {}
                sc = fv.get("status_code") if isinstance(fv, dict) else None
                check_enum(ctx, p + ("action_parameters", "from_value", "status_code"), sc, [301, 302, 303, 307, 308, None])


# ==========================================================================
# Security, cache, settings
# ==========================================================================
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
                ctx.warn(("preload",), "preload is very hard to undo; browsers enforce HTTPS for months after removal.")

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
                    ctx.warn(p, "no notes: say why this rule exists so it can be removed safely later.")
                sig = (t, v)
                if sig in seen:
                    ctx.error(p, f"same target as '{seen[sig]}'.", "remove one of them")
                seen[sig] = key

    f = d / "cache" / "settings.yaml"
    data, lines = load(report, f)
    if data not in (None, "ERROR"):
        ctx = Ctx(report, f, lines, plan)
        if check_fields(ctx, (), data, {"smart_tiered_cache": "str", "argo_tiered_caching": "str"}):
            for k in data:
                check_enum(ctx, (k,), data[k], ["on", "off"])


def validate_settings(report, d, plan):
    f = d / "settings" / "zone.yaml"
    data, lines = load(report, f)
    if data in (None, "ERROR"):
        return
    ctx = Ctx(report, f, lines, plan)
    if not check_type(ctx, (), data, "dict"):
        return
    for k, v in data.items():
        p = (str(k),)
        k = str(k)
        if k == "security_header":
            ctx.error(p, "HSTS is set in security/hsts.yaml, not here.")
            continue
        if k not in KNOWN_SETTINGS:
            ctx.warn(p, f"'{k}' is not a setting this repo knows.", suggest(k, KNOWN_SETTINGS) + " (ignore if it is a new Cloudflare setting)")
        if isinstance(v, bool):
            ctx.error(p, f"{k}: {str(v).lower()} was read as yes/no, but Cloudflare expects the text \"{'on' if v else 'off'}\".",
                      f'write {k}: "{"on" if v else "off"}" with the quotes')
            continue
        if k in ON_OFF_SETTINGS:
            check_enum(ctx, p, v, ["on", "off"])
        if k in SETTING_ENUMS:
            if isinstance(v, (int, float)):
                ctx.error(p, f"{k} was read as a number.", f'put it in quotes: "{v}"')
            else:
                check_enum(ctx, p, v, SETTING_ENUMS[k])
        if k == "browser_cache_ttl" and not isinstance(v, int):
            ctx.error(p, "browser_cache_ttl must be a number of seconds.", "remove the quotes")
        if k == "ssl" and v in ("off", "flexible"):
            ctx.warn(p, f"ssl: {v} sends traffic to your origin unencrypted.", "use full or strict")
        if k == "min_tls_version" and v in ("1.0", "1.1"):
            ctx.warn(p, "TLS 1.0 and 1.1 are deprecated.", 'use "1.2"')


# ==========================================================================
# Domain and account entry points
# ==========================================================================
def validate_domain(report, d, list_names):
    f = d / "domain.yaml"
    data, lines = load(report, f)
    if data is None:
        report.add("error", f, 1, "domain.yaml is missing or empty.", "copy it from domains/_template")
        return
    if data == "ERROR":
        return
    ctx = Ctx(report, f, lines, None)
    if not check_fields(ctx, (), data, {"name": "str", "zone_id": "str", "plan": "str", "owner": "str", "example": "bool"},
                        ["name", "zone_id", "plan"]):
        return
    name, zid, plan = data.get("name"), data.get("zone_id"), data.get("plan")
    if isinstance(zid, str) and not HEX32.match(zid):
        ctx.error(("zone_id",), "zone_id must be the 32-character Zone ID (lowercase letters a-f and digits).",
                  "copy it from the zone's Overview page in Cloudflare")
    if isinstance(name, str):
        check_host(ctx, ("name",), name, "domain name")
        if name != d.name and d.name != "_template":
            ctx.error(("name",), f"name '{name}' does not match the folder name '{d.name}'.", "rename one so they match")
    if not check_enum(ctx, ("plan",), plan, PLANS):
        return
    zone = name if isinstance(name, str) else d.name
    refs = {}
    validate_dns(report, d, plan, zone)
    validate_waf(report, d, plan, list_names, refs)
    validate_rule_files(report, d, plan, list_names, refs)
    validate_security(report, d, plan)
    validate_settings(report, d, plan)
    for extra in ("imports.tf",):
        if (d / extra).exists():
            report.add("warning", d / extra, 1, "imports.tf is present: the next apply adopts existing Cloudflare objects.",
                       "delete it after the first successful apply")


def validate_account(report, a):
    f = a / "account.yaml"
    data, lines = load(report, f)
    plan = "enterprise"
    if data not in (None, "ERROR"):
        ctx = Ctx(report, f, lines, None)
        if check_fields(ctx, (), data, {"account_id": "str", "plan": "str", "example": "bool"}, ["account_id"]):
            if isinstance(data.get("account_id"), str) and not HEX32.match(data["account_id"]):
                ctx.error(("account_id",), "account_id must be the 32-character Account ID.", "put it in quotes")
            plan = data.get("plan", "enterprise")
            check_enum(ctx, ("plan",), plan, PLANS)
            if "plan" not in data:
                ctx.warn((), "no plan set; list limits are checked as Enterprise.", "add plan: <highest plan in the account>")
    names, total, counts = {}, 0, {"redirect": 0, "other": 0}
    for kind in ("ip", "asn", "hostname", "redirect"):
        f = a / "lists" / f"{kind}.yaml"
        data, lines = load(report, f)
        if data in (None, "ERROR"):
            continue
        ctx = Ctx(report, f, lines, plan)
        if not check_type(ctx, (), data, "dict"):
            continue
        if kind in ("asn", "hostname") and data and plan != "enterprise":
            ctx.error((), f"{kind} lists are Enterprise only.")
        for lname, l in data.items():
            p = (lname,)
            if not re.match(r"^[a-z0-9_]{1,50}$", str(lname)):
                ctx.error(p, f"list name '{lname}' must be lowercase letters, digits and _ (max 50).")
            if lname in names:
                ctx.error(p, f"list name '{lname}' is also used in {names[lname]}.")
            names[lname] = f"{kind}.yaml"
            counts["redirect" if kind == "redirect" else "other"] += 1
            if not check_fields(ctx, p, l or {}, {"description": "str", "items": "list", "enabled": "bool"}, ["items"]):
                continue
            items = l.get("items") or []
            total += len(items)
            seen = set()
            for i, it in enumerate(items):
                ip_ = p + ("items", i)
                if kind == "ip":
                    v = it.get("ip") if isinstance(it, dict) else it
                    if isinstance(it, dict):
                        check_fields(ctx, ip_, it, {"ip": "str", "comment": "str"}, ["ip"])
                    if not is_cidr(str(v)):
                        ctx.error(ip_, f"'{v}' is not an IP address or range.")
                elif kind == "asn":
                    v = it.get("asn") if isinstance(it, dict) else it
                    if isinstance(it, dict):
                        check_fields(ctx, ip_, it, {"asn": "int", "comment": "str"}, ["asn"])
                    if not isinstance(v, int) or isinstance(v, bool):
                        ctx.error(ip_, f"'{v}' is not an ASN number.", "write the number only, e.g. 64496")
                elif kind == "hostname":
                    v = it.get("hostname") if isinstance(it, dict) else it
                    if isinstance(it, dict):
                        check_fields(ctx, ip_, it, {"hostname": "str", "comment": "str"}, ["hostname"])
                    check_host(ctx, ip_, str(v))
                else:
                    spec = {"source_url": "str", "target_url": "str", "status_code": "int", "include_subdomains": "bool",
                            "preserve_path_suffix": "bool", "preserve_query_string": "bool", "subpath_matching": "bool",
                            "comment": "str"}
                    if not check_fields(ctx, ip_, it, spec, ["source_url", "target_url"]):
                        continue
                    v = it.get("source_url")
                    if isinstance(v, str) and re.match(r"^https?://", v):
                        ctx.error(ip_ + ("source_url",), "source_url must not include http:// or https://.")
                    if isinstance(it.get("target_url"), str) and not re.match(r"^https?://", it["target_url"]):
                        ctx.error(ip_ + ("target_url",), "target_url must start with http:// or https://.")
                    check_enum(ctx, ip_ + ("status_code",), it.get("status_code"), [301, 302, 307, 308, None])
                    if it.get("preserve_path_suffix") and not it.get("subpath_matching"):
                        ctx.error(ip_ + ("preserve_path_suffix",), "preserve_path_suffix needs subpath_matching: true.")
                if str(v) in seen:
                    ctx.error(ip_, f"duplicate item '{v}'.")
                seen.add(str(v))
    max_lists = {"free": 1, "pro": 10, "business": 10, "enterprise": 1000}[plan]
    if counts["other"] > max_lists:
        report.add("error", a / "lists", 1, f"{counts['other']} custom lists, but the {plan} plan allows {max_lists}.")
    if counts["redirect"] > (25 if plan == "enterprise" else 5):
        report.add("error", a / "lists" / "redirect.yaml", 1, "too many Bulk Redirect lists for this plan (5, Enterprise 25).")
    if total > (500000 if plan == "enterprise" else 10000) + 0 and counts["other"]:
        report.add("error", a / "lists", 1, f"{total} list items exceed the plan limit.")
    return set(names)


def domain_dirs():
    return sorted(p for p in (ROOT / "domains").iterdir() if p.is_dir() and not p.name.startswith("_"))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("targets", nargs="*", help="domain folders or 'account' (default: everything)")
    ap.add_argument("--all", action="store_true")
    a = ap.parse_args()

    report = Report()
    account_dir = ROOT / "account"
    list_names = validate_account(report, account_dir) if account_dir.exists() else None

    targets = a.targets if a.targets and not a.all else ["account"] + [str(p) for p in domain_dirs()]
    for t in targets:
        p = Path(t)
        if t == "account" or p.resolve() == account_dir.resolve():
            continue  # always validated above
        if not p.is_absolute():
            p = (Path.cwd() / p) if (Path.cwd() / p).exists() else ROOT / "domains" / t
        if not p.exists():
            report.add("error", t, 1, f"no such domain folder: {t}")
            continue
        validate_domain(report, p.resolve(), list_names)

    report.print()
    n_err, n_warn = len(report.errors), len(report.items) - len(report.errors)
    if n_err:
        print(f"\n{n_err} error(s), {n_warn} warning(s). Nothing was sent to Cloudflare; fix the errors and run again.")
        sys.exit(1)
    print(f"YAML OK ({n_warn} warning(s)).")


if __name__ == "__main__":
    main()
