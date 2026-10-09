"""Shared constants, the Report/Ctx reporting classes, and generic checks
(type/field/enum/schema/ref/expression) reused by every validation/*.py
module. Structural correctness only -- always an error, never configurable.
Opinionated best-practice checks belong in scripts/checks/ (Phase 3), not
here."""
import difflib
import ipaddress
import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from yamlio import DuplicateKeyError, line_for, load_with_lines, unquote_txt  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent.parent
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

    def flag(self, check_id, path, msg, hint=None):
        """Like warn(), but the severity (or whether it fires at all) is
        controlled by policy.yaml -- see validation/policy.py. Used for
        best-practice checks, as opposed to error()/warn() which are for
        structural correctness and always fire."""
        from .policy import GATE  # local import: policy.py imports ROOT from here
        severity = GATE.severity(check_id)
        if severity is None:
            return
        (self.error if severity == "error" else self.warn)(path, msg, hint)


DOC_BLOCK_RE = re.compile(r"^##\s*([A-Za-z]+)\s*:\s*\S")
DOC_BLOCK_REQUIRED = ("owner", "purpose", "impact")


def top_level_key_lines(raw):
    """0-based indices of lines that start a top-level ('column 0') key, in
    file order. yamlio's `lines` map tracks where each key's *value* starts
    (one line below the key for a normal block mapping), not the key line
    itself, so record-doc-block scanning -- which needs the key's own line
    -- pairs this up with dict key order instead (both are file order)."""
    return [i for i, line in enumerate(raw) if line and not line[0].isspace() and not line.startswith("#") and ":" in line]


def check_record_doc_blocks(ctx, f, data, needs_proxy=False):
    """Every DNS record needs a '##' documentation block (Owner, Purpose,
    Impact, and Proxy for record types that support proxied) on the lines
    directly above its key. Gated through policy.yaml ('record_has_doc_block')
    like any other best-practice check -- see docs/41-record-documentation.md."""
    if not isinstance(data, dict) or not data:
        return
    raw = f.read_text(encoding="utf-8").splitlines()
    key_lines = top_level_key_lines(raw)
    required = list(DOC_BLOCK_REQUIRED) + (["proxy"] if needs_proxy else [])
    for key, key_idx in zip(data, key_lines):
        found = set()
        i = key_idx - 1
        while i >= 0:
            m = DOC_BLOCK_RE.match(raw[i])
            if not m:
                break
            found.add(m.group(1).lower())
            i -= 1
        missing = [name for name in required if name not in found]
        if missing:
            ctx.flag("record_has_doc_block", (key,),
                     f"'{key}' has no '##' documentation block ({', '.join(n.title() for n in missing)} missing).",
                     "add lines directly above it, e.g. \"## Owner: ...\", \"## Purpose: ...\", \"## Impact: ...\""
                     + (', "## Proxy: ..."' if needs_proxy else "") + " -- see docs/41-record-documentation.md")


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


# ---- shared across WAF and the rules engine ----------------------------------
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


def check_ref(ctx, path, ref, refs, f):
    if not isinstance(ref, str):
        return
    if not REF_RE.match(ref):
        ctx.error(path + ("ref",), f"ref '{ref}' must be letters, digits, _ or - only (max 120).")
    key = (str(f.parent), ref)
    if key in refs:
        ctx.error(path + ("ref",), f"ref '{ref}' is used twice ({refs[key]}).", "each ref must be unique")
    refs[key] = f"{f.name} line {line_for(ctx.lines, path)}"


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
