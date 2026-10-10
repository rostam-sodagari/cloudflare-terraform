"""Checks helpers for configuration validation."""
import difflib
import ipaddress
from config import HOST_RE, LIST_REF_RE, REF_RE, REGEX_RE
from yamlio import line_for


def suggest(word, options):
    # Stringify first: difflib and join/sort need strings, but several enums are
    # numeric ([301, 302, ...], [0, 128]) and a typo in one of those fields used
    # to crash validate.py with a TypeError instead of reporting the error.
    options_as_text = [str(o) for o in options]
    matches = difflib.get_close_matches(str(word), options_as_text, n=1, cutoff=0.6)
    return f"did you mean '{matches[0]}'?" if matches else f"allowed: {', '.join(sorted(options_as_text))}"

def fmt_path(path):
    """('www', 'content') -> www.content ; (0, 'expression') -> #1.expression"""
    return ".".join(f"#{p + 1}" if isinstance(p, int) else str(p) for p in path) or "(top level)"

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
    for field_name in obj:
        if field_name not in spec:
            ctx.error(path + (field_name,), f"unknown field '{field_name}' in {fmt_path(path)}.", suggest(field_name, spec))
    for field_name in required:
        if field_name not in obj or obj[field_name] is None:
            ctx.error(path, f"{fmt_path(path)} is missing required field '{field_name}'.")
    for field_name, kind in spec.items():
        if field_name in obj and obj[field_name] is not None:
            check_type(ctx, path + (field_name,), obj[field_name], kind)
    return True

def check_enum(ctx, path, value, allowed):
    if value is not None and value not in allowed:
        ctx.error(path, f"{fmt_path(path)} has invalid value '{value}'.", suggest(value, allowed))
        return False
    return True


def list_values(value):
    """Iterate only actual lists after callers report child type diagnostics."""
    return value if isinstance(value, list) else []

def check_ttl(ctx, path, ttl, plan):
    if ttl is None or not isinstance(ttl, int) or isinstance(ttl, bool):
        return
    minimum_ttl = 30 if plan == "enterprise" else 60
    if ttl != 1 and not (minimum_ttl <= ttl <= 86400):
        ctx.error(path, f"ttl {ttl} is out of range.", f"use 1 (automatic) or {minimum_ttl} to 86400 seconds")

def is_ip(v, version):
    value = v
    try:
        return ipaddress.ip_address(value).version == version
    except ValueError:
        return False

def is_cidr(v, version=None):
    value = v
    try:
        network = ipaddress.ip_network(value, strict=False)
        return version is None or network.version == version
    except ValueError:
        return False

def check_host(ctx, path, v, what="hostname"):
    value = v
    if isinstance(value, str) and (value.endswith(".") or not HOST_RE.match(value)):
        ctx.error(path, f"'{value}' is not a valid {what}.",
                  "no trailing dot, no scheme (https://) and no path" if value.endswith(".") or "/" in value else None)

def expression_checks(ctx, path, expr, plan, list_names):
    expression = expr
    if not isinstance(expression, str):
        return
    if not expression.strip():
        ctx.error(path, "expression is empty.")
    if plan in ("free", "pro") and REGEX_RE.search(expression):
        ctx.error(path, "regular expressions (matches, ~, regex_replace) need Business or Enterprise.",
                  "use wildcard, starts_with, ends_with or contains instead")
    if expression.count("(") != expression.count(")"):
        ctx.error(path, "unbalanced brackets in expression.")
    if list_names is not None:
        for name in LIST_REF_RE.findall(expression):
            if name not in list_names:
                ctx.error(path, f"expression uses list ${name}, which is not defined in account/lists/.",
                          "add the list in account/lists/ (and apply account first) or fix the name")

def check_ref(ctx, path, ref, refs, f):
    config_file = f
    if not isinstance(ref, str):
        return
    if not REF_RE.match(ref):
        ctx.error(path + ("ref",), f"ref '{ref}' must be letters, digits, _ or - only (max 120).")
    key = (str(config_file.parent), ref)
    if key in refs:
        ctx.error(path + ("ref",), f"ref '{ref}' is used twice ({refs[key]}).", "each ref must be unique")
    refs[key] = f"{config_file.name} line {line_for(ctx.lines, path)}"
