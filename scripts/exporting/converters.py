"""Pure conversion of API fields to repository configuration."""
import re
from .config import BENIGN_DROPS
from yamlio import quote_txt, unquote_txt


def clean(value, schema, path, dropped):
    """Keep only fields the provider accepts; record anything removed."""
    if isinstance(schema, str):
        return value
    if "__list__" in schema:
        return [clean(value, schema["__list__"], f"{path}[]", dropped) for value in (value or [])]
    if "__map__" in schema:
        return {key: clean(value, schema["__map__"], f"{path}.{key}", dropped) for key, value in (value or {}).items()}
    converted = {}
    for key, value in (value or {}).items():
        if key not in schema:
            if key not in BENIGN_DROPS:
                dropped.append(f"{path}.{key}".lstrip("."))
            continue
        if value is None or value == {} or value == []:
            continue
        converted[key] = clean(value, schema[key], f"{path}.{key}", dropped)
    return converted


def rel(name, zone):
    if name == zone:
        return "@"
    return name[: -(len(zone) + 1)] if name.endswith("." + zone) else name


def slug(text):
    s = re.sub(r"[^A-Za-z0-9]+", "_", str(text).replace("*", "wildcard")).strip("_").lower()
    return s[:60] or "item"


def unique(key, used):
    key, i = key, 2
    while key in used:
        key, i = f"{key}_{i}", i + 1
    used.add(key)
    return key


def ttl_fields(r, rec):
    if r.get("ttl", 1) != 1 and not r.get("proxied"):
        rec["ttl"] = r["ttl"]
    if r.get("comment"):
        rec["comment"] = r["comment"]
    return rec


def build_spf(s):
    parts = ["v=spf1"] + (["a"] if s.get("a") else []) + (["mx"] if s.get("mx") else [])
    parts += [f"ip4:{x}" for x in s.get("ip4", [])] + [f"ip6:{x}" for x in s.get("ip6", [])]
    parts += [f"include:{x}" for x in s.get("includes", [])] + s.get("extra", []) + [s.get("all", "-all")]
    return " ".join(parts)


def parse_spf(content):
    s = {"includes": [], "ip4": [], "ip6": [], "extra": []}
    for t in content.split()[1:]:
        if t in ("a", "+a"):
            s["a"] = True
        elif t in ("mx", "+mx"):
            s["mx"] = True
        elif t.startswith("ip4:"):
            s["ip4"].append(t[4:])
        elif t.startswith("ip6:"):
            s["ip6"].append(t[4:])
        elif t.startswith("include:"):
            s["includes"].append(t[8:])
        elif t in ("-all", "~all", "?all", "+all"):
            s["all"] = t
        else:
            s["extra"].append(t)
    s = {key: value for key, value in s.items() if value not in ([], None)}
    return s if build_spf(s) == content else {"raw": content}


def build_dmarc(d):
    def match(addresses):
        return ",".join(x if x.startswith("mailto:") else f"mailto:{x}" for x in addresses)
    parts = ["v=DMARC1", f"p={d.get('policy', 'none')}"]
    if d.get("subdomain_policy"):
        parts.append(f"sp={d['subdomain_policy']}")
    if d.get("pct") is not None:
        parts.append(f"pct={d['pct']}")
    for key in ("rua", "ruf"):
        if d.get(key):
            parts.append(f"{key}={match(d[key])}")
    for key in ("adkim", "aspf", "fo"):
        if d.get(key):
            parts.append(f"{key}={d[key]}")
    return "; ".join(parts)


def parse_dmarc(content):
    tags = {}
    for p in content.split(";"):
        if "=" in p:
            key, value = p.strip().split("=", 1)
            tags[key.strip()] = value.strip()

    def addrs(value):
        return [x.strip()[7:] if x.strip().startswith("mailto:") else x.strip() for x in value.split(",") if x.strip()]
    d = {"policy": tags.get("p", "none")}
    if "sp" in tags:
        d["subdomain_policy"] = tags["sp"]
    if tags.get("pct", "").isdigit():
        d["pct"] = int(tags["pct"])
    for key in ("rua", "ruf"):
        if key in tags:
            d[key] = addrs(tags[key])
    for key in ("adkim", "aspf", "fo"):
        if key in tags:
            d[key] = tags[key]
    return d if build_dmarc(d) == content else {"raw": content}


def txt_fields(content):
    plain, quoted = unquote_txt(content)
    if quoted and quote_txt(plain) == content:
        return {"content": plain}                      # the normal case today
    if quoted is False:
        return {"content": content, "quoted": False}   # legacy unquoted record
    return {"content": content}                        # unusual split: kept verbatim


def structured_fields(content, parse, build):
    """SPF/DMARC: structured fields when they rebuild the exact value, else raw."""
    plain, quoted = unquote_txt(content)
    if quoted is None:
        return {"raw": content}
    fields = parse(plain)
    built = fields.get("raw") or build(fields)
    if quoted:
        return fields if quote_txt(built) == content else {"raw": content}
    return {**fields, "quoted": False}


def custom_rule_fields(api_rule, *, include_skip_logging=False):
    rule = {"ref": api_rule.get("ref") or api_rule["id"], "description": api_rule.get("description", ""),
            "expression": api_rule["expression"], "action": api_rule["action"]}
    if not api_rule.get("enabled", True):
        rule["enabled"] = False
    action_parameters = api_rule.get("action_parameters") or {}
    if api_rule["action"] == "skip":
        rule["skip"] = {field_name: action_parameters[field_name] for field_name in ("ruleset", "phases", "products") if field_name in action_parameters}
        if include_skip_logging and not (api_rule.get("logging") or {}).get("enabled", True):
            rule["skip"]["log"] = False
    if action_parameters.get("response"):
        rule["response"] = {field_name: value for field_name, value in action_parameters["response"].items() if value is not None}
    return rule


def rate_limit_fields(api_rule, *, include_zone_fields=False):
    rate_limit = api_rule.get("ratelimit") or {}
    rule = {"ref": api_rule.get("ref") or api_rule["id"], "description": api_rule.get("description", ""),
            "expression": api_rule["expression"], "action": api_rule["action"],
            "characteristics": rate_limit.get("characteristics", ["ip.src", "cf.colo.id"]),
            "period": rate_limit.get("period", 10), "requests_per_period": rate_limit.get("requests_per_period"),
            "mitigation_timeout": rate_limit.get("mitigation_timeout", 10)}
    if include_zone_fields:
        for field_name in ("counting_expression", "requests_to_origin"):
            if rate_limit.get(field_name) not in (None, ""):
                rule[field_name] = rate_limit[field_name]
    if not api_rule.get("enabled", True):
        rule["enabled"] = False
    response = (api_rule.get("action_parameters") or {}).get("response")
    if include_zone_fields and response:
        rule["response"] = {field_name: value for field_name, value in response.items() if value is not None}
    return rule


def list_item_fields(list_kind, items):
    converted_items = []
    for item in items:
        comment_fields = {"comment": item["comment"]} if item.get("comment") else {}
        if list_kind == "ip":
            converted_items.append({"ip": item["ip"], **comment_fields} if comment_fields else item["ip"])
        elif list_kind == "asn":
            converted_items.append({"asn": item["asn"], **comment_fields} if comment_fields else item["asn"])
        elif list_kind == "hostname":
            hostname = item["hostname"]["url_hostname"]
            converted_items.append({"hostname": hostname, **comment_fields} if comment_fields else hostname)
        elif list_kind == "redirect":
            converted_items.append({**{field_name: value for field_name, value in item["redirect"].items() if value is not None}, **comment_fields})
    return converted_items
