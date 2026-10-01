#!/usr/bin/env python3
"""
Export an existing Cloudflare zone into this repo's YAML layout and write
import blocks, so the first `terraform plan` adopts the live config instead
of recreating it.

    export CLOUDFLARE_API_TOKEN=...   # read-only token is enough
    python3 scripts/export_zone.py --zone-id <id> --domain example.org

    python3 scripts/export_zone.py --account-id <id>     # lists + bulk redirects

Writes:
    domains/<domain>/{dns,waf,security,cache,rules,settings}/*.yaml
    domains/<domain>/imports.tf        (delete after the first apply)
    .export/<domain>/                  (raw JSON for anything not converted)

Goal is a zero-diff first plan. Where a value cannot be rebuilt exactly
(e.g. an SPF with unusual ordering) it is kept as `raw:` so nothing changes.
"""
import argparse
import json
import os
import re
import sys
import urllib.parse
import urllib.request
from collections import defaultdict
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("PyYAML is required: pip install pyyaml")

API = "https://api.cloudflare.com/client/v4"
ROOT = Path(__file__).resolve().parent.parent
GENERIC = {"A": "a", "AAAA": "aaaa", "CNAME": "cname", "MX": "mx", "TXT": "txt", "NS": "ns"}
SETTINGS = [
    "ssl", "min_tls_version", "tls_1_3", "always_use_https", "automatic_https_rewrites",
    "opportunistic_encryption", "security_level", "browser_check", "email_obfuscation",
    "browser_cache_ttl", "cache_level", "brotli", "early_hints", "http3", "0rtt",
]
# Must match modules/rules/main.tf and modules/domain-stack/main.tf.
RULE_PHASES = {
    "cache": ("http_request_cache_settings", "cache/cache-rules.yaml"),
    "redirects": ("http_request_dynamic_redirect", "rules/redirects.yaml"),
    "url_rewrites": ("http_request_transform", "rules/url-rewrites.yaml"),
    "request_headers": ("http_request_late_transform", "rules/request-headers.yaml"),
    "response_headers": ("http_response_headers_transform", "rules/response-headers.yaml"),
    "origin": ("http_request_origin", "rules/origin.yaml"),
    "config": ("http_config_settings", "rules/config.yaml"),
    "compression": ("http_response_compression", "rules/compression.yaml"),
}
BOT_FIELDS = [
    "fight_mode", "enable_js", "sbfm_definitely_automated", "sbfm_likely_automated",
    "sbfm_verified_bots", "sbfm_static_resource_protection", "optimize_wordpress",
    "ai_bots_protection", "crawler_protection", "is_robots_txt_managed",
    "auto_update_model", "suppress_session_score", "bm_cookie_enabled",
]
CUSTOM_ACTIONS = {"block", "managed_challenge", "js_challenge", "challenge", "log", "skip"}
WARNINGS = []


def warn(msg):
    WARNINGS.append(msg)


def api(path, params=None):
    token = os.environ.get("CLOUDFLARE_API_TOKEN")
    if not token:
        sys.exit("Set CLOUDFLARE_API_TOKEN")
    url = f"{API}{path}"
    if params:
        url += "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req) as r:
        body = json.load(r)
    if not body.get("success", False):
        raise RuntimeError(f"{path}: {body.get('errors')}")
    return body


def list_dns(zone_id):
    out, page = [], 1
    while True:
        body = api(f"/zones/{zone_id}/dns_records", {"page": page, "per_page": 100})
        out += body["result"]
        info = body.get("result_info") or {}
        if page >= info.get("total_pages", 1):
            return out
        page += 1


def rel(name, zone):
    if name == zone:
        return "@"
    return name[: -(len(zone) + 1)] if name.endswith("." + zone) else name


def slug(r):
    if r == "@":
        return "root"
    s = r.replace("*", "wildcard").replace(".", "_").replace("-", "_")
    return re.sub(r"[^A-Za-z0-9_]", "", s) or "record"


def unique(key, used):
    k, i = key, 2
    while k in used:
        k, i = f"{key}_{i}", i + 1
    used.add(k)
    return k


# ---- SPF / DMARC round-trip (must match modules/dns/main.tf exactly) -------
def build_spf(s):
    parts = ["v=spf1"]
    parts += ["a"] if s.get("a") else []
    parts += ["mx"] if s.get("mx") else []
    parts += [f"ip4:{x}" for x in s.get("ip4", [])]
    parts += [f"ip6:{x}" for x in s.get("ip6", [])]
    parts += [f"include:{x}" for x in s.get("includes", [])]
    parts += s.get("extra", [])
    parts += [s.get("all", "-all")]
    return " ".join(parts)


def parse_spf(content):
    toks = content.split()[1:]
    s = {"includes": [], "ip4": [], "ip6": [], "extra": []}
    for t in toks:
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
        elif t in ("-all", "~all", "?all", "+all", "all"):
            s["all"] = t if t != "all" else "+all"
        else:
            s["extra"].append(t)
    s = {k: v for k, v in s.items() if v not in ([], None)}
    if build_spf(s) == content:
        return s
    return {"raw": content}


def build_dmarc(d):
    m = lambda xs: ",".join(x if x.startswith("mailto:") else f"mailto:{x}" for x in xs)
    parts = ["v=DMARC1", f"p={d.get('policy', 'none')}"]
    if d.get("subdomain_policy"):
        parts.append(f"sp={d['subdomain_policy']}")
    if d.get("pct") is not None:
        parts.append(f"pct={d['pct']}")
    if d.get("rua"):
        parts.append(f"rua={m(d['rua'])}")
    if d.get("ruf"):
        parts.append(f"ruf={m(d['ruf'])}")
    for k in ("adkim", "aspf", "fo"):
        if d.get(k):
            parts.append(f"{k}={d[k]}")
    return "; ".join(parts)


def parse_dmarc(content):
    tags = {}
    for p in content.split(";"):
        if "=" in p:
            k, v = p.strip().split("=", 1)
            tags[k.strip()] = v.strip()
    strip = lambda v: [x.strip().removeprefix("mailto:") for x in v.split(",") if x.strip()]
    d = {"policy": tags.get("p", "none")}
    if "sp" in tags:
        d["subdomain_policy"] = tags["sp"]
    if "pct" in tags and tags["pct"].isdigit():
        d["pct"] = int(tags["pct"])
    if "rua" in tags:
        d["rua"] = strip(tags["rua"])
    if "ruf" in tags:
        d["ruf"] = strip(tags["ruf"])
    for k in ("adkim", "aspf", "fo"):
        if k in tags:
            d[k] = tags[k]
    if build_dmarc(d) == content:
        return d
    return {"raw": content}


# ---- DNS ---------------------------------------------------------------------
def export_dns(zone_id, zone):
    files = defaultdict(dict)  # file -> {key: record}
    imports, used, unsupported = [], defaultdict(set), []

    def imp(addr_key, rec_id):
        imports.append((f'module.domain.module.dns.cloudflare_dns_record.this["{addr_key}"]', f"{zone_id}/{rec_id}"))

    def imp_s(addr_key, rec_id):
        imports.append((f'module.domain.module.dns.cloudflare_dns_record.structured["{addr_key}"]', f"{zone_id}/{rec_id}"))

    for r in sorted(list_dns(zone_id), key=lambda x: (x["type"], x["name"])):
        name, typ, content = rel(r["name"], zone), r["type"], r.get("content", "")
        d = r.get("data") or {}
        if typ == "CAA" and d:
            key = unique(f"{d.get('tag', 'caa')}_{slug(str(d.get('value', ''))).lower()}"[:60], used["caa"])
            rec = {"name": name, "tag": d.get("tag"), "value": d.get("value")}
            if d.get("flags", 0):
                rec["flags"] = d["flags"]
            if r.get("ttl", 1) != 1:
                rec["ttl"] = r["ttl"]
            if r.get("comment"):
                rec["comment"] = r["comment"]
            files["caa"][key] = rec
            imp_s(f"caa/{key}", r["id"])
            continue
        if typ == "SRV" and d:
            key = unique(slug(name), used["srv"])
            rec = {"name": name, "priority": d.get("priority"), "weight": d.get("weight"),
                   "port": d.get("port"), "target": d.get("target")}
            if r.get("ttl", 1) != 1:
                rec["ttl"] = r["ttl"]
            if r.get("comment"):
                rec["comment"] = r["comment"]
            files["srv"][key] = rec
            imp_s(f"srv/{key}", r["id"])
            continue
        if typ == "NS" and name == "@":
            continue  # apex NS is Cloudflare's
        if typ not in GENERIC:
            unsupported.append(r)
            continue

        if typ == "TXT":
            if content.startswith("v=spf1") and name not in files["spf"]:
                files["spf"][name] = parse_spf(content)
                if r.get("ttl", 1) != 1:
                    files["spf"][name]["ttl"] = r["ttl"]
                if r.get("comment"):
                    files["spf"][name]["comment"] = r["comment"]
                imp(f"spf/{name}", r["id"])
                continue
            if content.startswith('"'):
                warn(f"TXT {r['name']} is stored with quotes; kept verbatim.")
            if name == "_dmarc" or name.startswith("_dmarc."):
                host = "@" if name == "_dmarc" else name[len("_dmarc."):]
                if host not in files["dmarc"] and content.startswith("v=DMARC1"):
                    files["dmarc"][host] = parse_dmarc(content)
                    if r.get("ttl", 1) != 1:
                        files["dmarc"][host]["ttl"] = r["ttl"]
                    if r.get("comment"):
                        files["dmarc"][host]["comment"] = r["comment"]
                    imp(f"dmarc/{host}", r["id"])
                    continue
            m = re.fullmatch(r"([^.]+)\._domainkey", name)
            if m and m.group(1) not in files["dkim"]:
                files["dkim"][m.group(1)] = {"content": content}
                if r.get("ttl", 1) != 1:
                    files["dkim"][m.group(1)]["ttl"] = r["ttl"]
                if r.get("comment"):
                    files["dkim"][m.group(1)]["comment"] = r["comment"]
                imp(f"dkim/{m.group(1)}", r["id"])
                continue

        f = GENERIC[typ]
        key = unique(slug(name), used[f])
        rec = {"name": name, "content": content}
        if typ in ("A", "AAAA", "CNAME"):
            rec["proxied"] = bool(r.get("proxied"))
        if r.get("ttl", 1) != 1 and not r.get("proxied"):
            rec["ttl"] = r["ttl"]
        if typ == "MX":
            rec["priority"] = r.get("priority", 0)
        if r.get("comment"):
            rec["comment"] = r["comment"]
        files[f][key] = rec
        imp(f"{f}/{key}", r["id"])

    return files, imports, unsupported


# ---- WAF -----------------------------------------------------------------
def entry_ruleset(zone_id, phase):
    try:
        return api(f"/zones/{zone_id}/rulesets/phases/{phase}/entrypoint")["result"]
    except Exception:
        return None


def export_waf(zone_id, outdir):
    out, imports = {}, []

    rs = entry_ruleset(zone_id, "http_request_firewall_custom")
    if rs and rs.get("rules"):
        rules = []
        for r in rs["rules"]:
            if r["action"] not in CUSTOM_ACTIONS:
                warn(f"Custom rule '{r.get('description')}' uses action {r['action']}; review by hand.")
            ap = r.get("action_parameters") or {}
            extra = set(ap) - {"ruleset", "phases", "products"}
            if extra:
                warn(f"Custom rule '{r.get('description')}' has action_parameters {sorted(extra)} not modelled; plan will show a diff.")
            rule = {
                "ref": r.get("ref") or r["id"],
                "description": r.get("description", ""),
                "expression": r["expression"],
                "action": r["action"],
            }
            if not r.get("enabled", True):
                rule["enabled"] = False
            if r["action"] == "skip":
                skip = {k: ap[k] for k in ("ruleset", "phases", "products") if k in ap}
                if not (r.get("logging") or {}).get("enabled", True):
                    skip["log"] = False
                rule["skip"] = skip
            rules.append(rule)
        out["custom-rules"] = rules
        imports.append(("module.domain.module.waf.cloudflare_ruleset.custom[0]", f"zones/{zone_id}/{rs['id']}"))

    rs = entry_ruleset(zone_id, "http_ratelimit")
    if rs and rs.get("rules"):
        rules = []
        for r in rs["rules"]:
            rl = r.get("ratelimit") or {}
            if r.get("action_parameters"):
                warn(f"Rate limit '{r.get('description')}' has a custom response; not modelled.")
            rule = {
                "ref": r.get("ref") or r["id"],
                "description": r.get("description", ""),
                "expression": r["expression"],
                "action": r["action"],
                "characteristics": rl.get("characteristics", ["ip.src", "cf.colo.id"]),
                "period": rl.get("period", 10),
                "requests_per_period": rl.get("requests_per_period"),
                "mitigation_timeout": rl.get("mitigation_timeout", 10),
            }
            if rl.get("counting_expression"):
                rule["counting_expression"] = rl["counting_expression"]
            if not r.get("enabled", True):
                rule["enabled"] = False
            rules.append(rule)
        out["rate-limits"] = rules
        imports.append(("module.domain.module.waf.cloudflare_ruleset.rate_limit[0]", f"zones/{zone_id}/{rs['id']}"))

    rs = entry_ruleset(zone_id, "http_request_firewall_managed")
    if rs and rs.get("rules"):
        (outdir / "managed-ruleset.json").write_text(json.dumps(rs, indent=2))
        warn("Managed WAF ruleset exported to .export only. Fill waf/managed-rules.yaml, then uncomment its import block.")
        imports.append(("# module.domain.module.waf.cloudflare_ruleset.managed[0]", f"zones/{zone_id}/{rs['id']}"))

    return out, imports


def export_settings(zone_id):
    vals, imports = {}, []
    for s in SETTINGS:
        try:
            v = api(f"/zones/{zone_id}/settings/{s}")["result"]["value"]
        except Exception:
            continue
        vals[s] = v
        imports.append((f'module.domain.module.zone_settings.cloudflare_zone_setting.this["{s}"]', f"{zone_id}/{s}"))
    return vals, imports


def clean_rule(r):
    """Keep only fields the YAML uses; `action` is set by the module per phase."""
    out = {"ref": r.get("ref") or r["id"], "description": r.get("description", "")}
    out["expression"] = r["expression"]
    if r.get("action_parameters"):
        out["action_parameters"] = r["action_parameters"]
    if not r.get("enabled", True):
        out["enabled"] = False
    return out


def export_rules(zone_id):
    files, imports = {}, []
    for svc, (phase, path) in RULE_PHASES.items():
        rs = entry_ruleset(zone_id, phase)
        if not rs or not rs.get("rules"):
            continue
        files[path] = [clean_rule(r) for r in rs["rules"]]
        imports.append((f'module.domain.module.rules.cloudflare_ruleset.this["{svc}"]', f"zones/{zone_id}/{rs['id']}"))
    return files, imports


def export_security(zone_id):
    files, imports = {}, []

    # HSTS lives in the security_header zone setting.
    try:
        sh = api(f"/zones/{zone_id}/settings/security_header")["result"]["value"]
        hsts = sh.get("strict_transport_security", {})
        if hsts.get("enabled"):
            files["security/hsts.yaml"] = {k: hsts[k] for k in ("enabled", "max_age", "include_subdomains", "preload", "nosniff") if k in hsts}
            imports.append(('module.domain.module.zone_settings.cloudflare_zone_setting.this["security_header"]', f"{zone_id}/security_header"))
    except Exception:
        pass

    try:
        bm = api(f"/zones/{zone_id}/bot_management")["result"]
        vals = {k: bm[k] for k in BOT_FIELDS if k in bm and bm[k] is not None}
        if vals:
            files["security/bot-management.yaml"] = vals
            imports.append(("module.domain.module.security.cloudflare_bot_management.this[0]", zone_id))
    except Exception:
        warn("Could not read bot management settings (token scope?).")

    try:
        rules, used, page = {}, set(), 1
        while True:
            body = api(f"/zones/{zone_id}/firewall/access_rules/rules", {"page": page, "per_page": 100})
            for r in body["result"]:
                if (r.get("scope") or {}).get("type") != "zone":
                    continue  # inherited account rules are managed elsewhere
                cfg = r.get("configuration", {})
                key = unique(slug(r.get("notes") or cfg.get("value", "rule")).lower()[:50] or "rule", used)
                rule = {"mode": r["mode"], "target": cfg.get("target"), "value": cfg.get("value")}
                if r.get("notes"):
                    rule["notes"] = r["notes"]
                rules[key] = rule
                imports.append((f'module.domain.module.security.cloudflare_access_rule.this["{key}"]', f"zones/{zone_id}/{r['id']}"))
            if page >= (body.get("result_info") or {}).get("total_pages", 1):
                break
            page += 1
        if rules:
            files["security/ip-access-rules.yaml"] = rules
    except Exception:
        warn("Could not read IP Access Rules (token scope?).")

    return files, imports


def export_cache(zone_id):
    vals, imports = {}, []
    try:
        v = api(f"/zones/{zone_id}/cache/tiered_cache_smart_topology_enable")["result"]["value"]
        vals["smart_tiered_cache"] = v
        imports.append(("module.domain.module.cache.cloudflare_tiered_cache.this[0]", zone_id))
    except Exception:
        pass
    return vals, imports


def export_dnssec(zone_id):
    try:
        st = api(f"/zones/{zone_id}/dnssec")["result"]["status"]
    except Exception:
        return None, []
    if st in ("active", "pending"):
        return {"status": "active"}, [("module.domain.module.dns.cloudflare_zone_dnssec.this[0]", zone_id)]
    return None, []


# ---- Account (lists + bulk redirects) -------------------------------------
def export_account(account_id):
    adir = ROOT / "account"
    out = {"ip": {}, "asn": {}, "hostname": {}, "redirect": {}}
    imports = []
    for l in api(f"/accounts/{account_id}/rules/lists")["result"]:
        items, cursor = [], None
        while True:
            params = {"per_page": 500}
            if cursor:
                params["cursor"] = cursor
            body = api(f"/accounts/{account_id}/rules/lists/{l['id']}/items", params)
            items += body["result"]
            cursor = ((body.get("result_info") or {}).get("cursors") or {}).get("after")
            if not cursor:
                break
        kind = l["kind"]
        conv = []
        for i in items:
            c = {"comment": i["comment"]} if i.get("comment") else {}
            if kind == "ip":
                conv.append({"ip": i["ip"], **c} if c else i["ip"])
            elif kind == "asn":
                conv.append({"asn": i["asn"], **c} if c else i["asn"])
            elif kind == "hostname":
                h = i["hostname"]["url_hostname"]
                conv.append({"hostname": h, **c} if c else h)
            elif kind == "redirect":
                conv.append({k: v for k, v in i["redirect"].items() if v is not None} | c)
        entry = {"description": l.get("description") or None, "items": conv}
        out.setdefault(kind, {})[l["name"]] = {k: v for k, v in entry.items() if v is not None}
        imports.append((f'module.lists.cloudflare_list.this["{l["name"]}"]', f"{account_id}/{l['id']}"))

    try:
        rs = api(f"/accounts/{account_id}/rulesets/phases/http_request_redirect/entrypoint")["result"]
        if rs.get("rules"):
            imports.append(("module.lists.cloudflare_ruleset.bulk_redirects[0]", f"accounts/{account_id}/{rs['id']}"))
            warn("Existing Bulk Redirect rules are replaced by one generated rule per redirect list; review the plan.")
    except Exception:
        pass

    dump(adir / "account.yaml", {"account_id": account_id})
    for kind, lists in out.items():
        dump(adir / "lists" / f"{kind}.yaml", lists, "# Exported from Cloudflare. Key = list name ($name in rules).")
    write_imports(adir / "imports.tf", imports)
    print(f"Account {account_id}: {sum(len(v) for v in out.values())} lists exported.")
    for w in WARNINGS:
        print(f"WARNING: {w}")
    print("Next: make plan D=account")


def write_imports(path, imports):
    lines = ["# Generated by scripts/export_zone.py. Delete after the first successful apply.", ""]
    for to, id_ in imports:
        c = "# " if to.startswith("#") else ""
        to = to.lstrip("# ")
        lines += [f"{c}import {{", f"{c}  to = {to}", f'{c}  id = "{id_}"', f"{c}}}", ""]
    path.write_text("\n".join(lines))


# ---- Write -----------------------------------------------------------------
def dump(path, data, header=""):
    path.parent.mkdir(parents=True, exist_ok=True)
    text = yaml.safe_dump(data, sort_keys=False, allow_unicode=True, width=200) if data else ""
    path.write_text((header + "\n" if header else "") + text)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--zone-id")
    ap.add_argument("--domain")
    ap.add_argument("--account-id", help="export account lists and bulk redirects instead of a zone")
    ap.add_argument("--plan", help="free|pro|business|enterprise (read from the API if omitted)")
    a = ap.parse_args()
    if a.account_id:
        return export_account(a.account_id)
    if not (a.zone_id and a.domain):
        ap.error("--zone-id and --domain are required (or --account-id)")

    zone = api(f"/zones/{a.zone_id}")["result"]
    if zone["name"] != a.domain:
        sys.exit(f"Zone {a.zone_id} is {zone['name']}, not {a.domain}")
    plan = a.plan or zone.get("plan", {}).get("legacy_id", "free")
    plan = {"business": "business", "enterprise": "enterprise", "pro": "pro"}.get(plan, "free")

    ddir = ROOT / "domains" / a.domain
    xdir = ROOT / ".export" / a.domain
    xdir.mkdir(parents=True, exist_ok=True)
    if not ddir.exists():
        import shutil
        shutil.copytree(ROOT / "domains" / "_template", ddir)
        (ddir / "README.md").unlink(missing_ok=True)

    dump(ddir / "domain.yaml", {"name": a.domain, "zone_id": a.zone_id, "plan": plan, "owner": "change-me"})

    files, imports, unsupported = export_dns(a.zone_id, a.domain)
    for f in ("a", "aaaa", "cname", "mx", "txt", "ns", "spf", "dmarc", "dkim", "caa", "srv"):
        if files.get(f):
            dump(ddir / "dns" / f"{f}.yaml", files[f], "# Exported from Cloudflare. Keys are Terraform IDs: do not rename.")
    dnssec, dnssec_imports = export_dnssec(a.zone_id)
    if dnssec:
        dump(ddir / "dns" / "dnssec.yaml", dnssec, "# Exported from Cloudflare.")
    if unsupported:
        (xdir / "unsupported-dns.json").write_text(json.dumps(unsupported, indent=2))
        types = sorted({r["type"] for r in unsupported})
        warn(f"{len(unsupported)} DNS records of type {types} are not managed yet (see .export).")

    waf, waf_imports = export_waf(a.zone_id, xdir)
    for f in ("custom-rules", "rate-limits"):
        if waf.get(f):
            dump(ddir / "waf" / f"{f}.yaml", waf[f], "# Exported from Cloudflare. Order matters.")

    rule_files, rule_imports = export_rules(a.zone_id)
    for path, rules in rule_files.items():
        dump(ddir / path, rules, "# Exported from Cloudflare. Order matters. `action` is set per file automatically.")

    sec_files, sec_imports = export_security(a.zone_id)
    for path, data in sec_files.items():
        dump(ddir / path, data, "# Exported from Cloudflare.")

    cache, cache_imports = export_cache(a.zone_id)
    if cache:
        dump(ddir / "cache" / "settings.yaml", cache, "# Exported from Cloudflare.")

    settings, set_imports = export_settings(a.zone_id)
    dump(ddir / "settings" / "zone.yaml", settings, "# Exported from Cloudflare. HSTS is in security/hsts.yaml.")

    write_imports(ddir / "imports.tf",
                  imports + dnssec_imports + waf_imports + rule_imports + sec_imports + cache_imports + set_imports)

    n = sum(len(v) for v in files.values())
    print(f"{a.domain} ({plan}): {n} DNS records, "
          f"{len(waf.get('custom-rules', []))} custom rules, {len(waf.get('rate-limits', []))} rate limits, "
          f"{len(rule_files)} rule phases, {len(sec_files)} security files, {len(settings)} settings exported.")
    raws = [k for k in ("spf", "dmarc") for v in files.get(k, {}).values() if "raw" in v]
    if raws:
        print(f"Kept {len(raws)} SPF/DMARC record(s) as raw to avoid changes.")
    for w in WARNINGS:
        print(f"WARNING: {w}")
    print(f"Next: make plan D={a.domain}   (expect 0 to add, 0 to change, 0 to destroy)")


if __name__ == "__main__":
    main()
