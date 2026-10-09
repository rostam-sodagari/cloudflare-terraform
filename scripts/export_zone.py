#!/usr/bin/env python3
"""
Export a live Cloudflare zone (or the account's lists) into this repo's YAML,
with an imports.tf so the first apply ADOPTS what exists instead of
recreating it. Read-only: this script never changes anything in Cloudflare.

    export CLOUDFLARE_API_TOKEN=<read-only token>
    python3 scripts/export_zone.py --zone-id <id> --domain example.org
    python3 scripts/export_zone.py --account-id <id>

Usually run through `python3 cf.py export`.

What you get
  domains/<domain>/              every service file, each with its documentation
                                 header from domains/_template, plus your data
  domains/<domain>/imports.tf    one import block per adopted object
  .export/<domain>/EXPORT_REPORT.md   what was exported and what needs a look

The goal is a first plan that says "0 to add, 0 to change, 0 to destroy".
Anything that cannot be represented exactly is kept in a raw form (SPF/DMARC
`raw:`, managed WAF `raw_rules:`) so nothing changes in Cloudflare.

Safety
  Refuses to overwrite an existing domain folder unless --force; with --force
  the old folder is copied to .export/<domain>/backup-<time>/ first.
"""
import argparse
import datetime as dt
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    from yamlio import dump_with_header, header_of, quote_txt, unquote_txt
except ImportError:
    sys.exit("PyYAML is required: pip install -r requirements.txt")

API = "https://api.cloudflare.com/client/v4"
ROOT = Path(__file__).resolve().parent.parent
TEMPLATE = ROOT / "domains" / "_template"
RULE_SCHEMA = json.loads((ROOT / "scripts" / "data" / "ruleset_rule_schema.json").read_text())["rule"]

# Which token permission each endpoint needs, for clear error messages.
PERMISSIONS = [
    ("/dns_records", "Zone > DNS > Read"),
    ("/dnssec", "Zone > DNS > Read"),
    ("/rulesets/phases/http_request_firewall", "Zone > Zone WAF > Read"),
    ("/rulesets/phases/http_ratelimit", "Zone > Zone WAF > Read"),
    ("/rulesets/phases/http_request_cache", "Zone > Cache Rules > Read"),
    ("/rulesets/phases/http_request_dynamic_redirect", "Zone > Single Redirect > Read"),
    ("/rulesets/phases/http_request_transform", "Zone > Transform Rules > Read"),
    ("/rulesets/phases/http_request_late_transform", "Zone > Transform Rules > Read"),
    ("/rulesets/phases/http_response_headers_transform", "Zone > Transform Rules > Read"),
    ("/rulesets/phases/http_request_origin", "Zone > Origin Rules > Read"),
    ("/rulesets/phases/http_config_settings", "Zone > Config Rules > Read"),
    ("/rulesets/phases/http_response_compression", "Zone > Response Compression > Read"),
    ("/settings", "Zone > Zone Settings > Read"),
    ("/bot_management", "Zone > Bot Management > Read"),
    ("/access_rules", "Zone > Firewall Services > Read"),
    ("/hold", "Zone > Zone > Read"),
    ("/cache/", "Zone > Cache Settings > Read"),
    ("/argo/", "Zone > Argo Smart Routing > Read"),
    ("/rules/lists", "Account > Account Filter Lists > Read"),
    ("/rulesets/phases/http_request_redirect", "Account > Mass URL Redirects > Read"),
]

DNS_FILES = {"A": "a", "AAAA": "aaaa", "CNAME": "cname", "MX": "mx", "TXT": "txt", "NS": "ns"}
RULE_FILES = {  # module key: (phase, file)
    "cache": ("http_request_cache_settings", "cache/cache-rules.yaml"),
    "redirects": ("http_request_dynamic_redirect", "rules/redirects.yaml"),
    "url_rewrites": ("http_request_transform", "rules/url-rewrites.yaml"),
    "request_headers": ("http_request_late_transform", "rules/request-headers.yaml"),
    "response_headers": ("http_response_headers_transform", "rules/response-headers.yaml"),
    "origin": ("http_request_origin", "rules/origin.yaml"),
    "config": ("http_config_settings", "rules/config.yaml"),
    "compression": ("http_response_compression", "rules/compression.yaml"),
}
SETTINGS = [
    "ssl", "min_tls_version", "tls_1_3", "always_use_https", "automatic_https_rewrites",
    "opportunistic_encryption", "security_level", "browser_check", "email_obfuscation",
    "browser_cache_ttl", "cache_level", "brotli", "early_hints", "http3", "0rtt",
]
BOT_FIELDS_BY_PLAN = {
    "free": ["fight_mode", "enable_js", "ai_bots_protection", "crawler_protection", "is_robots_txt_managed"],
    "pro": ["sbfm_definitely_automated", "sbfm_verified_bots", "sbfm_static_resource_protection",
            "optimize_wordpress", "enable_js", "ai_bots_protection", "crawler_protection", "is_robots_txt_managed"],
}
BOT_FIELDS_BY_PLAN["business"] = BOT_FIELDS_BY_PLAN["pro"] + ["sbfm_likely_automated"]
BOT_FIELDS_BY_PLAN["enterprise"] = BOT_FIELDS_BY_PLAN["business"] + [
    "auto_update_model", "suppress_session_score", "bm_cookie_enabled"]
MANAGED_IDS = {"efb7b8c949ac4650a09736fc376e9aee": "cloudflare_managed", "4814384a9e5d4991b9815dcfc25d2f1f": "owasp"}
BENIGN_DROPS = {"id", "version", "last_updated", "categories"}
CUSTOM_ACTIONS = ("block", "managed_challenge", "js_challenge", "challenge", "log", "skip")


class NotFound(Exception):
    pass


# --------------------------------------------------------------------------
class Client:
    def __init__(self, token):
        self.token = token

    def get(self, path, params=None):
        url = f"{API}{path}" + ("?" + urllib.parse.urlencode(params) if params else "")
        for attempt in range(5):
            req = urllib.request.Request(url, headers={"Authorization": f"Bearer {self.token}",
                                                       "User-Agent": "cloudflare-terraform-export"})
            try:
                with urllib.request.urlopen(req, timeout=60) as r:
                    return json.load(r)
            except urllib.error.HTTPError as e:
                body = e.read().decode(errors="replace")
                if e.code == 404:
                    raise NotFound(path)
                if e.code in (429, 500, 502, 503, 504) and attempt < 4:
                    time.sleep(int(e.headers.get("Retry-After") or 2 ** attempt))
                    continue
                if e.code in (401, 403):
                    need = next((p for k, p in PERMISSIONS if k in path), "the matching Read permission")
                    raise PermissionError(f"token cannot read {path}: add '{need}' to the API token") from None
                raise RuntimeError(f"{path}: HTTP {e.code} {body[:300]}") from None
            except urllib.error.URLError as e:
                if attempt < 4:
                    time.sleep(2 ** attempt)
                    continue
                raise RuntimeError(f"cannot reach the Cloudflare API: {e.reason}") from None
        raise RuntimeError(f"{path}: gave up after retries")

    def result(self, path, params=None):
        return self.get(path, params)["result"]

    def pages(self, path, per_page=100):
        page, out = 1, []
        while True:
            body = self.get(path, {"page": page, "per_page": per_page})
            out += body["result"] or []
            if page >= (body.get("result_info") or {}).get("total_pages", 1):
                return out
            page += 1


# --------------------------------------------------------------------------
def clean(value, schema, path, dropped):
    """Keep only fields the provider accepts; record anything removed."""
    if isinstance(schema, str):
        return value
    if "__list__" in schema:
        return [clean(v, schema["__list__"], f"{path}[]", dropped) for v in (value or [])]
    if "__map__" in schema:
        return {k: clean(v, schema["__map__"], f"{path}.{k}", dropped) for k, v in (value or {}).items()}
    out = {}
    for k, v in (value or {}).items():
        if k not in schema:
            if k not in BENIGN_DROPS:
                dropped.append(f"{path}.{k}".lstrip("."))
            continue
        if v is None or v == {} or v == []:
            continue
        out[k] = clean(v, schema[k], f"{path}.{k}", dropped)
    return out


def rel(name, zone):
    if name == zone:
        return "@"
    return name[: -(len(zone) + 1)] if name.endswith("." + zone) else name


def slug(text):
    s = re.sub(r"[^A-Za-z0-9]+", "_", str(text).replace("*", "wildcard")).strip("_").lower()
    return s[:60] or "item"


def unique(key, used):
    k, i = key, 2
    while k in used:
        k, i = f"{key}_{i}", i + 1
    used.add(k)
    return k


def ttl_fields(r, rec):
    if r.get("ttl", 1) != 1 and not r.get("proxied"):
        rec["ttl"] = r["ttl"]
    if r.get("comment"):
        rec["comment"] = r["comment"]
    return rec


# ---- SPF / DMARC round trip (must match modules/dns/main.tf exactly) -------
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
    s = {k: v for k, v in s.items() if v not in ([], None)}
    return s if build_spf(s) == content else {"raw": content}


def build_dmarc(d):
    def m(xs):
        return ",".join(x if x.startswith("mailto:") else f"mailto:{x}" for x in xs)
    parts = ["v=DMARC1", f"p={d.get('policy', 'none')}"]
    if d.get("subdomain_policy"):
        parts.append(f"sp={d['subdomain_policy']}")
    if d.get("pct") is not None:
        parts.append(f"pct={d['pct']}")
    for k in ("rua", "ruf"):
        if d.get(k):
            parts.append(f"{k}={m(d[k])}")
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

    def addrs(v):
        return [x.strip()[7:] if x.strip().startswith("mailto:") else x.strip() for x in v.split(",") if x.strip()]
    d = {"policy": tags.get("p", "none")}
    if "sp" in tags:
        d["subdomain_policy"] = tags["sp"]
    if tags.get("pct", "").isdigit():
        d["pct"] = int(tags["pct"])
    for k in ("rua", "ruf"):
        if k in tags:
            d[k] = addrs(tags[k])
    for k in ("adkim", "aspf", "fo"):
        if k in tags:
            d[k] = tags[k]
    return d if build_dmarc(d) == content else {"raw": content}


# ---- TXT content: keep exactly what Cloudflare holds -------------------------
# The DNS module quotes TXT content like Cloudflare does (quote_txt). Each
# helper returns YAML fields that make the module send the live value back
# unchanged, so adopting a zone never rewrites a record.
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


# --------------------------------------------------------------------------
class ZoneExport:
    def __init__(self, client, zone_id, domain, plan):
        self.c, self.zid, self.zone, self.plan = client, zone_id, domain, plan
        self.files = {}          # path inside the domain folder -> data
        self.imports = []        # (address, import id)
        self.notes = []          # things a human should look at
        self.counts = defaultdict(int)

    def imp(self, address, import_id):
        self.imports.append((address, import_id))

    def note(self, msg):
        self.notes.append(msg)

    def entrypoint(self, phase):
        try:
            rs = self.c.result(f"/zones/{self.zid}/rulesets/phases/{phase}/entrypoint")
        except NotFound:
            return None
        return rs if rs.get("rules") else None

    # ---- DNS -------------------------------------------------------------
    def dns(self):
        files, used, skipped = defaultdict(dict), defaultdict(set), defaultdict(int)

        def dns_imp(k, rid):
            self.imp(f'module.domain.module.dns.cloudflare_dns_record.this["{k}"]', f"{self.zid}/{rid}")

        def st_imp(k, rid):
            self.imp(f'module.domain.module.dns.cloudflare_dns_record.structured["{k}"]', f"{self.zid}/{rid}")

        records = self.c.pages(f"/zones/{self.zid}/dns_records")
        for r in sorted(records, key=lambda x: (x["type"], x["name"], x.get("content", ""))):
            name, t, content, d = rel(r["name"], self.zone), r["type"], r.get("content", ""), r.get("data") or {}
            if t == "CAA" and d:
                key = unique(slug(f"{d.get('tag')}_{d.get('value')}"), used["caa"])
                rec = {"name": name, "tag": d.get("tag"), "value": d.get("value")}
                if d.get("flags"):
                    rec["flags"] = d["flags"]
                files["caa"][key] = ttl_fields(r, rec)
                st_imp(f"caa/{key}", r["id"])
                continue
            if t == "SRV" and d:
                key = unique(slug(name), used["srv"])
                rec = {"name": name, **{k: d.get(k) for k in ("priority", "weight", "port", "target")}}
                files["srv"][key] = ttl_fields(r, rec)
                st_imp(f"srv/{key}", r["id"])
                continue
            if t == "NS" and name == "@":
                continue  # Cloudflare's own name servers
            if t not in DNS_FILES:
                skipped[t] += 1
                continue
            plain = unquote_txt(content)[0] if t == "TXT" else content
            if t == "TXT" and plain.startswith("v=spf1") and name not in files["spf"]:
                files["spf"][name] = ttl_fields(r, structured_fields(content, parse_spf, build_spf))
                dns_imp(f"spf/{name}", r["id"])
                continue
            if t == "TXT" and (name == "_dmarc" or name.startswith("_dmarc.")) and plain.startswith("v=DMARC1"):
                host = "@" if name == "_dmarc" else name[len("_dmarc."):]
                if host not in files["dmarc"]:
                    files["dmarc"][host] = ttl_fields(r, structured_fields(content, parse_dmarc, build_dmarc))
                    dns_imp(f"dmarc/{host}", r["id"])
                    continue
            # Matches a selector at the apex ("sel._domainkey") or under a
            # subdomain ("sel._domainkey.mg", e.g. Mailgun) -- the selector
            # itself may contain dots (e.g. "select1.343"), so match
            # non-greedily up to the first "._domainkey" label.
            m = re.match(r"^(.+?)\._domainkey(?:\.|$)", name)
            if t == "TXT" and m:
                sel = unique(m.group(1), used["dkim"])
                rec = {"name": name, **txt_fields(content)}
                files["dkim"][sel] = ttl_fields(r, rec)
                dns_imp(f"dkim/{sel}", r["id"])
                continue
            f = DNS_FILES[t]
            key = unique(slug(name) if name != "@" else "root", used[f])
            rec = {"name": name, **(txt_fields(content) if t == "TXT" else {"content": content})}
            if t in ("A", "AAAA", "CNAME"):
                rec["proxied"] = bool(r.get("proxied"))
            if t == "MX":
                rec["priority"] = r.get("priority", 0)
            files[f][key] = ttl_fields(r, rec)
            dns_imp(f"{f}/{key}", r["id"])

        for f, data in files.items():
            self.files[f"dns/{f}.yaml"] = data
            self.counts["DNS records"] += len(data)
        for t, n in skipped.items():
            self.note(f"{n} DNS record(s) of type {t} are not managed by this repo yet and were left alone.")
        raws = [h for k in ("spf", "dmarc") for h, v in files.get(k, {}).items() if "raw" in v]
        if raws:
            self.note(f"{len(raws)} SPF/DMARC record(s) kept as raw: to avoid any change. "
                      "Convert them to fields later in a separate pull request if you like.")
        try:
            st = self.c.result(f"/zones/{self.zid}/dnssec").get("status")
            if st in ("active", "pending"):
                self.files["dns/dnssec.yaml"] = {"status": "active"}
                self.imp("module.domain.module.dns.cloudflare_zone_dnssec.this[0]", self.zid)
        except NotFound:
            pass

    # ---- WAF -------------------------------------------------------------
    def waf(self):
        rs = self.entrypoint("http_request_firewall_custom")
        if rs:
            out = []
            for r in rs["rules"]:
                rule = {"ref": r.get("ref") or r["id"], "description": r.get("description", ""),
                        "expression": r["expression"], "action": r["action"]}
                if not r.get("enabled", True):
                    rule["enabled"] = False
                ap = r.get("action_parameters") or {}
                if r["action"] == "skip":
                    rule["skip"] = {k: ap[k] for k in ("ruleset", "phases", "products") if k in ap}
                    if not (r.get("logging") or {}).get("enabled", True):
                        rule["skip"]["log"] = False
                if ap.get("response"):
                    rule["response"] = {k: v for k, v in ap["response"].items() if v is not None}
                other = set(ap) - {"ruleset", "phases", "products", "response"}
                if other:
                    self.note(f"Custom rule '{rule['ref']}' uses {sorted(other)}, which this repo does not model; "
                              "the first plan will show a change for it.")
                if r["action"] not in CUSTOM_ACTIONS:
                    self.note(f"Custom rule '{rule['ref']}' uses action {r['action']}, which this repo does not model.")
                out.append(rule)
            self.files["waf/custom-rules.yaml"] = out
            self.counts["WAF custom rules"] += len(out)
            self.imp("module.domain.module.waf.cloudflare_ruleset.custom[0]", f"zones/{self.zid}/{rs['id']}")

        rs = self.entrypoint("http_ratelimit")
        if rs:
            out = []
            for r in rs["rules"]:
                rl = r.get("ratelimit") or {}
                rule = {"ref": r.get("ref") or r["id"], "description": r.get("description", ""),
                        "expression": r["expression"], "action": r["action"],
                        "characteristics": rl.get("characteristics", ["ip.src", "cf.colo.id"]),
                        "period": rl.get("period", 10), "requests_per_period": rl.get("requests_per_period"),
                        "mitigation_timeout": rl.get("mitigation_timeout", 10)}
                for k in ("counting_expression", "requests_to_origin"):
                    if rl.get(k) not in (None, ""):
                        rule[k] = rl[k]
                if not r.get("enabled", True):
                    rule["enabled"] = False
                resp = (r.get("action_parameters") or {}).get("response")
                if resp:
                    rule["response"] = {k: v for k, v in resp.items() if v is not None}
                if rl.get("score_per_period") or rl.get("score_response_header_name"):
                    self.note(f"Rate limit '{rule['ref']}' uses complexity scoring, which this repo does not model.")
                out.append(rule)
            self.files["waf/rate-limits.yaml"] = out
            self.counts["Rate limiting rules"] += len(out)
            self.imp("module.domain.module.waf.cloudflare_ruleset.rate_limit[0]", f"zones/{self.zid}/{rs['id']}")

        rs = self.entrypoint("http_request_firewall_managed")
        if rs:
            if self.plan == "free":
                self.note("The zone has a managed WAF entry point but is on Free; it was not exported.")
                return
            dropped = []
            raw = [clean(r, RULE_SCHEMA, f"managed #{i + 1}", dropped) for i, r in enumerate(rs["rules"])]
            self.files["waf/managed-rules.yaml"] = {"raw_rules": raw}
            names = [MANAGED_IDS.get((r.get("action_parameters") or {}).get("id"), "other managed ruleset")
                     for r in rs["rules"] if r.get("action") == "execute"]
            self.counts["Managed WAF rules"] += len(raw)
            self.imp("module.domain.module.waf.cloudflare_ruleset.managed[0]", f"zones/{self.zid}/{rs['id']}")
            self.note("Managed WAF exported exactly as raw_rules (deploys: " + (", ".join(names) or "none") +
                      "). It works as it is; switching to the simple cloudflare_managed/owasp form is optional "
                      "and will show as a change in the plan.")
            if dropped:
                self.note(f"Managed WAF fields not supported by the provider were left out: {', '.join(dropped)}.")

    # ---- Rules engine phases ----------------------------------------------
    def rules(self):
        for key, (phase, path) in RULE_FILES.items():
            rs = self.entrypoint(phase)
            if not rs:
                continue
            dropped, out = [], []
            for i, r in enumerate(rs["rules"]):
                rule = {"ref": r.get("ref") or r["id"], "description": r.get("description", ""),
                        "expression": r["expression"]}
                if r.get("action_parameters"):
                    rule["action_parameters"] = clean(r["action_parameters"], RULE_SCHEMA["action_parameters"],
                                                      f"{path} #{i + 1}", dropped)
                if not r.get("enabled", True):
                    rule["enabled"] = False
                out.append(rule)
            self.files[path] = out
            self.counts[f"Rules: {key.replace('_', ' ')}"] += len(out)
            self.imp(f'module.domain.module.rules.cloudflare_ruleset.this["{key}"]', f"zones/{self.zid}/{rs['id']}")
            if dropped:
                self.note(f"{path}: fields not supported by the provider were left out: {', '.join(dropped)}.")

    # ---- Security and cache -----------------------------------------------
    def security(self):
        try:
            sh = self.c.result(f"/zones/{self.zid}/settings/security_header")["value"]
            h = sh.get("strict_transport_security") or {}
            if h.get("enabled"):
                self.files["security/hsts.yaml"] = {k: h[k] for k in ("enabled", "max_age", "include_subdomains",
                                                                       "preload", "nosniff") if k in h}
                self.imp('module.domain.module.zone_settings.cloudflare_zone_setting.this["security_header"]',
                         f"{self.zid}/security_header")
        except NotFound:
            pass
        try:
            bm = self.c.result(f"/zones/{self.zid}/bot_management")
            vals = {k: bm[k] for k in BOT_FIELDS_BY_PLAN[self.plan] if bm.get(k) is not None}
            if vals:
                self.files["security/bot-management.yaml"] = vals
                self.imp("module.domain.module.security.cloudflare_bot_management.this[0]", self.zid)
        except NotFound:
            pass
        try:
            hold = self.c.result(f"/zones/{self.zid}/hold")
            if hold.get("hold"):
                vals = {"enabled": True}
                if hold.get("include_subdomains"):
                    vals["include_subdomains"] = True
                self.files["security/zone-hold.yaml"] = vals
                self.imp("module.domain.module.security.cloudflare_zone_hold.this[0]", self.zid)
        except NotFound:
            pass
        rules, used = {}, set()
        for r in self.c.pages(f"/zones/{self.zid}/firewall/access_rules/rules"):
            if (r.get("scope") or {}).get("type") != "zone":
                continue  # inherited account-level rules stay in the dashboard
            cfg = r.get("configuration") or {}
            key = unique(slug(r.get("notes") or f"{r['mode']}_{cfg.get('value', '')}"), used)
            rule = {"mode": r["mode"], "target": cfg.get("target"), "value": cfg.get("value")}
            if r.get("notes"):
                rule["notes"] = r["notes"]
            rules[key] = rule
            self.imp(f'module.domain.module.security.cloudflare_access_rule.this["{key}"]',
                     f"zones/{self.zid}/{r['id']}")
        if rules:
            self.files["security/ip-access-rules.yaml"] = rules
            self.counts["IP Access Rules"] += len(rules)

    def cache(self):
        vals = {}
        for key, path, addr in (("smart_tiered_cache", "cache/tiered_cache_smart_topology_enable", "cloudflare_tiered_cache"),
                                ("argo_tiered_caching", "argo/tiered_caching", "cloudflare_argo_tiered_caching")):
            try:
                v = self.c.result(f"/zones/{self.zid}/{path}").get("value")
            except (NotFound, PermissionError):
                continue
            if key == "argo_tiered_caching" and v != "on":
                continue  # only manage Argo tiered caching when it is in use
            vals[key] = v
            self.imp(f"module.domain.module.cache.{addr}.this[0]", self.zid)
        if vals:
            self.files["cache/settings.yaml"] = vals

    def settings(self):
        vals = {}
        for s in SETTINGS:
            try:
                res = self.c.result(f"/zones/{self.zid}/settings/{s}")
            except NotFound:
                continue
            if res.get("editable") is False:
                continue  # locked by the plan; managing it would only cause errors
            vals[s] = res.get("value")
            self.imp(f'module.domain.module.zone_settings.cloudflare_zone_setting.this["{s}"]', f"{self.zid}/{s}")
        if vals:
            self.files["settings/zone.yaml"] = vals
            self.counts["Zone settings"] += len(vals)

    def run(self):
        for label, fn in (("DNS", self.dns), ("WAF", self.waf), ("rules", self.rules),
                          ("security", self.security), ("cache", self.cache), ("settings", self.settings)):
            print(f"  reading {label} ...", flush=True)
            try:
                fn()
            except PermissionError as e:
                self.note(f"{label} skipped: {e}.")
                print(f"  ! {label} skipped: {e}")


# --------------------------------------------------------------------------
def write_imports(path, imports):
    lines = [
        "# Generated by scripts/export_zone.py.",
        "# These blocks tell Terraform to ADOPT objects that already exist in",
        "# Cloudflare instead of creating them; the change summary lists them",
        "# as \"adopt\". Delete this file after the first successful apply.",
        "",
    ]
    for to, id_ in imports:
        lines += ["import {", f"  to = {to}", f'  id = "{id_}"', "}", ""]
    Path(path).write_text("\n".join(lines), encoding="utf-8", newline="\n")


def prepare_dest(dest, force, backup_dir):
    if not dest.exists():
        return
    if not force:
        sys.exit(f"{dest} already exists. Re-run with --force to replace it "
                 f"(the current folder is backed up to {backup_dir} first).")
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    shutil.copytree(dest, backup_dir / f"backup-{stamp}")
    shutil.rmtree(dest)
    print(f"Backed up the old folder to {backup_dir / f'backup-{stamp}'}")


def run_validator(target):
    print("\nChecking the exported YAML ...")
    return subprocess.call([sys.executable, str(ROOT / "scripts" / "validate.py"), str(target)])


def export_zone(client, a):
    zone = client.result(f"/zones/{a.zone_id}")
    if zone["name"] != a.domain:
        sys.exit(f"Zone {a.zone_id} is {zone['name']}, not {a.domain}. Check the Zone ID.")
    plan = a.plan or {"pro": "pro", "business": "business", "enterprise": "enterprise"}.get(
        (zone.get("plan") or {}).get("legacy_id"), "free")
    dest = ROOT / "domains" / a.domain
    xdir = ROOT / ".export" / a.domain
    xdir.mkdir(parents=True, exist_ok=True)
    prepare_dest(dest, a.force, xdir)

    print(f"Exporting {a.domain} ({plan} plan). Nothing in Cloudflare is changed.")
    ex = ZoneExport(client, a.zone_id, a.domain, plan)
    ex.run()

    # Start from the template so every file exists with its documentation,
    # then put the exported data under each file's header.
    shutil.copytree(TEMPLATE, dest)
    (dest / "README.md").unlink(missing_ok=True)
    stamp = dt.date.today().isoformat()
    marker = f"--- Exported from Cloudflare on {stamp}. Your data starts below this line. ---"
    for tpl in sorted(TEMPLATE.rglob("*.yaml")):
        relpath = tpl.relative_to(TEMPLATE).as_posix()
        if relpath != "domain.yaml" and ex.files.get(relpath):
            dump_with_header(dest / relpath, ex.files[relpath], header_of(tpl), marker)
    dump_with_header(dest / "domain.yaml", {"name": a.domain, "zone_id": a.zone_id, "plan": plan, "owner": "change-me"},
                     header_of(TEMPLATE / "domain.yaml"))
    write_imports(dest / "imports.tf", ex.imports)

    report = [f"# Export report: {a.domain}", "", f"Exported {stamp}, plan **{plan}**, zone `{a.zone_id}`.", "",
              "## Exported", ""]
    report += [f"- {k}: {v}" for k, v in sorted(ex.counts.items())] or ["- nothing"]
    report += ["", f"{len(ex.imports)} objects will be adopted (see imports.tf).", "", "## Needs a look", ""]
    report += [f"- {n}" for n in ex.notes] or ["- nothing"]
    report += ["", "## Next steps", "", "1. Read the notes above.",
               f"2. `python3 cf.py plan {a.domain}`.",
               "3. The change summary must show only *adopt* lines: nothing created, changed or deleted.",
               "4. Open a pull request. After merge and approval, the apply only adopts.",
               "5. Delete imports.tf in a follow-up pull request."]
    (xdir / "EXPORT_REPORT.md").write_text("\n".join(report) + "\n", encoding="utf-8")

    print(f"\nExported to domains/{a.domain}/")
    for k, v in sorted(ex.counts.items()):
        print(f"  {k}: {v}")
    print(f"  Objects to adopt: {len(ex.imports)}")
    for n in ex.notes:
        print(f"  NOTE: {n}")
    print(f"Report: .export/{a.domain}/EXPORT_REPORT.md")
    rc = run_validator(dest)
    print(f"\nNext: python3 cf.py plan {a.domain}")
    return rc


def export_account(client, a):
    adir = ROOT / "account"
    out = {"ip": {}, "asn": {}, "hostname": {}, "redirect": {}}
    imports, notes = [], []
    print("Exporting account lists. Nothing in Cloudflare is changed.")
    for lst in client.result(f"/accounts/{a.account_id}/rules/lists"):
        items, cursor = [], None
        while True:
            params = {"per_page": 500}
            if cursor:
                params["cursor"] = cursor
            body = client.get(f"/accounts/{a.account_id}/rules/lists/{lst['id']}/items", params)
            items += body["result"] or []
            cursor = ((body.get("result_info") or {}).get("cursors") or {}).get("after")
            if not cursor:
                break
        kind, conv = lst["kind"], []
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
                conv.append({**{k: v for k, v in i["redirect"].items() if v is not None}, **c})
        entry = {"description": lst["description"]} if lst.get("description") else {}
        entry["items"] = conv
        out.setdefault(kind, {})[lst["name"]] = entry
        imports.append((f'module.lists.cloudflare_list.this["{lst["name"]}"]', f"{a.account_id}/{lst['id']}"))
    try:
        rs = client.result(f"/accounts/{a.account_id}/rulesets/phases/http_request_redirect/entrypoint")
        if rs.get("rules"):
            imports.append(("module.lists.cloudflare_ruleset.bulk_redirects[0]", f"accounts/{a.account_id}/{rs['id']}"))
            notes.append("Existing Bulk Redirect rules are replaced by one generated rule per redirect list; "
                         "the plan shows this as a change to review.")
    except NotFound:
        pass

    def account_entrypoint(phase):
        try:
            rs = client.result(f"/accounts/{a.account_id}/rulesets/phases/{phase}/entrypoint")
        except NotFound:
            return None
        return rs if rs.get("rules") else None

    waf_files = {}
    rs = account_entrypoint("http_request_firewall_custom")
    if rs:
        out_rules = []
        for r in rs["rules"]:
            rule = {"ref": r.get("ref") or r["id"], "description": r.get("description", ""),
                    "expression": r["expression"], "action": r["action"]}
            if not r.get("enabled", True):
                rule["enabled"] = False
            ap = r.get("action_parameters") or {}
            if r["action"] == "skip":
                rule["skip"] = {k: ap[k] for k in ("ruleset", "phases", "products") if k in ap}
            if ap.get("response"):
                rule["response"] = {k: v for k, v in ap["response"].items() if v is not None}
            out_rules.append(rule)
        waf_files["waf/custom-rules.yaml"] = out_rules
        imports.append(("module.account_waf.cloudflare_ruleset.custom[0]", f"accounts/{a.account_id}/{rs['id']}"))

    rs = account_entrypoint("http_ratelimit")
    if rs:
        out_rules = []
        for r in rs["rules"]:
            rl = r.get("ratelimit") or {}
            rule = {"ref": r.get("ref") or r["id"], "description": r.get("description", ""),
                    "expression": r["expression"], "action": r["action"],
                    "characteristics": rl.get("characteristics", ["ip.src", "cf.colo.id"]),
                    "period": rl.get("period", 10), "requests_per_period": rl.get("requests_per_period"),
                    "mitigation_timeout": rl.get("mitigation_timeout", 10)}
            if not r.get("enabled", True):
                rule["enabled"] = False
            out_rules.append(rule)
        waf_files["waf/rate-limits.yaml"] = out_rules
        imports.append(("module.account_waf.cloudflare_ruleset.rate_limit[0]", f"accounts/{a.account_id}/{rs['id']}"))

    rs = account_entrypoint("http_request_firewall_managed")
    if rs:
        dropped = []
        raw = [clean(r, RULE_SCHEMA, f"account managed #{i + 1}", dropped) for i, r in enumerate(rs["rules"])]
        waf_files["waf/managed-rules.yaml"] = {"raw_rules": raw}
        imports.append(("module.account_waf.cloudflare_ruleset.managed[0]", f"accounts/{a.account_id}/{rs['id']}"))
        if dropped:
            notes.append(f"account/waf/managed-rules.yaml: fields not supported by the provider were left out: {', '.join(dropped)}.")

    logpush_jobs = {}
    try:
        for job in client.result(f"/accounts/{a.account_id}/logpush/jobs"):
            name = job.get("name") or f"job_{job['id']}"
            entry = {"dataset": job["dataset"], "destination_conf": job["destination_conf"]}
            if not job.get("enabled", True):
                entry["enabled"] = False
            for k in ("filter", "frequency", "logpull_options"):
                if job.get(k):
                    entry[k] = job[k]
            logpush_jobs[name] = entry
            imports.append((f'module.logpush.cloudflare_logpush_job.this["{name}"]', f"accounts/{a.account_id}/{job['id']}"))
    except (NotFound, PermissionError):
        pass

    headers = {k: header_of(adir / "lists" / f"{k}.yaml") for k in out}
    acct_header = header_of(adir / "account.yaml")
    stamp = dt.date.today().isoformat()
    marker = f"--- Exported from Cloudflare on {stamp}. Your data starts below this line. ---"
    dump_with_header(adir / "account.yaml", {"account_id": a.account_id, "plan": a.plan or "enterprise"}, acct_header)
    for kind, lists in out.items():
        dump_with_header(adir / "lists" / f"{kind}.yaml", lists, headers[kind],
                         marker if lists else None)
    for rel, data in waf_files.items():
        dump_with_header(adir / rel, data, header_of(adir / rel), marker if data else None)
    if logpush_jobs:
        dump_with_header(adir / "logpush.yaml", logpush_jobs, header_of(adir / "logpush.yaml"), marker)
    write_imports(adir / "imports.tf", imports)
    print(f"Exported {sum(len(v) for v in out.values())} list(s), "
          f"{sum(len(v) for v in waf_files.values())} account WAF rule(s), {len(logpush_jobs)} Logpush job(s).")
    notes.append("Notification policies (notifications.yaml) are not exported yet -- "
                 "set them up by hand here if you have existing ones in the dashboard.")
    if not a.plan:
        print("  NOTE: set plan: in account/account.yaml to the highest plan in the account (used for limit checks).")
    for n in notes:
        print(f"  NOTE: {n}")
    rc = run_validator("account")
    print("\nNext: python3 cf.py plan account")
    return rc


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--zone-id")
    ap.add_argument("--domain")
    ap.add_argument("--account-id", help="export account lists and Bulk Redirects instead of a zone")
    ap.add_argument("--plan", choices=["free", "pro", "business", "enterprise"], help="override the plan read from the API")
    ap.add_argument("--force", action="store_true", help="replace an existing folder (it is backed up first)")
    a = ap.parse_args()

    token = os.environ.get("CLOUDFLARE_API_TOKEN")
    if not token:
        sys.exit("Set CLOUDFLARE_API_TOKEN first (a read-only token is enough).")
    hexid = re.compile(r"^[0-9a-f]{32}$")
    hostre = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")
    client = Client(token)
    try:
        if a.account_id:
            if not hexid.match(a.account_id):
                sys.exit("--account-id must be the 32-character Account ID.")
            sys.exit(export_account(client, a))
        if not (a.zone_id and a.domain):
            ap.error("--zone-id and --domain are required (or --account-id)")
        if not hexid.match(a.zone_id):
            sys.exit("--zone-id must be the 32-character Zone ID.")
        if not hostre.match(a.domain):
            sys.exit("--domain must be a valid hostname (letters, digits, hyphens, dots).")
        sys.exit(export_zone(client, a))
    except (PermissionError, RuntimeError) as e:
        sys.exit(f"Export stopped: {e}")


if __name__ == "__main__":
    main()
