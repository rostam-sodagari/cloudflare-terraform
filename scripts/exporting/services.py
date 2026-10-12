"""Collect a zone export in memory before publishing files."""
import re
from collections import defaultdict
from .client import NotFound
from .config import BOT_FIELDS_BY_PLAN, CUSTOM_ACTIONS, DNS_FILES, MANAGED_IDS, RULE_FILES, RULE_SCHEMA, SETTINGS
from .converters import custom_rule_fields, rate_limit_fields, clean, rel, slug, unique, ttl_fields, txt_fields, structured_fields, parse_spf, build_spf, parse_dmarc, build_dmarc
from yamlio import unquote_txt
from .identities import Identities
from .output import indexed
from config import KNOWN_SETTINGS


class ZoneExport:
    def __init__(self, client, zone_id, domain, plan, bindings=None):
        self.c, self.zid, self.zone, self.plan = client, zone_id, domain, plan
        self.identities = Identities(bindings)
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
            ruleset = self.c.result(f"/zones/{self.zid}/rulesets/phases/{phase}/entrypoint")
        except NotFound:
            return None
        return ruleset if ruleset.get("rules") else None

    # ---- DNS -------------------------------------------------------------
    def dns(self):
        files, used, skipped = defaultdict(dict), defaultdict(set), defaultdict(int)

        def dns_imp(k, record_id):
            self.imp(indexed('module.domain.module.dns.cloudflare_dns_record.this', k), f"{self.zid}/{record_id}")

        def st_imp(k, record_id):
            self.imp(indexed('module.domain.module.dns.cloudflare_dns_record.structured', k), f"{self.zid}/{record_id}")

        records = self.c.pages(f"/zones/{self.zid}/dns_records")
        email_dns = []
        if any((record.get("meta") or {}).get("email_routing") is True for record in records):
            from .dns_values import matches_dns
            email_dns = self.c.pages(f"/zones/{self.zid}/email/routing/dns")
            email_dns = [{**record, "name": self.zone if record["name"] == "@" else record["name"]} for record in email_dns]
        email_owned = 0
        for api_record in sorted(records, key=lambda x: (x["type"], x["name"], x.get("content", ""))):
            if email_dns and any(matches_dns(api_record, required) for required in email_dns):
                email_owned += 1
                continue
            name, record_type, content, record_data = rel(api_record["name"], self.zone), api_record["type"], api_record.get("content", ""), api_record.get("data") or {}
            if record_type == "CAA" and record_data:
                key = self.identities.key("caa", slug(f"{record_data.get('tag')}_{record_data.get('value')}"), f"{self.zid}/{api_record['id']}", used["caa"])
                record_config = {"name": name, "tag": record_data.get("tag"), "value": record_data.get("value")}
                if record_data.get("flags"):
                    record_config["flags"] = record_data["flags"]
                files["caa"][key] = ttl_fields(api_record, record_config)
                st_imp(f"caa/{key}", api_record["id"])
                continue
            if record_type == "SRV" and record_data:
                key = self.identities.key("srv", slug(name), f"{self.zid}/{api_record['id']}", used["srv"])
                record_config = {"name": name, **{k: record_data.get(k) for k in ("priority", "weight", "port", "target")}}
                files["srv"][key] = ttl_fields(api_record, record_config)
                st_imp(f"srv/{key}", api_record["id"])
                continue
            if record_type == "NS" and name == "@":
                continue  # Cloudflare's own name servers
            if record_type not in DNS_FILES:
                skipped[record_type] += 1
                continue
            plain = unquote_txt(content)[0] if record_type == "TXT" else content
            if record_type == "TXT" and plain.startswith("v=spf1") and name not in files["spf"]:
                files["spf"][name] = ttl_fields(api_record, structured_fields(content, parse_spf, build_spf))
                dns_imp(f"spf/{name}", api_record["id"])
                continue
            if record_type == "TXT" and (name == "_dmarc" or name.startswith("_dmarc.")) and plain.startswith("v=DMARC1"):
                host = "@" if name == "_dmarc" else name[len("_dmarc."):]
                if host not in files["dmarc"]:
                    files["dmarc"][host] = ttl_fields(api_record, structured_fields(content, parse_dmarc, build_dmarc))
                    dns_imp(f"dmarc/{host}", api_record["id"])
                    continue
            # Matches a selector at the apex ("sel._domainkey") or under a
            # subdomain ("sel._domainkey.mg", e.g. Mailgun) -- the selector
            # itself may contain dots (e.g. "select1.343"), so match
            # non-greedily up to the first "._domainkey" label.
            selector_match = re.match(r"^(.+?)\._domainkey(?:\.|$)", name)
            if record_type == "TXT" and selector_match:
                selector = self.identities.key("dkim", selector_match.group(1), f"{self.zid}/{api_record['id']}", used["dkim"])
                record_config = {"name": name, **txt_fields(content)}
                files["dkim"][selector] = ttl_fields(api_record, record_config)
                dns_imp(f"dkim/{selector}", api_record["id"])
                continue
            f = DNS_FILES[record_type]
            key = self.identities.key(f, slug(name) if name != "@" else "root", f"{self.zid}/{api_record['id']}", used[f])
            record_config = {"name": name, **(txt_fields(content) if record_type == "TXT" else {"content": content})}
            if record_type in ("A", "AAAA", "CNAME"):
                record_config["proxied"] = bool(api_record.get("proxied"))
            if record_type == "MX":
                record_config["priority"] = api_record.get("priority", 0)
            files[f][key] = ttl_fields(api_record, record_config)
            dns_imp(f"{f}/{key}", api_record["id"])

        for f, data in files.items():
            self.files[f"dns/{f}.yaml"] = data
            self.counts["DNS records"] += len(data)
        for record_type, n in skipped.items():
            self.note(f"{n} DNS record(s) of type {record_type} are not managed by this repo yet and were left alone.")
        for name in (*DNS_FILES.values(), "spf", "dmarc", "dkim", "caa", "srv"):
            self.files.setdefault(f"dns/{name}.yaml", {})
        if email_owned:
            self.note(f"{email_owned} automatic Email Routing DNS record(s) are owned by Email Routing and were not imported as separate DNS resources.")
        raws = [h for k in ("spf", "dmarc") for h, v in files.get(k, {}).items() if "raw" in v]
        if raws:
            self.note(f"{len(raws)} SPF/DMARC record(s) kept as raw: to avoid any change. "
                      "Convert them to fields later in a separate pull request if you like.")
        try:
            dnssec_status = self.c.result(f"/zones/{self.zid}/dnssec").get("status")
            if dnssec_status in ("active", "pending", "disabled", "pending-disabled"):
                self.files["dns/dnssec.yaml"] = {"status": {"pending": "active", "pending-disabled": "disabled"}.get(dnssec_status, dnssec_status)}
                self.imp("module.domain.module.dns.cloudflare_zone_dnssec.this[0]", self.zid)
        except NotFound:
            pass

    # ---- WAF -------------------------------------------------------------
    def waf(self):
        self._custom_rules()
        self._rate_limits()
        self._managed_rules()

    def _custom_rules(self):
        ruleset = self.entrypoint("http_request_firewall_custom")
        self.files["waf/custom-rules.yaml"] = []
        if ruleset:
            exported_rules = []
            for api_rule in ruleset["rules"]:
                rule = custom_rule_fields(api_rule, include_skip_logging=True)
                action_parameters = api_rule.get("action_parameters") or {}
                unsupported_fields = set(action_parameters) - {"ruleset", "phases", "products", "response"}
                if unsupported_fields:
                    self.note(f"Custom rule '{rule['ref']}' uses {sorted(unsupported_fields)}, which this repo does not model; "
                              "the first plan will show a change for it.")
                if api_rule["action"] not in CUSTOM_ACTIONS:
                    self.note(f"Custom rule '{rule['ref']}' uses action {api_rule['action']}, which this repo does not model.")
                exported_rules.append(rule)
            self.files["waf/custom-rules.yaml"] = exported_rules
            self.counts["WAF custom rules"] += len(exported_rules)
            self.imp("module.domain.module.waf.cloudflare_ruleset.custom[0]", f"zones/{self.zid}/{ruleset['id']}")

    def _rate_limits(self):
        ruleset = self.entrypoint("http_ratelimit")
        self.files["waf/rate-limits.yaml"] = []
        if ruleset:
            exported_rules = []
            for api_rule in ruleset["rules"]:
                rate_limit = api_rule.get("ratelimit") or {}
                rule = rate_limit_fields(api_rule, include_zone_fields=True)
                if rate_limit.get("score_per_period") or rate_limit.get("score_response_header_name"):
                    self.note(f"Rate limit '{rule['ref']}' uses complexity scoring, which this repo does not model.")
                exported_rules.append(rule)
            self.files["waf/rate-limits.yaml"] = exported_rules
            self.counts["Rate limiting rules"] += len(exported_rules)
            self.imp("module.domain.module.waf.cloudflare_ruleset.rate_limit[0]", f"zones/{self.zid}/{ruleset['id']}")

    def _managed_rules(self):
        ruleset = self.entrypoint("http_request_firewall_managed")
        if self.plan != "free":
            self.files["waf/managed-rules.yaml"] = {}
        if ruleset:
            if self.plan == "free":
                self.note("The zone has a managed WAF entry point but is on Free; it was not exported.")
                return
            dropped = []
            raw = [clean(api_rule, RULE_SCHEMA, f"managed #{i + 1}", dropped) for i, api_rule in enumerate(ruleset["rules"])]
            self.files["waf/managed-rules.yaml"] = {"raw_rules": raw}
            names = [MANAGED_IDS.get((api_rule.get("action_parameters") or {}).get("id"), "other managed ruleset")
                     for api_rule in ruleset["rules"] if api_rule.get("action") == "execute"]
            self.counts["Managed WAF rules"] += len(raw)
            self.imp("module.domain.module.waf.cloudflare_ruleset.managed[0]", f"zones/{self.zid}/{ruleset['id']}")
            self.note("Managed WAF exported exactly as raw_rules (deploys: " + (", ".join(names) or "none") +
                      "). It works as it is; switching to the simple cloudflare_managed/owasp form is optional "
                      "and will show as a change in the plan.")
            if dropped:
                self.note(f"Managed WAF fields not supported by the provider were left out: {', '.join(dropped)}.")

    # ---- Rules engine phases ----------------------------------------------
    def rules(self):
        for key, (phase, path) in RULE_FILES.items():
            ruleset = self.entrypoint(phase)
            self.files[path] = []
            if not ruleset:
                continue
            dropped, exported_rules = [], []
            for i, api_record in enumerate(ruleset["rules"]):
                rule = {"ref": api_record.get("ref") or api_record["id"], "description": api_record.get("description", ""),
                        "expression": api_record["expression"]}
                if api_record.get("action_parameters"):
                    rule["action_parameters"] = clean(api_record["action_parameters"], RULE_SCHEMA["action_parameters"],
                                                      f"{path} #{i + 1}", dropped)
                if not api_record.get("enabled", True):
                    rule["enabled"] = False
                exported_rules.append(rule)
            self.files[path] = exported_rules
            self.counts[f"Rules: {key.replace('_', ' ')}"] += len(exported_rules)
            self.imp(indexed('module.domain.module.rules.cloudflare_ruleset.this', key), f"zones/{self.zid}/{ruleset['id']}")
            if dropped:
                self.note(f"{path}: fields not supported by the provider were left out: {', '.join(dropped)}.")

    # ---- Security and cache -----------------------------------------------
    def security(self):
        try:
            sh = self.c.result(f"/zones/{self.zid}/settings/security_header")["value"]
            h = sh.get("strict_transport_security") or {}
            if "enabled" in h:
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
        rules, used = {}, set()
        for api_record in self.c.pages(f"/zones/{self.zid}/firewall/access_rules/rules"):
            if (api_record.get("scope") or {}).get("type") != "zone":
                continue  # inherited account-level rules stay in the dashboard
            cfg = api_record.get("configuration") or {}
            key = self.identities.key("access", slug(api_record.get("notes") or f"{api_record['mode']}_{cfg.get('value', '')}"), f"zones/{self.zid}/{api_record['id']}", used)
            rule = {"mode": api_record["mode"], "target": cfg.get("target"), "value": cfg.get("value")}
            if api_record.get("notes"):
                rule["notes"] = api_record["notes"]
            rules[key] = rule
            self.imp(indexed('module.domain.module.security.cloudflare_access_rule.this', key),
                     f"zones/{self.zid}/{api_record['id']}")
        self.files["security/ip-access-rules.yaml"] = rules
        if rules:
            self.counts["IP Access Rules"] += len(rules)

    def cache(self):
        vals = {}
        for key, path, addr in (("smart_tiered_cache", "cache/tiered_cache_smart_topology_enable", "cloudflare_tiered_cache"),
                                ("argo_tiered_caching", "argo/tiered_caching", "cloudflare_argo_tiered_caching"),
                                ("cache_reserve", "cache/cache_reserve", "cloudflare_zone_cache_reserve"),
                                ("argo_smart_routing", "argo/smart_routing", "cloudflare_argo_smart_routing"),
                                ("regional_tiered_cache", "cache/regional_tiered_cache", "cloudflare_regional_tiered_cache")):
            try:
                v = self.c.result(f"/zones/{self.zid}/{path}").get("value")
            except NotFound:
                continue
            vals[key] = v
            self.imp(f"module.domain.module.cache.{addr}.this[0]", self.zid)
        if vals:
            self.files["cache/settings.yaml"] = vals

    def extended(self):
        for endpoint, path, fields, address in (
            ('origin_tls_client_auth/settings', 'security/authenticated-origin-pulls.yaml', ('enabled',), 'module.domain.module.security.cloudflare_authenticated_origin_pulls_settings.zone[0]'),
            ("acm/total_tls", "security/total-tls.yaml", ("enabled", "certificate_authority"), "module.domain.module.zone_settings.cloudflare_total_tls.this[0]"),
            ("ct/alerting", "security/ct-alerting.yaml", ("enabled", "emails"), "module.domain.module.zone_settings.cloudflare_ct_alerting.this[0]"),
            ("cache/variants", "cache/variants.yaml", (), "module.domain.module.cache.cloudflare_zone_cache_variants.this[0]")):
            try:
                value = self.c.result(f"/zones/{self.zid}/{endpoint}")
            except NotFound:
                continue
            data = {field: value[field] for field in fields if field in value} if fields else value.get("value", {})
            if data:
                if endpoint == 'origin_tls_client_auth/settings':
                    # Hostname configuration is a separate API; preserve this file when scoped.
                    # Resync supplies the existing scope rather than overwriting it with zone defaults.
                    if getattr(self, 'origin_pull_hostname', None):
                        zone_enabled = data['enabled']
                        value = self.c.result(f'/zones/{self.zid}/origin_tls_client_auth/hostnames/{self.origin_pull_hostname}')
                        data = {key: value[key] for key in ('enabled', 'hostname', 'cert_id') if key in value}
                        data['zone_enabled'] = zone_enabled
                        self.imp('module.domain.module.security.cloudflare_authenticated_origin_pulls_settings.zone[0]', self.zid)
                        address = 'module.domain.module.security.cloudflare_authenticated_origin_pulls.this[0]'
                self.files[path] = data
                self.imp(address, f'{self.zid}/{self.origin_pull_hostname}' if endpoint == 'origin_tls_client_auth/settings' and getattr(self, 'origin_pull_hostname', None) else self.zid)
        try:
            settings = self.c.result(f"/zones/{self.zid}/email/routing")
        except NotFound:
            return
        email = {"enabled": settings["enabled"]}
        if email["enabled"]:
            self.imp("module.domain.module.email_routing.cloudflare_email_routing_settings.this[0]", self.zid)
        email["rules"] = []
        used = set()
        try:
            catch = self.c.result(f"/zones/{self.zid}/email/routing/rules/catch_all")
        except NotFound:
            catch = None
        for rule in self.c.pages(f"/zones/{self.zid}/email/routing/rules"):
            if catch and rule.get("id") == catch.get("id"):
                continue  # The list includes catch-all; its resource uses a separate API.
            key = self.identities.key("email", slug(rule.get("name") or rule["id"]), f"{self.zid}/{rule['id']}", used)
            email["rules"].append({"ref": key, **{field: rule[field] for field in
                ("name", "enabled", "priority", "matchers", "actions") if field in rule}})
            self.imp(indexed('module.domain.module.email_routing.cloudflare_email_routing_rule.this', key), f"{self.zid}/{rule['id']}")
        if catch is not None:
            if len(catch.get("actions", [])) != 1:
                raise RuntimeError("Catch-all has multiple actions that cannot be represented")
            action = catch["actions"][0]
            email["catch_all"] = {"action": action["type"], "enabled": catch.get("enabled", True), "name": catch.get("name", "")}
            if action["type"] in ("forward", "worker"):
                if len(action.get("value", [])) != 1:
                    raise RuntimeError("Catch-all destinations cannot be represented without loss")
                email["catch_all"]["destination"] = action["value"][0]
            self.imp("module.domain.module.email_routing.cloudflare_email_routing_catch_all.this[0]", self.zid)
        self.files["dns/email-routing.yaml"] = email

    def settings(self):
        vals = {}
        try:
            values = self.c.pages(f"/zones/{self.zid}/settings")
        except NotFound:
            values = []
            for setting in sorted(KNOWN_SETTINGS - {"security_header", "ssl_recommender"}):
                try:
                    value = self.c.result(f"/zones/{self.zid}/settings/{setting}")
                    values.append({**value, "id": setting})
                except NotFound:
                    continue
        available = {setting["id"] for setting in values if setting.get("editable") is not False}
        for res in values:
            s = res["id"]
            if s == "0rtt" and "tls_1_3" in available:
                continue  # TLS 1.3 zrt is the single writer for both settings.
            if s not in KNOWN_SETTINGS or s in ("security_header", "ssl_recommender"):
                continue
            if res.get("editable") is False:
                continue  # locked by the plan; managing it would only cause errors
            vals[s] = res.get("value")
            self.imp(indexed('module.domain.module.zone_settings.cloudflare_zone_setting.this', s), f"{self.zid}/{s}")
        if vals:
            self.files["settings/zone.yaml"] = vals
            self.counts["Zone settings"] += len(vals)

    def run(self):
        for label, fn in (("DNS", self.dns), ("WAF", self.waf), ("rules", self.rules),
                          ("security", self.security), ("cache", self.cache), ("settings", self.settings), ("extended", self.extended)):
            print(f"  reading {label} ...", flush=True)
            try:
                fn()
            except PermissionError as e:
                raise PermissionError(
                    f"{label} export failed because the token lacks a required "
                    f"read permission: {e}"
                ) from e
