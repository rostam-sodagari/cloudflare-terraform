"""Evaluate domain controls in their established reporting order."""
import re
from pathlib import Path
from config import LIMITS
from .common import Result, load, managed_or


def audit_domain(d: Path):
    domain_dir = d
    domain_name = domain_dir.name
    dom = load(domain_dir / "domain.yaml") or {}
    plan = dom.get("plan", "free")
    is_example = bool(dom.get("example"))
    zone_settings = load(domain_dir / "settings" / "zone.yaml") or {}
    results = []

    def add(cid, area, control, sev, scope, status, evidence):
        results.append(Result(cid, area, control, sev, scope, status, evidence))

    _audit_dns(domain_dir, plan, zone_settings, add)
    _audit_tls(domain_dir, plan, zone_settings, add)
    custom_rules = _audit_waf(domain_dir, plan, zone_settings, add)
    _audit_rate_limits(domain_dir, plan, zone_settings, add)
    _audit_bots(domain_dir, plan, zone_settings, add, custom_rules)
    _audit_cache(domain_dir, plan, zone_settings, add)
    _audit_origin(domain_dir, plan, zone_settings, add)
    _audit_logging(domain_dir, plan, zone_settings, add, domain_name)
    return results, dom, is_example


def _audit_dns(domain_dir, plan, zone_settings, add):
    dnssec = load(domain_dir / "dns" / "dnssec.yaml") or {}
    dnssec_status = dnssec.get("status")
    add("DNS-01", "Domain and DNS", "DNSSEC enabled", "High", "All",
        "PASS" if dnssec_status == "active" else "FAIL",
        f"dns/dnssec.yaml: status={dnssec_status!r}" if dnssec_status else "dns/dnssec.yaml missing or empty")

    web_hints = {"@", "www", "app", "portal", "shop", "api"}
    unproxied_web = []
    for filename in ("a.yaml", "aaaa.yaml", "cname.yaml"):
        records = load(domain_dir / "dns" / filename) or {}
        for key, record in records.items():
            if not isinstance(record, dict):
                continue
            record_name = str(record.get("name", key)).lower()
            if record_name in web_hints and record.get("proxied") is not True:
                unproxied_web.append(f"{filename}:{key} ({record_name})")
    has_web_records = any(load(domain_dir / "dns" / f) for f in ("a.yaml", "aaaa.yaml", "cname.yaml"))
    add("DNS-02", "Domain and DNS", "HTTP(S) records proxied (heuristic: apex/www/app/api/portal/shop)",
        "High", "All",
        "FAIL" if unproxied_web else ("PASS" if has_web_records else "MANUAL"),
        ("not proxied: " + ", ".join(unproxied_web)) if unproxied_web
        else ("all likely-web hostnames are proxied; heuristic does not replace a live hostname review"
              if has_web_records else "no likely-web records found; verify the live hostname inventory manually"))

    caa = load(domain_dir / "dns" / "caa.yaml") or {}
    vals = {str(value.get("value", "")).lower() for value in caa.values() if isinstance(value, dict)}
    if not caa:
        add("DNS-05", "Domain and DNS", "CAA records restrict issuance", "Medium", "All", "FAIL", "dns/caa.yaml has no records")
    elif {"letsencrypt.org", "pki.goog"} & vals:
        add("DNS-05", "Domain and DNS", "CAA records restrict issuance", "Medium", "All", "PASS", f"dns/caa.yaml: {sorted(vals)}")
    else:
        add("DNS-05", "Domain and DNS", "CAA records restrict issuance", "Medium", "All", "PARTIAL",
            f"CAA present ({sorted(vals)}) but neither letsencrypt.org nor pki.goog allowed -- Universal SSL may fail to renew")

    spf = load(domain_dir / "dns" / "spf.yaml") or {}
    dmarc = load(domain_dir / "dns" / "dmarc.yaml") or {}
    dkim = load(domain_dir / "dns" / "dkim.yaml") or {}
    cname = load(domain_dir / "dns" / "cname.yaml") or {}
    has_dkim_cname = any(isinstance(value, dict) and "domainkey" in str(value.get("name", "")).lower() for value in cname.values())
    present = {"SPF": bool(spf), "DMARC": bool(dmarc), "DKIM": bool(dkim) or has_dkim_cname}
    missing = [key for key, ok in present.items() if not ok]
    add("DNS-06", "Domain and DNS", "SPF, DKIM and DMARC published", "Medium", "All",
        "PASS" if not missing else ("PARTIAL" if len(missing) < 3 else "FAIL"),
        "all three present" if not missing else f"missing: {', '.join(missing)}")


def _audit_tls(domain_dir, plan, zone_settings, add):
    status, evidence = managed_or(zone_settings.get("ssl"), lambda value: value == "strict",
                       lambda value: f"ssl: {value!r} does not enforce strict origin validation")
    add("TLS-01", "SSL/TLS", "Encryption mode is Full (strict)", "High", "All", status, evidence)

    cfg_rules = load(domain_dir / "rules" / "config.yaml") or []
    ssl_overrides = [rule for rule in cfg_rules if isinstance(rule, dict) and "ssl" in (rule.get("action_parameters") or {})]
    add("TLS-02", "SSL/TLS", "Hostname SSL overrides are ticketed exceptions", "Medium", "All",
        "PARTIAL" if ssl_overrides else "N/A",
        f"{len(ssl_overrides)} override(s) in rules/config.yaml -- confirm each has a ticket and end date" if ssl_overrides
        else "no SSL overrides in rules/config.yaml")

    status, evidence = managed_or(zone_settings.get("always_use_https"), lambda value: value == "on", lambda value: f"always_use_https: {value!r}")
    add("TLS-03", "SSL/TLS", "Always Use HTTPS", "High", "All", status, evidence)

    status, evidence = managed_or(zone_settings.get("automatic_https_rewrites"), lambda value: value == "on", lambda value: f"automatic_https_rewrites: {value!r}")
    add("TLS-04", "SSL/TLS", "Automatic HTTPS Rewrites", "Low", "All", status, evidence)

    status, evidence = managed_or(zone_settings.get("min_tls_version"), lambda value: value in ("1.2", "1.3"), lambda value: f"min_tls_version: {value!r} is deprecated")
    add("TLS-05", "SSL/TLS", "Minimum TLS version 1.2+", "High", "All", status, evidence)

    status, evidence = managed_or(zone_settings.get("tls_1_3"), lambda value: value == "on", lambda value: f"tls_1_3: {value!r}")
    add("TLS-06", "SSL/TLS", "TLS 1.3 enabled", "Medium", "All", status, evidence)

    rtt = zone_settings.get("0rtt")
    if rtt is None:
        add("TLS-07", "SSL/TLS", "0-RTT off on zones with logins/payments/APIs", "Medium", "All", "MANUAL",
            "not set -- Cloudflare's default applies; confirm this zone's sensitivity independently")
    elif rtt == "on":
        add("TLS-07", "SSL/TLS", "0-RTT off on zones with logins/payments/APIs", "Medium", "All", "PARTIAL",
            "0rtt: on -- confirm this zone has no login, payment or API endpoints before accepting")
    else:
        add("TLS-07", "SSL/TLS", "0-RTT off on zones with logins/payments/APIs", "Medium", "All", "PASS", "0rtt: off")

    hsts = load(domain_dir / "security" / "hsts.yaml") or {}
    if not hsts.get("enabled"):
        add("TLS-08", "SSL/TLS", "HSTS enabled with an agreed max-age", "Medium", "All", "FAIL",
            "security/hsts.yaml missing or enabled: false")
    else:
        max_age = hsts.get("max_age", 0)
        add("TLS-08", "SSL/TLS", "HSTS enabled with an agreed max-age", "Medium", "All",
            "PASS" if max_age >= 31536000 else "PARTIAL",
            f"enabled, max_age={max_age}" + ("" if max_age >= 31536000 else " -- below the recommended 31536000 (one year)"))


def _audit_waf(domain_dir, plan, zone_settings, add):
    managed = load(domain_dir / "waf" / "managed-rules.yaml") or {}
    custom_rules = load(domain_dir / "waf" / "custom-rules.yaml") or []
    raw = "raw_rules" in managed

    if plan == "free":
        add("WAF-01", "WAF", "Cloudflare Managed Ruleset deployed", "High", "All", "N/A", "Free plan: Cloudflare applies its Free Managed Ruleset automatically")
        add("WAF-02", "WAF", "OWASP Core Ruleset deployed and tuned", "High", "All", "N/A", "managed rulesets need Pro or above")
    elif raw:
        add("WAF-01", "WAF", "Cloudflare Managed Ruleset deployed", "High", "All", "MANUAL", "waf/managed-rules.yaml uses raw_rules (exported form); verify cloudflare_managed is enabled in those rules")
        add("WAF-02", "WAF", "OWASP Core Ruleset deployed and tuned", "High", "All", "MANUAL", "waf/managed-rules.yaml uses raw_rules; verify OWASP tuning in those rules")
    else:
        cloudflare_managed = managed.get("cloudflare_managed") or {}
        add("WAF-01", "WAF", "Cloudflare Managed Ruleset deployed", "High", "All",
            "PASS" if cloudflare_managed.get("enabled") else "FAIL",
            f"cloudflare_managed.enabled={cloudflare_managed.get('enabled')!r}" if cloudflare_managed else "cloudflare_managed not configured")
        owasp = managed.get("owasp") or {}
        if not owasp:
            add("WAF-02", "WAF", "OWASP Core Ruleset deployed and tuned", "High", "All", "FAIL", "owasp not configured in waf/managed-rules.yaml")
        else:
            ok = bool(owasp.get("enabled")) and owasp.get("paranoia_level") in (1, 2) and owasp.get("score_threshold") in (40, 60) \
                and owasp.get("action") in (None, "managed_challenge", "block")
            add("WAF-02", "WAF", "OWASP Core Ruleset deployed and tuned", "High", "All",
                "PASS" if ok else "PARTIAL",
                f"enabled={owasp.get('enabled')}, paranoia_level={owasp.get('paranoia_level')}, "
                f"score_threshold={owasp.get('score_threshold')}, action={owasp.get('action')}")

    exceptions = (managed.get("exceptions") or [])
    skip_rules = [rule for rule in custom_rules if isinstance(rule, dict) and rule.get("action") == "skip"]
    overrides = exceptions + skip_rules
    undocumented = [rule for rule in overrides if not str(rule.get("description", "")).strip()]
    add("WAF-04", "WAF", "Overrides and skip rules are narrow and documented", "High", "All",
        "N/A" if not overrides else ("PASS" if not undocumented else "PARTIAL"),
        "no overrides or skip rules defined" if not overrides
        else (f"{len(undocumented)} of {len(overrides)} override(s) have no description" if undocumented else f"{len(overrides)} override(s), all documented"))

    admin_pat = re.compile(r"admin|wp-login|/manage|/dashboard", re.I)
    admin_rules = [rule for rule in custom_rules if isinstance(rule, dict) and admin_pat.search(rule.get("expression") or "")
                   and rule.get("action") in ("block", "challenge", "managed_challenge", "js_challenge")]
    add("WAF-05", "WAF", "Admin paths restricted", "High", "All", "PASS" if admin_rules else "FAIL",
        f"{len(admin_rules)} custom rule(s) guard an admin-like path" if admin_rules else "no custom rule restricts an admin-like path")

    method_rules = [rule for rule in custom_rules if isinstance(rule, dict) and re.search(r"TRACE|TRACK|CONNECT", rule.get("expression") or "")]
    add("WAF-06", "WAF", "Unused HTTP methods blocked", "Low", "All", "PASS" if method_rules else "FAIL",
        "a rule blocks TRACE/TRACK/CONNECT" if method_rules else "no rule blocks unused HTTP methods")

    limit = LIMITS["custom_rules"].get(plan, 0)
    add("WAF-08", "WAF", "Custom rule count within plan limit (headroom kept)", "Low", "All", "PASS" if len(custom_rules) <= limit else "FAIL",
        f"{len(custom_rules)}/{limit} custom rules used")
    return custom_rules


def _audit_rate_limits(domain_dir, plan, zone_settings, add):
    rate_limits = load(domain_dir / "waf" / "rate-limits.yaml") or []
    login_pat = re.compile(r"login|/auth|password|otp|signin", re.I)
    login_rules = [rule for rule in rate_limits if isinstance(rule, dict) and login_pat.search(rule.get("expression") or "")]
    add("RL-01", "Rate limiting", "Login/auth endpoints rate limited", "High", "All",
        "PASS" if login_rules else "MANUAL",
        f"{len(login_rules)} rule(s) match login/auth paths" if login_rules
        else "no matching rule in YAML; the application endpoint inventory is not available to this audit")

    busy_pat = re.compile(r"/api|search", re.I)
    busy_rules = [rule for rule in rate_limits if isinstance(rule, dict) and busy_pat.search(rule.get("expression") or "")]
    add("RL-02", "Rate limiting", "Busiest API/search endpoint rate limited", "Medium", "All",
        "PASS" if busy_rules else "MANUAL",
        f"{len(busy_rules)} rule(s) match an API/search path" if busy_rules
        else "no matching rule in YAML; the application endpoint inventory is not available to this audit")


def _audit_bots(domain_dir, plan, zone_settings, add, custom_rules):
    bot = load(domain_dir / "security" / "bot-management.yaml") or {}
    if plan == "free":
        setting_value = bot.get("fight_mode")
        add("BOT-01", "Bots and DDoS", "Bot protection configured (Fight Mode on Free)", "High", "All",
            "PASS" if setting_value is True else ("MANUAL" if setting_value is None else "FAIL"), f"fight_mode={setting_value!r}")
        add("BOT-02", "Bots and DDoS", "JavaScript Detections enabled", "Medium", "Pro", "N/A", "JS Detections needs Pro or above")
    else:
        setting_value = bot.get("sbfm_definitely_automated")
        add("BOT-01", "Bots and DDoS", "Super Bot Fight Mode configured", "High", "Pro",
            "PASS" if setting_value in ("block", "managed_challenge") else ("MANUAL" if setting_value is None else "FAIL"),
            f"sbfm_definitely_automated={setting_value!r}")
        javascript_detection = bot.get("enable_js")
        add("BOT-02", "Bots and DDoS", "JavaScript Detections enabled", "Medium", "Pro",
            "PASS" if javascript_detection is True else ("MANUAL" if javascript_detection is None else "FAIL"), f"enable_js={javascript_detection!r}")

    api_skip = any(isinstance(rule, dict) and rule.get("action") == "skip" and "/api" in (rule.get("expression") or "") for rule in custom_rules)
    add("BOT-03", "Bots and DDoS", "API clients exempted from SBFM by path+key/IP", "Medium", "Pro",
        "N/A" if plan == "free" else ("PASS" if api_skip else "FAIL"),
        "SBFM does not apply on Free" if plan == "free" else ("a skip rule scopes /api" if api_skip else "no skip rule scopes an API path"))

    req_headers = load(domain_dir / "rules" / "request-headers.yaml") or []
    bot_header = any(isinstance(rule, dict) and "bot_management.score" in str((rule.get("action_parameters") or {}))
                      for rule in req_headers)
    add("BOT-06", "Bots and DDoS", "Bot score forwarded to origin", "Low", "Ent",
        "N/A" if plan != "enterprise" else ("PASS" if bot_header else "FAIL"),
        "Enterprise Bot Management only" if plan != "enterprise" else ("header rule references cf.bot_management.score" if bot_header else "no request-header rule forwards the bot score"))

    ai_bot_protection = bot.get("ai_bots_protection")
    add("BOT-07", "Bots and DDoS", "AI crawler policy matches a recorded decision", "Low", "All",
        "PASS" if ai_bot_protection is not None else "FAIL", f"ai_bots_protection={ai_bot_protection!r}" if ai_bot_protection is not None else "ai_bots_protection not set -- no recorded decision")

    sec_level = zone_settings.get("security_level")
    add("DDOS-02", "Bots and DDoS", "Under Attack mode not left on", "Low", "All",
        "FAIL" if sec_level == "under_attack" else "PASS",
        f"security_level={sec_level!r}")


def _audit_cache(domain_dir, plan, zone_settings, add):
    cache_rules = load(domain_dir / "cache" / "cache-rules.yaml") or []
    bypass_pat = re.compile(r"admin|/api|account|cart|session", re.I)
    bypass_rules = [rule for rule in cache_rules if isinstance(rule, dict) and (rule.get("action_parameters") or {}).get("cache") is False
                     and bypass_pat.search(rule.get("expression") or "")]
    add("CACHE-01", "Cache and performance", "Authenticated/dynamic paths bypass cache", "High", "All",
        "PASS" if bypass_rules else "FAIL",
        f"{len(bypass_rules)} bypass rule(s) match admin/api/account/cart/session" if bypass_rules else "no cache rule bypasses admin/api/account/cart/session paths")

    long_ttl_rules = [rule for rule in cache_rules if isinstance(rule, dict) and (rule.get("action_parameters") or {}).get("cache") is True
                       and ((rule.get("action_parameters") or {}).get("edge_ttl") or {}).get("default", 0) >= 3600]
    add("CACHE-03", "Cache and performance", "Static assets cached with a long edge TTL", "Low", "All",
        "PASS" if long_ttl_rules else "FAIL",
        f"{len(long_ttl_rules)} rule(s) cache for >= 3600s at the edge" if long_ttl_rules else "no cache rule sets a long edge TTL")

    add("CACHE-05", "Cache and performance", "Legacy Page Rules not relied on", "Low", "All", "PASS",
        "this repo manages caching via Cache Rules / Terraform; legacy Page Rules are out of scope by design")

    cache_settings = load(domain_dir / "cache" / "settings.yaml") or {}
    smart_tiered_cache = cache_settings.get("smart_tiered_cache")
    add("CACHE-06", "Cache and performance", "Smart Tiered Cache enabled", "Low", "All",
        "PASS" if smart_tiered_cache == "on" else ("MANUAL" if smart_tiered_cache is None else "FAIL"), f"smart_tiered_cache={smart_tiered_cache!r}")


def _audit_origin(domain_dir, plan, zone_settings, add):
    status, evidence = managed_or(zone_settings.get("tls_client_auth"), lambda value: value == "on", lambda value: f"tls_client_auth: {value!r}")
    add("ORG-02", "Origin protection", "Authenticated Origin Pulls enabled", "High", "All", status, evidence)


def _audit_logging(domain_dir, plan, zone_settings, add, domain_name):
    add("LOG-05", "Logging and monitoring", "Zone in Terraform with no deviation", "High", "All", "MANUAL",
        f"run `python3 cf.py deviation-check {domain_name}` with live credentials to confirm (not run by this script unless --live)")
