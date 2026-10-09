#!/usr/bin/env python3
"""
Static compliance audit: scores this repository's YAML against the controls
in docs/Cloudflare_Account_Audit.docx and docs/Cloudflare_Zone_Audit.docx,
then writes a Word report.

Only controls answerable from the files in this repo are graded (Pass /
Partial / Fail / N/A). Everything else in those two checklists -- identity
and SSO, live Cloudflare/GitHub API state, origin-side checks, Enterprise
features this repo has no module for, and pure process evidence -- is
listed separately in the report's appendix as "needs a live or manual
check", never guessed at.

    python3 scripts/compliance_audit.py                    audit everything -> .audit/audit-report.docx
    python3 scripts/compliance_audit.py example.com         audit one domain (+ account)
    python3 scripts/compliance_audit.py --out report.docx
    python3 scripts/compliance_audit.py --live              also run `cf.py deviation-check` per root (needs credentials)

Requires: pip install python-docx (not in requirements.txt -- only report
generation needs it, not everyday YAML editing).
"""
import argparse
import re
import subprocess
import sys
from datetime import date
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
from validation.common import LIMITS, PLANS  # noqa: E402

STATUSES = ["PASS", "PARTIAL", "FAIL", "N/A", "MANUAL"]
STATUS_RGB = {
    "PASS": (0x1E, 0x7E, 0x34),
    "PARTIAL": (0xB8, 0x86, 0x00),
    "FAIL": (0xC0, 0x1E, 0x1E),
    "N/A": (0x6B, 0x6B, 0x6B),
    "MANUAL": (0x44, 0x5A, 0x8C),
}


def load(path):
    p = Path(path)
    if not p.exists():
        return None
    try:
        return yaml.safe_load(p.read_text(encoding="utf-8"))
    except yaml.YAMLError:
        return None


def workflow_has_schedule(path):
    """Return true only when YAML contains an actual non-empty schedule."""
    data = load(path)
    trigger = data.get("on", data.get(True)) if isinstance(data, dict) else None
    schedule = trigger.get("schedule") if isinstance(trigger, dict) else None
    return isinstance(schedule, list) and bool(schedule)


class Result:
    def __init__(self, cid, area, control, severity, plan_scope, status, evidence):
        self.id, self.area, self.control = cid, area, control
        self.severity, self.plan_scope = severity, plan_scope
        self.status, self.evidence = status, evidence


def managed_or(value, present_ok, present_bad_msg):
    """Shared pattern: an optional zone.yaml-style setting that this repo may
    legitimately leave unset (Cloudflare's default then applies, unmanaged)."""
    if value is None:
        return "MANUAL", "not set in settings/zone.yaml -- this repo leaves it to Cloudflare's default; verify independently"
    if present_ok(value):
        return "PASS", f"settings/zone.yaml: {value!r}"
    return "FAIL", present_bad_msg(value)


# ===========================================================================
# Per-domain controls
# ===========================================================================
def audit_domain(d: Path):
    name = d.name
    dom = load(d / "domain.yaml") or {}
    plan = dom.get("plan", "free")
    is_example = bool(dom.get("example"))
    z = load(d / "settings" / "zone.yaml") or {}
    results = []

    def add(cid, area, control, sev, scope, status, evidence):
        results.append(Result(cid, area, control, sev, scope, status, evidence))

    # ---- DNS --------------------------------------------------------------
    dnssec = load(d / "dns" / "dnssec.yaml") or {}
    st = dnssec.get("status")
    add("DNS-01", "Domain and DNS", "DNSSEC enabled", "High", "All",
        "PASS" if st == "active" else "FAIL",
        f"dns/dnssec.yaml: status={st!r}" if st else "dns/dnssec.yaml missing or empty")

    web_hints = {"@", "www", "app", "portal", "shop", "api"}
    unproxied_web = []
    for fname in ("a.yaml", "aaaa.yaml", "cname.yaml"):
        recs = load(d / "dns" / fname) or {}
        for key, r in recs.items():
            if not isinstance(r, dict):
                continue
            rname = str(r.get("name", key)).lower()
            if rname in web_hints and r.get("proxied") is not True:
                unproxied_web.append(f"{fname}:{key} ({rname})")
    has_web_records = any(load(d / "dns" / f) for f in ("a.yaml", "aaaa.yaml", "cname.yaml"))
    add("DNS-02", "Domain and DNS", "HTTP(S) records proxied (heuristic: apex/www/app/api/portal/shop)",
        "High", "All",
        "FAIL" if unproxied_web else ("PASS" if has_web_records else "MANUAL"),
        ("not proxied: " + ", ".join(unproxied_web)) if unproxied_web
        else ("all likely-web hostnames are proxied; heuristic does not replace a live hostname review"
              if has_web_records else "no likely-web records found; verify the live hostname inventory manually"))

    caa = load(d / "dns" / "caa.yaml") or {}
    vals = {str(v.get("value", "")).lower() for v in caa.values() if isinstance(v, dict)}
    if not caa:
        add("DNS-05", "Domain and DNS", "CAA records restrict issuance", "Medium", "All", "FAIL", "dns/caa.yaml has no records")
    elif {"letsencrypt.org", "pki.goog"} & vals:
        add("DNS-05", "Domain and DNS", "CAA records restrict issuance", "Medium", "All", "PASS", f"dns/caa.yaml: {sorted(vals)}")
    else:
        add("DNS-05", "Domain and DNS", "CAA records restrict issuance", "Medium", "All", "PARTIAL",
            f"CAA present ({sorted(vals)}) but neither letsencrypt.org nor pki.goog allowed -- Universal SSL may fail to renew")

    spf = load(d / "dns" / "spf.yaml") or {}
    dmarc = load(d / "dns" / "dmarc.yaml") or {}
    dkim = load(d / "dns" / "dkim.yaml") or {}
    cname = load(d / "dns" / "cname.yaml") or {}
    has_dkim_cname = any(isinstance(v, dict) and "domainkey" in str(v.get("name", "")).lower() for v in cname.values())
    present = {"SPF": bool(spf), "DMARC": bool(dmarc), "DKIM": bool(dkim) or has_dkim_cname}
    missing = [k for k, ok in present.items() if not ok]
    add("DNS-06", "Domain and DNS", "SPF, DKIM and DMARC published", "Medium", "All",
        "PASS" if not missing else ("PARTIAL" if len(missing) < 3 else "FAIL"),
        "all three present" if not missing else f"missing: {', '.join(missing)}")

    # ---- SSL/TLS ------------------------------------------------------------
    s, e = managed_or(z.get("ssl"), lambda v: v in ("strict", "full"), lambda v: f"ssl: {v!r} sends traffic to the origin unencrypted")
    add("TLS-01", "SSL/TLS", "Encryption mode is Full strict (or origin_pull)", "High", "All", s, e)

    cfg_rules = load(d / "rules" / "config.yaml") or []
    ssl_overrides = [r for r in cfg_rules if isinstance(r, dict) and "ssl" in (r.get("action_parameters") or {})]
    add("TLS-02", "SSL/TLS", "Hostname SSL overrides are ticketed exceptions", "Medium", "All",
        "PARTIAL" if ssl_overrides else "N/A",
        f"{len(ssl_overrides)} override(s) in rules/config.yaml -- confirm each has a ticket and end date" if ssl_overrides
        else "no SSL overrides in rules/config.yaml")

    s, e = managed_or(z.get("always_use_https"), lambda v: v == "on", lambda v: f"always_use_https: {v!r}")
    add("TLS-03", "SSL/TLS", "Always Use HTTPS", "High", "All", s, e)

    s, e = managed_or(z.get("automatic_https_rewrites"), lambda v: v == "on", lambda v: f"automatic_https_rewrites: {v!r}")
    add("TLS-04", "SSL/TLS", "Automatic HTTPS Rewrites", "Low", "All", s, e)

    s, e = managed_or(z.get("min_tls_version"), lambda v: v in ("1.2", "1.3"), lambda v: f"min_tls_version: {v!r} is deprecated")
    add("TLS-05", "SSL/TLS", "Minimum TLS version 1.2+", "High", "All", s, e)

    s, e = managed_or(z.get("tls_1_3"), lambda v: v == "on", lambda v: f"tls_1_3: {v!r}")
    add("TLS-06", "SSL/TLS", "TLS 1.3 enabled", "Medium", "All", s, e)

    rtt = z.get("0rtt")
    if rtt is None:
        add("TLS-07", "SSL/TLS", "0-RTT off on zones with logins/payments/APIs", "Medium", "All", "MANUAL",
            "not set -- Cloudflare's default applies; confirm this zone's sensitivity independently")
    elif rtt == "on":
        add("TLS-07", "SSL/TLS", "0-RTT off on zones with logins/payments/APIs", "Medium", "All", "PARTIAL",
            "0rtt: on -- confirm this zone has no login, payment or API endpoints before accepting")
    else:
        add("TLS-07", "SSL/TLS", "0-RTT off on zones with logins/payments/APIs", "Medium", "All", "PASS", "0rtt: off")

    hsts = load(d / "security" / "hsts.yaml") or {}
    if not hsts.get("enabled"):
        add("TLS-08", "SSL/TLS", "HSTS enabled with an agreed max-age", "Medium", "All", "FAIL",
            "security/hsts.yaml missing or enabled: false")
    else:
        ma = hsts.get("max_age", 0)
        add("TLS-08", "SSL/TLS", "HSTS enabled with an agreed max-age", "Medium", "All",
            "PASS" if ma >= 31536000 else "PARTIAL",
            f"enabled, max_age={ma}" + ("" if ma >= 31536000 else " -- below the recommended 31536000 (one year)"))

    # ---- WAF ----------------------------------------------------------------
    managed = load(d / "waf" / "managed-rules.yaml") or {}
    custom = load(d / "waf" / "custom-rules.yaml") or []
    raw = "raw_rules" in managed

    if plan == "free":
        add("WAF-01", "WAF", "Cloudflare Managed Ruleset deployed", "High", "All", "N/A", "Free plan: Cloudflare applies its Free Managed Ruleset automatically")
        add("WAF-02", "WAF", "OWASP Core Ruleset deployed and tuned", "High", "All", "N/A", "managed rulesets need Pro or above")
    elif raw:
        add("WAF-01", "WAF", "Cloudflare Managed Ruleset deployed", "High", "All", "MANUAL", "waf/managed-rules.yaml uses raw_rules (exported form); verify cloudflare_managed is enabled in those rules")
        add("WAF-02", "WAF", "OWASP Core Ruleset deployed and tuned", "High", "All", "MANUAL", "waf/managed-rules.yaml uses raw_rules; verify OWASP tuning in those rules")
    else:
        cm = managed.get("cloudflare_managed") or {}
        add("WAF-01", "WAF", "Cloudflare Managed Ruleset deployed", "High", "All",
            "PASS" if cm.get("enabled") else "FAIL",
            f"cloudflare_managed.enabled={cm.get('enabled')!r}" if cm else "cloudflare_managed not configured")
        ow = managed.get("owasp") or {}
        if not ow:
            add("WAF-02", "WAF", "OWASP Core Ruleset deployed and tuned", "High", "All", "FAIL", "owasp not configured in waf/managed-rules.yaml")
        else:
            ok = bool(ow.get("enabled")) and ow.get("paranoia_level") in (1, 2) and ow.get("score_threshold") in (40, 60) \
                and ow.get("action") in (None, "managed_challenge", "block")
            add("WAF-02", "WAF", "OWASP Core Ruleset deployed and tuned", "High", "All",
                "PASS" if ok else "PARTIAL",
                f"enabled={ow.get('enabled')}, paranoia_level={ow.get('paranoia_level')}, "
                f"score_threshold={ow.get('score_threshold')}, action={ow.get('action')}")

    exceptions = (managed.get("exceptions") or [])
    skip_rules = [r for r in custom if isinstance(r, dict) and r.get("action") == "skip"]
    overrides = exceptions + skip_rules
    undocumented = [r for r in overrides if not str(r.get("description", "")).strip()]
    add("WAF-04", "WAF", "Overrides and skip rules are narrow and documented", "High", "All",
        "N/A" if not overrides else ("PASS" if not undocumented else "PARTIAL"),
        "no overrides or skip rules defined" if not overrides
        else (f"{len(undocumented)} of {len(overrides)} override(s) have no description" if undocumented else f"{len(overrides)} override(s), all documented"))

    admin_pat = re.compile(r"admin|wp-login|/manage|/dashboard", re.I)
    admin_rules = [r for r in custom if isinstance(r, dict) and admin_pat.search(r.get("expression") or "")
                   and r.get("action") in ("block", "challenge", "managed_challenge", "js_challenge")]
    add("WAF-05", "WAF", "Admin paths restricted", "High", "All", "PASS" if admin_rules else "FAIL",
        f"{len(admin_rules)} custom rule(s) guard an admin-like path" if admin_rules else "no custom rule restricts an admin-like path")

    method_rules = [r for r in custom if isinstance(r, dict) and re.search(r"TRACE|TRACK|CONNECT", r.get("expression") or "")]
    add("WAF-06", "WAF", "Unused HTTP methods blocked", "Low", "All", "PASS" if method_rules else "FAIL",
        "a rule blocks TRACE/TRACK/CONNECT" if method_rules else "no rule blocks unused HTTP methods")

    limit = LIMITS["custom_rules"].get(plan, 0)
    add("WAF-08", "WAF", "Custom rule count within plan limit (headroom kept)", "Low", "All", "PASS" if len(custom) <= limit else "FAIL",
        f"{len(custom)}/{limit} custom rules used")

    # ---- Rate limiting --------------------------------------------------------
    rl = load(d / "waf" / "rate-limits.yaml") or []
    login_pat = re.compile(r"login|/auth|password|otp|signin", re.I)
    login_rules = [r for r in rl if isinstance(r, dict) and login_pat.search(r.get("expression") or "")]
    add("RL-01", "Rate limiting", "Login/auth endpoints rate limited", "High", "All",
        "PASS" if login_rules else "MANUAL",
        f"{len(login_rules)} rule(s) match login/auth paths" if login_rules
        else "no matching rule in YAML; the application endpoint inventory is not available to this audit")

    busy_pat = re.compile(r"/api|search", re.I)
    busy_rules = [r for r in rl if isinstance(r, dict) and busy_pat.search(r.get("expression") or "")]
    add("RL-02", "Rate limiting", "Busiest API/search endpoint rate limited", "Medium", "All",
        "PASS" if busy_rules else "MANUAL",
        f"{len(busy_rules)} rule(s) match an API/search path" if busy_rules
        else "no matching rule in YAML; the application endpoint inventory is not available to this audit")

    # ---- Bots and DDoS ----------------------------------------------------------
    bot = load(d / "security" / "bot-management.yaml") or {}
    if plan == "free":
        val = bot.get("fight_mode")
        add("BOT-01", "Bots and DDoS", "Bot protection configured (Fight Mode on Free)", "High", "All",
            "PASS" if val is True else ("MANUAL" if val is None else "FAIL"), f"fight_mode={val!r}")
        add("BOT-02", "Bots and DDoS", "JavaScript Detections enabled", "Medium", "Pro", "N/A", "JS Detections needs Pro or above")
    else:
        val = bot.get("sbfm_definitely_automated")
        add("BOT-01", "Bots and DDoS", "Super Bot Fight Mode configured", "High", "Pro",
            "PASS" if val in ("block", "managed_challenge") else ("MANUAL" if val is None else "FAIL"),
            f"sbfm_definitely_automated={val!r}")
        js = bot.get("enable_js")
        add("BOT-02", "Bots and DDoS", "JavaScript Detections enabled", "Medium", "Pro",
            "PASS" if js is True else ("MANUAL" if js is None else "FAIL"), f"enable_js={js!r}")

    api_skip = any(isinstance(r, dict) and r.get("action") == "skip" and "/api" in (r.get("expression") or "") for r in custom)
    add("BOT-03", "Bots and DDoS", "API clients exempted from SBFM by path+key/IP", "Medium", "Pro",
        "N/A" if plan == "free" else ("PASS" if api_skip else "FAIL"),
        "SBFM does not apply on Free" if plan == "free" else ("a skip rule scopes /api" if api_skip else "no skip rule scopes an API path"))

    req_headers = load(d / "rules" / "request-headers.yaml") or []
    bot_header = any(isinstance(r, dict) and "bot_management.score" in str((r.get("action_parameters") or {}))
                      for r in req_headers)
    add("BOT-06", "Bots and DDoS", "Bot score forwarded to origin", "Low", "Ent",
        "N/A" if plan != "enterprise" else ("PASS" if bot_header else "FAIL"),
        "Enterprise Bot Management only" if plan != "enterprise" else ("header rule references cf.bot_management.score" if bot_header else "no request-header rule forwards the bot score"))

    ai = bot.get("ai_bots_protection")
    add("BOT-07", "Bots and DDoS", "AI crawler policy matches a recorded decision", "Low", "All",
        "PASS" if ai is not None else "FAIL", f"ai_bots_protection={ai!r}" if ai is not None else "ai_bots_protection not set -- no recorded decision")

    sec_level = z.get("security_level")
    add("DDOS-02", "Bots and DDoS", "Under Attack mode not left on", "Low", "All",
        "FAIL" if sec_level == "under_attack" else "PASS",
        f"security_level={sec_level!r}")

    # ---- Cache --------------------------------------------------------------
    cr = load(d / "cache" / "cache-rules.yaml") or []
    bypass_pat = re.compile(r"admin|/api|account|cart|session", re.I)
    bypass_rules = [r for r in cr if isinstance(r, dict) and (r.get("action_parameters") or {}).get("cache") is False
                     and bypass_pat.search(r.get("expression") or "")]
    add("CACHE-01", "Cache and performance", "Authenticated/dynamic paths bypass cache", "High", "All",
        "PASS" if bypass_rules else "FAIL",
        f"{len(bypass_rules)} bypass rule(s) match admin/api/account/cart/session" if bypass_rules else "no cache rule bypasses admin/api/account/cart/session paths")

    long_ttl_rules = [r for r in cr if isinstance(r, dict) and (r.get("action_parameters") or {}).get("cache") is True
                       and ((r.get("action_parameters") or {}).get("edge_ttl") or {}).get("default", 0) >= 3600]
    add("CACHE-03", "Cache and performance", "Static assets cached with a long edge TTL", "Low", "All",
        "PASS" if long_ttl_rules else "FAIL",
        f"{len(long_ttl_rules)} rule(s) cache for >= 3600s at the edge" if long_ttl_rules else "no cache rule sets a long edge TTL")

    add("CACHE-05", "Cache and performance", "Legacy Page Rules not relied on", "Low", "All", "PASS",
        "this repo manages caching via Cache Rules / Terraform; legacy Page Rules are out of scope by design")

    cs = load(d / "cache" / "settings.yaml") or {}
    stc = cs.get("smart_tiered_cache")
    add("CACHE-06", "Cache and performance", "Smart Tiered Cache enabled", "Low", "All",
        "PASS" if stc == "on" else ("MANUAL" if stc is None else "FAIL"), f"smart_tiered_cache={stc!r}")

    # ---- Origin protection ----------------------------------------------------
    s, e = managed_or(z.get("tls_client_auth"), lambda v: v == "on", lambda v: f"tls_client_auth: {v!r}")
    add("ORG-02", "Origin protection", "Authenticated Origin Pulls enabled", "High", "All", s, e)

    # ---- Logging / IaC hygiene -----------------------------------------------
    add("LOG-05", "Logging and monitoring", "Zone in Terraform with no deviation", "High", "All", "MANUAL",
        f"run `python3 cf.py deviation-check {name}` with live credentials to confirm (not run by this script unless --live)")

    return results, dom, is_example


# ===========================================================================
# Account-level controls
# ===========================================================================
def audit_account(a: Path, domain_owners):
    results = []

    def add(cid, area, control, sev, scope, status, evidence):
        results.append(Result(cid, area, control, sev, scope, status, evidence))

    lists_dir = a / "lists"
    undocumented_lists = []
    total_lists = 0
    for kind in ("ip", "asn", "hostname", "redirect"):
        data = load(lists_dir / f"{kind}.yaml") or {}
        for lname, l in data.items():
            total_lists += 1
            if not isinstance(l, dict) or not str(l.get("description", "")).strip():
                undocumented_lists.append(f"{kind}.yaml:{lname}")
    add("ACC-20", "Governance and change management", "Shared IP/ASN/hostname/redirect lists have owners/descriptions", "Low", "All",
        "N/A" if total_lists == 0 else ("PASS" if not undocumented_lists else "PARTIAL"),
        "no lists defined" if total_lists == 0
        else (f"{len(undocumented_lists)} list(s) missing a description: {', '.join(undocumented_lists)}" if undocumented_lists
              else f"all {total_lists} list(s) have descriptions (stale-entry review is still manual)"))

    add("ACC-22", "Governance and change management", "Configuration managed as code", "High", "All", "PARTIAL",
        "repository contains Terraform/YAML for the declared roots; completeness against live Cloudflare objects needs a live inventory comparison")

    custom = load(a / "waf" / "custom-rules.yaml") or []
    add("ACC-18", "Governance and change management", "Account-level custom rulesets", "Medium", "Ent",
        "PASS" if custom else "N/A",
        f"{len(custom)} rule(s) in account/waf/custom-rules.yaml" if custom
        else "account/waf/custom-rules.yaml is empty -- fine if no account-wide custom rules are needed")

    rate_limits = load(a / "waf" / "rate-limits.yaml") or []
    add("ACC-19", "Governance and change management", "Account-level rate limiting rulesets", "Low", "Ent",
        "PASS" if rate_limits else "N/A",
        f"{len(rate_limits)} rule(s) in account/waf/rate-limits.yaml" if rate_limits
        else "account/waf/rate-limits.yaml is empty -- fine if no account-wide rate limits are needed")

    managed = load(a / "waf" / "managed-rules.yaml") or {}
    managed_active = bool(managed.get("raw_rules")) or bool((managed.get("cloudflare_managed") or {}).get("enabled")) \
        or bool((managed.get("owasp") or {}).get("enabled"))
    add("ACC-17", "Governance and change management", "Account-level managed rulesets", "High", "Ent",
        "PASS" if managed_active else "N/A",
        "account/waf/managed-rules.yaml deploys a managed ruleset account-wide" if managed_active
        else "account/waf/managed-rules.yaml is empty -- baseline managed-ruleset protection relies on each zone's own waf/managed-rules.yaml instead")

    logpush = load(a / "settings" / "logpush.yaml") or {}
    audit_log_job = any(j.get("dataset") == "audit_logs" for j in logpush.values() if isinstance(j, dict))
    add("ACC-21", "Governance and change management", "Logpush for account datasets", "High", "Ent",
        "PASS" if audit_log_job else ("PARTIAL" if logpush else "FAIL"),
        "an audit_logs Logpush job is configured" if audit_log_job
        else (f"{len(logpush)} Logpush job(s) configured, but none for the audit_logs dataset" if logpush
              else "account/settings/logpush.yaml has no jobs configured"))

    notif = load(a / "settings" / "notifications.yaml") or {}
    enabled_policies = [p for p in notif.values() if isinstance(p, dict) and p.get("enabled", True)]
    add("ACC-14", "Governance and change management", "Alerts on sensitive account events", "Medium", "All",
        "PASS" if enabled_policies else "FAIL",
        f"{len(enabled_policies)} enabled notification polic(ies) in account/settings/notifications.yaml" if enabled_policies
        else "no enabled policies in account/settings/notifications.yaml")
    ddos_policies = [p for p in enabled_policies if "dos_attack" in str(p.get("alert_type", "")) or "ddos" in str(p.get("alert_type", "")).lower()]
    add("ACC-15", "Governance and change management", "DDoS and security notifications", "High", "All",
        "PASS" if ddos_policies else "FAIL",
        f"{len(ddos_policies)} DDoS-related polic(ies) found" if ddos_policies
        else "no policy in account/settings/notifications.yaml has a DDoS-related alert_type")

    codeowners = (ROOT / ".github" / "CODEOWNERS").exists()
    add("ACC-23", "Governance and change management", "Peer review enforced for changes", "High", "All",
        "PARTIAL" if codeowners else "FAIL",
        ".github/CODEOWNERS present -- actual required-reviewer/branch-protection settings live in GitHub and are not visible from repo files" if codeowners
        else "no .github/CODEOWNERS; review routing cannot be enforced by code owners alone")

    backend_example = (ROOT / "backend.hcl.example")
    text = backend_example.read_text(encoding="utf-8") if backend_example.exists() else ""
    has_lock = bool(re.search(r"use_lockfile\s*=\s*true", text))
    add("ACC-24", "Governance and change management", "State backend locking configured", "High", "All",
        "PASS" if has_lock else "FAIL",
        "backend.hcl.example sets use_lockfile = true (locking enabled)" if has_lock
        else "backend.hcl.example does not set use_lockfile = true"
        + " -- bucket encryption and access restrictions live in R2 and are not visible from this repo")

    deviation_wf = ROOT / ".github" / "workflows" / "deviation-detection.yml"
    has_schedule = workflow_has_schedule(deviation_wf)
    add("ACC-25", "Governance and change management", "Scheduled deviation detection configured", "Medium", "All",
        "PASS" if has_schedule else "FAIL",
        ".github/workflows/deviation-detection.yml contains a non-empty YAML on.schedule" if has_schedule
        else "no non-empty YAML on.schedule found in the deviation-detection workflow")

    bad_owners = [n for n, o in domain_owners if not o or o == "change-me"]
    add("ACC-27", "Governance and change management", "Zone inventory complete (owners set)", "Medium", "All",
        "N/A" if not domain_owners else ("PASS" if not bad_owners else "FAIL"),
        "no domain folders found" if not domain_owners
        else (f"no real owner set: {', '.join(bad_owners)}" if bad_owners
              else f"all {len(domain_owners)} domain folder(s) have an owner")
        + " -- this only checks folders already in the repo; comparing against Cloudflare's live zone list needs the API and is not done here")

    return results


# ===========================================================================
# Controls this script does not attempt to grade (appendix)
# ===========================================================================
NOT_EVALUATED = [
    ("ACC-01", "SSO enforced for all dashboard users", "Account", "Identity/SSO provider -- needs a live Cloudflare members check"),
    ("ACC-02", "MFA enforced for accounts outside SSO", "Account", "Needs a live Cloudflare members check"),
    ("ACC-03", "Break-glass Super Administrator accounts", "Account", "Needs a live Cloudflare members check"),
    ("ACC-04", "Least privilege roles", "Account", "Needs a live Cloudflare members/API check"),
    ("ACC-05", "Leavers removed", "Account", "Needs HR records plus a live members comparison"),
    ("ACC-06", "Membership review cadence", "Account", "Process evidence (review tickets), not config"),
    ("ACC-07", "Global API Key not used in automation", "Account", "Needs a live audit-log and pipeline-secret review"),
    ("ACC-08", "Tokens scoped to least privilege", "Account", "Needs a live Cloudflare token API check"),
    ("ACC-09", "One token per pipeline or tool", "Account", "Needs a token inventory against live systems"),
    ("ACC-10", "Token expiry and IP filtering", "Account", "Needs live token details"),
    ("ACC-11", "Tokens stored in secrets manager and rotated", "Account", "Secrets-manager rotation records, not in this repo"),
    ("ACC-12", "Read and write tokens separated", "Account", "CI secret values are not readable by this script"),
    ("ACC-13", "Audit log reviewed", "Account", "Needs a live Cloudflare audit log and review evidence"),
    ("ACC-16", "Notification recipients current", "Account", "Needs live notification destinations"),
    ("ACC-26", "Manual dashboard changes controlled", "Account", "Needs a live audit log compared to change tickets"),
    ("DNS-03", "No origin exposure via grey records", "Zone", "Needs live DNS resolution plus origin IP comparison"),
    ("DNS-04", "No dangling records", "Zone", "Needs live resolution and cloud-resource checks"),
    ("DNS-07", "Registrar lock and auto-renew", "Zone", "Registrar portal, outside Cloudflare and this repo"),
    ("TLS-09", "Edge certificate coverage and expiry", "Zone", "Needs the live Cloudflare certificate API"),
    ("TLS-10", "Origin certificate valid", "Zone", "Needs an origin TLS probe (openssl s_client)"),
    ("WAF-03", "Exposed Credentials Check", "Zone", "No field for this managed check in this repo's schema"),
    ("WAF-07", "Custom rules documented with owner and ticket", "Zone", "ref/description exist; no owner/ticket field is graded"),
    ("WAF-09", "WAF attack score rule", "Zone", "Enterprise-only; no field in this repo's schema"),
    ("RL-03", "Thresholds evidenced by traffic data", "Zone", "Needs traffic analytics, not present in YAML"),
    ("RL-04", "Verified bots excluded on public pages", "Zone", "Expression intent can't be inferred reliably"),
    ("RL-05", "Counting by session/key on shared NAT", "Zone", "Enterprise-only; no field in this repo's schema"),
    ("RL-06", "Response-based counting for credential stuffing", "Zone", "Enterprise-only; no field in this repo's schema"),
    ("BOT-04", "Bot Management rules by path", "Zone", "Enterprise-only; no field in this repo's schema"),
    ("BOT-05", "Automation exempted by fingerprint/mTLS", "Zone", "Enterprise-only; no field in this repo's schema"),
    ("BOT-08", "Turnstile on public forms", "Zone", "No Turnstile widget module in this repo"),
    ("DDOS-01", "HTTP DDoS managed ruleset tuning", "Zone", "No field exposes DDoS L7 ruleset overrides"),
    ("DDOS-03", "Attack runbook", "Zone", "Process document, not config"),
    ("CACHE-02", "Cache Deception Armor", "Zone", "No field for this setting in this repo's schema"),
    ("CACHE-04", "No Set-Cookie on cached responses", "Zone", "Needs a live curl probe against production"),
    ("CACHE-07", "Purge token scoped", "Zone", "Needs live token permissions"),
    ("CACHE-08", "Cache hit ratio reviewed", "Zone", "Needs live analytics, not in YAML"),
    ("ORG-01", "Origin accepts Cloudflare IPs only", "Zone", "Origin-side firewall, outside Cloudflare config"),
    ("ORG-03", "Cloudflare Tunnel where possible", "Zone", "No Zero Trust/Tunnel module in this repo"),
    ("ORG-04", "Origin IP not leaked", "Zone", "Needs external OSINT (historical DNS/cert transparency)"),
    ("ORG-05", "Real client IP restored safely", "Zone", "Origin web-server config, outside Cloudflare"),
    ("LOG-01", "Logpush to SIEM", "Zone", "No Logpush module in this repo"),
    ("LOG-02", "Security Events reviewed", "Zone", "Process evidence, not config"),
    ("LOG-03", "Zone notifications", "Zone", "No notification-policy module in this repo"),
    ("LOG-04", "KPIs tracked", "Zone", "External dashboards/process, not config"),
]


# ===========================================================================
# Live deviation check (optional)
# ===========================================================================
def run_live_deviation_check(root_name):
    proc = subprocess.run([sys.executable, str(ROOT / "cf.py"), "deviation-check", root_name, "--deviation-exit"],
                           cwd=ROOT, capture_output=True, text=True)
    if proc.returncode == 0:
        return "PASS", "`cf.py deviation-check` found no changes outside Git"
    if proc.returncode == 2:
        return "FAIL", "`cf.py deviation-check` found changes outside Git -- see deviation.log"
    return "MANUAL", "`cf.py deviation-check` could not run (likely missing credentials); run it manually"


# ===========================================================================
# Report
# ===========================================================================
def build_report(account_results, domain_sections_full, out_path):
    from docx import Document
    from docx.enum.table import WD_TABLE_ALIGNMENT
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.oxml.ns import qn
    from docx.shared import Pt, RGBColor, Inches

    doc = Document()
    doc.styles["Normal"].font.size = Pt(10)

    title = doc.add_heading("Cloudflare Configuration Audit", level=0)
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    sub = doc.add_paragraph()
    sub.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = sub.add_run(f"Automated report -- generated {date.today().isoformat()} from the repository's YAML configuration")
    run.italic = True

    doc.add_paragraph()
    p = doc.add_paragraph()
    p.add_run("Scope and limitations: ").bold = True
    p.add_run(
        "This report grades every control from the Cloudflare Account Audit and Cloudflare Zone Audit "
        "checklists that can be answered by reading the YAML in account/ and domains/*. It is generated "
        "by scripts/compliance_audit.py and is not a substitute for the live Cloudflare/GitHub checks, "
        "identity reviews and sign-off process in the source checklists. Controls this script cannot "
        "evaluate are listed in the appendix with the reason, not guessed at."
    )

    # ---- executive summary ----
    doc.add_heading("Executive summary", level=1)
    all_sections = [("Account", account_results)] + [(n, r) for n, r, _ in domain_sections_full]
    summary_table = doc.add_table(rows=1, cols=2 + len(STATUSES))
    summary_table.style = "Light Grid Accent 1"
    hdr = summary_table.rows[0].cells
    hdr[0].text = "Root"
    for i, s in enumerate(STATUSES):
        hdr[1 + i].text = s
    hdr[-1].text = "Total"
    for root_name, results in all_sections:
        row = summary_table.add_row().cells
        row[0].text = root_name
        counts = {s: sum(1 for r in results if r.status == s) for s in STATUSES}
        for i, s in enumerate(STATUSES):
            row[1 + i].text = str(counts[s])
        row[-1].text = str(len(results))

    doc.add_paragraph()
    doc.add_paragraph(
        f"{len(NOT_EVALUATED)} additional control(s) across both source checklists need a live Cloudflare/"
        "GitHub check, external verification, or a Terraform module this repo does not have -- see the "
        "appendix."
    )

    # ---- per-root detail ----
    def add_detail_table(results):
        table = doc.add_table(rows=1, cols=6)
        table.style = "Light Grid Accent 1"
        table.alignment = WD_TABLE_ALIGNMENT.CENTER
        widths = [0.6, 1.3, 2.6, 0.7, 0.8, 3.0]
        for cell, w in zip(table.rows[0].cells, widths):
            cell.width = Inches(w)
        for i, h in enumerate(["ID", "Area", "Control", "Severity", "Result", "Evidence"]):
            table.rows[0].cells[i].text = h
            table.rows[0].cells[i].paragraphs[0].runs[0].bold = True
        for r in results:
            cells = table.add_row().cells
            cells[0].text = r.id
            cells[1].text = r.area
            cells[2].text = r.control
            cells[3].text = r.severity
            run = cells[4].paragraphs[0].add_run(r.status)
            run.bold = True
            run.font.color.rgb = RGBColor(*STATUS_RGB[r.status])
            cells[5].text = r.evidence

    doc.add_heading("Account", level=1)
    add_detail_table(account_results)

    for root_name, results, is_example in domain_sections_full:
        h = doc.add_heading(root_name, level=1)
        if is_example:
            run = h.add_run("  (EXAMPLE DATA -- fake IDs, not a real zone)")
            run.italic = True
            run.font.size = Pt(11)
            run.font.color.rgb = RGBColor(0x80, 0x80, 0x80)
        add_detail_table(results)

    # ---- appendix ----
    doc.add_heading("Appendix: controls not evaluated by this script", level=1)
    doc.add_paragraph(
        "These come from the same two source checklists but need a live Cloudflare/GitHub API check, "
        "external verification (registrar, origin server, OSINT), process evidence, or a Terraform "
        "resource this repository does not currently model."
    )
    app_table = doc.add_table(rows=1, cols=4)
    app_table.style = "Light Grid Accent 1"
    for i, h in enumerate(["ID", "Control", "Checklist", "Why this script can't grade it"]):
        app_table.rows[0].cells[i].text = h
        app_table.rows[0].cells[i].paragraphs[0].runs[0].bold = True
    for cid, control, checklist, reason in NOT_EVALUATED:
        cells = app_table.add_row().cells
        cells[0].text = cid
        cells[1].text = control
        cells[2].text = checklist
        cells[3].text = reason

    # python-docx's default template omits w:percent on w:zoom, which fails
    # strict OOXML validation (Word itself tolerates it, but don't rely on that).
    zoom = doc.settings.element.find(qn("w:zoom"))
    if zoom is not None and zoom.get(qn("w:percent")) is None:
        zoom.set(qn("w:percent"), "100")

    # python-docx stamps author="python-docx" / comments="generated by
    # python-docx" by default; clear that machine-generated fingerprint.
    cp = doc.core_properties
    cp.author = ""
    cp.last_modified_by = ""
    cp.comments = ""

    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    doc.save(out_path)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("domains", nargs="*", help="domain folders to audit (default: all under domains/)")
    ap.add_argument("--out", default=str(ROOT / ".audit" / "audit-report.docx"),
                    help="default: .audit/audit-report.docx (gitignored)")
    ap.add_argument("--live", action="store_true", help="also run `cf.py deviation-check` per root (needs credentials)")
    a = ap.parse_args()

    try:
        import docx  # noqa: F401
    except ImportError:
        sys.exit("python-docx is required for the report: pip install python-docx")

    names = a.domains or sorted(p.name for p in (ROOT / "domains").iterdir() if p.is_dir() and not p.name.startswith("_"))

    domain_owners = []
    domain_sections_full = []
    for name in names:
        d = ROOT / "domains" / name
        if not d.is_dir():
            sys.exit(f"No such domain folder: {d}")
        results, dom, is_example = audit_domain(d)
        if a.live:
            status, evidence = run_live_deviation_check(name)
            for r in results:
                if r.id == "LOG-05":
                    r.status, r.evidence = status, evidence
        domain_owners.append((name, dom.get("owner")))
        domain_sections_full.append((name, results, is_example))

    account_results = audit_account(ROOT / "account", domain_owners)

    build_report(account_results, domain_sections_full, a.out)
    print(f"Wrote {a.out}")


if __name__ == "__main__":
    main()
