"""account.yaml, account/lists/*.yaml (IP, ASN, hostname, redirect lists),
and the account-level WAF/Logpush/notifications files."""
import re

from .common import HEX32, PLANS, Ctx, check_enum, check_fields, check_host, check_type, is_cidr, load
from .waf import validate_waf


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

    list_names = set(names)
    # account/waf/*.yaml is the same shape as a zone's waf/*.yaml -- reuse
    # the same validator rather than duplicating it.
    validate_waf(report, a, plan, list_names, {})
    validate_logpush(report, a)
    validate_notifications(report, a)
    validate_registrar(report, a)
    validate_governance(report, a)
    validate_turnstile(report, a)
    return list_names


def validate_turnstile(report, a):
    f = a / "settings" / "turnstile.yaml"
    data, lines = load(report, f)
    if data in (None, "ERROR"):
        return
    ctx = Ctx(report, f, lines, None)
    if not check_type(ctx, (), data, "dict"):
        return
    for name, w in data.items():
        p = (name,)
        if check_fields(ctx, p, w or {}, {"domains": "list", "mode": "str", "bot_fight_mode": "bool"},
                        ["domains", "mode"]):
            check_enum(ctx, p + ("mode",), w.get("mode"), ["managed", "non-interactive", "invisible"])


def validate_governance(report, a):
    f = a / "settings" / "sso.yaml"
    data, lines = load(report, f)
    if data not in (None, "ERROR"):
        ctx = Ctx(report, f, lines, None)
        if check_fields(ctx, (), data, {"email_domain": "str", "enabled": "bool", "begin_verification": "bool"},
                        ["email_domain"]):
            check_host(ctx, ("email_domain",), data.get("email_domain"), "domain")

    f = a / "settings" / "user-groups.yaml"
    data, lines = load(report, f)
    if data not in (None, "ERROR"):
        ctx = Ctx(report, f, lines, None)
        if check_type(ctx, (), data, "dict"):
            for name, g in data.items():
                check_fields(ctx, (name,), g or {}, {"policies": "list", "members": "list"})

    f = a / "settings" / "dns-settings.yaml"
    data, lines = load(report, f)
    if data not in (None, "ERROR"):
        ctx = Ctx(report, f, lines, None)
        check_fields(ctx, (), data, {"enforce_dns_only": "bool", "zone_defaults": "dict"})


def validate_registrar(report, a):
    f = a / "settings" / "registrar.yaml"
    data, lines = load(report, f)
    if data in (None, "ERROR"):
        return
    ctx = Ctx(report, f, lines, None)
    if not check_type(ctx, (), data, "dict"):
        return
    for name, d in data.items():
        p = (name,)
        check_host(ctx, p, str(name), "registered domain name")
        check_fields(ctx, p, d or {}, {"auto_renew": "bool", "locked": "bool", "privacy": "bool"})


def validate_logpush(report, a):
    f = a / "settings" / "logpush.yaml"
    data, lines = load(report, f)
    if data in (None, "ERROR"):
        return
    ctx = Ctx(report, f, lines, None)
    if not check_type(ctx, (), data, "dict"):
        return
    spec = {"dataset": "str", "destination_conf": "str", "enabled": "bool", "filter": "str",
            "frequency": "str", "logpull_options": "str", "ownership_challenge": "str"}
    for name, job in data.items():
        p = (name,)
        if not check_fields(ctx, p, job or {}, spec, ["dataset", "destination_conf"]):
            continue
        check_enum(ctx, p + ("frequency",), job.get("frequency"), ["high", "low"])


def validate_notifications(report, a):
    f = a / "settings" / "notification-webhooks.yaml"
    data, lines = load(report, f)
    webhook_names = set()
    if data not in (None, "ERROR"):
        ctx = Ctx(report, f, lines, None)
        if check_type(ctx, (), data, "dict"):
            for name, w in data.items():
                p = (name,)
                if check_fields(ctx, p, w or {}, {"url": "str", "secret": "str"}, ["url"]):
                    webhook_names.add(name)

    f = a / "settings" / "notifications.yaml"
    data, lines = load(report, f)
    if data in (None, "ERROR"):
        return
    ctx = Ctx(report, f, lines, None)
    if not check_type(ctx, (), data, "dict"):
        return
    spec = {"alert_type": "str", "description": "str", "enabled": "bool", "alert_interval": "str",
            "mechanisms": "dict", "filters": "dict"}
    for name, policy in data.items():
        p = (name,)
        if not check_fields(ctx, p, policy or {}, spec, ["alert_type", "mechanisms"]):
            continue
        mech = policy.get("mechanisms") or {}
        if not check_fields(ctx, p + ("mechanisms",), mech, {"email": "list", "webhooks": "list", "pagerduty": "list"}):
            continue
        if not any(mech.get(k) for k in ("email", "webhooks", "pagerduty")):
            ctx.error(p + ("mechanisms",), "needs at least one of email, webhooks or pagerduty.")
        for i, w in enumerate(mech.get("webhooks") or []):
            if w not in webhook_names:
                ctx.error(p + ("mechanisms", "webhooks", i),
                          f"'{w}' is not defined in settings/notification-webhooks.yaml.")
