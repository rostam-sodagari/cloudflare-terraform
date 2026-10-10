"""account.yaml, account/lists/*.yaml (IP, ASN, hostname, redirect lists),
and the account-level WAF/Logpush/notifications files."""
import re

from config import HEX32, PLANS
from .common import Ctx, check_enum, check_fields, check_host, check_type, is_cidr, load, list_values
from .waf import validate_waf


def validate_account(report, a):
    """Validate account configuration, retaining the existing public signature."""
    account_dir = a
    plan = _validate_account_metadata(report, account_dir)
    list_source_files, list_counts, total_item_count = _validate_lists(report, account_dir, plan)
    _check_list_limits(report, account_dir, plan, list_counts, total_item_count)

    list_names = set(list_source_files)
    # Account WAF uses the same shape and validator as zone WAF.
    validate_waf(report, account_dir, plan, list_names, {})
    validate_logpush(report, account_dir)
    validate_notifications(report, account_dir)
    validate_registrar(report, account_dir)
    validate_governance(report, account_dir)
    validate_turnstile(report, account_dir)
    return list_names


def _validate_account_metadata(report, account_dir):
    config_file = account_dir / "account.yaml"
    data, line_numbers = load(report, config_file)
    plan = "enterprise"
    if data not in (None, "ERROR"):
        ctx = Ctx(report, config_file, line_numbers, None)
        if check_fields(ctx, (), data, {"account_id": "str", "plan": "str", "example": "bool"}, ["account_id"]):
            if isinstance(data.get("account_id"), str) and not HEX32.match(data["account_id"]):
                ctx.error(("account_id",), "account_id must be the 32-character Account ID.", "put it in quotes")
            plan = data.get("plan", "enterprise")
            if not check_enum(ctx, ("plan",), plan, PLANS):
                # Continue independent checks after reporting the invalid plan.
                # The error still blocks deployment; fallback avoids limit-map crashes.
                plan = "enterprise"
            if "plan" not in data:
                ctx.warn((), "no plan set; list limits are checked as Enterprise.", "add plan: <highest plan in the account>")
    return plan


def _validate_lists(report, account_dir, plan):
    list_source_files = {}
    total_item_count = 0
    list_counts = {"redirect": 0, "other": 0}
    for list_kind in ("ip", "asn", "hostname", "redirect"):
        config_file = account_dir / "lists" / f"{list_kind}.yaml"
        data, line_numbers = load(report, config_file)
        if data in (None, "ERROR"):
            continue
        ctx = Ctx(report, config_file, line_numbers, plan)
        if not check_type(ctx, (), data, "dict"):
            continue
        if list_kind in ("asn", "hostname") and data and plan != "enterprise":
            ctx.error((), f"{list_kind} lists are Enterprise only.")
        for list_name, list_config in data.items():
            list_path = (list_name,)
            if not re.match(r"^[a-z0-9_]{1,50}$", str(list_name)):
                ctx.error(list_path, f"list name '{list_name}' must be lowercase letters, digits and _ (max 50).")
            if list_name in list_source_files:
                ctx.error(list_path, f"list name '{list_name}' is also used in {list_source_files[list_name]}.")
            list_source_files[list_name] = f"{list_kind}.yaml"
            list_counts["redirect" if list_kind == "redirect" else "other"] += 1
            total_item_count += _validate_list(ctx, list_path, list_config, list_kind)
    return list_source_files, list_counts, total_item_count


def _validate_list(ctx, list_path, list_config, list_kind):
    list_config = list_config or {}
    if not check_fields(ctx, list_path, list_config,
                        {"description": "str", "items": "list", "enabled": "bool"}, ["items"]):
        return 0
    items = list_config.get("items") or []
    if not isinstance(items, list):
        return 0  # check_fields already reported the invalid type
    seen_item_values = set()
    for item_index, item in enumerate(items):
        item_path = list_path + ("items", item_index)
        if list_kind == "ip":
            item_value = _validate_ip_item(ctx, item_path, item)
        elif list_kind == "asn":
            item_value = _validate_asn_item(ctx, item_path, item)
        elif list_kind == "hostname":
            item_value = _validate_hostname_item(ctx, item_path, item)
        else:
            if not _validate_redirect_item(ctx, item_path, item):
                continue
            item_value = item.get("source_url")
        if str(item_value) in seen_item_values:
            ctx.error(item_path, f"duplicate item '{item_value}'.")
        seen_item_values.add(str(item_value))
    return len(items)


def _validate_ip_item(ctx, item_path, item):
    ip_value = item.get("ip") if isinstance(item, dict) else item
    if isinstance(item, dict):
        check_fields(ctx, item_path, item, {"ip": "str", "comment": "str"}, ["ip"])
    if not is_cidr(str(ip_value)):
        ctx.error(item_path, f"'{ip_value}' is not an IP address or range.")
    return ip_value


def _validate_asn_item(ctx, item_path, item):
    asn_value = item.get("asn") if isinstance(item, dict) else item
    if isinstance(item, dict):
        check_fields(ctx, item_path, item, {"asn": "int", "comment": "str"}, ["asn"])
    if not isinstance(asn_value, int) or isinstance(asn_value, bool):
        ctx.error(item_path, f"'{asn_value}' is not an ASN number.", "write the number only, e.g. 64496")
    return asn_value


def _validate_hostname_item(ctx, item_path, item):
    hostname = item.get("hostname") if isinstance(item, dict) else item
    if isinstance(item, dict):
        check_fields(ctx, item_path, item, {"hostname": "str", "comment": "str"}, ["hostname"])
    check_host(ctx, item_path, str(hostname))
    return hostname


def _validate_redirect_item(ctx, item_path, item):
    fields = {"source_url": "str", "target_url": "str", "status_code": "int", "include_subdomains": "bool",
              "preserve_path_suffix": "bool", "preserve_query_string": "bool", "subpath_matching": "bool",
              "comment": "str"}
    if not check_fields(ctx, item_path, item, fields, ["source_url", "target_url"]):
        return False
    source_url = item.get("source_url")
    if isinstance(source_url, str) and re.match(r"^https?://", source_url):
        ctx.error(item_path + ("source_url",), "source_url must not include http:// or https://.")
    if isinstance(item.get("target_url"), str) and not re.match(r"^https?://", item["target_url"]):
        ctx.error(item_path + ("target_url",), "target_url must start with http:// or https://.")
    check_enum(ctx, item_path + ("status_code",), item.get("status_code"), [301, 302, 307, 308, None])
    if item.get("preserve_path_suffix") and not item.get("subpath_matching"):
        ctx.error(item_path + ("preserve_path_suffix",), "preserve_path_suffix needs subpath_matching: true.")
    return True


def _check_list_limits(report, account_dir, plan, list_counts, total_item_count):
    custom_list_limit = {"free": 1, "pro": 10, "business": 10, "enterprise": 1000}[plan]
    if list_counts["other"] > custom_list_limit:
        report.add("error", account_dir / "lists", 1,
                   f"{list_counts['other']} custom lists, but the {plan} plan allows {custom_list_limit}.")
    if list_counts["redirect"] > (25 if plan == "enterprise" else 5):
        report.add("error", account_dir / "lists" / "redirect.yaml", 1,
                   "too many Bulk Redirect lists for this plan (5, Enterprise 25).")
    if total_item_count > (500000 if plan == "enterprise" else 10000) and list_counts["other"]:
        report.add("error", account_dir / "lists", 1, f"{total_item_count} list items exceed the plan limit.")


def validate_turnstile(report, a):
    account_dir = a
    config_file = account_dir / "settings" / "turnstile.yaml"
    data, line_numbers = load(report, config_file)
    if data in (None, "ERROR"):
        return
    ctx = Ctx(report, config_file, line_numbers, None)
    if not check_type(ctx, (), data, "dict"):
        return
    for widget_name, widget_config in data.items():
        widget_path = (widget_name,)
        if check_fields(ctx, widget_path, widget_config or {}, {"domains": "list", "mode": "str", "bot_fight_mode": "bool"},
                        ["domains", "mode"]):
            check_enum(ctx, widget_path + ("mode",), (widget_config or {}).get("mode"), ["managed", "non-interactive", "invisible"])


def validate_governance(report, a):
    account_dir = a
    config_file = account_dir / "settings" / "sso.yaml"
    data, line_numbers = load(report, config_file)
    if data not in (None, "ERROR"):
        ctx = Ctx(report, config_file, line_numbers, None)
        if check_fields(ctx, (), data, {"email_domain": "str", "enabled": "bool", "begin_verification": "bool"},
                        ["email_domain"]):
            check_host(ctx, ("email_domain",), data.get("email_domain"), "domain")

    config_file = account_dir / "settings" / "user-groups.yaml"
    data, line_numbers = load(report, config_file)
    if data not in (None, "ERROR"):
        ctx = Ctx(report, config_file, line_numbers, None)
        if check_type(ctx, (), data, "dict"):
            for group_name, group_config in data.items():
                check_fields(ctx, (group_name,), group_config or {}, {"policies": "list", "members": "list"})

    config_file = account_dir / "settings" / "dns-settings.yaml"
    data, line_numbers = load(report, config_file)
    if data not in (None, "ERROR"):
        ctx = Ctx(report, config_file, line_numbers, None)
        check_fields(ctx, (), data, {"enforce_dns_only": "bool", "zone_defaults": "dict"})


def validate_registrar(report, a):
    account_dir = a
    config_file = account_dir / "settings" / "registrar.yaml"
    data, line_numbers = load(report, config_file)
    if data in (None, "ERROR"):
        return
    ctx = Ctx(report, config_file, line_numbers, None)
    if not check_type(ctx, (), data, "dict"):
        return
    for domain_name, domain_config in data.items():
        domain_path = (domain_name,)
        check_host(ctx, domain_path, str(domain_name), "registered domain name")
        check_fields(ctx, domain_path, domain_config or {}, {"auto_renew": "bool", "locked": "bool", "privacy": "bool"})


def validate_logpush(report, a):
    account_dir = a
    config_file = account_dir / "settings" / "logpush.yaml"
    data, line_numbers = load(report, config_file)
    if data in (None, "ERROR"):
        return
    ctx = Ctx(report, config_file, line_numbers, None)
    if not check_type(ctx, (), data, "dict"):
        return
    fields = {"dataset": "str", "destination_conf": "str", 'destination_conf_ref': 'str', "enabled": "bool", "filter": "str",
            "frequency": "str", "logpull_options": "str", "ownership_challenge": "str"}
    for job_name, job in data.items():
        job = {} if job is None else job
        job_path = (job_name,)
        if not check_fields(ctx, job_path, job or {}, fields, ["dataset"]):
            continue
        if bool(job.get('destination_conf')) == bool(job.get('destination_conf_ref')):
            ctx.error(job_path, 'supply exactly one destination_conf or destination_conf_ref.')
        check_enum(ctx, job_path + ("frequency",), job.get("frequency"), ["high", "low"])


def validate_notifications(report, a):
    account_dir = a
    config_file = account_dir / "settings" / "notification-webhooks.yaml"
    data, line_numbers = load(report, config_file)
    webhook_names = set()
    if data not in (None, "ERROR"):
        ctx = Ctx(report, config_file, line_numbers, None)
        if check_type(ctx, (), data, "dict"):
            for name, webhook in data.items():
                entry_path = (name,)
                if check_fields(ctx, entry_path, webhook or {}, {"url": "str", 'url_ref': 'str', "secret_ref": "str"}):
                    webhook_names.add(name)
                    if bool((webhook or {}).get('url')) == bool((webhook or {}).get('url_ref')):
                        ctx.error(entry_path, 'supply exactly one webhook url or url_ref.')

    config_file = account_dir / "settings" / "notifications.yaml"
    data, line_numbers = load(report, config_file)
    if data in (None, "ERROR"):
        return
    ctx = Ctx(report, config_file, line_numbers, None)
    if not check_type(ctx, (), data, "dict"):
        return
    fields = {"alert_type": "str", "description": "str", "enabled": "bool", "alert_interval": "str",
            "mechanisms": "dict", "filters": "dict"}
    for name, policy in data.items():
        policy = {} if policy is None else policy
        entry_path = (name,)
        if not check_fields(ctx, entry_path, policy or {}, fields, ["alert_type", "mechanisms"]):
            continue
        mechanisms = policy.get("mechanisms") or {}
        if not check_fields(ctx, entry_path + ("mechanisms",), mechanisms, {"email": "list", "webhooks": "list", "pagerduty": "list"}):
            continue
        if not any(mechanisms.get(k) for k in ("email", "webhooks", "pagerduty")):
            ctx.error(entry_path + ("mechanisms",), "needs at least one of email, webhooks or pagerduty.")
        for webhook_index, webhook in enumerate(list_values(mechanisms.get("webhooks"))):
            if not isinstance(webhook, str) or webhook not in webhook_names:
                ctx.error(entry_path + ("mechanisms", "webhooks", webhook_index),
                          f"'{webhook}' is not defined in settings/notification-webhooks.yaml.")
