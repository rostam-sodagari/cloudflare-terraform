"""WAF: custom rules, rate limiting, managed rulesets (simple and raw_rules
form)."""
from config import OWASP_PARANOIA_LEVELS, OWASP_SCORE_THRESHOLDS

from config import HEX32, LIMITS, RL_CHARS, RL_MAX_PERIOD, RL_MAX_TIMEOUT, RL_PERIODS, RL_TIMEOUTS
from .common import (
    Ctx, RULE_SCHEMA, check_enum, check_fields, check_ref, check_rule_schema, check_type,
    expression_checks, load, list_values,
)


def validate_waf(report, d, plan, list_names, refs):
    configuration_dir = d
    _validate_custom_rules(report, configuration_dir, plan, list_names, refs)
    _validate_rate_limits(report, configuration_dir, plan, list_names, refs)
    _validate_managed_rules(report, configuration_dir, plan, list_names, refs)


def _validate_custom_rules(report, configuration_dir, plan, list_names, refs):
    file_path = configuration_dir / "waf" / "custom-rules.yaml"
    data, lines = load(report, file_path)
    if data in (None, "ERROR"):
        return
    ctx = Ctx(report, file_path, lines, plan)
    field_types = {"ref": "str", "description": "str", "expression": "str", "action": "str", "enabled": "bool",
            "skip": "dict", "response": "dict"}
    if not check_type(ctx, (), data, "list"):
        return
    if len(data) > LIMITS["custom_rules"][plan]:
        ctx.error((), f"{len(data)} custom rules, but the {plan} plan allows {LIMITS['custom_rules'][plan]}.")
    for rule_index, rule in enumerate(data):
        path = (rule_index,)
        _validate_custom_rule(ctx, path, rule, field_types, refs, file_path, plan, list_names)



def _validate_rate_limits(report, configuration_dir, plan, list_names, refs):
    file_path = configuration_dir / "waf" / "rate-limits.yaml"
    data, lines = load(report, file_path)
    if data in (None, "ERROR"):
        return
    ctx = Ctx(report, file_path, lines, plan)
    field_types = {"ref": "str", "description": "str", "expression": "str", "action": "str", "enabled": "bool",
            "characteristics": "list", "period": "int", "requests_per_period": "int", "mitigation_timeout": "int",
            "counting_expression": "str", "requests_to_origin": "bool", "response": "dict"}
    if not check_type(ctx, (), data, "list"):
        return
    if len(data) > LIMITS["rate_limits"][plan]:
        ctx.error((), f"{len(data)} rate limiting rules, but the {plan} plan allows {LIMITS['rate_limits'][plan]}.")
    for rule_index, rule in enumerate(data):
        path = (rule_index,)
        _validate_rate_limit_rule(ctx, path, rule, field_types, refs, file_path, plan, list_names)



def _validate_managed_rules(report, configuration_dir, plan, list_names, refs):
    file_path = configuration_dir / "waf" / "managed-rules.yaml"
    data, lines = load(report, file_path)
    if data in (None, "ERROR"):
        return
    ctx = Ctx(report, file_path, lines, plan)
    field_types = {"cloudflare_managed": "dict", "owasp": "dict", "exceptions": "list", "raw_rules": "list"}
    if not check_fields(ctx, (), data, field_types):
        return
    if plan == "free":
        ctx.error((), "managed rulesets need Pro or above; on Free Cloudflare applies its Free Managed Ruleset itself.",
                  "comment out this file for Free zones")
    cloudflare_managed = data.get("cloudflare_managed")
    if cloudflare_managed is not None and check_fields(ctx, ("cloudflare_managed",), cloudflare_managed, {"enabled": "bool", "action": "str"}):
        check_action_override(ctx, ("cloudflare_managed", "action"), cloudflare_managed.get("action"), plan)
    owasp = data.get("owasp")
    if owasp is not None and check_fields(ctx, ("owasp",), owasp, {"enabled": "bool", "action": "str",
                                                             "paranoia_level": "int", "score_threshold": "int"}):
        check_action_override(ctx, ("owasp", "action"), owasp.get("action"), plan)
        check_enum(ctx, ("owasp", "paranoia_level"), owasp.get("paranoia_level"), list(OWASP_PARANOIA_LEVELS))
        score_threshold = owasp.get("score_threshold")
        if isinstance(score_threshold, int) and score_threshold not in OWASP_SCORE_THRESHOLDS:
            ctx.flag("owasp_score_threshold_standard", ("owasp", "score_threshold"),
                     f"{score_threshold} is not one of Cloudflare's levels.", "60 low, 40 medium, 25 high")
    for rule_index, exception in enumerate(list_values(data.get("exceptions"))):
        path = ("exceptions", rule_index)
        if check_fields(ctx, path, exception, {"ref": "str", "description": "str", "expression": "str", "rulesets": "list"},
                        ["ref", "expression", "rulesets"]):
            check_ref(ctx, path, exception.get("ref"), refs, file_path)
            expression_checks(ctx, path + ("expression",), exception.get("expression"), plan, list_names)
            for item_index, ruleset in enumerate(list_values(exception.get("rulesets"))):
                if ruleset not in ("owasp", "cloudflare_managed") and not HEX32.match(str(ruleset)):
                    ctx.error(path + ("rulesets", item_index), f"'{ruleset}' is not a ruleset.", "use owasp, cloudflare_managed or a 32-character ruleset ID")
    if data.get("raw_rules"):
        if any(setting_name in data for setting_name in ("cloudflare_managed", "owasp", "exceptions")):
            ctx.warn(("raw_rules",), "raw_rules is set, so cloudflare_managed, owasp and exceptions are ignored.")
        for rule_index, rule in enumerate(list_values(data["raw_rules"])):
            check_rule_schema(ctx, ("raw_rules", rule_index), rule, RULE_SCHEMA)
            if isinstance(rule, dict):
                if rule.get("action") == "log" and plan != "enterprise":
                    ctx.error(("raw_rules", rule_index, "action"), "the log action is Enterprise only.")


def check_action_override(ctx, path, action, plan):
    if action is None:
        return
    check_enum(ctx, path, action, ["block", "managed_challenge", "js_challenge", "challenge", "log"])
    if action == "log" and plan != "enterprise":
        ctx.error(path, "the log action is Enterprise only.",
                  "remove action to use Cloudflare's default, or use managed_challenge while tuning")


def check_response(ctx, path, resp, action, plan):
    if action != "block":
        ctx.error(path, "a custom response only works with action: block.")
    if plan == "free":
        ctx.error(path, "custom block responses need a paid plan.")
    if check_fields(ctx, path, resp, {"status_code": "int", "content_type": "str", "content": "str"}, ["content"]):
        sc = resp.get("status_code")
        if isinstance(sc, int) and not (400 <= sc <= 499):
            ctx.error(path + ("status_code",), "status_code must be 400 to 499.")
        check_enum(ctx, path + ("content_type",), resp.get("content_type"),
                   ["text/html", "text/plain", "application/json", "text/xml"])


def _validate_custom_rule(ctx, path, rule, field_types, refs, file_path, plan, list_names):
    if not check_fields(ctx, path, rule, field_types, ["ref", "expression", "action"]):
        return
    check_ref(ctx, path, rule.get("ref"), refs, file_path)
    action = rule.get("action")
    check_enum(ctx, path + ("action",), action, ["block", "managed_challenge", "js_challenge", "challenge", "log", "skip"])
    if action == "log" and plan != "enterprise":
        ctx.error(path + ("action",), "the log action is Enterprise only.", "use managed_challenge while testing")
    expression_checks(ctx, path + ("expression",), rule.get("expression"), plan, list_names)
    if "skip" in rule:
        if action != "skip":
            ctx.error(path + ("skip",), "skip settings only apply when action is skip.")
        skip_settings = rule["skip"] or {}
        if check_fields(ctx, path + ("skip",), skip_settings, {"ruleset": "str", "phases": "list", "products": "list", "log": "bool"}):
            check_enum(ctx, path + ("skip", "ruleset"), skip_settings.get("ruleset"), ["current"])
            for item_index, phase in enumerate(list_values(skip_settings.get("phases"))):
                check_enum(ctx, path + ("skip", "phases", item_index), phase,
                           ["http_ratelimit", "http_request_firewall_managed", "http_request_sbfm"])
            for item_index, product in enumerate(list_values(skip_settings.get("products"))):
                check_enum(ctx, path + ("skip", "products", item_index), product,
                           ["bic", "hot", "rateLimit", "securityLevel", "uaBlock", "waf", "zoneLockdown"])
            if not any(skip_settings.get(setting_name) for setting_name in ("ruleset", "phases", "products")):
                ctx.error(path + ("skip",), "skip needs ruleset, phases or products.")
    elif action == "skip":
        ctx.error(path, "action skip needs a skip: section.", "e.g. skip: { ruleset: current }")
    if "response" in rule:
        check_response(ctx, path + ("response",), rule["response"], action, plan)


def _validate_rate_limit_rule(ctx, path, rule, field_types, refs, file_path, plan, list_names):
    if not check_fields(ctx, path, rule, field_types, ["ref", "expression", "requests_per_period"]):
        return
    check_ref(ctx, path, rule.get("ref"), refs, file_path)
    action = rule.get("action", "block")
    check_enum(ctx, path + ("action",), action, ["block", "managed_challenge", "js_challenge", "challenge", "log"])
    if action == "log" and plan != "enterprise":
        ctx.error(path + ("action",), "the log action is Enterprise only.")
    expression_checks(ctx, path + ("expression",), rule.get("expression"), plan, list_names)
    period, timeout = rule.get("period", 10), rule.get("mitigation_timeout", 10)
    if isinstance(period, int):
        if period not in RL_PERIODS:
            ctx.error(path + ("period",), f"period {period} is not a supported value.", f"use one of {RL_PERIODS}")
        elif period > RL_MAX_PERIOD[plan]:
            ctx.error(path + ("period",), f"the {plan} plan allows a period up to {RL_MAX_PERIOD[plan]} seconds.")
    if isinstance(timeout, int):
        if timeout not in RL_TIMEOUTS:
            ctx.error(path + ("mitigation_timeout",), f"mitigation_timeout {timeout} is not a supported value.",
                      f"use one of {RL_TIMEOUTS}")
        elif timeout > RL_MAX_TIMEOUT[plan] or (plan == "free" and timeout != 10):
            ctx.error(path + ("mitigation_timeout",),
                      f"the {plan} plan allows mitigation_timeout up to {RL_MAX_TIMEOUT[plan]} seconds"
                      + (" (exactly 10 on Free)." if plan == "free" else "."))
    if isinstance(rule.get("requests_per_period"), int) and rule["requests_per_period"] < 1:
        ctx.error(path + ("requests_per_period",), "requests_per_period must be at least 1.")
    characteristics = rule.get("characteristics")
    if isinstance(characteristics, list):
        if "cf.colo.id" not in characteristics:
            ctx.error(path + ("characteristics",), "characteristics must include cf.colo.id.",
                      "e.g. [ip.src, cf.colo.id]")
        if plan in RL_CHARS:
            unsupported_characteristics = set(map(str, characteristics)) - RL_CHARS[plan]
            if unsupported_characteristics:
                ctx.error(path + ("characteristics",),
                          f"{', '.join(sorted(unsupported_characteristics))} not available on {plan}; it counts by IP only.",
                          "use [ip.src, cf.colo.id]")
    if rule.get("counting_expression") and plan in ("free", "pro"):
        ctx.error(path + ("counting_expression",), "counting_expression needs Business or Enterprise.")
    if "response" in rule:
        check_response(ctx, path + ("response",), rule["response"], action, plan)
