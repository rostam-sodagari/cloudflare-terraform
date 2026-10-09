"""WAF: custom rules, rate limiting, managed rulesets (simple and raw_rules
form)."""
from config import OWASP_PARANOIA_LEVELS, OWASP_SCORE_THRESHOLDS

from config import HEX32, LIMITS, RL_CHARS, RL_MAX_PERIOD, RL_MAX_TIMEOUT, RL_PERIODS, RL_TIMEOUTS
from .common import (
    Ctx, RULE_SCHEMA, check_enum, check_fields, check_ref, check_rule_schema, check_type,
    expression_checks, load,
)


def validate_waf(report, d, plan, list_names, refs):
    # custom rules
    f = d / "waf" / "custom-rules.yaml"
    data, lines = load(report, f)
    if data not in (None, "ERROR"):
        ctx = Ctx(report, f, lines, plan)
        spec = {"ref": "str", "description": "str", "expression": "str", "action": "str", "enabled": "bool",
                "skip": "dict", "response": "dict"}
        if check_type(ctx, (), data, "list"):
            if len(data) > LIMITS["custom_rules"][plan]:
                ctx.error((), f"{len(data)} custom rules, but the {plan} plan allows {LIMITS['custom_rules'][plan]}.")
            for i, r in enumerate(data):
                p = (i,)
                if not check_fields(ctx, p, r, spec, ["ref", "expression", "action"]):
                    continue
                check_ref(ctx, p, r.get("ref"), refs, f)
                a = r.get("action")
                check_enum(ctx, p + ("action",), a, ["block", "managed_challenge", "js_challenge", "challenge", "log", "skip"])
                if a == "log" and plan != "enterprise":
                    ctx.error(p + ("action",), "the log action is Enterprise only.", "use managed_challenge while testing")
                expression_checks(ctx, p + ("expression",), r.get("expression"), plan, list_names)
                if "skip" in r:
                    if a != "skip":
                        ctx.error(p + ("skip",), "skip settings only apply when action is skip.")
                    sk = r["skip"] or {}
                    if check_fields(ctx, p + ("skip",), sk, {"ruleset": "str", "phases": "list", "products": "list", "log": "bool"}):
                        check_enum(ctx, p + ("skip", "ruleset"), sk.get("ruleset"), ["current"])
                        for j, ph in enumerate(sk.get("phases") or []):
                            check_enum(ctx, p + ("skip", "phases", j), ph,
                                       ["http_ratelimit", "http_request_firewall_managed", "http_request_sbfm"])
                        for j, pr in enumerate(sk.get("products") or []):
                            check_enum(ctx, p + ("skip", "products", j), pr,
                                       ["bic", "hot", "rateLimit", "securityLevel", "uaBlock", "waf", "zoneLockdown"])
                        if not any(sk.get(k) for k in ("ruleset", "phases", "products")):
                            ctx.error(p + ("skip",), "skip needs ruleset, phases or products.")
                elif a == "skip":
                    ctx.error(p, "action skip needs a skip: section.", "e.g. skip: { ruleset: current }")
                if "response" in r:
                    check_response(ctx, p + ("response",), r["response"], a, plan)

    # rate limits
    f = d / "waf" / "rate-limits.yaml"
    data, lines = load(report, f)
    if data not in (None, "ERROR"):
        ctx = Ctx(report, f, lines, plan)
        spec = {"ref": "str", "description": "str", "expression": "str", "action": "str", "enabled": "bool",
                "characteristics": "list", "period": "int", "requests_per_period": "int", "mitigation_timeout": "int",
                "counting_expression": "str", "requests_to_origin": "bool", "response": "dict"}
        if check_type(ctx, (), data, "list"):
            if len(data) > LIMITS["rate_limits"][plan]:
                ctx.error((), f"{len(data)} rate limiting rules, but the {plan} plan allows {LIMITS['rate_limits'][plan]}.")
            for i, r in enumerate(data):
                p = (i,)
                if not check_fields(ctx, p, r, spec, ["ref", "expression", "requests_per_period"]):
                    continue
                check_ref(ctx, p, r.get("ref"), refs, f)
                a = r.get("action", "block")
                check_enum(ctx, p + ("action",), a, ["block", "managed_challenge", "js_challenge", "challenge", "log"])
                if a == "log" and plan != "enterprise":
                    ctx.error(p + ("action",), "the log action is Enterprise only.")
                expression_checks(ctx, p + ("expression",), r.get("expression"), plan, list_names)
                period, timeout = r.get("period", 10), r.get("mitigation_timeout", 10)
                if isinstance(period, int):
                    if period not in RL_PERIODS:
                        ctx.error(p + ("period",), f"period {period} is not a supported value.", f"use one of {RL_PERIODS}")
                    elif period > RL_MAX_PERIOD[plan]:
                        ctx.error(p + ("period",), f"the {plan} plan allows a period up to {RL_MAX_PERIOD[plan]} seconds.")
                if isinstance(timeout, int):
                    if timeout not in RL_TIMEOUTS:
                        ctx.error(p + ("mitigation_timeout",), f"mitigation_timeout {timeout} is not a supported value.",
                                  f"use one of {RL_TIMEOUTS}")
                    elif timeout > RL_MAX_TIMEOUT[plan] or (plan == "free" and timeout != 10):
                        ctx.error(p + ("mitigation_timeout",),
                                  f"the {plan} plan allows mitigation_timeout up to {RL_MAX_TIMEOUT[plan]} seconds"
                                  + (" (exactly 10 on Free)." if plan == "free" else "."))
                if isinstance(r.get("requests_per_period"), int) and r["requests_per_period"] < 1:
                    ctx.error(p + ("requests_per_period",), "requests_per_period must be at least 1.")
                chars = r.get("characteristics")
                if isinstance(chars, list):
                    if "cf.colo.id" not in chars:
                        ctx.error(p + ("characteristics",), "characteristics must include cf.colo.id.",
                                  "e.g. [ip.src, cf.colo.id]")
                    if plan in RL_CHARS:
                        extra = set(map(str, chars)) - RL_CHARS[plan]
                        if extra:
                            ctx.error(p + ("characteristics",),
                                      f"{', '.join(sorted(extra))} not available on {plan}; it counts by IP only.",
                                      "use [ip.src, cf.colo.id]")
                if r.get("counting_expression") and plan in ("free", "pro"):
                    ctx.error(p + ("counting_expression",), "counting_expression needs Business or Enterprise.")
                if "response" in r:
                    check_response(ctx, p + ("response",), r["response"], a, plan)

    # managed
    f = d / "waf" / "managed-rules.yaml"
    data, lines = load(report, f)
    if data not in (None, "ERROR"):
        ctx = Ctx(report, f, lines, plan)
        spec = {"cloudflare_managed": "dict", "owasp": "dict", "exceptions": "list", "raw_rules": "list"}
        if check_fields(ctx, (), data, spec):
            if plan == "free":
                ctx.error((), "managed rulesets need Pro or above; on Free Cloudflare applies its Free Managed Ruleset itself.",
                          "comment out this file for Free zones")
            cm = data.get("cloudflare_managed")
            if cm is not None and check_fields(ctx, ("cloudflare_managed",), cm, {"enabled": "bool", "action": "str"}):
                check_action_override(ctx, ("cloudflare_managed", "action"), cm.get("action"), plan)
            ow = data.get("owasp")
            if ow is not None and check_fields(ctx, ("owasp",), ow, {"enabled": "bool", "action": "str",
                                                                     "paranoia_level": "int", "score_threshold": "int"}):
                check_action_override(ctx, ("owasp", "action"), ow.get("action"), plan)
                check_enum(ctx, ("owasp", "paranoia_level"), ow.get("paranoia_level"), list(OWASP_PARANOIA_LEVELS))
                st = ow.get("score_threshold")
                if isinstance(st, int) and st not in OWASP_SCORE_THRESHOLDS:
                    ctx.flag("owasp_score_threshold_standard", ("owasp", "score_threshold"),
                             f"{st} is not one of Cloudflare's levels.", "60 low, 40 medium, 25 high")
            for i, e in enumerate(data.get("exceptions") or []):
                p = ("exceptions", i)
                if check_fields(ctx, p, e, {"ref": "str", "description": "str", "expression": "str", "rulesets": "list"},
                                ["ref", "expression", "rulesets"]):
                    check_ref(ctx, p, e.get("ref"), refs, f)
                    expression_checks(ctx, p + ("expression",), e.get("expression"), plan, list_names)
                    for j, rs in enumerate(e.get("rulesets") or []):
                        if rs not in ("owasp", "cloudflare_managed") and not HEX32.match(str(rs)):
                            ctx.error(p + ("rulesets", j), f"'{rs}' is not a ruleset.", "use owasp, cloudflare_managed or a 32-character ruleset ID")
            if data.get("raw_rules"):
                if any(k in data for k in ("cloudflare_managed", "owasp", "exceptions")):
                    ctx.warn(("raw_rules",), "raw_rules is set, so cloudflare_managed, owasp and exceptions are ignored.")
                for i, r in enumerate(data["raw_rules"]):
                    check_rule_schema(ctx, ("raw_rules", i), r, RULE_SCHEMA)
                    if isinstance(r, dict):
                        if r.get("action") == "log" and plan != "enterprise":
                            ctx.error(("raw_rules", i, "action"), "the log action is Enterprise only.")


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
