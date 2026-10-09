"""Rule-engine phases: cache rules, redirects, URL rewrites, request/response
headers, origin rules, config rules, compression. All share one shape
(ref/description/expression/action_parameters) checked against the
provider's own rule schema."""
import json

from .common import (
    LIMITS, REGEX_RE, RULE_FILES, RULE_SCHEMA, Ctx, check_enum, check_ref,
    check_rule_schema, check_type, expression_checks, load, suggest,
)


def validate_rule_files(report, d, plan, list_names, refs):
    allowed_top = {"ref", "description", "expression", "action_parameters", "enabled", "action"}
    for rel, expected_action in RULE_FILES.items():
        f = d / rel
        data, lines = load(report, f)
        if data in (None, "ERROR"):
            continue
        ctx = Ctx(report, f, lines, plan)
        if not check_type(ctx, (), data, "list"):
            continue
        if len(data) > LIMITS["rules"][plan]:
            ctx.error((), f"{len(data)} rules, but the {plan} plan allows {LIMITS['rules'][plan]} in this file.")
        for i, r in enumerate(data):
            p = (i,)
            if not check_type(ctx, p, r, "dict"):
                continue
            for k in r:
                if k not in allowed_top:
                    ctx.error(p + (k,), f"unknown field '{k}'.", suggest(k, allowed_top))
            for k in ("ref", "expression"):
                if k not in r:
                    ctx.error(p, f"rule is missing required field '{k}'.")
            if "action" in r and r["action"] != expected_action:
                ctx.error(p + ("action",), f"this file only holds '{expected_action}' rules.", "remove the action line; it is set for you")
            check_ref(ctx, p, r.get("ref"), refs, f)
            if "enabled" in r:
                check_type(ctx, p + ("enabled",), r["enabled"], "bool")
            if "description" in r:
                check_type(ctx, p + ("description",), r["description"], "str")
            expression_checks(ctx, p + ("expression",), r.get("expression"), plan, list_names)
            ap = r.get("action_parameters")
            if ap is None:
                ctx.error(p, "rule has no action_parameters, so it would do nothing.")
                continue
            check_rule_schema(ctx, p + ("action_parameters",), ap, RULE_SCHEMA["action_parameters"])
            if not isinstance(ap, dict):
                continue
            if rel == "rules/origin.yaml" and plan != "enterprise":
                for k in ("host_header", "sni"):
                    if k in ap:
                        ctx.error(p + ("action_parameters", k), f"{k} override is Enterprise only.")
                if isinstance(ap.get("origin"), dict) and "host" in ap["origin"]:
                    ctx.error(p + ("action_parameters", "origin", "host"), "DNS record override (origin.host) is Enterprise only.",
                              "on other plans only origin.port can be changed")
            if plan in ("free", "pro") and REGEX_RE.search(json.dumps(ap)):
                ctx.error(p + ("action_parameters",), "regex_replace needs Business or Enterprise.",
                          "use wildcard_replace instead")
            if rel == "rules/redirects.yaml":
                fv = ap.get("from_value") or {}
                sc = fv.get("status_code") if isinstance(fv, dict) else None
                check_enum(ctx, p + ("action_parameters", "from_value", "status_code"), sc, [301, 302, 303, 307, 308, None])
