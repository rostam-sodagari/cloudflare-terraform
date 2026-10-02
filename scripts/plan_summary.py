#!/usr/bin/env python3
"""
Turn a Terraform plan into a plain-English list of what will change in
Cloudflare, so people who only edit YAML can check a change before it is
applied.

    terraform -chdir=domains/example.com show -json plan.bin > plan.json
    python3 scripts/plan_summary.py plan.json --root example.com
    python3 scripts/plan_summary.py plan.json --root example.com --format md > summary.md

Usually run for you by `python3 cf.py plan`, `python3 cf.py drift` and CI.

Sections
  WILL CHANGE IN CLOUDFLARE   add / change / delete / replace, field by field
  ADOPT                       existing objects taken over by imports.tf (no change)
  CHANGED OUTSIDE GIT (DRIFT) edits made in the dashboard or API since the last
                              apply. If the YAML was not updated to match, this
                              plan puts them back to what the YAML says.
  WARNINGS                    deletions or changes that can cut traffic or protection

Exit code: 0 = no changes, 2 = changes or drift present (like terraform -detailed-exitcode).
"""
import argparse
import json
import sys

# Computed or bookkeeping fields that are never what a person changed.
NOISE = {
    "id", "created_on", "modified_on", "last_updated", "version", "zone_id", "account_id",
    "created_at", "updated_at", "operation_id", "editable", "time_remaining",
}
NOISE_BY_TYPE = {
    "cloudflare_dns_record": {"comment_modified_on", "tags_modified_on", "meta", "proxiable",
                              "include_shadow_metadata", "settings", "tags", "private_routing"},
    "cloudflare_ruleset": {"name", "kind", "phase", "categories"},
    "cloudflare_zone_dnssec": {"ds", "digest", "digest_algorithm", "digest_type", "algorithm", "flags",
                               "key_tag", "key_type", "public_key", "dnssec_multi_signer",
                               "dnssec_presigned", "dnssec_use_nsec3"},
    "cloudflare_zone_setting": {"editable", "time_remaining", "enabled"},
    "cloudflare_bot_management": {"using_latest_model", "stale_zone_configuration"},
    "cloudflare_list": {"num_items", "num_referencing_filters"},
    "cloudflare_access_rule": {"allowed_modes", "scope"},
}
RULESET_LABELS = {
    "custom": "WAF custom rules", "rate_limit": "Rate limiting rules", "managed": "Managed WAF rules",
    '"cache"': "Cache rules", '"redirects"': "Redirect rules", '"url_rewrites"': "URL rewrite rules",
    '"request_headers"': "Request header rules", '"response_headers"': "Response header rules",
    '"origin"': "Origin rules", '"config"': "Configuration rules", '"compression"': "Compression rules",
    "bulk_redirects": "Bulk Redirect rules",
}
RISKY = {
    "cloudflare_ruleset": "removes the rules in this phase, including any protection they give",
    "cloudflare_access_rule": "removes an IP Access Rule",
    "cloudflare_bot_management": "bot protection settings stop being managed",
    "cloudflare_zone_dnssec": "switches DNSSEC off; remove the DS record at the registrar first",
    "cloudflare_list": "deletes a list; rules that reference it will fail",
}
MAXLEN = 140


def short(v):
    if isinstance(v, (dict, list)):
        v = json.dumps(v, separators=(",", ":"), sort_keys=True)
    s = "null" if v is None else str(v)
    return s if len(s) <= MAXLEN else s[: MAXLEN - 3] + "..."


def prune(v, noise=frozenset()):
    """Drop nulls, empties and noise so comparisons see only meaningful data."""
    if isinstance(v, dict):
        out = {k: prune(x, noise) for k, x in v.items() if k not in NOISE and k not in noise}
        return {k: x for k, x in out.items() if x not in (None, {}, [], "")}
    if isinstance(v, list):
        return [prune(x, noise) for x in v]
    return v


def leaf_diffs(before, after, path=""):
    """[(path, before, after)] for every differing leaf."""
    if isinstance(before, dict) and isinstance(after, dict):
        out = []
        for k in sorted(set(before) | set(after)):
            out += leaf_diffs(before.get(k), after.get(k), f"{path}.{k}" if path else k)
        return out
    if isinstance(before, list) and isinstance(after, list) and len(before) == len(after) \
            and all(isinstance(x, dict) for x in before + after):
        out = []
        for i, (b, a) in enumerate(zip(before, after)):
            out += leaf_diffs(b, a, f"{path}[{i + 1}]")
        return out
    return [] if before == after else [(path or "(value)", before, after)]


def mask_unknown(after, unknown):
    if unknown is True:
        return "(known after apply)"
    if isinstance(after, dict) and isinstance(unknown, dict):
        return {k: mask_unknown(after.get(k), unknown.get(k)) for k in set(after) | set(unknown)}
    return after


def address_key(addr):
    return (addr[addr.index("[") + 1:-1] if "[" in addr else addr.rsplit(".", 1)[-1]).strip('"')


# ---- describe one object ---------------------------------------------------------
def describe(rc, values):
    t, addr = rc["type"], rc["address"]
    v = values or {}
    if t == "cloudflare_dns_record":
        rtype = v.get("type", "?")
        data = {k: x for k, x in (v.get("data") or {}).items() if x is not None and x != "(known after apply)"} \
            if isinstance(v.get("data"), dict) else None
        order = {"CAA": ("flags", "tag", "value"), "SRV": ("priority", "weight", "port", "target")}.get(rtype)
        content = " ".join(str(data[k]) for k in order if k in data) if order and data else v.get("content")
        extra = " (proxied)" if v.get("proxied") else ""
        if rtype == "MX" and v.get("priority") is not None:
            extra += f" priority {v['priority']}"
        return f"DNS {rtype} `{v.get('name', '?')}` -> `{short(content)}`{extra}"
    if t == "cloudflare_zone_dnssec":
        return "DNSSEC"
    if t == "cloudflare_ruleset":
        for k, label in RULESET_LABELS.items():
            if addr.endswith(f".{k}[0]") or addr.endswith(f"[{k}]"):
                return label
        return f"Ruleset {v.get('phase', '')}"
    if t == "cloudflare_access_rule":
        cfg = v.get("configuration") or {}
        return f"IP Access Rule `{address_key(addr)}` ({v.get('mode', '?')} {cfg.get('target', '')} {cfg.get('value', '')})"
    if t == "cloudflare_bot_management":
        return "Bot protection settings"
    if t == "cloudflare_zone_setting":
        sid = v.get("setting_id") or address_key(addr).strip('"')
        return "HSTS (security header)" if sid == "security_header" else f"Zone setting `{sid}`"
    if t == "cloudflare_tiered_cache":
        return "Smart Tiered Cache"
    if t == "cloudflare_argo_tiered_caching":
        return "Argo Tiered Caching"
    if t == "cloudflare_list":
        return f"List `{v.get('name', address_key(addr))}` ({v.get('kind', '')})"
    return addr


def rule_label(r):
    return f"rule `{r.get('ref') or r.get('description') or '?'}`"


def ruleset_changes(before, after, noise=frozenset()):
    """Rule-by-rule differences between two rulesets."""
    b = [prune(r, noise) for r in (before or {}).get("rules") or []]
    a = [prune(r, noise) for r in (after or {}).get("rules") or []]
    bref = {r.get("ref", f"#{i}"): (i, r) for i, r in enumerate(b)}
    aref = {r.get("ref", f"#{i}"): (i, r) for i, r in enumerate(a)}
    lines = []
    for ref, (i, r) in aref.items():
        if ref not in bref:
            lines.append(f"add {rule_label(r)} at position {i + 1}: {r.get('action', '')} when `{short(r.get('expression'))}`")
    for ref, (i, r) in bref.items():
        if ref not in aref:
            lines.append(f"remove {rule_label(r)} ({r.get('action', '')} when `{short(r.get('expression'))}`)")
    for ref in aref:
        if ref in bref:
            (bi, br), (ai, ar) = bref[ref], aref[ref]
            for path, x, y in leaf_diffs(br, ar):
                lines.append(f"{rule_label(ar)}: {path} `{short(x)}` -> `{short(y)}`")
            if bi != ai:
                lines.append(f"{rule_label(ar)} moves from position {bi + 1} to {ai + 1} (rules run top to bottom)")
    return lines


def list_changes(before, after, noise=frozenset()):
    def items(v):
        return {json.dumps(prune(i), sort_keys=True) for i in (v or {}).get("items") or []}
    b, a = items(before), items(after)
    out = [f"add item {short(json.loads(x))}" for x in sorted(a - b)]
    out += [f"remove item {short(json.loads(x))}" for x in sorted(b - a)]
    for path, x, y in leaf_diffs(prune({k: v for k, v in (before or {}).items() if k != "items"}, noise),
                                 prune({k: v for k, v in (after or {}).items() if k != "items"}, noise)):
        out.append(f"{path}: `{short(x)}` -> `{short(y)}`")
    return out


def field_changes(rc, before, after):
    noise = NOISE_BY_TYPE.get(rc["type"], set())
    if rc["type"] == "cloudflare_ruleset":
        return ruleset_changes(before, after, noise)
    if rc["type"] == "cloudflare_list":
        return list_changes(before, after, noise)
    diffs = leaf_diffs(prune(before or {}, noise), prune(after or {}, noise))
    if not before:  # a new object: list only the values that are known now
        return [f"{p}: `{short(y)}`" for p, x, y in diffs if y != "(known after apply)"]
    # A value Cloudflare fills in itself (unknown until apply) is not a change.
    return [f"{p}: `{short(x)}` -> `{short(y)}`" for p, x, y in diffs if not (x is None and y == "(known after apply)")]


# ---- whole plan --------------------------------------------------------------------
def summarise(plan, drift_only=False):
    changes, adopts, warnings, drift = [], [], [], []
    counts = {"add": 0, "change": 0, "delete": 0, "replace": 0, "adopt": 0}

    drifted = set()
    for rc in plan.get("resource_drift") or []:
        ch = rc["change"]
        drifted.add(rc["address"])
        label = describe(rc, ch.get("after") or ch.get("before"))
        if "delete" in ch["actions"] and not ch.get("after"):
            drift.append(("deleted", label, ["deleted outside Git (dashboard or API)"]))
        else:
            drift.append(("changed", label, field_changes(rc, ch.get("before"), ch.get("after")) or ["changed outside Git"]))

    if not drift_only:
        for rc in plan.get("resource_changes") or []:
            ch, acts = rc["change"], rc["change"]["actions"]
            if rc.get("mode") == "data" or acts == ["read"]:
                continue
            importing = ch.get("importing") is not None
            before, after = ch.get("before"), mask_unknown(ch.get("after"), ch.get("after_unknown"))
            label = describe(rc, after if after else before)
            if acts == ["no-op"]:
                if importing:
                    counts["adopt"] += 1
                    adopts.append(label)
                continue
            if acts == ["create"]:
                kind = "ADD"
                counts["add"] += 1
                details = [] if rc["type"] in ("cloudflare_dns_record", "cloudflare_access_rule") else field_changes(rc, {}, after)
            elif acts == ["delete"]:
                kind = "DELETE"
                counts["delete"] += 1
                details = []
                if rc["type"] in RISKY:
                    warnings.append(f"Deleting {label}: {RISKY[rc['type']]}.")
                if rc["type"] == "cloudflare_dns_record" and (before or {}).get("type") in ("MX", "NS", "A", "AAAA", "CNAME"):
                    warnings.append(f"Deleting {label} can stop a website or e-mail from working.")
            elif "delete" in acts and "create" in acts:
                kind = "REPLACE"
                counts["replace"] += 1
                why = ", ".join(".".join(str(s) for s in p) for p in ch.get("replace_paths") or [])
                details = field_changes(rc, before, after) + ([f"replaced because `{why}` cannot be changed in place"] if why else [])
                warnings.append(f"{label} is deleted and recreated; expect a brief gap while it is replaced.")
            else:
                kind = "CHANGE"
                counts["change"] += 1
                details = field_changes(rc, before, after)
            if importing:
                counts["adopt"] += 1
                kind = f"ADOPT + {kind}"
            if rc["address"] in drifted and kind in ("CHANGE", "REPLACE"):
                details = details + ["this undoes the dashboard change listed under 'Changed outside Git'"]
            changes.append((kind, label, details))
    return changes, adopts, warnings, drift, counts


def headline(counts, drift):
    parts = [f"{counts[k]} to {k}" for k in ("add", "change", "delete", "replace") if counts[k]]
    if counts["adopt"]:
        parts.append(f"{counts['adopt']} to adopt")
    if drift:
        parts.append(f"{len(drift)} changed outside Git")
    return ", ".join(parts) if parts else "no changes"


def render(root, changes, adopts, warnings, drift, counts, fmt, drift_only):
    md = fmt == "md"
    out = []
    title = f"Cloudflare {'drift check' if drift_only else 'change summary'}: {root}"
    out.append(f"### {title}" if md else f"=== {title} ===")
    out.append(f"**{headline(counts, drift)}**" if md else headline(counts, drift).upper())
    out.append("")
    if not changes and not adopts and not drift:
        out.append("Nothing will change. Cloudflare already matches the YAML." if not drift_only
                   else "No drift. Cloudflare matches the last apply.")
        return "\n".join(out) + "\n"

    if warnings:
        out.append("#### WARNINGS: read these first" if md else "WARNINGS (read these first)")
        out += [f"- {w}" for w in warnings]
        out.append("")
    if drift:
        out.append("#### Changed outside Git (dashboard or API)" if md else "CHANGED OUTSIDE GIT (dashboard or API)")
        out.append("These were edited in Cloudflare directly since the last apply. "
                   + ("" if drift_only else "Unless the YAML was updated to match, applying this plan puts them back to what the YAML says. ")
                   + "To keep a dashboard change, copy it into the YAML.")
        for kind, label, details in drift:
            out.append(f"- **{label}**" if md else f"- {label}")
            out += [f"  - {d}" for d in details]
        out.append("")
    if changes:
        out.append("#### Will change in Cloudflare" if md else "WILL CHANGE IN CLOUDFLARE")
        for kind, label, details in changes:
            out.append(f"- **{kind}** {label}" if md else f"- {kind:<8} {label}")
            out += [f"  - {d}" for d in details]
        out.append("")
    if adopts:
        out.append("#### Adopt (already in Cloudflare, nothing changes)" if md else "ADOPT (already in Cloudflare, nothing changes)")
        if len(adopts) > 15 and md:
            out.append(f"<details><summary>{len(adopts)} objects</summary>\n")
        out += [f"- {a}" for a in adopts]
        if len(adopts) > 15 and md:
            out.append("\n</details>")
        out.append("")
    return "\n".join(out).rstrip() + "\n"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("plan_json")
    ap.add_argument("--root", default="")
    ap.add_argument("--format", choices=["text", "md"], default="text")
    ap.add_argument("--drift-only", action="store_true", help="report only changes made outside Git")
    a = ap.parse_args()
    with open(a.plan_json, encoding="utf-8") as f:
        plan = json.load(f)
    changes, adopts, warnings, drift, counts = summarise(plan, a.drift_only)
    if a.drift_only and plan.get("resource_changes") and not drift:
        # A -refresh-only plan reports drift as resource_changes in some versions.
        for rc in plan["resource_changes"]:
            if rc["change"]["actions"] not in (["no-op"], ["read"]):
                drift.append(("changed", describe(rc, rc["change"].get("before")),
                              field_changes(rc, rc["change"].get("before"), rc["change"].get("after"))))
    sys.stdout.write(render(a.root, changes, adopts, warnings, drift, counts, a.format, a.drift_only))
    has_change = any(counts[k] for k in ("add", "change", "delete", "replace")) or drift
    sys.exit(2 if has_change else 0)


if __name__ == "__main__":
    main()
