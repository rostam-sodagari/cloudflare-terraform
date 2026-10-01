#!/usr/bin/env python3
"""
Regenerate scripts/data/ruleset_rule_schema.json from the Cloudflare
provider schema. Run after upgrading the provider version:

    terraform -chdir=domains/<any> init -backend=false
    terraform -chdir=domains/<any> providers schema -json > /tmp/schema.json
    python3 scripts/gen_rules_schema.py /tmp/schema.json

The JSON lists every field a ruleset rule may contain, so the validator and
exporter can catch typos and drop API-only fields.
Leaf = type string, with allowed values appended as "string|a,b,c" when the
provider documents them; {...} = object; {"__list__": {...}} = list of
objects; {"__map__": {...}} = map of objects.
"""
import json
import re
import sys
from pathlib import Path


def walk(attrs):
    out = {}
    for name, a in attrs.items():
        if a.get("computed") and not (a.get("optional") or a.get("required")):
            continue
        nt = a.get("nested_type")
        if nt:
            inner = walk(nt["attributes"])
            mode = nt["nesting_mode"]
            out[name] = inner if mode == "single" else {f"__{'map' if mode == 'map' else 'list'}__": inner}
        else:
            t = a.get("type")
            t = t if isinstance(t, str) else json.dumps(t)
            m = re.search(r"Available values: (.+?)\.?$", a.get("description", ""), re.S)
            if m:
                vals = re.findall(r'"([^"]+)"', m.group(1))
                if vals:
                    t += "|" + ",".join(vals)
            out[name] = t
    return out


def main():
    src = json.load(open(sys.argv[1]))
    res = list(src["provider_schemas"].values())[0]["resource_schemas"]["cloudflare_ruleset"]
    rule = res["block"]["attributes"]["rules"]["nested_type"]["attributes"]
    version = list(src["provider_schemas"].keys())[0]
    out = {"_source": f"{version} cloudflare_ruleset.rules", "rule": walk(rule)}
    dest = Path(__file__).parent / "data" / "ruleset_rule_schema.json"
    dest.write_text(json.dumps(out, indent=1, sort_keys=True) + "\n")
    print(f"wrote {dest}")


if __name__ == "__main__":
    main()
