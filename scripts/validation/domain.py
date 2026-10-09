"""domain.yaml and the per-domain entry point that calls every service
validator (dns/waf/rules/security/settings)."""
from .common import HEX32, PLANS, ROOT, Ctx, check_enum, check_fields, check_host, load
from .dns import validate_dns
from .rules import validate_rule_files
from .security import validate_security
from .settings import validate_settings
from .waf import validate_waf


def validate_domain(report, d, list_names):
    f = d / "domain.yaml"
    data, lines = load(report, f)
    if data is None:
        report.add("error", f, 1, "domain.yaml is missing or empty.", "copy it from domains/_template")
        return
    if data == "ERROR":
        return
    ctx = Ctx(report, f, lines, None)
    if not check_fields(ctx, (), data, {"name": "str", "zone_id": "str", "plan": "str", "owner": "str", "example": "bool"},
                        ["name", "zone_id", "plan"]):
        return
    name, zid, plan = data.get("name"), data.get("zone_id"), data.get("plan")
    if isinstance(zid, str) and not HEX32.match(zid):
        ctx.error(("zone_id",), "zone_id must be the 32-character Zone ID (lowercase letters a-f and digits).",
                  "copy it from the zone's Overview page in Cloudflare")
    if isinstance(name, str):
        check_host(ctx, ("name",), name, "domain name")
        if name != d.name and d.name != "_template":
            ctx.error(("name",), f"name '{name}' does not match the folder name '{d.name}'.", "rename one so they match")
    if not check_enum(ctx, ("plan",), plan, PLANS):
        return
    zone = name if isinstance(name, str) else d.name
    refs = {}
    validate_dns(report, d, plan, zone)
    validate_waf(report, d, plan, list_names, refs)
    validate_rule_files(report, d, plan, list_names, refs)
    validate_security(report, d, plan)
    validate_settings(report, d, plan)
    for extra in ("imports.tf",):
        if (d / extra).exists():
            report.add("warning", d / extra, 1, "imports.tf is present: the next apply adopts existing Cloudflare objects.",
                       "delete it after the first successful apply")


def domain_dirs():
    return sorted(p for p in (ROOT / "domains").iterdir() if p.is_dir() and not p.name.startswith("_"))
