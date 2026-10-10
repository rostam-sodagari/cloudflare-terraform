"""Publish collected exports while preserving existing staging and validation."""
import datetime as dt
import shutil
import sys
import json
import tempfile
from pathlib import Path
from .client import NotFound
from .config import RULE_SCHEMA
from .converters import custom_rule_fields, rate_limit_fields, list_item_fields, clean
from .output import prepare_dest, write_imports
from .services import ZoneExport
from yamlio import dump_with_header, header_of
from workflow.files import COPY_EXCLUDES, configuration_transaction, confined_path


def export_zone(client, a, *, repository_root, template_dir, validator):
    cli_args = a
    zone = client.result(f"/zones/{cli_args.zone_id}")
    if zone["name"] != cli_args.domain:
        sys.exit(f"Zone {cli_args.zone_id} is {zone['name']}, not {cli_args.domain}. Check the Zone ID.")
    plan = cli_args.plan or {"pro": "pro", "business": "business", "enterprise": "enterprise"}.get(
        (zone.get("plan") or {}).get("legacy_id"), "free")
    # deviation_autofix.py stages a resync elsewhere instead of rebuilding this.
    dest = getattr(cli_args, "dest", None) or repository_root / "domains" / cli_args.domain
    xdir = repository_root / ".export" / cli_args.domain
    xdir.mkdir(parents=True, exist_ok=True)

    print(f"Exporting {cli_args.domain} ({plan} plan). Nothing in Cloudflare is changed.")
    ex = ZoneExport(client, cli_args.zone_id, cli_args.domain, plan)
    ex.run()  # all API reads, nothing written to disk yet -- safe to fail before here

    # Only now touch disk: back up/remove the old folder, then start from
    # the template so every file exists with its documentation, and put
    # the exported data under each file's header. Doing this only after a
    # successful ex.run() means a failed export never leaves dest deleted
    # with nothing to replace it.
    prepare_dest(dest, cli_args.force, xdir)
    shutil.copytree(template_dir, dest)
    (dest / "README.md").unlink(missing_ok=True)
    stamp = dt.date.today().isoformat()
    marker = f"--- Exported from Cloudflare on {stamp}. Your data starts below this line. ---"
    for tpl in sorted(template_dir.rglob("*.yaml")):
        relpath = tpl.relative_to(template_dir).as_posix()
        if relpath != "domain.yaml" and relpath in ex.files:
            dump_with_header(dest / relpath, ex.files[relpath], header_of(tpl), marker)
    dump_with_header(dest / "domain.yaml", {"name": cli_args.domain, "zone_id": cli_args.zone_id, "plan": plan, "owner": "change-me"},
                     header_of(template_dir / "domain.yaml"))
    write_imports(dest / "imports.tf", ex.imports)
    (dest / ".exported-files.json").write_text(json.dumps(sorted(ex.files)), encoding="utf-8")

    report = [f"# Export report: {cli_args.domain}", "", f"Exported {stamp}, plan **{plan}**, zone `{cli_args.zone_id}`.", "",
              "## Exported", ""]
    report += [f"- {field_name}: {field_value}" for field_name, field_value in sorted(ex.counts.items())] or ["- nothing"]
    report += ["", f"{len(ex.imports)} objects will be adopted (see imports.tf).", "", "## Needs a look", ""]
    report += [f"- {note}" for note in ex.notes] or ["- nothing"]
    report += ["", "## Next steps", "", "1. Read the notes above.",
               f"2. `python3 cf.py plan {cli_args.domain}`.",
               "3. The change summary must show only *adopt* lines: nothing created, changed or deleted.",
               "4. Open a pull request. After merge and approval, the apply only adopts.",
               "5. Delete imports.tf in a follow-up pull request."]
    (xdir / "EXPORT_REPORT.md").write_text("\n".join(report) + "\n", encoding="utf-8")

    print(f"\nExported to domains/{cli_args.domain}/")
    for field_name, field_value in sorted(ex.counts.items()):
        print(f"  {field_name}: {field_value}")
    print(f"  Objects to adopt: {len(ex.imports)}")
    for note in ex.notes:
        print(f"  NOTE: {note}")
    print(f"Report: .export/{cli_args.domain}/EXPORT_REPORT.md")
    exit_code = validator(dest)
    print(f"\nNext: python3 cf.py plan {cli_args.domain}")
    return exit_code


def export_account(client, a, *, repository_root, validator):
    """Validate a complete candidate before publishing account configuration."""
    account_dir = Path(getattr(a, "dest", None) or repository_root / "account")
    with tempfile.TemporaryDirectory(prefix="account-export-") as workspace:
        candidate = Path(workspace) / "account"
        shutil.copytree(account_dir, candidate, ignore=shutil.ignore_patterns(*COPY_EXCLUDES))
        exit_code = _write_account(client, a, candidate, validator)
        if exit_code != 0:
            return exit_code
        with configuration_transaction(account_dir):
            for source in candidate.rglob("*"):
                if source.is_file() and source.suffix in {".yaml", ".yml", ".tf"}:
                    target = confined_path(account_dir, source.relative_to(candidate))
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(source, target)
    return 0


def _write_account(client, a, account_dir, validator):
    cli_args = a
    lists_by_kind = {"ip": {}, "asn": {}, "hostname": {}, "redirect": {}}
    imports, notes = [], []
    print("Exporting account lists. Nothing in Cloudflare is changed.")
    _collect_account_lists(client, cli_args.account_id, lists_by_kind, imports, notes)

    waf_files = _collect_account_waf(client, cli_args.account_id, imports, notes)

    logpush_jobs = _collect_account_logpush(client, cli_args.account_id, imports)
    if logpush_jobs is None:
        notes.append("Logpush could not be read with this token; existing settings/logpush.yaml was preserved.")

    headers = {field_name: header_of(account_dir / "lists" / f"{field_name}.yaml") for field_name in lists_by_kind}
    account_header = header_of(account_dir / "account.yaml")
    stamp = dt.date.today().isoformat()
    marker = f"--- Exported from Cloudflare on {stamp}. Your data starts below this line. ---"
    dump_with_header(account_dir / "account.yaml", {"account_id": cli_args.account_id, "plan": cli_args.plan or "enterprise"}, account_header)
    for kind, lists in lists_by_kind.items():
        dump_with_header(account_dir / "lists" / f"{kind}.yaml", lists, headers[kind],
                         marker if lists else None)
    for rel, data in waf_files.items():
        dump_with_header(account_dir / rel, data, header_of(account_dir / rel), marker if data else None)
    if logpush_jobs is not None:
        dump_with_header(account_dir / "settings" / "logpush.yaml", logpush_jobs,
                         header_of(account_dir / "settings" / "logpush.yaml"), marker if logpush_jobs else None)
    write_imports(account_dir / "imports.tf", imports)
    print(f"Exported {sum(len(field_value) for field_value in lists_by_kind.values())} list(s), "
          f"{sum(len(field_value) for field_value in waf_files.values())} account WAF rule(s), {len(logpush_jobs or {})} Logpush job(s).")
    notes.append("Notification policies (settings/notifications.yaml) are not exported yet -- "
                 "set them up by hand here if you have existing ones in the dashboard.")
    if not cli_args.plan:
        print("  NOTE: set plan: in account/account.yaml to the highest plan in the account (used for limit checks).")
    for note in notes:
        print(f"  NOTE: {note}")
    exit_code = validator(account_dir)
    print("\nNext: python3 cf.py plan account")
    return exit_code


def _collect_account_lists(client, account_id, out, imports, notes):
    lists_by_kind = out
    for account_list in client.result(f"/accounts/{account_id}/rules/lists"):
        items, cursor = [], None
        while True:
            params = {"per_page": 500}
            if cursor:
                params["cursor"] = cursor
            body = client.get(f"/accounts/{account_id}/rules/lists/{account_list['id']}/items", params)
            items += body["result"] or []
            cursor = ((body.get("result_info") or {}).get("cursors") or {}).get("after")
            if not cursor:
                break
        kind = account_list["kind"]
        converted_items = list_item_fields(kind, items)
        entry = {"description": account_list["description"]} if account_list.get("description") else {}
        entry["items"] = converted_items
        lists_by_kind.setdefault(kind, {})[account_list["name"]] = entry
        imports.append((f'module.lists.cloudflare_list.this["{account_list["name"]}"]', f"{account_id}/{account_list['id']}"))
    try:
        ruleset = client.result(f"/accounts/{account_id}/rulesets/phases/http_request_redirect/entrypoint")
        if ruleset.get("rules"):
            imports.append(("module.lists.cloudflare_ruleset.bulk_redirects[0]", f"accounts/{account_id}/{ruleset['id']}"))
            notes.append("Existing Bulk Redirect rules are replaced by one generated rule per redirect list; "
                         "the plan shows this as a change to review.")
    except NotFound:
        pass


def _collect_account_waf(client, account_id, imports, notes):
    def account_entrypoint(phase):
        try:
            ruleset = client.result(f"/accounts/{account_id}/rulesets/phases/{phase}/entrypoint")
        except NotFound:
            return None
        return ruleset if ruleset.get("rules") else None

    # Successful empty reads/404 are authoritative, unlike permission errors.
    waf_files = {"waf/custom-rules.yaml": [], "waf/rate-limits.yaml": [], "waf/managed-rules.yaml": {}}
    ruleset = account_entrypoint("http_request_firewall_custom")
    if ruleset:
        out_rules = []
        for api_rule in ruleset["rules"]:
            rule = custom_rule_fields(api_rule, include_skip_logging=True)
            out_rules.append(rule)
        waf_files["waf/custom-rules.yaml"] = out_rules
        imports.append(("module.account_waf.cloudflare_ruleset.custom[0]", f"accounts/{account_id}/{ruleset['id']}"))

    ruleset = account_entrypoint("http_ratelimit")
    if ruleset:
        out_rules = []
        for api_rule in ruleset["rules"]:
            rule = rate_limit_fields(api_rule, include_zone_fields=True)
            out_rules.append(rule)
        waf_files["waf/rate-limits.yaml"] = out_rules
        imports.append(("module.account_waf.cloudflare_ruleset.rate_limit[0]", f"accounts/{account_id}/{ruleset['id']}"))

    ruleset = account_entrypoint("http_request_firewall_managed")
    if ruleset:
        dropped = []
        raw = [clean(api_rule, RULE_SCHEMA, f"account managed #{item + 1}", dropped) for item, api_rule in enumerate(ruleset["rules"])]
        waf_files["waf/managed-rules.yaml"] = {"raw_rules": raw}
        imports.append(("module.account_waf.cloudflare_ruleset.managed[0]", f"accounts/{account_id}/{ruleset['id']}"))
        if dropped:
            notes.append(f"account/waf/managed-rules.yaml: fields not supported by the provider were left out: {', '.join(dropped)}.")

    return waf_files


def _collect_account_logpush(client, account_id, imports):
    logpush_jobs = {}
    try:
        for job in client.result(f"/accounts/{account_id}/logpush/jobs"):
            name = job.get("name") or f"job_{job['id']}"
            entry = {"dataset": job["dataset"], "destination_conf": job["destination_conf"]}
            if not job.get("enabled", True):
                entry["enabled"] = False
            for field_name in ("filter", "frequency", "logpull_options"):
                if job.get(field_name):
                    entry[field_name] = job[field_name]
            logpush_jobs[name] = entry
            imports.append((f'module.logpush.cloudflare_logpush_job.this["{name}"]', f"accounts/{account_id}/{job['id']}"))
    except NotFound:
        pass
    except PermissionError:
        return None  # unreadable is not an empty service; preserve existing YAML

    return logpush_jobs
