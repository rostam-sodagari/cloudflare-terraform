# Maintaining the repository

*Who this is for: maintainers changing the Terraform, scripts, or CI, not the YAML.*

## Layout of the code

| Area | Key files | Responsibility |
|---|---|---|
| CLI and workflow | `cf.py`, `scripts/workflow/` | Command parsing, Terraform execution, backend setup, plan integrity and guarded resync |
| Terraform modules | `modules/` | Account- and zone-scoped resource definitions |
| Validation | `scripts/validate.py`, `scripts/validation/` | YAML, schema, cross-file, policy, and plan-limit checks |
| Configuration data | `scripts/config.py`, `policy.yaml` | Limits, patterns, known settings, and policy severity |
| Plan reporting | `scripts/plan_summary.py` | Converts Terraform JSON into reviewer-friendly summaries |
| Export | `scripts/export_zone.py`, `scripts/exporting/` | Read-only API collection, conversion and validated publication |
| Audit | `scripts/compliance_audit.py`, `scripts/audit/` | Static domain/account controls and Word rendering |
| Resync entry point | `scripts/deviation_autofix.py` | Compatibility entry point for `scripts/workflow/resync.py` |
| Repository paths | `scripts/repository_paths.py` | Locates each checkout or temporary copy without depending on package depth or working directory |
| Shared YAML support | `scripts/yamlio.py` | Headers, duplicate-key detection, and line-aware loading |
| Tests | `tests/` | Unit tests, fixtures, and the end-to-end workflow test |

## Running the tests

```bash
python3 -m pip install -r requirements-test.txt  # pinned unit/report dependencies
python3 cf.py unit           # validator, exporter, summary (seconds, no Terraform)
python3 cf.py test-all       # mocked account/domain plans and module lifecycle tests
python3 tests/e2e/run.py     # full cycle against a local stand-in API (needs Terraform)
```

The end-to-end test applies `domains/example.com` to a local stand-in for
the Cloudflare API, makes "dashboard" edits behind Terraform's back, and
checks that the deviation check, the PR summary (including the *undoes the
dashboard change* markers) and the confirmation guard all behave. It also
proves that re-planning right after an apply shows no changes.
It also verifies that direct Terraform plans reject malformed or wrong-shaped
YAML. CI runs on Python 3.12; use that version for reproducible dependency and
CLI contract checks.

## Changing the per-file instructions

The comments at the top of every YAML file come from
`scripts/gen_template.py`. Edit the text there, then:

```bash
python3 scripts/gen_template.py
```

New and exported domains pick up the new headers. To refresh the
instructions in existing domains too (their data is kept), name them:

```bash
python3 scripts/gen_template.py domains/example.com domains/example.org
```

Open a PR: the change summary must say *Nothing will change*, because only
comments moved.

## Upgrading the Cloudflare provider

1. Change `~> 5.26` in every `providers.tf` and `modules/*/versions.tf`.
2. Regenerate the rule schema so the validator and exporter know the new
   fields:

   ```bash
   terraform -chdir=domains/example.com init -backend=false -upgrade
   terraform -chdir=domains/example.com providers schema -json > /tmp/schema.json
   python3 scripts/gen_rules_schema.py /tmp/schema.json
   ```

3. Read the provider changelog for the resources used here
   (`cloudflare_dns_record`, `cloudflare_ruleset`, `cloudflare_zone_setting`,
   `cloudflare_zone_dnssec`, `cloudflare_bot_management`,
   `cloudflare_access_rule`, `cloudflare_tiered_cache`,
   `cloudflare_argo_tiered_caching`, `cloudflare_list`).
4. Run all tests, open a PR. Because `modules/` changed, CI plans every
   domain: each summary must say *Nothing will change*.

## Compliance audit report

`scripts/compliance_audit.py` grades this repo's YAML (DNS, TLS, WAF,
rate limiting, bots, cache, origin and a few IaC-process controls)
against a Cloudflare best-practice checklist and writes a Word report.
The control catalog (every ID, severity, and evaluator) lives in the
script itself, not in a separate document. Controls that need a live
Cloudflare/GitHub check, an origin probe, or a Terraform module this repo
doesn't have are listed in the report's appendix instead of being guessed
at.

```bash
python3 -m pip install -r requirements-test.txt  # includes the report dependencies
python3 scripts/compliance_audit.py                 # every domain + account -> .audit/audit-report.docx
python3 scripts/compliance_audit.py example.com      # one domain + account
python3 scripts/compliance_audit.py --live           # also runs `cf.py deviation-check` per root (needs credentials)
```

When a new control type becomes answerable from the YAML (a new module, a
new field), move it from `NOT_EVALUATED` into an `audit_domain`/
`audit_account` check in the same file.

## Adding a policy check

1. Add the check's logic at the point it belongs (`scripts/validation/dns.py`,
   `security.py`, `settings.py`, `waf.py`, ...), firing through
   `ctx.flag("check_id", path, msg, hint)` instead of `ctx.warn(...)`.
2. Add `"check_id": (description, default_severity)` to `CATALOG` in
   `scripts/validation/policy.py`.
3. Add a line for it in `policy.yaml` (not required -- a check left out
   keeps its `CATALOG` default -- but it keeps the file a complete,
   readable list of everything that's checked).
4. Document it in the table in [40 Policy](40-policy.md).

Only use this for a judgment call (something reasonable zones might
deliberately choose differently), not for something that's simply wrong --
that belongs as a plain `ctx.error()`/`ctx.warn()`, which can't be turned
off.

## Changing plan limits

Limits live in `scripts/config.py` (`LIMITS`, `RL_*`, `BOT_FIELDS`) on the validator side,
`modules/waf/main.tf` / `modules/rules/main.tf` on the Terraform side.
Update both, with a link to the Cloudflare page in [references](references.md).

## Adding a service

1. Create `modules/<service>/` (variables, resources, `versions.tf`).
2. Read its YAML in `modules/domain-stack/main.tf` (add the path to
   `local.files`) and call the module.
3. Add the file's header to `scripts/gen_template.py` and run it.
4. Add checks to `scripts/validation/` (the file matching the service's
   concern, e.g. a new `security/` file goes in `security.py`).
5. Export it in `scripts/exporting/services.py` (with compatibility entry points in
   `scripts/export_zone.py`), with import addresses that match
   the resource addresses exactly, and add a fixture to
   `tests/fixtures/zone_api.json`.
6. Teach `scripts/plan_summary.py` a readable label in `describe()`.
7. Document it in [20 Service reference](20-services.md).

If it is just another ruleset phase, steps 1 and 2 are one line each:
`local.services` in `modules/rules/main.tf` and `local.rule_files` in
domain-stack (plus `RULE_FILES` in the validator and exporter).
