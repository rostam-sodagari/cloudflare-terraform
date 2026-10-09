# Maintaining the repository

*Who this is for: maintainers changing the Terraform, scripts, or CI, not the YAML.*

## Layout of the code

```
cf.py                    the one CLI entry point (validate/plan/apply/deviation-check/new/export/...)
policy.yaml              best-practice checks: on/off, warning/error (see 40-policy.md)
modules/
  domain-stack/   reads one domain folder and calls every zone-scoped service module
  dns/  waf/  security/  cache/  rules/  zone-settings/        zone-scoped (domain-stack calls these)
  certificates/  email-routing/                                zone-scoped (domain-stack calls these)
  lists/  account-waf/  logpush/  notifications/                account-scoped (account/main.tf calls these)
  registrar/  governance/  turnstile/                          account-scoped (account/main.tf calls these)
scripts/
  validate.py            thin entry point -- the checks live in validation/
  config/                plan limits, regex patterns, known-settings tables, and
                          best-practice thresholds (DKIM key size, deprecated TLS, OWASP
                          levels, ...) used by validation/ -- the numbers, not the checks
  validation/            YAML checks with friendly messages (CI and cf.py), split by concern:
    common.py              Report/Ctx, generic checks, Ctx.flag() (policy-gated); re-exports config/
    policy.py               loads policy.yaml; CATALOG is every known policy check
    dns.py  waf.py  rules.py  security.py  settings.py  account.py  domain.py  cli.py
  plan_summary.py        Terraform plan JSON -> plain-English change summary
  export_zone.py         live zone/account -> YAML + imports.tf (read-only)
  deviation_autofix.py   re-export + validate + commit a drifted root (CI only, see 14-deviation-detection.md)
  yamlio.py              shared YAML loader (line numbers, duplicate keys) and headers
  gen_template.py        writes the documentation headers in domains/_template
  backfill_record_docs.py  one-off: add placeholder ## doc blocks to an existing domain (see 41-record-documentation.md)
  gen_rules_schema.py    provider schema -> scripts/data/ruleset_rule_schema.json
  compliance_audit.py    scores the YAML against a Cloudflare best-practice checklist -> a Word report
tests/
  test_validate.py, test_policy.py, test_export.py, test_plan_summary.py   unit tests
  fixtures/zone_api.json                                   recorded API responses
  e2e/run.py, e2e/fake_cloudflare.py                       end-to-end test
```

## Running the tests

```bash
python3 cf.py unit           # validator, exporter, summary (seconds, no Terraform)
python3 cf.py test-all       # validate + offline plan of every domain with a mocked provider
python3 tests/e2e/run.py     # full cycle against a local stand-in API (needs Terraform)
```

The end-to-end test applies `domains/example.com` to a local stand-in for
the Cloudflare API, makes "dashboard" edits behind Terraform's back, and
checks that the deviation check, the PR summary (including the *undoes the
dashboard change* markers) and the confirmation guard all behave. It also
proves that re-planning right after an apply shows no changes.

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
pip install python-docx   # not in requirements.txt; only this script needs it
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

Limits live in two places: `scripts/config/limits.py` (`LIMITS`, `RL_*`)
and `scripts/config/bot.py` (`BOT_FIELDS`) on the validator side,
`modules/waf/main.tf` / `modules/rules/main.tf` on the Terraform side.
Update both, with a link to the Cloudflare page in [references](references.md).

## Adding a service

1. Create `modules/<service>/` (variables, resources, `versions.tf`).
2. Read its YAML in `modules/domain-stack/main.tf` (add the path to
   `local.files`) and call the module.
3. Add the file's header to `scripts/gen_template.py` and run it.
4. Add checks to `scripts/validation/` (the file matching the service's
   concern, e.g. a new `security/` file goes in `security.py`).
5. Export it in `scripts/export_zone.py`, with import addresses that match
   the resource addresses exactly, and add a fixture to
   `tests/fixtures/zone_api.json`.
6. Teach `scripts/plan_summary.py` a readable label in `describe()`.
7. Document it in [20 Service reference](20-services.md).

If it is just another ruleset phase, steps 1 and 2 are one line each:
`local.services` in `modules/rules/main.tf` and `local.rule_files` in
domain-stack (plus `RULE_FILES` in the validator and exporter).
