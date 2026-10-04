# Maintaining the repository

## Layout of the code

```
cf.py                    the one CLI entry point (validate/plan/apply/drift/new/export/...)
modules/
  domain-stack/   reads one domain folder and calls every service module
  dns/  waf/  security/  cache/  rules/  zone-settings/  lists/
scripts/
  validate.py            YAML checks with friendly messages (CI and cf.py)
  plan_summary.py        Terraform plan JSON -> plain-English change summary
  export_zone.py         live zone/account -> YAML + imports.tf (read-only)
  yamlio.py              shared YAML loader (line numbers, duplicate keys) and headers
  gen_template.py        writes the documentation headers in domains/_template
  gen_rules_schema.py    provider schema -> scripts/data/ruleset_rule_schema.json
  compliance_audit.py    scores the YAML against docs/Cloudflare_*_Audit.docx -> a Word report
tests/
  test_validate.py, test_export.py, test_plan_summary.py   unit tests
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
checks that the drift check, the PR summary (including the *undoes the
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

`docs/Cloudflare_Account_Audit.docx` and `docs/Cloudflare_Zone_Audit.docx`
are manual audit checklists. `scripts/compliance_audit.py` grades the
controls that can be answered from this repo's YAML (DNS, TLS, WAF, rate
limiting, bots, cache, origin and a few IaC-process controls) and writes a
Word report. Controls that need a live Cloudflare/GitHub check, an origin
probe, or a Terraform module this repo doesn't have are listed in the
report's appendix instead of being guessed at.

```bash
pip install python-docx   # not in requirements.txt; only this script needs it
python3 scripts/compliance_audit.py                 # every domain + account -> .audit/audit-report.docx
python3 scripts/compliance_audit.py example.com      # one domain + account
python3 scripts/compliance_audit.py --live           # also runs `cf.py drift` per root (needs credentials)
```

When a new control type becomes answerable from the YAML (a new module, a
new field), move it from `NOT_EVALUATED` into an `audit_domain`/
`audit_account` check in the same file.

## Changing plan limits

Limits live in two places: `scripts/validate.py` (`LIMITS`, `RL_*`,
`BOT_FIELDS`) and `modules/waf/main.tf` / `modules/rules/main.tf`. Update
both, with a link to the Cloudflare page in [references](references.md).

## Adding a service

1. Create `modules/<service>/` (variables, resources, `versions.tf`).
2. Read its YAML in `modules/domain-stack/main.tf` (add the path to
   `local.files`) and call the module.
3. Add the file's header to `scripts/gen_template.py` and run it.
4. Add checks to `scripts/validate.py`.
5. Export it in `scripts/export_zone.py`, with import addresses that match
   the resource addresses exactly, and add a fixture to
   `tests/fixtures/zone_api.json`.
6. Teach `scripts/plan_summary.py` a readable label in `describe()`.
7. Document it in [20 Service reference](20-services.md).

If it is just another ruleset phase, steps 1 and 2 are one line each:
`local.services` in `modules/rules/main.tf` and `local.rule_files` in
domain-stack (plus `RULE_FILES` in the validator and exporter).
