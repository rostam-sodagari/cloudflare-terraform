# Project review — 10 October 2026

The refactoring passes its existing contracts, but the project still has
functional and safety gaps. Fix those before another structural refactor.
This review changes no production implementation or configuration.

## Scope and verification

Reviewed the Python entry points, validation/export/audit/workflow packages,
Terraform root and service wiring, GitHub Actions workflows, test setup,
dependency declarations, and relevant documentation. Graphify supplied the
architecture/navigation map (952 nodes, 2,181 edges, 44 communities).
Terraform is not indexed by the installed parser, so its wiring was inspected
directly. This is a source review with targeted reproductions, not a live
Cloudflare, R2, Delinea, Freshservice, or GitHub settings audit.

Checks performed during this review:

- **114 unit tests passed**, in 173.550 seconds.
- Repository YAML validation passed with the existing example.net DMARC
  warning about a missing reporting address.
- Terraform formatting and `git diff --check` passed before adding the review
  artifacts; formatting is checked again when the review is finalized.
- Offline probes reproduced malformed-input crashes, accepted replacement
  plan bytes, stale account WAF YAML, omitted account WAF fields, and a resync
  delete target outside `.export`. Recursive deletion was intercepted.
- A provider-free Terraform reproduction returned exit code **0** for
  malformed YAML, decoded to `{}`, with a failed-check warning.
- Simulating the absence of `python-docx` reproduced the Word-contract test's
  `ModuleNotFoundError`.

Logs and reproduction scripts are in ignored `graphify-out/review-*` files
and `graphify-out/review_probes.py`. Mocked Terraform and fake-API E2E passed
in the preceding package migration; they were not rerun for this review.

## Findings, ordered by recommended priority

### 1. P1 — CI does not install the Word test's dependency

Locations: `.github/workflows/cloudflare.yml:48`,
`tests/test_script_contracts.py:105`, `scripts/audit/report.py:8`,
`requirements.txt:1`.

CI installs only `requirements.txt`, which contains PyYAML. The new Word
contract test unconditionally calls `build_report`, which imports `docx`.
On a runner without a separately installed `python-docx`, unit discovery
fails even though the local environment passes all tests. This is a gap
introduced by the expanded test suite.

Fix: declare pinned test/report dependencies in a separate requirements file
and install them in CI. Keep the lightweight runtime dependency file if
report generation is intended to remain optional. Verify in a clean Python
3.12 environment using only the declared dependency files. Pinning the report
dependency also makes the exact Word XML snapshots more reproducible.

### 2. P1 — Reviewed JSON is not bound to the binary actually applied

Locations: `cf.py:172`, `cf.py:184`, `cf.py:333`,
`scripts/workflow/integrity.py:5`.

The saved fingerprint protects source inputs and revision, but hashes neither
`plan.bin` nor `plan.json`. Apply displays and checks destruction using the
JSON, then applies the binary without verifying that they represent the same
plan. Replacing the binary after saving the fingerprint still passes
`check_plan_fingerprint`. A different valid plan for the same state lineage
and serial could therefore be applied with the previous plan's summary and
destruction count. The probe used dummy bytes to verify the guard omission;
it did not attempt to apply them or bypass Terraform's own state checks.

Fix: save and verify digests of the binary and JSON; regenerate JSON from the
verified binary before reviewing/destruction checks. Reject unreadable or
inconsistent artifacts. Add tests where each artifact is changed separately.
These are consistency controls, not signatures against an actor who can
replace every local artifact.

### 3. P1 — Direct Terraform runs can turn malformed YAML into deletions

Locations: `modules/domain-stack/main.tf:49`,
`modules/domain-stack/main.tf:105`, `account/main.tf:23`.

Service decoding uses `try(..., {})` / `try(..., [])`. The domain stack's
parseability assertion is a `check` block, which warns and continues instead
of blocking plan/apply. Account decoding has the same fallback without that
assertion. Malformed files can thus become empty desired configurations and
plan deletion of previously managed resources when Terraform is run directly.
The Python validator protects the normal `cf.py` path; it does not protect
direct Terraform use. The current comment saying direct runs fail is wrong.

Verified with the same decode/check pattern: malformed YAML produced `{}`,
a warning, and plan exit code 0. HashiCorp documents the nonblocking behavior
of [check blocks](https://developer.hashicorp.com/terraform/language/block/check).

Fix: use blocking preconditions or strict decoding with explicit handling of
missing/comment-only files, consistently in account and domain roots. Include
wrong container types as well as syntax errors. Regression tests must require
a nonzero ordinary `terraform plan` exit code, not just a failing Terraform
test assertion.

### 4. P1 — `enabled: false` can enable Email Routing

Location: `modules/email-routing/main.tf:2`.

The resource count tests whether `enabled` is non-null, not whether it is
true. Both true and false create the settings resource; the YAML flag is not
passed into a configurable enabled field. The locked Cloudflare provider
5.27.0 marks enabled as computed, and its Create method calls Enable;
Update is unsupported. On an unmanaged zone, a configuration requesting
disabled routing can therefore enable it. Changing true to false also does
not remove this resource to invoke Disable.

Verified against the pinned provider's
[schema](https://github.com/cloudflare/terraform-provider-cloudflare/blob/v5.27.0/internal/services/email_routing_settings/schema.go)
and [resource implementation](https://github.com/cloudflare/terraform-provider-cloudflare/blob/v5.27.0/internal/services/email_routing_settings/resource.go).
No live routing change was performed.

Fix: define explicit managed-enabled/managed-disabled/unmanaged semantics,
map those to this provider's lifecycle, and test first adoption and both
toggle directions. Explain any unavoidable provider limitations in the
template. Also account for its unsupported Update before promising changes
to `support_subaddress`.

### 5. P2 — Account resync retains WAF rules deleted in Cloudflare

Locations: `scripts/exporting/publish.py:91`,
`scripts/exporting/publish.py:138`.

The account collector omits a WAF file when the live entrypoint is absent or
empty. Publication writes only returned files, leaving previously populated
YAML untouched. The same write-only-if-nonempty pattern affects Logpush.
The probe exported an account with no live WAF and confirmed that a deleted
custom rule remained in its YAML. A later plan can recreate the rule rather
than adopt the dashboard deletion; resync can also report no change.

Fix: distinguish successfully read empty state, 404 absence, unsupported
services, and permission failures. Explicitly clear previously managed
services when absence is authoritative. Never treat unreadable data as empty.
Add nonempty-to-empty resync tests for WAF and Logpush. Check the analogous
zone `copy_yaml` template-skipping behavior under the same policy.

### 6. P2 — Account export silently drops supported rule behavior

Locations: `scripts/exporting/publish.py:152`,
`scripts/exporting/publish.py:161`,
`scripts/exporting/converters.py:143`,
`scripts/exporting/converters.py:158`.

Account calls leave conversion flags at their false defaults. Export drops
skip `logging.enabled: false`, rate-limit `counting_expression`,
`requests_to_origin`, and custom response fields. `modules/account-waf`
supports these fields. The probe supplied them and verified they were absent
from the converted YAML, without an omission warning. Adoption/resync can
therefore change logging, what requests count, and block responses.

Fix: preserve fields supported in both scopes; model actual API differences
explicitly. Add API-to-YAML-to-Terraform semantic tests for these fields. The
current golden fixtures preserve this historical behavior, so deliberately
update the affected contracts when correcting it.

### 7. P2 — Malformed input still crashes validation

Locations: `scripts/validation/checks.py:57`,
`scripts/validation/security.py:63`,
`scripts/validation/security.py:175`,
`scripts/validation/waf.py:80`.

`check_fields` returns true for dictionaries even when child types are wrong.
Several callers then iterate invalid containers or dereference the original
null object. Reproductions:

| YAML | Result |
| --- | --- |
| IP access rules: `bad: null` | AttributeError on `.get` |
| CT alerting: `enabled: true`, `emails: 123` | TypeError iterating an integer |
| Managed WAF: `exceptions: 123` | TypeError iterating an integer |

The functions collect diagnostics first, but the CLI can crash before printing
them. Similar patterns exist in DNS nested lists and account settings.

Fix: guard individual child operations after reporting errors, so independent
checks still run. Do not globally stop every dictionary check after one bad
field, which would remove useful diagnostics. Add a matrix of null/scalar/
list/map inputs at nested boundaries and require clean diagnostic exits.

### 8. P2 — Standalone resync does not confine its paths

Locations: `scripts/workflow/resync.py:181`,
`scripts/workflow/resync.py:250`.

Unlike `cf.py.Rt`, the resync CLI accepts arbitrary root strings and joins
them into live and scratch paths. Absolute paths discard the intended parent;
traversal can also escape it. An intercepted probe showed `_resync_domain`
attempting recursive deletion of an external temporary directory's `resync`
child instead of `.export/<domain>/resync`. No external deletion occurred.
The earlier standalone drift check normally rejects such a name, but an
existing readable deviation report bypasses that check; containment must not
depend on it. The scheduled workflow supplies enumerated roots, so this is
primarily a standalone CLI hazard.

Fix: share the validated root resolver and check resolved containment under
`domains/` and `.export/` before any filesystem mutation, including symlinks.
Test absolute paths and traversal without allowing actual recursive deletion.

### 9. P2 — Failed resync can leave the working configuration changed

Locations: `scripts/workflow/resync.py:226`,
`scripts/workflow/resync.py:269`,
`scripts/exporting/publish.py:87`.

Account publication writes live files before validation. Domain publication
copies staged files into the live folder before documentation/deletion/live
drift guards finish. A later failure stops commit/push but does not restore
the files. This is an established limitation, rather than a newly introduced
package regression. Standalone use can overwrite local work and leave a
failed export as the next plan's input.

Fix: validate a complete candidate configuration in staging for both scopes,
including reinjected documentation and retained settings. Refuse conflicting
local changes, retain a backup, and restore on subsequent guard failure.
Also check `git add` failures and prevent an existing unrelated staged change
from being included by the unrestricted `git commit` call.

## Further improvements

- **Naming:** replace misleading names such as `cli_args` for resource
  addresses in `cf.py.check_destructive`. Use `root`, `config_file`,
  `record`, `rule`, `result`, and `repository_root` in internal helpers;
  remove redundant `a -> cli_args` / `r -> root` aliases where public keyword
  compatibility is unnecessary. Keep public argument changes deliberate.
- **Tests:** copy only needed repository inputs. Current copytree calls carry
  `.venv`, Graphify output, and other generated artifacts into temporary
  repositories; the E2E copy excludes only `.git`. This wastes disk/time and
  can carry local ignored configuration into a supposedly isolated test.
- **Audit input handling:** report invalid YAML separately from missing YAML.
  `audit.common.load` currently collapses parse failure into None and permits
  duplicate keys through `safe_load`, while the validator has stricter loading.
- **Packaging/tooling:** add a small project configuration for supported Python
  versions, formatter/linter settings, and test/report dependencies. Preserve
  established CLI wrappers; there is no immediate need for more folders.
- **CI behavior:** test workflow dependency installation and job conditions,
  including fork PRs, skipped/cancelled account jobs, and domain jobs referencing
  newly introduced account lists. Current Python contracts do not execute
  GitHub Actions. Verify the actual environment reviewer/bypass settings
  separately; those cannot be established from these YAML files.
- **Coverage quality:** the 218-diagnostic corpus and golden snapshots protect
  output compatibility. They do not prove correct behavior for empty live
  services, malformed nested input, provider lifecycle semantics, or artifact
  mismatch. Add targeted behavior tests rather than increasing snapshot size.
- **Documentation:** correct the domain-stack comment claiming empty/missing
  files never delete anything; removing previously managed entries does delete
  resources, as the service guide already explains. Keep that distinction
  consistent across templates, code comments, and runbooks.

## Suggested implementation order

1. Fix declared CI test dependencies and verify on a clean environment.
2. Bind saved plan artifacts together and make direct Terraform parsing block.
3. Correct Email Routing lifecycle behavior with targeted provider tests.
4. Fix account export fidelity and authoritative empty-service handling.
5. Make nested validation robust, then confine and stage resync safely.
6. Finish naming/tooling/test-isolation improvements after behavior is stable.

Keep fixes separate and reviewable. Add a reproduction test for each corrected
behavior, run the affected tests first, then the full unit suite and mocked
Terraform/fake-API checks when their behavior is touched. Regenerate golden
outputs only where a documented bug fix intentionally changes behavior.

## Implementation completed — 10 October 2026

All nine findings above have now been addressed. The original review remains
in this document as the record of what triggered the fixes.

| Finding | Implemented behavior |
| --- | --- |
| CI dependencies | `requirements-test.txt` pins report/test dependencies; CI installs it and changes to dependency files trigger checks. |
| Plan consistency | Metadata includes binary/JSON hashes; apply renders JSON from the binary and compares it to reviewed JSON; unreadable destruction data fails closed. Older saved plans must be recreated. |
| Terraform YAML | Syntax errors propagate; blocking output preconditions reject wrong map/list shapes in account and domain roots. |
| Email Routing | True creates the enabling resource; false removes a previously managed resource. Unsupported subaddress changes are rejected and documented. An unadopted service cannot be disabled by an initially false value. |
| Empty services | Account WAF/Logpush authoritative empty reads clear stale YAML. Zone exports carry a manifest identifying authoritative empty DNS/WAF/rule/IP services. Unreadable Logpush is preserved with a note. |
| Export fidelity | Account exports retain skip logging, rate-limit counting expressions, origin-request toggles, and block responses. |
| Validation robustness | Nested invalid lists and null entries report diagnostics without stopping independent validation; DNS, WAF, security and account regressions are covered. |
| Path containment | Root names are validated, resolved domain/account/scratch paths are confined, and configuration symlink escapes are rejected. The CLI and resync share the resolver. |
| Resync publication | Both scopes validate staged candidates; configuration is restored after guard or commit failure; dirty roots/staged changes are refused; git-add failures stop publication and commits are limited to the root. Successful local commits remain available when only push fails. |

Additional improvements: audit loading rejects syntax/duplicate-key errors;
tests exclude local environments, ignored secrets and generated graph output;
the exporter fixture loads its temporary checkout explicitly rather than
reusing a cached module; misleading resource-address naming was corrected;
templates, their generator, and operational documentation were updated.

Verification of the completed changes:

- **130 tests passed on Python 3.12.14** in a fresh environment installed from
  `requirements-test.txt` (89.252 seconds). The preceding local Python 3.14
  suite also passed before the final two transaction tests were added.
- Clean dependency installation used exactly PyYAML 6.0.2, python-docx 1.2.0
  and lxml 6.1.3. The fresh environment exposed a Python-version difference
  in argparse usage wrapping; help contracts now ignore only usage whitespace
  while retaining exact option and description comparisons.
- Mocked Terraform checks passed for account, example.com and example.net,
  plus **five Email Routing module tests** covering unmanaged, enable,
  disable-after-enable, re-enable and unsupported subaddress behavior.
- Fake-API E2E passed, including **five direct Terraform failure cases** for
  malformed/wrong-shaped account and domain service files.
- YAML validation, Terraform formatting and whitespace checks passed.
  The diagnostic corpus covers **142/142 sites** and intentionally records
  216 diagnostics across 129 cases; invalid list containers no longer emit
  misleading element diagnostics. Export golden updates cover the intended
  field preservation and authoritative empty services; audit/Word snapshots
  remain unchanged.
- Graphify's code map was refreshed to **1,012 nodes and 2,353 edges**. The
  installed graph parser still lacks HCL support; Terraform was verified
  directly rather than inferred from the graph.

Final publication paths also resolve each destination file before copying,
so a nested service-directory link cannot redirect writes outside its root.
The final affected checks passed: 8 resync integration tests and 12 review
regression tests, with one platform skip because this Windows account cannot
create directory symlinks. That symlink test runs on CI's Linux platform.

An exporter-test module-cache defect briefly wrote fixture data into the
working sample account/domain. The test now loads its temporary facade
explicitly; fixture-only data was removed and tracked sample-account YAML
was verified byte-for-byte against its pre-test tracked baseline. There is
no resulting sample-account data change.

No live Cloudflare/R2 changes or project-repository commits/pushes were made.
Both `docs/42-script-refactoring-plan.md` and this review are preserved.
The optional larger tooling/packaging initiative and external GitHub
environment/branch-protection audit remain separate improvement work.
