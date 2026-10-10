# Development

Use Python 3.12 to match CI. Run commands from the repository root.

## Checks

```sh
python -m pip install -r requirements.txt
python cf.py unit
python cf.py test-all
python tests/e2e/run.py
python cf.py lint
```

Python tests cover validation, exports, plan summaries, CLI contracts, and workflow safeguards.
Terraform tests use mock providers, including example roots copied from `tests/fixtures/domains/` into temporary workspaces.
The end-to-end test uses a local fake API and temporary state; it also checks invalid YAML through direct Terraform plans.
Terraform is required for the last three commands; provider downloads may need network access.

## Code map

| Location | Responsibility |
|---|---|
| `cf.py`, `scripts/workflow/` | CLI, process execution, backends, saved plans, and resync |
| `scripts/validation/` | YAML structure, schema, cross-file, and policy checks |
| `scripts/exporting/` | API reads, conversion, import generation, and publication |
| `scripts/repository_paths.py`, `scripts/yamlio.py` | Checkout resolution and YAML loading |
| `scripts/config.py`, `policy.yaml` | Limits, known fields, and policy settings |
| `scripts/plan_summary.py` | Human-readable Terraform plan summaries |
| `modules/` | Terraform resources |
| `tests/` | Regression fixtures, contract tests, and fake API tests |

Keep existing script entry points and compatibility exports working when reorganizing internals.
Include a regression test for a behavior fix; review intentional golden-output changes.

## Template instructions

Edit zone examples in `scripts/gen_template.py`, additional field guidance in `scripts/template_guidance.py`, or account examples in `scripts/account_templates.py`, then regenerate:

```sh
python scripts/gen_template.py
```

This also refreshes account headers while preserving their active YAML data. Examples stay commented out.
Keep headers short; put longer field explanations in `docs/yaml-fields.md`.

To refresh existing domain headers while retaining data:

```sh
python scripts/gen_template.py domains/example.org
```

Inspect the diff and verify that comment-only edits produce no live changes.

## Provider updates

Update provider constraints in roots and modules, regenerate lock files for CI and developer platforms, and review the provider changelog.
Regenerate the rules schema using the updated provider:

```sh
terraform -chdir=domains/_template init -backend=false -upgrade
terraform -chdir=domains/_template providers schema -json > schema.json
python scripts/gen_rules_schema.py schema.json
```

Remove the temporary `schema.json` after use.
Run the checks above and inspect live plans for affected roots before deploying.

## Add a service or policy

For a service, update the Terraform module and root wiring, template headers, validation, exporter coverage, plan labels, and fixtures together.
Document it in [Services](services.md).

For a configurable policy check, emit `ctx.flag(...)`, register it in `scripts/validation/policy.py`, and add its setting to `policy.yaml`.
Structural errors remain unconditional validation failures.
Limits used by Python and Terraform must stay consistent.
