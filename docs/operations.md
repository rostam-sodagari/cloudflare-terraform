# Operations

These tasks need maintainer access. Live plans and exports also need [credentials](setup.md#credentials).
Use `account` wherever a command accepts a root and you want account-wide resources.

## Add a domain

The zone must already exist in Cloudflare; this repository does not create zones.
For a new or empty zone:

```sh
python cf.py new example.org --zone-id YOUR_ZONE_ID --plan pro
```

This copies the template with commented samples and a domain-specific `README.md`.
Set the owner in `domain.yaml`, then follow that README to add, validate, plan, and deploy the services you need.
The `plan` value must match the zone's subscription: `free`, `pro`, `business`, or `enterprise`.
For a populated zone, use the adoption procedure below.

## Adopt an existing zone

Adoption brings existing objects into Terraform state. It should leave their live configuration unchanged.

1. Arrange a pause in dashboard edits during adoption.
2. Export account resources first if the zone uses account lists.
3. Export the zone and review the export report.
4. Plan and resolve unexpected additions, deletions, or changes.
5. Open a PR, review the adoption plan, and deploy through CI.

```sh
python cf.py export-account --account-id YOUR_ACCOUNT_ID --plan pro
python cf.py plan account
python cf.py export example.org --zone-id YOUR_ZONE_ID
python cf.py plan example.org
```

Use the account's highest zone plan for `export-account`.
Export reads Cloudflare and writes local YAML, import blocks, and a report under `.export/`.
It does not modify live resources. Zone export refuses an existing folder unless `--force` is given; forced export backs up the old folder first.

An adoption plan should contain **Adopt** entries. Investigate any **Add**, **Delete**, **Replace**, or **Adopt + Change** entry before applying.
Bulk Redirect export generates rules per list and can produce changes to an existing deployment; review those explicitly.
Use [Services](services.md#export-coverage) for export gaps.

After successful adoption, remove `imports.tf` in a follow-up PR. Its plan should show no changes.
Set the zone owner in `domain.yaml`.

## State backends

R2 is the default and is used in CI. Local state is for a sandbox that nobody else manages:

```sh
python cf.py plan example.org --backend local
python cf.py apply example.org
```

Apply infers the backend from the saved plan when no environment override is set.
Local state lives under `.state/`; back it up and keep it out of Git.
Do not use separate local and R2 state files to manage the same resources.

To move existing state, use migration rather than reinitializing against an empty backend:

```sh
python cf.py migrate example.org --to r2
python cf.py plan example.org --backend r2
```

Use `--to local` for the reverse direction. Terraform prompts before copying state.
Check the resulting plan before applying anything.

## Dashboard changes

A deviation is a live change to a managed object since the last apply.
To inspect it without changing Cloudflare:

```sh
python cf.py deviation-check example.org --deviation-exit
```

Exit code `0` means no deviation, `2` means deviation exists, and other failures need investigation.
Without `--deviation-exit`, a successful check exits `0` even when it reports deviation.

Supported live changes are adopted automatically by the scheduled workflow. To restore earlier configuration, open a PR with the desired YAML and have a second user approve its live plan.
After an emergency dashboard fix, tell anyone with a pending deployment so they do not overwrite it.

### Automatic resync

The scheduled workflow checks non-example roots hourly, including weekends. It compares managed state and a configuration inventory, including objects added outside Terraform.
Supported changes are exported, validated, and committed directly to `main`. This dashboard-to-Git path is intentionally automatic; it does not write changes back to Cloudflare. A `deviation` issue records the result.

The reconciliation sequence is:

1. Capture complete API inventory, current state identities, and the starting Git revision.
2. Stage exported YAML and imports, preserving stable keys for existing IDs, then validate.
3. Check that live configuration stayed unchanged.
4. Apply a refresh-only plan to update state and forget remotely deleted objects.
5. Import new objects and move renamed bindings only when the plan contains no Cloudflare mutations. An already-disabled Email Routing settings binding can be forgotten without sending another disable request.
6. Check another plan and inventory, remove temporary imports, and publish YAML plus hash and identity metadata.

A plan that would create, update, replace, or delete live objects stops reconciliation. Unreadable services stop automation; 404s remain distinct from successful empty reads. Observation-only changes stay visible in an issue and do not repeatedly trigger exports.

Before state reconciliation begins, failures restore the previous local configuration. Once state operations begin, the candidate and checkpoints are retained for recovery. A rejected push can leave state reconciled while `main` is unchanged; retain the artifact, fetch the latest branch, and rerun from a fresh snapshot. Never force-push to recover.

Direct pushes need a bot identity permitted by the repository's branch rules. Supply its `DEVIATION_BOT_TOKEN` in the `plan` environment; checkout uses it for Git pushes. Configure and test that access with a repository administrator; the default Actions token is the fallback and may not bypass protection.
To keep detection but disable automatic commits, remove the **Auto-fix** step and its unused `contents: write` permission from `deviation-detection.yml`.

The standalone helper requires a clean checkout at the current target branch revision and also commits and pushes:

```sh
python scripts/deviation_autofix.py example.org
```

## Stop managing a resource

Removing YAML normally deletes managed objects. To leave an object in Cloudflare, a maintainer removes its state entry and its YAML entry as one coordinated change.

```sh
python cf.py init example.org
terraform -chdir=domains/example.org state list
```

Back up state, find the exact address, then coordinate `terraform state rm` for that address with the YAML change and its reviewed PR. State removal itself does not delete the Cloudflare object.
Check a new plan before continuing. Removing a domain folder alone does not delete the Cloudflare zone, but can leave its managed resources and state behind.

## Failed or interrupted deployment

Inspect the deployment artifact: apply output, actual changed services, remaining planned effects, and state lineage/serial. A failed apply can leave some approved changes live; there is no automatic rollback.

```sh
python scripts/operations.py status example.org
```

The R2 journal records `approved-pending`, `applying`, reconciliation, failure, and completion. Detection keeps unfinished operations visible and prevents resync from replacing unfinished PR intent with a partial live configuration. A crashed GitHub run must be confirmed completed before another operation can recover it.

For a failed apply, open a recovery PR against current `main`. Keep or adjust the intended YAML, rerun its live plans, and obtain a second user's approval after the failure. Merge deploys the newly reviewed remaining effects. If the desired YAML is already on `main`, a small explanatory YAML comment in that root selects a fresh PR plan without changing its desired values. Do not clear the journal to bypass this review.

For failed state-only resync, inspect retained checkpoints and candidate YAML, save the retained evidence, resolve branch or export issues, then rerun the state-only resync helper from a clean checkout of the latest target branch. Scheduled detection reports the unresolved failure instead of repeatedly retrying it. Do not restore old state blindly or run an ordinary apply to finish a dashboard resync.

Pause dashboard writes during deployment and adoption. Inventory reads and preflight catch changes at observation points; they cannot make multiple Cloudflare API writes atomic. Out-of-band Terraform runs and dashboard edits during the actual apply require operational coordination.
