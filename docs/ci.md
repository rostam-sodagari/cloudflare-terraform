# CI and approvals

A second user reviews and approves the PR. Merge deploys the approved effects; no additional environment approval is required.
Follow [Setup](setup.md#github-deployment-setup) before enabling production jobs.

## Pull requests

Checks validate YAML, Terraform formatting, mock plans, Python tests, and the local fake-API workflow.
Trusted PRs also get live plans for affected roots. Fork PRs run offline checks without live credentials.
Account planning runs first; roots marked `example: true` are excluded.

Read the summary and download the **review** artifact linked from the PR comment. It contains complete writable before/after values, actions, imports, unknown values, and dashboard coverage. Long comments can be shortened; the artifact is the complete report. Secrets are redacted.
A reviewer with repository write permission, other than the PR author, must approve the current head after its reports were generated. Dismissed, stale, and author approvals do not authorize deployment.

## After merge

1. CI finds the merged PR and its successful PR run and review artifacts.
2. It plans the merged code and compares inputs, live inventory, and every writable effect with the reviewed report.
3. All selected roots must finish planning before account apply begins. Approved roots receive durable pending-operation markers.
4. Apply checks live inventory and a fresh plan again, then applies the saved binary. Domains follow a successful account apply.
5. The apply uses the approver's own Cloudflare token so the audit log names them; see [Personal Cloudflare tokens](setup.md#personal-cloudflare-tokens).
6. A follow-up plan and stable inventory verify convergence. Actual changes and remaining effects are retained even after failure.

Changed dashboard configuration, advanced `main`, different inputs, expired evidence, or different effects stop deployment. Refresh the PR plan and obtain another review. Review artifacts last 14 days; merged apply plans last three days and outcome artifacts seven days.
Direct pushes, including dashboard resync commits, do not authorize Cloudflare writes. Manual runs can retry an eligible merged revision; they cannot approve new restoration changes. Restore through a reviewed PR.

## Dashboard detection

`deviation-detection.yml` runs hourly, including weekends. It combines Terraform drift with configuration inventory, so newly created dashboard objects can be detected too.
Supported changes are mirrored to `main` after validation and state-only reconciliation. Observation-only changes remain in a review issue. An incomplete deployment blocks resync until recovery.
Deployment and resync workflows share concurrency; Terraform backend locks and a conditional R2 operation journal provide additional coordination. See [Operations](operations.md#automatic-resync).

## Optional change-request gate

With `FRESHSERVICE_DOMAIN` set, supply `freshservice-api-key` in the production vault and put `Change-Ref: CHG-00123` in the PR description. The numeric suffix must identify the API change ID. Manual runs may supply `change_ref`.
The gate reads that exact change, checks its ID and approval status, and validates its timezone-aware planned window. Test the mapping and approval values against your tenant before enabling it. API reference: [Freshservice](https://api.freshservice.com/).

## Access and evidence

Keep Terraform versions aligned across workflows and commit provider lock files.
Plan binaries, Terraform state, API inventories, and outcome artifacts can contain sensitive configuration. Restrict repository, artifact, and R2 access; Terraform sensitivity does not encrypt these files.
Deployment status is stored at `operations/<root>.json` in the state bucket. It contains operation metadata and configuration hashes, not raw configuration values.
