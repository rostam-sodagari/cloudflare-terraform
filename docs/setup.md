# Setup

Editing through GitHub needs repository access only. Follow this guide if you need local commands or are setting up deployment automation.

## Local tools

Install Git, Python 3.12, and Terraform. Terraform configuration requires 1.10 or later; CI currently uses the 1.16 series.
Python 3.12 matches CI. Check the workflow files when changing these versions.

```sh
python -m pip install -r requirements.txt
python cf.py validate-all
python cf.py help
```

Commands use `python`; use `python3` where required by your installation.

### Windows

Run the same commands in PowerShell. If the tools are missing:

```powershell
winget install Git.Git
winget install Python.Python.3.12
winget install Hashicorp.Terraform
```

Open a new terminal after installation. To copy the backend template:

```powershell
Copy-Item backend.hcl.example backend.hcl
```

On macOS or Linux, use `cp backend.hcl.example backend.hcl`.

## State storage

Shared environments use an R2 bucket. Create the bucket and an R2 key pair with object read/write access scoped to it.
Fill in the bucket and endpoint in `backend.hcl`; the file is ignored by Git.
Keep versioned or independent backups of state objects and test restoration. Before production, test conditional journal writes and Terraform locking against a nonproduction bucket; a failed conditional write must stop the run.

Each domain has `domains/<domain>.tfstate`; account resources use `account.tfstate`.
For a sandbox without R2, use the [local backend](operations.md#state-backends).

## Credentials

Local commands read `CLOUDFLARE_API_TOKEN`. R2 access uses `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`; these names belong to Terraform's S3-compatible backend and hold R2 credentials here.
Use a read token for exports, plans, and deviation checks; applies need an edit token.
Scope permissions to the account, zones, and services being managed.

Ask your administrator for the approved Delinea `tss` CLI, Secret Server URL, onboarding rule, and secret ID. After running `tss init`, load credentials for the current session.
Replace `1234` with that secret ID.

PowerShell:

```powershell
$env:CLOUDFLARE_API_TOKEN = tss -q secret -s 1234 -f cloudflare-api-token
$env:AWS_ACCESS_KEY_ID = tss -q secret -s 1234 -f r2-access-key-id
$env:AWS_SECRET_ACCESS_KEY = tss -q secret -s 1234 -f r2-secret-access-key
```

macOS or Linux:

```sh
export CLOUDFLARE_API_TOKEN="$(tss -q secret -s 1234 -f cloudflare-api-token)"
export AWS_ACCESS_KEY_ID="$(tss -q secret -s 1234 -f r2-access-key-id)"
export AWS_SECRET_ACCESS_KEY="$(tss -q secret -s 1234 -f r2-secret-access-key)"
```

Keep credentials out of configuration files and commits. Confirm that retrieval succeeded before running a live command.

## GitHub deployment setup

Create the `plan` and `production` environments:

| Setting | `plan` | `production` |
|---|---|---|
| Secret Server access | Read Cloudflare token and R2 keys | Read Cloudflare token, edit R2 keys, and View on each approver's token |
| Secrets | `TSS_ONBOARDING_KEY` | Same name, separate onboarding rule |
| Variables | `TSS_SERVER_URL`, `TSS_RULE_NAME`, `TSS_SECRET_ID`, `TSS_CLI_URL`, `TSS_CLI_SHA256` | Same names, separate rule and secret |
| Deployment protection | Trusted PR branches; no environment reviewer gate | `main` only; no extra required environment reviewers |

### Delinea Secret Server

GitHub runners must be able to reach Secret Server; an on-premises server behind a firewall needs a self-hosted runner or an allowed network path. Enable Webservices and SDK Configuration.

For each of `plan` and `production`, create:

- An application account with a role limited to View Secret, for example `svc-cloudflare-plan` and `svc-cloudflare-prod`.
- An onboarding rule for that account, with an onboarding key required. Its name must not contain spaces. Allowed IP ranges suit self-hosted runners; GitHub-hosted runners have no small fixed range.
- A secret that only that account can view. Its template needs the field slugs `cloudflare-api-token`, `r2-access-key-id`, `r2-secret-access-key`, and `r2-account-id`. `notification-webhook-secrets`, `logpush-destinations`, and `freshservice-api-key` are read when present.

Both `cloudflare-api-token` fields hold a read-only token. `production` R2 keys need state write access. Never give the plan account View on a personal token: plans run on PR branches before approval.

Workflows run `tss init` on each job and remove the client afterwards. Confirm with your Delinea administrator that a client registered this way uses the rule's application account without manual assignment; otherwise reads fail with `invalid_client`.

`TSS_CLI_URL` and `TSS_CLI_SHA256` identify the Linux x64 zip of the approved release, for example `https://downloads.ss.thycotic.com/secretserversdk/1.6.2/secretserver-sdk-1.6.2-linux-x64.zip` with `9adf9c5837eb749c481c134a39bcd58141618e0bbec834ce130fb71d50e2215c`.

### Personal Cloudflare tokens

Applies use the approver's own Cloudflare token, so Cloudflare's audit log names that person. No shared edit token exists; the `production` secret's `cloudflare-api-token` is read-only and only reports outcomes.

Each person who approves PRs:

1. Creates a user-owned Cloudflare API token with the edit permissions this repository needs.
2. Stores it in their own Secret Server secret, in a field with the slug `cloudflare-api-token`.
3. Grants the production application account View on that secret.
4. Adds their GitHub login and the secret ID to [`.github/cloudflare-operators.yml`](../.github/cloudflare-operators.yml) through a PR.

The most recent eligible approver in that file is used. If no approver is listed, the merged run stops before anything is marked pending; register the approver and repeat the change through a new PR. Rotate and remove these tokens with the person's access.
CI uses the token on the approver's behalf, so keep the GitHub run with the audit entry; the log identifies who authorised the change, not who operated the runner.

### Test the flow

Test with a read-only token first. Applying a real change with one fails partway, so use a PR with no Cloudflare effects:

1. Store a read-only user-owned token as the approver's personal token and register it in `.github/cloudflare-operators.yml`.
2. Open a PR that adds a YAML comment to one domain's `domain.yaml`, plus the registration if it is not merged yet. Confirm the plan says nothing will change.
3. Approve as a second user with write access, after the plan comment appears, then merge.
4. Confirm the `Apply domain` job shows no changes and finishes. This proves the Delinea fetch, approver selection, and personal token.

This writes nothing to Cloudflare, so it cannot prove the audit log. Afterwards, replace the personal token with an edit token, merge one small real change, and confirm the audit log names the approver.

Protect `main` with at least one approving PR review, dismissal of stale reviews, required checks, and restricted bypass access. Require approval by someone other than the author after the complete plan is available. Test these settings with two users; repository files do not enforce GitHub branch rules by themselves. Configure `.github/CODEOWNERS` for your teams.
Environment protection and branch rules are GitHub settings; the repository does not create them.
For automatic dashboard resync, add `DEVIATION_BOT_TOKEN` to the `plan` environment for a dedicated bot allowed to push through the chosen branch rules. Limit its repository access, rotate it, and test a resync with protection enabled. Without this secret, checkout uses the default Actions token, which may be unable to push to protected `main`.
Review [CI and approvals](ci.md) and [automatic resync](operations.md#automatic-resync) before enabling live automation.

## Sample configuration

Example domains are test fixtures under `tests/fixtures/domains/`, outside live root discovery.
The sample account uses a fake ID and `example: true`; CI excludes it from live planning.
Set up your real account and domains using [Operations](operations.md).

## External service secrets

Webhook YAML uses `secret_ref` instead of a signing secret and `url_ref` instead of a credential-bearing URL (such as a Slack webhook). Credential-bearing Logpush destinations use `destination_conf_ref` instead of the destination URL.
Supply JSON maps through `TF_VAR_notification_webhook_secrets` and `TF_VAR_logpush_destinations`. CI retrieves the optional `notification-webhook-secrets` and `logpush-destinations` vault entries in both environments. Missing referenced values fail planning.

For example, YAML `secret_ref: incident_hook` selects the `incident_hook` signing secret; `url_ref: incident_url` selects the endpoint from the same webhook map. YAML `destination_conf_ref: central_logs` selects that key in the Logpush destination map. Keep values in the vault and use the same references and values for planning and applying.

Inventory permissions cover every endpoint in `scripts/workflow/coverage.py`, including observation-only services. Permission failures stop automation instead of treating unreadable services as empty. A 404 is reported separately and is not proof that an entire product is unsupported.

Check R2 coordination with `python scripts/operations.py verify-storage account`. It creates and removes an isolated temporary probe, checks ETags and rejection of stale/duplicate writes, and leaves state and journal entries untouched. Every operation also checks these conditions before it starts.
