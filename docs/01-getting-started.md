# 1. Getting started

## Tools

On Windows, follow [07-windows.md](07-windows.md) for setup and use
`.\cf.ps1` wherever these guides say `make`.

1. Terraform 1.10 or later (OpenTofu 1.10+ also works). 1.10 is needed for
   S3 native locking on R2.
2. GNU Make, Python 3.10+ with `pip install pyyaml` (for the exporter),
   `jq` (for CI change detection), optionally `yamllint`.
3. Git access to this repo.

## Cloudflare API token

Create two tokens in **My Profile > API Tokens > Create Token > Custom**:
a read-only one for exports and PR plans, and an edit one for applies.
Scope both to the account and only the zones this repo manages.

| Permission | Read token | Edit token | Used by |
|------------|------------|------------|---------|
| Zone > Zone | Read | Read | everything |
| Zone > DNS | Read | Edit | dns/ |
| Zone > Zone Settings | Read | Edit | settings/, security/hsts |
| Zone > Zone WAF | Read | Edit | waf/ |
| Zone > Firewall Services | Read | Edit | security/ip-access-rules |
| Zone > Bot Management | Read | Edit | security/bot-management |
| Zone > Cache Rules / Cache Settings | Read | Edit | cache/ |
| Zone > Transform Rules | Read | Edit | rules/url-rewrites, request/response headers |
| Zone > Single Redirect / Dynamic Redirect | Read | Edit | rules/redirects |
| Zone > Origin Rules | Read | Edit | rules/origin |
| Zone > Config Rules | Read | Edit | rules/config |
| Zone > Response Compression | Read | Edit | rules/compression |
| Account > Account Filter Lists | Read | Edit | account/lists |
| Account > Account Rulesets | Read | Edit | account bulk redirects |
| Account > Mass URL Redirects | Read | Edit | account bulk redirects |

Permission names in the dashboard occasionally change; if a plan fails with
an authentication error on one resource, the token is missing that scope.
Store both tokens in Delinea, never in Git.

## R2 state bucket

Skip this section if you only want to try the repo: run every command with
`BACKEND=local` (Windows: `-Backend local`) and state stays in `.state/` on
your machine. See [08-local-backend.md](08-local-backend.md). Shared zones
and CI must use R2.

1. In the Cloudflare dashboard: **R2 > Create bucket**, e.g. `cf-terraform-state`.
   Keep it in the same account, location hint near London (WEUR).
2. **R2 > Manage API tokens > Create API token**: permission *Object Read &
   Write*, scoped to that bucket only. Note the **Access Key ID** and
   **Secret Access Key** (S3-compatible credentials) and your **Account ID**.
3. Store the two keys in Delinea.
4. Back the bucket up: state files are the only record of what Terraform
   manages. Use R2 object versioning if your account has it; otherwise run a
   scheduled copy of the bucket to a second bucket.

## Backend config

```bash
cp backend.hcl.example backend.hcl     # git-ignored
```

Edit `backend.hcl`: set `bucket` and replace `<R2_ACCOUNT_ID>`. The state key
is added per root by the Makefile:

| Root | State key |
|------|-----------|
| `account/` | `account.tfstate` |
| `domains/example.com/` | `domains/example.com.tfstate` |

Locking uses `use_lockfile = true` (a `.tflock` object next to the state);
no DynamoDB is needed. If a run is killed, clear a stale lock with
`terraform -chdir=domains/<d> force-unlock <LOCK_ID>`.

## Credentials in your shell

```bash
export CLOUDFLARE_API_TOKEN=...          # read or edit token
export AWS_ACCESS_KEY_ID=...             # R2 key ID
export AWS_SECRET_ACCESS_KEY=...         # R2 secret
```

## First run

```bash
make help
make test-all              # offline checks for every root, no token needed
make plan D=example.com    # needs the token and R2 keys
```

The example domains use fake zone IDs, so delete `domains/example.com` and
`domains/example.net` once you have real domains in place.

## Making a change (daily workflow)

1. Branch from `main`.
2. Edit the YAML in `domains/<d>/...` (or `account/...`).
3. `make test D=<d>` locally; fix anything it reports.
4. Optional: `make plan D=<d>` with the read-only token to see the diff.
5. Open a pull request. CI posts the plan to the run summary.
6. A reviewer checks the plan, not just the YAML.
7. Merge. CI applies after approval in the `production` environment.
