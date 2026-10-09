# Setup for maintainers

*Who this is for: maintainers doing the one-off repository setup.*

One-off setup of the repository, Cloudflare credentials, the R2 state
bucket and GitHub. People who only edit YAML need none of this; they
only need write access to the repo ([11 Making a change](11-making-a-change.md)).

## 1. Cloudflare API tokens

Create two tokens in **My Profile > API Tokens > Create Token > Custom**,
both limited to this account and the zones this repo manages:

- **read** token: for exports, PR plans and the deviation check.
- **edit** token: for applies only.

| Permission | Read token | Edit token | Used by |
|---|---|---|---|
| Zone > Zone | Read | Read | everything |
| Zone > DNS | Read | Edit | dns/ |
| Zone > Zone Settings | Read | Edit | settings/, security/hsts |
| Zone > Zone WAF | Read | Edit | waf/ |
| Zone > Firewall Services | Read | Edit | security/ip-access-rules |
| Zone > Bot Management | Read | Edit | security/bot-management |
| Zone > Cache Rules, Cache Settings | Read | Edit | cache/ |
| Zone > Transform Rules | Read | Edit | rules/url-rewrites, request/response headers |
| Zone > Single Redirect | Read | Edit | rules/redirects |
| Zone > Origin Rules | Read | Edit | rules/origin |
| Zone > Config Rules | Read | Edit | rules/config |
| Zone > Response Compression | Read | Edit | rules/compression |
| Account > Account Filter Lists | Read | Edit | account/lists |
| Account > Account Rulesets, Mass URL Redirects | Read | Edit | Bulk Redirects |

Permission names in the dashboard change occasionally. The exporter names
the missing permission when it gets a 403 and stops before replacing any
existing exported folder. Fix the token permission and rerun the export;
never use a partially completed export. During plan, the provider asks
Cloudflare to *dry-run* rule changes; with the read token this produces a
harmless warning ("failed to make http request for the dry run") and the
plan still works.

## 2. R2 bucket for Terraform state

1. Cloudflare dashboard **R2 > Create bucket**, e.g. `cf-terraform-state`,
   location hint Western Europe.
2. **R2 > Manage API tokens > Create API token**: *Object Read & Write*,
   this bucket only. Note the Access Key ID, Secret Access Key and your
   Account ID.
3. Back the bucket up: state is the only record of what Terraform manages.
   Use R2 object versioning if your account has it; otherwise a scheduled
   copy to a second bucket.

`backend.hcl.example` holds the settings Cloudflare documents for using R2
as an S3 backend, plus `use_lockfile = true` for locking (Terraform 1.10+).
Each root has its own state object: `domains/<name>.tfstate` and
`account.tfstate`.

**There is no AWS account anywhere in this project.** Terraform's S3
backend is a generic protocol, and R2 implements it
([Remote R2 backend](https://developers.cloudflare.com/terraform/advanced-topics/remote-backend/)),
so Terraform talks to R2 using code written for S3 -- pointed at
`backend.hcl`'s R2 endpoint, never at `amazonaws.com`. The catch is that
this Terraform backend hardcodes the environment variable names
`AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` for *whichever* S3-compatible
service it's talking to; that's Terraform's naming, not a sign this repo
depends on AWS. Every value behind those names is an R2 key pair, scoped
to the one bucket in step 2 above.

## 3. GitHub

### Environments (Settings > Environments)

Tokens live in Delinea DevOps Secrets Vault (DSV), not directly as
GitHub secrets -- the only thing each environment holds is the DSV
client credentials needed to fetch them at run time:

| Environment | Secrets | Variables | Protection |
|---|---|---|---|
| `plan` | `DSV_CLIENT_ID`, `DSV_CLIENT_SECRET` (scoped to the **read**-only Cloudflare token + R2 keys in DSV) | `DSV_TENANT`, `DSV_SECRET_PATH`, `DSV_CLI_URL`, `DSV_CLI_SHA256` | none |
| `production` | `DSV_CLIENT_ID`, `DSV_CLIENT_SECRET` (scoped to the **edit** Cloudflare token + R2 keys in DSV) | `DSV_TENANT`, `DSV_SECRET_PATH`, `DSV_CLI_URL`, `DSV_CLI_SHA256` | **Required reviewers** (2 or more people); **Prevent self-review**; deployment branches: `main` only |

`DSV_CLI_URL` must point to the approved, versioned Delinea CLI release for
the runner platform. `DSV_CLI_SHA256` must be the vendor-published SHA-256
for that exact download. The workflows refuse to run if either value is
missing or the checksum does not match.

The least-privilege split (read for `plan`, edit for `production`) is
enforced by which DSV secrets each environment's client credentials can
read, not by GitHub -- set that up as a DSV role/policy, not here.

**Optional: Freshservice change-request gate.** To require every apply to
name an approved Freshservice change request
([33 CI/CD](33-ci-cd.md#freshservice-change-request-gate-optional)), set
`FRESHSERVICE_DOMAIN` as a variable on the `production` environment (your
Freshservice subdomain, e.g. `acme` for `acme.freshservice.com`) and add a
`freshservice-api-key` secret at the same DSV path as the Cloudflare/R2
secrets above. Leave `FRESHSERVICE_DOMAIN` unset to leave this gate off.

To use plain GitHub Actions secrets instead of Delinea, follow the
comment in `.github/workflows/cloudflare-root.yml`: delete the "Fetch
secrets from Delinea" step and uncomment the four `secrets.*` lines below
it, then set `CLOUDFLARE_API_TOKEN`/`R2_ACCESS_KEY_ID`/
`R2_SECRET_ACCESS_KEY`/`R2_ACCOUNT_ID` directly as secrets on both
environments.

### Branch protection (Settings > Branches > main)

- Require a pull request, with at least 1 approval.
- Dismiss stale approvals when new commits are pushed.
- Require status checks: `checks`, and the `plan ...` jobs.
- Require conversation resolution.
- Do not allow bypassing the above.

### Code owners (optional but recommended)

Create `.github/CODEOWNERS` so the right team is asked to review:

```
# Everyone may edit YAML; these teams review it.
/domains/                @your-org/network-team
/account/                @your-org/security-team
/domains/*/waf/          @your-org/security-team
# Code changes need a maintainer.
/modules/                @your-org/platform-maintainers
/scripts/                @your-org/platform-maintainers
/.github/                @your-org/platform-maintainers
```

### Labels

The deviation-detection workflow creates the `deviation` label itself.

## 4. On your computer

Needed only to run commands locally (exports, plans before a PR).

1. Tools: Terraform 1.10+ (or OpenTofu 1.10+), Python 3.9+, and Git.
   Windows: see [34 Windows](34-windows.md).
2. `pip install -r requirements.txt`
3. `cp backend.hcl.example backend.hcl` and fill in the bucket and account ID.
4. Credentials for the session, pulled from Delinea DevOps Secrets Vault
   (DSV) -- never paste a token directly, and never commit one:

   ```bash
   # One-time: install the DSV CLI (see Delinea's current docs for your
   # platform) and log in with your own Delinea account:
   dsv init --tenant <your-tenant>

   # Every session: pull your personal read token and the R2 keys into
   # this shell. A read token is enough for plan, deviation-check, export;
   # only ask for an edit-scoped token if you're applying locally, which
   # should be rare -- applies normally happen in CI after review.
   export CLOUDFLARE_API_TOKEN=$(dsv secret read <secret-path>:cloudflare-api-token --data.value)
   export AWS_ACCESS_KEY_ID=$(dsv secret read <secret-path>:r2-access-key-id --data.value)
   export AWS_SECRET_ACCESS_KEY=$(dsv secret read <secret-path>:r2-secret-access-key --data.value)
   ```

   Ask your Delinea admin for `<your-tenant>` and `<secret-path>` if you
   don't have them -- every user reads their own token from their own
   Delinea access, nobody shares a token directly.

5. Check everything works offline: `python3 cf.py test-all` and `python3 cf.py unit`.

The main plan/apply workflow and scheduled deviation workflow both use
Delinea. The scheduled workflow uses the `plan` environment and its
read-only DSV client. If the DSV client or any required secret is missing,
the scheduled check fails rather than silently reporting a clean result.

No R2 yet? Use `--backend local` for a trial; see [35 Local backend](35-local-backend.md).

## 5. Remove the samples

`domains/example.com`, `domains/example.net` and the account files carry
`example: true` and fake IDs; CI never plans them. Before real use:

1. Delete `domains/example.com` and `domains/example.net`.
2. Run `python3 cf.py export-account --account-id <id> --plan <highest plan>`,
   which replaces `account/` with your real lists (and removes `example: true`).
3. Add domains: [31 Adding a domain](31-adding-a-domain.md).
