# Setup for maintainers

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
the missing permission when it gets a 403. During plan, the provider asks
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

## 3. GitHub

### Environments (Settings > Environments)

| Environment | Secrets | Protection |
|---|---|---|
| `plan` | `CLOUDFLARE_API_TOKEN` (read token), `R2_ACCESS_KEY_ID`, `R2_SECRET_ACCESS_KEY`, `R2_ACCOUNT_ID` | none |
| `production` | `CLOUDFLARE_API_TOKEN` (**edit** token), same three R2 secrets | **Required reviewers** (2 or more people); **Prevent self-review**; deployment branches: `main` only |

To use Delinea instead of GitHub secrets, follow the comment in
`.github/workflows/cloudflare-root.yml`: remove the four `secrets.*` lines
and add a Delinea step that exports the same variable names.

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

1. Tools: Terraform 1.10+ (or OpenTofu 1.10+), Python 3.9+, Git, Make.
   Windows: see [34 Windows](34-windows.md).
2. `pip install -r requirements.txt`
3. `cp backend.hcl.example backend.hcl` and fill in the bucket and account ID.
4. Credentials for the session (from Delinea; never commit them):

   ```bash
   export CLOUDFLARE_API_TOKEN=...          # read token is enough for plan, deviation-check, export
   export AWS_ACCESS_KEY_ID=...             # R2 key
   export AWS_SECRET_ACCESS_KEY=...
   ```

5. Check everything works offline: `python3 cf.py test-all` and `python3 cf.py unit`.

No R2 yet? Use `--backend local` for a trial; see [35 Local backend](35-local-backend.md).

## 5. Remove the samples

`domains/example.com`, `domains/example.net` and the account files carry
`example: true` and fake IDs; CI never plans them. Before real use:

1. Delete `domains/example.com` and `domains/example.net`.
2. Run `python3 cf.py export-account --account-id <id> --plan <highest plan>`,
   which replaces `account/` with your real lists (and removes `example: true`).
3. Add domains: [31 Adding a domain](31-adding-a-domain.md).
