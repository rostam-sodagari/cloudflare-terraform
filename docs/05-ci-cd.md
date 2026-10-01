# 5. CI/CD (GitHub Actions)

Two workflows:

| File | Role |
|------|------|
| `.github/workflows/terraform.yml` | Detects changed roots, runs `account` first, then domains in parallel |
| `.github/workflows/terraform-root.yml` | Plan and apply for one root (reusable) |

## What runs when

| Event | Steps per changed root |
|-------|------------------------|
| Pull request | `fmt` check, offline test, plan (written to the job summary) |
| Merge to `main` | the same, then apply after `production` approval |

Change detection (`scripts/changed-domains.sh`):

1. A change under `modules/` plans **every** root.
2. A change under `account/` plans `account`.
3. A change under `domains/<d>/` plans that domain.
4. `domains/_template` and deleted folders are ignored.

Runs are serialised per root (`concurrency: cf-<root>`), so two merges
never apply to the same zone at once.

## One-off setup

1. **Environments** (repo Settings > Environments):
   - `plan`: read-only Cloudflare token.
   - `production`: edit token, *required reviewers* set, deployment branch
     limited to `main`.
2. **Delinea:** replace the placeholder step in `terraform-root.yml` with
   your Delinea retrieval. It must write these to `$GITHUB_ENV`:
   `CLOUDFLARE_API_TOKEN`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`,
   `R2_ACCOUNT_ID`. Use the environment name to pick the read or edit token.
3. **Branch protection on `main`:** require pull requests, one approval,
   and the `cloudflare-terraform` checks to pass.
4. Pin `TF_VERSION` in `terraform-root.yml` to the version your team uses.

## Reviewing a plan

1. Open the PR's workflow run > Summary; each root has its own plan.
2. Check the counts first: unexpected destroys are the main risk.
3. For rulesets, Terraform shows the whole rule list; look for rules that
   moved position, not just changed text.
4. Approve only when the plan matches the intent in the PR description.
