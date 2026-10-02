# CI/CD (GitHub Actions)

| Workflow | When | What |
|---|---|---|
| `cloudflare.yml` | every PR; every merge to `main`; manual run | checks, plans, PR summaries, approved applies |
| `cloudflare-root.yml` | called by the above | plan or apply one domain (or `account`) |
| `drift.yml` | weekdays 06:30 UTC; manual | drift check, opens/closes `drift` issues |
| `windows.yml` | PRs touching `cf.py` or scripts | runs the same CLI on Windows |

## On a pull request

1. **checks** (no secrets, runs for forks too):
   - YAML validation (`scripts/validate.py --all`); errors are posted as
     annotations on the changed lines.
   - `terraform fmt` check.
   - Offline plan of every domain with a mocked Cloudflare (`python3 cf.py test-all`).
   - Unit tests for the validator, exporter and change summary.
   - End-to-end test against a local stand-in for the Cloudflare API
     (apply, dashboard drift, PR plan, re-apply).
2. **detect**: which domains changed. A change under `modules/` or
   `scripts/` plans every domain. Folders with `example: true` are never
   planned.
3. **plan** (environment `plan`, read token), `account` first:
   - `python3 cf.py plan`: validate, plan, change summary.
   - Summary written to the run page and posted as **one comment per
     domain**, updated in place on every push.

## On merge to `main`

1. The same checks and plans run again, from `main`.
2. Each plan is saved as an artifact (`plan.bin`, `plan.json`, the summary
   and the provider lock file) for 3 days.
3. **apply** jobs wait for approval in the `production` environment
   ([13 Reviewing](13-reviewing.md#approving-the-deployment-after-merge)).
4. On approval, the job downloads **that** saved plan and applies it.
   Nothing outside the reviewed summary is changed. If the state changed
   since (another apply to the same domain), Terraform refuses the stale
   plan and nothing is applied. A dashboard edit made after the plan is
   overwritten if it touched an object in the plan; anything else is
   reported by the next step and by the drift check.
5. A final plan must say *Nothing will change*; otherwise the run shows a
   warning with the remaining changes.

Runs for the same domain never overlap (`concurrency: cloudflare-<root>`),
and R2 locking (`use_lockfile`) protects state as a second guard.

## Manual run: re-apply a domain

**Actions > cloudflare > Run workflow**, enter a domain folder name (or
`account`). It plans and, after `production` approval, applies. Use it to
put Cloudflare back to the YAML after unwanted [drift](14-drift.md).

## Drift check

For every non-example domain, `python3 cf.py drift --drift-exit` compares Cloudflare
with the last apply (`terraform plan -refresh-only`; read-only). Drift
opens or updates an issue **Cloudflare drift: <domain>** labelled `drift`;
when it is gone, the issue is closed with a comment.

## Pull requests from forks

Secrets are not available to forks, so only the checks run; the plan is
skipped with a notice. A maintainer can push the branch to the main
repository to get a plan.

## Public repositories

Plan comments, run summaries and plan artifacts contain record contents
and rule expressions. For a public repository that publishes the zone's
configuration. Keep real domains in a **private** repository.

## Versions

- Terraform: `TF_VERSION` in `cloudflare.yml`, the `tf_version` default in
  `cloudflare-root.yml`, and `drift.yml`. Keep the three the same.
- Cloudflare provider: `~> 5.26` in every `providers.tf` and module. The
  plan job saves `.terraform.lock.hcl`, so the apply uses exactly the
  provider build that made the plan. After upgrading, regenerate the rule
  schema ([37 Maintaining](37-maintaining.md)).
