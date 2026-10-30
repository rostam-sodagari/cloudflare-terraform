# Troubleshooting

Start with the first failing step in the Actions run or the first error printed by the command.
Validation reports a file and line number; `plan.log` contains the full Terraform output.

## Configuration errors

| Message or symptom | Next step |
|---|---|
| YAML syntax error | Use spaces, consistent indentation, and `key: value` |
| Duplicate key | Give each entry a unique key; do not rename an existing managed item casually |
| Unknown field | Use the suggested spelling or the file's example |
| Value read as boolean or number | Quote text such as `"on"`, `"1.2"`, and IDs |
| Must be a whole number | Remove quotes from numeric fields such as `ttl` |
| CNAME conflicts with another record | Remove the conflicting record at that name |
| SPF or DMARC in `txt.yaml` | Move it to the dedicated service file |
| Missing list `$name` | Check `account/lists/` and deploy the list before its consumers |
| Plan limit or feature error | Check the real subscription and the `plan` field |

## Plan and apply errors

| Message or symptom | Next step |
|---|---|
| Wants to create objects that already exist | Check backend/state selection and [adoption](operations.md#adopt-an-existing-zone) |
| Backend configuration changed | Use `python cf.py migrate <root> --to local` or `--to r2` |
| Missing `backend.hcl` | Copy and fill in `backend.hcl.example`, or choose local state for a sandbox |
| Stale, invalid, or modified saved plan | Run a fresh plan and review it before applying |
| Cannot read or verify the plan | Replan; inspect `plan.log` if the error repeats |
| State lock error | Wait for the active run; investigate an abandoned lock before unlocking it |
| DNSSEC destruction blocked | Follow the [DNSSEC disable procedure](services.md#dnssec) |
| Authentication or permission error | Check the token scope and the service being accessed |
| Existing ruleset not imported | Review export/import blocks rather than creating a second ruleset |
| Same change appears after apply | Compare provider/API normalization with the YAML and investigate before retrying |


## CI and resync errors

| Symptom | Next step |
|---|---|
| No approver has a Cloudflare token | Add a listed approver's login and secret ID to `.github/cloudflare-operators.yml`, per [Personal Cloudflare tokens](setup.md#personal-cloudflare-tokens) |
| Missing Cloudflare/R2 credentials | Check the Secret Server onboarding rule and application account, CLI URL/checksum, and required field slugs in [Setup](setup.md) |
| Live plan unavailable on a fork PR | Run the branch in the trusted repository with appropriate access |
| No summary comment | Inspect the failed or skipped plan job |
| Deployment waiting | Check PR review evidence and branch/environment configuration; no extra environment reviewer gate is required |
| Follow-up plan contains changes | Read actual changes and remaining effects; follow [recovery](operations.md#failed-or-interrupted-deployment) |
| Resync refuses local changes | Commit or separately save your work before rerunning |
| Resync push rejected | Check branch rules and concurrent commits; do not force-push |

## Renaming without recreation

A maintainer can use a Terraform `moved` block when an identity must change:

```hcl
moved {
  from = module.domain.module.dns.cloudflare_dns_record.this["a/web"]
  to   = module.domain.module.dns.cloudflare_dns_record.this["a/www"]
}
```

Place it in the domain's Terraform root and inspect the plan to confirm the resource is moved rather than replaced.

An expired or mismatched review artifact requires a fresh PR plan and second-user approval. An unfinished journal blocks automatic resync until the deployment is recovered. Observation-only configuration remains in an issue without repeated export attempts.
