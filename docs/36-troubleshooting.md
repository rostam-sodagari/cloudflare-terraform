# Troubleshooting

*Who this is for: everyone -- look up the error message you're seeing.*

## YAML check errors

The check always says the file, the line and the fix. The common ones:

| Message contains | Cause | Fix |
|---|---|---|
| `duplicate key` | The same key twice in one file; YAML would silently keep only the last | Rename one of them |
| `unknown field ... did you mean` | Typo in a field name | Use the suggested name |
| `was read as yes/no` | `on`, `off`, `yes`, `no`, `true` without quotes where text is needed | Quote it: `"on"` |
| `was read as a number` | IDs, `1.2` etc. without quotes | Quote it |
| `must be a whole number ... remove the quotes` | `ttl: "300"` | `ttl: 300` |
| `YAML syntax error` | Tab characters, missing space after `:`, bad indentation | Spaces only, `key: value`, two-space indents |
| `has a CNAME and other records` | A name with a CNAME also has an A/TXT/MX record | Remove one; a CNAME name can have nothing else |
| `SPF record found in txt.yaml` | SPF written as a plain TXT | Move it to `spf.yaml` |
| `starts with a double quote but is not a list of quoted strings` | A TXT/SPF value copied with a missing or extra quote | Remove the quotes entirely (they are added for you), or wrap the whole value in single quotes: `'"v=spf1 -all"'` |
| A TXT record changes on every plan between `v=...` and `"v=..."` | An old record Cloudflare holds without quotes | Add `quoted: false` to that record (the exporter does this for you) |
| `needs N DNS lookups; the limit is 10` | Too many `include:` in SPF | Remove unused senders or use `ip4` ranges |
| `the log action is Enterprise only` | `log` on Free/Pro/Business | `managed_challenge` while testing |
| `need Business or Enterprise` | Regular expressions on Free/Pro | `wildcard`, `starts_with`, `contains`, `wildcard_replace` |
| `plan allows N` | Over the plan's rule limit | Remove rules, or update `plan:` after an upgrade |
| `not available on the free plan` (bot settings) | `sbfm_*` on Free | `fight_mode: true` |
| `uses list $name, which is not defined` | Rule refers to a list that does not exist | Add it in `account/lists/` or fix the name |
| `does not match the folder name` | `name:` in domain.yaml differs from the folder | Make them the same |

## Plan and apply

| Symptom | Cause | Fix |
|---|---|---|
| Plan wants to **add** things that already exist | Wrong backend (empty state), or a domain not yet imported | Stop. Check `BACKEND`; for a live zone use the [import runbook](32-migration.md) |
| `Backend configuration changed` | This domain was last used with the other backend | `python3 cf.py migrate <d> --to <local or r2>` ([35](35-local-backend.md)) |
| `Saved plan is stale` | Another apply changed the state after this plan | Plan again and re-check the summary |
| `Error acquiring the state lock` | Another run on the same domain, or a killed run | Wait. If stale: `terraform -chdir=domains/<d> force-unlock <LOCK_ID>` |
| `Instance cannot be destroyed` on DNSSEC | `dnssec.yaml` was emptied; deletion is blocked on purpose | Set `status: disabled` (after removing the DS record at the registrar) |
| Warning `failed to make http request for the dry run` | The provider's rule pre-check needs edit rights; the read token cannot | Harmless with the read token |
| Authentication error on one resource type | Token lacks that permission | Add it ([30 Setup](30-setup.md#1-cloudflare-api-tokens)) |
| A ruleset keeps showing the same change | The YAML differs in form from what Cloudflare returns | Copy the value exactly as the summary shows the "before" side |
| `A ruleset with this phase already exists` | A dashboard-created ruleset that is not imported | Export again (`FORCE=1`) or add an import block |
| `Missing backend.hcl` | Not created | `cp backend.hcl.example backend.hcl` and fill in, or `BACKEND=local` |
| `PyYAML is required` | Python dependencies missing | `pip install -r requirements.txt` |

## CI

| Symptom | Cause | Fix |
|---|---|---|
| Plan blocked: missing or incomplete Cloudflare/R2 credentials | Delinea client settings, CLI release variables, or fetched secrets are missing; fork PRs cannot access environment secrets | Run the workflow from a trusted branch/repository and check the required settings in [30 Setup](30-setup.md#3-github) |
| No change summary comment | The plan job failed or was skipped | Open the run; the first red step says why |
| Apply waiting for a long time | Needs approval in `production` | A required reviewer approves ([13](13-reviewing.md)) |
| After apply: "a new plan still shows changes" | Cloudflare normalises a value differently | Copy the "after" value into the YAML in a follow-up PR |

## Renaming a key without recreating the item

Keys are identities, so renaming deletes and recreates. If you must
rename, add `domains/<d>/moved.tf` in the same PR:

```hcl
moved {
  from = module.domain.module.dns.cloudflare_dns_record.this["a/web"]
  to   = module.domain.module.dns.cloudflare_dns_record.this["a/www"]
}
```

The summary should then show no change for that record. Delete `moved.tf`
in a later PR.

## Getting more detail

1. `domains/<d>/plan.log` holds Terraform's full output from `python3 cf.py plan`.
2. `TF_LOG=DEBUG python3 cf.py plan <d>` shows every API call. Check it for
   anything sensitive before sharing it outside the team.
