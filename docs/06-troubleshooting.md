# 6. Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `zone_id in domain.yaml must be the 32-character hex Zone ID` | ID unquoted (YAML read it as a number) or wrong value | Quote it: `zone_id: "0123..."` |
| `Resource precondition failed ... plan allows N rules` | Over the plan limit | Remove rules or change `plan` if the zone was upgraded |
| `Super Bot Fight Mode settings need Pro or above` | `sbfm_*` on a Free zone | Use `fight_mode` |
| `An SPF record needs more than 10 DNS lookups` | Too many `include:` | Remove unused senders, use `ip4` ranges, or an SPF flattening service |
| `SPF found in txt.yaml` | SPF in the wrong file | Move it to `spf.yaml` |
| Plan error from Cloudflare naming a field, e.g. not entitled | Feature not in your plan | Remove the field or upgrade |
| `A ruleset with this phase already exists` | Dashboard-created entry point ruleset | Import it: `make export`, or add an `import` block |
| Plan keeps showing the same ruleset change | Field ordering or a default the API adds | Copy the value exactly as the plan shows it into YAML |
| `Error acquiring the state lock` | Another run, or a killed run | Wait; if stale: `terraform -chdir=<root> force-unlock <ID>` |
| `Missing backend.hcl` | Not created | `cp backend.hcl.example backend.hcl` and fill in |
| Authentication error on one resource type | Token missing that permission | Add the scope (see [01](01-getting-started.md)) |
| `expression: true` rejected | YAML turned it into a boolean | Quote it: `expression: "true"` |
| Value `"on"` turned into `true` | Unquoted on/off | Quote `"on"` / `"off"` |
| Plugin crash during `plan` with no network | The ruleset resource validates against the API during plan | Use `make test` offline; `make plan` needs the API |
| Renamed a YAML key and the plan destroys and recreates | Keys are identities | Rename back, or add a `moved` block in the domain's `main.tf` |

## Moving an item without recreating it

If you must rename a key, tell Terraform in `domains/<d>/moved.tf`:

```hcl
moved {
  from = module.domain.module.dns.cloudflare_dns_record.this["a/web"]
  to   = module.domain.module.dns.cloudflare_dns_record.this["a/www"]
}
```

Plan should then show no changes for that record. Delete `moved.tf` after
the apply.

## Getting help

1. `make test D=<d>` for the exact failing check.
2. `TF_LOG=DEBUG make plan D=<d>` for API calls (contains no secrets, but
   check before sharing outside the team).
3. Cloudflare API errors quote the field name; search it in the Rulesets
   or relevant API reference on developers.cloudflare.com.
