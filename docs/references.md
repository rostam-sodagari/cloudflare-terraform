# References

Facts this repository depends on, and where they come from. Checked
against the documentation on 1 October 2026; Cloudflare changes plan
limits from time to time, so re-check when something is rejected.

## Cloudflare

| Fact used in this repo | Source |
|---|---|
| Custom rules per plan (5 / 20 / 100 / 1000); Log action Enterprise only; regex Business+ | [WAF custom rules](https://developers.cloudflare.com/waf/custom-rules/) |
| Log action is Enterprise only (all rule types) | [Rules actions](https://developers.cloudflare.com/ruleset-engine/rules-language/actions/) |
| Rate limiting per plan: rules 1 / 2 / 5 / 100, periods, timeouts, characteristics, counting expression Business+ | [Rate limiting rules](https://developers.cloudflare.com/waf/rate-limiting-rules/) |
| Allowed `period` and `mitigation_timeout` values; `cf.colo.id` always included | [Rate limiting parameters](https://developers.cloudflare.com/waf/rate-limiting-rules/parameters/) |
| Managed rulesets per plan (Cloudflare Managed and OWASP on Pro+) | [WAF managed rules](https://developers.cloudflare.com/waf/managed-rules/) |
| Managed ruleset IDs, OWASP paranoia via category overrides, threshold rule `6179ae15870a4bb7b2d480d4843b323c` | [Terraform: WAF managed rulesets](https://developers.cloudflare.com/terraform/additional-configurations/waf-managed-rulesets/) |
| OWASP thresholds: low 60, medium 40 (default), high 25; paranoia PL1 default | [OWASP concepts](https://developers.cloudflare.com/waf/managed-rules/reference/owasp-core-ruleset/concepts/) |
| Cache rules per plan 10 / 25 / 50 / 300 | [Cache rules](https://developers.cloudflare.com/cache/how-to/cache-rules/) |
| Transform rules per plan 10 / 25 / 50 / 300; regex Business+ | [Transform rules](https://developers.cloudflare.com/rules/transform/) |
| Origin rules per plan; host header, SNI and DNS override Enterprise only | [Origin rules](https://developers.cloudflare.com/rules/origin-rules/) |
| Configuration rules per plan | [Configuration rules](https://developers.cloudflare.com/rules/configuration-rules/) |
| Compression rules per plan | [Compression rules](https://developers.cloudflare.com/rules/compression-rules/) |
| Single and Bulk Redirect limits | [URL forwarding](https://developers.cloudflare.com/rules/url-forwarding/) |
| Lists: per-plan counts, ASN/hostname Enterprise only, name rules | [Lists](https://developers.cloudflare.com/waf/tools/lists/) |
| IP Access Rules: ranges IPv4 /16 /24, IPv6 /32 /48 /64; country block Enterprise only; T1, XX | [IP Access Rules parameters](https://developers.cloudflare.com/waf/tools/ip-access-rules/parameters/) |
| R2 as a Terraform S3 backend (settings in `backend.hcl.example`) | [Remote R2 backend](https://developers.cloudflare.com/terraform/advanced-topics/remote-backend/) |
| Super Bot Fight Mode on Pro, Business, Enterprise | [Super Bot Fight Mode](https://developers.cloudflare.com/bots/get-started/super-bot-fight-mode/) |

## Terraform and the provider

| Fact used in this repo | Source |
|---|---|
| Plan JSON: `resource_changes`, `resource_drift`, `importing`, `replace_paths`, actions | [JSON output format](https://developer.hashicorp.com/terraform/internals/json-format) |
| S3 backend options and `use_lockfile` (Terraform 1.10+) | [S3 backend](https://developer.hashicorp.com/terraform/language/backend/s3) |
| `plan -refresh-only` for drift; re-check a plan before applying it | [terraform plan](https://developer.hashicorp.com/terraform/cli/commands/plan) |
| `import` blocks, `moved` blocks, `check` blocks, `prevent_destroy` | [Terraform language](https://developer.hashicorp.com/terraform/language) |
| `mock_provider` in `terraform test` (1.7+) | [Tests](https://developer.hashicorp.com/terraform/language/tests/mocking) |
| Provider v5 resources and import ID formats | [Cloudflare provider docs](https://registry.terraform.io/providers/cloudflare/cloudflare/latest/docs) |
| Ruleset plan-time dry run (`?dry_run=true`) | [provider source, ruleset resource](https://github.com/cloudflare/terraform-provider-cloudflare/blob/v5.26.0/internal/services/ruleset/resource.go) |

The rule field names and allowed values used by the validator are
generated from the provider itself (`scripts/data/ruleset_rule_schema.json`,
provider 5.26.0).
