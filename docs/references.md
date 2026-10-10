# External documentation

Use upstream documentation when checking an API behavior, entitlement, or provider change.
This repository's configured limits live in `scripts/config.py` and the Terraform modules; subscriptions and upstream behavior can change.

| Topic | Reference |
|---|---|
| DNS record formats | [Cloudflare DNS record types](https://developers.cloudflare.com/dns/manage-dns-records/reference/dns-record-types/) |
| Custom WAF rules | [Cloudflare custom rules](https://developers.cloudflare.com/waf/custom-rules/) |
| Rate limits | [Cloudflare rate limiting](https://developers.cloudflare.com/waf/rate-limiting-rules/) |
| Managed WAF | [Cloudflare managed rules](https://developers.cloudflare.com/waf/managed-rules/) |
| Request and response rules | [Cloudflare Rules](https://developers.cloudflare.com/rules/) |
| Named lists | [Cloudflare lists](https://developers.cloudflare.com/waf/tools/lists/) |
| R2 state backend | [Cloudflare remote backend](https://developers.cloudflare.com/terraform/advanced-topics/remote-backend/) |
| Terraform backend configuration | [S3 backend](https://developer.hashicorp.com/terraform/language/backend/s3) |
| Terraform plan data | [JSON output format](https://developer.hashicorp.com/terraform/internals/json-format) |
| Terraform mock tests | [Provider mocking](https://developer.hashicorp.com/terraform/language/tests/mocking) |
| Provider resources and import formats | [Cloudflare provider](https://registry.terraform.io/providers/cloudflare/cloudflare/latest/docs) |

For version-specific behavior, use the provider version in the root's `.terraform.lock.hcl` and the corresponding provider source tag.
The generated rules schema is `scripts/data/ruleset_rule_schema.json`.
