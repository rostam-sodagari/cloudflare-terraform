# Services

Use this page to find the right file. Each template header lists key fields and shows an example.
Optional fields and defaults are in the [YAML field reference](yaml-fields.md).
Validation checks the limits implemented in this repository for the configured plan.
For YAML syntax and deletion behavior, see [Configuration](configuration.md).
For additional nested examples, see [Rule examples](rule-examples.md). For every recognized zone setting, see [Zone setting values](zone-settings.md).

## DNS

Files are under `domains/<domain>/dns/`.

| File | Use | Key fields |
|---|---|---|
| `a.yaml`, `aaaa.yaml` | IPv4 and IPv6 addresses | `name`, `content`, `proxied` |
| `cname.yaml` | Alias to a hostname | `name`, `content`, `proxied` |
| `mx.yaml` | Mail servers | `name`, `content`, `priority` |
| `txt.yaml` | Verification and other text records | `name`, `content` |
| `ns.yaml` | Subdomain delegation | `name`, `content` |
| `spf.yaml` | Authorized mail senders | `includes`, `ip4`, `ip6`, `all`, or `raw` |
| `dmarc.yaml` | Mail authentication policy | `policy`, `rua`, or `raw` |
| `dkim.yaml` | DKIM TXT keys | `name`, `content`; use CNAME for CNAME-based DKIM |
| `caa.yaml` | Certificate authority restrictions | `name`, `tag`, `value` |
| `srv.yaml` | Service discovery | `name`, `priority`, `weight`, `port`, `target` |
| `dnssec.yaml` | DNSSEC status | `status: active` or `status: disabled` |
| `email-routing.yaml` | Mail forwarding | `enabled`, `rules`, `catch_all` |

Common record fields include `ttl` and `comment`. Leave `ttl` out for automatic TTL.
`ttl: 1` also means automatic. Header examples use documentation-only addresses: replace them with your real hosts and provider values.
For TXT, SPF, DMARC, and DKIM, write plain text: the module handles TXT quoting.
Exported `quoted: false` preserves older unquoted TXT values.
Use `name` explicitly for DKIM keys published under a subdomain.

### DNSSEC

After enabling DNSSEC, publish the resulting `dnssec_ds` value at the registrar.
To disable it, remove the registrar's DS record and allow cached DS records to expire before setting `status: disabled`.
Deleting the configuration file does not disable DNSSEC; resource destruction is blocked.

### Email Routing

Verify destination addresses in Cloudflare before using them.
Changing a managed routing configuration from `enabled: true` to `enabled: false` disables routing through the provider resource lifecycle.
An initially false or omitted setting leaves unadopted routing alone; adopt it before trying to disable it here.
`support_subaddress` is unsupported by the pinned provider implementation and is rejected by validation.

## WAF

Files are under `waf/` in a domain or account root.

| File | Use |
|---|---|
| `custom-rules.yaml` | Ordered rules with `ref`, `expression`, and `action` |
| `rate-limits.yaml` | Matching rules plus request counts, periods, and mitigation timeouts |
| `managed-rules.yaml` | Cloudflare Managed WAF, OWASP, and exceptions |

Put matching `skip` rules before rules they should bypass.
Managed WAF supports a simple `cloudflare_managed` / `owasp` / `exceptions` form or provider-shaped `raw_rules`.
The exporter uses `raw_rules` to retain existing overrides.
Rule counts, regex availability, actions, and rate-limit options are plan-dependent; validate before planning.
Account WAF uses account-scoped resources and requires the corresponding account entitlement.

## Security and certificates

Files are under `domains/<domain>/security/`.

| File | Use | Notes |
|---|---|---|
| `hsts.yaml` | Browser HTTPS enforcement | Browsers retain the policy for `max_age`; review preload carefully |
| `bot-management.yaml` | Bot controls | Available fields depend on the configured plan |
| `ip-access-rules.yaml` | IP, range, ASN, or country access rules | Include a reason in `notes` |
| `origin-cert.yaml` | Origin CA certificate from a CSR | Keep the private key on the origin, outside this repository |
| `certificate-pack.yaml` | Certificate packs | Check the account's billing and entitlement before enabling |
| `total-tls.yaml` | Automatic hostname certificates | Requires the relevant service entitlement |
| `ct-alerting.yaml` | Certificate Transparency alerts | Set alert recipients in `emails` |
| `authenticated-origin-pulls.yaml` | Client certificate authentication to the origin | Custom certificates must already be uploaded |

## Cache, redirects, and request rules

| File | Use |
|---|---|
| `cache/cache-rules.yaml` | Cache eligibility and TTL rules |
| `cache/settings.yaml` | Tiered Cache, Cache Reserve, and Argo settings |
| `cache/variants.yaml` | Media format variants |
| `rules/redirects.yaml` | Single redirects |
| `rules/url-rewrites.yaml` | Path and query rewrites |
| `rules/request-headers.yaml` | Headers sent to the origin |
| `rules/response-headers.yaml` | Headers sent to clients |
| `rules/origin.yaml` | Origin connection overrides |
| `rules/config.yaml` | Per-request configuration |
| `rules/compression.yaml` | Compression choices |

Rule lists use stable `ref` values, `expression`, `action_parameters`, and optional `enabled`.
Available parameters and limits depend on the service and plan; use the file's example.
Some cache services have separate billing.

## Zone settings

`settings/zone.yaml` contains `setting_name: value` entries:

```yaml
ssl: strict
min_tls_version: "1.2"
always_use_https: "on"
```

Only listed settings are managed. Removing a setting stops management without resetting its live value.
See [Zone setting values](zone-settings.md) for choices, units, and nested options.

## Account

Set the account ID and highest zone plan in `account/account.yaml`.

| Path under `account/` | Use |
|---|---|
| `lists/ip.yaml`, `lists/asn.yaml`, `lists/hostname.yaml` | Named lists referenced by rules, such as `$office_ips` |
| `lists/redirect.yaml` | Bulk Redirect lists and generated deployment rules |
| `waf/` | Account-scoped WAF rules |
| `settings/logpush.yaml` | Dataset delivery jobs and destinations |
| `settings/notifications.yaml` | Alert policies and delivery mechanisms |
| `settings/notification-webhooks.yaml` | Named webhook destinations |
| `settings/registrar.yaml` | Settings for Cloudflare-registered domains |
| `settings/sso.yaml` | SSO domain verification configuration |
| `settings/user-groups.yaml` | Account groups, policies, and members |
| `settings/dns-settings.yaml` | Account DNS defaults |
| `settings/turnstile.yaml` | Turnstile widgets |

Create lists before deploying zone rules that use them. Remove references before deleting lists.
Some services need external setup, such as a Logpush ownership challenge or SSO verification.
API tokens are managed outside Terraform in this project.

## Export coverage

Zone export covers supported DNS, DNSSEC, WAF and request rules, HSTS, editable zone settings, bot settings, IP access rules, cache settings and variants, Email Routing, Total TLS, CT alerts, and zone-wide Authenticated Origin Pulls. Configured hostname origin pulls are read separately and retain their hostname scope.
Account export also covers lists, WAF, Logpush, notifications and webhooks, one SSO connector, user groups/members, DNS defaults, and supported Turnstile fields.

The inventory report declares every configured service's endpoint status and whether it can be mirrored. Page Rules, Worker routes, other custom rulesets, certificate packs, origin certificates, and externally customized Bulk Redirect deployment rules currently include observation-only coverage. Unknown hostname origin-pull associations cannot be enumerated by the endpoint used here. Logs and products outside the registry are not configuration inventory coverage.

Some individual fields are unrepresentable even within a supported service, such as DNS tags/settings, Worker-owned Email Routing, and unsupported rule parameters. Updates that could discard protected fields are blocked. A state-only plan also blocks lossy exports before publication. Multiple SSO connectors, duplicate names, and ambiguous mappings require manual review.

Read `.export/<root>/EXPORT_REPORT.md`, the complete PR artifact, and the first plan for gaps. Supported new dashboard objects are imported into state before automatic publication. Successful empty reads can clear exported configuration; unreadable services cannot be treated as empty. Vault secret references are preserved rather than writing API credentials into Git.

Registrar list responses do not reliably expose auto-renew/privacy or stable domain-name mappings. Registrar YAML is preserved during resync, and production Registrar mutations are blocked until an adapter can verify those settings. Webhook signing secrets are write-only, so dashboard secret rotations cannot be detected from API snapshots. Changes reverted between observations are not captured; configuration inventory does not replace an event log.
