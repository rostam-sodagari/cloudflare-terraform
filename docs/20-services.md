# Service reference

*Who this is for: anyone editing YAML who wants the full detail, not just the file header.*

The comment at the top of each file is a short summary with one example.
This page is the full reference, with the plan limits taken from
Cloudflare's documentation ([sources](references.md)).

General rules for every file:

1. **Keys are identities.** The YAML key (or `ref` in rule lists) becomes
   the item's identity. Renaming it deletes and recreates the item.
2. **Lists are ordered.** Rule files run top to bottom.
3. **Quote ambiguous values:** `"on"`, `"off"`, `"1.2"`, `"@"`, IDs, and an
   expression of just `"true"`.
4. **A service this repo has never managed is left alone** while its file is
   empty or fully commented. Once managed, deleting its entries deletes
   them in Cloudflare (the change summary warns you).
5. **Every DNS record needs a `##` documentation block directly above it**
   (Owner, Purpose, Impact, and Proxy for A/AAAA/CNAME) -- see
   [41 Record documentation](41-record-documentation.md).

---

## DNS (`dns/`)

| File | Record | Required fields | Notes |
|---|---|---|---|
| `a.yaml` | A | content (IPv4) | `proxied: true` for websites |
| `aaaa.yaml` | AAAA | content (IPv6) | |
| `cname.yaml` | CNAME | content (hostname) | No other record may share the name |
| `mx.yaml` | MX | content, priority | Lower priority is tried first |
| `txt.yaml` | TXT | content | Not for SPF, DMARC or DKIM |
| `ns.yaml` | NS | content | Subdomain delegation only |
| `spf.yaml` | TXT (built) | none | Keyed by name; 10-lookup limit checked |
| `dmarc.yaml` | TXT at `_dmarc` | none | Roll out none, quarantine, reject |
| `dkim.yaml` | TXT at `<selector>._domainkey` | content | M365 DKIM is CNAME: use `cname.yaml`; set `name` explicitly if the selector contains a dot or DKIM is published under a subdomain (e.g. Mailgun's `mta._domainkey.mg`) |
| `caa.yaml` | CAA | tag, value | Keep `letsencrypt.org` and `pki.goog` |
| `srv.yaml` | SRV | name, priority, weight, port, target | |
| `dnssec.yaml` | DNSSEC | status | Cannot be deleted by removing the file |

Common fields: `name` ("@" or a label), `ttl` (leave out for automatic;
60 to 86400, 30 on Enterprise), `comment` (100 characters on Free, 500 paid).

**TXT quoting (txt, spf, dmarc, dkim).** TXT content is one or more
strings in double quotes, and Cloudflare adds the quotes itself to new
records saved without them ([Cloudflare DNS record types](https://developers.cloudflare.com/dns/manage-dns-records/reference/dns-record-types/)).
So the module always sends the quoted form, splitting text longer than 255
characters into several quoted parts; what is sent is what Cloudflare
stores, and plans stay clean. You write plain text. Values copied from
Cloudflare with their quotes (`'"v=spf1 ..."'`, in single quotes) are
accepted unchanged. `quoted: false` keeps an old record that Cloudflare
holds without quotes; the exporter sets it where needed.

Checks: valid IPs and hostnames (no trailing dot), duplicate records, a
CNAME clashing with other records, SPF or DMARC in the wrong file.

### DNSSEC

- On: `status: active`, apply, then add the DS record (Terraform output
  `dnssec_ds`) at the registrar.
- Off: remove the DS record at the registrar, wait 24 to 48 hours, then
  `status: disabled`.
- Deleting `dnssec.yaml` after it has been applied is refused on purpose
  (`prevent_destroy`), because switching DNSSEC off while the registrar
  still publishes a DS record makes the domain unresolvable.

### email-routing.yaml

Forwards mail for this domain to real mailboxes: `enabled`,
`support_subaddress` (optional), `rules` (`ref`, `matchers`, `actions` --
`ref` is the stable identity, same convention as every other rule file),
`catch_all`. Destination addresses must already be verified with
Cloudflare (it e-mails a confirmation link); this file doesn't request or
track that verification.

---

## WAF (`waf/`)

### custom-rules.yaml

| Plan | Rules | Log action | Regex | Custom block page |
|---|---|---|---|---|
| Free | 5 | no | no | no |
| Pro | 20 | no | no | yes |
| Business | 100 | no | yes | yes |
| Enterprise | 1000 | yes | yes | yes |

Actions: `block`, `managed_challenge`, `js_challenge`, `challenge`, `skip`,
and `log` (Enterprise). `skip` rules need a `skip:` block saying what to
skip and belong at the top.

### rate-limits.yaml

| Plan | Rules | Period (s) | Timeout (s) | Counts by | counting_expression |
|---|---|---|---|---|---|
| Free | 1 | 10 | 10 | IP | no |
| Pro | 2 | up to 60 | up to 3600 | IP | no |
| Business | 5 | up to 600 | up to 86400 | IP, IP with NAT | yes |
| Enterprise | 100 | up to 3600 | up to 86400 | many | yes |

Allowed periods: 10, 60, 120, 300, 600, 3600. Allowed timeouts: 0, 10, 60,
120, 300, 600, 3600, 86400. `characteristics` must include `cf.colo.id`.

### managed-rules.yaml (Pro and above)

Simple form: `cloudflare_managed`, `owasp` (`paranoia_level` 1 to 4,
`score_threshold` 60 low / 40 medium / 25 high, `action`), and
`exceptions` (skip a ruleset for matching traffic, placed first).

- `log` is Enterprise only. On Pro and Business, tune OWASP with
  `managed_challenge` or `score_threshold: 60`, then tighten.
- Leaving `action` out uses Cloudflare's default (block).
- `raw_rules:` holds the ruleset exactly as Cloudflare does; the exporter
  writes this form for existing zones so nothing changes on adoption.
- Emptying the file after it has been applied deletes the managed WAF
  protection; the change summary warns.
- **"Deleted and recreated, expect a brief gap" can mean two different
  things.** For a *content* change (rule overrides, adding/removing a
  managed ruleset deployment), this is Cloudflare's own operational note,
  not a Terraform replace: the plan shows a clean in-place *update* for
  `cloudflare_ruleset.managed`, confirmed by testing both cases directly
  in `raw_rules:` form. But a **genuine Terraform replace** happens if the
  ruleset's `name` ever differs from this repo's `"Managed WAF rulesets"`
  literal -- the provider forces a delete+recreate on any `name` change
  (`stringplanmodifier.RequiresReplace()` in the provider's own source;
  this does *not* show up in `terraform providers schema -json`, which is
  why an earlier check of this repo missed it). That mismatch is most
  likely on a zone adopted from an existing ruleset whose dashboard-given
  name isn't exactly that literal. Fixed here with `lifecycle {
  ignore_changes = [name] }` on every `cloudflare_ruleset` in this repo
  (`modules/waf`, `modules/account-waf`, `modules/lists`, `modules/rules`)
  -- the name is cosmetic only, so nothing is lost by never reconciling it.

---

## Security (`security/`)

**hsts.yaml**: `enabled`, `max_age` (start at 300), `include_subdomains`,
`preload` (needs include_subdomains and max_age 31536000), `nosniff`.
Browsers keep enforcing HTTPS for `max_age` even after you switch it off.

**bot-management.yaml**: settings depend on the plan.

| Plan | Settings |
|---|---|
| Free | `fight_mode` |
| Pro | `sbfm_definitely_automated`, `sbfm_verified_bots`, `sbfm_static_resource_protection`, `optimize_wordpress`, `enable_js` |
| Business | Pro + `sbfm_likely_automated` |
| Enterprise Bot Management | `auto_update_model`, `suppress_session_score`, `bm_cookie_enabled` |
| All | `ai_bots_protection`, `crawler_protection`, `is_robots_txt_managed` |

**ip-access-rules.yaml**: `mode` (whitelist, block, managed_challenge,
challenge, js_challenge), `target` (ip, ip6, ip_range, asn, country),
`value`, `notes`. IPv4 ranges must be /16 or /24; IPv6 /32, /48 or /64.
Blocking a whole country is Enterprise only.

**total-tls.yaml**: `enabled`, `certificate_authority` (optional).
Automatic certificate issuance for every hostname on the zone.

**ct-alerting.yaml**: `enabled`, `emails` (optional). Alerts when a
Certificate Transparency log sees a new certificate issued for this zone
-- an early warning for mis-issued certs.

**origin-cert.yaml**: `csr`, `hostnames`, `request_type`
(origin-rsa/origin-ecc), `requested_validity` (optional). Issues a
Cloudflare Origin CA certificate from a CSR **you** generate; the
matching private key stays on your origin server and never enters this
repo. The validator rejects anything that looks like a private key here.

**certificate-pack.yaml**: `certificate_authority`, `type`
(advanced/custom), `validation_method`, `validity_days`, `hosts` and
`cloudflare_branding` (optional). Orders an Advanced Certificate Manager
pack -- **can be a billable action** depending on the CA and type; check
Cloudflare's pricing before enabling this.

**authenticated-origin-pulls.yaml**: `enabled`, `hostname` (optional,
zone-wide if left out), `cert_id` (optional -- references a client
certificate already uploaded via the dashboard; left out, Cloudflare's
own shared certificate is used). Uploading a *custom* certificate needs
its private key, which this repo deliberately doesn't accept -- upload it
via the dashboard first.

---

## Cache and rules

All rule files share one format: `ref`, `description`, `expression`,
`action_parameters`, optional `enabled`. Field names are Cloudflare's own,
and the check compares them with the provider schema, so a typo such as
`operaton` is caught with a suggestion.

| File | What it does | Rules per plan (Free/Pro/Business/Ent) | Plan notes |
|---|---|---|---|
| `cache/cache-rules.yaml` | cache or bypass, TTLs | 10 / 25 / 50 / 300 | needs proxied DNS |
| `cache/settings.yaml` | Smart/Regional Tiered Cache, Cache Reserve, Argo Smart Routing | | Cache Reserve and Argo have their own cost |
| `cache/variants.yaml` | per-format image/media variants to serve | | |
| `rules/redirects.yaml` | single redirects | 10 / 25 / 50 / 300 | regex Business+ |
| `rules/url-rewrites.yaml` | rewrite path or query | 10 / 25 / 50 / 300 | `regex_replace` Business+ |
| `rules/request-headers.yaml` | headers to your server | 10 / 25 / 50 / 300 | |
| `rules/response-headers.yaml` | headers to browsers | 10 / 25 / 50 / 300 | |
| `rules/origin.yaml` | change origin port, host | 10 / 25 / 50 / 300 | only port below Enterprise |
| `rules/config.yaml` | settings per request | 10 / 25 / 50 / 300 | |
| `rules/compression.yaml` | compression order | 10 / 25 / 50 / 300 | |

---

## Zone settings (`settings/zone.yaml`)

`setting_name: value`, one per line. Any setting ID from the Cloudflare
API works; unknown names get a warning with a suggestion. The check
enforces quoting of `"on"`/`"off"` and version numbers, and allowed values
for `ssl`, `min_tls_version`, `security_level`, `cache_level`, `tls_1_3`.
Removing a line stops managing that setting; it is not reset.

---

## Account (`account/`)

`account.yaml`: `account_id`, `plan` (highest plan in the account; used
for list limits).

| List file | Use in rules | Plans |
|---|---|---|
| `lists/ip.yaml` | `(ip.src in $name)` | all (Free 1 list, Pro/Business 10, Ent 1000) |
| `lists/asn.yaml` | `(ip.src.asnum in $name)` | Enterprise |
| `lists/hostname.yaml` | | Enterprise |
| `lists/redirect.yaml` | Bulk Redirects, rule created for you | all (5 lists, Ent 25) |

Order: a new list is applied (account first) before domains use it; a list
is removed from every rule before it is deleted. The check stops a rule
from using a list that does not exist.

**Account-level WAF** (`waf/custom-rules.yaml`, `waf/rate-limits.yaml`,
`waf/managed-rules.yaml`): the exact same shape as a domain's `waf/`
files (same validator, reused) -- see the WAF section above -- but these
rules apply across every zone in the account. Deploying account-level WAF
is an Enterprise feature.

Everything below lives under `account/settings/`, kept apart from
`account/main.tf`/`providers.tf` and the generated plan/state files at
the account root, the same way `lists/` and `waf/` already were.

**`settings/logpush.yaml`**: Logpush jobs for account-level datasets
(`dataset`, `destination_conf`, `enabled`, `filter`, `frequency`,
`logpull_options`, `ownership_challenge`). A new destination needs a
one-time ownership challenge Cloudflare writes to it; this repo doesn't
automate fetching that token.

**`settings/notifications.yaml`** and **`settings/notification-webhooks.yaml`**:
alert policies (`alert_type`, `mechanisms: {email, webhooks, pagerduty}`,
optional `filters`) and the webhook destinations they reference by name.
Each policy needs at least one mechanism.

**`settings/registrar.yaml`**: `auto_renew`, `locked`, `privacy` -- only
for domains actually registered through Cloudflare Registrar, keyed by
the exact registered domain name.

**`settings/sso.yaml`**: `email_domain`, `enabled`, `begin_verification`.
Starts Cloudflare's domain-verification flow for SSO; doesn't finish SSO
setup by itself.

**`settings/user-groups.yaml`**: least-privilege role groups, keyed by
name. `policies` (access/permission_groups/resource_groups -- Cloudflare
permission-group UUIDs you look up yourself, passed through as-is) and
`members` (existing account Member IDs to assign to the group).

**`settings/dns-settings.yaml`**: `enforce_dns_only`, `zone_defaults`
(passed through as-is). Account-wide DNS resolution behavior and
defaults for new zones.

**`settings/turnstile.yaml`**: `domains` (a widget can cover more than
one), `mode` (managed/non-interactive/invisible), `bot_fight_mode`
(optional). A CAPTCHA alternative for public forms. The sitekey (public,
embed it in your page) and secret key (server-side, verifies challenge
responses) are returned by Cloudflare, not written here -- treat the
secret like a credential even though you never type it into this repo.

**Not modeled: account token scoping.** `cloudflare_account_token`'s
`value` is the live token secret, computed back and stored in Terraform
state -- creating tokens this way would scatter a second copy of the
secret outside Delinea. Tokens stay dashboard/API-created and
Delinea-stored.

---

## Stop managing something without deleting it

Removing an item from YAML deletes it in Cloudflare. To stop managing it
here instead, without deleting it, a maintainer removes it from state and
the YAML in the same PR:

```bash
python3 cf.py init example.com
terraform -chdir=domains/example.com state list
terraform -chdir=domains/example.com state rm 'module.domain.module.dns.cloudflare_dns_record.this["a/www"]'
```

Zone settings, bot settings and tiered cache are different: removing them
from YAML only stops management; Cloudflare keeps the current value.
