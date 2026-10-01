# 3. Service reference

Every file in `domains/_template/` holds a commented, working example; this
page explains the rules behind them. Paths are relative to a domain folder.

General rules for every file:

1. **Keys are identities.** The YAML key (or `ref` in rule lists) becomes
   the Terraform address. Renaming it deletes and recreates the item.
2. **Lists are ordered.** Rule files are evaluated top to bottom.
3. **Quote ambiguous values:** `"on"`, `"off"`, `"true"` as an expression,
   `"1.2"`, IDs. Unquoted, YAML turns them into booleans or numbers.
4. **Run `make test D=<d>` after every edit.** It catches typos, limits and
   plan-gated features without a token.

---

## DNS (`dns/`)

### a.yaml, aaaa.yaml, cname.yaml, mx.yaml, txt.yaml, ns.yaml

```yaml
www:                       # key: permanent id
  name: www                # "@" = apex; relative or fully qualified
  content: example.com
  proxied: true            # A/AAAA/CNAME only; orange cloud
  ttl: 300                 # 1 = auto (default); ignored when proxied
  comment: optional note
```

1. MX needs `priority`.
2. `ns.yaml` is for delegating a subdomain only; apex NS is Cloudflare's.
3. Microsoft 365 DKIM is CNAME-based and belongs in `cname.yaml`.
4. Keep SPF out of `txt.yaml`; a check fails the plan if it finds one.

### spf.yaml

```yaml
"@":
  includes: [spf.protection.outlook.com]
  ip4: [203.0.113.0/28]
  all: "-all"
```

Builds `v=spf1 ip4:203.0.113.0/28 include:spf.protection.outlook.com -all`.
Order is always `a mx ip4 ip6 include extra all`. A check fails if more than
10 DNS lookups are needed (RFC 7208). Use `raw:` for anything unusual.

### dmarc.yaml

```yaml
"@":
  policy: quarantine
  subdomain_policy: reject
  rua: [dmarc@example.com]
```

Published at `_dmarc.<host>`. Roll out `none` > `quarantine` > `reject`
while reading the `rua` reports.

### dkim.yaml

Key is the selector; publishes `<selector>._domainkey` as TXT.

### caa.yaml

```yaml
letsencrypt: { tag: issue, value: letsencrypt.org }
google:      { tag: issue, value: pki.goog }
```

Once any CAA record exists, only the listed CAs may issue. Include every CA
Cloudflare uses for your edge certificates (Universal SSL uses Let's
Encrypt and Google Trust Services; Advanced Certificates may use others) or
renewals fail.

### srv.yaml

```yaml
m365_sip:
  name: _sip._tls
  priority: 100
  weight: 1
  port: 443
  target: sipdir.online.lync.com
```

### DNSSEC

`dns/dnssec.yaml`:

```yaml
status: active
```

1. Apply, then read the DS record: `terraform -chdir=domains/<d> output summary`
   (`dnssec_ds`). Add it at the registrar.
2. **Turning it off:** remove the DS at the registrar first, wait at least
   the DS TTL (often 24 to 48 hours), then set `status: disabled`. The other
   order breaks resolution for validating resolvers.

---

## WAF (`waf/`)

### custom-rules.yaml

```yaml
- ref: block_admin_outside_uk
  description: Admin only from the UK
  expression: (starts_with(http.request.uri.path, "/admin") and not ip.src.country in {"GB"})
  action: block              # block | managed_challenge | js_challenge | challenge | log | skip
```

Skip rules use `skip: { ruleset: current }` or `skip: { phases: [...], products: [...] }`.
Build expressions in the dashboard's expression builder, then paste.

| Plan | Custom rules | Rate limit rules |
|------|--------------|------------------|
| Free | 5 | 1 (10 s period, 10 s timeout) |
| Pro | 20 | 2 |
| Business | 100 | 5 |
| Enterprise | 1000 | 100 |

### rate-limits.yaml

```yaml
- ref: login_rl
  description: Login brute force
  expression: (http.request.uri.path eq "/login" and http.request.method eq "POST")
  period: 60
  requests_per_period: 10
  mitigation_timeout: 600
```

### managed-rules.yaml (Pro and above)

```yaml
cloudflare_managed: { enabled: true }
owasp:
  enabled: true
  action: log                # move to block after a week of tuning
  paranoia_level: 1
  score_threshold: 40        # 60 low | 40 medium | 25 high
exceptions:
  - ref: skip_owasp_webhooks
    description: Payment webhooks
    expression: (http.request.uri.path eq "/webhooks/payments")
    rulesets: [owasp]
```

Tuning OWASP: run in `log`, filter **Security > Events** by the OWASP
ruleset, add exceptions for false positives, then switch to `block`.

---

## Security (`security/`)

### hsts.yaml

```yaml
enabled: true
max_age: 300               # seconds; raise to 31536000 when confident
include_subdomains: false
preload: false
nosniff: true
```

Browsers remember HSTS for `max_age`. Never enable `preload` unless every
subdomain is HTTPS forever; removal from browser preload lists takes months.

### bot-management.yaml

| Plan | Keys |
|------|------|
| Free | `fight_mode: true` |
| Pro | `sbfm_definitely_automated`, `sbfm_verified_bots`, `sbfm_static_resource_protection`, `optimize_wordpress` |
| Business | Pro keys + `sbfm_likely_automated` |
| Enterprise Bot Management | `auto_update_model`, `suppress_session_score`, `bm_cookie_enabled` |
| All | `ai_bots_protection` (block, disabled, only_on_ad_pages), `crawler_protection`, `enable_js` |

Using `fight_mode` on a paid plan or `sbfm_*` on Free fails the plan check.

### ip-access-rules.yaml

```yaml
office_allow:
  mode: whitelist          # block | managed_challenge | challenge | js_challenge | whitelist
  target: ip_range         # ip | ip6 | ip_range | asn | country
  value: 203.0.113.0/24
  notes: Head office
```

For more than a handful of IPs, use an account IP list
(`account/lists/ip.yaml`) and a WAF custom rule: `(ip.src in $office_ips)`.

---

## Cache (`cache/`)

### settings.yaml

```yaml
smart_tiered_cache: "on"
```

### cache-rules.yaml

```yaml
- ref: cache_static
  description: Static assets for a day
  expression: (http.request.uri.path.extension in {"css" "js" "png"})
  action_parameters:
    cache: true
    edge_ttl: { mode: override_origin, default: 86400 }
```

Cache-related zone settings (`browser_cache_ttl`, `cache_level`) live in
`settings/zone.yaml`.

---

## Rules (`rules/`) and cache rules

All rule files share one format and Cloudflare's API field names, so any
example from developers.cloudflare.com converts directly to YAML:

```yaml
- ref: unique_id               # required
  description: what and why
  expression: (http.host eq "www.example.com")
  action_parameters: { ... }   # see the template file for each type
  enabled: true                # optional
```

Do not set `action`; each file sets it for you.

| File | Phase | Typical use |
|------|-------|-------------|
| `cache/cache-rules.yaml` | http_request_cache_settings | cache or bypass, TTLs, cache keys |
| `rules/redirects.yaml` | http_request_dynamic_redirect | www to apex, moved pages |
| `rules/url-rewrites.yaml` | http_request_transform | serve /blog from /news |
| `rules/request-headers.yaml` | http_request_late_transform | headers to the origin |
| `rules/response-headers.yaml` | http_response_headers_transform | security headers to browsers |
| `rules/origin.yaml` | http_request_origin | change port, origin host (Ent) |
| `rules/config.yaml` | http_config_settings | per-path security level, SSL, features |
| `rules/compression.yaml` | http_response_compression | Zstd / Brotli / gzip order |

Limits per file: Free 10, Pro 25, Business 50, Enterprise 300. Plan-gated
fields (e.g. `regex_replace`, origin Host header override) are rejected by
Cloudflare during `make plan`.

---

## Zone settings (`settings/zone.yaml`)

```yaml
ssl: strict
min_tls_version: "1.2"
always_use_https: "on"
browser_cache_ttl: 14400
```

Any setting ID from the Cloudflare API works. Values keep their YAML type.
HSTS is in `security/hsts.yaml`.

---

## Account (`account/`)

Account-wide resources with their own state. Apply `account` **before** a
domain that references a new list, and remove references **before**
deleting a list. CI does this ordering for you.

### lists/ip.yaml, asn.yaml, hostname.yaml

```yaml
blocked_ips:               # list name, used as $blocked_ips
  description: Known bad actors
  items:
    - 203.0.113.7
    - ip: 198.51.100.0/24
      comment: Scanner range
```

### lists/redirect.yaml (Bulk Redirects)

```yaml
marketing_2026:
  items:
    - source_url: example.com/summer
      target_url: https://example.com/offers
      status_code: 301
```

Each list automatically gets one account-level redirect rule. Use this for
hundreds of fixed redirects; use `rules/redirects.yaml` for patterns.

---

## Stop managing something without deleting it

Removing an item from YAML deletes it in Cloudflare on the next apply. To
hand something back to the dashboard instead:

```bash
make init D=<d>
terraform -chdir=domains/<d> state list                      # find the address
terraform -chdir=domains/<d> state rm 'module.domain.module.dns.cloudflare_dns_record.this["a/www"]'
```

Then remove it from the YAML in the same pull request.

Zone settings, bot management and tiered cache are different: removing them
from YAML only stops management; Cloudflare keeps the current value.

---

## Adding a new service

1. Create `modules/<service>/` with `versions.tf`, variables, resources.
2. Read its YAML in `modules/domain-stack/main.tf` (add the path to
   `local.files`) and call the module.
3. Add a commented example file to `domains/_template/<folder>/`.
4. If it is just another ruleset phase, add one line to `local.services` in
   `modules/rules/main.tf` and one to `local.rule_files` in domain-stack.
5. Extend `scripts/export_zone.py` so existing config can be imported.
6. `make test-all`, then document it here.
