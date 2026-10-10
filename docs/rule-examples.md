# Rule syntax and extra examples

Each rule is a list item beginning with `- ref:`. Keep `ref` stable and unique across the zone's rule files.
Use a short `description`, an `expression` that selects traffic, and the parameters for the chosen file.
`enabled: false` retains a rule while disabling it. Omitting `enabled` defaults to true.

## Expressions

| Match | Expression |
|---|---|
| One hostname | `'(http.host eq "api.example.com")'` |
| One path | `'(http.request.uri.path eq "/login")'` |
| A path prefix | `'(starts_with(http.request.uri.path, "/admin/"))'` |
| POST requests | `'(http.request.method eq "POST")'` |
| Several IPs | `'(ip.src in {203.0.113.7 198.51.100.9})'` |
| An account list | `'(ip.src in $office_ips)'` |
| All requests | `"true"` (keep the quotes) |

Combine conditions with `and`, `or` and `not`, using parentheses for grouping. Expressions are text in the [Cloudflare Rules language](https://developers.cloudflare.com/ruleset-engine/rules-language/), not YAML objects or Python code.
Regex operations require Business or Enterprise in this repository. Define an account list before using its name.

## Cache bypass and optional TTLs

Put this in `cache/cache-rules.yaml`. Do not cache authenticated or personalized pages.

```yaml
- ref: bypass_account
  description: Keep account pages out of the shared cache
  expression: '(starts_with(http.request.uri.path, "/account"))'
  action_parameters:
    cache: false
```

For a cacheable static-assets rule, optional nested parameters include:

```yaml
action_parameters:
  cache: true
  edge_ttl:
    mode: override_origin
    default: 86400
    status_code_ttl:
      - status_code: 404
        value: 60
  browser_ttl:
    mode: respect_origin
  serve_stale:
    disable_stale_while_updating: false
  respect_strong_etags: true
```

This is a parameters block to place inside a complete rule. `default` and TTL values are seconds.
Advanced cache options include `cache_key` for cache-key composition, `cache_reserve` for eligibility, and `origin_cache_control` for respecting origin instructions. Their availability and combinations are described in [Cache Rules settings](https://developers.cloudflare.com/cache/how-to/cache-rules/settings/).

## Header operations

Put this in `rules/request-headers.yaml` to remove an unwanted origin request header:

```yaml
- ref: remove_debug_header
  description: Strip the debug flag before reaching the origin
  expression: "true"
  action_parameters:
    headers:
      X-Debug:
        operation: remove
```

Request transforms use `set` or `remove`. For `set`, choose `value` for fixed text or `expression` for a computed value; omit both for `remove`. Header restrictions are listed in the [request header reference](https://developers.cloudflare.com/rules/transform/request-header-modification/reference/).
Response transforms in `rules/response-headers.yaml` also support `add` to append a value.

## Enterprise origin overrides

Put this in `rules/origin.yaml`, using your real server and TLS hostname:

```yaml
- ref: api_origin
  description: Route API requests to the dedicated origin
  expression: '(starts_with(http.request.uri.path, "/api/"))'
  action_parameters:
    origin:
      host: origin-api.example.com
      port: 8443
    host_header: api.example.com
    sni:
      value: api.example.com
```

`origin.host`, `host_header` and `sni` require Enterprise here. Other plans can override `origin.port`.

## Per-request configuration

Put this in `rules/config.yaml`. These toggles are booleans, unlike quoted zone switches:

```yaml
- ref: admin_settings
  description: Adjust browser features for the admin application
  expression: '(starts_with(http.request.uri.path, "/admin/"))'
  action_parameters:
    rocket_loader: false
    email_obfuscation: false
    automatic_https_rewrites: true
```

Optional nested parameters use the provider's structure, for example `autominify: {css: true, html: false, js: false}` where that feature remains available. Do not assume every `settings/zone.yaml` key is a per-request parameter.

## Managed WAF exceptions

In `waf/managed-rules.yaml`, add `exceptions` alongside the simple ruleset settings:

```yaml
cloudflare_managed:
  enabled: true
owasp:
  enabled: true
  paranoia_level: 1
  score_threshold: 40
exceptions:
  - ref: skip_owasp_for_webhook
    description: Trusted webhook skips OWASP checks
    expression: '(http.request.uri.path eq "/trusted-webhook" and ip.src in {203.0.113.7})'
    rulesets:
      - owasp
```

Use a narrow expression. `rulesets` accepts `owasp`, `cloudflare_managed`, or actual ruleset IDs.
Managed WAF needs Pro or higher for zone configuration; account WAF needs account entitlement.

## Advanced exported managed rules

`raw_rules` replaces the simple form when non-empty. Use it to retain API-shaped overrides from an export.
Replace the sample ID with the actual managed ruleset ID; `enabled: false` is a staging example:

```yaml
raw_rules:
  - ref: managed_rules_with_override
    description: Execute a managed ruleset with its default actions
    expression: "true"
    action: execute
    enabled: false
    action_parameters:
      id: "<managed-ruleset-id>"
      overrides:
        enabled: true
```

An override can contain `rules: [{id: '<rule-id>', enabled: false}]` or `categories: [{category: '<category-name>', enabled: false}]` under `overrides`. Use real IDs/categories from your export. Omit an override to preserve the managed ruleset default.
The pinned provider schema in `scripts/data/ruleset_rule_schema.json` is the advanced field inventory; an accepted schema field must still be valid for the chosen rule phase and entitlement.

Run `python cf.py validate <domain>` and review `python cf.py plan <domain>` after each change.
