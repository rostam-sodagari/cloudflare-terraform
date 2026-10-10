# Zone setting values

Edit `domains/<domain>/settings/zone.yaml`. Add only settings you want to manage.
The file uses a mapping, with no `-` before setting names. These are examples, not a baseline to copy wholesale.

```yaml
ssl: strict
min_tls_version: "1.2"
always_use_https: "on"
browser_cache_ttl: 14400
```

Quotes matter: `"on"` is text; `true` is a boolean; `14400` is a number of seconds.
Removing a setting stops managing it without resetting its live value.
Availability depends on the zone's entitlement. Validation checks repository rules; the plan and API also check service availability.

## Text switches

For the following settings, use the quoted text `"on"` or `"off"`:

| Setting | What it controls |
|---|---|
| `0rtt` | TLS early data |
| `always_online` | Archived content during origin outages |
| `always_use_https` | Redirecting HTTP to HTTPS |
| `automatic_https_rewrites` | Rewriting eligible HTTP asset URLs |
| `brotli` | Brotli response compression |
| `browser_check` | Browser integrity checks |
| `development_mode` | Temporarily bypassing edge caching |
| `early_hints` | Sending early asset-loading hints |
| `email_obfuscation` | Hiding published email addresses from scrapers |
| `fonts` | Cloudflare Fonts |
| `hotlink_protection` | Preventing other sites from embedding your images |
| `http2`, `http3` | Visitor HTTP protocol support |
| `ip_geolocation` | Adding visitor country information |
| `ipv6` | IPv6 access to proxied hosts |
| `mirage` | Legacy mobile image optimization |
| `opportunistic_encryption` | Opportunistic HTTPS support |
| `opportunistic_onion` | Tor routing support |
| `origin_error_page_pass_thru` | Passing origin error pages to clients |
| `prefetch_preload` | Prefetching eligible preload resources |
| `privacy_pass` | Privacy Pass challenge handling |
| `response_buffering` | Buffering responses before delivery |
| `rocket_loader` | JavaScript loading optimization |
| `server_side_exclude` | Hiding marked page content from suspicious visitors |
| `sort_query_string_for_cache` | Normalizing query parameter order for caching |
| `speed_brain` | Speculative navigation loading |
| `tls_client_auth` | Client certificate authentication |
| `true_client_ip_header` | Adding the True-Client-IP header |
| `waf` | Legacy WAF setting; use `waf/` files for rulesets |
| `websockets` | WebSocket connections |

Some recognized IDs are legacy services. Keep an exported value only if the current API still allows it; recognition by validation does not guarantee editability.

## Other scalar values

| Setting | Syntax / choices | Meaning |
|---|---|---|
| `ssl` | `off`, `flexible`, `full`, `strict` | `strict` also validates the origin certificate; `flexible` leaves the origin connection unencrypted |
| `min_tls_version` | `"1.0"`, `"1.1"`, `"1.2"`, `"1.3"` | Minimum visitor TLS version; older versions trigger a policy warning |
| `tls_1_3` | `"on"`, `"off"`, `zrt` | TLS 1.3 handling |
| `security_level` | `off`, `essentially_off`, `low`, `medium`, `high`, `under_attack` | Challenge sensitivity |
| `cache_level` | `basic`, `simplified`, `aggressive` | Legacy cache matching mode |
| `browser_cache_ttl` | `14400` | Browser cache duration in seconds; `0` respects origin headers |
| `challenge_ttl` | `1800` | Challenge passage duration in seconds; use an API-supported duration |
| `max_upload` | `100` | Upload limit in MB, within your plan's allowance |
| `proxy_read_timeout` | `120` | Origin read timeout in seconds; changes need the relevant entitlement |
| `polish` | `"off"`, `lossless`, `lossy` | Image optimization |
| `pseudo_ipv4` | `"off"`, `add_header`, `overwrite_header` | IPv4 representation of IPv6 visitors |
| `image_resizing` | `"off"`, `"on"`, `open` | Image transformation access |
| `h2_prioritization` | `"off"`, `"on"`, `custom` | HTTP/2 prioritization |
| `origin_max_http_version` | `"1"`, `"2"` | Highest origin HTTP version; keep quotes |
| `advanced_ddos`, `tls_1_2_only`, `webp` | `"on"`, `"off"` | Additional service-specific text switches |

These service-specific values follow the [Cloudflare zone settings API](https://developers.cloudflare.com/api/resources/zones/subresources/settings/methods/get/). Check its accepted values before changing a setting outside the repository's validated enums.

## Lists and nested values

`ciphers` uses a list of cipher names your origin and visitors support:

```yaml
ciphers:
  - ECDHE-RSA-AES128-GCM-SHA256
  - ECDHE-RSA-AES256-GCM-SHA384
```

`nel` uses a mapping with a boolean inside it, rather than a top-level boolean:

```yaml
nel:
  enabled: true
```

`aegis` takes an existing egress pool ID; use it only with provisioned Aegis service:

```yaml
aegis:
  enabled: true
  pool_id: "<your-provisioned-aegis-pool-id>"
```

`automatic_platform_optimization` takes an options mapping. Enable the service and connect your WordPress integration before configuring its options:

```yaml
automatic_platform_optimization:
  enabled: true
  cache_by_device_type: false
```

The API defines these [nested setting shapes](https://developers.cloudflare.com/api/resources/zones/subresources/settings/methods/get/). Replace placeholders with real values; do not use `true` directly as the value of a setting that expects an options mapping.

## Legacy and special settings

| Recognized setting | How to handle it |
|---|---|
| `cname_flattening` | Deprecated zone-setting route; use DNS settings instead. Account `zone_defaults.flatten_all_cnames` affects new zones only |
| `orange_to_orange` | Deprecated zone-setting route; leave it unmanaged for new configuration |
| `ssl_recommender` | API enrollment uses `enabled`, which this repository's generic zone-setting resource does not map; configure in Cloudflare |
| `ech` | Service-specific Encrypted Client Hello control; use Cloudflare's current feature controls rather than guessing a value here |
| `origin_h2_max_streams` | Advanced origin connection tuning; retain a verified exported numeric value or leave unmanaged |
| `replace_insecure_js` | Legacy recognized ID; leave unmanaged unless the current API documents it for your zone |

For CNAME flattening, follow [Cloudflare's DNS settings instructions](https://developers.cloudflare.com/dns/cname-flattening/set-up-cname-flattening/). Generic zone setting IDs do not automatically add support for a replacement API route.

HSTS belongs in `security/hsts.yaml`. Do not add `security_header` here.
After editing, run `python cf.py validate <domain>` and `python cf.py plan <domain>`.
