# YAML field reference

The YAML headers show the essentials and examples. Use this reference for optional fields and defaults.

For indentation and quoting, see [Configuration](configuration.md). For additional rule examples, see [Rule examples](rule-examples.md).

Zone files are relative to `domains/<domain>/`. Account paths start with `account/`.

## dns/a.yaml

Required: name and content. proxied defaults to DNS only when omitted.

## dns/aaaa.yaml

Required: name and content. An IPv6 address is text, e.g. '2001:db8::10'.

## dns/cname.yaml

Required: name and content. The CNAME conflict rule applies below the zone apex.
Apex CNAMEs are flattened, so MX/TXT can coexist at '@'.

## dns/mx.yaml

Required: name, content and priority. priority is an integer from 0 to 65535.
MX records are DNS only; do not add proxied: true.

## dns/txt.yaml

Required: name and content. Put text containing ': ' or '#' in quotes.
quoted is optional (default true); false preserves an exported legacy TXT record.

## dns/ns.yaml

Required: name and content. Name the delegated subdomain, such as dev.
Use one entry per nameserver; NS records are DNS only.

## dns/spf.yaml

All fields are optional; omitted lists are empty and a/mx default to false.
includes/ip4/ip6/extra are lists: [item1, item2] or indented '- ' lines.
extra: ['exists:%{i}.spf.example.com'] adds an advanced SPF mechanism as written.
all: '-all' rejects; '~all' soft-fails; '?all' is neutral; '+all' allows anyone.
Use either builder fields or raw: 'v=spf1 include:_spf.google.com -all'.
raw takes precedence over the builder. Do not publish two SPF policies for one name.
ttl: optional, 1 = automatic; otherwise 60-86400 (30 minimum on Enterprise).
comment: optional text note in Cloudflare. quoted: optional, default true.

## dns/dmarc.yaml

policy defaults to none; optional subdomain_policy uses none/quarantine/reject.
pct: integer 0-100; percentage of messages subject to enforcement.
rua: [reports@example.com] for summaries; ruf: [failures@example.com] for failure reports.
adkim/aspf: r (relaxed) or s (strict) identifier alignment; omit for receiver defaults.
fo: text '0', '1', 'd' or 's'; combine with ':' (e.g. '1:d') for failure-report options.
raw: 'v=DMARC1; p=none; rua=mailto:reports@example.com' overrides builder fields.
ttl: optional, 1 = automatic; otherwise 60-86400 (30 minimum on Enterprise).
comment: optional text. quoted: optional, default true.

## dns/dkim.yaml

Required: content. Replace the entire sample key with your provider's real key.
The '...' in the example is an illustration, not a usable public key.
ttl: optional, 1 = automatic; otherwise 60-86400 (30 minimum on Enterprise).
comment: optional text. quoted: optional, default true.

## dns/caa.yaml

Required: tag and value. name defaults to '@'; flags defaults to 0.
flags: integer 0-255 (normally 0; 128 marks issuer-critical handling).
ttl: optional, 1 = automatic; otherwise 60-86400 (30 minimum on Enterprise).
comment: optional text. Example report entry: {tag: iodef, value: 'mailto:security@example.com'}.

## dns/srv.yaml

Required: name, priority, weight, port and target. All three numbers are 0-65535.
Lower priority is preferred; weight shares traffic between equal-priority targets.
port is the listening port (e.g. 443); target is a hostname, without a URL path.
ttl: optional, 1 = automatic; otherwise 60-86400 (30 minimum on Enterprise).
comment: optional text.

## dns/dnssec.yaml

Required: status. Use the registrar's DS cache lifetime when waiting to disable DNSSEC.

## dns/email-routing.yaml

Required: enabled. rules and catch_all are optional; omit either if unused.
matchers/actions are lists; each nested item starts with '- '.
forward: value is a list of verified mailboxes, e.g. [sales-team@example.net].
worker: value is a list containing your deployed Email Worker's name.
drop: omit value. For catch_all drop, omit destination.
Catch-all forward and worker actions require destination; drop omits it.
Rules accept numeric priority. Catch-all accepts name and enabled (default true).
Only configure forwarding for a domain whose mail should use Cloudflare Email Routing.

## waf/custom-rules.yaml

Required by Terraform: ref, description, expression and action. enabled defaults to true.
ref: 1-120 letters, digits, '_' or '-'; keep it unique across this zone's rule files.
skip.ruleset: current; skip.phases: [http_ratelimit, http_request_firewall_managed, http_request_sbfm].
skip.products: [bic, hot, rateLimit, securityLevel, uaBlock, waf, zoneLockdown].
Use only the phases/products you intend to bypass. skip.log defaults to true.
response: {status_code: 403, content_type: text/plain, content: 'Access denied'}.
Custom responses need block on a paid plan; status_code 400-499; content is required.
content_type: text/html, text/plain, application/json or text/xml.

## waf/rate-limits.yaml

Required by Terraform: ref, description, expression and requests_per_period (integer >= 1).
period defaults to 10 seconds. mitigation_timeout defaults to 10 seconds.
Plan maximums (period / timeout): Free 10/10; Pro 60/3600;
Business 600/86400; Enterprise 3600/86400. Free timeout must be exactly 10.
enabled: optional boolean, default true. action defaults to block; log is Enterprise only.
characteristics: [ip.src, cf.colo.id] counts each visitor IP at each Cloudflare location.
Business also supports cf.unique_visitor_id; Enterprise accepts custom characteristics.
counting_expression: optional rule expression (Business/Enterprise), e.g. '(http.response.code eq 403)'.
requests_to_origin: optional boolean; true counts requests reaching the origin.
response: {status_code: 429, content_type: text/plain, content: 'Too many requests'}.
Custom responses need block on a paid plan; status_code 400-499;
content_type: text/html, text/plain, application/json or text/xml.

## waf/managed-rules.yaml

Choose the simple form OR non-empty raw_rules (advanced, provider-shaped list).
Simple form defaults: both rulesets enabled; OWASP paranoia_level 1, score_threshold 40.
Override action: block, managed_challenge, js_challenge, challenge, or log (Enterprise).
Omit action to keep the managed ruleset's default actions.
exceptions: list of {ref, description, expression, rulesets}; all four fields are required.
rulesets: [owasp, cloudflare_managed] or a list of real 32-character ruleset IDs.
raw_rules entries need their API action/expression/action_parameters; retain exported overrides.
See docs/rule-examples.md for exception and raw_rules examples.

## security/hsts.yaml

When this file has configuration, enabled/nosniff default to true; include_subdomains/preload to false.
max_age defaults to 31536000 if omitted: set 300 explicitly when first enabling.
max_age: integer 0-31536000 seconds. All other fields: true or false.
include_subdomains extends the policy to subdomains; nosniff disables MIME sniffing.

## security/bot-management.yaml

All fields are optional; list only settings you intend to manage.
Boolean values (true/false): fight_mode, enable_js, sbfm_static_resource_protection,
optimize_wordpress, is_robots_txt_managed, auto_update_model,
suppress_session_score, bm_cookie_enabled.
sbfm_definitely_automated/sbfm_likely_automated: allow, block or managed_challenge.
sbfm_verified_bots: allow or block (search engines and other verified bots).
ai_bots_protection: block, disabled or only_on_ad_pages.
crawler_protection: enabled or disabled (text, not a boolean).
bm_cookie_enabled, auto_update_model and suppress_session_score need Enterprise.
enable_js runs JavaScript detections; fight_mode enables Free Bot Fight Mode.
sbfm_static_resource_protection extends checks to assets; optimize_wordpress adjusts WordPress handling.
is_robots_txt_managed lets Cloudflare prepend managed robots.txt content.
auto_update_model upgrades detection models; suppress_session_score disables session score tracking.
bm_cookie_enabled allows the Bot Management cookie on visitor devices.
Choose the example for your plan, not both:

## security/ip-access-rules.yaml

Required: mode, target and value. notes is optional text explaining the rule.
Examples by target: ip -> '203.0.113.7'; ip6 -> '2001:db8::7';
ip_range -> '203.0.113.0/24'; asn -> 'AS64496'; country -> 'GB'.
Do not put the country name or a numeric ASN without 'AS' in value.

## security/total-tls.yaml

Required: enabled (boolean). Omit certificate_authority for the service default.

## security/ct-alerting.yaml

Required: enabled (boolean). emails: [security@example.com, ops@example.com].

## security/origin-cert.yaml

Required: csr, hostnames and request_type. Keep the PEM lines indented under csr: |.
Replace the entire placeholder CSR with the real CSR; '...' cannot be submitted.
requested_validity: days, one of 7, 30, 90, 365, 730, 1095, 5475; optional.
Use fully qualified hostnames; '*.example.com' covers one subdomain level.

## security/certificate-pack.yaml

Required: certificate_authority, type, validation_method and validity_days.
hosts: optional list, e.g. [example.com, '*.example.com']; replace with your hostnames.
cloudflare_branding: optional boolean (true/false), subject to certificate type.

## security/authenticated-origin-pulls.yaml

Required: enabled. hostname is optional text, e.g. api.example.com.
With hostname, zone_enabled optionally sets the zone default independently.
For a hostname-specific configuration, supply cert_id for an uploaded certificate.
The origin must be configured to validate the presented client certificate.

## cache/settings.yaml

All fields are optional quoted text: 'on' or 'off'. Omit services you do not use.

## cache/variants.yaml

All format keys are optional; values are MIME-type lists, not file extensions.
Example long-list syntax: webp:
  - image/webp

## cache/cache-rules.yaml

edge_ttl.mode: respect_origin, bypass_by_default or override_origin.
browser_ttl.mode: respect_origin, bypass_by_default, override_origin or bypass.
default: integer seconds, needed when you choose override_origin.
Optional edge_ttl.status_code_ttl: [{status_code: 404, value: 60}].
Other options and a bypass example: docs/rule-examples.md.

## rules/redirects.yaml

Choose target_url.value for a fixed full URL or target_url.expression for a computed URL.
Do not set both. status_code also accepts 303 (redirect using GET).
preserve_query_string: true keeps '?key=value'; false drops it.
To redirect one page only, match '(http.request.uri.path eq "/old")'
and use target_url: {value: 'https://example.com/new'}.

## rules/url-rewrites.yaml

uri is required for a URL rewrite. path/query are optional; set at least one.
Choose value (fixed text) OR expression (computed text) for each, not both.
uri.query.value contains 'a=1&b=2', without the leading '?'; '' removes the query.
Rewrites change the origin request; they do not redirect the visitor's browser.

## rules/request-headers.yaml

headers is a mapping of header names to operations. remove needs no value/expression.
set replaces the value; choose value (fixed text) OR expression (computed), not both.
The shared provider schema also lists add; request-header transforms support set/remove.
For a fixed header: X-App: {operation: set, value: website}.
For removal: X-Debug: {operation: remove}.

## rules/response-headers.yaml

headers is a mapping. set replaces; add appends; remove needs no value/expression.
Choose value (fixed text) OR expression (computed), not both, for set/add.
For removal: X-Powered-By: {operation: remove}.

## rules/origin.yaml

origin.port: integer 1-65535. Enterprise origin.host: DNS hostname, no scheme/path.
Enterprise host_header: text hostname (HTTP Host header override).
Enterprise sni: {value: api.example.com} (TLS certificate hostname override).
Omitted fields keep the normal origin behavior.

## rules/config.yaml

Unlike settings/zone.yaml, per-request toggle values here are booleans true/false.
Common toggles: bic, disable_apps, disable_rum, disable_zaraz, hotlink_protection,
mirage, opportunistic_encryption, rocket_loader,
email_obfuscation, automatic_https_rewrites. Availability depends on entitlement.
polish is text: off, lossless, lossy or webp (phase/entitlement-dependent).
Use only parameters supported for Configuration Rules, not every zone setting.
See docs/rule-examples.md for nested options.

## rules/compression.yaml

Required parameter: algorithms, a list of {name: <choice>}, tried in order.
Use [{name: none}] to disable compression for matching traffic.

## settings/zone.yaml

Find the complete list of recognized settings, value types and examples in docs/zone-settings.md.
ssl strict validates your origin's certificate; full encrypts without that validation.
min_tls_version: quoted '1.0', '1.1', '1.2' or '1.3'; prefer a version your clients support.
Each setting is optional. Avoid copying the entire reference into a real zone.

## account/account.yaml

The Cloudflare account that owns your zones (required).
account_id: required quoted 32-character Account ID from Account home > API.
plan: free, pro, business or enterprise; highest zone plan, used for list limits.
example: true marks this repository's test account; remove it for a real account.
Keep the account's existing data below; replace the sample ID before real deployment.

## account/lists/ip.yaml

Named IP lists shared by all zones. Required per list: items.
List names: 1-50 lowercase letters, digits or '_'; unique across all list files.
description: optional text. items: a list of IPs or CIDR ranges (IPv4 or IPv6).
Use a plain address, or {ip: <address>, comment: <optional explanation>}.
Reference with '(ip.src in $office_ips)' in a rule expression.
Limits: Free 1 list; Pro/Business 10; Enterprise 1000 custom lists.
Create a list before deploying rules that use it; remove references before deleting it.

## account/lists/asn.yaml

Named network (ASN) lists; Enterprise only. Required per list: items.
List names: 1-50 lowercase letters, digits or '_'; unique across list files.
description: optional text. Each item is an integer ASN, without the 'AS' prefix.
Use a number, or {asn: 64496, comment: <optional explanation>}.
Reference with '(ip.src.asnum in $hosting_asns)' in a rule expression.

## account/lists/hostname.yaml

Named hostname lists; Enterprise only. Required per list: items.
List names: 1-50 lowercase letters, digits or '_'; unique across list files.
description: optional text. Hostnames contain no scheme, path or trailing dot.
Use text, or {hostname: partner.example, comment: <optional explanation>}.
Reference the list using a hostname field, e.g. '(http.host in $partner_hosts)'.

## account/lists/redirect.yaml

Bulk Redirect lists; a deployment rule is created for each list automatically.
List names: 1-50 lowercase letters, digits or '_'; unique across list files.
Required per list: items. description: optional text; enabled defaults to true.
Required per item: source_url (no scheme) and target_url (complete http/https URL).
status_code: 301 (default), 302, 307 or 308. comment: optional text.
include_subdomains: also match subdomains (boolean, default false).
subpath_matching: also match child paths (boolean, default false).
preserve_path_suffix: retain child paths; requires subpath_matching: true.
preserve_query_string: keep '?key=value' (boolean, default false).
Set list enabled: false to retain it while disabling its deployment rule.
Limits: 5 lists, or 25 on Enterprise. Use zone rules/redirects.yaml for expressions.

## account/settings/logpush.yaml

Logpush jobs, keyed by a stable job name.
Required: dataset and exactly one destination_conf or destination_conf_ref. enabled defaults to true.
dataset: an account dataset you have access to, e.g. audit_logs or access_requests.
destination_conf: quoted destination URL, e.g. 's3://my-bucket/audit?region=us-east-1'.
destination_conf_ref: vault map key for a URL containing credentials; see [Setup](setup.md#external-service-secrets).
ownership_challenge: optional text token from Cloudflare's destination verification file.
filter: optional JSON text, not a YAML mapping. Use the Logpush JSON filter language.
frequency: optional high or low (legacy provider field).
logpull_options: optional query-string text such as 'fields=Action,ActorEmail'.
frequency/logpull_options are deprecated provider fields supported by this repository.
New output_options/max_upload_* fields are not modeled here; do not add them.
Dataset fields and destination formats: https://developers.cloudflare.com/logs/

## account/settings/notification-webhooks.yaml

Webhook destinations, keyed by the name used in notifications.yaml.
Required: HTTPS url or url_ref for a credential-bearing endpoint in the vault. secret_ref: optional signing-secret key in the same externally supplied map.
Use a real endpoint you control. Avoid storing credentials in a readable repository.

## account/settings/notifications.yaml

Notification policies, keyed by a stable name.
Required: alert_type and mechanisms. description: optional text; enabled defaults to true.
alert_type: API alert identifier available to this account, e.g. dos_attack_l7.
mechanisms needs at least one non-empty list: email, webhooks or pagerduty.
email: mailbox addresses. webhooks: names in notification-webhooks.yaml.
pagerduty: existing integration IDs as quoted text, not URLs.
alert_interval: optional text; accepted intervals depend on alert_type.
filters: optional mapping; keys depend on alert_type, usually lists of text values.
Example zone filter: {zones: ['0123456789abcdef0123456789abcdef']}.
Only add a filter if the chosen alert supports it.
Alert choices: https://developers.cloudflare.com/notifications/notification-available/

## account/settings/registrar.yaml

Cloudflare Registrar settings, keyed by the actual registered domain name.
Only use domains registered with Cloudflare Registrar.
All fields are optional booleans (true/false); omit a field to leave its value unspecified.
auto_renew: renew registration automatically. locked: prevent domain transfers.
privacy: enable WHOIS contact privacy where supported by the registration.

## account/settings/sso.yaml

Start SSO domain verification; complete identity-provider setup in Cloudflare.
Required: email_domain, your organization's domain, without '@' or 'https://'.
enabled: optional boolean. begin_verification: optional boolean to start verification.
Follow the resulting DNS verification instructions in the Cloudflare dashboard.

## account/settings/user-groups.yaml

Groups for existing account members, keyed by a stable group name.
policies: optional list, default empty. members: optional list, default empty.
Each policy needs access: allow or deny, permission_groups and resource_groups.
Each permission/resource group is an object containing id, not a bare ID string.
Look up real permission-group IDs and resource-group IDs in the account IAM API.
members: list of Account Member IDs (not email addresses or User IDs).
Get Member IDs from the account members API; invite members before assigning them.
Replace every '<...>' placeholder with a real ID from this account.

## account/settings/dns-settings.yaml

Account-wide DNS behavior; all fields are optional.
enforce_dns_only: boolean; true bypasses proxying at the edge for all account records.
zone_defaults: mapping of defaults for NEW zones; it does not update existing zones.
Boolean defaults: flatten_all_cnames, foundation_dns, multi_provider, secondary_overrides.
nameservers: {type: cloudflare.standard}; other choices are cloudflare.standard.random,
custom.account and custom.tenant (custom nameservers require the relevant entitlement).
zone_mode: standard, cdn_only or dns_only. ns_ttl: integer seconds.
internal_dns: {reference_zone_id: '<zone-id>'} for an existing fallback zone.
soa: optional mapping; expire/min_ttl/refresh/retry/ttl are integer seconds;
mname is the primary nameserver; rname is an administrator address in DNS form,
e.g. hostmaster.example.com for hostmaster@example.com.
Configure only options relevant to your DNS setup; advanced DNS needs entitlement.

## account/settings/turnstile.yaml

Turnstile widgets, keyed by a stable widget name.
Required: domains and mode. domains: list of hostnames, without scheme/path.
mode: managed (interactive only when needed), non-interactive (no user interaction),
or invisible (no visible widget). bot_fight_mode: optional boolean, default false.
Embed the returned sitekey in your app and verify responses server-side with its secret.
Keep the secret outside repository configuration; it is returned by Cloudflare.
