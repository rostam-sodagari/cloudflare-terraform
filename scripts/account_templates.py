"""Concise account YAML guidance and inactive examples."""

ACCOUNT_TEMPLATES = {
    'account.yaml': """Required: quoted account_id (32 characters); plan is the highest zone plan.
Plans: free, pro, business, enterprise. Remove example: true for a real account.

EXAMPLE:
account_id: "0123456789abcdef0123456789abcdef"
plan: pro
""",
    'lists/ip.yaml': """Required per list: items (IP addresses or CIDR ranges); description is optional.
Names: lowercase letters, digits and _ (max 50); reference as $list_name in rules.
Create lists before using them; remove rule references before deleting them.

EXAMPLE:
trusted_offices:
  description: Office egress addresses
  items:
    - 203.0.113.7
    - ip: 2001:db8::/48
      comment: IPv6 office network
""",
    'lists/asn.yaml': """Enterprise only. Required per list: items (integer ASNs, without AS).
description/comment are optional; reference as $list_name in rule expressions.

EXAMPLE:
hosting_asns:
  description: Networks to challenge on login
  items:
    - 64496
    - asn: 64497
      comment: Additional hosting network
""",
    'lists/hostname.yaml': """Enterprise only. Required per list: items (hostnames without scheme or path).
description/comment are optional; reference as $list_name in rule expressions.

EXAMPLE:
partner_hosts:
  description: Partner hostnames
  items:
    - partner.example
    - hostname: other.example
      comment: Second partner
""",
    'lists/redirect.yaml': """Required: items with source_url (no scheme) and target_url (full URL).
status_code: 301 (default), 302, 307, 308. enabled: false disables the list rule.
preserve_path_suffix requires subpath_matching: true; other flags are optional booleans.

EXAMPLE:
retired_pages:
  description: Redirect old documentation
  enabled: true
  items:
    - source_url: example.com/old-docs
      target_url: https://example.com/docs
      status_code: 301
      subpath_matching: true
      preserve_path_suffix: true
      preserve_query_string: true
""",
    'settings/logpush.yaml': """Required per job: dataset and destination_conf OR destination_conf_ref; enabled defaults to true.
Use destination_conf_ref for a vault destination containing credentials.
filter is JSON text; frequency is high/low. Verify the destination first.
frequency/logpull_options are legacy fields; newer output_options is not modeled here.

EXAMPLE:
audit_archive:
  dataset: audit_logs
  destination_conf: "s3://my-cf-logs/audit?region=us-east-1"
  enabled: true

EXAMPLE (optional filter within a job):
  filter: '{"where":{"key":"Action","operator":"eq","value":"login"}}'
""",
    'settings/notification-webhooks.yaml': """Required: HTTPS url or url_ref for a credential-bearing URL in the vault.
secret_ref optionally names a signing secret in the same vault map.
Reference the destination name from notifications.yaml.

EXAMPLE:
security_team:
  url: https://hooks.example.com/cloudflare-alerts
""",
    'settings/notifications.yaml': """Required: alert_type and mechanisms with email, webhooks or pagerduty lists.
webhooks names come from notification-webhooks.yaml; enabled defaults to true.
filters/alert_interval depend on the alert type.

EXAMPLE:
ddos_alerts:
  alert_type: dos_attack_l7
  description: Notify the security team about HTTP DDoS attacks
  enabled: true
  mechanisms:
    email:
      - security@example.com

EXAMPLE (optional, add within mechanisms after defining the destination):
    webhooks:
      - security_team
""",
    'settings/registrar.yaml': """Cloudflare-registered domains only, keyed by registered domain name.
auto_renew, locked and privacy: optional true/false values.

EXAMPLE:
example.com:
  auto_renew: true
  locked: true
  privacy: true
""",
    'settings/sso.yaml': """Required: email_domain (no @ or URL). enabled/begin_verification: optional booleans.
Complete DNS verification and identity-provider setup in Cloudflare.

EXAMPLE:
email_domain: example.com
enabled: true
begin_verification: true
""",
    'settings/user-groups.yaml': """policies/members: optional lists; use real IDs from the account IAM/member APIs.
Policy access: allow/deny; permission_groups/resource_groups use {id: ...} objects.
members contains Account Member IDs, not email addresses.

EXAMPLE:
network_team:
  policies:
    - access: allow
      permission_groups:
        - id: "<dns-read-permission-group-id>"
      resource_groups:
        - id: "<zones-resource-group-id>"
  members:
    - "<account-member-id>"

""",
    'settings/dns-settings.yaml': """enforce_dns_only: optional boolean; true bypasses proxying account-wide.
zone_defaults: optional mapping for NEW zones only; nested fields are in the reference.

EXAMPLE:
enforce_dns_only: false
zone_defaults:
  flatten_all_cnames: false
  nameservers:
    type: cloudflare.standard
  ns_ttl: 86400

EXAMPLE (optional SOA block inside zone_defaults):
  soa:
    refresh: 3600
    retry: 600
    expire: 604800
    min_ttl: 300
    ttl: 3600
""",
    'settings/turnstile.yaml': """Required: domains (hostname list) and mode: managed, non-interactive or invisible.
bot_fight_mode: optional boolean. Embed the returned sitekey and verify responses server-side.

EXAMPLE:
signup_form:
  domains:
    - example.com
    - www.example.com
  mode: managed
  bot_fight_mode: false
""",
}
