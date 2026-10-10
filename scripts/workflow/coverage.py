"""API coverage for all configuration files; gaps are explicit operational results."""
from dataclasses import dataclass
from exporting.config import RULE_FILES


@dataclass(frozen=True)
class Service:
    name: str
    files: tuple
    endpoint: str
    collection: bool = False
    export: bool = True


ZONE_SERVICES = [
    Service("dns", tuple(f"dns/{kind}.yaml" for kind in
            ("a", "aaaa", "cname", "mx", "txt", "ns", "spf", "dmarc", "dkim", "caa", "srv")), "dns_records", True),
    Service("dnssec", ("dns/dnssec.yaml",), "dnssec"),
    Service("zone-settings", ("settings/zone.yaml", "security/hsts.yaml"), "settings", True),
    Service("bots", ("security/bot-management.yaml",), "bot_management"),
    Service("access", ("security/ip-access-rules.yaml",), "firewall/access_rules/rules", True),
    Service("email-settings", ("dns/email-routing.yaml",), "email/routing"),
    Service("email-rules", ("dns/email-routing.yaml",), "email/routing/rules", True),
    Service("email-catch-all", ("dns/email-routing.yaml",), "email/routing/rules/catch_all"),
    Service("total-tls", ("security/total-tls.yaml",), "acm/total_tls"),
    Service("ct-alerting", ("security/ct-alerting.yaml",), "ssl/certificate_transparency/settings"),
    Service("origin-pulls", ("security/authenticated-origin-pulls.yaml",), "origin_tls_client_auth/settings"),
    Service("certificate-packs", ("security/certificate-pack.yaml",), "ssl/certificate_packs", True, False),
    Service("cache-variants", ("cache/variants.yaml",), "cache/variants"),
    Service("smart-tiered", ("cache/settings.yaml",), "cache/tiered_cache_smart_topology_enable"),
    Service("argo-tiered", ("cache/settings.yaml",), "argo/tiered_caching"),
    Service("cache-reserve", ("cache/settings.yaml",), "cache/cache_reserve"),
    Service("argo-routing", ("cache/settings.yaml",), "argo/smart_routing"),
    Service("regional-tiered", ("cache/settings.yaml",), "cache/regional_tiered_cache"),
    Service("origin-certificates", ("security/origin-cert.yaml",), "certificates?zone_id={id}", True, False),
    Service("other-rulesets", (), "rulesets", True, False),
    Service("page-rules", (), "pagerules", True, False),
    Service("worker-routes", (), "workers/routes", True, False),
]
ZONE_SERVICES += [Service(name, (path,), f"rulesets/phases/{phase}/entrypoint")
                  for name, (phase, path) in RULE_FILES.items()]
ZONE_SERVICES += [Service(name, (path,), f"rulesets/phases/{phase}/entrypoint") for name, path, phase in
                  (("custom-waf", "waf/custom-rules.yaml", "http_request_firewall_custom"),
                   ("rate-limits", "waf/rate-limits.yaml", "http_ratelimit"),
                   ("managed-waf", "waf/managed-rules.yaml", "http_request_firewall_managed"))]

ACCOUNT_SERVICES = [
    Service("lists", tuple(f"lists/{kind}.yaml" for kind in ("ip", "asn", "hostname", "redirect")), "rules/lists", True),
    Service("logpush", ("settings/logpush.yaml",), "logpush/jobs", True),
    Service("notifications", ("settings/notifications.yaml",), "alerting/v3/policies", True),
    Service("webhooks", ("settings/notification-webhooks.yaml",), "alerting/v3/destinations/webhooks", True),
    Service("registrar", ("settings/registrar.yaml",), "registrar/domains", True, False),
    Service("sso", ("settings/sso.yaml",), "sso_connectors", True),
    Service("groups", ("settings/user-groups.yaml",), "iam/user_groups", True),
    Service("account-dns", ("settings/dns-settings.yaml",), "dns_settings"),
    Service("turnstile", ("settings/turnstile.yaml",), "challenges/widgets", True),
    Service("bulk-redirects", ("lists/redirect.yaml",), "rulesets/phases/http_request_redirect/entrypoint", export=False),
    Service("other-rulesets", (), "rulesets", True, False),
]
ACCOUNT_SERVICES += [Service(name, (path,), f"rulesets/phases/{phase}/entrypoint") for name, path, phase in
                     (("custom-waf", "waf/custom-rules.yaml", "http_request_firewall_custom"),
                      ("rate-limits", "waf/rate-limits.yaml", "http_ratelimit"),
                      ("managed-waf", "waf/managed-rules.yaml", "http_request_firewall_managed"))]


def services(account=False):
    return ACCOUNT_SERVICES if account else ZONE_SERVICES


def endpoint(service, identity, account=False):
    if service.name == "origin-certificates":
        return f"/certificates?zone_id={identity}"
    return f"/{'accounts' if account else 'zones'}/{identity}/{service.endpoint}"
