"""Cloudflare 5.27 resource operations that do not delete dashboard settings."""

# Verified against the Delete handlers in the pinned provider, not Terraform's
# action labels. Removing these resources forgets state without an API write.
STATE_ONLY_DELETE = frozenset("cloudflare_" + name for name in (
    "account_dns_settings", "argo_smart_routing", "argo_tiered_caching",
    "authenticated_origin_pulls_settings", "bot_management", "ct_alerting",
    "email_routing_catch_all", "regional_tiered_cache", "registrar_domain",
    "total_tls", "zone_cache_reserve", "zone_setting",
))


def stops_managing(resource):
    return resource["type"] in STATE_ONLY_DELETE and resource["change"]["actions"] == ["delete"]


def secondary_effects(resource):
    if resource["type"] == "cloudflare_email_routing_settings":
        actions = resource["change"]["actions"]
        if "create" in actions:
            return ["Cloudflare also adds and locks the required MX and SPF DNS records."]
        if "delete" in actions:
            return ["Cloudflare also removes the MX DNS records required for Email Routing."]
    return []
