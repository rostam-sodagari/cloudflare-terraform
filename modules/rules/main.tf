locals {
  # Service name (YAML file) => ruleset phase and the default action.
  services = {
    cache            = { phase = "http_request_cache_settings", action = "set_cache_settings", name = "Cache rules" }
    redirects        = { phase = "http_request_dynamic_redirect", action = "redirect", name = "Single redirects" }
    url_rewrites     = { phase = "http_request_transform", action = "rewrite", name = "URL rewrite rules" }
    request_headers  = { phase = "http_request_late_transform", action = "rewrite", name = "Request header transform rules" }
    response_headers = { phase = "http_response_headers_transform", action = "rewrite", name = "Response header transform rules" }
    origin           = { phase = "http_request_origin", action = "route", name = "Origin rules" }
    config           = { phase = "http_config_settings", action = "set_config", name = "Configuration rules" }
    compression      = { phase = "http_response_compression", action = "compress_response", name = "Compression rules" }
  }

  # Rules per product. Check against the Cloudflare plan matrix; Enterprise
  # contracts can raise these.
  limits = { free = 10, pro = 25, business = 50, enterprise = 300 }

  active = {
    for svc, rules in var.phases : svc => [
      for r in rules : merge(
        { enabled = true, action = local.services[svc].action },
        r,
      )
    ]
    if contains(keys(local.services), svc) && length(rules) > 0
  }
}

resource "cloudflare_ruleset" "this" {
  for_each = toset(keys(local.active))

  zone_id = var.zone_id
  name    = local.services[each.key].name
  kind    = "zone"
  phase   = local.services[each.key].phase
  rules   = local.active[each.key]

  lifecycle {
    # name is cosmetic only, but the provider forces a delete+recreate if
    # it ever differs from state -- including on the first plan after
    # adopting a zone whose live ruleset name for this phase isn't exactly
    # this literal. Never fight over it.
    ignore_changes = [name]
    precondition {
      condition     = length(local.active[each.key]) <= local.limits[var.plan]
      error_message = "${var.plan} plan allows ${local.limits[var.plan]} ${each.key} rules; ${length(local.active[each.key])} defined."
    }
    precondition {
      condition     = alltrue([for r in local.active[each.key] : can(r.ref) && can(r.expression)])
      error_message = "Every ${each.key} rule needs ref and expression."
    }
  }
}

check "unknown_services" {
  assert {
    condition     = alltrue([for k in keys(var.phases) : contains(keys(local.services), k)])
    error_message = "Unknown rule service in ${jsonencode(keys(var.phases))}. Valid: ${jsonencode(keys(local.services))}."
  }
}
