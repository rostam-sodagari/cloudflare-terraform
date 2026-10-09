# Account-level WAF: same rule shapes as modules/waf (zone-level), but
# kind = "root" + account_id instead of kind = "zone" + zone_id -- these
# rulesets apply across every zone in the account. Deploying account-level
# rulesets is an Enterprise feature; Cloudflare enforces that server-side,
# not here (account-wide limits aren't publicly documented the way
# per-zone plan limits are, so this module doesn't assert specific
# numbers -- verify against your contract).
locals {
  ruleset_ids = {
    cloudflare_managed = "efb7b8c949ac4650a09736fc376e9aee"
    owasp              = "4814384a9e5d4991b9815dcfc25d2f1f"
  }
  owasp_score_rule_id = "6179ae15870a4bb7b2d480d4843b323c"

  custom_rules = [
    for r in var.custom_rules : {
      ref         = r.ref
      description = r.description
      expression  = r.expression
      action      = r.action
      enabled     = r.enabled
      action_parameters = r.action == "skip" ? {
        ruleset  = try(r.skip.ruleset, null)
        phases   = try(r.skip.phases, null)
        products = try(r.skip.products, null)
        response = null
        } : r.response != null ? {
        ruleset  = null
        phases   = null
        products = null
        response = r.response
      } : null
      logging = r.action == "skip" ? { enabled = try(r.skip.log, true) } : null
    }
  ]

  rate_limit_rules = [
    for r in var.rate_limits : {
      ref         = r.ref
      description = r.description
      expression  = r.expression
      action      = r.action
      enabled     = r.enabled
      ratelimit = {
        characteristics     = r.characteristics
        period              = r.period
        requests_per_period = r.requests_per_period
        mitigation_timeout  = r.mitigation_timeout
        counting_expression = r.counting_expression
        requests_to_origin  = r.requests_to_origin
      }
      action_parameters = r.response != null ? { response = r.response } : null
    }
  ]

  cf_managed = try(var.managed.cloudflare_managed, { enabled = false })
  owasp      = try(var.managed.owasp, { enabled = false })

  structured_managed_rules = concat(
    [
      for e in try(var.managed.exceptions, []) : {
        ref         = e.ref
        description = e.description
        expression  = e.expression
        action      = "skip"
        enabled     = true
        action_parameters = {
          rulesets = [for r in e.rulesets : lookup(local.ruleset_ids, r, r)]
        }
        logging = { enabled = true }
      }
    ],
    try(local.cf_managed.enabled, false) ? [{
      ref         = "execute_cloudflare_managed"
      description = "Cloudflare Managed Ruleset"
      expression  = "true"
      action      = "execute"
      enabled     = true
      action_parameters = {
        id        = local.ruleset_ids.cloudflare_managed
        overrides = try(local.cf_managed.action, null) == null ? null : { action = local.cf_managed.action }
      }
      logging = null
    }] : [],
    try(local.owasp.enabled, false) ? [{
      ref         = "execute_owasp"
      description = "Cloudflare OWASP Core Ruleset"
      expression  = "true"
      action      = "execute"
      enabled     = true
      action_parameters = {
        id = local.ruleset_ids.owasp
        overrides = {
          categories = [
            for pl in range(try(local.owasp.paranoia_level, 1) + 1, 5) : {
              category = "paranoia-level-${pl}"
              enabled  = false
            }
          ]
          rules = [{
            id              = local.owasp_score_rule_id
            action          = try(local.owasp.action, null)
            score_threshold = try(local.owasp.score_threshold, null)
          }]
        }
      }
      logging = null
    }] : [],
  )

  raw_managed   = [for r in var.managed_raw_rules : merge({ enabled = true }, r)]
  managed_rules = [for r in coalescelist(local.raw_managed, local.structured_managed_rules, [null]) : r if r != null]
}

resource "cloudflare_ruleset" "custom" {
  count = length(local.custom_rules) > 0 ? 1 : 0

  account_id = var.account_id
  name       = "Account custom WAF rules"
  kind       = "root"
  phase      = "http_request_firewall_custom"
  rules      = local.custom_rules
}

resource "cloudflare_ruleset" "rate_limit" {
  count = length(local.rate_limit_rules) > 0 ? 1 : 0

  account_id = var.account_id
  name       = "Account rate limiting rules"
  kind       = "root"
  phase      = "http_ratelimit"
  rules      = local.rate_limit_rules
}

resource "cloudflare_ruleset" "managed" {
  count = var.manage_managed_rules && length(local.managed_rules) > 0 ? 1 : 0

  account_id = var.account_id
  name       = "Account managed WAF rulesets"
  kind       = "root"
  phase      = "http_request_firewall_managed"
  rules      = local.managed_rules
}
