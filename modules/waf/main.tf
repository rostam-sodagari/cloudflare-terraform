locals {
  # Published Cloudflare managed ruleset IDs (identical on every account).
  ruleset_ids = {
    cloudflare_managed = "efb7b8c949ac4650a09736fc376e9aee"
    owasp              = "4814384a9e5d4991b9815dcfc25d2f1f"
  }
  owasp_score_rule_id = "6179ae15870a4bb7b2d480d4843b323c" # 949110 Inbound Anomaly Score Exceeded

  # Per-plan limits. Check against the Cloudflare plan matrix before relying
  # on them; Enterprise contracts can raise these.
  limits = {
    free       = { custom_rules = 5, rate_limits = 1, managed = false }
    pro        = { custom_rules = 20, rate_limits = 2, managed = true }
    business   = { custom_rules = 100, rate_limits = 5, managed = true }
    enterprise = { custom_rules = 1000, rate_limits = 100, managed = true }
  }
  limit = local.limits[var.plan]

  # ---- Custom rules ------------------------------------------------------
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

  # ---- Rate limiting -----------------------------------------------------
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

  # ---- Managed rulesets --------------------------------------------------
  cf_managed = var.managed.cloudflare_managed
  owasp      = var.managed.owasp

  structured_managed_rules = concat(
    # Exceptions must sit above the execute rules they skip.
    [
      for e in var.managed.exceptions : {
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
    local.cf_managed.enabled ? [{
      ref         = "execute_cloudflare_managed"
      description = "Cloudflare Managed Ruleset"
      expression  = "true"
      action      = "execute"
      enabled     = true
      action_parameters = {
        id        = local.ruleset_ids.cloudflare_managed
        overrides = local.cf_managed.action == null ? null : { action = local.cf_managed.action }
      }
      logging = null
    }] : [],
    local.owasp.enabled ? [{
      ref         = "execute_owasp"
      description = "Cloudflare OWASP Core Ruleset"
      expression  = "true"
      action      = "execute"
      enabled     = true
      action_parameters = {
        id = local.ruleset_ids.owasp
        overrides = {
          # Turn off paranoia levels above the chosen one.
          categories = [
            for pl in range(local.owasp.paranoia_level + 1, 5) : {
              category = "paranoia-level-${pl}"
              enabled  = false
            }
          ]
          rules = [{
            id              = local.owasp_score_rule_id
            action          = local.owasp.action # null = Cloudflare default
            score_threshold = local.owasp.score_threshold
          }]
        }
      }
      logging = null
    }] : [],
  )

  raw_managed = [for r in var.managed_raw_rules : merge({ enabled = true }, r)]
  # raw_rules, when given, replace the structured form entirely.
  managed_rules = [for r in coalescelist(local.raw_managed, local.structured_managed_rules, [null]) : r if r != null]

  # The Log action is Enterprise only (Cloudflare rules actions reference).
  uses_log = anytrue(concat(
    [for r in var.custom_rules : r.action == "log"],
    [for r in var.rate_limits : r.action == "log"],
    [local.cf_managed.action == "log", local.owasp.action == "log"],
  ))
}

check "log_action_enterprise_only" {
  assert {
    condition     = var.plan == "enterprise" || !local.uses_log
    error_message = "The log action is only available on Enterprise. Use managed_challenge, or a higher OWASP score_threshold, while tuning."
  }
}

resource "cloudflare_ruleset" "custom" {
  count = length(local.custom_rules) > 0 ? 1 : 0

  zone_id = var.zone_id
  name    = "Custom WAF rules"
  kind    = "zone"
  phase   = "http_request_firewall_custom"
  rules   = local.custom_rules

  lifecycle {
    # name is cosmetic only (Cloudflare never uses it functionally) but the
    # provider forces a delete+recreate if it ever differs from state --
    # including on the very first plan after adopting an existing zone,
    # if the live ruleset's name isn't exactly this literal. Never fight
    # over it.
    ignore_changes = [name]
    precondition {
      condition     = length(local.custom_rules) <= local.limit.custom_rules
      error_message = "${var.plan} plan allows ${local.limit.custom_rules} custom rules; ${length(local.custom_rules)} defined."
    }
    precondition {
      condition     = var.plan == "enterprise" || !local.uses_log
      error_message = "The log action is only available on Enterprise. Use managed_challenge while tuning."
    }
  }
}

resource "cloudflare_ruleset" "rate_limit" {
  count = length(local.rate_limit_rules) > 0 ? 1 : 0

  zone_id = var.zone_id
  name    = "Rate limiting rules"
  kind    = "zone"
  phase   = "http_ratelimit"
  rules   = local.rate_limit_rules

  lifecycle {
    # See the comment on cloudflare_ruleset.custom above: name forces
    # replace on any difference, so it's never worth tracking.
    ignore_changes = [name]
    precondition {
      condition     = length(local.rate_limit_rules) <= local.limit.rate_limits
      error_message = "${var.plan} plan allows ${local.limit.rate_limits} rate limiting rules; ${length(local.rate_limit_rules)} defined."
    }
  }
}

resource "cloudflare_ruleset" "managed" {
  count = var.manage_managed_rules && local.limit.managed && length(local.managed_rules) > 0 ? 1 : 0

  zone_id = var.zone_id
  name    = "Managed WAF rulesets"
  kind    = "zone"
  phase   = "http_request_firewall_managed"
  rules   = local.managed_rules

  lifecycle {
    # See the comment on cloudflare_ruleset.custom above: name forces
    # replace on any difference, so it's never worth tracking. This is
    # almost certainly why a managed-ruleset "deleted and recreated" plan
    # happens on an adopted zone -- Cloudflare's own dashboard-created name
    # for this ruleset rarely matches this literal exactly.
    ignore_changes = [name]
    precondition {
      condition     = var.plan == "enterprise" || !local.uses_log
      error_message = "The log action is only available on Enterprise. Use managed_challenge, or raise the OWASP score_threshold, while tuning."
    }
  }
}

check "managed_on_free_plan" {
  assert {
    condition     = local.limit.managed || length(var.managed.exceptions) == 0
    error_message = "Managed ruleset settings are ignored on the free plan (the Free Managed Ruleset is applied by Cloudflare)."
  }
}
