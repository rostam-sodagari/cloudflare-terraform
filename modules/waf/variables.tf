variable "zone_id" {
  type = string
}

variable "plan" {
  description = "Zone plan: free, pro, business or enterprise. Drives feature gates and rule limits."
  type        = string

  validation {
    condition     = contains(["free", "pro", "business", "enterprise"], var.plan)
    error_message = "plan must be free, pro, business or enterprise."
  }
}

variable "custom_rules" {
  description = "WAF custom rules (phase http_request_firewall_custom), evaluated top to bottom."
  type = list(object({
    ref         = string
    description = string
    expression  = string
    action      = string
    enabled     = optional(bool, true)
    # Only for action = "block" on paid plans: custom response body.
    response = optional(object({
      status_code  = optional(number, 403)
      content_type = optional(string, "text/html")
      content      = string
    }))
    # Only for action = "skip"
    skip = optional(object({
      ruleset  = optional(string)       # "current" skips remaining custom rules
      phases   = optional(list(string)) # e.g. ["http_ratelimit", "http_request_firewall_managed"]
      products = optional(list(string)) # e.g. ["bic", "uaBlock", "securityLevel"]
      log      = optional(bool, true)
    }))
  }))
  default = []

  validation {
    condition = alltrue([
      for r in var.custom_rules :
      contains(["block", "managed_challenge", "js_challenge", "challenge", "log", "skip"], r.action)
    ])
    error_message = "custom rule action must be block, managed_challenge, js_challenge, challenge, log or skip."
  }

  validation {
    condition     = length(distinct([for r in var.custom_rules : r.ref])) == length(var.custom_rules)
    error_message = "Every custom rule needs a unique ref."
  }
}

variable "rate_limits" {
  description = "Rate limiting rules (phase http_ratelimit)."
  type = list(object({
    ref                 = string
    description         = string
    expression          = string
    action              = optional(string, "block")
    enabled             = optional(bool, true)
    characteristics     = optional(list(string), ["ip.src", "cf.colo.id"])
    period              = optional(number, 10)
    requests_per_period = number
    mitigation_timeout  = optional(number, 10)
    counting_expression = optional(string)
    requests_to_origin  = optional(bool)
    # Only for action = "block" on paid plans: custom response body.
    response = optional(object({
      status_code  = optional(number, 429)
      content_type = optional(string, "text/html")
      content      = string
    }))
  }))
  default = []

  validation {
    condition     = length(distinct([for r in var.rate_limits : r.ref])) == length(var.rate_limits)
    error_message = "Every rate limit rule needs a unique ref."
  }
}

variable "managed_raw_rules" {
  description = <<-EOT
    Optional: the managed WAF phase as raw API-shaped rules. When non-empty it
    replaces cloudflare_managed/owasp/exceptions. The exporter uses this when a
    zone's managed configuration cannot be expressed in the simple form.
  EOT
  type        = any
  default     = []
}

variable "manage_managed_rules" {
  description = "false = leave the managed WAF phase alone (managed-rules.yaml empty or missing)."
  type        = bool
  default     = false
}

variable "managed" {
  description = "Managed rulesets (Pro and above). On Free, the Free Managed Ruleset is applied by Cloudflare and is not managed here."
  type = object({
    cloudflare_managed = optional(object({
      enabled = optional(bool, true)
      action  = optional(string) # override every rule, e.g. "log" while tuning
    }), {})
    owasp = optional(object({
      enabled = optional(bool, true)
      # Action when the score threshold is reached. null = Cloudflare's
      # default (block). "log" is Enterprise only.
      action          = optional(string)
      paranoia_level  = optional(number, 1)
      score_threshold = optional(number, 40) # 60 low, 40 medium, 25 high
    }), {})
    exceptions = optional(list(object({
      ref         = string
      description = string
      expression  = string
      rulesets    = list(string) # "cloudflare_managed", "owasp" or a raw ruleset ID
    })), [])
  })
  default = {}
}
