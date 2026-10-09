variable "account_id" {
  type = string
}

variable "custom_rules" {
  description = "Contents of account/waf/custom-rules.yaml -- same shape as a zone's waf/custom-rules.yaml, applied account-wide."
  type = list(object({
    ref         = string
    description = optional(string, "")
    expression  = string
    action      = string
    enabled     = optional(bool, true)
    skip = optional(object({
      ruleset  = optional(string)
      phases   = optional(list(string))
      products = optional(list(string))
      log      = optional(bool, true)
    }))
    response = optional(object({
      status_code  = optional(number, 403)
      content_type = optional(string, "text/plain")
      content      = string
    }))
  }))
  default = []
}

variable "rate_limits" {
  description = "Contents of account/waf/rate-limits.yaml -- same shape as a zone's waf/rate-limits.yaml, applied account-wide."
  type = list(object({
    ref                 = string
    description         = optional(string, "")
    expression          = string
    action              = optional(string, "block")
    enabled             = optional(bool, true)
    characteristics     = optional(list(string), ["ip.src", "cf.colo.id"])
    period              = optional(number, 10)
    requests_per_period = number
    mitigation_timeout  = optional(number, 10)
    counting_expression = optional(string)
    requests_to_origin  = optional(bool)
    response = optional(object({
      status_code  = optional(number, 403)
      content_type = optional(string, "text/plain")
      content      = string
    }))
  }))
  default = []
}

variable "managed" {
  description = "Contents of account/waf/managed-rules.yaml -- same simple form as a zone's (cloudflare_managed, owasp, exceptions)."
  type        = any
  default     = {}
}

variable "managed_raw_rules" {
  type    = list(any)
  default = []
}

variable "manage_managed_rules" {
  description = "false when account/waf/managed-rules.yaml is empty/missing, so the resource isn't created with no rules."
  type        = bool
  default     = false
}
