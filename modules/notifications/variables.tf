variable "account_id" {
  type = string
}

variable "webhooks" {
  description = <<-EOT
    Contents of account/settings/notification-webhooks.yaml, keyed by a stable name
    referenced from settings/notifications.yaml's mechanisms.webhooks list.
      url      webhook endpoint
      secret   optional, for signature verification
  EOT
  type = map(object({
    url    = string
    secret = optional(string)
  }))
  default = {}
}

variable "policies" {
  description = <<-EOT
    Contents of account/settings/notifications.yaml, keyed by a stable policy name.
      alert_type       Cloudflare alert type id, e.g. dos_attack_l7
      description      optional
      enabled          optional, default true
      alert_interval   optional (some alert types support this)
      mechanisms       at least one of: email (list of addresses),
                       webhooks (list of names from settings/notification-webhooks.yaml),
                       pagerduty (list of PagerDuty integration IDs)
      filters          optional, alert-type-specific -- passed through as-is
  EOT
  type = map(object({
    alert_type     = string
    description    = optional(string)
    enabled        = optional(bool, true)
    alert_interval = optional(string)
    mechanisms = object({
      email     = optional(list(string), [])
      webhooks  = optional(list(string), [])
      pagerduty = optional(list(string), [])
    })
    filters = optional(any)
  }))
  default = {}

  validation {
    condition = alltrue([
      for p in values(var.policies) :
      length(p.mechanisms.email) + length(p.mechanisms.webhooks) + length(p.mechanisms.pagerduty) > 0
    ])
    error_message = "Each notification policy needs at least one mechanism (email, webhooks or pagerduty)."
  }
}
