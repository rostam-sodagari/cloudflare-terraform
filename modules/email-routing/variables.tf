variable "zone_id" {
  type = string
}

variable "settings" {
  description = "Contents of dns/email-routing.yaml's top-level enabled/support_subaddress fields."
  type        = any
  default     = {}
}

variable "rules" {
  description = <<-EOT
    Contents of dns/email-routing.yaml's rules list. Each rule:
      ref        required, stable identity (same convention as every
                other rule file in this repo -- renaming it deletes and
                recreates the rule)
      name       optional, human-readable
      enabled    optional, default true
      matchers   list of { field: "to", type: "literal", value: <address> }
      actions    list of { type: forward | worker | drop, value: [<destination>, ...] }
    Destination addresses must already be verified (Cloudflare sends a
    confirmation e-mail the recipient has to click; this repo doesn't
    automate that step).
  EOT
  type = list(object({
    ref      = string
    name     = optional(string)
    enabled  = optional(bool, true)
    priority = optional(number)
    matchers = list(object({
      field = optional(string)
      type  = string
      value = optional(string)
    }))
    actions = list(object({
      type  = string
      value = optional(list(string))
    }))
  }))
  default = []
}

variable "catch_all" {
  description = <<-EOT
    Contents of dns/email-routing.yaml's catch_all block.
      action        forward | worker | drop
      destination   required when action is forward or worker
  EOT
  type        = any
  default     = {}
}
