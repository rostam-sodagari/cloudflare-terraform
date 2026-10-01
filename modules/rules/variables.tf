variable "zone_id" {
  type = string
}

variable "plan" {
  type = string
}

variable "phases" {
  description = <<-EOT
    Rules per service, keyed by service name (see local.services):
      { cache = [ {ref, description, expression, action, action_parameters}, ... ], ... }
    Rule fields use the Cloudflare Rulesets API names, so examples from the
    Cloudflare docs can be pasted in (as YAML) with no translation.
  EOT
  type        = any
  default     = {}
}
