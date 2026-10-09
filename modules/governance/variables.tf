variable "account_id" {
  type = string
}

variable "sso" {
  description = <<-EOT
    Contents of account/settings/sso.yaml: { email_domain, enabled, begin_verification }.
    Creating this starts Cloudflare's domain-verification flow; it doesn't
    finish SSO setup by itself (you still complete it with your IdP).
  EOT
  type        = any
  default     = {}
}

variable "user_groups" {
  description = <<-EOT
    Contents of account/settings/user-groups.yaml, keyed by a stable group name.
      policies   passed through as-is to the provider -- each entry needs
                access (allow|deny), permission_groups and resource_groups,
                which are Cloudflare permission-group UUIDs you look up
                from the dashboard or API, not something this repo
                validates the shape of.
      members    list of existing account Member IDs to put in this group
  EOT
  type = map(object({
    policies = optional(any, [])
    members  = optional(list(string), [])
  }))
  default = {}
}

variable "dns_settings" {
  description = <<-EOT
    Contents of account/settings/dns-settings.yaml: { enforce_dns_only, zone_defaults }.
    zone_defaults is passed through as-is -- see Cloudflare's
    account DNS settings documentation for its shape.
  EOT
  type        = any
  default     = {}
}
