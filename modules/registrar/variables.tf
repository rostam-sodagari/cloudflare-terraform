variable "account_id" {
  type = string
}

variable "domains" {
  description = <<-EOT
    Contents of account/settings/registrar.yaml, keyed by the exact registered
    domain name. Only domains actually registered through Cloudflare
    Registrar -- this errors on any other domain.
      auto_renew   optional
      locked       optional, transfer lock
      privacy      optional, WHOIS privacy
  EOT
  type = map(object({
    auto_renew = optional(bool)
    locked     = optional(bool)
    privacy    = optional(bool)
  }))
  default = {}
}
