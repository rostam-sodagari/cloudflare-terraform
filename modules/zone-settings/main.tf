variable "zone_id" {
  type = string
}

variable "settings" {
  description = <<-EOT
    Zone settings as setting_id => value. Values keep their YAML type, so
    strings ("strict"), numbers (14400) and objects (security_header) all work:
      ssl: strict
      min_tls_version: "1.2"
      browser_cache_ttl: 14400
  EOT
  type        = any
  default     = {}
}

resource "cloudflare_zone_setting" "this" {
  for_each = toset(keys(var.settings))

  zone_id    = var.zone_id
  setting_id = each.key
  value      = var.settings[each.key]
}

variable "total_tls" {
  description = "Contents of security/total-tls.yaml: { enabled, certificate_authority }."
  type        = any
  default     = {}
}

variable "ct_alerting" {
  description = "Contents of security/ct-alerting.yaml: { enabled, emails }."
  type        = any
  default     = {}
}

resource "cloudflare_total_tls" "this" {
  count = try(var.total_tls.enabled, null) != null ? 1 : 0

  zone_id               = var.zone_id
  enabled               = var.total_tls.enabled
  certificate_authority = try(var.total_tls.certificate_authority, null)
}

resource "cloudflare_ct_alerting" "this" {
  count = try(var.ct_alerting.enabled, null) != null ? 1 : 0

  zone_id = var.zone_id
  enabled = var.ct_alerting.enabled
  emails  = try(var.ct_alerting.emails, null)
}
