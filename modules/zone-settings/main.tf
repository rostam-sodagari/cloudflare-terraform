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
