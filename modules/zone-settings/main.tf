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
  # TLS 1.3 zrt controls 0-RTT too. Updating both endpoints can fail on the
  # second request because Cloudflare rejects an identical 0-RTT mode.
  for_each = toset([for key in keys(var.settings) : key if key != "0rtt" || !contains(keys(var.settings), "tls_1_3")])

  zone_id    = var.zone_id
  setting_id = each.key
  value      = var.settings[each.key]

  lifecycle {
    precondition {
      condition     = each.key != "tls_1_3" || try((var.settings["0rtt"] == "on") == (var.settings.tls_1_3 == "zrt"), true)
      error_message = "0rtt on requires tls_1_3 zrt; 0rtt off requires tls_1_3 on or off. Review both settings together."
    }
  }
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
