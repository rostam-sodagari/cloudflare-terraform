variable "zone_id" {
  type = string
}

variable "plan" {
  type = string
}

variable "bot_management" {
  description = <<-EOT
    Contents of security/bot-management.yaml. Field names match the
    cloudflare_bot_management resource. Which ones apply depends on the plan:
      free:          fight_mode, enable_js
      pro/business:  sbfm_definitely_automated, sbfm_likely_automated (business),
                     sbfm_verified_bots, sbfm_static_resource_protection,
                     optimize_wordpress, enable_js
      all plans:     ai_bots_protection, crawler_protection, is_robots_txt_managed
      enterprise BM: auto_update_model, suppress_session_score, bm_cookie_enabled
  EOT
  type        = any
  default     = {}
}

variable "authenticated_origin_pulls" {
  description = <<-EOT
    Contents of security/authenticated-origin-pulls.yaml.
      enabled    true | false
      hostname   optional -- apply only to this hostname instead of the
                whole zone
      cert_id    optional -- id of a client certificate already uploaded
                via the dashboard. Leave out to use Cloudflare's own
                shared certificate (no custom upload needed). Uploading a
                custom certificate needs its private key, which this repo
                deliberately does not accept -- see docs/services.md.
      zone_enabled optional boolean for the zone default when hostname is set
  EOT
  type        = any
  default     = {}
}

variable "ip_access_rules" {
  description = "Zone IP Access Rules keyed by a stable id."
  type = map(object({
    mode   = string # block | challenge | managed_challenge | js_challenge | whitelist
    target = string # ip | ip6 | ip_range | asn | country
    value  = string
    notes  = optional(string)
  }))
  default = {}

  validation {
    condition = alltrue([
      for r in values(var.ip_access_rules) : contains(["block", "challenge", "managed_challenge", "js_challenge", "whitelist"], r.mode)
    ])
    error_message = "mode must be block, challenge, managed_challenge, js_challenge or whitelist."
  }

  validation {
    condition = alltrue([
      for r in values(var.ip_access_rules) : contains(["ip", "ip6", "ip_range", "asn", "country"], r.target)
    ])
    error_message = "target must be ip, ip6, ip_range, asn or country."
  }
}
