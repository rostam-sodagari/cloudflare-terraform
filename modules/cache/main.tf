variable "zone_id" {
  type = string
}

variable "plan" {
  type = string
}

variable "settings" {
  description = <<-EOT
    Contents of cache/settings.yaml (on | off for each):
      smart_tiered_cache, argo_tiered_caching, cache_reserve,
      argo_smart_routing, regional_tiered_cache
  EOT
  type = object({
    smart_tiered_cache    = optional(string)
    argo_tiered_caching   = optional(string)
    cache_reserve         = optional(string)
    argo_smart_routing    = optional(string)
    regional_tiered_cache = optional(string)
  })
  default = {}

  validation {
    condition = alltrue([
      for v in [
        var.settings.smart_tiered_cache, var.settings.argo_tiered_caching, var.settings.cache_reserve,
        var.settings.argo_smart_routing, var.settings.regional_tiered_cache
      ] : v == null || contains(["on", "off"], coalesce(v, "x"))
    ])
    error_message = "Tiered cache values must be on or off."
  }
}

variable "cache_variants" {
  description = <<-EOT
    Contents of cache/variants.yaml: per-format lists of MIME variants to
    serve, e.g. { webp: ["image/webp"], avif: ["image/avif"] }.
  EOT
  type        = any
  default     = {}
}

# Smart Tiered Cache topology selection: available on every plan.
resource "cloudflare_tiered_cache" "this" {
  count = var.settings.smart_tiered_cache == null ? 0 : 1

  zone_id = var.zone_id
  value   = var.settings.smart_tiered_cache
}

# Tiered Cache enablement: available on every plan, separately from paid Argo routing.
resource "cloudflare_argo_tiered_caching" "this" {
  count = var.settings.argo_tiered_caching == null ? 0 : 1

  zone_id = var.zone_id
  value   = var.settings.argo_tiered_caching
}

resource "cloudflare_zone_cache_reserve" "this" {
  count = var.settings.cache_reserve == null ? 0 : 1

  zone_id = var.zone_id
  value   = var.settings.cache_reserve
}

resource "cloudflare_argo_smart_routing" "this" {
  count = var.settings.argo_smart_routing == null ? 0 : 1

  zone_id = var.zone_id
  value   = var.settings.argo_smart_routing
}

resource "cloudflare_regional_tiered_cache" "this" {
  count = var.settings.regional_tiered_cache == null ? 0 : 1

  zone_id = var.zone_id
  value   = var.settings.regional_tiered_cache
}

resource "cloudflare_zone_cache_variants" "this" {
  count = length(keys(var.cache_variants)) > 0 ? 1 : 0

  zone_id = var.zone_id
  value   = var.cache_variants
}
