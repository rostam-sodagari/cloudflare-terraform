variable "zone_id" {
  type = string
}

variable "plan" {
  type = string
}

variable "settings" {
  description = "Contents of cache/settings.yaml: smart_tiered_cache, argo_tiered_caching (on | off)."
  type = object({
    smart_tiered_cache  = optional(string)
    argo_tiered_caching = optional(string)
  })
  default = {}

  validation {
    condition = alltrue([
      for v in [var.settings.smart_tiered_cache, var.settings.argo_tiered_caching] : v == null || contains(["on", "off"], coalesce(v, "x"))
    ])
    error_message = "Tiered cache values must be on or off."
  }
}

# Smart Tiered Cache: available on every plan.
resource "cloudflare_tiered_cache" "this" {
  count = var.settings.smart_tiered_cache == null ? 0 : 1

  zone_id = var.zone_id
  value   = var.settings.smart_tiered_cache
}

# Generic Tiered Caching toggle (Argo). Leave unset unless you use Argo.
resource "cloudflare_argo_tiered_caching" "this" {
  count = var.settings.argo_tiered_caching == null ? 0 : 1

  zone_id = var.zone_id
  value   = var.settings.argo_tiered_caching
}
