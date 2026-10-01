variable "account_id" {
  type = string
}

variable "lists" {
  description = <<-EOT
    Account lists keyed by list name (lowercase, digits, underscores; used in
    rule expressions as $name). Each: { kind, description, items }.
      ip:       items = [{ ip = "203.0.113.0/24", comment = "..." }]
      asn:      items = [{ asn = 13335 }]
      hostname: items = [{ hostname = { url_hostname = "example.com" } }]
      redirect: items = [{ redirect = { source_url, target_url, status_code, ... } }]
  EOT
  type        = any
  default     = {}
}

locals {
  names = keys(var.lists)

  redirect_lists = [
    for n in local.names : n
    if var.lists[n].kind == "redirect" && try(var.lists[n].enabled, true)
  ]
}

resource "cloudflare_list" "this" {
  for_each = toset(local.names)

  account_id  = var.account_id
  name        = each.key
  kind        = var.lists[each.key].kind
  description = try(var.lists[each.key].description, null)
  items       = try(var.lists[each.key].items, [])

  lifecycle {
    precondition {
      condition     = can(regex("^[a-z0-9_]{1,50}$", each.key))
      error_message = "List name ${each.key} must be lowercase letters, digits or underscores (max 50)."
    }
    precondition {
      condition     = contains(["ip", "asn", "hostname", "redirect"], var.lists[each.key].kind)
      error_message = "List kind must be ip, asn, hostname or redirect."
    }
  }
}

# Bulk Redirects: one account-level rule per redirect list.
resource "cloudflare_ruleset" "bulk_redirects" {
  count = length(local.redirect_lists) > 0 ? 1 : 0

  account_id = var.account_id
  name       = "Bulk redirects"
  kind       = "root"
  phase      = "http_request_redirect"

  rules = [
    for n in local.redirect_lists : {
      ref         = "bulk_${n}"
      description = "Bulk redirects from list ${n}"
      expression  = format("http.request.full_uri in $%s", n)
      action      = "redirect"
      enabled     = true
      action_parameters = {
        from_list = {
          name = n
          key  = "http.request.full_uri"
        }
      }
    }
  ]

  depends_on = [cloudflare_list.this]
}

output "list_ids" {
  value = { for k, l in cloudflare_list.this : k => l.id }
}
