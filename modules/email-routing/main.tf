resource "cloudflare_email_routing_settings" "this" {
  # This provider enables on creation and disables on destruction. enabled
  # is computed, so false must remove a previously managed settings resource.
  count = try(var.settings.enabled, false) == true ? 1 : 0

  zone_id            = var.zone_id
  support_subaddress = try(var.settings.support_subaddress, null)
  lifecycle {
    precondition {
      condition     = try(var.settings.support_subaddress, null) == null
      error_message = "Cloudflare provider 5.27 does not apply support_subaddress updates; configure it in Cloudflare and omit this field."
    }
  }
}

resource "cloudflare_email_routing_rule" "this" {
  for_each = { for r in var.rules : r.ref => r }

  zone_id = var.zone_id
  name    = each.value.name
  enabled = each.value.enabled
  matchers = [
    for m in each.value.matchers : {
      field = m.field
      type  = m.type
      value = m.value
    }
  ]
  actions = [
    for a in each.value.actions : {
      type  = a.type
      value = a.value
    }
  ]
}

resource "cloudflare_email_routing_catch_all" "this" {
  count = try(var.catch_all.action, null) != null ? 1 : 0

  zone_id = var.zone_id
  name    = "catch-all"
  matchers = [{
    type = "all"
  }]
  actions = [{
    type  = var.catch_all.action
    value = var.catch_all.action == "forward" ? [var.catch_all.destination] : null
  }]
}
