resource "cloudflare_notification_policy_webhooks" "this" {
  for_each = var.webhooks

  account_id = var.account_id
  name       = each.key
  url        = each.value.url
  secret     = each.value.secret
}

resource "cloudflare_notification_policy" "this" {
  for_each = var.policies

  account_id     = var.account_id
  name           = each.key
  alert_type     = each.value.alert_type
  description    = each.value.description
  enabled        = each.value.enabled
  alert_interval = each.value.alert_interval
  filters        = each.value.filters

  mechanisms = {
    email = length(each.value.mechanisms.email) > 0 ? [
      for e in each.value.mechanisms.email : { id = e }
    ] : null
    webhooks = length(each.value.mechanisms.webhooks) > 0 ? [
      for w in each.value.mechanisms.webhooks : { id = cloudflare_notification_policy_webhooks.this[w].id }
    ] : null
    pagerduty = length(each.value.mechanisms.pagerduty) > 0 ? [
      for p in each.value.mechanisms.pagerduty : { id = p }
    ] : null
  }
}
