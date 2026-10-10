resource "cloudflare_notification_policy_webhooks" "this" {
  for_each = var.webhooks

  account_id = var.account_id
  name       = each.key
  url        = each.value.url_ref == null ? each.value.url : lookup(var.webhook_secrets, each.value.url_ref, null)
  secret     = each.value.secret_ref == null ? null : lookup(var.webhook_secrets, each.value.secret_ref, null)
  lifecycle {
    precondition {
      condition     = (each.value.url != null) != (each.value.url_ref != null)
      error_message = "Supply exactly one webhook url or url_ref."
    }
    precondition {
      condition     = each.value.url_ref == null || contains(keys(var.webhook_secrets), coalesce(each.value.url_ref, "__unset__"))
      error_message = "Webhook url_ref has no externally supplied URL."
    }
    precondition {
      condition     = each.value.secret_ref == null || contains(keys(var.webhook_secrets), coalesce(each.value.secret_ref, "__unset__"))
      error_message = "A webhook secret_ref has no externally supplied signing secret."
    }
  }
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
