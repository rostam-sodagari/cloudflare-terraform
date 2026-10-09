resource "cloudflare_logpush_job" "this" {
  for_each = var.jobs

  account_id          = var.account_id
  name                = each.key
  dataset             = each.value.dataset
  destination_conf    = each.value.destination_conf
  enabled             = each.value.enabled
  filter              = each.value.filter
  frequency           = each.value.frequency
  logpull_options     = each.value.logpull_options
  ownership_challenge = each.value.ownership_challenge
}
