resource "cloudflare_logpush_job" "this" {
  for_each = var.jobs

  account_id          = var.account_id
  name                = each.key
  dataset             = each.value.dataset
  destination_conf    = each.value.destination_conf_ref == null ? each.value.destination_conf : lookup(var.destinations, each.value.destination_conf_ref, null)
  enabled             = each.value.enabled
  filter              = each.value.filter
  frequency           = each.value.frequency
  logpull_options     = each.value.logpull_options
  ownership_challenge = each.value.ownership_challenge
  lifecycle {
    precondition {
      condition     = (each.value.destination_conf != null) != (each.value.destination_conf_ref != null)
      error_message = "Supply exactly one destination_conf or destination_conf_ref."
    }
    precondition {
      condition     = each.value.destination_conf_ref == null || contains(keys(var.destinations), coalesce(each.value.destination_conf_ref, "__unset__"))
      error_message = "Logpush destination_conf_ref has no externally supplied destination."
    }
  }
}
