# Account token scoping (cloudflare_account_token) is deliberately NOT
# modeled here: the provider's `value` attribute for that resource is the
# live token secret, computed back from Cloudflare and stored in Terraform
# state. Creating tokens through Terraform would put a second copy of the
# secret in state, working against centralizing tokens in Delinea instead
# of scattering them across stores. Tokens stay dashboard/API-created and
# Delinea-stored; this repo doesn't manage their lifecycle.

resource "cloudflare_sso_connector" "this" {
  count = try(var.sso.email_domain, null) != null ? 1 : 0

  account_id         = var.account_id
  email_domain       = var.sso.email_domain
  enabled            = try(var.sso.enabled, null)
  begin_verification = try(var.sso.begin_verification, null)
}

resource "cloudflare_user_group" "this" {
  for_each = var.user_groups

  account_id = var.account_id
  name       = each.key
  policies   = each.value.policies
}

resource "cloudflare_user_group_members" "this" {
  for_each = { for name, g in var.user_groups : name => g if length(g.members) > 0 }

  account_id    = var.account_id
  user_group_id = cloudflare_user_group.this[each.key].id
  members       = [for m in each.value.members : { id = m }]
}

resource "cloudflare_account_dns_settings" "this" {
  count = length(keys(var.dns_settings)) > 0 ? 1 : 0

  account_id       = var.account_id
  enforce_dns_only = try(var.dns_settings.enforce_dns_only, null)
  zone_defaults    = try(var.dns_settings.zone_defaults, null)
}
