resource "cloudflare_registrar_domain" "this" {
  for_each = var.domains

  account_id  = var.account_id
  domain_name = each.key
  auto_renew  = each.value.auto_renew
  locked      = each.value.locked
  privacy     = each.value.privacy
}
