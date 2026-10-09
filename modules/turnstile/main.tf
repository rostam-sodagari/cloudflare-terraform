resource "cloudflare_turnstile_widget" "this" {
  for_each = var.widgets

  account_id     = var.account_id
  name           = each.key
  domains        = each.value.domains
  mode           = each.value.mode
  bot_fight_mode = each.value.bot_fight_mode
}
