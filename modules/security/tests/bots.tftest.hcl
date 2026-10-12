mock_provider "cloudflare" {}
variables {
  zone_id = "0123456789abcdef0123456789abcdef"
  plan    = "free"
}
run "fight_mode_enables_required_js" {
  command = plan
  variables { bot_management = { fight_mode = true } }
  assert {
    condition     = cloudflare_bot_management.this[0].enable_js == true
    error_message = "Bot Fight Mode must plan its required JavaScript detection."
  }
}
run "fight_mode_rejects_disabled_js" {
  command = plan
  variables { bot_management = { fight_mode = true, enable_js = false } }
  expect_failures = [cloudflare_bot_management.this]
}
