mock_provider "cloudflare" {}
variables {
  account_id = "0123456789abcdef0123456789abcdef"
}
run "public_endpoint" {
  command = plan
  variables {
    webhooks = { alerts = { url = "https://alerts.example.com/cloudflare" } }
  }
  assert {
    condition     = cloudflare_notification_policy_webhooks.this["alerts"].url == "https://alerts.example.com/cloudflare"
    error_message = "Plain endpoints must reach the provider unchanged."
  }
}
run "vault_endpoint_and_signing_secret" {
  command = plan
  variables {
    webhooks        = { alerts = { url_ref = "endpoint", secret_ref = "signing" } }
    webhook_secrets = { endpoint = "https://hooks.example.com/private", signing = "fixture-secret" }
  }
  assert {
    condition     = cloudflare_notification_policy_webhooks.this["alerts"].url == "https://hooks.example.com/private" && cloudflare_notification_policy_webhooks.this["alerts"].secret == "fixture-secret"
    error_message = "Both vault references must reach the provider."
  }
}
run "missing_vault_reference" {
  command = plan
  variables {
    webhooks = { alerts = { url_ref = "missing" } }
  }
  expect_failures = [cloudflare_notification_policy_webhooks.this["alerts"]]
}
run "ambiguous_endpoint" {
  command = plan
  variables {
    webhooks        = { alerts = { url = "https://alerts.example.com", url_ref = "endpoint" } }
    webhook_secrets = { endpoint = "https://hooks.example.com/private" }
  }
  expect_failures = [cloudflare_notification_policy_webhooks.this["alerts"]]
}
