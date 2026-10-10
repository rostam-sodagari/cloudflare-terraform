mock_provider "cloudflare" {}

variables {
  zone_id = "0123456789abcdef0123456789abcdef"
}

run "unmanaged" {
  command = plan
  assert {
    condition     = length(cloudflare_email_routing_settings.this) == 0
    error_message = "An unset setting must not enable routing."
  }
}

run "enabled" {
  command = apply
  variables { settings = { enabled = true } }
  assert {
    condition     = length(cloudflare_email_routing_settings.this) == 1
    error_message = "Explicit enable must create the settings resource."
  }
}

run "disabled_after_enable" {
  command = apply
  variables { settings = { enabled = false } }
  assert {
    condition     = length(cloudflare_email_routing_settings.this) == 0
    error_message = "Explicit disable must destroy the previously managed settings resource."
  }
}

run "enable_again" {
  command = plan
  variables { settings = { enabled = true } }
  assert {
    condition     = length(cloudflare_email_routing_settings.this) == 1
    error_message = "Routing must be able to enable again after disable."
  }
}

run "unsupported_subaddress" {
  command = plan
  variables { settings = { enabled = true, support_subaddress = true } }
  expect_failures = [cloudflare_email_routing_settings.this]
}
