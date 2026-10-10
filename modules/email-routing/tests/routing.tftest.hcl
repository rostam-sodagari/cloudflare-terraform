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

run "worker_delivery" {
  command = plan
  variables {
    rules = [{
      ref      = "worker_route"
      priority = 7
      matchers = [{ type = "all" }]
      actions  = [{ type = "worker", value = ["mail-handler"] }]
    }]
    catch_all = { action = "worker", destination = "fallback-handler", enabled = false, name = "fallback" }
  }
  assert {
    condition     = cloudflare_email_routing_catch_all.this[0].actions[0].value == tolist(["fallback-handler"]) && !cloudflare_email_routing_catch_all.this[0].enabled
    error_message = "Worker catch-all destination and disabled status must reach Terraform."
  }
  assert {
    condition     = cloudflare_email_routing_rule.this["worker_route"].priority == 7
    error_message = "Routing priority must reach Terraform."
  }
}
