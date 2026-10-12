mock_provider "cloudflare" {}

variables {
  zone_id = "0123456789abcdef0123456789abcdef"
}

run "one_writer_for_consistent_aliases" {
  command = plan
  variables {
    settings = { "0rtt" = "on", tls_1_3 = "zrt" }
  }
  assert {
    condition     = keys(cloudflare_zone_setting.this) == ["tls_1_3"] && cloudflare_zone_setting.this["tls_1_3"].value == "zrt"
    error_message = "TLS 1.3 must be the single writer when both aliases are configured."
  }
}

run "conflicting_aliases_fail_before_writes" {
  command = plan
  variables {
    settings = { "0rtt" = "on", tls_1_3 = "on" }
  }
  expect_failures = [cloudflare_zone_setting.this["tls_1_3"]]
}

run "legacy_zero_rtt_configuration" {
  command = plan
  variables {
    settings = { "0rtt" = "on" }
  }
  assert {
    condition     = keys(cloudflare_zone_setting.this) == ["0rtt"]
    error_message = "A standalone legacy 0-RTT configuration retains its existing resource identity."
  }
}
