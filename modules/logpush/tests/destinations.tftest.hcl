mock_provider "cloudflare" {}
variables {
  account_id = "0123456789abcdef0123456789abcdef"
}
run "public_destination" {
  command = plan
  variables {
    jobs = { audit = { dataset = "audit_logs", destination_conf = "s3://bucket/audit?region=eu-west-2" } }
  }
  assert {
    condition     = cloudflare_logpush_job.this["audit"].destination_conf == "s3://bucket/audit?region=eu-west-2"
    error_message = "Plain destinations must reach the provider unchanged."
  }
}
run "vault_destination" {
  command = plan
  variables {
    jobs         = { audit = { dataset = "audit_logs", destination_conf_ref = "destination" } }
    destinations = { destination = "https://logs.example.com?token=fixture" }
  }
  assert {
    condition     = cloudflare_logpush_job.this["audit"].destination_conf == "https://logs.example.com?token=fixture"
    error_message = "Vault destinations must reach the provider."
  }
}
run "missing_vault_reference" {
  command = plan
  variables {
    jobs = { audit = { dataset = "audit_logs", destination_conf_ref = "missing" } }
  }
  expect_failures = [cloudflare_logpush_job.this["audit"]]
}
run "ambiguous_destination" {
  command = plan
  variables {
    jobs         = { audit = { dataset = "audit_logs", destination_conf = "s3://bucket/audit", destination_conf_ref = "destination" } }
    destinations = { destination = "https://logs.example.com?token=fixture" }
  }
  expect_failures = [cloudflare_logpush_job.this["audit"]]
}
