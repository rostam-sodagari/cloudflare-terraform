mock_provider "cloudflare" {}
variables {
  zone_id = "0123456789abcdef0123456789abcdef"
  plan    = "pro"
}
run "zone_pull" {
  command = plan
  variables { authenticated_origin_pulls = { enabled = true } }
  assert {
    condition     = length(cloudflare_authenticated_origin_pulls.this) == 0 && cloudflare_authenticated_origin_pulls_settings.zone[0].enabled
    error_message = "Zone enablement must use the zone setting endpoint."
  }
}
run "hostname_and_zone" {
  command = plan
  variables { authenticated_origin_pulls = { enabled = true, hostname = "api.example.com", cert_id = "existing", zone_enabled = false } }
  assert {
    condition     = cloudflare_authenticated_origin_pulls.this[0].config[0].hostname == "api.example.com" && !cloudflare_authenticated_origin_pulls_settings.zone[0].enabled
    error_message = "Hostname and zone settings must remain independent."
  }
}
