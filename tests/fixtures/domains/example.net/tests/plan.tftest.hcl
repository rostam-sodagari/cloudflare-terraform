# Offline check: parses the YAML, runs every validation and plan-limit
# precondition, with no API token needed. Run: terraform test
mock_provider "cloudflare" {}

run "plan_offline" {
  command = plan
}
