output "ruleset_ids" {
  value = {
    custom     = one(cloudflare_ruleset.custom[*].id)
    rate_limit = one(cloudflare_ruleset.rate_limit[*].id)
    managed    = one(cloudflare_ruleset.managed[*].id)
  }
}
