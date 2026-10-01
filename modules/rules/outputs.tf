output "ruleset_ids" {
  value = { for k, r in cloudflare_ruleset.this : k => r.id }
}
