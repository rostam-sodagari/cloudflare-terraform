output "ip_access_rule_ids" {
  value = { for k, r in cloudflare_access_rule.this : k => r.id }
}
