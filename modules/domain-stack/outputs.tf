output "zone" {
  value = {
    name = local.domain.name
    id   = local.domain.zone_id
    plan = local.plan
  }
}

output "dns_records" {
  value = module.dns.records
}

output "dnssec_ds" {
  description = "Give this DS record to the registrar after enabling DNSSEC."
  value       = module.dns.dnssec_ds
}

output "ruleset_ids" {
  value = merge(module.waf.ruleset_ids, module.rules.ruleset_ids)
}

output "ip_access_rule_ids" {
  value = module.security.ip_access_rule_ids
}
