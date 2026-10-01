# Identical in every domain. Do not edit: all domain data lives in the YAML.
module "domain" {
  source     = "../../modules/domain-stack"
  domain_dir = path.module
}

output "summary" {
  value = {
    zone               = module.domain.zone
    dns_records        = module.domain.dns_records
    dnssec_ds          = module.domain.dnssec_ds
    ruleset_ids        = module.domain.ruleset_ids
    ip_access_rule_ids = module.domain.ip_access_rule_ids
  }
}
