# Identical in every domain. Do not edit: all domain data lives in the YAML.
module "domain" {
  source     = "../../modules/domain-stack"
  domain_dir = path.module
}

output "zone" {
  value = module.domain.zone
}

# After enabling DNSSEC, give this DS record to the domain registrar.
output "dnssec_ds" {
  value = module.domain.dnssec_ds
}
