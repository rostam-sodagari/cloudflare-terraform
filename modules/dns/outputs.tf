output "records" {
  description = "Managed records: key => { id, name, type, content }."
  value = {
    for k, r in merge(cloudflare_dns_record.this, cloudflare_dns_record.structured) : k => {
      id      = r.id
      name    = r.name
      type    = r.type
      content = r.content
    }
  }
}

output "spf_lookup_counts" {
  value = local.spf_lookups
}

output "dnssec_ds" {
  description = "DS record to add at the registrar once DNSSEC is active."
  value       = one(cloudflare_zone_dnssec.this[*].ds)
}
