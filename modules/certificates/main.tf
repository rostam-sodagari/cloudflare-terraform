resource "cloudflare_origin_ca_certificate" "this" {
  count = try(var.origin_cert.csr, null) != null ? 1 : 0

  csr                = var.origin_cert.csr
  hostnames          = var.origin_cert.hostnames
  request_type       = var.origin_cert.request_type
  requested_validity = try(var.origin_cert.requested_validity, null)

  lifecycle {
    # A CSR is tied to a private key generated outside this repo; rotating
    # it (new CSR) should issue the new cert before the old one is
    # revoked, not leave the origin without a valid cert mid-apply.
    create_before_destroy = true
  }
}

resource "cloudflare_certificate_pack" "this" {
  count = try(var.certificate_pack.type, null) != null ? 1 : 0

  zone_id               = var.zone_id
  certificate_authority = var.certificate_pack.certificate_authority
  type                  = var.certificate_pack.type
  validation_method     = var.certificate_pack.validation_method
  validity_days         = var.certificate_pack.validity_days
  hosts                 = try(var.certificate_pack.hosts, null)
  cloudflare_branding   = try(var.certificate_pack.cloudflare_branding, null)
}
