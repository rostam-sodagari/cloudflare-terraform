variable "zone_id" {
  type = string
}

variable "origin_cert" {
  description = <<-EOT
    Contents of security/origin-cert.yaml.
      csr                 a Certificate Signing Request YOU generate and keep
                          the matching private key for -- never put a private
                          key in this repo, only the CSR (public, not secret).
      hostnames           list of hostnames the cert covers
      request_type        e.g. origin-rsa, origin-ecc
      requested_validity  days, optional (Cloudflare default applies if omitted)
  EOT
  type        = any
  default     = {}
}

variable "certificate_pack" {
  description = <<-EOT
    Contents of security/certificate-pack.yaml. Ordering a certificate pack
    can be a billable action depending on certificate_authority/type --
    check Cloudflare's pricing before enabling this.
      certificate_authority   e.g. lets_encrypt, google, ssl_com
      type                    advanced | custom (advanced = Advanced Cert Manager)
      validation_method       txt | http | email
      validity_days           14 | 30 | 90 | 365 (varies by CA)
      hosts                   optional, defaults to the zone's hostnames
      cloudflare_branding     optional
  EOT
  type        = any
  default     = {}
}
