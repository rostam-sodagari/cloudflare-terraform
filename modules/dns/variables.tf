variable "zone_id" {
  description = "Cloudflare zone ID."
  type        = string
}

variable "zone_name" {
  description = "Apex domain, e.g. example.com."
  type        = string
}

variable "records" {
  description = <<-EOT
    Generic records (A, AAAA, CNAME, MX, TXT, NS). Map key must be stable,
    because it becomes part of the Terraform address, e.g. "a/www".
    Use "@" for the apex. Names can be relative ("www") or fully qualified.
  EOT
  type = map(object({
    type     = string
    name     = string
    content  = string
    ttl      = optional(number, 1) # 1 = automatic
    proxied  = optional(bool)
    priority = optional(number) # MX only
    comment  = optional(string)
  }))
  default = {}

  validation {
    condition = alltrue([
      for r in values(var.records) : contains(["A", "AAAA", "CNAME", "MX", "TXT", "NS"], r.type)
    ])
    error_message = "Only A, AAAA, CNAME, MX, TXT and NS are supported in var.records."
  }

  validation {
    condition = alltrue([
      for r in values(var.records) : r.type != "MX" || r.priority != null
    ])
    error_message = "Every MX record needs a priority."
  }

  validation {
    condition = alltrue([
      for r in values(var.records) : r.type != "NS" || !contains(["@", var.zone_name], r.name)
    ])
    error_message = "Apex NS records are controlled by Cloudflare. NS records here are for subdomain delegation only."
  }
}

variable "caa" {
  description = "CAA records keyed by a stable id."
  type = map(object({
    name    = optional(string, "@")
    flags   = optional(number, 0)
    tag     = string # issue | issuewild | iodef
    value   = string
    ttl     = optional(number, 1)
    comment = optional(string)
  }))
  default = {}

  validation {
    condition     = alltrue([for c in values(var.caa) : contains(["issue", "issuewild", "iodef"], c.tag)])
    error_message = "CAA tag must be issue, issuewild or iodef."
  }
}

variable "srv" {
  description = "SRV records keyed by a stable id. name is the full service label, e.g. _sip._tls or _sip._tls.voice."
  type = map(object({
    name     = string
    priority = number
    weight   = number
    port     = number
    target   = string
    ttl      = optional(number, 1)
    comment  = optional(string)
  }))
  default = {}

  validation {
    condition     = alltrue([for r in values(var.srv) : startswith(r.name, "_")])
    error_message = "SRV names start with the service label, e.g. _sip._tls."
  }
}

variable "dnssec" {
  description = "DNSSEC status: active, disabled, or null to leave it unmanaged."
  type        = string
  default     = null

  validation {
    condition     = var.dnssec == null || contains(["active", "disabled"], coalesce(var.dnssec, "x"))
    error_message = "dnssec must be active or disabled."
  }
}

variable "spf" {
  description = "SPF policies keyed by hostname (\"@\" for the apex). Set raw to bypass the builder."
  type = map(object({
    includes = optional(list(string), [])
    ip4      = optional(list(string), [])
    ip6      = optional(list(string), [])
    a        = optional(bool, false)
    mx       = optional(bool, false)
    extra    = optional(list(string), []) # e.g. ["exists:%{i}.spf.example.com"]
    all      = optional(string, "-all")
    raw      = optional(string)
    ttl      = optional(number, 1)
    comment  = optional(string)
  }))
  default = {}

  validation {
    condition     = alltrue([for s in values(var.spf) : contains(["-all", "~all", "?all", "+all"], s.all)])
    error_message = "spf.all must be one of -all, ~all, ?all, +all."
  }
}

variable "dmarc" {
  description = "DMARC policies keyed by hostname (\"@\" for the apex). Set raw to bypass the builder."
  type = map(object({
    policy           = optional(string, "none")
    subdomain_policy = optional(string)
    pct              = optional(number)
    rua              = optional(list(string), [])
    ruf              = optional(list(string), [])
    adkim            = optional(string)
    aspf             = optional(string)
    fo               = optional(string)
    raw              = optional(string)
    ttl              = optional(number, 1)
    comment          = optional(string)
  }))
  default = {}

  validation {
    condition     = alltrue([for d in values(var.dmarc) : contains(["none", "quarantine", "reject"], d.policy)])
    error_message = "dmarc.policy must be none, quarantine or reject."
  }
}

variable "dkim" {
  description = "DKIM TXT records keyed by selector. CNAME-style DKIM (e.g. Microsoft 365) belongs in cname.yaml."
  type = map(object({
    content = string
    ttl     = optional(number, 1)
    comment = optional(string)
  }))
  default = {}
}
