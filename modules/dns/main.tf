locals {
  # Turn a relative name ("www", "@", "_dmarc") into a fully qualified one.
  fqdn = {
    for n in distinct(concat(
      [for r in values(var.records) : r.name],
      keys(var.spf),
      [for k in keys(var.dmarc) : k == "@" ? "_dmarc" : "_dmarc.${k}"],
      [for s in keys(var.dkim) : "${s}._domainkey"],
      [for c in values(var.caa) : c.name],
      [for r in values(var.srv) : r.name],
      )) : n => (
      n == "@" || n == var.zone_name ? var.zone_name :
      endswith(n, ".${var.zone_name}") ? n : "${n}.${var.zone_name}"
    )
  }

  # ---- SPF builder -------------------------------------------------------
  spf_content = {
    for host, s in var.spf : host => coalesce(s.raw, join(" ", concat(
      ["v=spf1"],
      s.a ? ["a"] : [],
      s.mx ? ["mx"] : [],
      [for ip in s.ip4 : "ip4:${ip}"],
      [for ip in s.ip6 : "ip6:${ip}"],
      [for d in s.includes : "include:${d}"],
      s.extra,
      [s.all],
    )))
  }

  # Mechanisms that cost a DNS lookup (RFC 7208 limit is 10).
  spf_lookups = {
    for host, c in local.spf_content : host => length([
      for t in split(" ", c) : t
      if can(regex("^[-~?+]?(include:|a$|a:|a/|mx$|mx:|mx/|ptr|exists:|redirect=)", t))
    ])
  }

  spf_records = {
    for host, s in var.spf : "spf/${host}" => {
      type     = "TXT"
      name     = host
      content  = local.spf_content[host]
      ttl      = s.ttl
      proxied  = null
      priority = null
      comment  = s.comment
    }
  }

  # ---- DMARC builder -----------------------------------------------------
  dmarc_records = {
    for host, d in var.dmarc : "dmarc/${host}" => {
      type = "TXT"
      name = host == "@" ? "_dmarc" : "_dmarc.${host}"
      content = coalesce(d.raw, join("; ", compact([
        "v=DMARC1",
        "p=${d.policy}",
        d.subdomain_policy != null ? "sp=${d.subdomain_policy}" : "",
        d.pct != null ? "pct=${d.pct}" : "",
        length(d.rua) > 0 ? "rua=${join(",", [for a in d.rua : startswith(a, "mailto:") ? a : "mailto:${a}"])}" : "",
        length(d.ruf) > 0 ? "ruf=${join(",", [for a in d.ruf : startswith(a, "mailto:") ? a : "mailto:${a}"])}" : "",
        d.adkim != null ? "adkim=${d.adkim}" : "",
        d.aspf != null ? "aspf=${d.aspf}" : "",
        d.fo != null ? "fo=${d.fo}" : "",
      ])))
      ttl      = d.ttl
      proxied  = null
      priority = null
      comment  = d.comment
    }
  }

  # ---- DKIM ----------------------------------------------------------------
  dkim_records = {
    for sel, k in var.dkim : "dkim/${sel}" => {
      type     = "TXT"
      name     = "${sel}._domainkey"
      content  = k.content
      ttl      = k.ttl
      proxied  = null
      priority = null
      comment  = k.comment
    }
  }

  generic_records = {
    for k, r in var.records : k => {
      type     = r.type
      name     = r.name
      content  = r.content
      ttl      = r.ttl
      proxied  = r.proxied
      priority = r.priority
      comment  = r.comment
    }
  }

  all_records = merge(local.generic_records, local.spf_records, local.dmarc_records, local.dkim_records)
}

# CAA and SRV use the structured `data` block, so they get their own resource.
resource "cloudflare_dns_record" "structured" {
  for_each = merge(
    { for k, c in var.caa : "caa/${k}" => {
      type = "CAA", name = c.name, ttl = c.ttl, comment = c.comment
      data = { flags = c.flags, tag = c.tag, value = c.value, priority = null, weight = null, port = null, target = null }
    } },
    { for k, r in var.srv : "srv/${k}" => {
      type = "SRV", name = r.name, ttl = r.ttl, comment = r.comment
      data = { flags = null, tag = null, value = null, priority = r.priority, weight = r.weight, port = r.port, target = r.target }
    } },
  )

  zone_id = var.zone_id
  name    = local.fqdn[each.value.name]
  type    = each.value.type
  ttl     = each.value.ttl
  comment = each.value.comment
  data    = each.value.data
}

resource "cloudflare_zone_dnssec" "this" {
  count = var.dnssec == null ? 0 : 1

  zone_id = var.zone_id
  status  = var.dnssec
}

resource "cloudflare_dns_record" "this" {
  for_each = local.all_records

  zone_id  = var.zone_id
  name     = local.fqdn[each.value.name]
  type     = each.value.type
  content  = each.value.content
  ttl      = each.value.proxied == true ? 1 : each.value.ttl
  proxied  = each.value.proxied
  priority = each.value.priority
  comment  = each.value.comment
}

check "spf_lookup_limit" {
  assert {
    condition     = alltrue([for n in values(local.spf_lookups) : n <= 10])
    error_message = "An SPF record needs more than 10 DNS lookups (RFC 7208). Counts: ${jsonencode(local.spf_lookups)}"
  }
}

check "single_spf_per_name" {
  assert {
    condition = length([
      for r in values(var.records) : r if r.type == "TXT" && startswith(r.content, "v=spf1")
    ]) == 0
    error_message = "SPF found in txt.yaml. Move it to spf.yaml so there is only one SPF record per name."
  }
}
