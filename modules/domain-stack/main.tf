# Reads one domain folder and wires every service module.
#
#   domain.yaml
#   dns/       a aaaa cname mx txt ns spf dmarc dkim caa srv dnssec
#   waf/       custom-rules rate-limits managed-rules
#   security/  hsts bot-management ip-access-rules
#   cache/     cache-rules settings
#   rules/     redirects url-rewrites request-headers response-headers
#              origin config compression
#   settings/  zone
#
# Any file can be missing, empty or comments only: that service is then
# left alone (nothing is created, nothing is deleted).

locals {
  dir = var.domain_dir

  files = [
    "dns/a.yaml", "dns/aaaa.yaml", "dns/cname.yaml", "dns/mx.yaml", "dns/txt.yaml", "dns/ns.yaml",
    "dns/spf.yaml", "dns/dmarc.yaml", "dns/dkim.yaml", "dns/caa.yaml", "dns/srv.yaml", "dns/dnssec.yaml",
    "waf/custom-rules.yaml", "waf/rate-limits.yaml", "waf/managed-rules.yaml",
    "security/hsts.yaml", "security/bot-management.yaml", "security/ip-access-rules.yaml",
    "cache/cache-rules.yaml", "cache/settings.yaml",
    "rules/redirects.yaml", "rules/url-rewrites.yaml", "rules/request-headers.yaml",
    "rules/response-headers.yaml", "rules/origin.yaml", "rules/config.yaml", "rules/compression.yaml",
    "settings/zone.yaml",
  ]

  # Missing file => "{}" so yamldecode never sees nothing.
  raw = { for f in local.files : f => fileexists("${local.dir}/${f}") ? file("${local.dir}/${f}") : "{}" }

  # Map-shaped files (keyed by a stable id). Empty/comment-only => {}.
  as_map = { for f, s in local.raw : f => try({ for k, v in yamldecode(s) : k => v }, {}) }
  # List-shaped files (order matters). Empty/comment-only => [].
  as_list = { for f, s in local.raw : f => try([for v in yamldecode(s) : v], []) }

  domain = yamldecode(file("${local.dir}/domain.yaml"))
  plan   = lower(local.domain.plan)

  # ---- DNS -------------------------------------------------------------
  dns_types = { a = "A", aaaa = "AAAA", cname = "CNAME", mx = "MX", txt = "TXT", ns = "NS" }

  dns_records = merge([
    for file_key, type in local.dns_types : {
      for id, r in local.as_map["dns/${file_key}.yaml"] : "${file_key}/${id}" => {
        type     = type
        name     = tostring(try(r.name, id))
        content  = tostring(r.content)
        ttl      = try(r.ttl, 1)
        proxied  = try(r.proxied, null)
        priority = try(r.priority, null)
        comment  = try(r.comment, null)
        quoted   = try(r.quoted, true)
      }
    }
  ]...)

  # ---- Security headers (HSTS) is a zone setting -------------------------
  hsts = local.as_map["security/hsts.yaml"]
  hsts_setting = {
    for k, v in {
      security_header = {
        strict_transport_security = {
          enabled            = try(local.hsts.enabled, true)
          max_age            = try(local.hsts.max_age, 31536000)
          include_subdomains = try(local.hsts.include_subdomains, false)
          preload            = try(local.hsts.preload, false)
          nosniff            = try(local.hsts.nosniff, true)
        }
      }
    } : k => v
    if length(keys(local.hsts)) > 0
  }

  # ---- Rules engine phases ----------------------------------------------
  rule_files = {
    cache            = "cache/cache-rules.yaml"
    redirects        = "rules/redirects.yaml"
    url_rewrites     = "rules/url-rewrites.yaml"
    request_headers  = "rules/request-headers.yaml"
    response_headers = "rules/response-headers.yaml"
    origin           = "rules/origin.yaml"
    config           = "rules/config.yaml"
    compression      = "rules/compression.yaml"
  }
  rule_phases = { for svc, f in local.rule_files : svc => local.as_list[f] }
}

module "dns" {
  source = "../dns"

  zone_id   = local.domain.zone_id
  zone_name = local.domain.name
  records   = local.dns_records
  spf       = local.as_map["dns/spf.yaml"]
  dmarc     = local.as_map["dns/dmarc.yaml"]
  dkim      = local.as_map["dns/dkim.yaml"]
  caa       = local.as_map["dns/caa.yaml"]
  srv       = local.as_map["dns/srv.yaml"]
  dnssec    = try(local.as_map["dns/dnssec.yaml"].status, null)
}

module "waf" {
  source = "../waf"

  zone_id      = local.domain.zone_id
  plan         = local.plan
  custom_rules = local.as_list["waf/custom-rules.yaml"]
  rate_limits  = local.as_list["waf/rate-limits.yaml"]
  managed      = { for k, v in local.as_map["waf/managed-rules.yaml"] : k => v if k != "raw_rules" }

  managed_raw_rules = try(local.as_map["waf/managed-rules.yaml"].raw_rules, [])

  manage_managed_rules = length(keys(local.as_map["waf/managed-rules.yaml"])) > 0
}

module "security" {
  source = "../security"

  zone_id         = local.domain.zone_id
  plan            = local.plan
  bot_management  = local.as_map["security/bot-management.yaml"]
  ip_access_rules = local.as_map["security/ip-access-rules.yaml"]
}

module "cache" {
  source = "../cache"

  zone_id  = local.domain.zone_id
  plan     = local.plan
  settings = local.as_map["cache/settings.yaml"]
}

module "rules" {
  source = "../rules"

  zone_id = local.domain.zone_id
  plan    = local.plan
  phases  = local.rule_phases
}

module "zone_settings" {
  source = "../zone-settings"

  zone_id  = local.domain.zone_id
  settings = merge(local.as_map["settings/zone.yaml"], local.hsts_setting)
}

check "zone_id_format" {
  assert {
    condition     = can(regex("^[0-9a-f]{32}$", tostring(local.domain.zone_id)))
    error_message = "zone_id in domain.yaml must be the 32-character hex Zone ID, in quotes."
  }
}
