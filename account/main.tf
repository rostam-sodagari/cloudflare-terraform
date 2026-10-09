# Account-level resources shared by every domain: lists and Bulk Redirects.
# Own state file (account.tfstate). Apply this BEFORE a domain whose rules
# reference a list ($list_name), and remove references before deleting a list.

locals {
  account = yamldecode(file("${path.module}/account.yaml"))

  # Missing file => "{}"/"[]" so yamldecode never sees nothing.
  raw_map = { for f in ["waf/managed-rules.yaml", "logpush.yaml", "notifications.yaml", "notification-webhooks.yaml", "registrar.yaml"] :
    f => fileexists("${path.module}/${f}") ? file("${path.module}/${f}") : "{}"
  }
  raw_list = { for f in ["waf/custom-rules.yaml", "waf/rate-limits.yaml"] :
    f => fileexists("${path.module}/${f}") ? file("${path.module}/${f}") : "[]"
  }
  as_map  = { for f, s in local.raw_map : f => try({ for k, v in yamldecode(s) : k => v }, {}) }
  as_list = { for f, s in local.raw_list : f => try([for v in yamldecode(s) : v], []) }

  read = {
    for k in ["ip", "asn", "hostname", "redirect"] : k => try(
      { for n, v in yamldecode(fileexists("${path.module}/lists/${k}.yaml") ? file("${path.module}/lists/${k}.yaml") : "{}") : n => v },
      {}
    )
  }

  # Friendly YAML item shapes -> API item shapes.
  lists = merge(
    { for n, l in local.read.ip : n => {
      kind        = "ip"
      description = try(l.description, null)
      items = [for i in try(l.items, []) : {
        ip      = can(i.ip) ? tostring(i.ip) : tostring(i)
        comment = try(i.comment, null)
      }]
    } },
    { for n, l in local.read.asn : n => {
      kind        = "asn"
      description = try(l.description, null)
      items = [for i in try(l.items, []) : {
        asn     = can(i.asn) ? tonumber(i.asn) : tonumber(i)
        comment = try(i.comment, null)
      }]
    } },
    { for n, l in local.read.hostname : n => {
      kind        = "hostname"
      description = try(l.description, null)
      items = [for i in try(l.items, []) : {
        hostname = { url_hostname = can(i.hostname) ? tostring(i.hostname) : tostring(i) }
        comment  = try(i.comment, null)
      }]
    } },
    { for n, l in local.read.redirect : n => {
      kind        = "redirect"
      description = try(l.description, null)
      enabled     = try(l.enabled, true)
      items = [for i in try(l.items, []) : {
        comment = try(i.comment, null)
        redirect = {
          source_url            = i.source_url
          target_url            = i.target_url
          status_code           = try(i.status_code, 301)
          include_subdomains    = try(i.include_subdomains, null)
          preserve_path_suffix  = try(i.preserve_path_suffix, null)
          preserve_query_string = try(i.preserve_query_string, null)
          subpath_matching      = try(i.subpath_matching, null)
        }
      }]
    } },
  )
}

module "lists" {
  source = "../modules/lists"

  account_id = local.account.account_id
  lists      = local.lists
}

module "account_waf" {
  source = "../modules/account-waf"

  account_id   = local.account.account_id
  custom_rules = local.as_list["waf/custom-rules.yaml"]
  rate_limits  = local.as_list["waf/rate-limits.yaml"]
  managed      = { for k, v in local.as_map["waf/managed-rules.yaml"] : k => v if k != "raw_rules" }

  managed_raw_rules    = try(local.as_map["waf/managed-rules.yaml"].raw_rules, [])
  manage_managed_rules = length(keys(local.as_map["waf/managed-rules.yaml"])) > 0
}

module "logpush" {
  source = "../modules/logpush"

  account_id = local.account.account_id
  jobs       = local.as_map["logpush.yaml"]
}

module "notifications" {
  source = "../modules/notifications"

  account_id = local.account.account_id
  webhooks   = local.as_map["notification-webhooks.yaml"]
  policies   = local.as_map["notifications.yaml"]
}

module "registrar" {
  source = "../modules/registrar"

  account_id = local.account.account_id
  domains    = local.as_map["registrar.yaml"]
}

output "list_ids" {
  value = module.lists.list_ids
}
