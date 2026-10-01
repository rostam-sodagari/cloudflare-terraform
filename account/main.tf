# Account-level resources shared by every domain: lists and Bulk Redirects.
# Own state file (account.tfstate). Apply this BEFORE a domain whose rules
# reference a list ($list_name), and remove references before deleting a list.

locals {
  account = yamldecode(file("${path.module}/account.yaml"))

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

output "list_ids" {
  value = module.lists.list_ids
}
