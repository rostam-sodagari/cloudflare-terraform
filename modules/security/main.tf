locals {
  bm      = var.bot_management
  bm_used = length(keys(local.bm)) > 0

  sbfm_fields = ["sbfm_definitely_automated", "sbfm_likely_automated", "sbfm_verified_bots", "sbfm_static_resource_protection", "optimize_wordpress"]
}

resource "cloudflare_bot_management" "this" {
  count = local.bm_used ? 1 : 0

  zone_id = var.zone_id

  # Free
  fight_mode = try(local.bm.fight_mode, null)
  enable_js  = try(local.bm.enable_js, null)

  # Pro / Business (Super Bot Fight Mode)
  sbfm_definitely_automated       = try(local.bm.sbfm_definitely_automated, null)
  sbfm_likely_automated           = try(local.bm.sbfm_likely_automated, null)
  sbfm_verified_bots              = try(local.bm.sbfm_verified_bots, null)
  sbfm_static_resource_protection = try(local.bm.sbfm_static_resource_protection, null)
  optimize_wordpress              = try(local.bm.optimize_wordpress, null)

  # All plans
  ai_bots_protection    = try(local.bm.ai_bots_protection, null)
  crawler_protection    = try(local.bm.crawler_protection, null)
  is_robots_txt_managed = try(local.bm.is_robots_txt_managed, null)

  # Enterprise Bot Management
  auto_update_model      = try(local.bm.auto_update_model, null)
  suppress_session_score = try(local.bm.suppress_session_score, null)
  bm_cookie_enabled      = try(local.bm.bm_cookie_enabled, null)

  lifecycle {
    precondition {
      condition     = var.plan != "free" || length([for f in local.sbfm_fields : f if can(local.bm[f])]) == 0
      error_message = "Super Bot Fight Mode settings (sbfm_*, optimize_wordpress) need Pro or above. Use fight_mode on free."
    }
    precondition {
      condition     = var.plan == "free" || !can(local.bm.fight_mode)
      error_message = "fight_mode is the free-plan Bot Fight Mode. On paid plans use the sbfm_* settings."
    }
  }
}

resource "cloudflare_authenticated_origin_pulls" "this" {
  count = try(var.authenticated_origin_pulls.enabled, null) != null ? 1 : 0

  zone_id = var.zone_id
  config = [{
    enabled  = var.authenticated_origin_pulls.enabled
    hostname = try(var.authenticated_origin_pulls.hostname, null)
    cert_id  = try(var.authenticated_origin_pulls.cert_id, null)
  }]
}

resource "cloudflare_zone_hold" "this" {
  count = try(var.zone_hold.enabled, false) ? 1 : 0

  zone_id = var.zone_id
  # Always a concrete bool, never null: include_subdomains is
  # optional+computed with a provider-side default of false, and sending
  # an explicit null (instead of omitting it) can make the plan re-apply
  # the default on every run even when nothing in the YAML changed,
  # showing a spurious "null -> false" diff.
  include_subdomains = try(var.zone_hold.include_subdomains, false)
}

resource "cloudflare_access_rule" "this" {
  for_each = var.ip_access_rules

  zone_id = var.zone_id
  mode    = each.value.mode
  notes   = each.value.notes
  configuration = {
    target = each.value.target
    value  = each.value.value
  }
}
