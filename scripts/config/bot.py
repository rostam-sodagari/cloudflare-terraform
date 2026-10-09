"""Bot management fields: allowed values (or type) and which plans each one
is available on."""
from .limits import PLANS

BOT_FIELDS = {
    # field: (allowed values or type, plans)
    "fight_mode": (bool, {"free"}),
    "enable_js": (bool, set(PLANS)),
    "sbfm_definitely_automated": (["allow", "block", "managed_challenge"], {"pro", "business", "enterprise"}),
    "sbfm_likely_automated": (["allow", "block", "managed_challenge"], {"pro", "business", "enterprise"}),
    "sbfm_verified_bots": (["allow", "block"], {"pro", "business", "enterprise"}),
    "sbfm_static_resource_protection": (bool, {"pro", "business", "enterprise"}),
    "optimize_wordpress": (bool, {"pro", "business", "enterprise"}),
    "ai_bots_protection": (["block", "disabled", "only_on_ad_pages"], set(PLANS)),
    "crawler_protection": (["enabled", "disabled"], set(PLANS)),
    "is_robots_txt_managed": (bool, set(PLANS)),
    "auto_update_model": (bool, {"enterprise"}),
    "suppress_session_score": (bool, {"enterprise"}),
    "bm_cookie_enabled": (bool, {"enterprise"}),
}
