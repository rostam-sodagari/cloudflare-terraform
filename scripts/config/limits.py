"""Cloudflare plan limits (checked against Cloudflare's docs -- see
docs/references.md). Keep in step with modules/waf/main.tf and
modules/rules/main.tf, which enforce the same limits in Terraform."""

PLANS = ["free", "pro", "business", "enterprise"]

LIMITS = {
    "custom_rules": {"free": 5, "pro": 20, "business": 100, "enterprise": 1000},
    "rate_limits": {"free": 1, "pro": 2, "business": 5, "enterprise": 100},
    "rules": {"free": 10, "pro": 25, "business": 50, "enterprise": 300},
}

RL_PERIODS = [10, 60, 120, 300, 600, 3600]
RL_TIMEOUTS = [0, 10, 60, 120, 300, 600, 3600, 86400]
RL_MAX_PERIOD = {"free": 10, "pro": 60, "business": 600, "enterprise": 3600}
RL_MAX_TIMEOUT = {"free": 10, "pro": 3600, "business": 86400, "enterprise": 86400}
RL_CHARS = {
    "free": {"ip.src", "cf.colo.id"},
    "pro": {"ip.src", "cf.colo.id"},
    "business": {"ip.src", "cf.colo.id", "cf.unique_visitor_id"},
}
