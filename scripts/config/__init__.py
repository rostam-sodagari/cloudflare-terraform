"""Tunable numbers and lookup tables used by scripts/validation/ -- plan
limits, regex patterns, known zone settings, bot fields, and a handful of
best-practice thresholds. Split by concern (see the individual modules)
rather than one flat file, but every name is also re-exported here so
`from config import X` works regardless of which module X actually lives in.

These are the values someone changes when Cloudflare changes a plan limit
or adds a setting -- not business logic. The checks that use them stay in
scripts/validation/; this package holds only the numbers and tables they
check against.
"""
from .bot import BOT_FIELDS
from .limits import LIMITS, PLANS, RL_CHARS, RL_MAX_PERIOD, RL_MAX_TIMEOUT, RL_PERIODS, RL_TIMEOUTS
from .patterns import (
    DOC_BLOCK_RE, EMAIL_RE, HEX32, HOST_RE, KEY_RE, LIST_REF_RE, NAME_RE,
    REF_RE, REGEX_RE,
)
from .thresholds import (
    DEPRECATED_TLS_VERSIONS, DKIM_MIN_RSA_BITS, DOC_BLOCK_REQUIRED,
    MAX_DESTRUCTIVE_CHANGES, OWASP_PARANOIA_LEVELS, OWASP_SCORE_THRESHOLDS,
    WEAK_SSL_MODES,
)
from .zone_settings import KNOWN_SETTINGS, ON_OFF_SETTINGS, RULE_FILES, SETTING_ENUMS

__all__ = [
    "BOT_FIELDS",
    "LIMITS", "PLANS", "RL_CHARS", "RL_MAX_PERIOD", "RL_MAX_TIMEOUT", "RL_PERIODS", "RL_TIMEOUTS",
    "DOC_BLOCK_RE", "EMAIL_RE", "HEX32", "HOST_RE", "KEY_RE", "LIST_REF_RE", "NAME_RE", "REF_RE", "REGEX_RE",
    "DEPRECATED_TLS_VERSIONS", "DKIM_MIN_RSA_BITS", "DOC_BLOCK_REQUIRED",
    "MAX_DESTRUCTIVE_CHANGES", "OWASP_PARANOIA_LEVELS", "OWASP_SCORE_THRESHOLDS", "WEAK_SSL_MODES",
    "KNOWN_SETTINGS", "ON_OFF_SETTINGS", "RULE_FILES", "SETTING_ENUMS",
]
