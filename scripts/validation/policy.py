"""Best-practice policy gate: policy.yaml (repo root) turns named checks
on/off and sets each to warning or error severity. A check left out of
policy.yaml keeps its default severity below and stays enabled -- never
silently off. Checked on every validate.py run, which means every
`cf.py plan`/`cf.py apply`/`cf.py lint` and the CI "Validate YAML" step
all enforce it automatically.

    checkflag: { enabled: true, severity: error }
    other:     { enabled: false }

CATALOG is also the source of truth for what a check *is*; `Ctx.flag()`
(validation/common.py) is where each one actually fires.
"""
import yaml

from .common import ROOT

# check_id -> (description, default severity)
CATALOG = {
    "caa_trusted_ca": (
        "CAA records allow a CA that can issue for Cloudflare Universal SSL (letsencrypt.org or pki.goog)",
        "warning"),
    "spf_not_plus_all": (
        "SPF 'all' mechanism is not +all, which lets anyone send mail as this domain",
        "warning"),
    "dmarc_has_rua": (
        "DMARC policy has an rua address so reports are actually received",
        "warning"),
    "dkim_looks_valid": (
        "DKIM content looks like a real key (has a p= tag)",
        "warning"),
    "hsts_preload_risk": (
        "HSTS preload is flagged as very hard to undo once applied",
        "warning"),
    "ip_access_rule_has_notes": (
        "IP access rules explain why they exist, so they can be removed safely later",
        "warning"),
    "ssl_not_weak": (
        "SSL mode is not off or flexible (both send traffic to the origin unencrypted)",
        "warning"),
    "tls_version_current": (
        "min_tls_version is not a deprecated version (1.0 or 1.1)",
        "warning"),
    "owasp_score_threshold_standard": (
        "OWASP score_threshold is one of Cloudflare's standard levels (60/40/25)",
        "warning"),
    "record_has_doc_block": (
        "every DNS record has a '##' Owner/Purpose/Impact(/Proxy) documentation block directly above it",
        "warning"),
}


class PolicyGate:
    def __init__(self, config):
        self.config = config  # {check_id: {"enabled": bool, "severity": "warning"|"error"}}

    @classmethod
    def load(cls, path):
        if not path.exists():
            return cls({})
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        return cls(data) if isinstance(data, dict) else cls({})

    def severity(self, check_id):
        """Returns 'warning', 'error', or None (disabled). Unknown check
        ids (not in CATALOG, not in policy.yaml) are never disabled."""
        entry = self.config.get(check_id) or {}
        if entry.get("enabled", True) is False:
            return None
        default = CATALOG.get(check_id, (None, "warning"))[1]
        severity = entry.get("severity", default)
        if severity not in ("warning", "error"):
            severity = default
        return severity


GATE = PolicyGate.load(ROOT / "policy.yaml")
