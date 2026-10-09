"""Best-practice thresholds: numbers and small enums behind the checks in
policy.yaml (and the record-doc-block convention, which isn't policy-gated
but shares this module since it's the same kind of "what's required"
constant). Changing one of these changes what a check flags -- keep in
step with docs/40-policy.md and docs/41-record-documentation.md."""

# dkim_key_size_strong (scripts/validation/dns.py): RSA keys under this are
# flagged. Ed25519 keys (k=ed25519) have no comparable bit count and are
# always skipped, regardless of this value.
DKIM_MIN_RSA_BITS = 2048

# tls_version_current (scripts/validation/settings.py): min_tls_version
# values considered deprecated.
DEPRECATED_TLS_VERSIONS = ("1.0", "1.1")

# ssl_not_weak (scripts/validation/settings.py): ssl values that send
# traffic to the origin unencrypted.
WEAK_SSL_MODES = ("off", "flexible")

# owasp_score_threshold_standard (scripts/validation/waf.py): Cloudflare's
# documented OWASP score_threshold levels (60 low, 40 medium, 25 high).
OWASP_SCORE_THRESHOLDS = (25, 40, 60)

# Allowed OWASP paranoia_level values (not policy-gated -- a structural
# check, since Cloudflare's API itself only accepts 1-4).
OWASP_PARANOIA_LEVELS = (1, 2, 3, 4)

# record_has_doc_block (scripts/validation/common.py): required '##' lines
# above every DNS record. "proxy" is added only for A/AAAA/CNAME, which is
# decided at the call site (check_record_doc_blocks' needs_proxy argument),
# not here.
DOC_BLOCK_REQUIRED = ("owner", "purpose", "impact")
