# Policy: best-practice checks

*Who this is for: anyone deciding whether a best-practice check should be on, off, a warning, or an error.*

`policy.yaml`, at the repository root, controls a set of Cloudflare
best-practice checks: things that are a judgment call rather than flat-out
wrong (an SSL mode that sends traffic to your origin unencrypted, an SPF
record that lets anyone send mail as you, a CAA record that blocks
Cloudflare's own certificate authorities, and a handful of others). These
are different from the checks `python3 cf.py validate` always runs for
structural correctness (duplicate records, wrong types, unknown fields,
plan limits): those can never be turned off, because they describe things
that are simply broken. Policy checks can be turned off, or turned into a
hard error, per check.

## How it's checked

Nothing extra to run: policy checks are part of the same validation pass
as everything else, so they're already covered by `python3 cf.py validate`,
`cf.py plan`, `cf.py apply`, `cf.py lint`, and the CI "Validate YAML" step.
Setting a check's severity to `error` in `policy.yaml` makes it block a
plan or apply exactly like a structural mistake would — including on
`cf.py apply`, even if the plan was generated before the `policy.yaml`
change.

## The file

```yaml
ssl_not_weak: { enabled: true, severity: error }
dmarc_has_rua: { enabled: false }
```

- `enabled: false` fully skips the check — no warning, no error.
- `severity: warning` (the default) or `error`.
- A check left out of `policy.yaml` entirely keeps its own default
  (enabled, warning) — it's never silently off just because the file
  doesn't mention it.

## Checks today

| Check | What it looks for |
|---|---|
| `caa_trusted_ca` | CAA records allow a CA that can issue for Cloudflare Universal SSL (`letsencrypt.org` or `pki.goog`) |
| `spf_not_plus_all` | SPF's `all` mechanism isn't `+all`, which lets anyone send mail as this domain |
| `dmarc_has_rua` | DMARC has an `rua` address, so reports are actually received |
| `dmarc_policy_strict` | DMARC `policy` is `quarantine`/`reject`, not just `none` (monitoring only) |
| `dkim_looks_valid` | DKIM content looks like a real key (has a `p=` tag) |
| `dkim_key_size_strong` | DKIM RSA keys are 2048 bits or larger (Ed25519 keys are skipped) |
| `hsts_preload_risk` | Flags HSTS `preload`, which is very hard to undo once applied |
| `ip_access_rule_has_notes` | IP access rules explain why they exist |
| `ssl_not_weak` | SSL mode isn't `off` or `flexible` (both send traffic to the origin unencrypted) |
| `tls_version_current` | `min_tls_version` isn't a deprecated version (1.0 or 1.1) |
| `owasp_score_threshold_standard` | OWASP `score_threshold` is one of Cloudflare's standard levels (60/40/25) |
| `record_has_doc_block` | Every DNS record has a `##` Owner/Purpose/Impact(/Proxy) block directly above it ([41 Record documentation](41-record-documentation.md)) |

The full list with descriptions also lives in `scripts/validation/policy.py`
(`CATALOG`), which is the source of truth if this page ever drifts from it.
