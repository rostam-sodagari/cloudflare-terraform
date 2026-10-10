# Configuration

Domain configuration lives in `domains/<domain>/`; account-wide configuration lives in `account/`.
Use the example in each YAML file's header and validate after editing.

## YAML essentials

```yaml
api:
  name: api
  content: 203.0.113.20
  proxied: true
```

Use two spaces for indentation, never tabs. Keep a space after each colon.
Quote text such as `"on"`, `"off"`, `"@"`, `"1.2"`, IDs, and an expression containing only `"true"`.
Keep numbers and booleans unquoted: `ttl: 300`, `proxied: true`.

Lines starting with `#` are instructions or inactive examples. To use one, remove the first `# ` from **its configuration lines only**, keeping the spaces after it:

```yaml
# www:
#   name: www
#   content: 203.0.113.10
#   proxied: true
```

becomes:

```yaml
www:
  name: www
  content: 203.0.113.10
  proxied: true
```

Replace `203.0.113.10` with your real origin address. Keep explanatory lines commented and uncomment only one alternative example at a time.
`required` means you must provide that field; `optional` means you may leave the line out. A documented default applies when the field is omitted.
Replace `<...>`, `change-me`, and sample IDs with real values. A truncated key or CSR containing `...` must be replaced entirely.

Lists can be compact (`emails: [ops@example.com, security@example.com]`) or one item per line:

```yaml
emails:
  - ops@example.com
  - security@example.com
```

Use `|` for multi-line text such as a CSR, keeping every text line indented below it.
Do not repeat a mapping key: add a second record under a new identity, or edit the existing entry.

Records use named mapping entries. Rules use ordered lists:

```yaml
- ref: protect_admin
  description: Challenge requests to the admin page
  expression: '(http.request.uri.path eq "/admin")'
  action: managed_challenge
```

Record keys and rule `ref` values are identities. Renaming one can delete and recreate the resource.
Rules run in file order, so moving a rule can change its behavior.
The file header shows the essentials and an example. See [YAML field reference](yaml-fields.md) for optional fields and defaults, [Services](services.md) to find a file, [Zone setting values](zone-settings.md) for settings, or [Rule examples](rule-examples.md) for nested rules.

## Empty files and deletions

An empty or commented service file leaves an initially unmanaged service alone.
For a service already in state, removing entries can delete managed resources.
Removing a zone setting stops managing its value; it does not reset that value.
Always use the plan to confirm the result. DNSSEC and Email Routing have additional lifecycle rules in [Services](services.md).

## Policy checks

`policy.yaml` controls best-practice checks. Structural checks, such as invalid types, duplicate keys, and plan limits, always run.

```yaml
ssl_not_weak: { enabled: true, severity: error }
dmarc_has_rua: { enabled: false }
```

`error` blocks validation, planning, and applying. `warning` reports the issue; `enabled: false` skips that policy check.
An omitted check keeps its default.

| Checks | Concern |
|---|---|
| `spf_not_plus_all`, `dmarc_has_rua`, `dmarc_policy_strict` | Mail authorization and reporting |
| `dkim_looks_valid`, `dkim_key_size_strong` | DKIM key format and strength |
| `caa_trusted_ca` | Certificate authority restrictions |
| `ssl_not_weak`, `tls_version_current` | SSL mode and minimum TLS version |
| `hsts_preload_risk` | Persistent browser HTTPS enforcement |
| `ip_access_rule_has_notes` | Reasons for access rules |
| `owasp_score_threshold_standard` | OWASP threshold configuration |

The complete definitions and defaults are in `scripts/validation/policy.py`.

```sh
python cf.py validate example.org
python cf.py validate-all
```
