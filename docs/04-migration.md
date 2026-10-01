# 4. Migrating existing zones (import runbook)

Goal: bring a live zone under Terraform **without changing anything** in
Cloudflare. Success is a first plan that says
`0 to add, 0 to change, 0 to destroy` (imports only).

## Before you start

1. Read-only API token exported (see [01](01-getting-started.md)).
2. `backend.hcl` in place and R2 keys exported.
3. Pick a low-risk zone first. Agree a short change freeze on that zone in
   the dashboard while you migrate it.

## Step 1: account (once)

```bash
make export-account ACCOUNT_ID=<account id>
make plan D=account
```

Writes `account/lists/*.yaml` and `account/imports.tf`. Existing Bulk
Redirect rules are replaced by one generated rule per redirect list; the
plan shows this as an update, which is expected. Review, then:

```bash
make apply D=account
rm account/imports.tf
```

## Step 2: export the zone

```bash
make export D=example.org ZONE_ID=<zone id>
```

The exporter writes every service it can read into the domain folder and
generates `imports.tf`. It prints a summary and warnings, for example:

| Warning | Meaning | Action |
|---------|---------|--------|
| `N DNS records of type [...] are not managed yet` | e.g. PTR, LOC, TLSA | Left alone; raw JSON in `.export/` |
| `Kept N SPF/DMARC record(s) as raw` | Could not rebuild byte-for-byte | Fine; convert later |
| `Managed WAF ruleset exported to .export only` | Overrides are too varied to convert | Step 4 |
| `has action_parameters [...] not modelled` | e.g. custom block response | Plan will show a diff; decide |
| `TXT ... stored with quotes` | Kept verbatim | None |

## Step 3: first plan

```bash
make plan D=example.org
```

Read the plan line by line.

1. **Imports only, no changes:** perfect, go to step 5.
2. **In-place updates:** usually cosmetic (field ordering, a default the
   API returns). Adjust the YAML until the update disappears, or accept it
   if you are sure it is harmless.
3. **Create or destroy:** stop. A key or address is wrong, or an import is
   missing. Never apply a migration plan that creates or destroys.

## Step 4: managed WAF ruleset (Pro+)

1. Open `.export/<domain>/managed-ruleset.json`.
2. Express it in `waf/managed-rules.yaml` (enabled rulesets, OWASP action,
   paranoia level, threshold, exceptions).
3. Uncomment the managed ruleset block in `imports.tf`.
4. Plan again until the managed ruleset shows no changes, or only ones you
   intend.

## Step 5: apply and clean up

```bash
make apply D=example.org      # imports only
rm domains/example.org/imports.tf
make plan D=example.org       # must now say "No changes"
```

Commit everything in one pull request titled "Import example.org".

## Step 6: hand over

1. Tell the team that WAF, rules and DNS for this zone now change only via
   Git. Dashboard edits to these phases are overwritten on the next apply.
2. Optionally restrict dashboard roles for the zone.
3. Lift the change freeze.

## Rollback

Nothing in Cloudflare changes during an import-only apply. To undo,
delete `domains/<d>.tfstate` from R2 and the folder from Git.
