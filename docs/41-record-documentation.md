# Per-record documentation blocks

*Who this is for: anyone adding or editing a DNS record.*

Every DNS record in `dns/` carries a `##` (double-hash) comment block
directly above it, answering four questions a reviewer or an on-call
responder shouldn't have to go dig for:

```yaml
## Owner: platform-team
## Purpose: primary website, public-facing
## Impact: changing content moves live traffic; changing proxied exposes the origin IP
## Proxy: on -- must stay proxied, this is a public web host
root:
  name: "@"
  content: 203.0.113.10
  proxied: true
```

| Line | Answers |
|---|---|
| `Owner` | Who to ask before changing this, or who's on the hook if it breaks |
| `Purpose` | What this record is for, in one line |
| `Impact` | What breaks, and how badly, if this is wrong or removed |
| `Proxy` | Why `proxied` is set the way it is (A/AAAA/CNAME only -- other record types don't have a `proxied` field) |

## Why `##`, not `#`

Every file already has a `#` header explaining the file's format in
general. A `##` block is a different thing: specific to the one record
below it, not the file as a whole. The double hash also lets an editor
color it differently (see below), so it's visually obvious at a glance
which records are documented and which aren't.

## The check

`record_has_doc_block` (in [40 Policy](40-policy.md)) looks for the
required lines directly above every DNS record's key, no blank line in
between. It's a warning by default, same as this repo's other
best-practice checks -- it won't block your PR, but it will show up on
every plan until it's fixed. A maintainer can turn it into a hard error
in `policy.yaml` once existing domains are backfilled.

## Coloring it in VS Code

This repo ships `.vscode/settings.json` and `.vscode/extensions.json`,
which configure the
[Better Comments](https://marketplace.visualstudio.com/items?itemName=aaron-bond.better-comments)
extension to render `##` lines in a distinct color from plain `#`
comments. VS Code will offer to install it when you open this repo;
it's recommended, not required -- without it, `##` lines are still
completely ordinary YAML comments, and the policy check still enforces
their presence either way.

## New and exported domains

`python3 cf.py new` and `python3 cf.py export` both write a placeholder
block (`Owner: change-me`, etc.) above every example or exported record,
so the file is policy-compliant from the moment it's created -- fill in
the real values instead of leaving `change-me`.

## Backfilling existing domains

For a domain that predates this convention, run the one-off helper once:

```bash
python3 scripts/backfill_record_docs.py domains/<domain>
```

It inserts a placeholder block above every record that doesn't already
have one (records with a block, even a partial one, are left alone).
This only adds comments -- `python3 cf.py plan <domain>` should still say
*Nothing will change* afterwards. Fill in the placeholders in a follow-up
PR, then flip `record_has_doc_block` to `severity: error` once every
domain is clean.
