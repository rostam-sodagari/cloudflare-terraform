# Migrating existing zones (import runbook)

Goal: bring a live zone under this repo **without changing anything** in
Cloudflare. Success is a change summary that only says *to adopt*.

The exporter is read-only. It never changes Cloudflare.

## Before you start

1. Read token exported, `backend.hcl` in place, R2 keys exported
   ([30 Setup](30-setup.md)).
2. Start with a low-risk zone.
3. Agree a short change freeze on that zone in the dashboard. Changes made
   during the migration would appear as deviation.

## Step 1: account lists (once)

```bash
python3 cf.py export-account --account-id <account id> --plan <highest plan>
python3 cf.py plan account
```

The summary should list the lists as *adopt*. If Bulk Redirects exist, the
existing redirect rules are replaced by one generated rule per list; the
summary shows that as a change. Check it, then open a PR, merge, approve.

## Step 2: export the zone

```bash
python3 cf.py export example.org --zone-id <zone id>
```

What happens:

1. Every service is read: DNS (incl. CAA, SRV, NS, DNSSEC), WAF custom
   rules, rate limits, the managed WAF ruleset, cache rules, redirects,
   transforms, origin, configuration and compression rules, HSTS, bot
   settings, IP Access Rules, tiered cache and the common zone settings.
2. The domain folder is created from the template, so **every file keeps
   its documentation header**, with the exported data below a marker line.
3. `imports.tf` gets one import block per object.
4. A report is written to `.export/<domain>/EXPORT_REPORT.md`.
5. The YAML check runs on the result.

It refuses to overwrite an existing folder. Use `--force` to replace it;
the old folder is backed up to `.export/<domain>/backup-<time>/` first.

### Things the exporter keeps exactly as they are

| What | Kept as | Why |
|---|---|---|
| SPF or DMARC that cannot be rebuilt byte for byte from fields | `raw:` | no change on adoption |
| The managed WAF ruleset (Cloudflare Managed, OWASP, exceptions, overrides) | `raw_rules:` | every override preserved; switching to the simple form is optional and shows as a change |
| TXT, SPF, DMARC, DKIM stored in quotes (Cloudflare's normal form) | plain text; the module adds the quotes back | read and parsed from inside the quotes |
| TXT records Cloudflare holds without quotes (older records) | `quoted: false` | sent back unquoted, so no change |
| TXT split into parts at other points than every 255 characters | verbatim, with its quotes | the module sends quoted values unchanged |
| API fields the provider does not accept (e.g. `version`) | left out, listed in the report | they cannot be set anyway |

### Things it leaves alone (listed in the report)

DNS record types not modelled here (PTR, LOC, TLSA, ...), account-level IP
Access Rules, rate limits using complexity scoring, settings locked by the
plan.

## Step 3: first plan

```bash
python3 cf.py plan example.org
```

| The summary shows | Meaning | Do |
|---|---|---|
| only *to adopt* | perfect | step 4 |
| *ADOPT + CHANGE* on a few items | a value differs in form only (field order, a default the API adds) | adjust the YAML until it goes, or accept it if clearly harmless |
| *to add* or *to delete* | an import is missing or a key is wrong | **stop**; never apply a migration plan that adds or deletes |
| *changed outside Git* | someone edited the zone during the export | export again with `--force` |

## Step 4: pull request

Open a PR titled *Import example.org*. In the description, say it is an
import and paste the report's *Needs a look* section. Reviewers check that
the summary shows only adopt lines. Merge and approve: the apply only
adopts.

## Step 5: clean up

Open a second PR that deletes `domains/example.org/imports.tf`. Its plan
must say *Nothing will change*.

## Step 6: hand over

1. Tell the team that from now on this zone changes only through Git
   ([00 Start here](00-start-here.md)).
2. Consider restricting dashboard roles for the zone.
3. Lift the change freeze. The daily deviation check now watches the zone.

## Rollback

An adopt-only apply changes nothing in Cloudflare. To undo, delete
`domains/<d>.tfstate` from R2 and remove the folder in a PR.
