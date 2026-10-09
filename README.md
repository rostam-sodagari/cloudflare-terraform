# Cloudflare configuration as code

This repository controls Cloudflare for our domains: DNS, the firewall
(WAF), bot protection, redirects, caching, headers, certificates, zone
hygiene and account governance. Changes are made by editing small YAML
files and opening a pull request. Before anything is applied, everyone
sees a plain-English list of exactly what will change in Cloudflare, and
a colleague approves it.

**New here? Start with [docs/00-start-here.md](docs/00-start-here.md).**
You do not need to know Terraform.

## How a change works

1. Edit the YAML for a domain in your editor. Do not edit Cloudflare directly
   unless it is an emergency.
2. Open a pull request. Automatic checks mark any mistake on the exact line,
   with the fix, and run a configurable set of best-practice checks
   ([policy](docs/40-policy.md)).
3. A **change summary** is posted on the pull request: what will be added,
   changed or deleted, warnings for risky changes, and anything changed in
   the Cloudflare dashboard since the last apply.
4. A reviewer checks the summary and approves; you merge.
5. The change is planned again and an approver confirms it. That saved plan
   is applied, then a follow-up plan checks whether Cloudflare matches the
   YAML. Any remaining change must be investigated.

A daily check auto-fixes any change made outside this repository when it
validates cleanly, and opens a GitHub issue either way
([deviation detection](docs/14-deviation-detection.md)). Cloudflare and R2
credentials come from Delinea DevOps Secrets Vault, never from a value
pasted into this repo or a chat ([30 Setup](docs/30-setup.md)).

## Guides

| For | Guide |
|---|---|
| Everyone | [00 Start here](docs/00-start-here.md) |
| People who edit YAML | [10 YAML in five minutes](docs/10-yaml-basics.md), [11 Making a change](docs/11-making-a-change.md), [12 Reading the change summary](docs/12-reading-the-change-summary.md) |
| Reviewers and approvers | [13 Reviewing a pull request](docs/13-reviewing.md), [14 Deviation detection](docs/14-deviation-detection.md) |
| Anyone turning a best-practice check on/off | [40 Policy](docs/40-policy.md) |
| Anyone adding or editing a DNS record | [41 Record documentation](docs/41-record-documentation.md) |
| Reference | [20 Service reference](docs/20-services.md) (full detail); each YAML file's header has a short summary and one example |
| Maintainers | [30 Setup](docs/30-setup.md), [31 Adding a domain](docs/31-adding-a-domain.md), [32 Migrating existing zones](docs/32-migration.md), [33 CI/CD](docs/33-ci-cd.md), [34 Windows](docs/34-windows.md), [35 Local backend](docs/35-local-backend.md), [36 Troubleshooting](docs/36-troubleshooting.md), [37 Maintaining](docs/37-maintaining.md), [References](docs/references.md) |

## Layout

| Location | Purpose |
|---|---|
| `domains/<domain>/` | One folder per Cloudflare zone; this is where contributors edit configuration |
| `domains/_template/` | Template copied when a new domain is added |
| `account/` | Account-wide Cloudflare configuration |
| `policy.yaml` | Best-practice checks and severity settings |
| `modules/` | Terraform implementation used by maintainers |
| `scripts/` | Validation, policy, export, summary, and helper tooling |
| `tests/` | Unit tests and the end-to-end test |
| `docs/` | User, reviewer, and maintainer guides |

`domains/example.com` (Pro) and `domains/example.net` (Free) are samples
with fake IDs, marked `example: true`; CI never plans them.

## What is covered

| Area | Covered |
|---|---|
| DNS | A, AAAA, CNAME, MX, TXT, NS (delegation), CAA, SRV; SPF and DMARC built from fields; DKIM (including subdomain-published keys); DNSSEC; Email Routing |
| WAF | custom rules (incl. custom block pages), rate limiting, Cloudflare Managed and OWASP rulesets with exceptions -- zone-level and account-level |
| Security | HSTS, IP Access Rules, Bot Fight Mode / Super Bot Fight Mode / Bot Management, AI crawler blocking, Turnstile, Authenticated Origin Pulls |
| Certificates | Origin CA certificates, Advanced Certificate Manager packs, Total TLS, Certificate Transparency alerting |
| Rules | cache rules, single redirects, URL rewrites, request/response header rules, origin rules, configuration rules, compression rules |
| Cache | cache rules, Smart/Regional Tiered Cache, Cache Reserve, Argo Smart Routing, per-format variants |
| Account | IP/ASN/hostname lists, Bulk Redirects, account-level WAF, Logpush, notification policies, registrar settings, SSO connector, user groups, account DNS settings |
| Settings | any zone setting |
| Process | a repo-wide [policy gate](docs/40-policy.md) for best-practice checks, [deviation detection](docs/14-deviation-detection.md) with auto-fix, an optional [Freshservice change-request gate](docs/33-ci-cd.md#freshservice-change-request-gate-optional) |

Plan limits and plan-only features (Free, Pro, Business, Enterprise) are
checked before anything reaches Cloudflare, using the figures in
Cloudflare's documentation ([references](docs/references.md)).

Not covered: Workers, Pages, R2, Stream, D1, Queues, AI Gateway, Images
(separate platforms, not zone/account hygiene), Zero Trust/Access, Load
Balancing, Cloudflare for SaaS, Magic Transit/WAN, Spectrum, Waiting Room,
Email Security, secondary DNS, Snippets, and the Data Localization Suite
-- none of these are in use; adding modules for unused products is pure
maintenance weight with no one to catch a mistake in them.

## Commands

One command, identical on macOS, Linux and Windows: `python3 cf.py` (use
`python` instead of `python3` on Windows).

```bash
python3 cf.py validate example.com              # check the YAML (no token needed)
python3 cf.py plan example.com                  # exactly what would change, in plain English
python3 cf.py apply example.com                 # apply the reviewed plan (asks you to confirm)
python3 cf.py deviation-check example.com       # changes made outside Git since the last apply
python3 cf.py export example.org --zone-id <id> # bring an existing zone in (read-only)
python3 cf.py help                              # everything else
```

## Safety features

- **Line-level checks** for typos, wrong types, quoting traps (`on`/`off`),
  plan limits, CNAME conflicts, SPF lookup limits and missing lists.
- **A repo-wide policy gate** ([40 Policy](docs/40-policy.md)) for
  best-practice checks that are a judgment call rather than flat-out wrong,
  each one individually on/off and warning/error, checked on every plan
  and apply.
- **Plain-English change summary** with warnings for deletions that can cut
  traffic, e-mail or protection.
- **Deviation detection** on every plan and every weekday, auto-fixed when
  it validates cleanly against the same checks above.
- **Two approvals**: the pull request, then the deployment of the exact
  saved plan -- plus an optional Freshservice change-request check before
  the second one.
- **Credentials never touch this repo**: Cloudflare and R2 access come
  from Delinea DevOps Secrets Vault, in CI and locally.
- **No surprise deletions**: zones are never created or deleted here;
  DNSSEC cannot be switched off by deleting a file; an empty file for a
  service never managed here changes nothing.
- **One state file per domain** in Cloudflare R2, with locking, so a
  mistake in one domain cannot touch another.
