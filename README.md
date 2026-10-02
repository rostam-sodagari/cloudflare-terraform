# Cloudflare configuration as code

This repository controls Cloudflare for our domains: DNS, the firewall
(WAF), bot protection, redirects, caching, headers and zone settings.
Changes are made by editing small YAML files and opening a pull request.
Before anything is applied, everyone sees a plain-English list of exactly
what will change in Cloudflare, and a colleague approves it.

**New here? Start with [docs/00-start-here.md](docs/00-start-here.md).**
You do not need to know Terraform.

## How a change works

1. Edit the YAML for a domain, in the browser or on your computer.
2. Open a pull request. Automatic checks mark any mistake on the exact line,
   with the fix.
3. A **change summary** is posted on the pull request: what will be added,
   changed or deleted, warnings for risky changes, and anything changed in
   the Cloudflare dashboard since the last apply.
4. A reviewer checks the summary and approves; you merge.
5. The change is planned again and an approver confirms it. Exactly that
   plan is applied, then a final check confirms Cloudflare matches the YAML.

A daily check reports any change made outside this repository as a GitHub
issue ([drift](docs/14-drift.md)).

## Guides

| For | Guide |
|---|---|
| Everyone | [00 Start here](docs/00-start-here.md) |
| People who edit YAML | [10 YAML in five minutes](docs/10-yaml-basics.md), [11 Making a change](docs/11-making-a-change.md), [12 Reading the change summary](docs/12-reading-the-change-summary.md) |
| Reviewers and approvers | [13 Reviewing a pull request](docs/13-reviewing.md), [14 Drift](docs/14-drift.md) |
| Reference | [20 Service reference](docs/20-services.md) (full detail); each YAML file's header has a short summary and one example |
| Maintainers | [30 Setup](docs/30-setup.md), [31 Adding a domain](docs/31-adding-a-domain.md), [32 Migrating existing zones](docs/32-migration.md), [33 CI/CD](docs/33-ci-cd.md), [34 Windows](docs/34-windows.md), [35 Local backend](docs/35-local-backend.md), [36 Troubleshooting](docs/36-troubleshooting.md), [37 Maintaining](docs/37-maintaining.md), [References](docs/references.md) |

## Layout

```
domains/<domain>/          one folder per Cloudflare zone; the files people edit
  domain.yaml              zone ID and plan
  dns/                     a, aaaa, cname, mx, txt, ns, spf, dmarc, dkim, caa, srv, dnssec
  waf/                     custom-rules, rate-limits, managed-rules
  security/                hsts, bot-management, ip-access-rules
  cache/                   cache-rules, settings
  rules/                   redirects, url-rewrites, request-headers, response-headers,
                           origin, config, compression
  settings/zone.yaml       SSL, TLS, HTTPS, caching and speed settings
domains/_template/         copied for every new domain; documents every file
account/                   account-wide lists and Bulk Redirects
modules/                   Terraform code (maintainers only)
scripts/                   validator, change summary, exporter, helpers
tests/                     unit tests and an end-to-end test
docs/                      the guides above
```

`domains/example.com` (Pro) and `domains/example.net` (Free) are samples
with fake IDs, marked `example: true`; CI never plans them.

## What is covered

| Area | Covered |
|---|---|
| DNS | A, AAAA, CNAME, MX, TXT, NS (delegation), CAA, SRV; SPF and DMARC built from fields; DKIM; DNSSEC |
| WAF | custom rules (incl. custom block pages), rate limiting, Cloudflare Managed and OWASP rulesets with exceptions |
| Security | HSTS, IP Access Rules, Bot Fight Mode / Super Bot Fight Mode / Bot Management, AI crawler blocking |
| Rules | cache rules, single redirects, URL rewrites, request/response header rules, origin rules, configuration rules, compression rules |
| Account | IP, ASN and hostname lists; Bulk Redirects |
| Settings | any zone setting, plus Smart Tiered Cache |

Plan limits and plan-only features (Free, Pro, Business, Enterprise) are
checked before anything reaches Cloudflare, using the figures in
Cloudflare's documentation ([references](docs/references.md)).

Not covered yet: Workers, Load Balancing, Spectrum, Zero Trust / Access,
custom certificates, Page Shield, Turnstile, Logpush.

## Commands

One command, identical on macOS, Linux and Windows: `python3 cf.py` (use
`python` instead of `python3` on Windows).

```bash
python3 cf.py validate example.com              # check the YAML (no token needed)
python3 cf.py plan example.com                  # exactly what would change, in plain English
python3 cf.py apply example.com                 # apply the reviewed plan (asks you to confirm)
python3 cf.py drift example.com                 # changes made outside Git since the last apply
python3 cf.py export example.org --zone-id <id> # bring an existing zone in (read-only)
python3 cf.py help                              # everything else
```

## Safety features

- **Line-level checks** for typos, wrong types, quoting traps (`on`/`off`),
  plan limits, CNAME conflicts, SPF lookup limits and missing lists.
- **Plain-English change summary** with warnings for deletions that can cut
  traffic, e-mail or protection.
- **Drift detection** on every plan and every weekday.
- **Two approvals**: the pull request, then the deployment of the exact
  saved plan.
- **No surprise deletions**: zones are never created or deleted here;
  DNSSEC cannot be switched off by deleting a file; an empty file for a
  service never managed here changes nothing.
- **One state file per domain** in Cloudflare R2, with locking, so a
  mistake in one domain cannot touch another.
