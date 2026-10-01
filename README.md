# Cloudflare Terraform (multi-domain)

Manage many Cloudflare zones (Free, Pro, Business, Enterprise) from one repo.
Each domain is a folder, each service is a sub-folder, and the data is plain
YAML. The Terraform logic lives in shared modules, so day-to-day changes
never need HCL. State is stored in Cloudflare R2.

```
cloudflare-terraform/
├── README.md                    this file
├── docs/                        step-by-step instructions (start here)
├── Makefile                     make help
├── backend.hcl.example          R2 state backend (copy to backend.hcl)
├── account/                     account-wide: IP/ASN/hostname lists, Bulk Redirects
├── domains/
│   ├── _template/               fully commented template, copied for new domains
│   ├── example.com/             Pro zone using most services
│   └── example.net/             Free zone, minimal
├── modules/                     shared logic (no domain data here)
│   ├── domain-stack/            reads a domain folder, wires every service
│   ├── dns/ waf/ security/ cache/ rules/ zone-settings/ lists/
├── scripts/
│   ├── export_zone.py           live zone or account -> YAML + import blocks
│   ├── new-domain.sh
│   └── changed-domains.sh       used by CI
└── .github/workflows/           plan on PR, apply on merge
```

## Inside a domain folder

```
domains/example.com/
├── domain.yaml                  name, zone_id, plan, owner
├── dns/
│   ├── a.yaml  aaaa.yaml  cname.yaml  mx.yaml  txt.yaml  ns.yaml
│   ├── spf.yaml  dmarc.yaml  dkim.yaml      (built from structured fields)
│   ├── caa.yaml  srv.yaml
│   └── dnssec.yaml
├── waf/
│   ├── custom-rules.yaml  rate-limits.yaml  managed-rules.yaml
├── security/
│   ├── hsts.yaml  bot-management.yaml  ip-access-rules.yaml
├── cache/
│   ├── cache-rules.yaml  settings.yaml      (tiered cache)
├── rules/
│   ├── redirects.yaml  url-rewrites.yaml
│   ├── request-headers.yaml  response-headers.yaml
│   ├── origin.yaml  config.yaml  compression.yaml
├── settings/zone.yaml           SSL mode, TLS, HTTPS, caching, speed
├── tests/plan.tftest.hcl        offline check, no token needed
└── main.tf  providers.tf        identical everywhere, never edited
```

Every file in `domains/_template` explains its own format with working
examples. **A service Terraform has never managed is left alone while its
file is empty, missing or fully commented.** Once something is managed,
deleting it from the YAML deletes it in Cloudflare; to stop managing
without deleting, see
[docs/03-services.md](docs/03-services.md#stop-managing-something-without-deleting-it).

## What is covered

| Area | Services | Plans |
|------|----------|-------|
| DNS | A, AAAA, CNAME, MX, TXT, NS (delegation), CAA, SRV | all |
| Email auth | SPF builder with 10-lookup check, DMARC builder, DKIM | all |
| DNSSEC | enable/disable, DS record output | all |
| WAF | custom rules, rate limiting | all (limits vary) |
| WAF | Cloudflare Managed Ruleset, OWASP Core Ruleset, exceptions | Pro+ |
| Security | HSTS, IP Access Rules | all |
| Bots | Bot Fight Mode (Free), Super Bot Fight Mode (Pro/Business), AI crawler blocking, Enterprise Bot Management settings | per plan |
| Cache | cache rules, Smart Tiered Cache | all |
| Rules | single redirects, URL rewrites, request and response header transforms, origin rules, configuration rules, compression rules | all (limits vary) |
| Account | IP, ASN and hostname lists; Bulk Redirects | all |
| Settings | any zone setting (SSL, TLS, HTTPS rewrites, browser cache TTL, Brotli, HTTP/3, ...) | all |

Plan limits are enforced at plan time with a clear message. Features a plan
does not include (for example origin Host header override on Pro) are
rejected by Cloudflare's own dry-run during `make plan`.

Not covered yet: Workers, Load Balancing, Spectrum, Zero Trust / Access,
custom certificates, Page Shield, Turnstile, Logpush. See
[docs/03-services.md](docs/03-services.md#adding-a-new-service) for how to add one.

## Quick start

```bash
cp backend.hcl.example backend.hcl                       # once; see docs/01
export CLOUDFLARE_API_TOKEN=...                          # from Delinea
export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=...   # R2 keys

make help
make test D=example.com      # offline: YAML, validation, plan limits
make plan D=example.com      # against Cloudflare
make apply D=example.com
```

## Instructions

1. [Getting started](docs/01-getting-started.md): tools, API token, R2 bucket, first plan
2. [Adding a domain](docs/02-adding-a-domain.md): new zone or existing zone
3. [Service reference](docs/03-services.md): every YAML file, with examples and gotchas
4. [Migrating existing zones](docs/04-migration.md): zero-change import runbook
5. [CI/CD](docs/05-ci-cd.md): GitHub Actions, environments, Delinea secrets
6. [Troubleshooting](docs/06-troubleshooting.md)

## Design decisions

1. **One state per root** in R2 (`domains/<name>.tfstate`, `account.tfstate`).
   A mistake in one zone cannot touch another; CI plans domains in parallel.
2. **YAML for data, modules for logic.** Rule files use Cloudflare's own API
   field names, so examples from Cloudflare's docs paste straight in.
3. **Zones are referenced, never created or destroyed here.** A bad change
   cannot delete a zone.
4. **Stable keys.** A YAML key becomes the Terraform address (`a/www`,
   `caa/letsencrypt`). Renaming a key deletes and recreates that item.
5. **Git is the source of truth.** Rulesets replace their whole phase, so
   dashboard edits to a managed phase are removed on the next apply.
