# 2. Adding a domain

First decide which case you are in.

| Case | Command | Result |
|------|---------|--------|
| Zone exists in Cloudflare and already has records/rules | `make export` | YAML filled from the live zone, plus `imports.tf` |
| Zone exists but is empty, or you want to start clean | `make new` | Commented template, nothing managed yet |

Find the Zone ID on the zone's **Overview** page (right-hand column, *API*).

## A. Existing zone (most common)

```bash
export CLOUDFLARE_API_TOKEN=<read-only token>
make export D=example.org ZONE_ID=<zone id>
```

Then follow [04-migration.md](04-migration.md). Do not edit anything before
the first clean plan; you want the import to change nothing.

## B. New or empty zone

```bash
make new D=example.org ZONE_ID=<zone id> PLAN=pro
```

This copies `domains/_template` to `domains/example.org` and fills in
`domain.yaml`. Every service file is commented out, so the first plan
manages nothing.

Then, one service at a time:

1. Open the file, read its header, uncomment and edit the examples.
2. `make test D=example.org`
3. `make plan D=example.org` and check the diff.
4. Commit and open a pull request.

A sensible order for a fresh zone:

1. `settings/zone.yaml`: uncomment the recommended baseline (SSL strict,
   TLS 1.2+, Always Use HTTPS).
2. `dns/`: A/CNAME records, then MX, SPF, DMARC (start at `policy: none`), DKIM.
3. `dns/caa.yaml` if you restrict certificate authorities.
4. `waf/custom-rules.yaml`, `waf/rate-limits.yaml`.
5. `waf/managed-rules.yaml` (Pro+), with OWASP in `log` first.
6. `security/bot-management.yaml`.
7. `cache/`, `rules/` as needed.
8. `security/hsts.yaml` last, with a short `max_age`.
9. `dns/dnssec.yaml` once the zone is stable (see the DS step in
   [03-services.md](03-services.md#dnssec)).

## domain.yaml

```yaml
name: example.org
zone_id: "0123456789abcdef0123456789abcdef"   # keep the quotes
plan: pro                                     # free | pro | business | enterprise
owner: platform-team
```

`plan` must match the real Cloudflare plan: it sets rule limits and which
settings are allowed. If the plan changes (e.g. Pro to Enterprise), update
it here in the same pull request as any new features you enable.

## Removing a domain

Zones themselves are never managed here, so removing a domain from the repo
never deletes the zone. Choose one:

1. **Hand the zone back to the dashboard, keep everything live (usual):**
   run `make init D=<d>`, then remove every resource from state without
   touching Cloudflare:
   `terraform -chdir=domains/<d> state list | xargs -n1 terraform -chdir=domains/<d> state rm`
   Then delete `domains/<d>.tfstate` from the R2 bucket.
2. **Remove everything Terraform created in the zone:** comment out every
   YAML file, `make plan D=<d>` (review the destroy list carefully),
   `make apply D=<d>`, then delete the state object.

Finally delete the folder and open a pull request. CI ignores deleted
folders, so nothing runs against them.
