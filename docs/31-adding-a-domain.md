# Adding a domain

*Who this is for: maintainers bringing a new or existing zone into this repo.*

| Situation | Command | You get |
|---|---|---|
| The zone already exists in Cloudflare with records and rules (usual) | `python3 cf.py export` | Every file filled from the live zone, plus `imports.tf` |
| The zone is new or empty | `python3 cf.py new` | Every file commented out; nothing managed yet |

Find the Zone ID on the zone's **Overview** page, *API* section.

## Existing zone

Pull your read token from Delinea first ([30 Setup](30-setup.md#4-on-your-computer)),
then:

```bash
python3 cf.py export example.org --zone-id <zone id>
```

Then follow [32 Migrating existing zones](32-migration.md). Change nothing
until the first plan shows only *adopt* lines.

## New or empty zone

```bash
python3 cf.py new example.org --zone-id <zone id> --plan pro
```

This copies `domains/_template` and fills in `domain.yaml`. Then, one
service per pull request, in roughly this order:

1. `settings/zone.yaml`: uncomment the recommended baseline.
2. `dns/`: website records, then MX, SPF, DMARC (`policy: none` first), DKIM.
3. `dns/caa.yaml` if you restrict certificate authorities.
4. `waf/custom-rules.yaml`, `waf/rate-limits.yaml` (`managed_challenge` first).
5. `waf/managed-rules.yaml` (Pro+): OWASP at `score_threshold: 60`.
6. `security/bot-management.yaml`.
7. `cache/`, `rules/` as needed.
8. `security/hsts.yaml`, with `max_age: 300` to start.
9. `dns/dnssec.yaml` once the zone is stable.

## domain.yaml

```yaml
name: example.org
zone_id: "0123456789abcdef0123456789abcdef"   # keep the quotes
plan: pro                                     # free | pro | business | enterprise
owner: platform-team
```

`plan` must match the real Cloudflare plan. After an upgrade, change it in
the same PR as any new features you start using.

## Removing a domain

Zones are never created or deleted by this repo, so removing a folder
never deletes the zone. Choose one:

1. **Stop managing it here, without changing it in Cloudflare (usual):**

   ```bash
   python3 cf.py init <d>
   terraform -chdir=domains/<d> state list | xargs -n1 terraform -chdir=domains/<d> state rm
   ```

   Then delete `domains/<d>.tfstate` from the R2 bucket.

2. **Remove everything this repo created in the zone:** comment out every
   YAML file in a PR (DNSSEC must first be set to `disabled`), review the
   delete list in the change summary very carefully, merge and approve,
   then delete the state object.

Finally delete the folder in a PR. CI ignores deleted folders.
