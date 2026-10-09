# Start here

This repository controls Cloudflare for our domains: DNS records, the
firewall (WAF), redirects, caching and security settings. Instead of
clicking in the Cloudflare dashboard, you edit small text files and open a
pull request. A computer then shows exactly what would change in
Cloudflare, a colleague checks it, and only then is it applied.

You do **not** need to know Terraform. If you can edit a text file, you
can make changes here.

## Which guide do I need?

| I want to... | Read |
|---|---|
| Change a DNS record, a firewall rule, a redirect or a setting | [10 YAML in five minutes](10-yaml-basics.md), then [11 Making a change](11-making-a-change.md) |
| Understand the change summary on my pull request | [12 Reading the change summary](12-reading-the-change-summary.md) |
| Review someone else's pull request | [13 Reviewing a pull request](13-reviewing.md) |
| Understand a "deviation" issue, or I changed something in the dashboard | [14 Deviation detection](14-deviation-detection.md) |
| Turn a best-practice check on/off or warning/error | [40 Policy](40-policy.md) |
| Look up what a file or field means | [20 Service reference](20-services.md) (full detail); each file's header has a short summary and one example |
| Set the repository up, add a domain, run CI | [30 Setup for maintainers](30-setup.md) and the 3x guides |

## The five rules

1. **Change Cloudflare through this repository, not the dashboard.**
   Dashboard changes are detected as deviation; if they pass validation
   they're committed back into the YAML automatically within one business
   day, otherwise they're flagged for manual review. Either way, don't
   rely on a dashboard-only change sticking around.
2. **Only edit the `.yaml` files.** Never edit `.tf` files unless you are a
   maintainer.
3. **Every file explains itself.** Read the comments at the top of the file
   you are editing for a quick summary and one example; the full field list
   is in [20 Service reference](20-services.md).
4. **Read the change summary before asking for a review.** It is the exact
   list of what will happen in Cloudflare.
5. **When something looks wrong, stop and ask.** Nothing is applied until a
   reviewer approves it, twice.

## How a change flows

```
 you edit YAML ──► pull request ──► automatic checks ──► change summary posted on the PR
                                         │                        │
                                   errors marked on          reviewer reads it,
                                   the exact line            approves the PR
                                                                  │
                                                                merge
                                                                  │
                         planned again on main ──► approver checks the summary again
                                                                  │
                                                    exactly that plan is applied
                                                                  │
                                               a final check confirms Cloudflare
                                               now matches the YAML
```

## Where things are

```
domains/<your-domain>/
├── domain.yaml               which Cloudflare zone, which plan
├── dns/                      DNS records: a, aaaa, cname, mx, txt, ns,
│                             spf, dmarc, dkim, caa, srv, dnssec
├── waf/                      firewall: custom-rules, rate-limits, managed-rules
├── security/                 hsts, bot-management, ip-access-rules
├── cache/                    cache-rules, settings (tiered cache)
├── rules/                    redirects, url-rewrites, request-headers,
│                             response-headers, origin, config, compression
└── settings/zone.yaml        SSL mode, TLS, HTTPS, caching, speed

account/lists/                lists shared by every domain (IP lists, Bulk Redirects)
```

Ignore everything else unless you are a maintainer.

## Words you will see

| Word | Meaning |
|---|---|
| **YAML** | The simple text format of the files you edit. See [10](10-yaml-basics.md). |
| **Plan** | The list of changes Terraform would make. Reading Cloudflare to build it changes nothing. |
| **Change summary** | The plan in plain English, posted on your pull request. |
| **Apply** | Actually making the changes in Cloudflare. Only after approval. |
| **Deviation** (formerly "drift") | Something changed in Cloudflare outside this repository (usually the dashboard). Auto-fixed when it validates cleanly, otherwise flagged for review. |
| **Adopt** | Taking over something that already exists in Cloudflare without changing it. |
| **Zone** | One domain in Cloudflare (example.com). |
| **Proxied** | Orange cloud: traffic goes through Cloudflare's network. |
| **Ruleset / rule** | Firewall, redirect, cache and other rules. Rules in a file run top to bottom. |
| **State** | Terraform's record of what it manages, stored in Cloudflare R2. You never touch it. |
