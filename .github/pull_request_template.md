<!--
Thank you! Fill in every section; reviewers use it to check the change
summary that CI posts on this pull request. Guide: docs/11-making-a-change.md
-->

## What changes in Cloudflare

<!-- In plain words, per domain. e.g. "example.com: api.example.com moves to the new load balancer (A record 203.0.113.20 -> 203.0.113.21)" -->

## Why

<!-- Ticket, request or incident link, and the reason. -->

## Risk and timing

<!-- Could this stop a website, e-mail or protection? (MX, NS, DNSSEC, HSTS, SSL mode, WAF deletions)
     When should it be applied, and who will watch afterwards? Write "low risk" if it is. -->

## Checklist

- [ ] I edited only `.yaml` files (or I am a maintainer changing code on purpose).
- [ ] The YAML check passes (green), or I am fixing the errors it marked.
- [ ] I read the **change summary** comment and it shows only what I described above.
- [ ] Every **WARNING** in the summary is intended and explained above.
- [ ] If the summary shows **Changed outside Git**, I explained whether that dashboard change is kept (copied into YAML) or reverted on purpose.
- [ ] New blocking WAF rules were tried with `managed_challenge` first, or I explained why not.
- [ ] No secrets (passwords, tokens, private keys) are in this PR.
