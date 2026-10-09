# Reading the change summary

Every plan produces a change summary: on your pull request (as a comment),
on the GitHub Actions run page, and in your terminal after `python3 cf.py plan`. It
lists **exactly** what would happen in Cloudflare if the plan were applied.
Nothing in it has happened yet.

## The first line

```
2 to change, 1 to delete, 1 changed outside Git
```

| Word | Meaning |
|---|---|
| to add | New things will be created in Cloudflare |
| to change | Existing things will be edited |
| to delete | Things will be removed from Cloudflare |
| to replace | Deleted and created again (brief gap) |
| to adopt | Already exist; taken over by this repo with no change |
| changed outside Git | Someone edited Cloudflare directly since the last apply |
| **no changes** | Cloudflare already matches the YAML |

## The sections, in the order they appear

### WARNINGS: read these first

Things that can cut traffic, e-mail or protection, for example:

```
- Deleting DNS MX `example.com` -> `mail.example.com` priority 10 can stop a website or e-mail from working.
- Deleting WAF custom rules: removes the rules in this phase, including any protection they give.
- DNS A `api.example.com` is deleted and recreated; expect a brief gap while it is replaced.
```

If you did not mean it, fix the YAML. If you did, say so in the PR
description so the reviewer knows it is intended.

### Changed outside Git (dashboard or API)

```
- DNS A `vpn.example.com` -> `198.51.100.99`
  - content: `198.51.100.5` -> `198.51.100.99`
```

Someone changed this in Cloudflare directly. **Applying your PR would put
it back** to what the YAML says, and the matching line under "Will change"
says *this undoes the dashboard change*. Decide before continuing:

- **The dashboard change should stay:** copy it into the YAML in your PR
  (here: set `content: 198.51.100.99`). The plan then stops undoing it.
- **The dashboard change was a mistake:** leave the YAML as it is and say
  in the PR that the revert is intended.
- **Not sure:** ask whoever made it (Cloudflare's audit log shows who)
  before merging. See [14 Deviation detection](14-deviation-detection.md).

### Will change in Cloudflare

One line per object, then the field changes under it:

```
- CHANGE   DNS A `api.example.com` -> `203.0.113.21` (proxied)
  - content: `203.0.113.20` -> `203.0.113.21`
- ADD      DNS TXT `example.com` -> `google-site-verification=abc`
- CHANGE   WAF custom rules
  - rule `block_admin`: action `block` -> `managed_challenge`
  - add rule `block_xmlrpc` at position 2: block when `(http.request.uri.path eq "/xmlrpc.php")`
  - rule `allow_monitoring` moves from position 2 to 3 (rules run top to bottom)
```

How to read the arrows: **before -> after**. For rules, each rule is
named by its `ref`, and moves are shown because order changes behaviour.

### Adopt (already in Cloudflare, nothing changes)

Only seen when a domain is first brought into the repo. These objects are
taken over as they are.

## A good summary for a small change

```
1 to add

WILL CHANGE IN CLOUDFLARE
- ADD      DNS CNAME `docs.example.com` -> `example.gitbook.io` (proxied)
```

One line, matching exactly what you meant. Most PRs look like this.

## Questions to ask yourself

1. Is every line something I meant to change?
2. Is anything I meant to change **missing**? (Maybe a typo in a key, or the
   wrong file.)
3. Do I understand every warning?
4. Is anything "changed outside Git"? Have I decided what to do about it?

If any answer is "no", do not ask for a review yet. Fix the YAML or ask
for help in the PR.

## Why it is trustworthy

- It is generated from Terraform's own plan, not from your YAML, so it
  shows what Terraform will actually do.
- After merge the plan is made again and the approver sees that new
  summary. Only that exact saved plan is applied: nothing that was not in
  the summary is changed.
- If another apply to the same domain happened in between, Terraform
  refuses the old plan ("saved plan is stale") and a fresh plan is needed.
- A dashboard edit made *after* the plan is not seen by that plan. If it
  touched an object the plan changes, the apply overwrites it with the
  reviewed values. If it touched anything else, it is left alone and the
  check after the apply (and the daily deviation check) reports it. So keep
  the time between plan and approval short, and do not edit a domain in
  the dashboard while it has a deployment waiting for approval.
- After applying, a final plan must say "Nothing will change".
