# Drift: changes made outside this repository

**Drift** is any difference between Cloudflare and the last apply from
this repo. It happens when someone changes something in the Cloudflare
dashboard, with another tool, or through the API.

Drift matters because this repository is the source of truth: **the next
apply for that domain puts everything back to what the YAML says.** A
quick dashboard fix can be silently undone by someone else's unrelated PR.

## How drift is found

1. **On every pull request**: the change summary has a
   *Changed outside Git* section, and marks each change that would undo
   it with *this undoes the dashboard change*.
2. **Every weekday morning**: the *cloudflare-drift* workflow checks every
   domain. If it finds drift, it opens (or updates) a GitHub issue titled
   **Cloudflare drift: <domain>** with the label `drift`, listing exactly
   what changed. The issue closes itself when the drift is gone.
3. **Any time, on your computer**: `make drift D=example.com`
   (Windows: `.\cf.ps1 drift example.com`). Read-only.

Example:

```
CHANGED OUTSIDE GIT (dashboard or API)
- DNS A `vpn.example.com` -> `198.51.100.99`
  - content: `198.51.100.5` -> `198.51.100.99`
- Zone setting `ssl`
  - value: `strict` -> `flexible`
```

## Resolving it

For each item, decide:

| Situation | Do this |
|---|---|
| The dashboard change is right and should stay | Open a PR that copies it into the YAML. When the plan for that PR no longer shows the item under *Will change*, it is resolved. |
| The dashboard change was a mistake | Re-apply the domain: GitHub **Actions > cloudflare > Run workflow**, enter the domain folder name, run. It plans (the summary shows the revert), waits for approval in `production`, then puts Cloudflare back to the YAML. |
| You do not know who did it or why | Check **Manage account > Audit log** in Cloudflare, ask that person, then pick one of the above. |

After the fix is applied, the next drift check closes the issue.

## Emergency changes in the dashboard

Sometimes the dashboard is the fastest fix (an attack, an outage). That is
fine. Then:

1. Make the fix in the dashboard.
2. Post in the team channel what you changed and why.
3. Within one working day, open a PR that copies the change into the YAML.
   The PR's change summary should then show **no** change for that item;
   that confirms the YAML now matches.
4. Until that PR is merged, warn anyone with an open PR for the same
   domain: their apply would undo your fix.

## What drift does not cover

- Things this repo does not manage at all (for example DNS record types it
  does not model, Workers, Zero Trust). Those are never touched.
- Settings that are not listed in a domain's YAML. If `settings/zone.yaml`
  does not mention `http3`, changing HTTP/3 in the dashboard is not drift.
