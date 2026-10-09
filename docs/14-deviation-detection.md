# Deviation detection: changes made outside this repository

*Who this is for: everyone, but especially reviewers and maintainers.*

**Deviation** is any difference between Cloudflare and the last apply
from this repo. It happens when someone changes something in the
Cloudflare dashboard, with another tool, or through the API.

Deviation matters because this repository is the source of truth. What
happens next depends on whether it can be auto-fixed (below) -- but
either way, a quick dashboard fix is never the end of the story: it's
either committed back into the YAML automatically, or flagged for you to
resolve.

## What changed in this version: auto-fix

Earlier versions of this check were read-only: they only opened an issue
and left the fix to a human. **That's no longer true.** When the
scheduled check finds deviation, it now:

1. Re-exports the deviated root from live Cloudflare (the same mechanism
   as `cf.py export`, which is read-only against Cloudflare itself).
2. Runs the exact same `validate.py` + `policy.yaml` checks a pull
   request would have to pass.
3. **Only if that passes**, commits the result and pushes it directly to
   `main` -- no pull request, no review.
4. Either way, you're notified: an issue is opened (then immediately
   closed) recording what was auto-fixed, or left open asking for manual
   review if the re-exported YAML didn't validate.

This is a deliberate trade-off: it removes the peer-review guarantee this
repo otherwise enforces on every change, specifically for deviation-
sourced commits. We chose it anyway because an undetected deviation (Cloudflare
silently diverging from the YAML of record) was judged the bigger risk.
If you'd rather not run with that trade-off, read
[Turning auto-fix off](#turning-auto-fix-off) below.

### Guardrails

- **Validation gates every push.** If the re-exported YAML fails
  structural checks or a `policy.yaml` rule set to `error`, nothing is
  pushed -- it falls back to the manual-review issue instead, same as
  before this version.
- **Only a resync, never new scope.** Zone settings this repo wasn't
  already managing (an entry missing from `settings/zone.yaml`) are never
  added by auto-fix, even though a full export would include them --
  auto-fix specifically restricts itself to settings already tracked
  before the run, matching this repo's rule that an omitted setting stays
  unmanaged.
- **Attributable commits.** Auto-fix commits come from a distinct bot
  identity (`deviation-bot` by default), so `git log`/`git blame` make it
  obvious at a glance that a commit wasn't a human change.
- **You're always told.** Every auto-fix opens (and closes) an issue
  recording exactly what changed and why, even though no approval was
  needed.
- **Race-safe.** If `main` moved between the check and the push, the push
  is rejected by git itself (not force-pushed) and falls back to the
  manual-review issue -- auto-fix never overwrites a concurrent change.
- **Known limitation: re-export isn't always a minimal diff.** The export
  mechanism normalizes some things to its own canonical form on every run
  (for example, `waf/managed-rules.yaml` always comes back as `raw_rules`,
  even when the simple `cloudflare_managed`/`owasp` form was hand-written
  and functionally identical). This means an auto-fix commit can
  occasionally include reformatting noise alongside the real fix. The
  committed YAML is always valid and reflects Cloudflare truthfully --
  just not always a surgically minimal diff. A purpose-built, minimal-diff
  resync is a reasonable future improvement, not something this version
  attempts.

### Required one-time setup: branch protection

Pushing straight to `main` only works if the bot identity is allowed to
bypass your branch protection rule (by default, `GITHUB_TOKEN`-based
pushes are blocked by required-PR-review rules exactly like anyone else's
would be). A repo admin needs to, once:

1. **Settings > Branches > main > Edit** the protection rule.
2. Under **"Allow specified actors to bypass required pull requests"**,
   add the GitHub Actions identity this workflow pushes as.
3. Save.

Until this is done, auto-fix will fail at the `git push` step and fall
back to the manual-review issue every time -- safe, but it means you're
not actually getting the auto-fix behavior. The job log will say so
explicitly if the push is rejected.

### Turning auto-fix off

If you'd rather go back to read-only detection (open an issue, human
decides), the auto-fix behavior lives entirely in
`scripts/deviation_autofix.py` and the "Auto-fix" step of
`.github/workflows/deviation-detection.yml`. Removing that step (and the
`contents: write` permission it needs) restores the pre-auto-fix
behavior: every deviation opens an issue, nothing is ever pushed
automatically.

## How deviation is found

1. **On every pull request**: the change summary has a
   *Changed outside Git* section, and marks each change that would undo
   it with *this undoes the dashboard change*.
2. **Every weekday morning**: the *cloudflare-deviation-detection*
   workflow checks every domain, auto-fixes what it safely can, and opens
   an issue either way (see above).
3. **Any time, on your computer**: `python3 cf.py deviation-check
   example.com`. Read-only -- it never writes anything, auto-fix or
   otherwise; that only happens in CI.

Example:

```
CHANGED OUTSIDE GIT (dashboard or API)
- DNS A `vpn.example.com` -> `198.51.100.99`
  - content: `198.51.100.5` -> `198.51.100.99`
- Zone setting `ssl`
  - value: `strict` -> `flexible`
```

## Resolving a "needs manual review" issue

Auto-fix doesn't catch everything -- it only pushes when the re-exported
YAML validates cleanly. For anything left open:

| Situation | Do this |
|---|---|
| The dashboard change is right and should stay | Open a PR that copies it into the YAML. When the plan for that PR no longer shows the item under *Will change*, it is resolved. |
| The dashboard change was a mistake | Re-apply the domain: GitHub **Actions > cloudflare > Run workflow**, enter the domain folder name, run. It plans (the summary shows the revert), waits for approval in `production`, then puts Cloudflare back to the YAML. |
| You do not know who did it or why | Check **Manage account > Audit log** in Cloudflare, ask that person, then pick one of the above. |

After the fix is applied, the next deviation check closes the issue.

## Emergency changes in the dashboard

Sometimes the dashboard is the fastest fix (an attack, an outage). That
is fine. Then:

1. Make the fix in the dashboard.
2. Post in the team channel what you changed and why.
3. Either let the next scheduled check auto-fix it (if it validates
   cleanly, it'll be committed within one business day, no action needed
   from you), or open a PR yourself sooner if you don't want to wait.
4. Until it's committed one way or the other, warn anyone with an open PR
   for the same domain: their apply would undo your fix.

## What deviation detection does not cover

- Things this repo does not manage at all (for example DNS record types
  it does not model, Workers, most of Zero Trust). Those are never
  touched.
- Settings that are not listed in a domain's YAML. If `settings/zone.yaml`
  does not mention `http3`, changing HTTP/3 in the dashboard is not
  deviation.
- Account-level objects outside what `account/` tracks.
