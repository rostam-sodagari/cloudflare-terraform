# Reviewing a pull request

As a reviewer you approve **what will happen in Cloudflare**, not just the
YAML. The change summary comment is your main tool. Plan for 5 to 10
minutes for a normal change.

## Before you start

- You need write access to the repo, and to be a required reviewer of the
  `production` environment if you also approve deployments.
- Do not approve your own PR, and do not approve a deployment for a PR
  you wrote.

## Checklist

Copy this into your review if it helps.

**1. The request**
- [ ] The PR description says what changes and **why** (ticket or request link).
- [ ] The change is small and about one thing. Ask for a split if not.

**2. The checks**
- [ ] All checks are green. A red YAML check means the PR is not ready.
- [ ] The change summary comment exists for every domain touched, and its
      footer shows the latest commit.

**3. The change summary** ([how to read it](12-reading-the-change-summary.md))
- [ ] Every line under *Will change in Cloudflare* matches the description.
- [ ] Nothing unexpected: no extra records, rules or settings.
- [ ] Every **WARNING** is explained in the description as intended.
- [ ] **Deletes**: the item really should go (MX, NS, A/CNAME for live
      sites, WAF rulesets, IP access rules, DNSSEC need extra care).
- [ ] **Changed outside Git**: the description says whether the dashboard
      change is being kept (copied into YAML) or deliberately reverted.

**4. The YAML** (Files changed tab)
- [ ] Keys were not renamed (renaming deletes and recreates).
- [ ] New WAF rules are in the right **position**: rules run top to bottom,
      and `skip` rules belong at the top.
- [ ] New blocking rules were tested with `managed_challenge` first, or the
      description explains why not.
- [ ] Nothing secret is committed (passwords, tokens, private keys).
- [ ] DNS: proxied (orange cloud) only for web traffic; mail, VPN and SSH
      records are not proxied.

**5. Timing**
- [ ] Risky changes (MX, NS, DNSSEC, HSTS, WAF deletions, SSL mode) are
      scheduled for a time when someone can watch and fix things.

Then **Approve**, or **Request changes** with a clear reason.

## Approving the deployment (after merge)

After merge, the change is planned again on `main` and waits for approval
in the `production` environment. You get a notification
(*Review pending deployments*).

1. Open the workflow run.
2. Open the **plan** job for each domain and read its summary on the run
   page. It should match what you approved on the PR.
3. If it shows anything new, especially **Changed outside Git**, someone
   changed Cloudflare since the PR was planned. **Reject** and ask the
   author to re-plan (push an empty commit or re-run the PR checks).
4. If it matches, click **Review deployments**, tick the domain(s), and
   **Approve and deploy**.

Only the plan you just read is applied. If another apply to the same
domain happened in between, Terraform refuses it as stale and nothing is
applied. Approve soon after reading: a dashboard edit made after the plan
is not part of it. If that edit touched an object being changed, the
reviewed values overwrite it; anything else is reported by the after-apply
check and the daily drift check.

## After the apply

- The run's last step re-plans and must say *Nothing will change*. If it
  warns otherwise, tell a maintainer.
- For DNS changes, spot-check with `dig` or an online DNS checker.
- For WAF changes, watch **Security > Events** in Cloudflare for a few
  minutes for unexpected blocks.

## If something goes wrong

1. **Revert the PR** on GitHub (the *Revert* button on the merged PR) and
   merge the revert. It follows the same plan and approve path, so it is
   safe and fast.
2. In a real emergency, fix it in the Cloudflare dashboard **first**, then
   open a PR that copies the fix into the YAML. The next drift check will
   remind you if you forget. See [14 Drift](14-drift.md#emergency-changes-in-the-dashboard).
