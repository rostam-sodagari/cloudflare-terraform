# Making a change

*Who this is for: anyone making a change, in the browser or on a computer.*

There are two ways to make a change. Both end in a pull request (PR), and
both show you the exact Cloudflare changes before anything happens. If you
are unsure which option to use, choose the browser method.

| | A. In the browser | B. On your computer |
|---|---|---|
| Needs | A GitHub account with access to the repo | Git, Python, Terraform, and Cloudflare/R2 credentials |
| Good for | Most changes: one record, one rule | Many changes, or trying things before a PR |
| You see the change summary | On the PR, about 2 minutes after each push | Straight away in your terminal, and on the PR |

---

## A. In the browser (no tools needed)

### 1. Open the file

1. Go to the repository on GitHub.
2. Open `domains/<your-domain>/` and then the file for what you want to
   change. Not sure which file? See the table in
   [Start here](00-start-here.md#where-things-are).
3. Read the comments at the top of the file. They list every field and
   show examples.

### 2. Edit it

1. Click the pencil icon (**Edit this file**).
2. Make your change. Copy an existing block, or uncomment an example
   (see [YAML in five minutes](10-yaml-basics.md#uncommenting-an-example)).
3. Use two spaces for indentation and quote `"on"` / `"off"`.

### 3. Create the pull request

1. Click **Commit changes...**
2. Commit message: what and why, e.g. `Point api.example.com at the new load balancer`.
3. Choose **Create a new branch for this commit and start a pull request**.
   Name it something like `dns/api-new-lb` or `waf/block-xmlrpc`.
4. Click **Propose changes**, then fill in the PR form. The template asks
   what you changed, why, and how you checked it. Fill in every part. If
   this repo has the Freshservice change-request gate enabled (ask a
   maintainer), add a line `Change-Ref: CHG-00123` naming your approved
   change request -- the apply after merge is blocked without it.
5. Click **Create pull request**.

### 4. Wait for the checks (about 2 minutes)

At the bottom of the PR you will see the checks running.

- **YAML errors** appear as red annotations on the exact line in the
  **Files changed** tab, with the fix. Edit the file again (pencil icon on
  your branch) and commit; the checks run again.
- **The change summary** is posted as a comment titled
  *Cloudflare change summary: your-domain*. It updates on every commit.

### 5. Read the change summary

This is the most important step. Check that it says exactly what you
meant and nothing else. [12 Reading the change summary](12-reading-the-change-summary.md)
explains every section. In particular:

- **Will change in Cloudflare** should list only your change.
- **WARNINGS** must be understood before you continue.
- **Changed outside Git** means someone used the dashboard: see
  [14 Deviation detection](14-deviation-detection.md) before continuing.

### 6. Ask for a review

Add a reviewer (top right of the PR). The reviewer follows
[13 Reviewing](13-reviewing.md). When they approve, merge the PR (or let
them).

### 7. After merge

1. The change is planned again on `main`.
2. An approver gets a request to approve the **production** deployment.
   They check the summary again; this protects against anything that
   changed in the meantime.
3. That saved plan is applied.
4. A follow-up plan checks whether Cloudflare now matches the YAML. Any
   remaining change must be investigated.

You can follow it under the **Actions** tab. If the apply fails, nothing
partial is left unreported: the run shows what happened, and a
maintainer will help.

---

## B. On your computer

One-off setup: [30 Setup](30-setup.md#4-on-your-computer). The same commands
work on macOS, Linux and Windows.

```bash
git switch main && git pull
git switch -c dns/api-new-lb              # a branch for your change

# edit the YAML in your editor, then:
python3 cf.py validate example.com        # check the YAML (no token needed)
python3 cf.py plan example.com            # the exact changes, in plain English

git add domains/example.com
git commit -m "Point api.example.com at the new load balancer"
git push -u origin dns/api-new-lb
```

Open the PR from the link Git prints. Paste the contents of
`domains/example.com/plan-summary.md` into the PR description if you like;
CI posts the same summary anyway.

Then continue from step 5 of the browser flow.

**Do not run `python3 cf.py apply` for shared domains.** Applying happens
from `main` after review. It is for sandboxes and emergencies agreed with a
maintainer; it shows the summary again and asks you to type the domain name
before changing anything.

---

## Common tasks

| Task | File | What to do |
|---|---|---|
| Add a website record | `dns/a.yaml` or `dns/cname.yaml` | Copy a block, new key, `proxied: true` |
| Point a name somewhere new | same file | Change `content` only; keep the key |
| Remove a record | its file | Delete the whole block (all its lines) |
| Verify a domain for a service | `dns/txt.yaml` | Add a block with the exact text you were given |
| Add a mail sender to SPF | `dns/spf.yaml` | Add its domain to `includes` |
| Block a path or country | `waf/custom-rules.yaml` | Add a rule; start with `managed_challenge` |
| Allow an office IP past the firewall | `waf/custom-rules.yaml` | A `skip` rule at the top |
| Add a redirect | `rules/redirects.yaml` | Copy the `old_page` example |
| Change SSL mode or TLS | `settings/zone.yaml` | Edit the line; quote the value |

## If you get stuck

1. The YAML check message usually contains the fix.
2. [36 Troubleshooting](36-troubleshooting.md) lists common errors.
3. Ask in the PR: mention a maintainer. Nothing is applied until approved,
   so a half-finished PR is safe.
