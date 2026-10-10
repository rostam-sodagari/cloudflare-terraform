# Making changes

Use a pull request for changes to shared domains. GitHub Actions validates the YAML and posts a plan before deployment.

## Edit and open a pull request

1. Open `domains/<domain>/` and find the file in the [service reference](services.md).
2. Read its example, then edit the YAML. Keep existing record keys and rule `ref` values.
3. Commit to a new branch and open a pull request. Explain the change, its purpose, and how you checked it.
4. Fix failed checks and review the change summary before requesting approval.

In GitHub, use **Edit this file**, then choose a new branch when committing.
Locally, use:

```sh
git switch main
git pull
git switch -c dns/update-api
# Edit the YAML, then check it.
python cf.py validate example.org
git add domains/example.org/dns/a.yaml
git commit -m "fix(dns): point API record to the new origin"
git push -u origin dns/update-api
```

Validation needs no credentials. To preview live changes locally, [configure credentials](setup.md#credentials), then run:

```sh
python cf.py plan example.org
```

This writes `plan.log` and `plan-summary.md` inside the domain folder.
Shared R2 deployments use CI and reviewed PRs. Local `apply` is for a separate local-state sandbox.

## Read the change summary

Read **Warnings**, **Changed outside Git**, and **Will change in Cloudflare**.
Arrows mean **before -> after**.

| Label | Meaning |
|---|---|
| Add | Create an object |
| Change | Update an existing object |
| Delete | Remove an object |
| Replace | Delete and recreate an object |
| Adopt | Import an existing object into Terraform state |
| Changed outside Git | A managed object changed through the dashboard or API |

Every planned change should match your request. Explain intentional deletions and warnings in the PR.
Resolve unexpected dashboard changes using [Operations](operations.md#dashboard-changes).

## Review and deploy

The reviewer checks that:

- Checks pass and the summary and complete artifact match the latest commit.
- Additions, deletions, replacements, and rule order are intentional.
- Warnings and dashboard changes are explained.

A second user with repository write permission approves the current PR commit after reading its complete review artifact.
After merge, CI plans `main` again and requires the same inputs, live inventory, and writable effects. It applies that saved plan and checks convergence. No additional production environment approval is required.

Live changes detected after review stop deployment and require a fresh plan and PR approval. Pause dashboard edits during deployment: Cloudflare does not provide a transaction spanning all these resources, so an edit during the actual apply remains a race.

## Undo a change

Revert the PR and merge the revert through the same review process.
An apply can partially succeed before failing; inspect the run and create a fresh plan before deciding what to retry.
After an emergency dashboard fix, update the YAML and notify anyone preparing a deployment for that domain.
