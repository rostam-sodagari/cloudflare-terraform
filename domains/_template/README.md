# {{DOMAIN}}

Run the commands below from the repository root. Use `python3` if needed on your system.
This folder configures an existing Cloudflare zone; it does not create the zone.

## 1. Configure the zone

In `domain.yaml`, check the zone ID and plan, and replace `owner: change-me` with your team.
New zones have commented samples in each service file. Uncomment only the blocks you need and replace sample values.
Each header explains required fields, defaults, value choices, and indentation. Leave its explanatory text commented.
For an exported zone, review the existing data and `.export/{{DOMAIN}}/EXPORT_REPORT.md` before editing.

For example, add a website record to `dns/a.yaml`:

```yaml
www:
  name: www
  content: 203.0.113.10
  proxied: true
```

Replace the sample address with your origin's real address. Keep the record key when changing its fields.
The samples remain inactive until uncommented; exported data is active configuration.
See [Services](../../docs/services.md) for other files.
Use [YAML syntax](../../docs/configuration.md), [Zone setting values](../../docs/zone-settings.md), or [Rule examples](../../docs/rule-examples.md) when you need more detail.

## 2. Validate and preview

```sh
python cf.py validate {{DOMAIN}}
python cf.py plan {{DOMAIN}}
```

Validation is offline. Planning needs [credentials and state setup](../../docs/setup.md).
Read the terminal summary or `domains/{{DOMAIN}}/plan-summary.md`.
Check every deletion, replacement, warning, and dashboard change. An initial export should primarily adopt existing objects; investigate unexpected changes.

## 3. Deploy through a pull request

```sh
git switch -c zone/configure-{{DOMAIN}}
git add domains/{{DOMAIN}}
git commit -m "feat(zone): configure {{DOMAIN}}"
git push -u origin zone/configure-{{DOMAIN}}
```

Open a PR and review the CI summary. After review and merge, a production approver reviews the new plan from `main` and approves deployment.
CI applies that saved plan and checks the result. See [Making changes](../../docs/making-changes.md).

## Local sandbox apply

For an agreed sandbox using local state:

```sh
python cf.py plan {{DOMAIN}} --backend local
python cf.py apply {{DOMAIN}}
python cf.py plan {{DOMAIN}} --backend local
```

Apply asks you to type the domain name. The last plan should show no changes.
Use the PR deployment path for shared zones. To move existing state, follow [State backends](../../docs/operations.md#state-backends).
