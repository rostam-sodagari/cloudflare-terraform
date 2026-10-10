# Documentation

Edit YAML, review a plan, then deploy through GitHub Actions. Start with the guide for your task.

| I want to... | Guide |
|---|---|
| Change a record, rule, or setting | [Making changes](making-changes.md) |
| Understand YAML or policy | [Configuration](configuration.md) |
| Find the right configuration file | [Services](services.md) |
| Look up optional YAML fields and defaults | [YAML field reference](yaml-fields.md) |
| Choose values for zone settings | [Zone setting values](zone-settings.md) |
| Write expressions or nested rule options | [Rule examples](rule-examples.md) |
| Set up my computer or GitHub | [Setup](setup.md) |
| Add a domain, import a zone, or manage state | [Operations](operations.md) |
| Understand deployment automation | [CI and approvals](ci.md) |
| Fix a failed check or deployment | [Troubleshooting](troubleshooting.md) |
| Change scripts, Terraform, or tests | [Development](development.md) |

## First change

1. Find your domain under `domains/<domain>/`.
2. Edit the relevant YAML file; its header contains an example.
3. Open a pull request and read its change summary.
4. After review and merge, approve the final deployment plan.

You can edit files through GitHub without installing local tools.
For local work, follow [Setup](setup.md), then run `python cf.py help`.
All commands in these guides run from the repository root. Use `python3` if that is your Python executable.
Replace example domains and IDs with your own values.

[External documentation](references.md) lists the upstream references.
