# Cloudflare configuration as code

Manage Cloudflare DNS, WAF, redirects, caching, security, and account settings through YAML and reviewed Terraform plans.

**[Read the documentation](docs/README.md)** or start with [Making changes](docs/making-changes.md).

## How it works

1. Edit YAML under `domains/<domain>/` or `account/`.
2. Open a pull request. CI checks the files and posts a change summary.
3. Review the summary and merge.
4. Approve the final plan from `main`. CI applies it and checks the result.

The scheduled deviation workflow can also adopt dashboard changes into Git automatically. Review its behavior in [Operations](docs/operations.md#automatic-resync).

## Quick commands

Run from the repository root with Python 3.12. Use `python3` if needed on your system.

```sh
python -m pip install -r requirements.txt
python cf.py validate-all
python cf.py help
```

Validation needs no credentials. Live plans, exports, and applies need [Setup](docs/setup.md).

## Find your guide

| Task | Guide |
|---|---|
| Edit and review configuration | [Making changes](docs/making-changes.md) |
| YAML and policy | [Configuration](docs/configuration.md) |
| File and service reference | [Services](docs/services.md) |
| Add domains, adopt resources, and manage state | [Operations](docs/operations.md) |
| Deployment automation | [CI and approvals](docs/ci.md) |
| Fix errors | [Troubleshooting](docs/troubleshooting.md) |
| Work on the implementation | [Development](docs/development.md) |

## Repository layout

| Path | Purpose |
|---|---|
| `domains/<domain>/` | Zone configuration |
| `domains/_template/` | Template for new domains |
| `account/` | Account-wide resources |
| `policy.yaml` | Best-practice check settings |
| `cf.py`, `scripts/` | CLI and supporting tools |
| `modules/`, `tests/` | Terraform implementation and tests |
| `docs/` | Guides and service reference |

`domains/` contains the template and your generated zones. Test domains live under `tests/fixtures/domains/`.
The sample account contains a fake ID and is excluded from live CI planning until configured.
