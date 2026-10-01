# 7. Using the repo on Windows

Everything the Makefile does is also in **`cf.ps1`** at the repo root. It
runs in Windows PowerShell 5.1 and PowerShell 7+, so no Make, WSL or Git
Bash is needed.

## One-off setup

1. Install the tools (winget shown; any installer works):

   ```powershell
   winget install Hashicorp.Terraform
   winget install Python.Python.3.12
   winget install Git.Git
   pip install pyyaml yamllint
   ```

   Open a new terminal afterwards so `terraform` and `python` are on PATH.

2. Allow local scripts to run (once per user):

   ```powershell
   Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
   ```

   If the repo was downloaded as a zip rather than cloned, also run
   `Get-ChildItem -Recurse *.ps1 | Unblock-File`.

3. Backend config:

   ```powershell
   Copy-Item backend.hcl.example backend.hcl
   notepad backend.hcl
   ```

4. Credentials for the current session (values from Delinea):

   ```powershell
   $env:CLOUDFLARE_API_TOKEN  = '...'
   $env:AWS_ACCESS_KEY_ID     = '...'   # R2 key ID
   $env:AWS_SECRET_ACCESS_KEY = '...'   # R2 secret
   ```

   These last only for that terminal window. Do not store them with
   `setx`; they would sit in your user profile in plain text.

## Command map

| Makefile | PowerShell |
|----------|------------|
| `make help` | `.\cf.ps1 help` |
| `make test D=example.com` | `.\cf.ps1 test example.com` |
| `make test-all` | `.\cf.ps1 test-all` |
| `make plan D=example.com` | `.\cf.ps1 plan example.com` |
| `make apply D=example.com` | `.\cf.ps1 apply example.com` |
| `make plan D=account` | `.\cf.ps1 plan account` |
| `make new D=example.org ZONE_ID=<id> PLAN=pro` | `.\cf.ps1 new example.org -ZoneId <id> -Plan pro` |
| `make export D=example.org ZONE_ID=<id>` | `.\cf.ps1 export example.org -ZoneId <id>` |
| `make export-account ACCOUNT_ID=<id>` | `.\cf.ps1 export-account -AccountId <id>` |
| `make plan D=example.com BACKEND=local` | `.\cf.ps1 plan example.com -Backend local` |
| `export CF_BACKEND=local` | `$env:CF_BACKEND = 'local'` |
| `make migrate D=example.com TO=r2` | `.\cf.ps1 migrate example.com -To r2` |
| `make fmt` / `make lint` / `make domains` | `.\cf.ps1 fmt` / `lint` / `domains` |

Tab completion works for the command names. Use OpenTofu instead of
Terraform with `$env:TF = 'tofu'`.

Wherever the other guides say `make <target> D=<name>`, use the
PowerShell form from this table.

## Raw Terraform commands from the guides

Commands such as `terraform -chdir=domains/example.com state list` work
unchanged in PowerShell; forward slashes are fine. Quote addresses that
contain square brackets in single quotes:

```powershell
terraform -chdir=domains/example.com state rm 'module.domain.module.dns.cloudflare_dns_record.this["a/www"]'
```

## Line endings

`.gitattributes` keeps `*.sh` and the `Makefile` on LF (CI runs on Linux)
and `*.ps1` on CRLF. Leave Git's default `core.autocrlf=true` on Windows;
YAML and Terraform files work with either ending.

## What stays Linux-only

`scripts/changed-domains.sh` and the GitHub Actions workflows run only in
CI on Ubuntu runners, so they have no Windows version. You never run them
locally.
