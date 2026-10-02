# Using the repo on Windows

`python cf.py <command> ...` works exactly like `python3 cf.py <command> ...`
on macOS and Linux — no Make, WSL, Git Bash or PowerShell script is needed.

## One-off setup

1. Install the tools (winget shown; any installer works):

   ```powershell
   winget install Hashicorp.Terraform
   winget install Python.Python.3.12
   winget install Git.Git
   pip install -r requirements.txt
   ```

   Open a new terminal afterwards so `terraform` and `python` are on PATH.

2. Backend config:

   ```powershell
   Copy-Item backend.hcl.example backend.hcl
   notepad backend.hcl
   ```

3. Credentials for the current session (values from Delinea):

   ```powershell
   $env:CLOUDFLARE_API_TOKEN  = '...'
   $env:AWS_ACCESS_KEY_ID     = '...'   # R2 key ID
   $env:AWS_SECRET_ACCESS_KEY = '...'   # R2 secret
   ```

   These last only for that terminal window. Do not store them with
   `setx`; they would sit in your user profile in plain text.

## Commands

Every guide's `python3 cf.py <command> <domain>` works unchanged in
PowerShell or cmd.exe; just use `python` instead of `python3` (both usually
work, but Windows installs `python.exe`, not always `python3.exe`).

```powershell
python cf.py plan example.com
python cf.py apply example.com --yes      # skip typing the name to confirm
python cf.py plan example.com --backend local
$env:CF_BACKEND = 'local'                 # or set it for the session
$env:TF = 'tofu'                          # use OpenTofu instead of Terraform
```

## Raw Terraform commands from the guides

Commands such as `terraform -chdir=domains/example.com state list` work
unchanged in PowerShell; forward slashes are fine. Quote addresses that
contain square brackets in single quotes:

```powershell
terraform -chdir=domains/example.com state rm 'module.domain.module.dns.cloudflare_dns_record.this["a/www"]'
```

## What stays Linux-only

The GitHub Actions workflows run only in CI on Ubuntu runners (except
`windows.yml`, which re-runs the offline checks on Windows). You never run
them locally.
