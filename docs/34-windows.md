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

3. Credentials for the current session, pulled from Delinea DevOps
   Secrets Vault (DSV) -- never paste a token directly, and never commit
   one:

   ```powershell
   # One-time: install the DSV CLI (see Delinea's current docs for
   # Windows) and log in with your own Delinea account:
   dsv init --tenant <your-tenant>

   # Every session: pull your personal read token and the R2 keys into
   # this shell. A read token is enough for plan, deviation-check, export;
   # only ask for an edit-scoped token if you're applying locally, which
   # should be rare -- applies normally happen in CI after review.
   $env:CLOUDFLARE_API_TOKEN  = dsv secret read <secret-path>:cloudflare-api-token --data.value
   $env:AWS_ACCESS_KEY_ID     = dsv secret read <secret-path>:r2-access-key-id --data.value
   $env:AWS_SECRET_ACCESS_KEY = dsv secret read <secret-path>:r2-secret-access-key --data.value
   ```

   Ask your Delinea admin for `<your-tenant>` and `<secret-path>` if you
   don't have them -- every user reads their own token from their own
   Delinea access, nobody shares a token directly.

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

The GitHub Actions workflows run only in CI, on Ubuntu runners. You never
run them locally.
