<#
.SYNOPSIS
  Windows / PowerShell equivalent of the Makefile.

.DESCRIPTION
  Works in Windows PowerShell 5.1 and PowerShell 7+ (also on macOS/Linux).
  Run from the repo root:

    .\cf.ps1 help
    .\cf.ps1 test example.com
    .\cf.ps1 plan example.com
    .\cf.ps1 apply example.com
    .\cf.ps1 plan account
    .\cf.ps1 new example.org -ZoneId <32-hex> -Plan pro
    .\cf.ps1 export example.org -ZoneId <32-hex>
    .\cf.ps1 export-account -AccountId <32-hex>

  Set $env:TF = "tofu" to use OpenTofu instead of Terraform.
#>
[CmdletBinding()]
param(
  [Parameter(Position = 0)]
  [ValidateSet('help', 'init', 'plan', 'apply', 'test', 'test-all', 'fmt', 'lint', 'domains', 'new', 'export', 'export-account')]
  [string]$Command = 'help',

  [Parameter(Position = 1)]
  [Alias('D')]
  [string]$Domain,

  [string]$ZoneId,
  [ValidateSet('free', 'pro', 'business', 'enterprise')]
  [string]$Plan,
  [string]$AccountId
)

$ErrorActionPreference = 'Stop'
$Root    = $PSScriptRoot
$Tf      = if ($env:TF) { $env:TF } else { 'terraform' }
$Backend = Join-Path $Root 'backend.hcl'

function Fail([string]$Message) {
  Write-Host $Message -ForegroundColor Red
  exit 1
}

function Invoke-Tf {
  param([string[]]$TfArgs)
  & $Tf @TfArgs
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

function Get-Python {
  foreach ($c in @('python', 'python3')) {
    if (Get-Command $c -ErrorAction SilentlyContinue) { return @($c) }
  }
  if (Get-Command 'py' -ErrorAction SilentlyContinue) { return @('py', '-3') }
  Fail 'Python 3 not found. Install it from python.org, then: pip install pyyaml'
}

function Resolve-RootDir([string]$Name) {
  if (-not $Name) { Fail "Name a domain or 'account', e.g. .\cf.ps1 $Command example.com" }
  if ($Name -eq 'account') {
    $dir = Join-Path $Root 'account'
    $key = 'account.tfstate'
  } else {
    $dir = Join-Path (Join-Path $Root 'domains') $Name
    $key = "domains/$Name.tfstate"
  }
  if (-not (Test-Path $dir -PathType Container)) { Fail "No such folder: $dir" }
  return @{ Dir = $dir; Key = $key }
}

function Get-Domains {
  Get-ChildItem (Join-Path $Root 'domains') -Directory |
    Where-Object { -not $_.Name.StartsWith('_') } |
    Sort-Object Name |
    ForEach-Object { $_.Name }
}

function Invoke-Init([hashtable]$R) {
  if (-not (Test-Path $Backend)) {
    Fail 'Missing backend.hcl: copy backend.hcl.example to backend.hcl and fill it in'
  }
  Invoke-Tf @("-chdir=$($R.Dir)", 'init', '-input=false', '-reconfigure',
    "-backend-config=$Backend", "-backend-config=key=$($R.Key)")
}

# imports.tf is set aside during the offline test: mocked providers cannot
# import, and import blocks only matter for a real plan.
function Invoke-Test([hashtable]$R) {
  $imports = Join-Path $R.Dir 'imports.tf'
  $parked  = Join-Path $R.Dir '.imports.tf.skip'
  $moved = $false
  if (Test-Path $imports) { Move-Item $imports $parked -Force; $moved = $true }
  try {
    & $Tf "-chdir=$($R.Dir)" init -backend=false -input=false | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "init failed in $($R.Dir)" }
    & $Tf "-chdir=$($R.Dir)" test
    if ($LASTEXITCODE -ne 0) { throw "tests failed in $($R.Dir)" }
  } finally {
    if ($moved) { Move-Item $parked $imports -Force }
  }
}

switch ($Command) {
  'help' {
    @'
.\cf.ps1 new <domain> -ZoneId <id> -Plan <free|pro|business|enterprise>   create from template
.\cf.ps1 export <domain> -ZoneId <id>      import an existing zone into YAML
.\cf.ps1 export-account -AccountId <id>    import account lists and bulk redirects
.\cf.ps1 test <domain|account>             offline checks, no token
.\cf.ps1 test-all                          offline checks for every root
.\cf.ps1 plan <domain|account>             plan against Cloudflare
.\cf.ps1 apply <domain|account>            apply the saved plan
.\cf.ps1 fmt | lint | domains
'@ | Write-Host
  }

  'init' { Invoke-Init (Resolve-RootDir $Domain) }

  'plan' {
    $r = Resolve-RootDir $Domain
    Invoke-Init $r
    Invoke-Tf @("-chdir=$($r.Dir)", 'plan', '-input=false', '-out=plan.bin')
  }

  'apply' {
    $r = Resolve-RootDir $Domain
    $planFile = Join-Path $r.Dir 'plan.bin'
    if (-not (Test-Path $planFile)) { Fail "Run .\cf.ps1 plan $Domain first" }
    Invoke-Tf @("-chdir=$($r.Dir)", 'apply', '-input=false', 'plan.bin')
    Remove-Item $planFile -Force
  }

  'test' {
    try { Invoke-Test (Resolve-RootDir $Domain) } catch { Fail $_.Exception.Message }
  }

  'test-all' {
    $failed = @()
    foreach ($name in @('account') + @(Get-Domains)) {
      Write-Host "== $name" -ForegroundColor Cyan
      try { Invoke-Test (Resolve-RootDir $name) } catch { $failed += $name }
    }
    if ($failed.Count -gt 0) { Fail "Failed: $($failed -join ', ')" }
  }

  'fmt' { Invoke-Tf @("-chdir=$Root", 'fmt', '-recursive') }

  'lint' {
    Invoke-Tf @("-chdir=$Root", 'fmt', '-recursive', '-check')
    if (Get-Command 'yamllint' -ErrorAction SilentlyContinue) {
      & yamllint -d relaxed (Join-Path $Root 'domains') (Join-Path $Root 'account')
      if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    } else {
      Write-Host 'yamllint not installed (pip install yamllint); skipped YAML lint' -ForegroundColor Yellow
    }
  }

  'domains' { Get-Domains | Write-Host }

  'new' {
    if (-not $Domain -or -not $ZoneId -or -not $Plan) {
      Fail '.\cf.ps1 new example.org -ZoneId <id> -Plan pro'
    }
    & (Join-Path (Join-Path $Root 'scripts') 'new-domain.ps1') -Name $Domain -ZoneId $ZoneId -Plan $Plan
    if (-not $?) { exit 1 }
  }

  'export' {
    if (-not $Domain -or -not $ZoneId) { Fail '.\cf.ps1 export example.org -ZoneId <id>' }
    $py = @(Get-Python)
    $pyArgs = @($py | Select-Object -Skip 1) + @((Join-Path (Join-Path $Root 'scripts') 'export_zone.py'), '--zone-id', $ZoneId, '--domain', $Domain)
    & $py[0] @pyArgs
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
  }

  'export-account' {
    if (-not $AccountId) { Fail '.\cf.ps1 export-account -AccountId <id>' }
    $py = @(Get-Python)
    $pyArgs = @($py | Select-Object -Skip 1) + @((Join-Path (Join-Path $Root 'scripts') 'export_zone.py'), '--account-id', $AccountId)
    & $py[0] @pyArgs
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
  }
}
