<#
.SYNOPSIS
  Create domains/<name> from the template (PowerShell version of new-domain.sh).
.EXAMPLE
  .\scripts\new-domain.ps1 -Name example.org -ZoneId 0123456789abcdef0123456789abcdef -Plan pro
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)] [string]$Name,
  [Parameter(Mandatory)] [string]$ZoneId,
  [Parameter(Mandatory)] [ValidateSet('free', 'pro', 'business', 'enterprise')] [string]$Plan
)

$ErrorActionPreference = 'Stop'

if ($ZoneId -notmatch '^[0-9a-f]{32}$') {
  Write-Host 'Zone ID must be 32 lowercase hex characters' -ForegroundColor Red
  exit 1
}

$root     = Split-Path $PSScriptRoot -Parent
$domains  = Join-Path $root 'domains'
$template = Join-Path $domains '_template'
$dest     = Join-Path $domains $Name

if (Test-Path $dest) {
  Write-Host "$dest already exists" -ForegroundColor Red
  exit 1
}

Copy-Item $template $dest -Recurse
Remove-Item (Join-Path $dest 'README.md') -ErrorAction SilentlyContinue

# UTF-8 without BOM and LF endings, so files match the rest of the repo.
$content = "name: $Name`nzone_id: `"$ZoneId`"`nplan: $Plan`nowner: change-me`n"
[System.IO.File]::WriteAllText((Join-Path $dest 'domain.yaml'), $content, (New-Object System.Text.UTF8Encoding $false))

Write-Host "Created $dest. Fill in the YAML files, then: .\cf.ps1 plan $Name" -ForegroundColor Green
