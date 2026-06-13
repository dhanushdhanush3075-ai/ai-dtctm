<#
================================================================
AI-DTCTM — Trust This Publisher (User-side, ONE TIME)
================================================================
Users run this script ONCE before installing AI-DTCTM to import
the publisher certificate into their Trusted Publishers store.
After this, the SmartScreen warning never appears again for ANY
future AI-DTCTM version signed by the same certificate.

USAGE
  # User downloads AI-DTCTM-CodeSign.cer + this script.
  # Right-click PowerShell → Run as Administrator, then:

  pwsh -ExecutionPolicy Bypass -File trust_publisher.ps1

  # Output:
  #   Certificate imported into LocalMachine\TrustedPublisher
  #   Future AI-DTCTM .exe installs run without SmartScreen warnings

ALTERNATIVE WAYS TO TRUST (if user doesn't want PowerShell):
  • Double-click the .cer file → Install Certificate → Local Machine
    → "Place all certificates in the following store" → Browse →
    Trusted Publishers → Finish
================================================================
#>

param(
    [string]$CertPath = "AI-DTCTM-CodeSign.cer"
)

$ErrorActionPreference = 'Stop'

# Find cert next to this script if no path given
if (-not [System.IO.Path]::IsPathRooted($CertPath)) {
    $CertPath = Join-Path $PSScriptRoot $CertPath
}

if (-not (Test-Path $CertPath)) {
    Write-Error "Cannot find certificate at $CertPath"
    exit 1
}

# Check we're elevated
$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal   = New-Object Security.Principal.WindowsPrincipal($currentUser)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must run as Administrator. Right-click PowerShell -> Run as Administrator."
    exit 1
}

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  AI-DTCTM — Trust Publisher" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Importing $CertPath into:" -ForegroundColor White
Write-Host "  LocalMachine\TrustedPublisher" -ForegroundColor White
Write-Host "  LocalMachine\Root" -ForegroundColor White
Write-Host ""

# Import into Trusted Publishers (silences SmartScreen for signed exes)
Import-Certificate `
    -FilePath $CertPath `
    -CertStoreLocation 'Cert:\LocalMachine\TrustedPublisher' | Out-Null
Write-Host "  [OK] Trusted Publisher store" -ForegroundColor Green

# Import into Root (so Windows can chain-validate)
Import-Certificate `
    -FilePath $CertPath `
    -CertStoreLocation 'Cert:\LocalMachine\Root' | Out-Null
Write-Host "  [OK] Trusted Root CA store" -ForegroundColor Green

Write-Host ""
Write-Host "Done. AI-DTCTM .exe files signed with this certificate will" -ForegroundColor Green
Write-Host "now run without SmartScreen warnings on this machine." -ForegroundColor Green
Write-Host ""
Write-Host "To remove later:" -ForegroundColor Yellow
Write-Host "  certmgr.msc -> Trusted Publishers -> AI-DTCTM Code Signing -> Delete"
