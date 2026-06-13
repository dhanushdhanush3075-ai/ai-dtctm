<#
================================================================
AI-DTCTM — Self-Sign Setup (Free Code Signing)
================================================================
Creates a self-signed code-signing certificate, exports the public
half for users to import, and signs your built launcher .exe.

USAGE
  # Run ONCE as Administrator on your dev machine:
  pwsh -ExecutionPolicy Bypass -File installer\sign_setup.ps1

  # Output:
  #   installer\cert\AI-DTCTM-CodeSign.pfx   (private, keep secret)
  #   installer\cert\AI-DTCTM-CodeSign.cer   (public, ship to users)
  #   dist\AI-DTCTM-Launcher\AI-DTCTM-Launcher.exe   (now signed)

For users to remove the SmartScreen warning permanently:
  pwsh -ExecutionPolicy Bypass -File installer\trust_publisher.ps1
================================================================
#>

param(
    [string]$CertName     = "AI-DTCTM Code Signing",
    [string]$Password     = "ChangeMe!2026",
    [string]$ValidYears   = "3"
)

$ErrorActionPreference = 'Stop'
$root   = Split-Path -Parent $PSScriptRoot
$out    = Join-Path $PSScriptRoot 'cert'
$pfx    = Join-Path $out 'AI-DTCTM-CodeSign.pfx'
$cer    = Join-Path $out 'AI-DTCTM-CodeSign.cer'
$exe    = Join-Path $root 'dist\AI-DTCTM-Launcher\AI-DTCTM-Launcher.exe'

# ── Verify the .exe to sign exists ────────────────────────────────
if (-not (Test-Path $exe)) {
    Write-Error "Cannot find launcher.exe at $exe — run build_windows.py first."
    exit 1
}

New-Item -ItemType Directory -Force -Path $out | Out-Null

# ── Step 1 — Generate the certificate in CurrentUser\My ───────────
Write-Host "[1/4] Creating self-signed code-signing certificate..." -ForegroundColor Cyan
$validUntil = (Get-Date).AddYears([int]$ValidYears)
$cert = New-SelfSignedCertificate `
    -Subject "CN=$CertName, O=DHANUSH S, C=IN" `
    -CertStoreLocation 'Cert:\CurrentUser\My' `
    -Type CodeSigningCert `
    -HashAlgorithm SHA256 `
    -KeyAlgorithm RSA `
    -KeyLength 4096 `
    -NotAfter $validUntil

Write-Host "      Thumbprint: $($cert.Thumbprint)"
Write-Host "      Valid until: $validUntil"

# ── Step 2 — Export PFX (with private key — keep secret) ──────────
Write-Host "[2/4] Exporting .pfx (KEEP THIS PRIVATE)..." -ForegroundColor Cyan
$securePass = ConvertTo-SecureString -String $Password -Force -AsPlainText
Export-PfxCertificate -Cert $cert -FilePath $pfx -Password $securePass | Out-Null
Write-Host "      $pfx"

# ── Step 3 — Export public .cer (ship this to users) ──────────────
Write-Host "[3/4] Exporting .cer (PUBLIC — ship to users)..." -ForegroundColor Cyan
Export-Certificate -Cert $cert -FilePath $cer -Type CERT | Out-Null
Write-Host "      $cer"

# ── Step 4 — Sign the launcher .exe ───────────────────────────────
Write-Host "[4/4] Signing $exe..." -ForegroundColor Cyan
Set-AuthenticodeSignature `
    -FilePath $exe `
    -Certificate $cert `
    -TimestampServer 'http://timestamp.digicert.com' `
    -HashAlgorithm SHA256 | Out-Null

# Verify the signature
$sig = Get-AuthenticodeSignature -FilePath $exe
Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  Signature status: $($sig.Status)" -ForegroundColor Green
Write-Host "  Signer:           $($sig.SignerCertificate.Subject)" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "NEXT STEPS:" -ForegroundColor Yellow
Write-Host "  1. Ship dist\AI-DTCTM-Launcher\AI-DTCTM-Launcher.exe to your users"
Write-Host "  2. Ship installer\cert\AI-DTCTM-CodeSign.cer (the public cert)"
Write-Host "  3. Ship installer\trust_publisher.ps1 (users run this ONCE)"
Write-Host ""
Write-Host "KEEP SECRET:" -ForegroundColor Red
Write-Host "  installer\cert\AI-DTCTM-CodeSign.pfx (your private key — never share)"
