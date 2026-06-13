$ErrorActionPreference = 'Stop'
try {
    $cert = New-SelfSignedCertificate `
        -Subject "CN=AI-DTCTM Code Signing, O=DHANUSH S, C=IN" `
        -DnsName "ai-dtctm.local" `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -Type CodeSigningCert `
        -HashAlgorithm SHA256 `
        -KeyAlgorithm RSA `
        -KeyLength 4096 `
        -NotAfter ((Get-Date).AddYears(3)) `
        -FriendlyName "AI-DTCTM Code Signing Certificate"

    Write-Host "[OK] Certificate generated"
    Write-Host ("      Subject:    " + $cert.Subject)
    Write-Host ("      Thumbprint: " + $cert.Thumbprint)
    Write-Host ("      Valid till: " + $cert.NotAfter.ToString("yyyy-MM-dd"))

    $exe = "D:\AI_DTCTM\dist\AI-DTCTM-Launcher\AI-DTCTM-Launcher.exe"
    $sig = Set-AuthenticodeSignature `
        -FilePath $exe `
        -Certificate $cert `
        -HashAlgorithm SHA256
    Write-Host ""
    Write-Host ("[OK] Signature status: " + $sig.Status)
    Write-Host ("      Signed file:    " + $exe)

    $out = "D:\AI_DTCTM\installer\cert"
    New-Item -ItemType Directory -Force -Path $out | Out-Null
    $pass = ConvertTo-SecureString "Aidtctm!2026" -Force -AsPlainText
    Export-PfxCertificate -Cert $cert -FilePath (Join-Path $out "AI-DTCTM-CodeSign.pfx") -Password $pass | Out-Null
    Export-Certificate     -Cert $cert -FilePath (Join-Path $out "AI-DTCTM-CodeSign.cer") -Type CERT | Out-Null
    Write-Host ""
    Write-Host "[OK] Certificates exported:"
    Write-Host ("      Private (.pfx): " + (Join-Path $out "AI-DTCTM-CodeSign.pfx"))
    Write-Host ("      Public  (.cer): " + (Join-Path $out "AI-DTCTM-CodeSign.cer"))
}
catch {
    Write-Host ("[FAIL] " + $_.Exception.Message)
    exit 1
}
