/*
   AI-DTCTM | Fileless / Living-Off-The-Land Detection Rules
   ═══════════════════════════════════════════════════════════════
   Fileless attacks run entirely in memory using legit OS tooling
   (PowerShell, WMI, .NET reflection) — no disk artefact for AV
   to scan. Detected by behaviour, signed-binary abuse, and unusual
   command-line arguments.
*/

rule Fileless_PowerShell_Encoded
{
    meta:
        author      = "AI-DTCTM"
        description = "Base64-encoded PowerShell command (classic stager)"
        severity    = "critical"
        category    = "fileless"

    strings:
        $a = /powershell(\.exe)?\s+[^\r\n]{0,100}-(e|enc|encodedcommand)\s+[A-Za-z0-9+\/=]{60,}/ nocase
        $b = "FromBase64String"                    nocase
        $c = "IEX (New-Object Net.WebClient)"      nocase

    condition:
        $a or ($b and $c)
}


rule Fileless_PowerShell_Download_Cradle
{
    meta:
        author      = "AI-DTCTM"
        description = "PowerShell download-and-execute cradle"
        severity    = "critical"
        category    = "fileless"

    strings:
        $iex = "Invoke-Expression"                 nocase
        $iex2 = "IEX("                             nocase
        $dl1 = "DownloadString"                    nocase
        $dl2 = "DownloadFile"                      nocase
        $dl3 = "Invoke-WebRequest"                 nocase
        $dl4 = "iwr "                              nocase

    condition:
        any of ($iex*) and any of ($dl*)
}


rule Fileless_Reflective_DotNet_Load
{
    meta:
        author      = "AI-DTCTM"
        description = ".NET reflective assembly load — in-memory execution"
        severity    = "critical"
        category    = "fileless"

    strings:
        $a = "[Reflection.Assembly]::Load"         nocase
        $b = "[System.Reflection.Assembly]::Load"  nocase
        $c = "Assembly.Load("                      nocase

    condition:
        any of them
}


rule Fileless_AMSI_Bypass
{
    meta:
        author      = "AI-DTCTM"
        description = "AMSI bypass technique — disables PowerShell scan engine"
        severity    = "critical"
        category    = "fileless"

    strings:
        $a = "amsiInitFailed"                      nocase
        $b = "AmsiUtils"                           nocase
        $c = "amsi.dll"                            nocase
        $d = "AmsiScanBuffer"                      nocase
        $e = "[Ref].Assembly.GetType"              nocase

    condition:
        ($a) or ($b and $e) or ($c and $d)
}


rule Fileless_ETW_Patch
{
    meta:
        author      = "AI-DTCTM"
        description = "ETW patching — disable Event Tracing for Windows logging"
        severity    = "critical"
        category    = "fileless"

    strings:
        $a = "EtwEventWrite"                       nocase
        $b = "VirtualProtect"                      nocase
        $c = "0xC3"                                // ret instruction patch
        $d = "ntdll!EtwEventWrite"                 nocase

    condition:
        ($a and $b) or $d
}


rule Fileless_LOLBin_Squiblydoo
{
    meta:
        author      = "AI-DTCTM"
        description = "Squiblydoo — regsvr32 /i remote URL (signed binary abuse)"
        severity    = "critical"
        category    = "fileless"

    strings:
        $a = /regsvr32(\.exe)?\s+\/(s\s+)?\/?u?\s*\/?i:https?:\/\// nocase
        $b = "scrobj.dll"                          nocase

    condition:
        $a or $b
}


rule Fileless_LOLBin_CertUtil_Download
{
    meta:
        author      = "AI-DTCTM"
        description = "certutil abused as downloader"
        severity    = "high"
        category    = "fileless"

    strings:
        $a = /certutil(\.exe)?\s+[^\r\n]{0,40}-urlcache\s+[^\r\n]{0,40}-f\s+/ nocase
        $b = /certutil(\.exe)?\s+[^\r\n]{0,40}-decode/                        nocase

    condition:
        any of them
}
