/*
   AI-DTCTM | Generic Suspicious Patterns
   ═══════════════════════════════════════════════════════════════
   YARA rules that catch common malicious patterns regardless of
   malware family. Use this as the first pass before family-specific
   rules.

   REFERENCE:
     - YARA docs: https://yara.readthedocs.io/
     - Rule syntax: https://yara.readthedocs.io/en/stable/writingrules.html
*/

rule Suspicious_PowerShell_Execution
{
    meta:
        author      = "AI-DTCTM"
        description = "Detects obfuscated PowerShell execution"
        severity    = "high"
        category    = "execution"

    strings:
        $ps1 = "powershell" nocase
        $enc = "-EncodedCommand" nocase
        $iex = "IEX(" nocase
        $dl1 = "DownloadString" nocase
        $dl2 = "Invoke-WebRequest" nocase
        $bp  = "-ExecutionPolicy Bypass" nocase
        $hid = "-WindowStyle Hidden" nocase

    condition:
        $ps1 and 2 of ($enc, $iex, $dl1, $dl2, $bp, $hid)
}


rule Suspicious_Base64_Payload
{
    meta:
        author      = "AI-DTCTM"
        description = "Long base64 blob likely concealing a payload"
        severity    = "medium"
        category    = "obfuscation"

    strings:
        $b64 = /[A-Za-z0-9+\/]{200,}={0,2}/

    condition:
        $b64
}


rule Suspicious_Shellcode_Markers
{
    meta:
        author      = "AI-DTCTM"
        description = "Common shellcode byte patterns"
        severity    = "critical"
        category    = "shellcode"

    strings:
        $nop_sled    = { 90 90 90 90 90 90 90 90 90 90 }
        $ret_chain   = { C3 C3 C3 C3 }
        $exec_marker = "/bin/sh"
        $cmd_marker  = "cmd.exe"
        $call_eax    = { FF D0 }

    condition:
        any of them
}


rule Process_Injection_APIs
{
    meta:
        author      = "AI-DTCTM"
        description = "Windows APIs commonly used for process injection"
        severity    = "high"
        category    = "execution"

    strings:
        $a1 = "VirtualAllocEx"    ascii wide
        $a2 = "WriteProcessMemory" ascii wide
        $a3 = "CreateRemoteThread" ascii wide
        $a4 = "NtCreateThreadEx"   ascii wide
        $a5 = "QueueUserAPC"       ascii wide

    condition:
        3 of them
}


rule Registry_Persistence_Keys
{
    meta:
        author      = "AI-DTCTM"
        description = "Autorun registry keys used for persistence"
        severity    = "high"
        category    = "persistence"

    strings:
        $run1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"      nocase
        $run2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"  nocase
        $svc  = "SYSTEM\\CurrentControlSet\\Services"                    nocase
        $img  = "Image File Execution Options"                           nocase

    condition:
        any of them
}


rule Network_C2_Indicators
{
    meta:
        author      = "AI-DTCTM"
        description = "Network APIs used for C2 beaconing"
        severity    = "medium"
        category    = "c2"

    strings:
        $a1 = "InternetOpenA"   ascii wide
        $a2 = "HttpSendRequest" ascii wide
        $a3 = "WinHttpConnect"  ascii wide
        $a4 = "socket"          ascii wide
        $a5 = "connect"         ascii wide
        $tor  = ".onion"        ascii wide
        $tld1 = ".top"          ascii wide
        $tld2 = ".tk"           ascii wide

    condition:
        2 of ($a*) or any of ($tor, $tld1, $tld2)
}


rule EICAR_Test_File
{
    meta:
        author      = "AI-DTCTM"
        description = "EICAR anti-malware test string — safe to detect"
        severity    = "info"
        category    = "test"

    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

    condition:
        $eicar
}
