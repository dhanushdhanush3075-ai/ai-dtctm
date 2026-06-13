/*
   AI-DTCTM | Red-Team / C2 Framework Detection Rules
   ═══════════════════════════════════════════════════════════════
   Cobalt Strike, Metasploit, Sliver, Empire, Havoc, Mythic.
   These are dual-use: authorised red team OR threat actor.
   Always alert + confirm with engagement record.
*/

rule C2_CobaltStrike_Beacon
{
    meta:
        author      = "AI-DTCTM"
        description = "Cobalt Strike Beacon strings / config markers"
        severity    = "critical"
        category    = "c2_framework"
        family      = "CobaltStrike"

    strings:
        $s1 = "beacon.dll"                         nocase
        $s2 = "beacon_"                            nocase
        $s3 = "%%IMPORT%%"                         nocase
        $s4 = "ReflectiveLoader"                   nocase
        $s5 = "this program cannot be run in dos mode"  nocase
        $s6 = "MZARUH"                             nocase  // beacon header marker
        $s7 = ".4.0;Win32"                         nocase  // CS UA
        $s8 = "CobaltStrike"                       nocase

    condition:
        2 of ($s1, $s2, $s3, $s4, $s6, $s7, $s8)
}


rule C2_Meterpreter
{
    meta:
        author      = "AI-DTCTM"
        description = "Metasploit Meterpreter payload markers"
        severity    = "critical"
        category    = "c2_framework"
        family      = "Metasploit"

    strings:
        $s1 = "meterpreter"                        nocase
        $s2 = "metsrv.dll"                         nocase
        $s3 = "stdapi_"                            nocase
        $s4 = "core_loadlib"                       nocase
        $s5 = "PAYLOAD_UUID"                       nocase
        $s6 = "ReflectiveDllInjection"             nocase

    condition:
        2 of them
}


rule C2_Sliver
{
    meta:
        author      = "AI-DTCTM"
        description = "Sliver implant (BishopFox red-team framework)"
        severity    = "critical"
        category    = "c2_framework"
        family      = "Sliver"

    strings:
        $s1 = "sliverpb"                           nocase
        $s2 = "implant.proto"                      nocase
        $s3 = "Sliver"                             nocase
        $s4 = "bishopfox/sliver"                   nocase
        $s5 = "SliverServerPubKey"                 nocase

    condition:
        2 of them
}


rule C2_Empire_PowerShell
{
    meta:
        author      = "AI-DTCTM"
        description = "PowerShell Empire agent strings"
        severity    = "critical"
        category    = "c2_framework"
        family      = "Empire"

    strings:
        $s1 = "Invoke-Empire"                      nocase
        $s2 = "Empire/agent"                       nocase
        $s3 = "$global:agent"                      nocase
        $s4 = "Invoke-Obfuscation"                 nocase
        $s5 = "BypassUAC"                          nocase
        $s6 = "Get-Keystrokes"                     nocase

    condition:
        2 of them
}


rule C2_Havoc
{
    meta:
        author      = "AI-DTCTM"
        description = "Havoc C2 framework (HavocFramework/Havoc)"
        severity    = "critical"
        category    = "c2_framework"
        family      = "Havoc"

    strings:
        $s1 = "Havoc"                              nocase
        $s2 = "Demon.x64"                          nocase
        $s3 = "Demon.x86"                          nocase
        $s4 = "HavocAgent"                         nocase
        $s5 = "HavocBeacon"                        nocase

    condition:
        2 of them
}


rule C2_Mythic_Apollo
{
    meta:
        author      = "AI-DTCTM"
        description = "Mythic C2 with Apollo (.NET) agent"
        severity    = "critical"
        category    = "c2_framework"
        family      = "Mythic"

    strings:
        $s1 = "Apollo.exe"                         nocase
        $s2 = "Mythic"                             nocase
        $s3 = "apfell"                             nocase
        $s4 = "Tetanus"                            nocase  // Mythic Rust agent
        $s5 = "AthenaAgent"                        nocase

    condition:
        any of them
}
