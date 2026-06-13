/*
   AI-DTCTM | Commodity RAT (Remote Access Trojan) Detection Rules
   ═══════════════════════════════════════════════════════════════
   RATs give attackers persistent remote control over an endpoint.
   The commodity scene (AsyncRAT, njRAT, Remcos, Quasar, NanoCore,
   Warzone, VenomRAT) dominates phishing campaigns.
*/

rule RAT_AsyncRAT
{
    meta:
        author      = "AI-DTCTM"
        description = "AsyncRAT — .NET RAT, dominant commodity RAT 2022–24"
        severity    = "critical"
        category    = "rat"
        family      = "AsyncRAT"

    strings:
        $s1 = "AsyncClient"                        nocase
        $s2 = "AsyncRAT"                           nocase
        $s3 = "ClientSocket"                       nocase
        $s4 = "Pastebin_URL"                       nocase
        $s5 = "Aes256"                             nocase
        $s6 = "MutexControl"                       nocase
        $s7 = "Antianalysis"                       nocase
        $s8 = "anti_VM"                            nocase

    condition:
        3 of them
}


rule RAT_njRAT
{
    meta:
        author      = "AI-DTCTM"
        description = "njRAT — long-running .NET RAT, very common in MENA region"
        severity    = "critical"
        category    = "rat"
        family      = "njRAT"

    strings:
        $s1 = "njRAT"                              nocase
        $s2 = "netframework"                       nocase
        $s3 = "OK[Splitter]"
        $s4 = "[endof]"
        $s5 = "@!#&^%$"                            // njrat sep
        $s6 = "ll]q@!"

    condition:
        any of ($s1, $s3, $s4, $s5, $s6) and #s2 < 5
}


rule RAT_Remcos
{
    meta:
        author      = "AI-DTCTM"
        description = "Remcos RAT — commercial remote-control tool abused by attackers"
        severity    = "critical"
        category    = "rat"
        family      = "Remcos"

    strings:
        $s1 = "Remcos"                             nocase
        $s2 = "Breaking-Security.net"              nocase
        $s3 = "remcos.exe"                         nocase
        $s4 = "Get-RemcosClientInfo"               nocase
        $s5 = "Remcos_Mutex_Inj"                   nocase

    condition:
        2 of them
}


rule RAT_QuasarRAT
{
    meta:
        author      = "AI-DTCTM"
        description = "Quasar RAT — open-source .NET RAT, also used by APT33"
        severity    = "critical"
        category    = "rat"
        family      = "Quasar"

    strings:
        $s1 = "Quasar"                             nocase
        $s2 = "QuasarRAT"                          nocase
        $s3 = "client.exe"                         nocase
        $s4 = "GetReversePort"                     nocase
        $s5 = "DoMouseClick"                       nocase

    condition:
        2 of them
}


rule RAT_NanoCore
{
    meta:
        author      = "AI-DTCTM"
        description = "NanoCore RAT — long-lived commodity RAT (CVE-2020-0688 / NanoCore.K)"
        severity    = "critical"
        category    = "rat"
        family      = "NanoCore"

    strings:
        $s1 = "NanoCore"                           nocase
        $s2 = "NanoCore.ClientPlugin"              nocase
        $s3 = "ClientPlugin.dll"                   nocase
        $s4 = "PluginCommand"                      nocase
        $s5 = "KeepAlive"                          nocase

    condition:
        2 of them
}


rule RAT_DarkCommet
{
    meta:
        author      = "AI-DTCTM"
        description = "DarkComet — classic RAT, still appears in opportunistic campaigns"
        severity    = "critical"
        category    = "rat"
        family      = "DarkComet"

    strings:
        $s1 = "DarkComet"                          nocase
        $s2 = "DC_MUTEX-"                          nocase
        $s3 = "#KCMDDC"                            nocase
        $s4 = "FastMM Borland Edition"             nocase

    condition:
        2 of them
}


rule RAT_VenomRAT
{
    meta:
        author      = "AI-DTCTM"
        description = "VenomRAT / WarzoneRAT — modern RAT-as-a-service"
        severity    = "critical"
        category    = "rat"
        family      = "VenomRAT"

    strings:
        $s1 = "VenomRAT"                           nocase
        $s2 = "Warzone"                            nocase
        $s3 = "RemoteShell"                        nocase
        $s4 = "PowerShellRAT"                      nocase
        $s5 = "ReverseProxy"                       nocase

    condition:
        2 of them
}


rule RAT_PlugX
{
    meta:
        author      = "AI-DTCTM"
        description = "PlugX — APT favourite RAT, used by Chinese groups"
        severity    = "critical"
        category    = "rat"
        family      = "PlugX"

    strings:
        $s1 = "PlugX"                              nocase
        $s2 = "Korplug"                            nocase
        $s3 = "XPLUG"                              nocase
        $s4 = "RC4_KEY"                            nocase

    condition:
        any of them
}
