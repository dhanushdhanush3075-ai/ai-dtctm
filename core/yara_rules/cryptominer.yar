/*
   AI-DTCTM | Cryptominer / Cryptojacking Detection Rules
   ═══════════════════════════════════════════════════════════════
   Cryptojacking = unauthorised use of system resources to mine
   cryptocurrency. Often deployed as part of a server compromise
   or supply-chain attack.
*/

rule Cryptominer_XMRig
{
    meta:
        author      = "AI-DTCTM"
        description = "XMRig Monero CPU miner — the dominant Linux/Windows cryptojacker"
        severity    = "critical"
        category    = "cryptominer"
        family      = "XMRig"

    strings:
        $s1 = "xmrig"                       nocase
        $s2 = "--donate-level"              nocase
        $s3 = "--cpu-priority"              nocase
        $s4 = "stratum+tcp://"              nocase
        $s5 = "randomx"                     nocase
        $s6 = "rx/0"                        nocase

    condition:
        2 of them
}


rule Cryptominer_Browser_JS
{
    meta:
        author      = "AI-DTCTM"
        description = "In-browser JavaScript cryptominer (Coinhive, CryptoLoot variants)"
        severity    = "high"
        category    = "cryptominer"

    strings:
        $s1 = "coinhive"                    nocase
        $s2 = "cryptoloot"                  nocase
        $s3 = "webminerpool"                nocase
        $s4 = "deepminer"                   nocase
        $s5 = "CoinHive.Anonymous"          nocase
        $s6 = "coin-have"                   nocase
        $s7 = "throttle"                    nocase
        $s8 = "minerScript"                 nocase

    condition:
        any of ($s1, $s2, $s3, $s4, $s5, $s6) or (2 of ($s7, $s8))
}


rule Cryptominer_Pool_URL
{
    meta:
        author      = "AI-DTCTM"
        description = "Reference to public mining pool — cryptojacking indicator"
        severity    = "high"
        category    = "cryptominer"

    strings:
        $p1 = "nicehash.com"                nocase
        $p2 = "ethermine.org"               nocase
        $p3 = "f2pool.com"                  nocase
        $p4 = "2miners.com"                 nocase
        $p5 = "hiveos.farm"                 nocase
        $p6 = "supportxmr.com"              nocase
        $p7 = "minexmr.com"                 nocase
        $p8 = "moneroocean.stream"          nocase

    condition:
        any of them
}


rule Cryptominer_Monero_Wallet
{
    meta:
        author      = "AI-DTCTM"
        description = "Hardcoded Monero wallet address (4… or 8… prefix)"
        severity    = "critical"
        category    = "cryptominer"

    strings:
        // 95-char Monero standard address — starts with 4
        $w = /4[0-9AB][0-9A-Za-z]{93}/

    condition:
        $w
}


rule Cryptominer_Lemon_Duck
{
    meta:
        author      = "AI-DTCTM"
        description = "Lemon Duck botnet — fileless cryptominer with worm capabilities"
        severity    = "critical"
        category    = "cryptominer"
        family      = "LemonDuck"

    strings:
        $s1 = "lemon_duck"                  nocase
        $s2 = "if-modified-since"           nocase
        $s3 = "iplogger"                    nocase
        $s4 = "Get-WmiObject -Class Win32"  nocase
        $s5 = "[Reflection.Assembly]::Load" nocase

    condition:
        ($s1) or (3 of ($s2, $s3, $s4, $s5))
}
