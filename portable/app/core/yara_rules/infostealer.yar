/*
   AI-DTCTM | Infostealer Detection Rules
   ═══════════════════════════════════════════════════════════════
   Infostealers grab browser-saved credentials, crypto wallets,
   session tokens, and ship them to an attacker-controlled server.
   2023–24 commodity threat: RedLine, Vidar, Raccoon, Lumma, Vidar.
*/

rule Infostealer_RedLine
{
    meta:
        author      = "AI-DTCTM"
        description = "RedLine Stealer — most prolific commodity stealer 2022–24"
        severity    = "critical"
        category    = "infostealer"
        family      = "RedLine"

    strings:
        $s1 = "RedLine"                            nocase
        $s2 = "ScannedWallets"                     nocase
        $s3 = "GetScannedFiles"                    nocase
        $s4 = "TelegramDesktop"                    nocase
        $s5 = "Discord_Tokens"                     nocase
        $s6 = "ZipBrowsers"                        nocase
        $s7 = "ScannedBrowser"                     nocase
        $s8 = "Login_Data"                         nocase

    condition:
        3 of them
}


rule Infostealer_Vidar
{
    meta:
        author      = "AI-DTCTM"
        description = "Vidar Stealer — forked from Arkei, sold as MaaS"
        severity    = "critical"
        category    = "infostealer"
        family      = "Vidar"

    strings:
        $s1 = "Vidar"                              nocase
        $s2 = "Files\\"                            nocase
        $s3 = "outlook.dat"                        nocase
        $s4 = "passwords.txt"                      nocase
        $s5 = "telegram.dat"                       nocase
        $s6 = "system.txt"                         nocase
        $s7 = "screenshot.jpg"                     nocase

    condition:
        4 of them
}


rule Infostealer_Lumma
{
    meta:
        author      = "AI-DTCTM"
        description = "Lumma Stealer (LummaC2) — successor to Mars/Aurora"
        severity    = "critical"
        category    = "infostealer"
        family      = "LummaC2"

    strings:
        $s1 = "Lumma"                              nocase
        $s2 = "LummaC2"                            nocase
        $s3 = "/c2sock"                            nocase
        $s4 = "/api/upload"                        nocase
        $s5 = "act=getconfig"                      nocase

    condition:
        2 of them
}


rule Infostealer_Browser_Cred_Targeting
{
    meta:
        author      = "AI-DTCTM"
        description = "Browser credential-store file targeting (generic)"
        severity    = "high"
        category    = "infostealer"

    strings:
        $s1 = "Login Data"                         nocase
        $s2 = "Cookies"                            nocase
        $s3 = "Web Data"                           nocase
        $s4 = "Local State"                        nocase
        $s5 = "key3.db"                            nocase
        $s6 = "key4.db"                            nocase
        $s7 = "logins.json"                        nocase
        $s8 = "formhistory.sqlite"                 nocase

    condition:
        3 of them
}


rule Infostealer_Crypto_Wallet_Targeting
{
    meta:
        author      = "AI-DTCTM"
        description = "Targeting desktop crypto wallets (Exodus, MetaMask, Electrum)"
        severity    = "high"
        category    = "infostealer"

    strings:
        $w1 = "Exodus\\exodus.wallet"              nocase
        $w2 = "Electrum\\wallets"                  nocase
        $w3 = "Ethereum\\keystore"                 nocase
        $w4 = "Atomic\\Local Storage"              nocase
        $w5 = "Coinomi\\Coinomi\\wallets"          nocase
        $w6 = "Bitcoin\\wallet.dat"                nocase
        $w7 = "MetaMask"                           nocase
        $w8 = "Trust Wallet"                       nocase

    condition:
        2 of them
}


rule Infostealer_Discord_Token_Grab
{
    meta:
        author      = "AI-DTCTM"
        description = "Discord token theft (Local Storage / leveldb)"
        severity    = "high"
        category    = "infostealer"

    strings:
        $s1 = "discord\\Local Storage\\leveldb"    nocase
        $s2 = "discordcanary\\Local Storage"       nocase
        $s3 = "discordptb\\Local Storage"          nocase
        $s4 = "mfa\\."                             nocase
        $s5 = "dQw4w9WgXcQ"                        nocase  // discord token salt
        $s6 = "discord_token"                      nocase

    condition:
        2 of them
}
