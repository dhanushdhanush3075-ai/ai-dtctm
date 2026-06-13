/*
   AI-DTCTM | Ransomware Detection Rules
   ═══════════════════════════════════════════════════════════════
   Patterns seen across real ransomware families. Defensive only —
   rules detect, they don't produce.
*/

rule Ransomware_Generic_Ransom_Note
{
    meta:
        author      = "AI-DTCTM"
        description = "Common ransom note phrases"
        severity    = "critical"
        category    = "ransomware"

    strings:
        $p1 = "Your files have been encrypted"       nocase
        $p2 = "pay the ransom"                       nocase
        $p3 = "Bitcoin"                              nocase
        $p4 = "decryption key"                       nocase
        $p5 = "contact us via"                       nocase
        $p6 = ".onion"                               nocase
        $p7 = "do not rename encrypted files"        nocase
        $p8 = "YOUR ID:"                             nocase
        $p9 = "Tor Browser"                          nocase

    condition:
        3 of them
}


rule Ransomware_File_Encryption_APIs
{
    meta:
        author      = "AI-DTCTM"
        description = "Windows CryptoAPI + file walking = likely encryptor"
        severity    = "critical"
        category    = "ransomware"

    strings:
        $c1 = "CryptGenKey"       ascii wide
        $c2 = "CryptEncrypt"      ascii wide
        $c3 = "CryptAcquireContext" ascii wide
        $f1 = "FindFirstFileW"    ascii wide
        $f2 = "FindNextFileW"     ascii wide
        $d1 = "DeleteFileW"       ascii wide
        $s1 = "vssadmin delete shadows" nocase
        $s2 = "wmic shadowcopy delete"  nocase

    condition:
        2 of ($c*) and 2 of ($f*) and any of ($s*)
}


rule Ransomware_LockBit_Indicators
{
    meta:
        author      = "AI-DTCTM"
        description = "LockBit ransomware family markers"
        severity    = "critical"
        category    = "ransomware"
        family      = "LockBit"

    strings:
        $s1 = "LockBit" nocase
        $s2 = ".lockbit" nocase
        $s3 = "Restore-My-Files.txt" nocase
        $s4 = "HLJkNskOq" ascii  // known LockBit string

    condition:
        any of them
}


rule Ransomware_Common_Extensions
{
    meta:
        author      = "AI-DTCTM"
        description = "File extensions added by known ransomware"
        severity    = "high"
        category    = "ransomware"

    strings:
        $e1 = ".locked"    nocase
        $e2 = ".encrypted" nocase
        $e3 = ".crypt"     nocase
        $e4 = ".wncry"     nocase
        $e5 = ".ryuk"      nocase
        $e6 = ".conti"     nocase
        $e7 = ".revil"     nocase
        $e8 = ".babuk"     nocase

    condition:
        2 of them
}
