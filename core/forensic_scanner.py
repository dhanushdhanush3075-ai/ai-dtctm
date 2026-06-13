"""
AI-DTCTM | Forensic File Scanner (v21 — Day 3)
══════════════════════════════════════════════════════════════════════
5-layer malware detection for user-uploaded files:
  [1] YARA rules (signature matching)
  [2] Heuristic regex (50+ suspicious patterns)
  [3] Hash reputation (MalwareBazaar lookup)
  [4] Static code analysis (SQLi / XSS / RCE patterns)
  [5] Entropy analysis (packed/encrypted payload detection)

Each finding includes:
  - severity (LOW / MEDIUM / HIGH / CRITICAL)
  - evidence (line number, code snippet)
  - fix suggestion (actionable remediation)
  - OWASP/MITRE reference

USAGE:
  from core.forensic_scanner import scan_file, scan_archive
  result = scan_file("/path/to/suspicious.php")
  # → {"findings": [...], "severity": "HIGH", "stats": {...}}
"""
from __future__ import annotations

import hashlib
import math
import os
import re
import tempfile
import zipfile
import tarfile
from dataclasses import dataclass, asdict
from pathlib import Path

from core.logger import get_logger

log = get_logger(__name__)


# ── Suspicious patterns registry ──────────────────────────────────
# Each tuple: (regex, severity, category, description, fix_suggestion)

PHP_PATTERNS = [
    (r"eval\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)",
     "CRITICAL", "Remote Code Execution",
     "eval() with user input — direct RCE vector",
     "NEVER eval() user input. Use json_decode() or a whitelist-based dispatcher."),
    (r"eval\s*\(\s*base64_decode",
     "CRITICAL", "Obfuscated Backdoor",
     "eval(base64_decode(...)) is a classic backdoor signature",
     "This is malicious code disguised. Remove immediately + audit server for compromise."),
    (r"eval\s*\(\s*gzinflate\s*\(\s*base64_decode",
     "CRITICAL", "Obfuscated Backdoor",
     "Triple-layer obfuscation — almost certainly malware",
     "Remove file. Run full server malware sweep. Rotate all credentials."),
    (r"\b(?:passthru|shell_exec|system|exec|popen|proc_open)\s*\(\s*\$_",
     "CRITICAL", "Remote Code Execution",
     "Shell command with user-controlled input",
     "Never pass user input to shell. Use escapeshellarg() or avoid shell entirely."),
    (r"\$_REQUEST\s*\[.+?\]\s*\(",
     "HIGH", "Dynamic Function Invocation",
     "Calling user-specified function — potential RCE",
     "Use whitelist of allowed function names."),
    (r"file_get_contents\s*\(\s*['\"]php://input['\"]",
     "HIGH", "Arbitrary Input Read",
     "Reads raw POST body — common in webshell uploaders",
     "Validate source of input. Authenticate users before accepting data."),
    (r"\bassert\s*\(\s*\$_",
     "CRITICAL", "Assert-based Backdoor",
     "assert() with user input executes as PHP — backdoor pattern",
     "Disable assert() in PHP.ini: zend.assertions=-1. Audit file origin."),
    (r"create_function\s*\(",
     "HIGH", "Deprecated Code Injection",
     "create_function() is eval() in disguise",
     "Replace with standard function definitions or closures."),
    (r"preg_replace\s*\([^)]*?/e['\"]",
     "CRITICAL", "PCRE /e Modifier RCE",
     "Deprecated /e modifier executes replacement — RCE",
     "Use preg_replace_callback() instead."),
    (r"['\"]\\\\x[0-9a-fA-F]{2}['\"]",
     "MEDIUM", "Hex-Encoded String",
     "Hex-encoded characters — possible obfuscation",
     "Review context. Legitimate uses rare in web apps."),
    (r"\b(FTP|SMB|LDAP)_URL\b|\bldap_bind\b",
     "LOW", "External Service Reference",
     "Code connects to LDAP/FTP — verify credentials not hardcoded",
     "Move credentials to environment variables."),
]

# JavaScript patterns
JS_PATTERNS = [
    (r"eval\s*\(\s*atob\s*\(",
     "HIGH", "Obfuscated JS",
     "eval(atob(...)) — base64-encoded JS execution, often malware",
     "Review decoded content. Legitimate use is extremely rare."),
    (r"document\.write\s*\(\s*unescape",
     "HIGH", "Legacy Obfuscation",
     "document.write(unescape()) pattern from 2010s-era JS malware",
     "Never use. Replace with safe DOM APIs like textContent."),
    (r"String\.fromCharCode\s*\((?:\s*\d+\s*,){10,}",
     "MEDIUM", "Obfuscated Strings",
     "Long fromCharCode sequence — hiding suspicious strings",
     "Review decoded output. Minifiers don't produce this."),
    (r"\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}",
     "MEDIUM", "Hex-Encoded JS",
     "Hex-escape-heavy code — typical obfuscation",
     "Review purpose."),
    (r"new Function\s*\(",
     "MEDIUM", "Dynamic Function Creation",
     "new Function() is runtime code compilation — review caller",
     "Prefer static function definitions when possible."),
    (r"crypto\.subtle\.digest.*location\.(?:href|host)",
     "HIGH", "Crypto Hashing of Location",
     "Hashing URL before exfil — common beacon pattern",
     "Investigate. Legitimate analytics use first-party libraries."),
]

# Generic patterns applicable to any language
# Python-specific malware patterns
# Windows/PowerShell malware patterns
POWERSHELL_PATTERNS = [
    (r"(?i)(IEX|Invoke-Expression).*(?:\$_|concat|join)",
     "CRITICAL", "PowerShell Code Execution",
     "IEX (Invoke-Expression) with dynamic code — typical malware pattern",
     "Block PowerShell if possible. Full system scan. Incident response."),
    (r"(?i)Start-Process.*(?:-WindowStyle|Hidden|-NoProfile)",
     "HIGH", "Hidden PowerShell Process",
     "Starting process with hidden window — evasion technique",
     "Investigate process. Check for persistence. Full scan."),
    (r"(?i)New-Object.*(?:Net\.WebClient|Net\.ServicePointManager)",
     "HIGH", "Remote Code Download",
     "Web download capability — potential malware staging",
     "Block URL. Check downloads. Investigate for secondary payload."),
    (r"(?i)(Get-Childitem|dir).*(?:Hidden|Force).*(?:System32|AppData)",
     "MEDIUM", "Hidden File Enumeration",
     "Enumerating system/appdata directories — reconnaissance",
     "Investigate. May indicate system compromise being explored."),
    (r"(?i)(Disable-MpPreference|Remove-MpPreference|Set-MpPreference).*(?:Disable|Add)",
     "CRITICAL", "Windows Defender Disabling",
     "Disabling Windows Defender — evasion of antimalware",
     "Re-enable immediately. Full malware scan. Check for other malware."),
    (r"(?i)Set-ItemProperty.*(?:HKLM|HKCU).*(?:Run|RunOnce)",
     "HIGH", "Registry Persistence",
     "Creating registry run key — persistence mechanism",
     "Remove registry entry. Full scan. Restart system."),
]

PYTHON_PATTERNS = [
    (r"(?i)(pynput|keyboard|mouse|listener).*(?:on_press|on_release)",
     "CRITICAL", "Keylogger (pynput)",
     "pynput library used for keystroke logging",
     "Remove immediately. Rotate credentials. Check compromise."),
    (r"(?i)(import|from).*(?:pynput|keyboard|mouse|pyautogui)",
     "CRITICAL", "Input Monitoring Library",
     "Importing libraries for keyboard/mouse monitoring — spyware",
     "Remove file. Full system malware scan. Credential rotation."),
    (r"(?i)subprocess\.(?:Popen|run|call).*(?:shell=True|shell\s*=\s*1)",
     "HIGH", "Subprocess with Shell=True",
     "subprocess with shell=True — command injection risk",
     "Use shell=False with list of arguments instead."),
    (r"(?i)(socket|requests).*(?:https?|ftp).*(?:post|get|send)",
     "HIGH", "Network Communication",
     "Network communication capability — potential C2 or exfiltration",
     "Inspect traffic. Investigate destination. Check for beaconing."),
    # Exfil signal = sending CREDENTIALS over HTTP, or POSTing to a raw IP.
    # (Plain requests.get(url) is normal app behaviour — must not flag it.)
    (r"(?i)(?:requests|urllib|httpx|aiohttp)\.(?:post|put|patch)\s*\([^)]{0,160}(?:password|passwd|token|secret|credential|cookie|api[_-]?key|session)",
     "HIGH", "Credentials Sent Over HTTP",
     "POSTing credentials/secrets to a remote endpoint — possible exfiltration",
     "Check destination. Investigate payload. Full malware analysis."),
    (r"(?i)(base64|hashlib|Crypto|cryptography).*(?:decode|encrypt|hash)",
     "MEDIUM", "Cryptographic Operations",
     "Encryption/hashing used — possible credential protection or payload obfuscation",
     "Investigate purpose in context. Check for credential hiding."),
    (r"(?i)\b(__import__|importlib|exec|eval)\b\s*\(",
     "HIGH", "Dynamic Code Execution",
     "__import__/importlib/exec/eval — dynamic code loading",
     "Review loaded modules. Verify source of imported code."),
    (r"(?i)(os\.system|os\.popen|commands\.getoutput).*(?:cmd|command)",
     "CRITICAL", "Direct OS Command Execution",
     "Direct system command execution without subprocess",
     "Sanitize all inputs. Use subprocess with shell=False instead."),
    (r"(?i)(pathlib|os\.path).*(?:home|\\~|appdata|temp)",
     "HIGH", "Accessing User Directories",
     "Accessing user home/temp — typical malware behavior",
     "Investigate file operations. Check for exfiltration targets."),
    (r"(?i)(PIL|Image).*(?:screenshot|screen|grab)",
     "HIGH", "Screenshot Capability",
     "PIL/Pillow used for screenshot — spyware behavior",
     "Remove. Investigate for active surveillance. Full scan."),
]

GENERIC_PATTERNS = [
    (r"(?i)(api[_-]?key|secret[_-]?key|access[_-]?token|password)\s*[:=]\s*['\"][A-Za-z0-9+/=]{20,}['\"]",
     "HIGH", "Hardcoded Credentials",
     "Secret literal found in source",
     "Move to environment variable: os.environ['SECRET']. Rotate exposed secret."),
    (r"AKIA[0-9A-Z]{16}",
     "CRITICAL", "AWS Access Key",
     "AWS access key literal — immediate compromise risk",
     "Revoke key in AWS console NOW. Rotate. Audit CloudTrail for misuse."),
    (r"AIza[0-9A-Za-z\-_]{35}",
     "HIGH", "Google API Key",
     "Google API key in source",
     "Regenerate in Google Cloud Console. Restrict by HTTP referrer."),
    (r"sk-[a-zA-Z0-9]{48}",
     "CRITICAL", "OpenAI API Key",
     "OpenAI secret key in source",
     "Revoke at platform.openai.com/api-keys. Rotate + audit usage."),
    (r"(?i)-----BEGIN\s+(RSA\s+)?PRIVATE KEY-----",
     "CRITICAL", "Private Key",
     "Private key embedded in source",
     "This key is compromised. Generate new key + rotate all places using it."),
    (r"(?i)mongodb(?:\+srv)?://[^\s\"']+:[^\s\"']+@",
     "CRITICAL", "MongoDB Connection String",
     "MongoDB URI with credentials literal",
     "Move to env var. Rotate DB password."),
    (r"(?i)postgres://[^\s\"']+:[^\s\"']+@",
     "CRITICAL", "Postgres Connection String",
     "Postgres URI with credentials",
     "Move to env var. Rotate DB password."),
    (r"(?i)mysql://[^\s\"']+:[^\s\"']+@",
     "CRITICAL", "MySQL Connection String",
     "MySQL URI with credentials",
     "Move to env var. Rotate DB password."),
    (r"https?://[^\s<>\"']*(?:evil|malware|phish|backdoor|ransom|miner)[^\s<>\"']*",
     "HIGH", "Known-Bad URL Hint",
     "URL contains malware-related keyword",
     "Investigate URL reputation via VirusTotal."),
]

# SQL injection heuristics (for static code analysis)
SQLI_PATTERNS = [
    (r"(?:query|execute)\s*\(\s*['\"].*?\$_(GET|POST|REQUEST|COOKIE).*?['\"]",
     "HIGH", "SQL Injection",
     "SQL query built with string concatenation of user input",
     "Use prepared statements with parameterised queries."),
    (r"mysqli_query\s*\(\s*\$[a-z_]+,\s*['\"].*?\..*?\.",
     "HIGH", "SQL Injection",
     "mysqli_query with concatenated string",
     "Use mysqli_prepare() + mysqli_stmt_bind_param()."),
    (r"\bf\"[^\"]*SELECT.*?\{.*?\}.*?\"",
     "HIGH", "SQL Injection (Python f-string)",
     "f-string with interpolated variable in SQL query",
     "Use cursor.execute(sql, params) with placeholders."),
    (r"\.execute\s*\(\s*['\"].*?%s.*?['\"]\s*%\s*\(",
     "MEDIUM", "SQL Format String",
     "Python %-formatting in SQL query",
     "Use cursor.execute(sql, params) tuple instead of %."),
]

# XSS heuristics
XSS_PATTERNS = [
    (r"echo\s+\$_(GET|POST|REQUEST|COOKIE)(?!.*htmlspecialchars)",
     "HIGH", "Reflected XSS",
     "PHP echoes user input without htmlspecialchars()",
     "Wrap output in htmlspecialchars(\\$input, ENT_QUOTES, 'UTF-8')."),
    (r"\.innerHTML\s*=\s*[^;]*(?:req|\\$\\{|\\+)",
     "MEDIUM", "DOM-based XSS",
     "innerHTML assigned dynamic content",
     "Use .textContent for text, or sanitize with DOMPurify."),
    (r"v-html\s*=\s*['\"][^'\"]+['\"]",
     "MEDIUM", "Vue.js v-html",
     "v-html renders raw HTML — XSS risk if data untrusted",
     "Use v-text or pre-sanitize with DOMPurify."),
    (r"dangerouslySetInnerHTML",
     "MEDIUM", "React dangerouslySetInnerHTML",
     "Explicit unsafe HTML rendering",
     "Verify content is sanitised with DOMPurify first."),
]

# ════════════════════════════════════════════════════════════════════
# ENHANCED: RANSOMWARE, TROJAN, WORM, BACKDOOR PATTERNS (NEW)
# ════════════════════════════════════════════════════════════════════

# Ransomware signatures
RANSOMWARE_PATTERNS = [
    (r"(?i)(encrypt|cipher|crypto).*(?:file|drive|volume|data)",
     "CRITICAL", "Ransomware Signature",
     "Encryption routine targeting files/volumes — ransomware behavior",
     "Quarantine immediately. Restore from backup. Do NOT pay ransom."),
    (r"(?i)(bitcoin|ethereum|wallet|payment).{0,50}(?:contact|email|ransom)",
     "CRITICAL", "Ransom Demand Pattern",
     "Cryptocurrency payment demand — active ransomware",
     "Report to FBI IC3. Do not pay. Restore from backup."),
    (r"(?i)(delete|remove|wipe).*(?:shadow|copy|backup|recovery)",
     "CRITICAL", "Backup Destruction",
     "Deleting shadow copies/backups — classic ransomware behavior",
     "System is likely infected. Isolate network. Full malware scan."),
    (r"(?i)vssadmin.*delete.*shadow",
     "CRITICAL", "VSS Shadow Copy Deletion",
     "vssadmin shadow copy deletion — ransomware destructive behavior",
     "Ransomware confirmed. Isolate network immediately."),
    (r"(?i)wmic.*logicaldisk.*delete",
     "CRITICAL", "WMIC Disk Destruction",
     "WMI logical disk deletion — ransomware attack pattern",
     "System compromised. Full rebuild recommended."),
    (r"(?i)cipher\.exe.*/w",
     "CRITICAL", "Cipher Disk Wiping",
     "cipher.exe wiping disk content — ransomware evasion",
     "Ransomware present. Disconnect from network. Full clean required."),
]

# Trojan/RAT (Remote Access Trojan) patterns
TROJAN_PATTERNS = [
    (r"(?i)(reverse.*shell|exec.*cmd|bind.*port|shell.*reverse)",
     "CRITICAL", "Reverse Shell Trojan",
     "Reverse shell code — remote command execution capability",
     "Immediate isolation. Full system malware scan. Credential rotation."),
    (r"(?i)(spawn|system|fork).*(?:/bin/sh|/bin/bash|cmd\.exe|powershell)",
     "CRITICAL", "Arbitrary Command Execution",
     "Spawning shell process — RCE trojan pattern",
     "Quarantine file. Isolate system. Full incident response."),
    # Python/sh reverse shell: spawning /bin/sh via subprocess/os.system
    (r"(?i)(?:subprocess\.(?:call|Popen|run)|os\.system|os\.execve?)\s*\(\s*\[?\s*['\"]/bin/(?:sh|bash)",
     "CRITICAL", "Reverse Shell (shell spawn)",
     "Spawning /bin/sh — reverse/bind shell payload",
     "Immediate isolation. Full system malware scan. Credential rotation."),
    # Socket fd duplicated onto stdio — the defining reverse-shell move
    (r"(?i)os\.dup2\s*\([^)]*fileno\s*\(",
     "CRITICAL", "Reverse Shell (fd redirection)",
     "Redirecting a socket onto stdin/stdout — reverse shell",
     "Immediate isolation. Full system malware scan. Credential rotation."),
    (r"(?i)(socket|connect).{0,100}(?:recv|send).*(?:command|exec)",
     "HIGH", "Network Command Channel",
     "Network socket for command reception — C2 trojan pattern",
     "Investigate network traffic. Isolate. Full malware analysis."),
    (r"(?i)keylog|screenshot|capture.{0,50}(?:key|screen|webcam)",
     "CRITICAL", "Spyware/Keylogger",
     "Screen capture or keystroke logging capability",
     "Remove immediately. Audit compromised credentials. Full scan."),
    (r"(?i)(persistence|startup|registry).*(?:run|startup|autostart)",
     "HIGH", "System Persistence Trojan",
     "Installing rootkit/persistence mechanism",
     "Requires full system restoration. Malware removal not reliable."),
]

# Worm/Mass propagation patterns
WORM_PATTERNS = [
    (r"(?i)(spread|propagate|replicate|copy.*self).{0,50}(?:email|network|share|usb)",
     "CRITICAL", "Worm Self-Propagation",
     "Self-replicating malware — network worm behavior",
     "Isolate network. Quarantine all systems. Full incident response."),
    (r"(?i)(email|send.*mail|smtp).{0,100}(?:subject|body|attachment)",
     "HIGH", "Email Worm",
     "Email transmission capability — mass propagation vector",
     "Isolate from network. Review email logs for spread."),
    (r"(?i)(usb|removable|flash|drive).*(?:copy|replicate|propagate)",
     "HIGH", "USB/Removable Media Worm",
     "USB-based propagation — worm capability",
     "Scan all USB devices. Update all systems."),
    (r"(?i)(share|smb|network.*drive).*(?:copy|replicate|modify)",
     "HIGH", "Network Share Worm",
     "Network share exploitation — lateral movement worm",
     "Isolate network. Scan all connected systems."),
]

# Backdoor patterns
BACKDOOR_PATTERNS = [
    (r"(?i)(backdoor|rootkit|stealth|hide).*(?:process|thread|module)",
     "CRITICAL", "Rootkit/Backdoor Installation",
     "Kernel-level backdoor or rootkit — deepest system compromise",
     "System likely unrecoverable. Full reinstall required."),
    (r"(?i)(listen|port|socket).*(?:accept|connect).*(?:fork|exec)",
     "CRITICAL", "Listening Backdoor",
     "Listening for incoming connections — remote backdoor access",
     "Immediate isolation. Network intrusion investigation. Full scan."),
    (r"(?i)(credential|password|hash).*(?:grab|steal|exfil|send)",
     "CRITICAL", "Credential Stealer",
     "Stealing credentials for lateral movement or exfiltration",
     "Rotate all credentials. Audit account usage. Full system scan."),
    # Precise botnet/DDoS terms only — bare "bot"/"dos" matched inside normal
    # words (robot, chatbot, windows…) and produced false positives on clean apps.
    (r"(?i)\b(ddos|botnet|c2[\s_-]?(?:server|channel|node)|command[\s_-]and[\s_-]control|irc[\s_-]?bot|stratum\+tcp|slowloris|syn[\s_-]?flood|udp[\s_-]?flood)\b",
     "CRITICAL", "Botnet/DDoS Agent",
     "System compromised as botnet node — resource abuse",
     "Isolate immediately. Notify ISP. Full malware removal."),
]

# Data exfiltration patterns
EXFIL_PATTERNS = [
    (r"(?i)(exfil|steal|extract|compress|encrypt).{0,50}(?:data|file|credential|password|api)",
     "CRITICAL", "Data Exfiltration",
     "Extracting sensitive data — data theft malware",
     "Breach investigation required. Notify users of data exposure."),
    (r"(?i)(https?|ftp|ssh).*(?:send|post|upload).*(?:data|file)",
     "HIGH", "Remote Data Upload",
     "Uploading data to external server — exfiltration vector",
     "Block URL. Investigate C2 infrastructure. Check for breach."),
    (r"(?i)(zip|tar|rar|compress).*(?:data|file|credential)",
     "HIGH", "Data Compression Before Exfil",
     "Compressing data before transmission — exfil preparation",
     "Investigate. Check network traffic for unusual uploads."),
]

# Lateral movement patterns
LATERAL_MOVEMENT_PATTERNS = [
    (r"(?i)(wmi|winrm|psremoting|ssh|rsh).*(?:execute|invoke|command)",
     "HIGH", "Remote Execution for Lateral Movement",
     "Remote execution on other systems — lateral movement capability",
     "Isolate network. Investigate compromised accounts. Credential rotation."),
    # Precise lateral-movement terms — bare "pass" matched inside password/bypass/compass.
    (r"(?i)\b(pass-the-hash|pass-the-ticket|overpass-the-hash|(?:credential|token|kerberos|unconstrained)\s+delegation)\b",
     "HIGH", "Credential Forwarding",
     "Passing credentials to other systems — lateral movement",
     "Full credential audit. Rotate all credentials. Investigate access."),
    (r"(?i)(exploit|vulnerability).{0,50}(?:cve|cvsn|ms[0-9]{2}-[0-9]{3})",
     "HIGH", "Exploit Code (Known CVE)",
     "Exploitation of known vulnerability — targeted lateral movement",
     "Patch vulnerable system immediately. Investigate prior access."),
]

# Privilege escalation patterns
PRIVILEGE_ESCALATION_PATTERNS = [
    (r"(?i)(uac|bypass|elevate|escalate).*(?:privilege|admin|root|system)",
     "CRITICAL", "Privilege Escalation",
     "Bypassing access controls — elevation to admin/root",
     "Full system compromise. Complete rebuild recommended."),
    (r"(?i)(token|impersonate|setuid|setgid).*(?:process|thread)",
     "HIGH", "Token Stealing/Impersonation",
     "Process token manipulation — privilege elevation",
     "Investigate privileged process. Full malware scan. Restart system."),
    (r"(?i)(sudo|sudoedit|visudo).*(?:nopass|bypass|edit)",
     "HIGH", "Sudo Bypass/Manipulation",
     "Sudo misconfiguration exploitation or bypass",
     "Restore sudoers file. Restrict sudo access. Audit usage."),
]

# ════════════════════════════════════════════════════════════════════
# EXPANDED THREAT PATTERN DATABASE — added in v24 for forensic accuracy
# Categories: CRYPTOMINER · INFOSTEALER · ROOTKIT · FILELESS · LOLBIN
#             SSH_KEYS · SUPPLY_CHAIN · C2_FRAMEWORKS · MOBILE
#             AV_EVASION · WEB_SHELL · DROPPER · CREDENTIAL_THEFT · MISC
# Each new category contributes 15–40 patterns for fine-grained detection.
# ════════════════════════════════════════════════════════════════════

# ── Cryptominer / cryptojacking ──
CRYPTOMINER_PATTERNS = [
    (r"(?i)\b(xmrig|cpuminer|cgminer|bfgminer|ethminer|nbminer|t-rex(?:miner)?|lolminer|nicehash)\b",
     "CRITICAL", "Cryptominer Binary",
     "Known cryptocurrency miner binary referenced",
     "Quarantine. Block hash. Audit CPU usage history."),
    (r"(?i)\bstratum\+tcp://",
     "CRITICAL", "Mining Pool Stratum URL",
     "Stratum mining-pool URL — cryptojacking C2",
     "Block pool domain. Kill miner process. Investigate entry vector."),
    (r"(?i)(coinhive|cryptoloot|jsecoin|deepminer|webminerpool|coin-?have)",
     "HIGH", "Browser Cryptominer",
     "In-browser JavaScript cryptominer library",
     "Remove script. Block domain. Notify users."),
    (r"(?i)--donate-level\s*=?\s*\d|--max-cpu-usage|--cpu-priority",
     "HIGH", "XMRig CLI Flag",
     "XMRig command-line flag — confirmed Monero miner config",
     "Kill process. Inspect autorun + crontab + systemd."),
    (r"(?i)monero|xmr\.|randomx|kawpow|ethash|equihash",
     "HIGH", "Mining Algorithm Reference",
     "Cryptocurrency mining algorithm string",
     "Investigate context. Likely cryptojacking if combined with high CPU."),
    (r"(?i)nicehash\.com|f2pool\.com|hiveos|minerstat|ethermine\.org|2miners\.com",
     "HIGH", "Mining Pool Domain",
     "Public cryptocurrency mining pool domain",
     "Block at firewall. Audit outbound connections."),
    (r"(?i)wallet[_\-\s]*(?:address|addr)\s*[:=]\s*['\"](?:4[0-9A-B][0-9A-Za-z]{93}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})",
     "CRITICAL", "Hardcoded Crypto Wallet",
     "Hardcoded Monero (4…) or Bitcoin (1.../3...) wallet address",
     "Remove. Investigate file source. Likely miner config."),
]

# ── Information stealers / RedLine / Vidar / Raccoon / Lumma ──
INFOSTEALER_PATTERNS = [
    (r"(?i)\b(redline|vidar|raccoon|lumma(?:c2)?|azorult|mars[\s_-]?stealer|aurora[\s_-]?stealer|rhadamanthys)\b",
     "CRITICAL", "Known Infostealer Family",
     "Named infostealer malware family reference",
     "Quarantine. Rotate ALL stored credentials. Full IR."),
    (r"(?i)login[\s_-]?data|cookies\.sqlite|key3\.db|key4\.db|signons\.sqlite|formhistory\.sqlite",
     "HIGH", "Browser Credential Store Access",
     "Reading Chrome/Firefox stored-credential files — infostealer",
     "Rotate all browser-saved passwords. EDR investigation."),
    (r"(?i)\\\\Local\\\\Google\\\\Chrome\\\\User Data|\\\\Microsoft\\\\Edge\\\\User Data|\\\\Mozilla\\\\Firefox\\\\Profiles",
     "HIGH", "Browser Profile Path",
     "Browser profile directory targeting — credential theft path",
     "Rotate creds. Investigate why file accesses these paths."),
    (r"(?i)(masterkey|os_crypt|encrypted_key|decrypt.*chrome|chrome.*decrypt)",
     "CRITICAL", "Chrome Master Key Decryption",
     "Chrome DPAPI master-key decryption — credential extraction",
     "Confirmed infostealer behaviour. Full IR."),
    (r"(?i)(discord|telegram|signal|whatsapp).*(?:token|session|local\s+storage)",
     "HIGH", "Messenger Token Theft",
     "Targeting Discord/Telegram/Signal session token",
     "Revoke sessions. Rotate auth. Investigate."),
    (r"(?i)(metamask|exodus|electrum|atomic|trust\s*wallet|coinbase|ledger\s*live)",
     "HIGH", "Crypto Wallet Targeting",
     "Targeting cryptocurrency desktop wallet",
     "Move funds to hardware wallet. Full credential rotation."),
    (r"(?i)Steam[\s\\/]config[\s\\/]loginusers\.vdf|ssfn[A-Fa-f0-9]+",
     "HIGH", "Steam Session Theft",
     "Steam session file targeting — account takeover",
     "Steam Guard reset. New phone code. Revoke sessions."),
    (r"(?i)(filezilla|winscp|putty).*(?:sitemanager|saved.*session|registry)",
     "HIGH", "SSH/FTP Credential Theft",
     "Extracting saved FTP/SSH credentials from popular clients",
     "Rotate ALL stored SSH/FTP keys + passwords."),
    (r"(?i)(grab|collect|harvest|dump).*(?:cookies|credentials|saved\s*logins|autofill)",
     "HIGH", "Generic Credential Harvest",
     "Credential harvesting routine",
     "Quarantine. Rotate credentials. Investigate scope."),
]

# ── Rootkit / kernel-mode ──
ROOTKIT_PATTERNS = [
    (r"(?i)(SSDT|IRP|MJ_CREATE|IoCreateDriver|ZwLoadDriver)",
     "CRITICAL", "Windows Kernel Driver API",
     "Direct Windows kernel driver / SSDT manipulation",
     "Kernel rootkit suspected. System unrecoverable — reinstall."),
    (r"(?i)(insmod|modprobe|init_module|kallsyms_lookup_name)\s*\(",
     "HIGH", "Linux Kernel Module Load",
     "Loading kernel module — possible LKM rootkit",
     "Audit /proc/modules. Check for hidden modules with rkhunter."),
    (r"(?i)(hook|hijack|patch).{0,30}(?:syscall|sysenter|sysret|sysenter_eip)",
     "CRITICAL", "Syscall Hooking",
     "Direct syscall table hijack — rootkit technique",
     "Kernel compromised. Reinstall OS from clean media."),
    (r"(?i)hidden\s+(?:process|file|directory|connection)",
     "HIGH", "Process/File Hiding Reference",
     "Hiding artefacts from system tools — rootkit/userland hider",
     "Run offline forensic boot disk. Compare hash of /bin tools."),
    (r"(?i)(LD_PRELOAD|/etc/ld\.so\.preload)",
     "HIGH", "ld.so.preload Hijack",
     "LD_PRELOAD library injection — classic Linux userland rootkit",
     "Check /etc/ld.so.preload, $LD_PRELOAD env. Remove unknown .so."),
    (r"(?i)(unhook|patch|nt(?:read|write)virtual).*(?:ntdll|kernel32|ntoskrnl)",
     "CRITICAL", "AV/EDR Unhooking",
     "Unhooking AV/EDR API hooks — defence evasion",
     "EDR was bypassed. Manual forensic acquisition required."),
]

# ── Fileless / living-off-the-land ──
FILELESS_PATTERNS = [
    (r"(?i)powershell(?:\.exe)?\s+[^\n]*-(?:e|enc|encodedcommand)\s+[A-Za-z0-9+/=]{40,}",
     "CRITICAL", "Encoded PowerShell Command",
     "Base64-encoded PowerShell — classic fileless attack",
     "Decode the base64 to identify payload. EDR alert + isolate host."),
    (r"(?i)powershell[^\n]*-(?:nop|noprofile|w\s+hidden|windowstyle\s+hidden|noni|noninteractive)",
     "HIGH", "Stealth PowerShell Flag",
     "PowerShell launched with stealth flags",
     "Investigate parent process + cmdline."),
    (r"(?i)(IEX|Invoke-Expression)\s*\(\s*(?:New-Object\s+Net\.WebClient|DownloadString|iwr|Invoke-WebRequest)",
     "CRITICAL", "PowerShell Download-and-Execute",
     "Classic PowerShell download cradle — fileless dropper",
     "Block URL at proxy. Isolate. Find initial access vector."),
    (r"(?i)\[Reflection\.Assembly\]::Load\s*\(",
     "CRITICAL", "In-Memory .NET Assembly Load",
     ".NET assembly loaded directly into memory — fileless execution",
     "Cobalt Strike or similar in-memory framework. Full IR."),
    (r"(?i)\[System\.Convert\]::FromBase64String\s*\(\s*['\"]?[A-Za-z0-9+/=]{200,}",
     "CRITICAL", "Large Base64 Blob Decoded",
     "Massive base64 string decoded in-memory — likely shellcode",
     "Capture memory. Decode and analyse payload."),
    (r"(?i)VirtualAlloc(?:Ex)?\s*\(.*PAGE_EXECUTE_READWRITE",
     "CRITICAL", "RWX Memory Allocation",
     "Allocating executable+writable memory — shellcode injection",
     "Capture process memory. Strong injection indicator."),
    (r"(?i)CreateRemoteThread|NtCreateThreadEx|RtlCreateUserThread|QueueUserAPC",
     "CRITICAL", "Cross-Process Thread Creation",
     "Process injection primitive used by malware/red teams",
     "Confirm legitimate use. Otherwise capture and investigate."),
    (r"(?i)(WriteProcessMemory|NtWriteVirtualMemory)\s*\(",
     "HIGH", "Cross-Process Memory Write",
     "Writing into another process — injection primitive",
     "Validate caller. Capture memory if untrusted."),
    (r"(?i)Add-MpPreference.*ExclusionPath",
     "CRITICAL", "Defender Exclusion Added",
     "Windows Defender exclusion added — disabling AV",
     "Re-enable scanning. Investigate why exclusion was added."),
    (r"(?i)Set-MpPreference.*DisableRealtimeMonitoring\s+\$true",
     "CRITICAL", "Defender Realtime Disabled",
     "Disabling Defender realtime protection",
     "Re-enable. Investigate parent process / account used."),
]

# ── LOLBin / signed-binary abuse ──
LOLBIN_PATTERNS = [
    (r"(?i)\bcertutil(?:\.exe)?\s+[^\n]*-urlcache",
     "HIGH", "certutil URL Download",
     "certutil.exe abused to download files (LOLBin)",
     "Block certutil network use via AppLocker / WDAC."),
    (r"(?i)\bbitsadmin(?:\.exe)?\s+/(?:transfer|create|addfile)",
     "HIGH", "BITSAdmin Transfer",
     "bitsadmin used for stealth download (LOLBin)",
     "Audit BITS jobs. Detect with `bitsadmin /list /allusers`."),
    (r"(?i)\bregsvr32(?:\.exe)?\s+[^\n]*/i\s*:\s*https?://",
     "CRITICAL", "regsvr32 Squiblydoo",
     "regsvr32 /i: remote URL — classic LOLBin RCE (Squiblydoo)",
     "Block regsvr32 network outbound. Hunt scrobj.dll usage."),
    (r"(?i)\bmshta(?:\.exe)?\s+(?:https?://|javascript:|vbscript:)",
     "CRITICAL", "mshta Remote Execution",
     "mshta loading remote HTA — phishing payload runner",
     "Disable mshta if not used. Block at proxy."),
    (r"(?i)\brundll32(?:\.exe)?\s+[^\n]*javascript:",
     "CRITICAL", "rundll32 JavaScript",
     "rundll32 javascript: — code execution via URL",
     "AppLocker block. EDR alert on this pattern."),
    (r"(?i)\bmsiexec(?:\.exe)?\s+/(?:q|quiet|i)\s+https?://",
     "HIGH", "msiexec Remote MSI",
     "msiexec installing remote MSI — payload delivery",
     "Audit. Block MSI download from untrusted domains."),
    (r"(?i)\b(?:wmic|invoke-wmimethod)\s+[^\n]*(?:process\s+call\s+create|win32_process)",
     "HIGH", "WMI Process Create",
     "WMI used to spawn process (lateral movement)",
     "Audit WMI subscriptions. Detect with sysmon EID 19/20/21."),
    (r"(?i)\bschtasks(?:\.exe)?\s+/create[^\n]*(?:/RU\s+SYSTEM|/SC\s+ONLOGON)",
     "HIGH", "Scheduled Task SYSTEM/ONLOGON",
     "Scheduled task with SYSTEM privileges or onlogon trigger",
     "Audit Task Scheduler. Confirm legitimacy."),
    (r"(?i)\bnet(?:\.exe)?\s+user\s+\S+\s+\S+\s+/add",
     "HIGH", "Local User Created",
     "Creating local user account",
     "Audit /etc/passwd or net user. Confirm authorised."),
    (r"(?i)Add-LocalGroupMember.*Administrators",
     "HIGH", "Admin Group Addition",
     "Adding user to local Administrators group",
     "Confirm authorisation. Roll back if not approved."),
    (r"(?i)reg(?:\.exe)?\s+add[^\n]*Run(?:Once)?[^\n]*reg_sz",
     "HIGH", "Registry Run Key Persistence",
     "Persistence via HKCU/HKLM Run key",
     "Audit autoruns. Remove unknown entries."),
]

# ── SSH key / cloud token theft ──
SSH_KEY_PATTERNS = [
    (r"-----BEGIN (?:RSA|DSA|EC|OPENSSH|ENCRYPTED) PRIVATE KEY-----",
     "CRITICAL", "Hardcoded Private Key",
     "Hardcoded SSH/SSL private key embedded in source",
     "ROTATE THIS KEY IMMEDIATELY. Remove from repo, scrub history."),
    (r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
     "CRITICAL", "Hardcoded PGP Private Key",
     "Hardcoded PGP private key block",
     "Revoke key. Generate new keypair. Audit signed artefacts."),
    (r"AKIA[0-9A-Z]{16}",
     "CRITICAL", "AWS Access Key ID",
     "AWS access key ID exposed",
     "Rotate immediately. Check CloudTrail for misuse."),
    (r"(?i)aws_secret_access_key\s*=\s*['\"]?[A-Za-z0-9/+=]{40}",
     "CRITICAL", "AWS Secret Key",
     "AWS secret access key exposed",
     "Rotate. Audit IAM usage. Check S3 buckets for damage."),
    (r"AIza[0-9A-Za-z\-_]{35}",
     "CRITICAL", "Google API Key",
     "Google API key exposed in source",
     "Restrict key in GCP console. Rotate. Audit usage."),
    (r"ghp_[A-Za-z0-9]{36}",
     "CRITICAL", "GitHub Personal Access Token",
     "GitHub PAT (ghp_) exposed",
     "Revoke immediately at github.com/settings/tokens."),
    (r"gho_[A-Za-z0-9]{36}",
     "CRITICAL", "GitHub OAuth Token",
     "GitHub OAuth token (gho_) exposed",
     "Revoke. Audit linked OAuth app."),
    (r"(?i)slack[\-_]?token\s*[:=]\s*['\"]?xox[baprs]-[A-Za-z0-9\-]+",
     "CRITICAL", "Slack Token",
     "Slack API token (xoxb / xoxp / xoxa / xoxr / xoxs) exposed",
     "Revoke. Rotate. Audit Slack app permissions."),
    (r"(?i)stripe[\-_]?(?:key|token)\s*[:=]\s*['\"]?(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{24,}",
     "CRITICAL", "Stripe API Key",
     "Stripe API secret key exposed",
     "Rotate at dashboard.stripe.com. Audit billing."),
    (r"(?i)sendgrid[\-_]?(?:api|key)\s*[:=]\s*['\"]?SG\.[A-Za-z0-9_\-\.]{60,}",
     "CRITICAL", "SendGrid API Key",
     "SendGrid API key exposed",
     "Rotate. Audit outbound mail volume."),
    (r"eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}",
     "HIGH", "JWT Token",
     "JSON Web Token (potentially with sensitive claims)",
     "Decode at jwt.io. If contains secrets, rotate. Use short TTL."),
    (r"(?i)bearer\s+[A-Za-z0-9_\-\.]{20,}",
     "MEDIUM", "Bearer Token",
     "OAuth Bearer token exposed",
     "Rotate. Use environment variables, not source."),
    (r"(?i)(api[_\-]?key|api[_\-]?secret|access[_\-]?token)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]",
     "HIGH", "Generic API Key",
     "Generic API key / secret / token in source",
     "Rotate. Move to secrets manager (Vault, AWS SM, GCP Secret Manager)."),
]

# ── Supply-chain / dependency confusion ──
SUPPLY_CHAIN_PATTERNS = [
    (r"(?i)require\(\s*['\"]\.\./\.\./\.\./node_modules",
     "MEDIUM", "Traversal into node_modules",
     "Path traversal into node_modules — possibly dep-confusion attack",
     "Audit package.json. Pin versions. Use lock files."),
    (r"(?i)post(?:install|publish)\s*[:=]",
     "MEDIUM", "npm postinstall Script",
     "package.json postinstall script — can execute arbitrary code",
     "Audit the script. Common supply-chain attack vector."),
    (r"(?i)curl[^\n]*\|\s*sh\b",
     "HIGH", "curl pipe to shell",
     "Downloading then piping to shell — supply-chain risk",
     "Inspect script before running. Pin commit hash."),
    (r"(?i)wget[^\n]*-O-[^\n]*\|\s*(?:bash|sh)\b",
     "HIGH", "wget pipe to shell",
     "Downloading then piping to shell",
     "Inspect script before running."),
    (r"(?i)pip\s+install\s+--index-url\s+http://",
     "HIGH", "pip Insecure Index",
     "pip install from non-HTTPS index",
     "Always use https://pypi.org. Never plain HTTP."),
    (r"(?i)(typosquat|brandjack|dependency[\s\-]?confusion)",
     "HIGH", "Supply-Chain Term",
     "Reference to supply-chain attack techniques",
     "Audit dependencies. Use namespaced packages."),
]

# ── C2 framework signatures ──
C2_FRAMEWORK_PATTERNS = [
    (r"(?i)\bcobalt[\s_-]?strike\b|beacon\.dll|teamserver\.dll",
     "CRITICAL", "Cobalt Strike Reference",
     "Cobalt Strike adversary simulation framework",
     "Confirm authorised red team. Otherwise full IR."),
    (r"(?i)\b(?:metasploit|meterpreter|msfvenom|msfconsole)\b",
     "CRITICAL", "Metasploit Reference",
     "Metasploit / Meterpreter usage",
     "If unauthorised, full IR. Capture network indicators."),
    (r"(?i)\bempire(?:\s+(?:agent|listener))?\b|PowerShellEmpire",
     "CRITICAL", "PowerShell Empire",
     "PowerShell Empire C2 framework",
     "Full IR. Empire post-exploitation framework."),
    (r"(?i)\bsliver(?:c2)?\b|implant\.bin",
     "CRITICAL", "Sliver C2 Reference",
     "Sliver adversary emulation framework",
     "Confirm authorised. Otherwise full IR."),
    (r"(?i)\bcovenant(?:c2)?\b|grunt\.dll",
     "HIGH", "Covenant C2 Reference",
     "Covenant .NET C2 framework",
     "Confirm authorised."),
    (r"(?i)\b(?:havoc|brutel|mythic|nighthawk)(?:\s+c2)?\b",
     "CRITICAL", "Modern Red-Team C2",
     "Reference to modern C2 framework",
     "Confirm authorised. Otherwise full IR."),
    (r"(?i)pwsh\s+-(?:nop|enc).{50,}(?:DownloadString|Net\.WebClient)",
     "CRITICAL", "Encoded PWSH Download",
     "Encoded PowerShell download cradle — likely C2 stager",
     "Decode. Identify C2 URL. Block + IR."),
]

# ── Webshell signatures ──
WEBSHELL_PATTERNS = [
    (r"(?i)<\?php\s+(?:eval|assert|system|exec|shell_exec|passthru|popen)\s*\(\s*\$_(?:POST|GET|REQUEST|COOKIE|SERVER)",
     "CRITICAL", "Classic PHP Webshell",
     "PHP webshell — direct user-input → code execution",
     "Delete. Audit upload directory. Check access logs for last visitor."),
    (r"(?i)c99shell|r57shell|wso\s*shell|b374k|alfashell|FilesMan",
     "CRITICAL", "Known PHP Webshell Family",
     "Named PHP webshell family",
     "Delete immediately. Audit entire web root."),
    (r"(?i)<%@\s*Page[^\n]*%>[^\n]*<%[^\n]*(?:eval|execute|server\.execute)",
     "CRITICAL", "ASP.NET Webshell",
     "ASP.NET webshell pattern",
     "Delete. Audit IIS logs."),
    (r"(?i)Runtime\.getRuntime\(\)\.exec\s*\(\s*request\.getParameter",
     "CRITICAL", "JSP Webshell",
     "JSP webshell — request parameter to Runtime.exec",
     "Delete. Audit Tomcat / Jetty access logs."),
    (r"(?i)assert\s*\(\s*\$_(?:POST|GET|REQUEST)\s*\[",
     "CRITICAL", "PHP assert Webshell",
     "PHP assert() used as eval — common webshell variant",
     "Delete. assert is functionally equivalent to eval."),
    (r"(?i)preg_replace\s*\(.{0,100}/e['\"].*\$_(?:POST|GET|REQUEST)",
     "CRITICAL", "PHP preg_replace /e Modifier",
     "preg_replace /e modifier — deprecated eval-on-match shell",
     "Delete. /e modifier disabled in PHP 7+ but legacy code still exists."),
    (r"(?i)\$\w+\s*\(\s*\$\w+\s*\(\s*\$_(?:POST|GET|REQUEST|COOKIE)",
     "HIGH", "Dynamic PHP Function Call",
     "Indirect function call from user input — obfuscated shell",
     "Audit context. Often an obfuscated eval."),
    (r"(?i)cmd\.jsp|cmd\.aspx|c\.php|shell\.php|x\.php|info\.php\?cmd=",
     "HIGH", "Suspicious Filename",
     "Filename commonly used for webshells",
     "Inspect file. Delete if shell."),
]

# ── AV evasion / packer ──
AV_EVASION_PATTERNS = [
    (r"(?i)\b(upx|themida|vmprotect|enigma\s*protector|aspack|aspr|petite|fsg|mpress|nspack)\b",
     "MEDIUM", "Known Packer/Protector",
     "Reference to executable packer/protector — common evasion",
     "Unpack and re-scan. Investigate why binary needs packing."),
    (r"(?i)IsDebuggerPresent\s*\(",
     "MEDIUM", "Anti-Debugging API",
     "IsDebuggerPresent — anti-debugging technique",
     "May be legitimate. Combined with other AV evasion = malware."),
    (r"(?i)NtQueryInformationProcess.*ProcessDebugPort",
     "HIGH", "NtQueryInformationProcess Anti-Debug",
     "Direct NT API anti-debug check — advanced evasion",
     "Strong malware indicator when combined with packer/inject."),
    (r"(?i)CheckRemoteDebuggerPresent",
     "MEDIUM", "Remote Debugger Check",
     "Checking for remote debugger — sandbox evasion",
     "Common in modern malware."),
    (r"(?i)GetTickCount.*GetTickCount|QueryPerformanceCounter.*sleep",
     "MEDIUM", "Timing-Based Sandbox Detection",
     "Timing comparison — sandbox evasion (delays past sandbox timeout)",
     "Combined with other indicators = high confidence malware."),
    (r"(?i)cpuid|cpu.{0,20}vendor.{0,20}(?:vmware|virtualbox|qemu|xen)",
     "HIGH", "Hypervisor Detection",
     "Checking CPU/hardware for VM presence — VM-aware malware",
     "Run in bare-metal lab or hidden-hypervisor sandbox."),
    (r"(?i)(VBoxService|vmtoolsd|vmwaretray|qemu-ga|prl_cc|XenService)",
     "HIGH", "VM Tool Process Check",
     "Checking for VM-tool process — sandbox detection",
     "Use hardened sandbox or bare-metal."),
    (r"(?i)Sleep\s*\(\s*(?:[2-9][0-9]{4,}|[1-9][0-9]{5,})\s*\)",
     "MEDIUM", "Long Sleep — Sandbox Stall",
     "Long Sleep() call — possibly stalling past sandbox timeout",
     "Patch sleep or use accelerated-time sandbox."),
]

# ── Dropper / second-stage loader ──
DROPPER_PATTERNS = [
    (r"(?i)(?:URLDownloadToFile|WinHttpReadData|InternetReadFile|HttpSendRequest).{0,200}(?:CreateProcess|ShellExecute|WinExec)",
     "CRITICAL", "Download-and-Execute",
     "Classic dropper: download payload → execute",
     "Block URL. Capture binary. Full IR."),
    (r"(?i)New-Object\s+Net\.WebClient[^\n]*DownloadFile",
     "HIGH", "PowerShell Download",
     "PowerShell file download — common dropper stager",
     "Inspect URL. Block at proxy."),
    (r"(?i)Invoke-WebRequest[^\n]*-OutFile",
     "MEDIUM", "PowerShell IWR Download",
     "Invoke-WebRequest saving to file",
     "Inspect URL + destination."),
    (r"(?i)\.write\(.*\.responseBody\)",
     "HIGH", "MSXMLHTTP Download",
     "MSXMLHTTP-based file write — VBScript dropper pattern",
     "Inspect context."),
    (r"(?i)CreateObject\s*\(\s*['\"]Wscript\.Shell['\"]\s*\).*\.Run",
     "HIGH", "WScript.Shell Run",
     "WScript.Shell .Run — VBS/JS dropper execution",
     "Inspect. Disable WSH if not needed (HKLM Software\\Microsoft\\Windows Script Host\\Settings)."),
    (r"(?i)CreateObject\s*\(\s*['\"]ADODB\.Stream['\"]",
     "HIGH", "ADODB.Stream Binary Write",
     "ADODB.Stream — write binary to disk (classic dropper)",
     "Inspect downstream actions."),
]

# ── Credential theft (LSASS, Mimikatz, etc.) ──
CREDENTIAL_THEFT_PATTERNS = [
    (r"(?i)\bmimikatz\b|sekurlsa::|kerberos::ptt|lsadump::",
     "CRITICAL", "Mimikatz Reference",
     "Mimikatz credential-theft tool reference",
     "Full IR. Rotate ALL credentials including KRBTGT (twice). Kerberoasting damage assessment."),
    (r"(?i)procdump(?:\.exe)?\s+[^\n]*lsass",
     "CRITICAL", "ProcDump on LSASS",
     "ProcDump dumping LSASS — credential theft stage",
     "Confirmed credential theft. Rotate all domain creds."),
    (r"(?i)comsvcs\.dll[^\n]*MiniDump",
     "CRITICAL", "comsvcs.dll MiniDump",
     "comsvcs.dll abuse to dump LSASS without procdump",
     "Confirmed credential theft. Rotate. Hunt parent process."),
    (r"(?i)rundll32[^\n]*comsvcs\.dll[^\n]*MiniDump",
     "CRITICAL", "comsvcs.dll LSASS Dump",
     "rundll32 comsvcs.dll MiniDump — LSASS dump LOLBin",
     "Highest-fidelity credential theft signal. Full IR."),
    (r"(?i)ntds\.dit",
     "HIGH", "NTDS.dit Reference",
     "Active Directory database file — full domain hash dump",
     "If exfiltrated, full domain reset (KRBTGT 2x, all users)."),
    (r"(?i)(?:vssadmin|wbadmin|diskshadow)[^\n]*shadow.*copy",
     "HIGH", "Volume Shadow Copy for NTDS",
     "Shadow copy creation — often used to grab ntds.dit",
     "Audit. May be backup or attacker. Check context."),
    (r"(?i)hashdump|samdump|pwdump|cachedump",
     "CRITICAL", "Hash Dump Tool Reference",
     "Local SAM/cached credential dumping",
     "Rotate local passwords. Audit credential reuse."),
    (r"(?i)kerberoast|GetUserSPNs",
     "HIGH", "Kerberoasting Tool",
     "Kerberoasting tool reference — service account hash crack",
     "Use long random service-account passwords. Move to gMSA."),
    (r"(?i)AS-?REP\s*roast(?:ing)?|GetNPUsers",
     "HIGH", "AS-REP Roasting",
     "AS-REP roasting — accounts with no preauth",
     "Audit. Enable preauth on all accounts (UF_DONT_REQUIRE_PREAUTH=false)."),
    (r"(?i)(?:DCSync|DRSGetNCChanges|Mimikatz.*lsadump)",
     "CRITICAL", "DCSync Attack",
     "DCSync — replicating domain credentials remotely",
     "Highest severity. Rotate KRBTGT 2x. Domain reset."),
]

# ── Mobile / Android-specific malware ──
MOBILE_PATTERNS = [
    (r"(?i)android\.permission\.SEND_SMS.*android\.permission\.READ_CONTACTS.*android\.permission\.INTERNET",
     "CRITICAL", "SMS Stealer Permission Combo",
     "SMS + CONTACTS + INTERNET = SMS stealer / smisher",
     "Reject app. Likely malware."),
    (r"(?i)android\.permission\.BIND_ACCESSIBILITY_SERVICE.*android\.permission\.SYSTEM_ALERT_WINDOW",
     "CRITICAL", "Banking Trojan Combo",
     "ACCESSIBILITY + SYSTEM_ALERT_WINDOW = overlay banking trojan",
     "Reject. Combined permissions = TOAD / TeaBot / Cerberus family."),
    (r"(?i)android\.permission\.REQUEST_INSTALL_PACKAGES",
     "HIGH", "Install Packages Permission",
     "App can install other APKs — dropper capability",
     "Investigate purpose. Rare in legit apps."),
    (r"(?i)DexClassLoader\s*\(.*\.dex|PathClassLoader\s*\(.*\.dex",
     "HIGH", "Runtime DEX Load",
     "Loading remote DEX at runtime — evasion / dropper",
     "Investigate URL source. Confirms dynamic code loading."),
    (r"(?i)https?://[^\s'\"]+\.(?:apk|dex|jar)\b",
     "HIGH", "Remote APK/DEX URL",
     "URL pointing to remote .apk/.dex — payload delivery",
     "Block domain. Inspect downloaded artefact."),
    (r"(?i)TrustManager\s*\(\s*\)[^\n}]*\{\s*\}",
     "CRITICAL", "Disabled SSL TrustManager",
     "Empty TrustManager — accepts ALL certs (MITM possible)",
     "Implement proper TrustManager or use system default."),
    (r"(?i)setHostnameVerifier\s*\(.*ALLOW_ALL",
     "CRITICAL", "Disabled Hostname Verification",
     "ALLOW_ALL_HOSTNAME_VERIFIER — accepts any hostname",
     "Use BrowserCompatHostnameVerifier."),
    (r"(?i)usesCleartextTraffic\s*=\s*['\"]?true",
     "HIGH", "Cleartext Traffic Allowed",
     "App allows cleartext HTTP — MITM risk",
     "Set to false. Use HTTPS everywhere."),
]

# ── Network anomalies ──
NETWORK_ANOMALY_PATTERNS = [
    (r"(?i)\bdns[\s_-]?tunnel(?:ing)?|iodine|dnscat2?",
     "HIGH", "DNS Tunneling Tool",
     "DNS tunneling tool reference — covert C2",
     "Inspect DNS volume + TXT query patterns. Block at resolver."),
    (r"(?i)\b(?:tor\b|torify|onion\b|\.onion\b|tor2web|hidden\s*service)",
     "MEDIUM", "Tor Network Reference",
     "Tor / .onion reference — anonymisation network",
     "Block Tor entry nodes if policy disallows. Investigate context."),
    (r"(?i)(ngrok|serveo|localtunnel|cloudflare\s*tunnel|tailscale\s*funnel)",
     "HIGH", "Reverse Tunnel Service",
     "Reverse tunnel SaaS — often abused to expose internal services",
     "Audit usage. Block at firewall if unauthorised."),
    (r"(?i)\bbeacon(?:ing)?\b.*(?:interval|jitter|sleep)",
     "HIGH", "Beacon Configuration",
     "Beaconing interval reference — C2 traffic shaping",
     "Common in Cobalt Strike / Sliver configs."),
    (r"(?i)(?:domain[\s\-_]generation|dga|fast[\s\-]?flux)",
     "HIGH", "DGA / Fast-Flux Reference",
     "Domain generation algorithm / fast-flux DNS — resilient C2",
     "Audit DNS resolutions. Detect with ML on NX domains."),
]

# ── Specific malware family names ──
MALWARE_FAMILY_PATTERNS = [
    (r"(?i)\b(emotet|trickbot|qakbot|qbot|icedid|bumblebee|gozi|dridex)\b",
     "CRITICAL", "Banking Trojan / Loader Family",
     "Named banking trojan / loader family",
     "Quarantine. Full IR. Often precursor to ransomware."),
    (r"(?i)\b(lockbit|conti|royal|blackcat|alphv|hive|akira|playready|blacksuit|noescape|cl0p)\b",
     "CRITICAL", "Ransomware Family Name",
     "Named ransomware family / RaaS",
     "Confirm context. If active, immediate IR. Notify legal."),
    (r"(?i)\b(zeus|spyeye|sphinx|atmos|chthonic|panda\s*banker)\b",
     "CRITICAL", "Legacy Banking Trojan",
     "Legacy banking trojan family",
     "Quarantine. Often delivered via phishing."),
    (r"(?i)\b(?:mirai|gafgyt|hajime|bashlite|tsunami|moobot|momentum)\b",
     "CRITICAL", "IoT Botnet Family",
     "IoT botnet malware reference",
     "Audit IoT devices. Default-cred scan + factory reset."),
    (r"(?i)\b(plugx|gh0st\s*rat|nanocore|asyncrat|remcos|njrat|darkcomet|venomrat|warzone(?:rat)?)\b",
     "CRITICAL", "Commodity RAT",
     "Commodity remote-access trojan",
     "Quarantine. Trace persistence + C2."),
    (r"(?i)\b(stuxnet|flame|duqu|regin|wannacry|notpetya|badrabbit|petya|shamoon)\b",
     "CRITICAL", "Historic Nation-State Malware",
     "Historic nation-state / wiper reference",
     "Audit context. If active, full IR + government notify."),
]

# ── PUA / adware (less severe) ──
PUA_ADWARE_PATTERNS = [
    (r"(?i)(adware|spyware|pup|browserhelperobject|toolbar.*install)",
     "MEDIUM", "PUA / Adware Reference",
     "Potentially Unwanted Application / adware",
     "Remove. Audit how it got installed."),
    (r"(?i)(install.*toolbar|browser.*hijack|search.*redirect)",
     "MEDIUM", "Browser Hijacker",
     "Browser hijacker pattern",
     "Remove from extensions/profiles."),
]

# Compile all new pattern groups
ALL_THREAT_PATTERNS = (
    RANSOMWARE_PATTERNS +
    TROJAN_PATTERNS +
    WORM_PATTERNS +
    BACKDOOR_PATTERNS +
    EXFIL_PATTERNS +
    LATERAL_MOVEMENT_PATTERNS +
    PRIVILEGE_ESCALATION_PATTERNS +
    CRYPTOMINER_PATTERNS +
    INFOSTEALER_PATTERNS +
    ROOTKIT_PATTERNS +
    FILELESS_PATTERNS +
    LOLBIN_PATTERNS +
    SSH_KEY_PATTERNS +
    SUPPLY_CHAIN_PATTERNS +
    C2_FRAMEWORK_PATTERNS +
    WEBSHELL_PATTERNS +
    AV_EVASION_PATTERNS +
    DROPPER_PATTERNS +
    CREDENTIAL_THEFT_PATTERNS +
    MOBILE_PATTERNS +
    NETWORK_ANOMALY_PATTERNS +
    MALWARE_FAMILY_PATTERNS +
    PUA_ADWARE_PATTERNS
)


def _compile_patterns():
    """Compile all pattern groups into (regex, severity, category, desc, fix) tuples."""
    compiled = []
    for group_name, patterns in [
        ("php", PHP_PATTERNS),
        ("js", JS_PATTERNS),
        ("python", PYTHON_PATTERNS),
        ("powershell", POWERSHELL_PATTERNS),
        ("generic", GENERIC_PATTERNS),
        ("sqli", SQLI_PATTERNS),
        ("xss", XSS_PATTERNS),
        ("ransomware", RANSOMWARE_PATTERNS),
        ("trojan", TROJAN_PATTERNS),
        ("worm", WORM_PATTERNS),
        ("backdoor", BACKDOOR_PATTERNS),
        ("exfil", EXFIL_PATTERNS),
        ("lateral_movement", LATERAL_MOVEMENT_PATTERNS),
        ("privilege_escalation", PRIVILEGE_ESCALATION_PATTERNS),
        # ── v24 expansion: 14 new categories, ~150 new patterns ─
        ("cryptominer",        CRYPTOMINER_PATTERNS),
        ("infostealer",        INFOSTEALER_PATTERNS),
        ("rootkit",            ROOTKIT_PATTERNS),
        ("fileless",           FILELESS_PATTERNS),
        ("lolbin",             LOLBIN_PATTERNS),
        ("ssh_keys",           SSH_KEY_PATTERNS),
        ("supply_chain",       SUPPLY_CHAIN_PATTERNS),
        ("c2_framework",       C2_FRAMEWORK_PATTERNS),
        ("webshell",           WEBSHELL_PATTERNS),
        ("av_evasion",         AV_EVASION_PATTERNS),
        ("dropper",            DROPPER_PATTERNS),
        ("credential_theft",   CREDENTIAL_THEFT_PATTERNS),
        ("mobile",             MOBILE_PATTERNS),
        ("network_anomaly",    NETWORK_ANOMALY_PATTERNS),
        ("malware_family",     MALWARE_FAMILY_PATTERNS),
        ("pua_adware",         PUA_ADWARE_PATTERNS),
    ]:
        for pat, sev, cat, desc, fix in patterns:
            try:
                compiled.append((re.compile(pat, re.MULTILINE | re.IGNORECASE), sev, cat, desc, fix, group_name))
            except re.error as e:
                log.warning("bad_regex", pattern=pat, error=str(e))
    return compiled


_COMPILED = _compile_patterns()


# ── Finding dataclass ─────────────────────────────────────────────
@dataclass
class Finding:
    file:         str
    line:         int
    severity:     str
    category:     str
    description:  str
    evidence:     str
    fix:          str
    owasp:        str = ""
    detector:     str = ""

    def to_dict(self):
        return asdict(self)


# ── Severity scoring ──────────────────────────────────────────────
_SEVERITY_SCORE = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 2}


# ── Shannon entropy (detects obfuscated/packed payloads) ─────────
def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    from collections import Counter
    counter = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counter.values())


# v25 — Scanner self-awareness helpers (suppress FPs on security-tool code)
import re as _re_v25

# Hints that strongly suggest this file is a security tool / pattern catalog
# (NOT actual malware). The denser these signals, the more confident.
_SECURITY_TOOL_HINTS = (
    "re.compile(", "_PATTERNS", "_RULES",
    "(r\"", "(r'",                          # raw-string pattern tuples
    "yara.compile", "rule.*:.*$",           # YARA rule headers
    "[\"CRITICAL\",", "[\"HIGH\",", "[\"MEDIUM\",",
    "(\"CRITICAL\",", "(\"HIGH\",", "(\"MEDIUM\",",
    "category", "severity", "MalwareBazaar",
    "VirusTotal", "PhishTank", "URLhaus",
    "scan_file", "scan_archive", "detect_malware",
    "Finding(", "FORENSIC", "FORENSIC_PATTERNS",
)

def _looks_like_security_tool(text: str, path: str) -> bool:
    """
    Decide whether this file is a security-tool / pattern-catalog rather
    than actual application code. Triggered when ≥6 hints OR known
    filename patterns are detected.
    """
    name = (path or "").lower()
    name_hints = (
        "forensic_scanner", "malware_pattern", "yara_rule",
        "pattern_catalog", "detection_rule", "vuln_pattern",
        "exploit_demo", "live_malware_lab", "attack_blueprint",
        "source_recon", "url_analyzer", "browser_warning_detector",
    )
    if any(h in name for h in name_hints):
        return True
    hit = sum(1 for h in _SECURITY_TOOL_HINTS if h in text)
    return hit >= 6


def _python_string_offsets(text: str) -> list | None:
    """
    Return a list of (start, end) byte ranges that are inside Python
    string literals OR comments. Used to suppress pattern matches that
    occur inside string definitions or documentation comments.

    Uses tokenize for correctness; falls back to None on parse error.
    """
    try:
        import tokenize
        import io
        ranges: list[tuple[int, int]] = []
        try:
            tokens = tokenize.generate_tokens(io.StringIO(text).readline)
            for tok in tokens:
                # v25: include both STRING and COMMENT tokens — many security
                # tool comments contain pattern words ("# reverse shell …")
                if tok.type in (tokenize.STRING, tokenize.COMMENT):
                    start_off = _line_col_to_offset(text, tok.start[0], tok.start[1])
                    end_off   = _line_col_to_offset(text, tok.end[0], tok.end[1])
                    ranges.append((start_off, end_off))
        except (tokenize.TokenizeError, IndentationError, SyntaxError):
            # Partial result is still useful — keep what we collected
            pass
        return ranges  # list, not set; we use linear search
    except Exception:
        return None


# Cache of line-start offsets per text — re-used across many offsets
_LINE_CACHE: dict[int, list[int]] = {}

def _line_col_to_offset(text: str, line: int, col: int) -> int:
    """Convert (1-based line, 0-based col) → absolute byte offset."""
    key = id(text)
    if key not in _LINE_CACHE:
        offs = [0]
        for i, ch in enumerate(text):
            if ch == "\n":
                offs.append(i + 1)
        _LINE_CACHE[key] = offs
        # Prevent memory leak — keep at most 8 cached
        if len(_LINE_CACHE) > 8:
            _LINE_CACHE.pop(next(iter(_LINE_CACHE)))
    offs = _LINE_CACHE[key]
    if line - 1 >= len(offs):
        return len(text)
    return offs[line - 1] + col


def _offset_inside_string(offset: int, ranges: list) -> bool:
    """True if `offset` falls inside any of the precomputed string ranges."""
    if not ranges:
        return False
    for s, e in ranges:
        if s <= offset < e:
            return True
    return False


def _line_looks_like_pattern_def(line: str) -> bool:
    """
    Heuristic: is this line obviously a regex/pattern-tuple definition?
    Catches cases tokenize can't follow (concatenated strings split across
    physical lines, f-strings with embedded code, etc.)
    """
    s = (line or "").strip()
    if not s:
        return False
    if s.startswith(("r\"", "r'", '"', "'", "(r\"", "(r'", "(r\"\"\"", "(r'''")):
        return True
    if "re.compile(" in s:
        return True
    # Tuple like: (r"...", "CRITICAL", "Category", "description", "fix"),
    if s.startswith("(") and ('"CRITICAL"' in s or '"HIGH"' in s
                              or '"MEDIUM"' in s or '"LOW"' in s
                              or "'CRITICAL'" in s or "'HIGH'" in s):
        return True
    return False


def _is_garbage_line(line: str) -> bool:
    """
    v24 quality gate: True if a line looks like binary garbage that
    coincidentally matched a regex. Stops false positives like the
    'Windows Kernel Driver API' match on `|"��^&�������x#`.
    """
    if not line:
        return True
    # Strip nulls and replacement chars first
    if not line.strip():
        return True
    # Count Unicode replacement chars + non-printable bytes
    replacements = line.count("�")
    non_printable = sum(
        1 for c in line
        if ord(c) < 9 or (13 < ord(c) < 32) or ord(c) == 127
    )
    total = len(line)
    # If > 25% of the line is replacement/garbage, treat as binary noise
    if (replacements + non_printable) / total > 0.25:
        return True
    # If line is mostly non-ASCII and short, likely binary garbage
    non_ascii = sum(1 for c in line if ord(c) > 127)
    if total < 80 and non_ascii / total > 0.40:
        return True
    return False


# ── File type detection ───────────────────────────────────────────
def _detect_language(filepath: str) -> str:
    ext = Path(filepath).suffix.lower()
    mapping = {
        ".php": "php", ".phtml": "php",
        ".js": "js", ".mjs": "js", ".jsx": "js",
        ".ts": "js", ".tsx": "js",
        ".py": "python",
        ".rb": "ruby",
        ".java": "java",
        ".jsp": "java",
        ".pl": "perl",
        ".sh": "shell", ".bash": "shell",
        ".ps1": "powershell",
        ".html": "html", ".htm": "html",
        ".sql": "sql",
        ".yml": "yaml", ".yaml": "yaml",
        ".env": "env", ".cfg": "env", ".conf": "env",
    }
    return mapping.get(ext, "text")


# ── v24 file-type classification — prevents false positives on binaries ──
# Binary/compressed/media containers where regex pattern matching produces
# garbage matches against random byte sequences. For these we ONLY use:
#   1) YARA (designed for binaries)
#   2) Hash reputation (MalwareBazaar)
#   3) Format-specific deep inspection (e.g. Office macro scan)
_BINARY_OR_COMPRESSED_EXTS = {
    # Office documents (ZIP-based)
    ".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm",
    ".odt", ".ods", ".odp",
    # Legacy Office (OLE compound)
    ".doc", ".xls", ".ppt", ".rtf",
    # PDFs
    ".pdf",
    # Archives
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".tgz", ".tbz2",
    ".jar", ".war", ".ear", ".apk", ".ipa", ".aab",
    # Images
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".ico", ".tiff", ".tif",
    ".svg", ".heic", ".heif",
    # Audio / video
    ".mp3", ".mp4", ".m4a", ".m4v", ".mov", ".avi", ".mkv", ".webm",
    ".wav", ".ogg", ".flac", ".opus",
    # Compiled executables
    ".exe", ".dll", ".so", ".dylib", ".o", ".a", ".lib",
    ".bin", ".dat", ".db", ".sqlite", ".sqlite3",
    # Fonts / others
    ".ttf", ".otf", ".woff", ".woff2", ".eot",
    ".iso", ".dmg", ".img",
}


def _is_binary_container(filepath: str, raw: bytes) -> bool:
    """
    True when the file is a binary/compressed container where regex
    pattern matching against raw bytes would generate false-positives.

    Detection is by extension first, then by magic-byte sniff (so a
    renamed file is still classified correctly).
    """
    ext = Path(filepath).suffix.lower()
    if ext in _BINARY_OR_COMPRESSED_EXTS:
        return True
    if not raw:
        return False
    # Magic byte sniff — catches renamed files
    head = raw[:16]
    magic_signatures = (
        b"PK\x03\x04",     # ZIP (also .docx, .xlsx, .jar, .apk)
        b"PK\x05\x06",     # ZIP empty
        b"PK\x07\x08",     # ZIP spanned
        b"\x50\x4B",       # generic PK*
        b"%PDF-",          # PDF
        b"\x89PNG\r\n",    # PNG
        b"\xFF\xD8\xFF",   # JPEG
        b"GIF87a", b"GIF89a",
        b"BM",             # BMP (only if size>2 next byte sensible)
        b"\xD0\xCF\x11\xE0",  # OLE2 compound (.doc, .xls, .ppt, .msi)
        b"MZ",             # Windows PE (.exe, .dll)
        b"\x7FELF",        # ELF binary
        b"\xCA\xFE\xBA\xBE",  # Java class / Mach-O
        b"7z\xBC\xAF",     # 7z
        b"Rar!\x1A\x07",   # RAR
        b"\x1F\x8B\x08",   # gzip
        b"\xFD7zXZ",       # xz
        b"RIFF",           # WAV / AVI / WEBP
        b"\x00\x00\x01\xBA",  # MPEG-PS
        b"\x00\x00\x00\x18ftyp",  # MP4/MOV (offset 4)
        b"\x49\x44\x33",   # ID3 (mp3)
        b"OggS",           # Ogg
        b"fLaC",           # FLAC
        b"SQLite format 3\x00",  # SQLite DB
        b"\x00\x01\x00\x00\x00",  # TTF (loose)
    )
    for sig in magic_signatures:
        if head.startswith(sig):
            return True
    # Statistical detection: if first 1KB contains >30% non-text bytes, treat as binary
    sample = raw[:1024]
    if sample:
        non_text = sum(
            1 for b in sample
            if b < 9 or (13 < b < 32 and b not in (10, 13)) or b == 127
        )
        if non_text / len(sample) > 0.30:
            return True
    return False


def _scan_office_document(filepath: str, raw: bytes) -> list:
    """
    Office-document specific scanning. Detects:
      - VBA macros (which CAN contain malware)
      - External link to suspicious URL
      - Embedded executable in .docx
      - DDEAUTO / DDE formula injection
    Returns a list of Finding objects.
    """
    findings: list[Finding] = []
    ext = Path(filepath).suffix.lower()

    # Modern Office = ZIP container
    if ext in (".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm"):
        try:
            import zipfile
            with zipfile.ZipFile(filepath) as zf:
                names = zf.namelist()

                # 1. VBA macro present?
                if any(n.endswith("vbaProject.bin") for n in names):
                    sev = "HIGH" if ext.endswith("m") else "MEDIUM"
                    findings.append(Finding(
                        file=filepath, line=0,
                        severity=sev,
                        category="Office VBA Macro",
                        description="Document contains a VBA macro project (vbaProject.bin).",
                        evidence="vbaProject.bin found inside the Office package",
                        fix=("Macros are a major malware vector. If you didn't author "
                             "this document, do NOT enable macros. Inspect with olevba."),
                        detector="office_zip",
                    ))

                # 2. External relationships → check for remote templates / OLE links
                for n in names:
                    if "_rels" in n and n.endswith(".rels"):
                        try:
                            rels_content = zf.read(n).decode("utf-8", errors="replace")
                        except Exception:
                            continue
                        # Suspicious external targets
                        if re.search(r'Target="https?://[^"]+\.(?:exe|dll|hta|scr|ps1)"',
                                     rels_content, re.IGNORECASE):
                            findings.append(Finding(
                                file=filepath, line=0,
                                severity="CRITICAL",
                                category="Office Remote Executable Link",
                                description="External relationship targets a remote .exe/.dll/.hta",
                                evidence=f"in {n}",
                                fix="Do not open. Investigate origin. Likely malware downloader.",
                                detector="office_zip",
                            ))
                        if re.search(r'Type="[^"]*oleObject"', rels_content):
                            findings.append(Finding(
                                file=filepath, line=0,
                                severity="MEDIUM",
                                category="Office Embedded OLE",
                                description="Embedded OLE object in document",
                                evidence=f"OLE relationship in {n}",
                                fix="OLE objects can contain executables. Inspect with oletools.",
                                detector="office_zip",
                            ))

                # 3. DDE/DDEAUTO formula injection
                for n in names:
                    if n.endswith(".xml") and any(
                        kw in n for kw in ("document", "sheet", "footer", "header")
                    ):
                        try:
                            xml = zf.read(n).decode("utf-8", errors="replace")
                        except Exception:
                            continue
                        if re.search(r'\bDDEAUTO\b|\bDDE\s+["\']?cmd', xml, re.IGNORECASE):
                            findings.append(Finding(
                                file=filepath, line=0,
                                severity="CRITICAL",
                                category="DDE Formula Injection",
                                description="DDE / DDEAUTO formula found — classic Office attack",
                                evidence=f"DDE marker in {n}",
                                fix="DO NOT open. DDE is used to spawn cmd.exe / powershell.",
                                detector="office_zip",
                            ))
        except zipfile.BadZipFile:
            # Not a valid ZIP — could be corrupted or renamed
            pass
        except Exception:
            pass

    # Legacy OLE (.doc/.xls/.ppt) — check for "Microsoft Office Word" + macro markers
    elif ext in (".doc", ".xls", ".ppt"):
        # OLE2 magic header check
        if raw[:8] == b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1":
            # Look for VBA macro storage stream names
            if b"VBA" in raw[:200000] or b"_VBA_PROJECT" in raw[:200000]:
                findings.append(Finding(
                    file=filepath, line=0,
                    severity="HIGH",
                    category="Legacy Office VBA Macro",
                    description="Legacy .doc/.xls/.ppt file contains VBA macro storage",
                    evidence="VBA stream detected in OLE container",
                    fix="Inspect with olevba. Common malware delivery vector.",
                    detector="office_ole",
                ))
            # Equation Editor exploit (CVE-2017-11882)
            if b"Equation.3" in raw or b"OLE10Native" in raw[:200000]:
                findings.append(Finding(
                    file=filepath, line=0,
                    severity="HIGH",
                    category="Equation Editor Object",
                    description="Embedded Equation Editor — historic CVE-2017-11882 exploit vector",
                    evidence="Equation.3 / OLE10Native object found",
                    fix="If you don't author equations, treat as suspicious.",
                    detector="office_ole",
                ))

    return findings


def _scan_pdf(filepath: str, raw: bytes) -> list:
    """PDF-specific scanning — JavaScript, embedded files, auto-actions."""
    findings: list[Finding] = []
    head_chunk = raw[:200000]  # Most metadata in first 200KB
    if b"/JavaScript" in head_chunk or b"/JS " in head_chunk:
        findings.append(Finding(
            file=filepath, line=0,
            severity="MEDIUM",
            category="PDF JavaScript",
            description="PDF contains embedded JavaScript",
            evidence="/JavaScript or /JS keyword found in PDF",
            fix=("Open in a sandbox or disable JS in your PDF reader. "
                 "Many phishing PDFs use JS to trigger downloads."),
            detector="pdf",
        ))
    if b"/Launch" in head_chunk:
        findings.append(Finding(
            file=filepath, line=0,
            severity="HIGH",
            category="PDF Launch Action",
            description="PDF contains /Launch action — can spawn external programs",
            evidence="/Launch keyword found",
            fix="Do not open. Modern Acrobat blocks but older versions execute.",
            detector="pdf",
        ))
    if b"/OpenAction" in head_chunk and b"/JavaScript" in head_chunk:
        findings.append(Finding(
            file=filepath, line=0,
            severity="HIGH",
            category="PDF AutoExec JavaScript",
            description="PDF triggers JS automatically when opened (/OpenAction + /JavaScript)",
            evidence="/OpenAction with embedded JavaScript",
            fix="High-risk indicator. Inspect with peepdf / pdfid.",
            detector="pdf",
        ))
    if b"/EmbeddedFile" in head_chunk:
        findings.append(Finding(
            file=filepath, line=0,
            severity="MEDIUM",
            category="PDF Embedded File",
            description="PDF contains an embedded file (could be malicious payload)",
            evidence="/EmbeddedFile keyword found",
            fix="Extract embedded file and scan separately.",
            detector="pdf",
        ))
    return findings


# ── Main single-file scan ─────────────────────────────────────────
def scan_file(filepath: str, max_bytes: int = 5_000_000) -> dict:
    """
    Scan a single file. Returns findings + metadata.
    
    Skips files larger than max_bytes (default 5MB).
    """
    path = Path(filepath)
    if not path.exists() or not path.is_file():
        return {"findings": [], "error": "file not found", "file": str(filepath)}

    size = path.stat().st_size
    if size > max_bytes:
        return {
            "findings": [],
            "skipped":  f"file too large ({size / 1e6:.1f} MB)",
            "file":     str(filepath),
            "size":     size,
        }

    # Read file
    try:
        raw = path.read_bytes()
    except Exception as e:
        return {"findings": [], "error": str(e), "file": str(filepath)}

    # Hash
    sha256 = hashlib.sha256(raw).hexdigest()
    md5    = hashlib.md5(raw).hexdigest()

    # Entropy
    entropy = _shannon_entropy(raw)

    # Decode as text for pattern matching (best effort)
    try:
        text = raw.decode("utf-8", errors="replace")
    except Exception:
        text = ""

    language = _detect_language(filepath)
    findings: list[Finding] = []

    # ── v24: BINARY / COMPRESSED FILE DETECTION ───────────────────
    # Running regex on a .docx / .zip / .pdf produces garbage matches
    # against random byte sequences. For these we ONLY use:
    #   1) Format-specific deep inspection (Office macro, PDF JS, etc.)
    #   2) YARA (which is designed for binaries)
    #   3) Hash reputation lookup
    is_binary = _is_binary_container(filepath, raw)
    ext = Path(filepath).suffix.lower()

    if is_binary:
        # Office documents — dedicated macro / DDE / OLE scan
        if ext in (".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm",
                   ".doc", ".xls", ".ppt"):
            findings.extend(_scan_office_document(filepath, raw))
        # PDFs — dedicated JS / Launch / EmbeddedFile scan
        elif ext == ".pdf":
            findings.extend(_scan_pdf(filepath, raw))
        # Other binaries (.exe/.dll/.zip/.png/.jpg/.mp4 etc) — rely on
        # YARA + hash reputation only. No regex.

        # NOTE: We skip Layer-2 (heuristic regex) entirely for binaries.
        # NOTE: We skip the entropy "obfuscation" warning for binaries
        #       — .docx is ZIP-compressed so 7.99 entropy is expected.

    else:
        # ── Layer 2: heuristic regex patterns (text files only) ───
        lines = text.splitlines()

        # v25: SCANNER SELF-DETECTION
        # Files that are security tools (forensic_scanner.py, yara_rules.py,
        # malware_patterns.py etc.) contain HUNDREDS of pattern strings that
        # look like malicious code but are actually DEFINITIONS. Real SAST
        # tools (Veracode, Snyk) call this "rule-definition awareness".
        # We detect this by counting how many regex.compile / pattern-tuple
        # markers the file has — if the density is high, we suppress matches
        # found inside Python string literals.
        is_security_tool = _looks_like_security_tool(text, filepath)

        # Pre-compute the set of byte offsets covered by Python string literals
        # (only when needed — costly tokenisation). Used to demote findings
        # inside string definitions.
        string_offsets = _python_string_offsets(text) if (
            is_security_tool and language in ("python", "text")
            and filepath.lower().endswith((".py", ".pyi", ".pyw"))
        ) else None

        for regex, severity, category, description, fix, group in _COMPILED:
            # Skip language-specific groups that don't match
            if group == "php" and language not in ("php", "text"):   continue
            if group == "js"  and language not in ("js", "html", "text"): continue
            if group == "sqli" and language not in ("php", "python", "java", "js", "text"): continue
            if group == "xss"  and language not in ("php", "js", "html", "text"): continue

            for match in regex.finditer(text):
                # v24: Quality gate — skip matches in lines that look like
                # binary garbage (high control-char ratio in the matched line)
                line_num = text[:match.start()].count("\n") + 1
                line_content = lines[line_num - 1] if line_num <= len(lines) else ""
                if _is_garbage_line(line_content):
                    continue

                # v25: skip the match if it's inside a Python string literal
                # in a known security-tool file (= it's a PATTERN DEFINITION,
                # not actual code execution).
                if string_offsets is not None:
                    if _offset_inside_string(match.start(), string_offsets):
                        continue
                    # Also bail out if the matched line is OBVIOUSLY a regex
                    # tuple: e.g. starts with a raw-string and ends with ),
                    if _line_looks_like_pattern_def(line_content):
                        continue

                # Trim very long lines
                if len(line_content) > 200:
                    line_content = line_content[:200] + "..."
                findings.append(Finding(
                    file=         filepath,
                    line=         line_num,
                    severity=     severity,
                    category=     category,
                    description=  description,
                    evidence=     line_content.strip(),
                    fix=          fix,
                    detector=     f"pattern/{group}",
                    owasp=        _owasp_for(category),
                ))

        # ── Layer 5: high entropy warning (text files only) ───────
        # Only fire on text files — .docx/.zip/.png all have high entropy by design
        if size > 500 and entropy > 7.5:
            findings.append(Finding(
                file=       filepath,
                line=       0,
                severity=   "MEDIUM",
                category=   "Obfuscation",
                description= f"Very high entropy ({entropy:.2f}/8.0) — file may be packed/encrypted",
                evidence=   f"Entropy score: {entropy:.2f}",
                fix=        "Manually inspect. Legitimate text rarely exceeds 6.5 entropy.",
                detector=   "entropy",
            ))

    # ── Layer 4: MalwareBazaar hash reputation ────────────────────
    try:
        from core.api_clients.malware_bazaar import check_hash
        mb_result = check_hash(sha256)
        if mb_result.get("known"):
            findings.append(Finding(
                severity=   "CRITICAL",
                category=   "Known Malware (MalwareBazaar)",
                line=       0,
                description=f"File hash matches known malware in MalwareBazaar database. "
                           f"Family: {mb_result.get('family', 'unknown')}. "
                           f"Tags: {', '.join(mb_result.get('tags', []))}",
                evidence=   f"SHA-256: {sha256} → MalwareBazaar: {mb_result.get('status')}",
                fix=        "DELETE this file immediately. Quarantine the system. "
                           "Run full AV scan. Check for lateral movement.",
                detector=   "malware_bazaar",
                owasp=      "A06:2021 – Vulnerable and Outdated Components",
            ))
    except Exception as e:
        log.debug("malware_bazaar_skip", error=str(e)[:50])

    # ── Layer 6 (v24): Deep ML File Classifier ─────────────────────
    # Pure-NumPy deep neural network predicts malicious probability
    # from 32 universal file features. Loads trained weights from
    # models/deep_file_v1.npz if available — otherwise silently skips.
    ml_result = None
    try:
        ml_result = _ml_classify_file(filepath, raw)
        if ml_result and ml_result.get("available"):
            p_mal = float(ml_result.get("p_malicious", 0))
            conf  = float(ml_result.get("confidence", 0))
            # Only raise a finding if confident (avoid noise)
            if p_mal >= 0.65:
                if   p_mal >= 0.90: sev = "CRITICAL"
                elif p_mal >= 0.80: sev = "HIGH"
                else:                sev = "MEDIUM"
                top_feats = ml_result.get("top_signals", [])[:3]
                signals_text = (", ".join(f"{f}={v:.2f}" for f, v in top_feats)
                                 if top_feats else "")
                findings.append(Finding(
                    file=        filepath,
                    line=        0,
                    severity=    sev,
                    category=    "ML: Malicious File Predicted",
                    description= (f"Deep neural network classified this file as "
                                  f"MALICIOUS with {p_mal:.1%} confidence "
                                  f"({ml_result.get('model_version', 'deep_file_v1')})."
                                  + (f" Top signals: {signals_text}" if signals_text else "")),
                    evidence=    f"p_malicious={p_mal:.4f}  p_benign={1-p_mal:.4f}",
                    fix=         ("This is an ML-based detection. Combine with other "
                                  "layers (YARA, hash reputation, regex) for confirmation. "
                                  "Inspect the file in a sandbox before opening."),
                    detector=    "ml/deep_file_v1",
                ))
            # Even if low score, attach the ML metadata to the result dict
    except Exception as e:
        log.debug("ml_file_classify_skip", error=str(e)[:80])

    # Aggregate
    max_severity = "NONE"
    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]
    for f in findings:
        if sev_order.index(f.severity) < sev_order.index(max_severity):
            max_severity = f.severity

    risk_score = sum(_SEVERITY_SCORE.get(f.severity, 0) for f in findings)
    risk_score = min(100, risk_score * 2)  # cap at 100

    return {
        "file":        str(filepath),
        "size":        size,
        "sha256":      sha256,
        "md5":         md5,
        "entropy":     round(entropy, 3),
        "language":    language,
        "is_binary":   is_binary,
        "findings":    [f.to_dict() for f in findings],
        "finding_count": len(findings),
        "max_severity": max_severity,
        "risk_score":   risk_score,
        "severity_breakdown": {
            "critical": sum(1 for f in findings if f.severity == "CRITICAL"),
            "high":     sum(1 for f in findings if f.severity == "HIGH"),
            "medium":   sum(1 for f in findings if f.severity == "MEDIUM"),
            "low":      sum(1 for f in findings if f.severity == "LOW"),
        },
        "ml":          ml_result,   # v24: deep ML classifier output
    }


# ── v24: Deep ML File Classifier helper (Layer 6) ──────────────────
_DEEP_FILE_MODEL = None
_DEEP_FILE_LOADED = False
_DEEP_FILE_PATH = Path(__file__).parent.parent / "models" / "deep_file_v1.npz"


def _try_load_deep_file_model():
    """Lazy-load the trained deep file classifier."""
    global _DEEP_FILE_MODEL, _DEEP_FILE_LOADED
    if _DEEP_FILE_LOADED:
        return _DEEP_FILE_MODEL
    _DEEP_FILE_LOADED = True
    if not _DEEP_FILE_PATH.exists():
        return None
    try:
        from core.deep_file_model import DeepFileClassifier
        m = DeepFileClassifier()
        m.load(_DEEP_FILE_PATH)
        _DEEP_FILE_MODEL = m
        log.info("deep_file_model_loaded",
                 path=str(_DEEP_FILE_PATH),
                 size_kb=round(_DEEP_FILE_PATH.stat().st_size / 1024, 1))
        return m
    except Exception as e:
        log.warning("deep_file_model_load_failed", error=str(e))
        return None


def _ml_classify_file(filepath: str, raw: bytes) -> dict | None:
    """
    Run the deep file classifier on the raw bytes. Returns None if
    the trained model isn't available.
    """
    m = _try_load_deep_file_model()
    if m is None:
        return {"available": False, "reason": "no trained model"}
    try:
        pred = m.predict_bytes(raw, path=filepath)
        # Rank features by absolute contribution (deviation from mean)
        # so the UI can show "top signals" that drove the decision
        feats = pred.get("features", {}) or {}
        # Top signals = features with the highest deviation from training mean
        if m.feat_mean is not None and m.feat_std is not None:
            from core.deep_file_model import FileFeatureExtractor
            mean = dict(zip(FileFeatureExtractor.FEATURE_NAMES, m.feat_mean))
            std  = dict(zip(FileFeatureExtractor.FEATURE_NAMES, m.feat_std))
            ranked = []
            for name, val in feats.items():
                if std.get(name, 0) > 1e-6:
                    z = (val - mean[name]) / std[name]
                    ranked.append((name, val, z))
            ranked.sort(key=lambda r: -abs(r[2]))
            top_signals = [(name, val) for name, val, _ in ranked[:5]]
        else:
            top_signals = list(feats.items())[:5]
        return {
            "available":     True,
            "p_malicious":   pred["p_malicious"],
            "p_benign":      pred["p_benign"],
            "label":         pred["label"],
            "confidence":    pred["confidence"],
            "features":      feats,
            "top_signals":   top_signals,
            "model_version": "deep_file_v1",
        }
    except Exception as e:
        log.warning("deep_file_predict_error", error=str(e))
        return {"available": False, "error": str(e)[:120]}


def _owasp_for(category: str) -> str:
    """Map category to relevant OWASP Top 10 2021 category."""
    mapping = {
        "SQL Injection":            "A03:2021 – Injection",
        "Reflected XSS":            "A03:2021 – Injection",
        "DOM-based XSS":            "A03:2021 – Injection",
        "Remote Code Execution":    "A03:2021 – Injection",
        "Dynamic Function Invocation": "A03:2021 – Injection",
        "Obfuscated Backdoor":      "A08:2021 – Software and Data Integrity Failures",
        "Hardcoded Credentials":    "A07:2021 – Identification and Authentication Failures",
        "AWS Access Key":           "A07:2021 – Identification and Authentication Failures",
        "Google API Key":           "A07:2021 – Identification and Authentication Failures",
        "Private Key":              "A02:2021 – Cryptographic Failures",
        "MongoDB Connection String": "A07:2021",
        "Postgres Connection String": "A07:2021",
        "MySQL Connection String":  "A07:2021",
    }
    return mapping.get(category, "A03:2021 – Injection")


# ── Archive scanning ──────────────────────────────────────────────
def scan_archive(archive_path: str, extract_to: str = None,
                 max_files: int = 500) -> dict:
    """
    Extract ZIP/TAR archive, scan each file inside.
    Returns aggregate report.
    """
    archive_path = str(archive_path)
    findings_per_file = []
    files_scanned = 0
    files_skipped = 0
    
    tmpdir = extract_to or tempfile.mkdtemp(prefix="aidtctm_scan_")
    
    try:
        # Extract
        if archive_path.endswith(".zip"):
            with zipfile.ZipFile(archive_path, "r") as zf:
                zf.extractall(tmpdir)
        elif archive_path.endswith((".tar.gz", ".tgz", ".tar.bz2", ".tar")):
            with tarfile.open(archive_path, "r:*") as tf:
                tf.extractall(tmpdir)
        else:
            return {"error": "Unsupported archive format"}

        # Walk and scan
        for root, dirs, files in os.walk(tmpdir):
            for fname in files:
                if files_scanned >= max_files:
                    files_skipped += 1
                    continue
                fp = os.path.join(root, fname)
                # Only scan text-like files
                ext = Path(fname).suffix.lower()
                if ext in (".jpg", ".png", ".gif", ".pdf", ".mp4", ".mp3",
                          ".woff", ".woff2", ".ttf", ".ico"):
                    files_skipped += 1
                    continue
                result = scan_file(fp)
                if result.get("finding_count", 0) > 0 or result.get("error"):
                    # Rewrite file path to be relative to archive root
                    rel_path = os.path.relpath(fp, tmpdir)
                    result["file"] = rel_path
                    for f in result.get("findings", []):
                        f["file"] = rel_path
                    findings_per_file.append(result)
                files_scanned += 1

    except Exception as e:
        log.error("archive_scan_failed", archive=archive_path, error=str(e))
        return {"error": str(e), "files_scanned": files_scanned}

    # Aggregate
    total_findings = sum(r.get("finding_count", 0) for r in findings_per_file)
    all_severities = {
        "critical": sum(r.get("severity_breakdown", {}).get("critical", 0) for r in findings_per_file),
        "high":     sum(r.get("severity_breakdown", {}).get("high", 0) for r in findings_per_file),
        "medium":   sum(r.get("severity_breakdown", {}).get("medium", 0) for r in findings_per_file),
        "low":      sum(r.get("severity_breakdown", {}).get("low", 0) for r in findings_per_file),
    }
    
    # Determine overall verdict
    if all_severities["critical"] > 0:
        verdict = "MALICIOUS"
        max_severity = "CRITICAL"
    elif all_severities["high"] > 0:
        verdict = "SUSPICIOUS"
        max_severity = "HIGH"
    elif all_severities["medium"] > 0:
        verdict = "SUSPICIOUS"
        max_severity = "MEDIUM"
    else:
        verdict = "CLEAN"
        max_severity = "LOW" if all_severities["low"] > 0 else "NONE"

    return {
        "archive":          archive_path,
        "files_scanned":    files_scanned,
        "files_with_findings": len(findings_per_file),
        "files_skipped":    files_skipped,
        "total_findings":   total_findings,
        "verdict":          verdict,
        "max_severity":     max_severity,
        "severity_totals":  all_severities,
        "findings_per_file": findings_per_file,
        "extract_dir":      tmpdir,
    }
