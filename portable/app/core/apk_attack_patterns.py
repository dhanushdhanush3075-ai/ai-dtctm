"""
AI-DTCTM | APK Attack Pattern Analyser
════════════════════════════════════════════════════════════════════════
Static-analysis attacks against the APK twin.
APKs are Android binaries — they can't run in a web container.
Instead we perform 30 attack patterns on the ALREADY-EXTRACTED data:
  - AndroidManifest.xml  (permissions, components, exported flags)
  - DEX string dump       (hardcoded secrets, URLs, keys)
  - native .so libs       (arch, dangerous symbols)

Each pattern has:
  id        - short snake_case key
  label     - display name
  what      - one sentence: what the attacker learns/does
  category  - one of: component | permission | data | crypto | network | privacy
  severity  - CRITICAL / HIGH / MEDIUM / LOW / INFO
"""
from __future__ import annotations

import re
from pathlib import Path


# ═══════════════════════════════════════════════════════════════════════
#  30 ATTACK PATTERNS (id, label, what, category, severity, check_fn)
# ═══════════════════════════════════════════════════════════════════════

def _check_exported_activity(manifest: str, **_) -> tuple[bool, str]:
    """Exported Activity with no permission — any app can launch it."""
    hits = re.findall(
        r'<activity[^>]+android:exported=["\']true["\'][^>]*>',
        manifest, re.I | re.S,
    )
    unprotected = [h for h in hits if "permission" not in h.lower()]
    if unprotected:
        names = re.findall(r'android:name=["\']([^"\']+)["\']', unprotected[0])
        return True, f"Exported activity: {names[0] if names else 'unknown'}"
    return False, "No unprotected exported activities"


def _check_exported_service(manifest: str, **_) -> tuple[bool, str]:
    """Exported Service — remote binding attack surface."""
    hits = re.findall(
        r'<service[^>]+android:exported=["\']true["\'][^>]*',
        manifest, re.I | re.S,
    )
    if hits:
        names = re.findall(r'android:name=["\']([^"\']+)["\']', hits[0])
        return True, f"{len(hits)} exported service(s) — first: {names[0] if names else '?'}"
    return False, "No exported services"


def _check_exported_receiver(manifest: str, **_) -> tuple[bool, str]:
    """Exported BroadcastReceiver — intent injection / privilege abuse."""
    hits = re.findall(
        r'<receiver[^>]+android:exported=["\']true["\'][^>]*',
        manifest, re.I | re.S,
    )
    if hits:
        return True, f"{len(hits)} exported receiver(s) found"
    return False, "No exported receivers"


def _check_exported_provider(manifest: str, **_) -> tuple[bool, str]:
    """Exported ContentProvider without readPermission — data theft."""
    hits = re.findall(
        r'<provider[^>]+android:exported=["\']true["\'](?![^>]*readPermission)[^>]*',
        manifest, re.I | re.S,
    )
    if hits:
        return True, f"{len(hits)} ContentProvider(s) exported without readPermission"
    return False, "ContentProviders protected or not exported"


def _check_debuggable(manifest: str, **_) -> tuple[bool, str]:
    """android:debuggable=true — ADB shell access to any device."""
    if re.search(r'android:debuggable=["\']true["\']', manifest, re.I):
        return True, "App is DEBUGGABLE — attacker gets ADB shell, heap dumps, code injection"
    return False, "debuggable not set (defaults to false)"


def _check_backup_allowed(manifest: str, **_) -> tuple[bool, str]:
    """android:allowBackup=true — adb backup extracts all app data."""
    if re.search(r'android:allowBackup=["\']true["\']', manifest, re.I):
        return True, "Backup allowed — `adb backup -f app.ab com.example` extracts DB, SharedPrefs, files"
    return False, "Backup disabled"


def _check_cleartext_traffic(manifest: str, **_) -> tuple[bool, str]:
    """android:usesCleartextTraffic=true — HTTP in 2024, MitM trivial."""
    if re.search(r'usesCleartextTraffic=["\']true["\']', manifest, re.I):
        return True, "Cleartext HTTP traffic ALLOWED — network MitM intercepts all API calls"
    return False, "Cleartext traffic not explicitly allowed"


def _check_network_security_missing(manifest: str, **_) -> tuple[bool, str]:
    """No networkSecurityConfig — default allows cleartext on Android < 9."""
    if not re.search(r'networkSecurityConfig', manifest, re.I):
        return True, "networkSecurityConfig not set — cleartext may be allowed on Android < 9"
    return False, "Network security config present"


def _check_dangerous_perms(manifest: str, **_) -> tuple[bool, str]:
    """Dangerous permissions: SMS, CALL_LOG, READ_CONTACTS."""
    danger = [
        "READ_SMS", "RECEIVE_SMS", "SEND_SMS",
        "READ_CALL_LOG", "PROCESS_OUTGOING_CALLS",
        "READ_CONTACTS", "WRITE_CONTACTS",
        "RECORD_AUDIO", "CAMERA",
        "ACCESS_FINE_LOCATION", "ACCESS_BACKGROUND_LOCATION",
        "READ_PHONE_STATE", "READ_PHONE_NUMBERS",
    ]
    found = [p for p in danger if p in manifest]
    if found:
        return True, f"{len(found)} dangerous permissions: {', '.join(found[:5])}"
    return False, "No dangerous permissions found"


def _check_stalkerware_combo(manifest: str, **_) -> tuple[bool, str]:
    """SMS + LOCATION + CONTACTS + CALL_LOG = stalkerware fingerprint."""
    combos = {
        "SMS": "RECEIVE_SMS" in manifest or "READ_SMS" in manifest,
        "Location": "ACCESS_FINE_LOCATION" in manifest,
        "Contacts": "READ_CONTACTS" in manifest,
        "CallLog": "READ_CALL_LOG" in manifest,
        "Audio": "RECORD_AUDIO" in manifest,
    }
    active = [k for k, v in combos.items() if v]
    if len(active) >= 4:
        return True, f"STALKERWARE COMBO: {' + '.join(active)} — classic surveillance fingerprint"
    return False, f"Only {len(active)} stalkerware components active ({', '.join(active) or 'none'})"


def _check_hardcoded_keys(strings: list[str], **_) -> tuple[bool, str]:
    """Hardcoded API keys, tokens, secrets in DEX strings."""
    patterns = [
        (r"AIza[0-9A-Za-z\-_]{35}",           "Google API key"),
        (r"AKIA[0-9A-Z]{16}",                  "AWS Access Key"),
        (r"sk_live_[0-9a-zA-Z]{24}",           "Stripe live secret key"),
        (r"sk_test_[0-9a-zA-Z]{24}",           "Stripe test secret key"),
        (r"ghp_[A-Za-z0-9]{36}",               "GitHub Personal Access Token"),
        (r"-----BEGIN RSA PRIVATE KEY-----",   "RSA private key"),
        (r"-----BEGIN EC PRIVATE KEY-----",    "EC private key"),
        (r"['\"]secret['\"]:\s*['\"][^'\"]{8,}","Hardcoded 'secret' field"),
        (r"password\s*=\s*['\"][^'\"]{4,}",    "Hardcoded password in code"),
        (r"api_key\s*=\s*['\"][^'\"]{8,}",     "Hardcoded api_key in code"),
    ]
    hits = []
    for s in strings:
        for pat, label in patterns:
            if re.search(pat, s, re.I):
                hits.append(f"{label}: {s[:40]}…")
    if hits:
        return True, f"{len(hits)} hardcoded secret(s) found: {hits[0]}"
    return False, "No hardcoded secrets detected"


def _check_http_endpoints(strings: list[str], **_) -> tuple[bool, str]:
    """http:// URLs in DEX — cleartext API endpoints."""
    http = [s for s in strings if s.startswith("http://") and len(s) > 10]
    if http:
        return True, f"{len(http)} plaintext http:// endpoint(s) — first: {http[0][:60]}"
    return False, "No http:// API endpoints found"


def _check_ssl_bypass(strings: list[str], **_) -> tuple[bool, str]:
    """TrustManager accept-all or HostnameVerifier.ALLOW_ALL strings."""
    markers = [
        "ALLOW_ALL_HOSTNAME_VERIFIER",
        "TrustAllCerts",
        "checkClientTrusted",
        "X509Certificate[] chain",
        "hostnameVerifier",
        "SSLSocketFactory",
    ]
    found = [m for m in markers if any(m.lower() in s.lower() for s in strings)]
    if found:
        return True, f"SSL bypass indicators: {', '.join(found[:3])} — certificate pinning may be disabled"
    return False, "No SSL bypass patterns found"


def _check_root_detection(strings: list[str], **_) -> tuple[bool, str]:
    """Absence of root-detection strings — app has no root protection."""
    markers = ["RootBeer", "rootCheck", "isRooted", "su binary",
               "/system/xbin/su", "Superuser.apk", "com.noshufou.android.su"]
    found = any(any(m.lower() in s.lower() for s in strings) for m in markers)
    if not found:
        return True, "NO root detection — app runs on rooted devices without warning"
    return False, "Root detection present"


def _check_reflection_invoke(strings: list[str], **_) -> tuple[bool, str]:
    """Java reflection invoke — dynamic code loading / evasion."""
    markers = ["invoke", "getDeclaredMethod", "getDeclaredField",
               "Class.forName", "DexClassLoader", "PathClassLoader"]
    found = [m for m in markers if any(m in s for s in strings)]
    if len(found) >= 2:
        return True, f"Reflection/dynamic loading: {', '.join(found[:3])} — code may load remote payloads"
    return False, "No suspicious reflection patterns"


def _check_dynamic_code_load(strings: list[str], **_) -> tuple[bool, str]:
    """DexClassLoader with remote URL — downloads and runs attacker code."""
    if any("DexClassLoader" in s for s in strings):
        url_nearby = [s for s in strings if "http" in s.lower() and "dex" in s.lower()]
        return True, f"DexClassLoader found — can load remote .dex payloads. URLs: {url_nearby[:1]}"
    return False, "No DexClassLoader found"


def _check_intent_data_leak(manifest: str, **_) -> tuple[bool, str]:
    """Deeplink/intent-filter without validation — intent injection."""
    schemes = re.findall(r'<data[^>]+android:scheme=["\']([^"\']+)["\']', manifest, re.I)
    if schemes:
        return True, (f"Custom URL schemes: {schemes[:5]} — unvalidated deeplink parameters "
                      "can trigger intent injection or open arbitrary activities")
    return False, "No custom URL schemes"


def _check_implicit_intent(manifest: str, strings: list[str], **_) -> tuple[bool, str]:
    """Implicit intents can be hijacked by malicious apps."""
    if re.search(r'<intent-filter>', manifest, re.I):
        count = len(re.findall(r'<intent-filter>', manifest, re.I))
        return True, f"{count} intent-filter(s) — implicit intents interchangeable, hijackable by any app"
    return False, "No intent-filters found"


def _check_weak_crypto(strings: list[str], **_) -> tuple[bool, str]:
    """MD5 / SHA1 / DES / RC4 — broken crypto algorithms."""
    weak = {
        "MD5": ["MD5", "MessageDigest.getInstance(\"MD5\")"],
        "SHA1": ["SHA-1", "SHA1"],
        "DES": ["DES/ECB", "DESKeySpec"],
        "RC4": ["RC4", "ARCFOUR"],
        "ECB": ["AES/ECB"],   # ECB mode leaks patterns
    }
    found = [name for name, markers in weak.items()
             if any(any(m in s for s in strings) for m in markers)]
    if found:
        return True, f"Weak/broken crypto: {', '.join(found)} — data encrypted with these is crackable"
    return False, "No weak crypto algorithms detected"


def _check_sqlite_unencrypted(strings: list[str], **_) -> tuple[bool, str]:
    """Plain SQLite storage — DB file readable after adb backup."""
    if any("SQLiteDatabase" in s or ".db" in s.lower() for s in strings):
        if not any("SQLCipher" in s or "encrypt" in s.lower() for s in strings):
            return True, "Plain SQLite used — database file is unencrypted, extractable via adb backup"
    return False, "Encrypted DB (SQLCipher) or no SQLite usage"


def _check_world_readable(manifest: str, strings: list[str], **_) -> tuple[bool, str]:
    """MODE_WORLD_READABLE SharedPreferences — any app can read."""
    if any("MODE_WORLD_READABLE" in s or "MODE_WORLD_WRITEABLE" in s for s in strings):
        return True, "World-readable file mode — other installed apps can read this app's preferences"
    return False, "No world-readable file modes"


def _check_logging(strings: list[str], **_) -> tuple[bool, str]:
    """Log.d/Log.v in release build — leaks sensitive data to logcat."""
    log_calls = [s for s in strings if re.search(r'Log\.[dv]\(', s)]
    if len(log_calls) >= 3:
        return True, f"{len(log_calls)} verbose Log.d/Log.v calls — sensitive data in logcat on production builds"
    return False, "Minimal or no verbose logging"


def _check_external_storage(strings: list[str], **_) -> tuple[bool, str]:
    """External storage write — files readable by all apps pre-Android 10."""
    markers = ["getExternalStorageDirectory", "getExternalFilesDir",
               "WRITE_EXTERNAL_STORAGE", "Environment.DIRECTORY_"]
    found = [m for m in markers if any(m in s for s in strings)]
    if found:
        return True, f"External storage: {', '.join(found[:2])} — files world-readable on Android < 10"
    return False, "No external storage usage"


def _check_webview_js(manifest: str, strings: list[str], **_) -> tuple[bool, str]:
    """WebView with JavaScript enabled — XSS to native bridge attack."""
    js = any("setJavaScriptEnabled(true)" in s or "javascript" in s.lower() for s in strings)
    wb = any("WebView" in s for s in strings)
    if js and wb:
        bridge = any("addJavascriptInterface" in s for s in strings)
        detail = "addJavascriptInterface bridge present — JS can call native Java" if bridge else "JS enabled in WebView"
        return True, detail
    return False, "No WebView JS usage"


def _check_firebase_no_auth(strings: list[str], **_) -> tuple[bool, str]:
    """Firebase accessed without auth — database rules may be open."""
    if any("firebaseio.com" in s.lower() for s in strings):
        if not any("FirebaseAuth" in s for s in strings):
            return True, "Firebase used without FirebaseAuth — database may use open rules (.read=true)"
    return False, "Firebase not used or auth present"


def _check_third_party_sdks(strings: list[str], **_) -> tuple[bool, str]:
    """Third-party ad/analytics SDKs — data harvesting."""
    sdks = {
        "Facebook": "com.facebook",
        "Mixpanel": "com.mixpanel",
        "Adjust": "com.adjust",
        "AppsFlyer": "com.appsflyer",
        "Crashlytics": "com.crashlytics",
        "OneSignal": "com.onesignal",
    }
    found = [name for name, pkg in sdks.items() if any(pkg in s for s in strings)]
    if found:
        return True, f"Tracking SDKs: {', '.join(found)} — user data sent to third parties"
    return False, "No major tracking SDKs detected"


def _check_otp_in_response(strings: list[str], **_) -> tuple[bool, str]:
    """OTP/2FA code leaked in SMS/logcat."""
    markers = ["OTP", "one.time.password", "verification.code", "otp_code"]
    found = [s[:60] for s in strings if any(m.lower() in s.lower() for m in markers)]
    if found:
        return True, f"OTP-related strings — verify OTP isn't logged: {found[0]}"
    return False, "No OTP leak patterns"


def _check_private_key_in_apk(strings: list[str], **_) -> tuple[bool, str]:
    """Embedded private key / certificate."""
    pem_markers = ["BEGIN PRIVATE KEY", "BEGIN RSA PRIVATE KEY",
                   "BEGIN EC PRIVATE KEY", "BEGIN CERTIFICATE"]
    found = [m for m in pem_markers if any(m in s for s in strings)]
    if found:
        return True, f"EMBEDDED PRIVATE KEY: {found[0]} — attacker extracts private key from APK"
    return False, "No embedded private keys"


def _check_hardcoded_urls(strings: list[str], **_) -> tuple[bool, str]:
    """Hardcoded server URLs — leaks internal infrastructure."""
    urls = [s for s in strings if re.match(r"https?://[a-zA-Z0-9.\-]+(:\d+)?/", s) and len(s) < 120]
    internal = [u for u in urls if any(k in u for k in ("internal", "staging", "dev.", "192.168", "10.0.", "localhost"))]
    if internal:
        return True, f"{len(internal)} internal/staging URL(s): {internal[0][:60]}"
    return False, f"{len(urls)} URLs found — no internal endpoints detected"


# ── Attack pattern registry ───────────────────────────────────────────

ATTACK_PATTERNS: list[dict] = [
    # Component exposure
    {"id": "exported_activity",     "label": "Exported Activity (unprotected)",
     "category": "component",  "severity": "CRITICAL",
     "what": "Any app or Intent can launch this Activity — zero-click UI bypass",
     "check": _check_exported_activity},
    {"id": "exported_service",      "label": "Exported Service",
     "category": "component",  "severity": "HIGH",
     "what": "Remote apps can bind to this Service — privilege escalation vector",
     "check": _check_exported_service},
    {"id": "exported_receiver",     "label": "Exported BroadcastReceiver",
     "category": "component",  "severity": "HIGH",
     "what": "Attacker broadcasts Intents to trigger internal app actions",
     "check": _check_exported_receiver},
    {"id": "exported_provider",     "label": "ContentProvider — no readPermission",
     "category": "component",  "severity": "CRITICAL",
     "what": "Any app can query this ContentProvider — data theft via content://URI",
     "check": _check_exported_provider},
    {"id": "implicit_intent",       "label": "Implicit Intent Hijacking",
     "category": "component",  "severity": "MEDIUM",
     "what": "Implicit intents matched by any installed app — activity/data hijacking",
     "check": _check_implicit_intent},
    {"id": "intent_deeplink",       "label": "Deeplink / Custom URI Scheme",
     "category": "component",  "severity": "HIGH",
     "what": "Unvalidated deeplink params trigger intent injection or auth bypass",
     "check": _check_intent_data_leak},
    # Configuration weaknesses
    {"id": "debuggable",            "label": "Debuggable Flag ON",
     "category": "permission", "severity": "CRITICAL",
     "what": "ADB shell gives attacker full app sandbox — heap dump, code inject, file access",
     "check": _check_debuggable},
    {"id": "backup_allowed",        "label": "ADB Backup Enabled",
     "category": "permission", "severity": "HIGH",
     "what": "`adb backup` extracts entire app data — DB files, SharedPrefs, tokens",
     "check": _check_backup_allowed},
    {"id": "cleartext_traffic",     "label": "Cleartext HTTP Allowed",
     "category": "network",    "severity": "HIGH",
     "what": "API calls sent over plain HTTP — network MitM captures all traffic",
     "check": _check_cleartext_traffic},
    {"id": "no_network_security",   "label": "No Network Security Config",
     "category": "network",    "severity": "MEDIUM",
     "what": "Default policy on Android < 9 permits cleartext — API calls interceptable",
     "check": _check_network_security_missing},
    # Permissions
    {"id": "dangerous_perms",       "label": "Dangerous Permissions",
     "category": "permission", "severity": "HIGH",
     "what": "SMS/Camera/Contacts/Location permissions — data collection beyond app's function",
     "check": _check_dangerous_perms},
    {"id": "stalkerware_combo",     "label": "Stalkerware Permission Combo",
     "category": "permission", "severity": "CRITICAL",
     "what": "SMS + Location + Contacts + CallLog = textbook surveillance fingerprint",
     "check": _check_stalkerware_combo},
    # Data / secrets
    {"id": "hardcoded_keys",        "label": "Hardcoded API Keys / Secrets",
     "category": "data",       "severity": "CRITICAL",
     "what": "API keys, AWS credentials, JWT secrets extracted directly from APK with jadx",
     "check": _check_hardcoded_keys},
    {"id": "private_key_in_apk",   "label": "Embedded Private Key",
     "category": "crypto",     "severity": "CRITICAL",
     "what": "PEM private key shipped inside APK — attacker impersonates the server",
     "check": _check_private_key_in_apk},
    {"id": "http_endpoints",        "label": "Plaintext http:// API Endpoints",
     "category": "network",    "severity": "HIGH",
     "what": "Hardcoded http:// URLs expose backend infrastructure to MitM",
     "check": _check_http_endpoints},
    {"id": "hardcoded_urls",        "label": "Internal / Staging URLs",
     "category": "data",       "severity": "MEDIUM",
     "what": "Internal server addresses leak network topology — lateral movement map",
     "check": _check_hardcoded_urls},
    # Crypto
    {"id": "weak_crypto",           "label": "Weak / Broken Crypto (MD5, DES, ECB)",
     "category": "crypto",     "severity": "HIGH",
     "what": "MD5 hashes crackable in seconds; DES/RC4 broken; ECB leaks plaintext patterns",
     "check": _check_weak_crypto},
    {"id": "ssl_bypass",            "label": "SSL Certificate Bypass",
     "category": "crypto",     "severity": "CRITICAL",
     "what": "TrustAllCerts / ALLOW_ALL disables HTTPS verification — proxy intercepts all traffic",
     "check": _check_ssl_bypass},
    {"id": "sqlite_unencrypted",    "label": "Unencrypted SQLite Database",
     "category": "data",       "severity": "HIGH",
     "what": "Plain .db file extracted via adb backup — all app data readable in DB Browser",
     "check": _check_sqlite_unencrypted},
    # Runtime / privacy
    {"id": "root_detection",        "label": "No Root Detection",
     "category": "privacy",    "severity": "MEDIUM",
     "what": "App runs on rooted device — attacker uses Frida/Magisk to bypass all security checks",
     "check": _check_root_detection},
    {"id": "reflection_invoke",     "label": "Reflection / Dynamic Invoke",
     "category": "data",       "severity": "MEDIUM",
     "what": "Java reflection hides method calls from static analysis — evasion technique",
     "check": _check_reflection_invoke},
    {"id": "dynamic_code_load",     "label": "DexClassLoader (remote code load)",
     "category": "data",       "severity": "CRITICAL",
     "what": "App can download and execute arbitrary .dex from a remote URL at runtime",
     "check": _check_dynamic_code_load},
    {"id": "webview_js",            "label": "WebView JavaScript Bridge",
     "category": "data",       "severity": "HIGH",
     "what": "JavaScript in WebView can call native Java methods via addJavascriptInterface",
     "check": _check_webview_js},
    {"id": "world_readable",        "label": "World-Readable Files",
     "category": "privacy",    "severity": "HIGH",
     "what": "Any installed app reads this app's SharedPreferences or files",
     "check": _check_world_readable},
    {"id": "external_storage",      "label": "External Storage (SD card)",
     "category": "privacy",    "severity": "MEDIUM",
     "what": "Data on external storage is world-readable — any app accesses it",
     "check": _check_external_storage},
    {"id": "logging",               "label": "Verbose Logging in Release",
     "category": "privacy",    "severity": "MEDIUM",
     "what": "Log.d/v calls leak tokens, passwords, user data to Android logcat",
     "check": _check_logging},
    {"id": "firebase_no_auth",      "label": "Firebase Without Auth",
     "category": "network",    "severity": "HIGH",
     "what": "Firebase Realtime DB / Firestore may have open rules — anyone reads/writes",
     "check": _check_firebase_no_auth},
    {"id": "third_party_sdks",      "label": "Third-Party Analytics / Ad SDKs",
     "category": "privacy",    "severity": "MEDIUM",
     "what": "Facebook, Mixpanel, Adjust etc. track user behavior and send to third parties",
     "check": _check_third_party_sdks},
    {"id": "otp_leak",              "label": "OTP / 2FA Code Leak",
     "category": "privacy",    "severity": "HIGH",
     "what": "OTP codes logged to logcat or leaked in response — 2FA bypass",
     "check": _check_otp_in_response},
    {"id": "hardcoded_password",    "label": "Hardcoded Password in Source",
     "category": "data",       "severity": "CRITICAL",
     "what": "Literal password string in compiled DEX — jadx extracts in seconds",
     "check": lambda strings, **kw: (
         True,
         next((s[:60] for s in strings if re.search(r'(?i)password\s*=\s*["\'][^"\']{4,}', s)), None) or ""
     ) if any(re.search(r'(?i)password\s*=\s*["\'][^"\']{4,}', s) for s in strings) else (False, "No hardcoded passwords"),
    },
    {"id": "intent_redirection",    "label": "Intent Redirect / Task Hijack",
     "category": "component",  "severity": "HIGH",
     "what": "App passes Intent extras to startActivity without validation — task affinity hijack",
     "check": lambda manifest, strings, **kw: (
         True, "BROWSE/VIEW intent used with startActivity — unvalidated redirect"
     ) if (re.search(r'ACTION_VIEW|ACTION_BROWSE', manifest, re.I) and
           any("startActivity" in s for s in strings))
     else (False, "No unvalidated intent redirect detected"),
    },
]


# ═══════════════════════════════════════════════════════════════════════
#  PUBLIC API
# ═══════════════════════════════════════════════════════════════════════

_SEV_COLOR = {
    "CRITICAL": "#DC2626",
    "HIGH":     "#EA580C",
    "MEDIUM":   "#D97706",
    "LOW":      "#16A34A",
    "INFO":     "#0284C7",
}
_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
_SEV_DEDUCT = {"CRITICAL": 25, "HIGH": 12, "MEDIUM": 5, "LOW": 1, "INFO": 0}


def _load_apk_meta() -> dict:
    """Load attacker_cmd + how_to_fix from the JSON sample file (keyed by id_key)."""
    import json, os
    here = Path(__file__).parent
    sample = here / "data" / "attack_samples" / "apk_patterns_30.json"
    if not sample.exists():
        return {}
    try:
        data = json.loads(sample.read_text(encoding="utf-8"))
        return {entry["id_key"]: entry for entry in data}
    except Exception:
        return {}


def run_apk_attacks(manifest: str, strings: list[str]) -> dict:
    """
    Run all 30 attack patterns against extracted APK data.
    Returns:
      {
        "findings": [{"id","label","category","severity","color","what","triggered","detail",
                       "attacker_cmd","how_to_fix"}],
        "score": int,
        "label": "CRITICAL_RISK"|"HIGH_RISK"|"MODERATE"|"SECURED",
        "color": str,
        "by_severity": {"CRITICAL": n, ...},
      }
    """
    meta = _load_apk_meta()
    findings = []
    for pat in ATTACK_PATTERNS:
        try:
            triggered, detail = pat["check"](manifest=manifest, strings=strings)
        except Exception as exc:
            triggered, detail = False, f"check error: {exc}"

        m = meta.get(pat["id"], {})
        findings.append({
            "id":           pat["id"],
            "label":        pat["label"],
            "category":     pat["category"],
            "severity":     pat["severity"],
            "color":        _SEV_COLOR.get(pat["severity"], "#94A3B8"),
            "what":         pat["what"],
            "triggered":    triggered,
            "detail":       detail,
            "attacker_cmd": m.get("attacker_cmd", ""),
            "how_to_fix":   m.get("how_to_fix", ""),
        })

    findings.sort(key=lambda f: (_SEV_ORDER.get(f["severity"], 4), not f["triggered"]))

    score = 100
    by_sev: dict[str, int] = {}
    for f in findings:
        if f["triggered"]:
            score -= _SEV_DEDUCT.get(f["severity"], 0)
            by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
    score = max(0, score)

    if score >= 80:
        lbl, color = "SECURED",        "#16A34A"
    elif score >= 60:
        lbl, color = "MODERATE",       "#D97706"
    elif score >= 30:
        lbl, color = "HIGH RISK",      "#EA580C"
    else:
        lbl, color = "CRITICAL RISK",  "#DC2626"

    return {
        "findings":    findings,
        "score":       score,
        "label":       lbl,
        "color":       color,
        "by_severity": by_sev,
    }
