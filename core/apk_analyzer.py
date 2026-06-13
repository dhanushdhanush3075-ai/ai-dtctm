"""
AI-DTCTM | APK Analyzer (v21 — Day 3 Part 2a)
══════════════════════════════════════════════════════════════════════
User uploads .apk → we:
  1. Clone to sandbox
  2. Decompile with androguard (Python-native, no Java needed)
  3. Parse AndroidManifest.xml → permissions, activities, services
  4. Scan all strings for malware patterns, hardcoded secrets, C2 URLs
  5. Hash the APK → lookup against MalwareBazaar
  6. Optionally: rebuild cleaned APK with dangerous permissions stripped
     (requires apktool + Java — user-side install; fallback to scan-only)
  7. Return full forensic report

INSTALLABLE OUTPUT:
  - Original APK preserved (user can download back)
  - Cleaned APK: dangerous permissions removed from manifest, malicious
    classes noted. User can install cleaned APK on their phone (Android
    will prompt for "install from unknown sources" — normal for modified
    APKs).

DEPENDENCIES:
  - androguard (pip) — REQUIRED, does everything in pure Python
  - apktool.jar (optional) — for cleaned rebuild; if missing, scan-only

USAGE:
  from core.apk_analyzer import analyze_apk
  result = analyze_apk("/path/to/user_upload.apk")
"""
from __future__ import annotations

import datetime
import hashlib
import os
import re
import secrets
import shutil
import subprocess
import zipfile
from pathlib import Path
from typing import Optional

from config import CFG
from core.logger import get_logger

log = get_logger(__name__)


# ── Androguard availability ───────────────────────────────────────
try:
    from androguard.core.apk import APK
    _ANDROGUARD_AVAILABLE = True
except ImportError:
    _ANDROGUARD_AVAILABLE = False


# ── Dangerous Android permissions ─────────────────────────────────
# Flagged when app requests these, especially in combinations.
DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS":              ("HIGH",     "SMS reading — spyware pattern"),
    "android.permission.SEND_SMS":              ("HIGH",     "SMS sending — premium rate fraud"),
    "android.permission.RECEIVE_SMS":           ("MEDIUM",   "Intercepts incoming SMS — OTP theft risk"),
    "android.permission.READ_CALL_LOG":         ("MEDIUM",   "Call log access"),
    "android.permission.WRITE_CALL_LOG":        ("HIGH",     "Modifies call log — evidence tampering"),
    "android.permission.READ_CONTACTS":         ("MEDIUM",   "Contacts harvesting"),
    "android.permission.WRITE_CONTACTS":        ("HIGH",     "Contacts modification"),
    "android.permission.RECORD_AUDIO":          ("HIGH",     "Microphone access — surveillance risk"),
    "android.permission.CAMERA":                ("MEDIUM",   "Camera access"),
    "android.permission.ACCESS_FINE_LOCATION":  ("MEDIUM",   "GPS tracking"),
    "android.permission.ACCESS_COARSE_LOCATION":("LOW",      "Cell-tower location"),
    "android.permission.SYSTEM_ALERT_WINDOW":   ("HIGH",     "Overlay — phishing / clickjack vector"),
    "android.permission.BIND_ACCESSIBILITY_SERVICE":("CRITICAL","Accessibility abuse — banker trojan pattern"),
    "android.permission.BIND_DEVICE_ADMIN":     ("CRITICAL","Device admin — uninstall-resistant malware"),
    "android.permission.REQUEST_INSTALL_PACKAGES":("HIGH",   "Can install other APKs"),
    "android.permission.QUERY_ALL_PACKAGES":    ("MEDIUM",   "Enumerates installed apps"),
    "android.permission.READ_EXTERNAL_STORAGE": ("LOW",      "File access"),
    "android.permission.WRITE_EXTERNAL_STORAGE":("LOW",      "File modification"),
    "android.permission.INTERNET":              ("LOW",      "Network access"),
}

# Permission combos that indicate malware
MALWARE_COMBOS = [
    (["READ_SMS", "INTERNET"],
     "CRITICAL", "SMS reading + internet = data exfiltration (banker trojan / OTP stealer)"),
    (["RECEIVE_SMS", "INTERNET"],
     "HIGH", "SMS interception + internet = OTP theft"),
    (["BIND_ACCESSIBILITY_SERVICE", "INTERNET"],
     "CRITICAL", "Accessibility + network = banker trojan pattern"),
    (["RECORD_AUDIO", "INTERNET", "ACCESS_FINE_LOCATION"],
     "CRITICAL", "Mic + location + network = stalkerware"),
    (["READ_CONTACTS", "SEND_SMS", "INTERNET"],
     "HIGH", "Contacts + SMS + network = SMS worm"),
    (["BIND_DEVICE_ADMIN", "REQUEST_INSTALL_PACKAGES"],
     "CRITICAL", "Device admin + installer = persistent malware"),
]


# ── Suspicious strings (decompiled code + resources) ──────────────
SUSPICIOUS_STRING_PATTERNS = [
    (r"http://[a-z0-9\-]+\.(tk|ml|ga|gq|cf|xyz|top)/", "HIGH", "Suspicious-TLD URL"),
    (r"\bAIza[0-9A-Za-z\-_]{35}\b",                    "HIGH", "Google API key exposed"),
    (r"AKIA[0-9A-Z]{16}",                              "CRITICAL", "AWS Access Key exposed"),
    (r"[0-9a-f]{32}-us[0-9]{1,2}",                     "HIGH", "Mailchimp API key"),
    (r"ghp_[A-Za-z0-9]{36}",                           "CRITICAL", "GitHub token exposed"),
    (r"xox[baprs]-[0-9a-zA-Z\-]{10,}",                 "HIGH", "Slack token exposed"),
    (r"-----BEGIN (RSA|DSA|EC|PRIVATE) KEY-----",      "CRITICAL", "Private key embedded"),
    (r"sk_live_[0-9a-zA-Z]{24,}",                      "CRITICAL", "Stripe live secret key"),
    (r"firebaseio\.com",                               "MEDIUM", "Firebase endpoint — check rules"),
    (r"[^\w]password\s*[=:]\s*['\"][^'\"]{4,}['\"]",   "MEDIUM", "Hardcoded password string"),
    (r"base64_decode\s*\(.*?eval",                     "CRITICAL", "Obfuscated JS code execution"),
    (r"Runtime\.getRuntime\(\)\.exec",                 "HIGH", "Runtime exec — RCE pattern"),
    (r"Cipher\.getInstance\s*\(\s*['\"](DES|RC4)",     "MEDIUM", "Weak cipher algorithm"),
    (r"SSLContext\.getInstance\s*\(\s*['\"]SSL",       "MEDIUM", "Deprecated SSL protocol"),
    (r"TrustManager.*checkServerTrusted.*return",      "HIGH", "Certificate validation bypass"),
]


# ── Sandbox ───────────────────────────────────────────────────────
SANDBOX_ROOT = Path(getattr(CFG, "DATA_DIR", Path(__file__).parent.parent / "data")) / "apk_clones"


def _now_iso() -> str:
    return datetime.datetime.utcnow().isoformat(timespec="milliseconds") + "Z"


# ══════════════════════════════════════════════════════════════════
# MAIN ANALYZE
# ══════════════════════════════════════════════════════════════════
def analyze_apk(apk_path: str, case_id: Optional[str] = None) -> dict:
    """
    Full APK forensic analysis pipeline.
    
    Returns:
      {
        "status":         "complete" | "error",
        "clone_id":       "apk_abc123",
        "sandbox_dir":    "/path/to/sandbox/apk_abc123/",
        "metadata":       {package, version, size, sha256, ...},
        "permissions":    [{name, severity, description}, ...],
        "permission_combos": [...],
        "activities":     [...],
        "services":       [...],
        "suspicious_strings": [...],
        "hash_verdict":   {"mb_match": bool, "family": str, ...},
        "cleaned_apk_path": "/path/to/cleaned.apk" or None,
        "severity":       "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "CLEAN",
        "score":          0-10,
        "summary":        "..."
      }
    """
    if not _ANDROGUARD_AVAILABLE:
        # androguard (or its lxml DLL) unavailable on this host → use the
        # dependency-free zip+regex analyzer. Still a real forensic report.
        return _analyze_apk_lite(apk_path, case_id)

    started = _now_iso()
    clone_id = f"apk_{secrets.token_hex(3)}"
    sandbox_dir = SANDBOX_ROOT / clone_id
    sandbox_dir.mkdir(parents=True, exist_ok=True)

    # ── 1. Clone APK to sandbox ───────────────────────────────────
    clone_path = sandbox_dir / "original.apk"
    try:
        shutil.copy2(apk_path, clone_path)
    except Exception as e:
        return {"status": "error", "error": f"Failed to clone APK: {e}",
                "clone_id": clone_id}

    # ── 2. Compute hash ───────────────────────────────────────────
    with open(clone_path, "rb") as f:
        data = f.read()
        sha256 = hashlib.sha256(data).hexdigest()
        md5    = hashlib.md5(data).hexdigest()
        size   = len(data)

    # ── 3. Parse with androguard ──────────────────────────────────
    try:
        apk = APK(str(clone_path))
    except Exception as e:
        log.error("apk_parse_failed", error=str(e))
        return {"status": "error", "error": f"APK parse failed: {e}",
                "clone_id": clone_id}

    metadata = {
        "package":         apk.get_package(),
        "app_name":        apk.get_app_name() or "unknown",
        "version_name":    apk.get_androidversion_name() or "",
        "version_code":    apk.get_androidversion_code() or "",
        "min_sdk":         apk.get_min_sdk_version() or "",
        "target_sdk":      apk.get_target_sdk_version() or "",
        "size_bytes":      size,
        "sha256":          sha256,
        "md5":             md5,
        "signed":          apk.is_signed(),
    }

    # ── 4. Permissions audit ──────────────────────────────────────
    requested_perms = apk.get_permissions() or []
    perm_findings = []
    for p in requested_perms:
        if p in DANGEROUS_PERMISSIONS:
            sev, desc = DANGEROUS_PERMISSIONS[p]
            perm_findings.append({
                "name":        p,
                "severity":    sev,
                "description": desc,
            })

    # Permission combo analysis
    perm_short = {p.split(".")[-1] for p in requested_perms}
    combo_findings = []
    for combo, sev, msg in MALWARE_COMBOS:
        if all(c in perm_short for c in combo):
            combo_findings.append({
                "combo":       combo,
                "severity":    sev,
                "description": msg,
            })

    # ── 5. Components ─────────────────────────────────────────────
    try:
        activities = apk.get_activities() or []
        services   = apk.get_services() or []
        receivers  = apk.get_receivers() or []
    except Exception:
        activities, services, receivers = [], [], []

    # ── 6. Extract strings + scan for suspicious patterns ─────────
    suspicious_strings = _scan_apk_strings(clone_path)

    # ── 7. Hash reputation (MalwareBazaar) ────────────────────────
    hash_verdict = {"mb_match": False, "family": None, "error": None}
    try:
        from core.api_clients import malware_bazaar
        mb_result = malware_bazaar.lookup_hash(sha256)
        if mb_result.get("available") and mb_result.get("detail"):
            d = mb_result["detail"]
            hash_verdict = {
                "mb_match":      d.get("found", False),
                "family":        d.get("signature"),
                "threat_type":   d.get("file_type"),
                "first_seen":    d.get("first_seen"),
                "tags":          d.get("tags", []),
            }
    except Exception as e:
        hash_verdict["error"] = str(e)

    # ── 8. Attempt cleaned rebuild (best-effort) ──────────────────
    cleaned_apk_path = None
    clean_result = _attempt_cleaned_rebuild(
        sandbox_dir,
        clone_path,
        perm_findings,
        combo_findings,
    )
    if clean_result.get("success"):
        cleaned_apk_path = clean_result["cleaned_path"]

    # ── 9. Score + severity ───────────────────────────────────────
    score, severity = _compute_severity(
        perm_findings, combo_findings, suspicious_strings, hash_verdict
    )

    # ── 10. Summary ───────────────────────────────────────────────
    summary_bits = []
    if hash_verdict.get("mb_match"):
        summary_bits.append(f"KNOWN MALWARE ({hash_verdict.get('family')})")
    if combo_findings:
        summary_bits.append(f"{len(combo_findings)} malware permission combo(s)")
    crit_perms = [p for p in perm_findings if p["severity"] == "CRITICAL"]
    if crit_perms:
        summary_bits.append(f"{len(crit_perms)} critical permission(s)")
    if suspicious_strings:
        crit_strings = [s for s in suspicious_strings if s["severity"] in ("CRITICAL", "HIGH")]
        if crit_strings:
            summary_bits.append(f"{len(crit_strings)} hardcoded secret(s)/suspicious string(s)")
    summary = " · ".join(summary_bits) if summary_bits else "No significant findings"

    return {
        "status":              "complete",
        "clone_id":            clone_id,
        "sandbox_dir":         str(sandbox_dir),
        "original_apk_path":   str(clone_path),
        "cleaned_apk_path":    str(cleaned_apk_path) if cleaned_apk_path else None,
        "cleaning_note":       clean_result.get("note"),
        "metadata":            metadata,
        "permissions":         perm_findings,
        "permission_combos":   combo_findings,
        "all_permissions":     requested_perms,
        "activities":          activities[:20],
        "services":            services[:20],
        "receivers":           receivers[:20],
        "suspicious_strings":  suspicious_strings,
        "hash_verdict":        hash_verdict,
        "severity":            severity,
        "score":               score,
        "summary":             summary,
        "started_at":          started,
        "finished_at":         _now_iso(),
        "case_id":             case_id,
    }


# ══════════════════════════════════════════════════════════════════
# LIGHTWEIGHT ANALYZER (no androguard — pure zip + regex on the bytes)
# ══════════════════════════════════════════════════════════════════
_LITE_PERM_RE = re.compile(rb"android\.permission\.([A-Z_]+)")
_LITE_COMP_RE = re.compile(rb"([A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+)")

def _analyze_apk_lite(apk_path: str, case_id: Optional[str] = None) -> dict:
    """Dependency-free APK analysis: permissions, combos, components, strings."""
    started = _now_iso()
    clone_id = f"apk_{secrets.token_hex(3)}"
    sandbox_dir = SANDBOX_ROOT / clone_id
    sandbox_dir.mkdir(parents=True, exist_ok=True)
    clone_path = sandbox_dir / "original.apk"

    try:
        shutil.copy2(apk_path, clone_path)
    except Exception as e:
        return {"status": "error", "error": f"Failed to clone APK: {e}",
                "clone_id": clone_id}

    if not zipfile.is_zipfile(clone_path):
        return {"status": "error", "error": "Not a valid APK (zip) file",
                "clone_id": clone_id}

    raw = clone_path.read_bytes()
    sha256 = hashlib.sha256(raw).hexdigest()
    md5    = hashlib.md5(raw).hexdigest()
    size   = len(raw)

    permissions: set[str] = set()
    package = ""
    activities: set[str] = set()
    services: set[str] = set()
    receivers: set[str] = set()
    dex_count = 0
    native_libs: list[str] = []

    try:
        with zipfile.ZipFile(clone_path, "r") as z:
            names = z.namelist()
            for n in names:
                low = n.lower()
                if low.endswith(".dex"):
                    dex_count += 1
                elif low.endswith(".so"):
                    native_libs.append(n.split("/")[-1])
            blob = b""
            for cand in ("AndroidManifest.xml", "resources.arsc"):
                try:
                    blob += z.read(cand)
                except KeyError:
                    pass
            # Binary AXML stores strings as UTF-16LE (a\x00n\x00d\x00…).
            # Strip null bytes so ASCII regex matches both UTF-8 and UTF-16.
            blob_ascii = blob.replace(b"\x00", b"")
            for src in (blob, blob_ascii):
                for pm in _LITE_PERM_RE.findall(src):
                    permissions.add("android.permission." + pm.decode("ascii", "ignore"))
                # Component class names (best-effort from manifest strings)
                for cm in _LITE_COMP_RE.findall(src)[:6000]:
                    s = cm.decode("ascii", "ignore")
                    if s.endswith("Activity"):   activities.add(s)
                    elif s.endswith("Service"):  services.add(s)
                    elif s.endswith("Receiver"): receivers.add(s)
            # package name = most common reversed-domain prefix among components
            comps = list(activities | services | receivers)
            if comps:
                pkgs = [".".join(c.split(".")[:-1]) for c in comps if "." in c]
                if pkgs:
                    package = max(set(pkgs), key=pkgs.count)
    except Exception as e:
        log.warning("apk_lite_unpack_failed", error=str(e))

    metadata = {
        "package":      package or "(binary manifest — package not extracted)",
        "app_name":     "unknown",
        "version_name": "",
        "version_code": "",
        "min_sdk":      "",
        "target_sdk":   "",
        "size_bytes":   size,
        "sha256":       sha256,
        "md5":          md5,
        "signed":       any(n.upper().startswith("META-INF/") and
                            n.upper().endswith((".RSA", ".DSA", ".EC"))
                            for n in zipfile.ZipFile(clone_path).namelist()),
        "dex_count":    dex_count,
        "native_libs":  native_libs[:20],
        "engine":       "lite (zip+regex, no androguard)",
    }

    # Permissions audit
    perm_findings = []
    for p in sorted(permissions):
        if p in DANGEROUS_PERMISSIONS:
            sev, desc = DANGEROUS_PERMISSIONS[p]
            perm_findings.append({"name": p, "severity": sev, "description": desc})

    perm_short = {p.split(".")[-1] for p in permissions}
    combo_findings = []
    for combo, sev, msg in MALWARE_COMBOS:
        if all(c in perm_short for c in combo):
            combo_findings.append({"combo": combo, "severity": sev, "description": msg})

    suspicious_strings = _scan_apk_strings(clone_path)

    # Hash reputation (best-effort)
    hash_verdict = {"mb_match": False, "family": None, "error": None}
    try:
        from core.api_clients import malware_bazaar
        mb = malware_bazaar.lookup_hash(sha256)
        if mb.get("available") and mb.get("detail"):
            d = mb["detail"]
            hash_verdict = {"mb_match": d.get("found", False),
                            "family": d.get("signature"),
                            "tags": d.get("tags", [])}
    except Exception as e:
        hash_verdict["error"] = str(e)

    score, severity = _compute_severity(
        perm_findings, combo_findings, suspicious_strings, hash_verdict)

    bits = []
    if combo_findings:
        bits.append(f"{len(combo_findings)} malware permission combo(s)")
    crit = [p for p in perm_findings if p["severity"] in ("CRITICAL", "HIGH")]
    if crit:
        bits.append(f"{len(crit)} high-risk permission(s)")
    if suspicious_strings:
        bits.append(f"{len(suspicious_strings)} suspicious string(s)")
    summary = " · ".join(bits) if bits else "No significant findings"

    return {
        "status":            "complete",
        "clone_id":          clone_id,
        "sandbox_dir":       str(sandbox_dir),
        "original_apk_path": str(clone_path),
        "cleaned_apk_path":  None,
        "cleaning_note":     "lite engine — cleaned rebuild needs androguard+apktool",
        "metadata":          metadata,
        "permissions":       perm_findings,
        "permission_combos": combo_findings,
        "all_permissions":   sorted(permissions),
        "activities":        sorted(activities)[:20],
        "services":          sorted(services)[:20],
        "receivers":         sorted(receivers)[:20],
        "suspicious_strings": suspicious_strings,
        "hash_verdict":      hash_verdict,
        "severity":          severity,
        "score":             score,
        "summary":           summary,
        "started_at":        started,
        "finished_at":       _now_iso(),
        "case_id":           case_id,
    }


# ══════════════════════════════════════════════════════════════════
# INTERNAL HELPERS
# ══════════════════════════════════════════════════════════════════
def _scan_apk_strings(apk_path: Path, max_strings: int = 50000) -> list[dict]:
    """Extract strings from APK and match against suspicious patterns."""
    findings = []
    try:
        with zipfile.ZipFile(apk_path, "r") as z:
            # Scan classes.dex (primary code) and resources.arsc
            for name in z.namelist():
                if not (name.endswith(".dex") or name.endswith(".xml")
                        or name.endswith(".arsc")):
                    continue
                try:
                    raw = z.read(name)
                except Exception:
                    continue

                # Extract ASCII strings (4+ chars)
                try:
                    text = raw.decode("utf-8", errors="ignore")
                except Exception:
                    continue

                for pattern, severity, description in SUSPICIOUS_STRING_PATTERNS:
                    for match in re.finditer(pattern, text)[:max_strings] \
                                 if hasattr(re.finditer(pattern, text), "__getitem__") \
                                 else list(re.finditer(pattern, text))[:20]:
                        findings.append({
                            "file":        name,
                            "severity":    severity,
                            "description": description,
                            "match":       match.group(0)[:120],
                        })
                        if len(findings) >= 200:
                            return findings
    except Exception as e:
        log.warning("apk_string_scan_failed", error=str(e))

    return findings


def _attempt_cleaned_rebuild(sandbox: Path, original: Path,
                             perm_findings: list, combo_findings: list) -> dict:
    """
    Try to produce a cleaned APK by removing dangerous permissions.
    Uses apktool if available (Java + apktool.jar in tools/), else falls
    back to 'scan-only' (no cleaned binary produced).
    """
    tools_dir = Path(__file__).parent.parent / "tools"
    apktool_jar = tools_dir / "apktool.jar"
    java_available = shutil.which("java") is not None

    if not apktool_jar.exists() or not java_available:
        return {
            "success": False,
            "note": (
                "Cleaned APK generation requires apktool.jar + Java. "
                "Scan-only mode active. To enable cleaning: "
                "(1) Install Java 17+, (2) download apktool.jar from "
                "https://bitbucket.org/iBotPeaches/apktool, "
                "(3) place at project/tools/apktool.jar"
            ),
        }

    try:
        decoded_dir = sandbox / "decoded"
        # apktool d -f -o decoded original.apk
        r = subprocess.run(
            ["java", "-jar", str(apktool_jar), "d", "-f",
             "-o", str(decoded_dir), str(original)],
            capture_output=True, text=True, timeout=60,
        )
        if r.returncode != 0:
            return {"success": False,
                    "note": f"apktool decode failed: {r.stderr[:200]}"}

        # Strip dangerous permissions from AndroidManifest.xml
        manifest_path = decoded_dir / "AndroidManifest.xml"
        if manifest_path.exists():
            content = manifest_path.read_text(encoding="utf-8", errors="ignore")
            removed = 0
            critical_perms = [p["name"] for p in perm_findings
                              if p["severity"] in ("CRITICAL", "HIGH")]
            for perm in critical_perms:
                pattern = rf'<uses-permission\s+android:name="{re.escape(perm)}"[^/]*/>'
                new_content, n = re.subn(pattern, "", content)
                if n > 0:
                    content = new_content
                    removed += n
            manifest_path.write_text(content, encoding="utf-8")

        # Rebuild
        cleaned_path = sandbox / "cleaned.apk"
        r2 = subprocess.run(
            ["java", "-jar", str(apktool_jar), "b", str(decoded_dir),
             "-o", str(cleaned_path)],
            capture_output=True, text=True, timeout=90,
        )
        if r2.returncode != 0 or not cleaned_path.exists():
            return {"success": False,
                    "note": f"apktool rebuild failed: {r2.stderr[:200]}"}

        return {
            "success": True,
            "cleaned_path": cleaned_path,
            "note": "Cleaned APK built. Must be re-signed before installation "
                    "(use jarsigner). Android will show 'unknown developer' warning.",
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "note": "apktool timed out"}
    except Exception as e:
        return {"success": False, "note": f"Cleaning error: {e}"}


def _compute_severity(perm_findings, combo_findings,
                      suspicious_strings, hash_verdict) -> tuple[float, str]:
    """Aggregate findings into 0-10 score + severity label."""
    score = 0.0

    # Known malware → instant CRITICAL
    if hash_verdict.get("mb_match"):
        return 10.0, "CRITICAL"

    # Permission combos
    for c in combo_findings:
        if c["severity"] == "CRITICAL":
            score = max(score, 8.5)
        elif c["severity"] == "HIGH":
            score = max(score, 7.0)

    # Individual permissions
    crit_count = sum(1 for p in perm_findings if p["severity"] == "CRITICAL")
    high_count = sum(1 for p in perm_findings if p["severity"] == "HIGH")
    med_count  = sum(1 for p in perm_findings if p["severity"] == "MEDIUM")

    score = max(score, crit_count * 2.5 + high_count * 1.2 + med_count * 0.4)

    # Suspicious strings
    crit_str = sum(1 for s in suspicious_strings if s["severity"] == "CRITICAL")
    high_str = sum(1 for s in suspicious_strings if s["severity"] == "HIGH")
    score = max(score, crit_str * 2.0 + high_str * 0.8)

    score = min(score, 10.0)

    if score >= 8.0:
        severity = "CRITICAL"
    elif score >= 5.5:
        severity = "HIGH"
    elif score >= 3.0:
        severity = "MEDIUM"
    elif score >= 1.0:
        severity = "LOW"
    else:
        severity = "CLEAN"

    return round(score, 2), severity
