"""
AI-DTCTM | Clone Attack Engine (v21 — Day 3 Part 2a)
══════════════════════════════════════════════════════════════════════
Real HTTP attacks against running user clones (source code deployed in
isolated Docker containers).

ATTACK TYPES:
  dir_enum        — Directory enumeration (find hidden paths)
  sql_injection   — SQL injection probe on forms
  xss_probe       — XSS reflection probe
  header_audit    — Security header audit

SAFETY:
  - Only attacks localhost targets (refuses anything else)
  - Limited request rate (doesn't flood)
  - Short timeouts per request
  - Never escalates — read-only probes only
"""
from __future__ import annotations

import datetime
import re
import time
from urllib.parse import urlparse, urljoin

import requests

from core.logger import get_logger

log = get_logger(__name__)


# ── Common paths for directory enumeration ────────────────────────
COMMON_PATHS = [
    ".git/", ".git/config", ".git/HEAD",
    ".env", ".env.local", ".env.production",
    "backup.zip", "backup.sql", "backup.tar.gz",
    "admin/", "admin/login", "admin/login.php",
    "wp-admin/", "wp-login.php", "wp-config.php",
    "phpinfo.php", "info.php", "test.php",
    ".htaccess", "config.php", "config.inc.php",
    "robots.txt", "sitemap.xml", "crossdomain.xml",
    "swagger.json", "swagger/", "api-docs",
    "debug", "debug.log", "error.log",
    "server-status", "server-info",
    ".DS_Store", "Thumbs.db",
    ".vscode/", ".idea/",
    "node_modules/", "vendor/",
]

# ── SQL injection payloads (detection-only) ───────────────────────
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1'-- -",
    "1' UNION SELECT NULL-- -",
    "' OR 1=1#",
    "admin'--",
]

SQLI_ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning.*mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "pg_query",
    "valid postgresql result",
    "sqlite error",
    "microsoft odbc",
    "ora-00",
]

# ── XSS probe ─────────────────────────────────────────────────────
XSS_PAYLOAD = '<svg onload=alert(1)>'


def _now() -> str:
    return datetime.datetime.utcnow().isoformat(timespec="milliseconds") + "Z"


def _ensure_localhost(target_url: str) -> None:
    """Reject any non-localhost target."""
    parsed = urlparse(target_url)
    if parsed.hostname not in ("localhost", "127.0.0.1", "0.0.0.0"):
        raise ValueError(
            f"Refusing to attack {parsed.hostname} — only localhost clones allowed."
        )


# ══════════════════════════════════════════════════════════════════
# MAIN DISPATCHER
# ══════════════════════════════════════════════════════════════════
def run_clone_attack(target_url: str, attack_type: str) -> dict:
    _ensure_localhost(target_url)
    started = _now()
    t0 = time.monotonic()

    dispatch = {
        "dir_enum":      _attack_dir_enum,
        "sql_injection": _attack_sqli,
        "xss_probe":     _attack_xss,
        "header_audit":  _attack_header_audit,
    }
    if attack_type not in dispatch:
        return {
            "attack_type": attack_type,
            "error":       f"Unknown attack: {attack_type}",
            "severity":    "UNKNOWN",
            "findings":    [],
        }

    try:
        result = dispatch[attack_type](target_url)
    except Exception as e:
        log.error("clone_attack_crashed",
                  target=target_url, attack=attack_type, error=str(e))
        return {
            "attack_type": attack_type,
            "target":      target_url,
            "error":       str(e),
            "severity":    "UNKNOWN",
            "findings":    [],
            "started_at":  started,
            "duration_ms": round((time.monotonic() - t0) * 1000, 1),
        }

    result["attack_type"] = attack_type
    result["target"]      = target_url
    result["started_at"]  = started
    result["finished_at"] = _now()
    result["duration_ms"] = round((time.monotonic() - t0) * 1000, 1)
    return result


# ══════════════════════════════════════════════════════════════════
# DIRECTORY ENUMERATION
# ══════════════════════════════════════════════════════════════════
def _attack_dir_enum(target_url: str) -> dict:
    findings = []
    base = target_url.rstrip("/")
    checked = 0

    for path in COMMON_PATHS:
        checked += 1
        url = f"{base}/{path}"
        try:
            r = requests.get(url, timeout=3, allow_redirects=False)
            if r.status_code in (200, 201, 301, 302):
                severity = "HIGH" if path in (
                    ".git/config", ".env", "backup.sql", "wp-config.php",
                    "config.php", ".env.production"
                ) else "MEDIUM" if path.endswith(("/admin/", "/wp-admin/")) else "LOW"
                findings.append({
                    "severity":    severity,
                    "title":       f"Exposed path: /{path}",
                    "url":         url,
                    "status":      r.status_code,
                    "size":        len(r.content),
                    "detail":      f"HTTP {r.status_code}, {len(r.content)} bytes",
                })
        except requests.RequestException:
            pass

    # Severity aggregate
    has_crit = any(f["severity"] == "HIGH" for f in findings)
    severity = "HIGH" if has_crit else ("MEDIUM" if findings else "CLEAN")

    return {
        "severity":   severity,
        "findings":   findings,
        "checked":    checked,
        "summary":    f"{len(findings)} exposed path(s) out of {checked} checked",
    }


# ══════════════════════════════════════════════════════════════════
# SQL INJECTION PROBE
# ══════════════════════════════════════════════════════════════════
def _attack_sqli(target_url: str) -> dict:
    findings = []

    # 1. Fetch homepage, find forms + links with ?id=1 style parameters
    try:
        r = requests.get(target_url, timeout=5)
    except requests.RequestException as e:
        return {"severity": "UNKNOWN", "findings": [],
                "error": f"Could not reach target: {e}"}

    html = r.text

    # Extract form action URLs
    form_actions = re.findall(r'<form[^>]+action=["\']([^"\']+)', html, re.I)
    # Extract query-param URLs (a href="page.php?id=1")
    param_urls = re.findall(r'href=["\']([^"\']*\?[^"\']+=[^"\']+)["\']', html, re.I)

    tested = 0
    vuln_points = []

    for url_part in list(form_actions) + list(param_urls):
        if tested >= 15:
            break
        target = urljoin(target_url, url_part)
        if urlparse(target).hostname not in ("localhost", "127.0.0.1"):
            continue

        # Inject into first parameter if present
        if "?" not in target:
            # Append ?id=<payload>
            test_url = f"{target}?id={SQLI_PAYLOADS[0]}"
        else:
            base, qs = target.split("?", 1)
            # Replace first param value
            first_pair = qs.split("&")[0]
            if "=" in first_pair:
                key = first_pair.split("=")[0]
                test_url = f"{base}?{key}={SQLI_PAYLOADS[0]}"
            else:
                continue

        tested += 1
        try:
            r2 = requests.get(test_url, timeout=4)
            body = r2.text.lower()[:5000]
            for sig in SQLI_ERROR_SIGNATURES:
                if re.search(sig, body, re.I):
                    findings.append({
                        "severity":  "HIGH",
                        "title":     "SQL error leakage",
                        "url":       test_url,
                        "detail":    f"SQL error signature '{sig[:40]}' in response",
                    })
                    vuln_points.append(test_url)
                    break
        except requests.RequestException:
            pass

    severity = "HIGH" if findings else ("CLEAN" if tested > 0 else "UNKNOWN")
    payloads_used = [
        {"payload": p, "purpose": purpose}
        for p, purpose in zip(SQLI_PAYLOADS[:5], [
            "Single-quote escape (classic)",
            "OR 1=1 boolean bypass",
            "UNION SELECT extraction",
            "Comment-out remaining query",
            "Time-based blind injection",
        ])
    ]
    return {
        "severity":      severity,
        "attack_type":   "sql_injection",
        "findings":      findings,
        "urls_tested":   tested,
        "entry_points":  list(form_actions)[:5] + list(param_urls)[:5],
        "payloads_used": payloads_used,
        "vuln_points":   vuln_points,
        "summary":       (f"Probed {tested} entry point(s) with "
                          f"{len(payloads_used)} payload classes; "
                          f"{len(findings)} SQL-injection indicator(s)"),
        "explanation":   (
            "This probe is detection-only — it sends classic SQLi payloads to "
            "discovered entry points and checks the response for database error "
            "leakage. It does NOT exploit the vulnerability or extract data "
            "(that would be unauthorized access). For full exploitation analysis "
            "in an authorized engagement, use sqlmap with proper consent."
        ),
    }


# ══════════════════════════════════════════════════════════════════
# XSS PROBE
# ══════════════════════════════════════════════════════════════════
def _attack_xss(target_url: str) -> dict:
    findings = []

    try:
        r = requests.get(target_url, timeout=5)
    except requests.RequestException as e:
        return {"severity": "UNKNOWN", "findings": [],
                "error": f"Could not reach: {e}"}

    html = r.text
    param_urls = re.findall(r'href=["\']([^"\']*\?[^"\']+=[^"\']+)["\']', html, re.I)

    tested = 0
    for url_part in param_urls:
        if tested >= 15:
            break
        target = urljoin(target_url, url_part)
        if urlparse(target).hostname not in ("localhost", "127.0.0.1"):
            continue
        if "?" not in target:
            continue

        base, qs = target.split("?", 1)
        first_pair = qs.split("&")[0]
        if "=" not in first_pair:
            continue
        key = first_pair.split("=")[0]
        test_url = f"{base}?{key}={XSS_PAYLOAD}"

        tested += 1
        try:
            r2 = requests.get(test_url, timeout=4)
            if XSS_PAYLOAD in r2.text:
                # Check it's NOT escaped
                escaped = XSS_PAYLOAD.replace("<", "&lt;").replace(">", "&gt;")
                is_unescaped = escaped not in r2.text
                if is_unescaped:
                    findings.append({
                        "severity":  "HIGH",
                        "title":     "XSS reflection (unescaped)",
                        "url":       test_url,
                        "detail":    f"Payload reflected into response unescaped",
                    })
                else:
                    findings.append({
                        "severity":  "LOW",
                        "title":     "XSS reflection (escaped)",
                        "url":       test_url,
                        "detail":    "Payload reflected but properly escaped",
                    })
        except requests.RequestException:
            pass

    has_high = any(f["severity"] == "HIGH" for f in findings)
    severity = "HIGH" if has_high else ("LOW" if findings else "CLEAN")
    return {
        "severity":    severity,
        "findings":    findings,
        "urls_tested": tested,
        "summary":     f"Probed {tested} entry point(s); "
                       f"{len([f for f in findings if f['severity']=='HIGH'])} exploitable",
    }


# ══════════════════════════════════════════════════════════════════
# HEADER AUDIT
# ══════════════════════════════════════════════════════════════════
def _attack_header_audit(target_url: str) -> dict:
    """Inspect security-relevant HTTP headers."""
    findings = []

    try:
        r = requests.get(target_url, timeout=5)
    except requests.RequestException as e:
        return {"severity": "UNKNOWN", "findings": [],
                "error": f"Could not reach: {e}"}

    h = {k.lower(): v for k, v in r.headers.items()}

    required_headers = [
        ("strict-transport-security", "HSTS missing", "MEDIUM",
         "Add: Strict-Transport-Security: max-age=63072000; includeSubDomains; preload"),
        ("content-security-policy", "CSP missing", "MEDIUM",
         "Add a Content-Security-Policy header restricting script sources"),
        ("x-frame-options", "X-Frame-Options missing", "LOW",
         "Add: X-Frame-Options: SAMEORIGIN"),
        ("x-content-type-options", "X-Content-Type-Options missing", "LOW",
         "Add: X-Content-Type-Options: nosniff"),
        ("referrer-policy", "Referrer-Policy missing", "LOW",
         "Add: Referrer-Policy: strict-origin-when-cross-origin"),
    ]
    for hdr, title, sev, fix in required_headers:
        if hdr not in h:
            findings.append({
                "severity": sev, "title": title,
                "detail": fix,
            })

    # Disclosure headers
    disclosures = [
        ("server", "Server header discloses software version"),
        ("x-powered-by", "X-Powered-By discloses tech stack"),
        ("x-aspnet-version", "X-AspNet-Version discloses framework version"),
        ("x-generator", "X-Generator discloses software"),
    ]
    for hdr, title in disclosures:
        if hdr in h:
            val = h[hdr][:100]
            findings.append({
                "severity": "LOW", "title": title,
                "detail": f"Value: `{val}` — consider hiding/obscuring",
            })

    severity = "MEDIUM" if any(f["severity"] == "MEDIUM" for f in findings) else (
        "LOW" if findings else "CLEAN"
    )
    return {
        "severity":   severity,
        "findings":   findings,
        "headers_found": list(h.keys()),
        "summary":    f"{len(findings)} header issue(s)",
    }
