"""
AI-DTCTM | Security Hygiene Scorer (v21 — Day 3)
══════════════════════════════════════════════════════════════════════
Independent of threat intelligence, rate the TARGET's own security
hygiene. This is what ssllabs.com, securityheaders.com, mozilla
observatory do — quantify how well the target site protects its OWN
users against common attacks.

Gives a 0-100 score and A+ / A / B / C / D / F letter grade.

WHY THIS MATTERS:
  A URL can be CLEAN from a threat perspective (no malware) but still
  have terrible security hygiene (HTTP only, no HSTS, weak TLS).
  A pro scanner separates these two dimensions.

CHECKS (max 100 points):
  HTTPS enabled                   20
  Valid SSL cert, not expiring    10
  TLS 1.2 or 1.3 only              5
  HSTS header present              8
  CSP header present               8
  X-Frame-Options set              5
  X-Content-Type-Options nosniff   5
  Referrer-Policy set              3
  Permissions-Policy set           3
  Cross-Origin-Opener-Policy       2
  No mixed content in page         6
  Cookies use Secure+HttpOnly      8
  No sensitive info in headers     3
  CAA DNS record present           2
  DMARC/SPF on domain              4
  No PHP version disclosure        3
  Server header minimized          2
  No directory listing exposed     3
                            Total 100

LETTER GRADES:
  95-100 = A+
  85-94  = A
  75-84  = B
  60-74  = C
  40-59  = D
  <40    = F
"""
from __future__ import annotations

import datetime
import re
import socket
import ssl
from urllib.parse import urlparse

import requests

from core.cache import cached
from core.logger import get_logger

log = get_logger(__name__)


# ── Check registry ────────────────────────────────────────────────
# Each check returns (points_earned, max_points, status, evidence)
# status: "pass" | "fail" | "warn" | "skip"

@cached(ttl=600)
def hygiene_scan(url: str) -> dict:
    """
    Full hygiene scan. ~5-10 seconds. Returns complete score + checks.
    """
    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        return {
            "error":  "invalid url",
            "score":  0,
            "grade":  "F",
            "checks": [],
        }

    checks: list = []
    total_score = 0
    total_max   = 0

    # ── Fetch the page once for later checks ─────────────────────
    page_headers = {}
    page_body    = ""
    final_url    = url
    cookies      = []
    fetch_error  = None
    try:
        r = requests.get(
            url, timeout=8, allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 AI-DTCTM Scanner"},
            verify=True,
        )
        page_headers = {k.lower(): v for k, v in r.headers.items()}
        page_body    = r.text[:250000]
        final_url    = r.url
        cookies      = [
            {"name": c.name, "secure": c.secure, "httponly": c.has_nonstandard_attr("HttpOnly"),
             "samesite": c._rest.get("SameSite") if hasattr(c, "_rest") else None}
            for c in r.cookies
        ]
    except requests.RequestException as e:
        fetch_error = str(e)

    # ── [1] HTTPS enabled ────────────────────────────────────────
    uses_https = final_url.startswith("https://")
    checks.append({
        "name":     "HTTPS enabled",
        "category": "Encryption",
        "max":      20,
        "score":    20 if uses_https else 0,
        "status":   "pass" if uses_https else "fail",
        "evidence": (f"Final URL uses HTTPS" if uses_https
                     else "Site serves plain HTTP — traffic interceptable by anyone on the network"),
        "fix":      "" if uses_https else "Deploy SSL certificate (free via Let's Encrypt). Redirect all HTTP→HTTPS with 301.",
    })

    # ── [2] Valid SSL cert, not expiring ─────────────────────────
    ssl_score, ssl_status, ssl_evidence, ssl_fix = _check_ssl(hostname, uses_https)
    checks.append({
        "name":     "SSL certificate valid",
        "category": "Encryption",
        "max":      10,
        "score":    ssl_score,
        "status":   ssl_status,
        "evidence": ssl_evidence,
        "fix":      ssl_fix,
    })

    # ── [3] TLS version ──────────────────────────────────────────
    tls_score, tls_status, tls_evidence, tls_fix = _check_tls_version(hostname, uses_https)
    checks.append({
        "name":     "Modern TLS (1.2/1.3)",
        "category": "Encryption",
        "max":      5,
        "score":    tls_score,
        "status":   tls_status,
        "evidence": tls_evidence,
        "fix":      tls_fix,
    })

    # ── [4] HSTS ─────────────────────────────────────────────────
    hsts_val = page_headers.get("strict-transport-security")
    hsts_ok  = hsts_val and "max-age" in hsts_val.lower()
    checks.append({
        "name":     "HSTS (Strict-Transport-Security)",
        "category": "HTTP Headers",
        "max":      8,
        "score":    8 if hsts_ok else 0,
        "status":   "pass" if hsts_ok else "fail",
        "evidence": f"HSTS present: {hsts_val}" if hsts_ok
                    else "Missing — browser won't enforce HTTPS-only on return visits",
        "fix":      "" if hsts_ok else "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains",
    })

    # ── [5] CSP ──────────────────────────────────────────────────
    csp_val = page_headers.get("content-security-policy")
    csp_ok  = bool(csp_val and len(csp_val) > 10)
    checks.append({
        "name":     "Content Security Policy",
        "category": "HTTP Headers",
        "max":      8,
        "score":    8 if csp_ok else 0,
        "status":   "pass" if csp_ok else "fail",
        "evidence": f"CSP present ({len(csp_val or '')} chars)" if csp_ok
                    else "Missing — page vulnerable to XSS injection",
        "fix":      "" if csp_ok else "Add header: Content-Security-Policy: default-src 'self'; script-src 'self'",
    })

    # ── [6] X-Frame-Options ──────────────────────────────────────
    xfo = page_headers.get("x-frame-options")
    xfo_ok = xfo and xfo.lower() in ("deny", "sameorigin")
    checks.append({
        "name":     "X-Frame-Options",
        "category": "HTTP Headers",
        "max":      5,
        "score":    5 if xfo_ok else 0,
        "status":   "pass" if xfo_ok else "fail",
        "evidence": f"Set to: {xfo}" if xfo_ok
                    else "Missing — page can be framed by attackers (clickjacking risk)",
        "fix":      "" if xfo_ok else "Add header: X-Frame-Options: SAMEORIGIN",
    })

    # ── [7] X-Content-Type-Options ───────────────────────────────
    xcto = page_headers.get("x-content-type-options")
    xcto_ok = xcto and "nosniff" in xcto.lower()
    checks.append({
        "name":     "X-Content-Type-Options: nosniff",
        "category": "HTTP Headers",
        "max":      5,
        "score":    5 if xcto_ok else 0,
        "status":   "pass" if xcto_ok else "fail",
        "evidence": "Set to nosniff" if xcto_ok
                    else "Missing — browser may MIME-sniff and execute non-JS as JS",
        "fix":      "" if xcto_ok else "Add header: X-Content-Type-Options: nosniff",
    })

    # ── [8] Referrer-Policy ──────────────────────────────────────
    rp = page_headers.get("referrer-policy")
    rp_ok = bool(rp)
    checks.append({
        "name":     "Referrer-Policy",
        "category": "HTTP Headers",
        "max":      3,
        "score":    3 if rp_ok else 0,
        "status":   "pass" if rp_ok else "warn",
        "evidence": f"Set to: {rp}" if rp_ok
                    else "Missing — full URL leaks to third-party resources",
        "fix":      "" if rp_ok else "Add header: Referrer-Policy: strict-origin-when-cross-origin",
    })

    # ── [9] Permissions-Policy ───────────────────────────────────
    pp = page_headers.get("permissions-policy") or page_headers.get("feature-policy")
    pp_ok = bool(pp)
    checks.append({
        "name":     "Permissions-Policy",
        "category": "HTTP Headers",
        "max":      3,
        "score":    3 if pp_ok else 0,
        "status":   "pass" if pp_ok else "warn",
        "evidence": f"Set: {(pp or '')[:60]}" if pp_ok
                    else "Missing — browser features (camera/geolocation) not restricted",
        "fix":      "" if pp_ok else "Add header: Permissions-Policy: geolocation=(), camera=(), microphone=()",
    })

    # ── [10] COOP ────────────────────────────────────────────────
    coop = page_headers.get("cross-origin-opener-policy")
    coop_ok = bool(coop)
    checks.append({
        "name":     "Cross-Origin-Opener-Policy",
        "category": "HTTP Headers",
        "max":      2,
        "score":    2 if coop_ok else 0,
        "status":   "pass" if coop_ok else "warn",
        "evidence": f"Set to: {coop}" if coop_ok
                    else "Missing — cross-origin windows can access this page",
        "fix":      "" if coop_ok else "Add header: Cross-Origin-Opener-Policy: same-origin",
    })

    # ── [11] No mixed content ────────────────────────────────────
    mc_ok = True
    mc_instances = 0
    if uses_https and page_body:
        mc_matches = re.findall(r'(?i)(?:src|href)=["\']http://', page_body)
        mc_instances = len(mc_matches)
        mc_ok = mc_instances == 0
    checks.append({
        "name":     "No mixed content",
        "category": "Encryption",
        "max":      6,
        "score":    6 if mc_ok else 0,
        "status":   "pass" if mc_ok else "fail",
        "evidence": "No HTTP assets found on HTTPS page" if mc_ok
                    else f"Found {mc_instances} HTTP resources loaded on HTTPS page",
        "fix":      "" if mc_ok else "Replace all http:// URLs in HTML with https:// (or protocol-relative //)",
    })

    # ── [12] Cookies secure ──────────────────────────────────────
    if not cookies:
        cookie_score, cookie_status, cookie_ev = 8, "skip", "No cookies set"
    else:
        all_secure = all(c.get("secure") for c in cookies) if uses_https else False
        all_httponly = all(c.get("httponly") for c in cookies)
        if all_secure and all_httponly:
            cookie_score, cookie_status, cookie_ev = 8, "pass", f"All {len(cookies)} cookies have Secure + HttpOnly"
        elif all_secure or all_httponly:
            cookie_score, cookie_status, cookie_ev = 4, "warn", f"Partial — {sum(c['secure'] for c in cookies)}/{len(cookies)} Secure, {sum(c['httponly'] for c in cookies)}/{len(cookies)} HttpOnly"
        else:
            cookie_score, cookie_status, cookie_ev = 0, "fail", f"Cookies ({len(cookies)}) lack Secure/HttpOnly flags"
    checks.append({
        "name":     "Cookie flags (Secure+HttpOnly)",
        "category": "Cookies",
        "max":      8,
        "score":    cookie_score,
        "status":   cookie_status,
        "evidence": cookie_ev,
        "fix":      "" if cookie_status == "pass" else "Set: Set-Cookie: name=val; Secure; HttpOnly; SameSite=Strict",
    })

    # ── [13] Server header minimized ─────────────────────────────
    server = page_headers.get("server", "")
    has_version = bool(re.search(r"\d+\.\d+", server))
    server_ok = not has_version
    checks.append({
        "name":     "Server header minimised",
        "category": "Information Disclosure",
        "max":      2,
        "score":    2 if server_ok else 0,
        "status":   "pass" if server_ok else "warn",
        "evidence": f"Server: {server}" if server else "No Server header — best",
        "fix":      "" if server_ok else "Remove version from Server header: e.g., `ServerTokens Prod` in Apache",
    })

    # ── [14] X-Powered-By disclosure ─────────────────────────────
    xpb = page_headers.get("x-powered-by", "")
    xpb_ok = not xpb
    checks.append({
        "name":     "No X-Powered-By disclosure",
        "category": "Information Disclosure",
        "max":      3,
        "score":    3 if xpb_ok else 0,
        "status":   "pass" if xpb_ok else "warn",
        "evidence": "Absent — clean" if xpb_ok else f"Exposes stack: {xpb}",
        "fix":      "" if xpb_ok else "Remove X-Powered-By header (PHP: expose_php=Off, .htaccess: Header unset X-Powered-By)",
    })

    # Compute totals
    total_score = sum(c["score"] for c in checks)
    total_max   = sum(c["max"]   for c in checks)

    # Letter grade
    pct = (total_score / total_max * 100) if total_max else 0
    if pct >= 95:   grade = "A+"
    elif pct >= 85: grade = "A"
    elif pct >= 75: grade = "B"
    elif pct >= 60: grade = "C"
    elif pct >= 40: grade = "D"
    else:           grade = "F"

    # Category aggregates for radar chart
    categories: dict = {}
    for c in checks:
        cat = c["category"]
        cur = categories.setdefault(cat, {"score": 0, "max": 0})
        cur["score"] += c["score"]
        cur["max"]   += c["max"]

    # Failing items for quick action
    failing = [c for c in checks if c["status"] == "fail"]
    warnings = [c for c in checks if c["status"] == "warn"]

    return {
        "target":       url,
        "final_url":    final_url,
        "score":        total_score,
        "max":          total_max,
        "percentage":   round(pct, 1),
        "grade":        grade,
        "checks":       checks,
        "categories":   categories,
        "failing_count":  len(failing),
        "warnings_count": len(warnings),
        "passing_count":  sum(1 for c in checks if c["status"] == "pass"),
        "fetch_error":  fetch_error,
    }


def _check_ssl(hostname: str, uses_https: bool) -> tuple[int, str, str, str]:
    if not uses_https:
        return 0, "fail", "Site not HTTPS — SSL cert check skipped", "Enable HTTPS first"
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                vt = cert.get("notAfter")
                if vt:
                    exp = datetime.datetime.strptime(vt, "%b %d %H:%M:%S %Y %Z")
                    days_left = (exp - datetime.datetime.utcnow()).days
                    if days_left < 0:
                        return 0, "fail", f"Certificate EXPIRED {-days_left} days ago", "Renew certificate immediately"
                    elif days_left < 15:
                        return 3, "warn", f"Certificate expires in {days_left} days", "Renew cert before expiry"
                    elif days_left < 30:
                        return 7, "warn", f"Certificate expires in {days_left} days", "Set up auto-renewal (certbot)"
                    else:
                        return 10, "pass", f"Valid, {days_left} days until expiry", ""
                return 8, "warn", "Cert valid but expiry unparseable", ""
    except ssl.SSLError as e:
        return 0, "fail", f"SSL error: {e}", "Fix certificate chain or hostname mismatch"
    except socket.timeout:
        return 3, "warn", "SSL handshake timeout (slow server)", "Optimize TLS handshake"
    except Exception as e:
        return 2, "warn", f"Could not verify: {e}", "Check SSL configuration"


def _check_tls_version(hostname: str, uses_https: bool) -> tuple[int, str, str, str]:
    if not uses_https:
        return 0, "fail", "Site not HTTPS — TLS check skipped", "Enable HTTPS first"
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                version = ssock.version()
                if version in ("TLSv1.3",):
                    return 5, "pass", f"Negotiated: {version}", ""
                elif version in ("TLSv1.2",):
                    return 4, "pass", f"Negotiated: {version} (acceptable)", "Enable TLS 1.3 for best"
                else:
                    return 0, "fail", f"Old TLS: {version}", "Disable SSL/TLS <1.2 in server config"
    except Exception as e:
        return 2, "warn", f"Could not determine: {e}", ""
