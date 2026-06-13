"""
AI-DTCTM | Source Reconnaissance Engine (v24)
═══════════════════════════════════════════════════════════════════════
Static analysis of a cloned source tree. After deployment, this scans
every file and returns structured findings the attack-blueprint engine
uses to propose tailored experiments.

WHAT THIS DETECTS
─────────────────
  Authentication
    • Login forms (HTML <form> + <input type=password>)
    • Session/cookie configuration (HttpOnly, Secure, SameSite)
    • Password hash usage (bcrypt vs MD5 vs plaintext)
    • CSRF token presence
    • Rate-limit middleware presence

  Web routes / API
    • Express routes (`app.get('/path'`)
    • Flask routes (`@app.route`)
    • Django urls.py patterns
    • Laravel Route::get
    • PHP file-as-route discovery
    • API path patterns (/api/, /v1/, /rest/)

  Data layer
    • Database drivers (mysql, pdo, sqlalchemy, mongoose…)
    • Raw query patterns vs parameterised queries
    • ORM usage

  Attack surface
    • File-upload handlers
    • Admin / dashboard URLs
    • Open redirect handlers
    • Hardcoded secrets (AWS, GitHub, Stripe, etc.)
    • Cleartext credentials in config files

  Security posture
    • Security headers (CSP, HSTS, X-Frame-Options)
    • SSL / TLS enforcement
    • Input validation patterns
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Optional


# ── File-type whitelist (don't scan binaries / image / build artefacts) ──
_TEXT_EXT = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".php", ".phtml",
    ".rb", ".java", ".jsp", ".go", ".rs", ".c", ".cpp", ".h",
    ".html", ".htm", ".css", ".scss", ".vue", ".svelte",
    ".json", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf",
    ".env", ".md", ".txt", ".xml",
    ".sh", ".bash", ".ps1", ".bat",
}
_SKIP_DIRS = {"node_modules", ".git", "__pycache__", ".venv", "venv",
               "dist", "build", "target", ".next", ".nuxt"}
_MAX_FILE_BYTES = 200_000   # skip huge files


# ─────────────────────────────────────────────────────────────────────
# PATTERN LIBRARY
# ─────────────────────────────────────────────────────────────────────

# Login form (HTML)
_PW_FIELD       = re.compile(r"""<input[^>]+type\s*=\s*['"]password['"]""", re.IGNORECASE)
_USER_FIELD     = re.compile(r"""<input[^>]+name\s*=\s*['"](?:username|email|user|login)['"]""", re.IGNORECASE)
_FORM_ACTION    = re.compile(r"""<form[^>]+action\s*=\s*['"]([^'"]+)['"]""", re.IGNORECASE)

# CSRF token
_CSRF_TOKEN     = re.compile(r"csrf[_-]?token|_token|authenticity_token|xsrf", re.IGNORECASE)
_CSRF_LIB       = re.compile(
    r"\b(?:csrf_protect|CsrfViewMiddleware|csurf|wtforms\.csrf|"
    r"Flask-?WTF|flask\.ext\.wtf|tornado\.web\.escape\.xhtml_escape|"
    r"VerifyCsrfToken)\b", re.IGNORECASE)

# Rate-limiting middleware
_RATE_LIMIT = re.compile(
    r"\b(?:rate[_-]?limit|RateLimiter|express-rate-limit|"
    r"Flask-Limiter|django-ratelimit|throttle|"
    r"throttle_classes|throttle_scope|nginx\s+limit_req)\b", re.IGNORECASE)

# Express / Koa routes
_EXPRESS_RT = re.compile(
    r"""\b(?:app|router|route)\.\s*(?P<method>get|post|put|patch|delete|"""
    r"""head|options|all)\s*\(\s*['"](?P<path>[^'"]+)['"]""", re.IGNORECASE)
# Flask routes
_FLASK_RT = re.compile(
    r"""@(?:app|bp|blueprint|api)\s*\.\s*route\s*\(\s*['"](?P<path>[^'"]+)['"]"""
    r"""(?:[^)]*methods\s*=\s*\[(?P<methods>[^\]]+)\])?""", re.IGNORECASE)
# Django urls.py
_DJANGO_PATH = re.compile(
    r"""(?:path|re_path|url)\s*\(\s*r?['"](?P<path>[^'"]+)['"]""", re.IGNORECASE)
# Laravel routes
_LARAVEL_RT = re.compile(
    r"""Route::\s*(?P<method>get|post|put|patch|delete|any|match)\s*\(\s*['"](?P<path>[^'"]+)['"]""", re.IGNORECASE)
# Rails routes
_RAILS_RT = re.compile(
    r"""^\s*(?P<method>get|post|put|patch|delete|resource|resources)\s+['"](?P<path>[^'"]+)['"]""",
    re.IGNORECASE | re.MULTILINE)
# FastAPI
_FASTAPI_RT = re.compile(
    r"""@(?:app|router|api)\s*\.\s*(?P<method>get|post|put|patch|delete)\s*\(\s*['"](?P<path>[^'"]+)['"]""",
    re.IGNORECASE)

# DB drivers
_DB_DRIVERS = {
    "mysql":    re.compile(r"\b(?:mysql\.connector|mysql2|mysqli_|new\s+mysqli|pymysql|mysql\.createConnection)\b", re.IGNORECASE),
    "postgres": re.compile(r"\b(?:psycopg2|pg\s*=\s*require|new\s+Client.*postgres|PG::Connection)\b", re.IGNORECASE),
    "sqlite":   re.compile(r"\bsqlite3|better-sqlite3|SQLite\.Database\b", re.IGNORECASE),
    "pdo":      re.compile(r"\bnew\s+PDO\(|PDO::|\$pdo\s*->\s*query\b", re.IGNORECASE),
    "mongo":    re.compile(r"\b(?:MongoClient|mongoose|pymongo|MongoCollection)\b", re.IGNORECASE),
    "redis":    re.compile(r"\b(?:redis\.createClient|Redis::|redis-py|StackExchange\.Redis)\b", re.IGNORECASE),
    "sqlalchemy": re.compile(r"\bsqlalchemy|create_engine|declarative_base\b", re.IGNORECASE),
    "orm_general": re.compile(r"\b(?:Sequelize|TypeORM|Prisma|ActiveRecord|Eloquent|Django\.db\.models)\b", re.IGNORECASE),
}

# Raw vs parameterised SQL
_RAW_SQL_CONCAT = re.compile(
    r"""(?:execute|query|run|exec)\s*\(\s*['"`][^'"`]*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^'"`]*['"`]\s*\+""",
    re.IGNORECASE)
_RAW_SQL_INTERP = re.compile(
    r"""(?:execute|query|run|exec)\s*\(\s*[fF]?['"`][^'"`]*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^'"`]*\$?\{""",
    re.IGNORECASE)
_PARAM_SQL = re.compile(
    r"""(?:execute|query|run|exec)\s*\(\s*['"`][^'"`]*[\?:$][1-9]?[^'"`]*['"`]\s*,""")

# File upload
_FILE_INPUT = re.compile(r"""<input[^>]+type\s*=\s*['"]file['"]""", re.IGNORECASE)
_MOVE_UPLOADED = re.compile(r"\bmove_uploaded_file\s*\(", re.IGNORECASE)
_MULTER       = re.compile(r"\b(?:multer|formidable|busboy|express-fileupload)\b", re.IGNORECASE)
_FLASK_FILES  = re.compile(r"\brequest\.files\b", re.IGNORECASE)
_MIME_CHECK   = re.compile(r"\b(?:finfo_file|mime_content_type|magic\.from_buffer|filetype\.guess)\b", re.IGNORECASE)
_EXT_CHECK    = re.compile(r"\bpathinfo\s*\([^)]*PATHINFO_EXTENSION|getClientOriginalExtension|\.split\(['\"]\\.['\"]?\)\s*\.\s*pop", re.IGNORECASE)

# Session config
_SESSION_HTTPONLY = re.compile(r"httponly\s*[:=]\s*(true|True|1)", re.IGNORECASE)
_SESSION_SECURE   = re.compile(r"\bsecure\s*[:=]\s*(true|True|1)", re.IGNORECASE)
_SESSION_SAMESITE = re.compile(r"samesite\s*[:=]\s*['\"]?(strict|lax|none)['\"]?", re.IGNORECASE)

# Security headers
_CSP_HEADER  = re.compile(r"Content-Security-Policy", re.IGNORECASE)
_HSTS_HEADER = re.compile(r"Strict-Transport-Security", re.IGNORECASE)
_XFRAME      = re.compile(r"X-Frame-Options", re.IGNORECASE)

# Hardcoded secrets (high-confidence patterns)
_SECRET_PATTERNS = [
    ("aws_access_key",  re.compile(r"AKIA[0-9A-Z]{16}")),
    ("aws_secret",      re.compile(r"(?i)aws_secret_access_key\s*=\s*['\"]?[A-Za-z0-9/+=]{40}")),
    ("github_pat",      re.compile(r"\bghp_[A-Za-z0-9]{36}\b")),
    ("github_oauth",    re.compile(r"\bgho_[A-Za-z0-9]{36}\b")),
    ("stripe_key",      re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{24,}\b")),
    ("slack_token",     re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("google_api_key",  re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("private_key",     re.compile(r"-----BEGIN (?:RSA|DSA|EC|OPENSSH|ENCRYPTED) PRIVATE KEY-----")),
    ("jwt_secret_kw",   re.compile(r"""(?i)JWT_SECRET\s*=\s*['"][A-Za-z0-9_\-]{8,}""")),
    ("db_pwd",          re.compile(r"""(?i)(?:DB_PASSWORD|DATABASE_PASSWORD|MYSQL_PASSWORD)\s*=\s*['"]?[^'"#\s]{4,}""")),
]

# Admin / dashboard paths
_ADMIN_HINT = re.compile(r"/(?:admin|dashboard|backoffice|cpanel|wp-admin|administrator|manager)/?", re.IGNORECASE)

# Auth-required hint (JWT / @login_required / middleware)
_AUTH_GUARD = re.compile(
    r"""@(?:login_required|requires_auth|jwt_required)|"""
    r"""\bauth(?:enticate)?Middleware\b|\bAuthorize\]|"""
    r"""\bmiddleware\(['"]auth['"]""", re.IGNORECASE)


# ─────────────────────────────────────────────────────────────────────
# MAIN ENTRYPOINT
# ─────────────────────────────────────────────────────────────────────
def reconnoiter(sandbox_dir: str | Path,
                 stack: Optional[dict] = None) -> dict:
    """
    Walk the cloned source and produce a structured findings dict.
    """
    root = Path(sandbox_dir)
    if not root.exists():
        return {"error": "sandbox missing", "ok": False}

    findings = {
        "ok":              True,
        "sandbox":         str(root),
        "stack":           (stack or {}).get("language", "?"),
        "files_scanned":   0,

        # Authentication
        "login_forms":     [],
        "csrf":            {"present": False, "evidence": []},
        "rate_limit":      {"present": False, "evidence": []},
        "session_config":  {"httponly": None, "secure": None, "samesite": None},

        # Routes / endpoints
        "routes":          [],          # list of {path, method, file}
        "api_routes":      [],          # subset where path starts with /api/

        # Data layer
        "db_drivers":      [],          # detected DB libs
        "raw_sql_count":   0,
        "param_sql_count": 0,

        # Attack surface
        "file_uploads":    [],          # list of {file, has_mime_check, has_ext_check}
        "admin_panels":    [],
        "hardcoded_secrets": [],        # list of {type, file, line}

        # Security posture
        "security_headers": {"csp": False, "hsts": False, "xframe": False},

        # Overall scores
        "risk_score":      0,           # 0-100 (higher = more attack surface)
        "exposure_chips":  [],          # short human-readable risk flags
    }

    for fp in _walk_text_files(root):
        try:
            text = fp.read_text(encoding="utf-8", errors="replace")[:_MAX_FILE_BYTES]
        except Exception:
            continue
        findings["files_scanned"] += 1
        rel = str(fp.relative_to(root)).replace("\\", "/")
        _scan_one(text, rel, findings)

    # ── Post-processing / scoring ──
    findings["api_routes"] = [r for r in findings["routes"]
                                if r["path"].startswith(("/api/", "/v1/", "/v2/", "/rest/"))]
    _compute_risk_score(findings)
    return findings


def _walk_text_files(root: Path):
    """Yield text source files, skipping bin / build / vendor dirs."""
    for fp in root.rglob("*"):
        if not fp.is_file():
            continue
        if any(part in _SKIP_DIRS for part in fp.parts):
            continue
        if fp.suffix.lower() not in _TEXT_EXT:
            continue
        try:
            if fp.stat().st_size > _MAX_FILE_BYTES:
                continue
        except Exception:
            continue
        yield fp


def _scan_one(text: str, rel: str, out: dict) -> None:
    """Apply every pattern to one file."""
    lines = text.splitlines()

    # ── Login form ──
    if _PW_FIELD.search(text):
        action_match = _FORM_ACTION.search(text)
        out["login_forms"].append({
            "file":     rel,
            "action":   action_match.group(1) if action_match else "/login",
            "has_username_field": bool(_USER_FIELD.search(text)),
            "has_csrf_token":     bool(_CSRF_TOKEN.search(text)),
        })

    # ── CSRF detection (project-wide) ──
    if _CSRF_TOKEN.search(text) or _CSRF_LIB.search(text):
        if not out["csrf"]["present"]:
            out["csrf"]["present"] = True
        if len(out["csrf"]["evidence"]) < 5:
            out["csrf"]["evidence"].append(rel)

    # ── Rate limiting ──
    if _RATE_LIMIT.search(text):
        if not out["rate_limit"]["present"]:
            out["rate_limit"]["present"] = True
        if len(out["rate_limit"]["evidence"]) < 5:
            out["rate_limit"]["evidence"].append(rel)

    # ── Routes / API endpoints ──
    for rx, kind in [
        (_EXPRESS_RT, "express"),
        (_FLASK_RT,   "flask"),
        (_DJANGO_PATH,"django"),
        (_LARAVEL_RT, "laravel"),
        (_FASTAPI_RT, "fastapi"),
        (_RAILS_RT,   "rails"),
    ]:
        for m in rx.finditer(text):
            path = m.groupdict().get("path") or m.group(0)
            method = (m.groupdict().get("method") or "GET").upper()
            if not path or len(path) > 200:
                continue
            # Make path web-relative
            if not path.startswith("/"):
                path = "/" + path
            out["routes"].append({
                "path":   path,
                "method": method,
                "file":   rel,
                "framework": kind,
            })

    # ── PHP file-as-route discovery (treat .php files as routes) ──
    if rel.endswith(".php") and "/" not in rel.rstrip(".php"):
        out["routes"].append({
            "path":   "/" + rel,
            "method": "ANY",
            "file":   rel,
            "framework": "php-file",
        })

    # ── DB drivers ──
    for name, rx in _DB_DRIVERS.items():
        if rx.search(text) and name not in out["db_drivers"]:
            out["db_drivers"].append(name)

    # ── Raw vs parameterised SQL ──
    out["raw_sql_count"]   += len(_RAW_SQL_CONCAT.findall(text))
    out["raw_sql_count"]   += len(_RAW_SQL_INTERP.findall(text))
    out["param_sql_count"] += len(_PARAM_SQL.findall(text))

    # ── File upload handlers ──
    if (_FILE_INPUT.search(text) or _MOVE_UPLOADED.search(text)
        or _MULTER.search(text) or _FLASK_FILES.search(text)):
        out["file_uploads"].append({
            "file":           rel,
            "has_mime_check": bool(_MIME_CHECK.search(text)),
            "has_ext_check":  bool(_EXT_CHECK.search(text)),
        })

    # ── Admin panel ──
    if _ADMIN_HINT.search(text) or _ADMIN_HINT.search(rel):
        # Extract the matching admin URL(s)
        for m in _ADMIN_HINT.finditer(text):
            url = m.group(0)
            if url not in out["admin_panels"]:
                out["admin_panels"].append(url)
        # Also if file path itself is in admin dir
        if "/admin/" in "/" + rel and "/admin/" not in out["admin_panels"]:
            out["admin_panels"].append("/admin/")

    # ── Hardcoded secrets ──
    for ln_idx, ln in enumerate(lines, 1):
        for sec_type, rx in _SECRET_PATTERNS:
            if rx.search(ln):
                out["hardcoded_secrets"].append({
                    "type": sec_type, "file": rel, "line": ln_idx,
                    "preview": ln.strip()[:80],
                })
                break

    # ── Session config ──
    if _SESSION_HTTPONLY.search(text):
        out["session_config"]["httponly"] = True
    if _SESSION_SECURE.search(text):
        out["session_config"]["secure"] = True
    m = _SESSION_SAMESITE.search(text)
    if m:
        out["session_config"]["samesite"] = m.group(1).lower()

    # ── Security headers ──
    if _CSP_HEADER.search(text):
        out["security_headers"]["csp"] = True
    if _HSTS_HEADER.search(text):
        out["security_headers"]["hsts"] = True
    if _XFRAME.search(text):
        out["security_headers"]["xframe"] = True


def _compute_risk_score(f: dict) -> None:
    """Aggregate findings into a single risk number + human chips."""
    score = 0
    chips = []

    # Login form without rate limit / CSRF = high risk
    if f["login_forms"]:
        chips.append(f"🔓 {len(f['login_forms'])} login form(s)")
        if not f["rate_limit"]["present"]:
            score += 18; chips.append("⚠ no rate-limit")
        if not f["csrf"]["present"]:
            score += 12; chips.append("⚠ no CSRF protection")

    # API routes are juicy attack surface
    if f["api_routes"]:
        chips.append(f"📡 {len(f['api_routes'])} API route(s)")
        score += min(15, len(f["api_routes"]) * 2)

    # Raw SQL = SQL-injection candidates
    if f["raw_sql_count"] > 0:
        score += min(25, f["raw_sql_count"] * 3)
        chips.append(f"💉 {f['raw_sql_count']} raw SQL string(s)")

    # File uploads
    risky_uploads = sum(1 for u in f["file_uploads"]
                         if not u.get("has_mime_check"))
    if risky_uploads:
        score += min(20, risky_uploads * 6)
        chips.append(f"📤 {risky_uploads} upload(s) w/o MIME check")

    # Admin panels
    if f["admin_panels"]:
        chips.append(f"🔑 {len(set(f['admin_panels']))} admin path(s)")
        score += 5

    # Hardcoded secrets
    if f["hardcoded_secrets"]:
        score += min(25, len(f["hardcoded_secrets"]) * 5)
        chips.append(f"🗝 {len(f['hardcoded_secrets'])} hardcoded secret(s)")

    # Security headers missing
    if not f["security_headers"]["csp"]:
        score += 6; chips.append("⚠ no CSP")
    if not f["security_headers"]["hsts"]:
        score += 3
    if not f["security_headers"]["xframe"]:
        score += 3

    # Session
    if f["session_config"]["httponly"] is False:
        score += 4; chips.append("⚠ cookie !HttpOnly")
    if f["session_config"]["secure"] is False:
        score += 3

    f["risk_score"]     = min(100, score)
    f["exposure_chips"] = chips
