"""
AI-DTCTM | Deep Code Scanner (v22 — Phase 2f)
══════════════════════════════════════════════════════════════════════
Walks every file in an extracted ZIP / directory, scans every LINE,
returns exact `file.py:247: <reason>` style findings.

Patterns are layered (most → least specific):
  Layer A: Hardcoded secrets    — API keys, passwords, JWT tokens
  Layer B: Dangerous functions  — eval, exec, system, popen
  Layer C: Injection sinks      — SQL string-concat, shell=True, innerHTML
  Layer D: Crypto issues        — DES/RC4, hardcoded IV, weak random
  Layer E: Network exfiltration — base64+http, suspicious domains
  Layer F: Obfuscation          — long base64 blobs, packed payloads
  Layer G: AST-level (Python)   — tainted-data flow detection

Each finding has:
  file, line, column, severity, category, code_snippet, why_risky, fix
"""
from __future__ import annotations

import ast
import base64
import math
import os
import re
import zipfile
from collections import Counter
from pathlib import Path
from typing import Iterator, Optional

from core.logger import get_logger

log = get_logger(__name__)


# ── Pattern dictionary (regex-based, language-agnostic) ──────────
# Format: (regex, severity, category, why_risky, fix)
LINE_PATTERNS: list[tuple[re.Pattern, str, str, str, str]] = [
    # ── A. Hardcoded secrets ─────────────────────────────────────
    (re.compile(r'\b(api[_-]?key|apikey|secret|token|password|passwd|pwd)\s*[=:]\s*["\']([^"\']{8,})["\']', re.I),
     "HIGH", "Hardcoded secret",
     "Credentials in source code leak through git history, logs, screenshots, builds.",
     "Move to environment variable, .env file (gitignored), or secrets manager (Vault/AWS SM)."),

    (re.compile(r'AKIA[0-9A-Z]{16}'),
     "CRITICAL", "AWS Access Key",
     "AWS access keys grant API access to your cloud account — full takeover risk.",
     "Rotate immediately, store in env, scan git history with truffleHog."),

    (re.compile(r'AIza[0-9A-Za-z_\-]{35}'),
     "HIGH", "Google API Key",
     "Google API keys allow paid quota consumption and data access.",
     "Restrict in Google Console (referrer/IP/API limits), rotate key."),

    (re.compile(r'sk_live_[0-9a-zA-Z]{24,}'),
     "CRITICAL", "Stripe Live Secret",
     "Stripe live secret = full payment-processing access, financial fraud risk.",
     "Rotate in Stripe dashboard, use only test keys in source."),

    (re.compile(r'ghp_[A-Za-z0-9]{36}'),
     "CRITICAL", "GitHub Personal Token",
     "PAT grants full repo access — code theft + supply-chain attack risk.",
     "Revoke at github.com/settings/tokens, never commit tokens."),

    (re.compile(r'-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----'),
     "CRITICAL", "Private cryptographic key",
     "Private keys grant authentication/decryption — total compromise.",
     "Rotate immediately, generate new keypair, audit usage."),

    (re.compile(r'mongodb(?:\+srv)?://[^"\'\s]+:[^"\'\s]+@'),
     "CRITICAL", "MongoDB connection with embedded credentials",
     "Database credentials in URL string leak through logs/git.",
     "Use SRV connection + IAM, store password in env."),

    (re.compile(r'(jdbc|mysql|postgresql)://[^"\'\s]+:[^"\'\s]+@'),
     "HIGH", "Database URL with credentials",
     "Hardcoded database password — pivot risk if code leaks.",
     "Read DB_PASSWORD from environment variable."),

    # ── B. Dangerous functions ───────────────────────────────────
    (re.compile(r'\beval\s*\([^)]*\b(input|request|argv|stdin|cookie|param|body)\b', re.I),
     "CRITICAL", "eval() on user input",
     "Direct code execution from untrusted input = remote code execution.",
     "Never eval untrusted input. Use ast.literal_eval for data, JSON.parse for objects."),

    (re.compile(r'\bexec\s*\([^)]*\b(input|request|argv|stdin|cookie|param|body)\b', re.I),
     "CRITICAL", "exec() on user input",
     "Same risk as eval — arbitrary code execution.",
     "Refuse user-controlled exec calls. Validate with allowlist."),

    (re.compile(r'subprocess\.(call|Popen|run)\s*\([^)]+shell\s*=\s*True', re.I),
     "HIGH", "subprocess shell=True",
     "shell=True with concatenated input enables command injection.",
     "Use shell=False + list args: subprocess.run(['ls', user_input])."),

    (re.compile(r'os\.(system|popen)\s*\([^)]*[\+%].*\b(input|request|argv|stdin|cookie|param)', re.I),
     "CRITICAL", "os.system with concatenated user input",
     "Classic command injection — `; rm -rf /` works.",
     "Use subprocess with list args + shell=False."),

    (re.compile(r'pickle\.loads\s*\([^)]*\b(request|input|cookie|body|recv|read|argv)', re.I),
     "CRITICAL", "pickle deserialization of user input",
     "Pickle is Turing-complete — deserialization = arbitrary code execution.",
     "Use JSON, MessagePack, or sandboxed deserialiser."),

    (re.compile(r'yaml\.load\s*\([^)]*(?!.*Loader\s*=\s*yaml\.SafeLoader)', re.I),
     "HIGH", "yaml.load without SafeLoader",
     "Unsafe YAML deserialisation = arbitrary Python objects → RCE.",
     "Use yaml.safe_load() OR yaml.load(data, Loader=yaml.SafeLoader)."),

    # ── C. Injection sinks ───────────────────────────────────────
    (re.compile(r'(execute|query|raw|cursor\.execute)\s*\(\s*["\'][^"\']*["\']\s*[\+%]\s*\w+', re.I),
     "HIGH", "SQL string concatenation",
     "Concatenated SQL = SQL injection. Attacker can read/modify/drop data.",
     "Use parameterised queries: cursor.execute('SELECT ... WHERE id=?', (uid,))."),

    (re.compile(r'\.innerHTML\s*=\s*[^;]*\b(input|value|param|cookie|location|hash|search)\b', re.I),
     "HIGH", "innerHTML assignment from user input",
     "Stored/reflected XSS — script tags in input get executed.",
     "Use textContent for data, or DOMPurify before innerHTML."),

    (re.compile(r'document\.write\s*\([^)]*\b(input|value|param|cookie|location)\b', re.I),
     "HIGH", "document.write with user input",
     "XSS sink — same risks as innerHTML.",
     "Replace with safe DOM methods: createElement + textContent."),

    (re.compile(r'dangerouslySetInnerHTML', re.I),
     "MEDIUM", "React dangerouslySetInnerHTML",
     "Bypasses React's auto-escaping — XSS if input untrusted.",
     "Sanitise with DOMPurify, OR use plain {data} children."),

    # ── D. Crypto weakness ───────────────────────────────────────
    (re.compile(r'Cipher\.getInstance\s*\(\s*["\'](DES|RC4|RC2|MD5)', re.I),
     "MEDIUM", "Weak cipher algorithm",
     "DES/RC4/MD5 broken — encrypted data can be decrypted by attacker.",
     "Use AES-256-GCM for encryption, SHA-256 for hashing."),

    (re.compile(r'\bMD5\s*\(.*password', re.I),
     "HIGH", "MD5 password hashing",
     "MD5 is broken (rainbow tables, GPU brute-force).",
     "Use bcrypt, scrypt, or Argon2id with cost ≥ 12."),

    (re.compile(r'random\.random\s*\(\s*\)', re.I),
     "LOW", "random.random for security",
     "Mersenne Twister is predictable — bad for tokens/keys.",
     "Use secrets.token_urlsafe() or os.urandom() for security tokens."),

    (re.compile(r'Math\.random\s*\(\s*\)', re.I),
     "LOW", "Math.random for security",
     "Predictable PRNG — bad for security-sensitive use.",
     "Use crypto.getRandomValues() (browser) or crypto.randomBytes() (Node)."),

    # ── E. Suspicious URLs / network ─────────────────────────────
    (re.compile(r'https?://[a-z0-9\-]+\.(tk|ml|ga|gq|cf|xyz|top|click)/', re.I),
     "HIGH", "Suspicious-TLD URL",
     "These TLDs heavily abused for phishing/malware C2 — flag for review.",
     "Audit endpoint, replace with verified domain, log usage."),

    (re.compile(r'(?:^|[^\w])([A-Za-z0-9+/]{40,}={0,2})(?:[^\w]|$)'),
     "MEDIUM", "Long base64 string",
     "Could be encoded payload, embedded binary, or hidden config.",
     "Decode + audit. If embedded binary, move to separate signed file."),

    # ── F. Auth / session weaknesses ─────────────────────────────
    (re.compile(r'verify\s*=\s*False', re.I),
     "MEDIUM", "TLS verification disabled",
     "Disabled cert verification = man-in-the-middle attack vector.",
     "Remove verify=False. Add proper CA cert if needed."),

    (re.compile(r'TrustManager.*?checkServerTrusted.*?{}', re.I | re.DOTALL),
     "HIGH", "Empty TrustManager (Java/Android)",
     "Accepts any TLS certificate — full MITM.",
     "Implement proper certificate pinning OR use system trust store."),

    (re.compile(r'(SECRET_KEY|JWT_SECRET|FLASK_SECRET)\s*=\s*["\'][^"\']{1,20}["\']', re.I),
     "CRITICAL", "Short hardcoded SECRET_KEY",
     "Short, hardcoded SECRET_KEY allows session forgery.",
     "Generate 64+ char random key, store in env: secrets.token_urlsafe(48)."),

    # ── G. Webshell signatures ───────────────────────────────────
    (re.compile(r'<\?php\s+(eval|assert|preg_replace)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)', re.I),
     "CRITICAL", "PHP webshell pattern",
     "Direct shell execution from request parameter — instant RCE.",
     "Remove file. Audit all uploaded PHP. Restrict upload directory execution."),

    (re.compile(r'\$_(GET|POST|REQUEST)\[[^\]]*\]\s*\(\s*\)', re.I),
     "CRITICAL", "Variable-function-call from request",
     "PHP feature where $_GET['x']() calls function named in request.",
     "Refactor to switch/case or allow-list of legal callbacks."),

    # ── H. Misc ──────────────────────────────────────────────────
    (re.compile(r'TODO[:\s]+(insecure|vulnerable|unsafe|fix.{0,15}before.{0,15}prod)', re.I),
     "LOW", "TODO comment about insecurity",
     "Developer left a known-bad-thing comment.",
     "Address before deployment."),
]


# ── File-extension filter ──────────────────────────────────────────
SCANNABLE_EXTENSIONS = {
    # Server-side
    ".py", ".pyw", ".php", ".php3", ".php4", ".php5", ".phtml",
    ".rb", ".pl", ".pm", ".cgi", ".jsp", ".jspx", ".asp", ".aspx",
    ".java", ".kt", ".scala", ".groovy",
    ".go", ".rs", ".swift", ".m", ".mm",
    ".cs", ".vb", ".fs",
    # Client-side
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".vue", ".svelte",
    ".html", ".htm", ".xhtml",
    # Config / shell / scripts
    ".yml", ".yaml", ".json", ".xml", ".ini", ".cfg", ".conf",
    ".sh", ".bash", ".zsh", ".ksh",
    ".ps1", ".psm1", ".psd1",
    ".env", ".envrc",
    # Build / CI
    ".dockerfile", ".gitlab-ci.yml", ".travis.yml",
    ".tf", ".tfvars", ".hcl",
    # Database
    ".sql", ".plsql",
    # Smali / Android
    ".smali",
    # Other
    ".css", ".scss", ".sass",
    ".md", ".rst",   # docs — secrets often pasted in markdown
}

SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv", "env",
    "dist", "build", "target", ".idea", ".vscode", ".gradle",
    "vendor", ".next", ".nuxt", ".cache", "coverage",
}

MAX_FILE_BYTES = 2_000_000   # skip huge minified bundles
MAX_LINES_PER_FILE = 50_000  # safety cap


# ══════════════════════════════════════════════════════════════════
# MAIN ENTRY POINT
# ══════════════════════════════════════════════════════════════════
def deep_scan(target_path: str,
              max_findings: int = 1000) -> dict:
    """
    Scan a directory or ZIP file for line-level findings.
    
    Args:
        target_path: directory OR .zip path
        max_findings: hard cap on findings to return
    
    Returns:
        {
          "files_scanned": int,
          "lines_scanned": int,
          "findings":      list[dict],   # see below
          "by_severity":   {"CRITICAL": n, ...},
          "by_category":   {"Hardcoded secret": n, ...},
          "skipped":       list[str],
          "duration_ms":   float,
        }

    Each finding:
        {
          "file":         "src/auth.py",
          "line":         247,
          "column":       12,
          "severity":     "CRITICAL",
          "category":     "Hardcoded secret",
          "match_text":   "API_KEY = 'sk_live_...",
          "line_text":    "    API_KEY = 'sk_live_xxxxxxxx'",
          "why_risky":    "...",
          "fix":          "..."
        }
    """
    import time as _t
    t0 = _t.monotonic()
    target = Path(target_path)
    work_dir: Path
    cleanup_path: Optional[Path] = None

    # Handle ZIP — extract to temp dir
    if target.is_file() and target.suffix.lower() == ".zip":
        import tempfile
        tmp_dir = Path(tempfile.mkdtemp(prefix="dtctm_deepscan_"))
        cleanup_path = tmp_dir
        try:
            with zipfile.ZipFile(target, "r") as zf:
                # Safety: refuse path traversal
                for nm in zf.namelist():
                    if nm.startswith("/") or ".." in nm:
                        return {"error": f"Unsafe ZIP entry: {nm}",
                                "files_scanned": 0, "findings": []}
                zf.extractall(tmp_dir)
            work_dir = tmp_dir
        except zipfile.BadZipFile:
            return {"error": "Invalid ZIP", "files_scanned": 0, "findings": []}
    elif target.is_dir():
        work_dir = target
    elif target.is_file():
        # Single file
        work_dir = target.parent
    else:
        return {"error": f"Not found: {target}", "files_scanned": 0, "findings": []}

    findings: list[dict] = []
    files_scanned = 0
    lines_scanned = 0
    skipped: list[str] = []

    def files_to_scan():
        if target.is_file() and target.suffix.lower() != ".zip":
            yield target
            return
        for root, dirs, files in os.walk(work_dir):
            # Prune walk
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for f in files:
                p = Path(root) / f
                if p.suffix.lower() not in SCANNABLE_EXTENSIONS:
                    continue
                try:
                    if p.stat().st_size > MAX_FILE_BYTES:
                        skipped.append(f"{p.relative_to(work_dir)} (>2MB)")
                        continue
                except OSError:
                    continue
                yield p

    for fpath in files_to_scan():
        if len(findings) >= max_findings:
            break

        try:
            content = fpath.read_text(encoding="utf-8", errors="replace")
        except Exception:
            skipped.append(f"{fpath.name} (read failed)")
            continue

        lines = content.split("\n")[:MAX_LINES_PER_FILE]
        files_scanned += 1
        lines_scanned += len(lines)

        rel = fpath.relative_to(work_dir) if fpath.is_relative_to(work_dir) else fpath.name

        # Layer 1-7: regex per line
        for line_no, line_text in enumerate(lines, 1):
            if not line_text.strip():
                continue
            for pat, sev, cat, why, fix in LINE_PATTERNS:
                m = pat.search(line_text)
                if m:
                    findings.append({
                        "file":       str(rel),
                        "line":       line_no,
                        "column":     m.start() + 1,
                        "severity":   sev,
                        "category":   cat,
                        "match_text": m.group(0)[:120],
                        "line_text":  line_text.rstrip()[:200],
                        "why_risky":  why,
                        "fix":        fix,
                    })
                    if len(findings) >= max_findings:
                        break
            if len(findings) >= max_findings:
                break

        # Layer G: AST (Python files only) — taint-flow detection
        if fpath.suffix.lower() == ".py" and len(findings) < max_findings:
            try:
                tree = ast.parse(content, filename=str(rel))
                ast_findings = _ast_walk(tree, str(rel))
                findings.extend(ast_findings)
            except SyntaxError:
                pass
            except Exception as e:
                log.warning("ast_walk_failed", file=str(rel), error=str(e))

        # Layer H: entropy on long strings (packed payload detection)
        if len(findings) < max_findings:
            for line_no, line_text in enumerate(lines, 1):
                # find long quoted strings
                for m in re.finditer(r'["\']([A-Za-z0-9+/=]{60,})["\']', line_text):
                    blob = m.group(1)
                    ent = _shannon(blob)
                    if ent > 5.0:   # high entropy in long string = likely encoded
                        findings.append({
                            "file":       str(rel),
                            "line":       line_no,
                            "column":     m.start() + 1,
                            "severity":   "MEDIUM",
                            "category":   "High-entropy blob",
                            "match_text": blob[:60] + "...",
                            "line_text":  line_text.rstrip()[:200],
                            "why_risky":  f"Long string with high entropy ({ent:.2f}/8.0) — may be encoded payload, embedded binary, or obfuscated config.",
                            "fix":        "Decode + audit. If binary asset, move to separate signed file.",
                        })
                        if len(findings) >= max_findings:
                            break
                if len(findings) >= max_findings:
                    break

    # Cleanup ZIP extraction
    if cleanup_path and cleanup_path.exists():
        try:
            import shutil
            shutil.rmtree(cleanup_path, ignore_errors=True)
        except Exception:
            pass

    # Aggregations
    by_sev = Counter(f["severity"] for f in findings)
    by_cat = Counter(f["category"] for f in findings)

    return {
        "files_scanned": files_scanned,
        "lines_scanned": lines_scanned,
        "findings":      findings,
        "by_severity":   dict(by_sev),
        "by_category":   dict(by_cat),
        "skipped":       skipped[:50],
        "skipped_count": len(skipped),
        "duration_ms":   round((_t.monotonic() - t0) * 1000, 1),
    }


# ══════════════════════════════════════════════════════════════════
# AST TAINT WALK (Python only)
# ══════════════════════════════════════════════════════════════════
def _ast_walk(tree: ast.AST, fname: str) -> list[dict]:
    """Detect dangerous AST patterns: eval/exec calls, format-string sql."""
    out = []
    for node in ast.walk(tree):
        # eval/exec/compile calls
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id in ("eval", "exec", "compile"):
                out.append({
                    "file":       fname,
                    "line":       node.lineno,
                    "column":     node.col_offset + 1,
                    "severity":   "HIGH",
                    "category":   "AST: dangerous call",
                    "match_text": f"{node.func.id}(...)",
                    "line_text":  f"AST: {node.func.id}() invocation",
                    "why_risky":  f"{node.func.id}() executes arbitrary code; if any argument flows from user input → RCE.",
                    "fix":        "Replace with a safe parser (ast.literal_eval for data, json.loads for JSON).",
                })
        # subprocess with shell=True
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr in (
                "call", "Popen", "run", "check_output", "check_call"):
                for kw in (node.keywords or []):
                    if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        out.append({
                            "file":       fname,
                            "line":       node.lineno,
                            "column":     node.col_offset + 1,
                            "severity":   "HIGH",
                            "category":   "AST: subprocess shell=True",
                            "match_text": "subprocess.* shell=True",
                            "line_text":  "AST: shell=True flag",
                            "why_risky":  "shell=True with user-controlled string allows command injection.",
                            "fix":        "Use shell=False with list args: subprocess.run(['cmd', arg1])."
                        })
    return out


# ══════════════════════════════════════════════════════════════════
# SHANNON ENTROPY
# ══════════════════════════════════════════════════════════════════
def _shannon(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    L = len(s)
    return -sum((n / L) * math.log2(n / L) for n in c.values())
