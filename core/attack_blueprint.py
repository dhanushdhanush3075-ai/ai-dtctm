"""
AI-DTCTM | Adaptive Attack Blueprint Engine (v24)
═══════════════════════════════════════════════════════════════════════
Takes a Source Recon report (from core.source_recon) and emits a
list of tailored Attack Proposals — specific experiments the user can
fire at the clone based on what was discovered in the source code.

PHILOSOPHY
─────────────────
This mimics what senior pentesters do in the first hour of an
engagement: triage the application's actual surface, then propose
HIGH-VALUE experiments instead of running a blanket nuclei sweep.

Each AttackProposal contains:
  • id            — stable identifier
  • category      — Auth / Injection / Stress / Authorization / Upload / Recon
  • severity      — LOW / MEDIUM / HIGH / CRITICAL
  • name          — human title
  • why           — WHY this experiment matters for this app
  • how           — WHAT the experiment does
  • expected      — what success / failure looks like
  • target        — concrete URL or path to attack
  • payload_kind  — code identifier the runner dispatches on
  • severity_color — UI hint
"""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import Optional


# ─────────────────────────────────────────────────────────────────────
# DATA CLASS
# ─────────────────────────────────────────────────────────────────────
@dataclass
class AttackProposal:
    id:             str
    category:       str
    severity:       str
    name:           str
    why:            str
    how:            str
    expected:       str
    target:         str
    payload_kind:   str
    confidence:     float = 0.9      # how confident the heuristic was
    cves:           list = field(default_factory=list)
    references:    list = field(default_factory=list)

    @property
    def severity_color(self) -> str:
        return {"CRITICAL": "#DC2626", "HIGH": "#EA580C",
                 "MEDIUM": "#D97706",  "LOW": "#16A34A"}.get(self.severity, "#64748B")

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity_color"] = self.severity_color
        return d


# ─────────────────────────────────────────────────────────────────────
# GENERATOR
# ─────────────────────────────────────────────────────────────────────
def generate_proposals(recon: dict, clone_url: str = "",
                        stack: Optional[dict] = None) -> list[dict]:
    """
    Walk the recon findings and emit tailored attack proposals.

    Returns a list of dicts (suitable for JSON / UI rendering).
    """
    stack = stack or {}
    base  = (clone_url or "").rstrip("/")
    out: list[AttackProposal] = []

    # ──────────────────────────────────────────────────────────────
    # AUTHENTICATION ATTACKS — only if login form detected
    # ──────────────────────────────────────────────────────────────
    for lf in recon.get("login_forms", []):
        login_path = lf.get("action", "/login")
        login_url  = base + login_path if base else login_path

        # 1. Brute-force burst (the user's "20 wrong passwords / sec" case)
        if not recon.get("rate_limit", {}).get("present"):
            out.append(AttackProposal(
                id="auth_brute_burst_20",
                category="Authentication",
                severity="HIGH",
                name="🔓 Brute-force burst — 20 wrong passwords / sec",
                why=(
                    f"A login form was found at {login_path} but no rate-limiter "
                    "middleware was detected anywhere in the source. Real "
                    "attackers exploit this exact gap to try thousands of "
                    "passwords against one account."
                ),
                how=(
                    "Fires 20 POST requests per second to the login URL with "
                    "wrong passwords for the same username. Observes whether "
                    "the server starts returning 429 Too Many Requests, locks "
                    "the account, or accepts all 20 requests."
                ),
                expected=(
                    "PROTECTED  → 429 within ~2 sec, account temp-locked\n"
                    "VULNERABLE → all 20 requests reach auth code path → "
                    "feasibility for offline cracking confirmed."
                ),
                target=login_url,
                payload_kind="brute_force_burst",
                confidence=0.95,
                cves=["CWE-307: Improper Restriction of Excessive Auth Attempts"],
            ))

            # 2. The "100 distributed correct creds / sec" case
            out.append(AttackProposal(
                id="auth_credential_stuffing",
                category="Authentication",
                severity="CRITICAL",
                name="🎯 Credential stuffing — 100 leaked pairs (distributed)",
                why=(
                    "Without a rate-limiter, attackers replay the top-100 "
                    "leaked credential pairs from public breaches (Collection #1, "
                    "RockYou2024). If even one user reused a leaked password, "
                    "the attacker wins. This is the #1 account-takeover vector."
                ),
                how=(
                    "Sends 100 different (user,pass) combinations rapidly from "
                    "rotating User-Agents (simulating a distributed attack). "
                    "Each pair is from a real public breach dump. Observes "
                    "how many return HTTP 200 / 302 (= successful auth)."
                ),
                expected=(
                    "RESILIENT  → 0 successes (passwords don't match)\n"
                    "VULNERABLE → ≥1 success → real users found in breach DB "
                    "→ immediate forced password reset for those accounts."
                ),
                target=login_url,
                payload_kind="credential_stuffing",
                confidence=0.92,
                cves=["CWE-521: Weak Password Requirements"],
            ))

        # 3. Username enumeration via timing or error message difference
        out.append(AttackProposal(
            id="auth_user_enum",
            category="Authentication",
            severity="MEDIUM",
            name="🧮 Username enumeration",
            why=(
                "Many login pages leak whether a username exists by returning "
                "different error messages or response times. This lets an "
                "attacker build a list of valid usernames for later phishing."
            ),
            how=(
                "Sends 10 login attempts with KNOWN-good usernames + 10 with "
                "random ones. Compares response bodies, headers and timing. "
                "Looks for differences like 'User not found' vs 'Wrong password'."
            ),
            expected=(
                "ZERO-LEAK   → identical responses for both cases\n"
                "VULNERABLE  → distinguishable response → user list is enumerable."
            ),
            target=login_url,
            payload_kind="username_enum",
            confidence=0.7,
            cves=["CWE-204: Observable Response Discrepancy"],
        ))

        # 4. CSRF login PoC (if no CSRF token in form)
        if not lf.get("has_csrf_token") and not recon.get("csrf", {}).get("present"):
            out.append(AttackProposal(
                id="auth_csrf_login",
                category="Authentication",
                severity="MEDIUM",
                name="🪤 Cross-site login CSRF",
                why=(
                    "The login form has no CSRF token. An attacker hosts a "
                    "page that auto-submits the login form from the victim's "
                    "browser using attacker-controlled credentials — useful in "
                    "attacks that piggyback on the victim's session for "
                    "secondary phishing."
                ),
                how=(
                    "Generates an HTML PoC that auto-submits login on page "
                    "load using attacker-supplied credentials. We don't actually "
                    "host it — we generate the PoC code so you can verify."
                ),
                expected=(
                    "SAFE        → token validation rejects the cross-site POST\n"
                    "VULNERABLE  → server accepts the login → CSRF possible."
                ),
                target=login_url,
                payload_kind="csrf_poc",
                confidence=0.85,
                cves=["CWE-352: Cross-Site Request Forgery"],
            ))

    # ──────────────────────────────────────────────────────────────
    # AUTHORIZATION — IDOR / BOLA on API routes
    # ──────────────────────────────────────────────────────────────
    api_routes = recon.get("api_routes", [])[:6]   # cap at 6 to avoid noise
    for r in api_routes:
        if ":" not in r["path"] and "{" not in r["path"] and "<" not in r["path"]:
            continue   # only routes with path parameters are IDOR candidates
        out.append(AttackProposal(
            id=f"authz_idor_{r['path'].replace('/','_').strip('_')}",
            category="Authorization",
            severity="HIGH",
            name=f"🔢 IDOR enumeration on {r['path']}",
            why=(
                f"This API route takes an ID parameter. If the handler doesn't "
                "verify the requested resource belongs to the authenticated "
                "user (BOLA = Broken Object-Level Authorization), an attacker "
                "can iterate IDs and read other users' data."
            ),
            how=(
                f"Sends 100 GETs to {r['path']} replacing the ID with values "
                "1, 2, 3 … 100. Counts how many return HTTP 200 vs 403 / 404."
            ),
            expected=(
                "PROTECTED   → only the user's own ID returns 200\n"
                "VULNERABLE  → multiple 200s with different user data."
            ),
            target=base + r["path"] if base else r["path"],
            payload_kind="idor_enum",
            confidence=0.8,
            cves=["CWE-639: Authorization Bypass via User-Controlled Key",
                   "OWASP API #1 — BOLA"],
        ))

    # ──────────────────────────────────────────────────────────────
    # INJECTION — based on raw SQL count
    # ──────────────────────────────────────────────────────────────
    raw_sql = recon.get("raw_sql_count", 0)
    if raw_sql > 0:
        out.append(AttackProposal(
            id="inj_blind_sqli",
            category="Injection",
            severity="CRITICAL",
            name=f"💉 Blind boolean SQLi battery ({raw_sql} suspect query / queries)",
            why=(
                f"Source code contains {raw_sql} raw SQL string(s) built via "
                "string concatenation or template interpolation. This is the "
                "classic SQLi pattern — parameterised queries would have used "
                "placeholders instead."
            ),
            how=(
                "Sends 30 payloads through every detected input vector: "
                "' OR '1'='1, ' OR SLEEP(5)--, ' UNION SELECT NULL,..., "
                "and 27 more from the SQLMap test suite. Times responses to "
                "detect blind-time-based injection."
            ),
            expected=(
                "PROTECTED   → identical responses + no SLEEP delay\n"
                "VULNERABLE  → 5-sec delay = time-based SQLi → DB fully readable."
            ),
            target=base or "/",
            payload_kind="sqli_battery",
            confidence=0.85 if raw_sql > 3 else 0.6,
            cves=["CWE-89: SQL Injection", "OWASP A03: Injection"],
        ))

    # ──────────────────────────────────────────────────────────────
    # FILE UPLOAD — polyglot bypass
    # ──────────────────────────────────────────────────────────────
    for up in recon.get("file_uploads", []):
        if up.get("has_mime_check"):
            continue   # well-protected — skip
        out.append(AttackProposal(
            id=f"upload_polyglot_{up['file'].replace('/','_')}",
            category="Code Execution",
            severity="CRITICAL",
            name=f"📤 PHP-JPEG polyglot upload → RCE",
            why=(
                f"Upload handler in {up['file']} validates only the file "
                "extension or Content-Type header — neither of which the "
                "attacker controls. We upload a file that's a valid JPEG "
                "(magic bytes \\xFF\\xD8\\xFF + image dimensions) BUT contains "
                "executable <?php ?> code at the end. If the server processes "
                ".jpg files through PHP, we get RCE."
            ),
            how=(
                "POSTs a 4 KB polyglot file named shell.php.jpg to the "
                "upload endpoint. Then attempts to GET the uploaded path "
                "with ?cmd=whoami appended."
            ),
            expected=(
                "PROTECTED   → upload rejected (magic-byte content check)\n"
                "VULNERABLE  → file accepted + cmd output returned → full RCE."
            ),
            target=base or "/",
            payload_kind="polyglot_upload",
            confidence=0.9,
            cves=["CWE-434: Unrestricted Upload", "OWASP A04: Insecure Design"],
        ))

    # ──────────────────────────────────────────────────────────────
    # ADMIN / DASHBOARD — default-credential test
    # ──────────────────────────────────────────────────────────────
    for ap in list(set(recon.get("admin_panels", [])))[:3]:
        out.append(AttackProposal(
            id=f"admin_defaults_{ap.strip('/').replace('/','_')}",
            category="Authentication",
            severity="HIGH",
            name=f"🔑 Default credentials on {ap}",
            why=(
                f"Admin panel discovered at {ap}. We test the top-20 "
                "default credential pairs (admin/admin, admin/password, "
                "root/toor, etc.) — still the #1 web-app-takeover vector "
                "in 2024 according to Verizon DBIR."
            ),
            how="POST 20 default (user,pass) pairs to the admin login.",
            expected=(
                "SAFE        → all 20 rejected\n"
                "PWNED       → at least 1 succeeded → full admin compromise."
            ),
            target=base + ap if base else ap,
            payload_kind="default_creds",
            confidence=0.85,
            cves=["CWE-521: Weak Password Requirements"],
        ))

    # ──────────────────────────────────────────────────────────────
    # HARDCODED SECRETS — verify they're live
    # ──────────────────────────────────────────────────────────────
    for sec in recon.get("hardcoded_secrets", [])[:5]:
        out.append(AttackProposal(
            id=f"secret_{sec['type']}_{sec['line']}",
            category="Recon",
            severity="HIGH",
            name=f"🗝 Verify hardcoded {sec['type']} is still live",
            why=(
                f"A {sec['type']} was hardcoded in {sec['file']} line {sec['line']}. "
                "If still valid, the attacker pivots out of the web app and "
                "into your cloud / payment / source code account."
            ),
            how=(
                f"Attempts a benign read-only API call using the discovered "
                "credential to determine whether it's still active and what "
                "permissions it carries."
            ),
            expected=(
                "ROTATED     → API returns 401/403 → key is dead\n"
                "ACTIVE      → success → IMMEDIATE rotation needed."
            ),
            target=sec['file'],
            payload_kind="secret_validity",
            confidence=0.9,
            cves=["CWE-798: Use of Hard-coded Credentials"],
        ))

    # ──────────────────────────────────────────────────────────────
    # STRESS / DoS RESILIENCE — always tested
    # ──────────────────────────────────────────────────────────────
    if base:
        out.append(AttackProposal(
            id="stress_hammer_1k",
            category="Resilience",
            severity="MEDIUM",
            name="🔨 Burst stress — 1000 RPS for 10 seconds",
            why=(
                "Tests how the app degrades under realistic burst traffic. "
                "Reveals capacity ceiling, missing connection limits, and "
                "whether legitimate users are denied service during a flood."
            ),
            how=(
                "Fires 1000 requests per second to the homepage for 10 sec "
                "(=10,000 reqs). Measures p50/p95/p99 latency and error rate."
            ),
            expected=(
                "RESILIENT   → p95 < 500 ms, 0 errors\n"
                "FRAGILE     → p95 spikes > 5 sec OR > 5 % error rate\n"
                "DOWN        → 0 successful responses → DoS achievable."
            ),
            target=base + "/",
            payload_kind="rps_hammer",
            confidence=0.8,
            cves=["CWE-770: Allocation Without Limits"],
        ))

        # If any login form: slow-burn stress on that endpoint
        if recon.get("login_forms"):
            login_path = recon["login_forms"][0].get("action", "/login")
            out.append(AttackProposal(
                id="stress_login_slowburn",
                category="Resilience",
                severity="MEDIUM",
                name="🐢 Slow-burn login flood — 5 req/sec × 60 sec",
                why=(
                    "A login endpoint that runs bcrypt or similar takes ~100 ms "
                    "of CPU per request. 5/sec × 60 sec is enough to saturate "
                    "one worker without tripping any naive flood detector."
                ),
                how="POST 5 login attempts per second for 60 seconds.",
                expected=(
                    "RESILIENT  → all 300 served, no degradation\n"
                    "VULNERABLE → response time climbs > 5 sec by end."
                ),
                target=base + login_path,
                payload_kind="slow_login",
                confidence=0.75,
            ))

    # ──────────────────────────────────────────────────────────────
    # SECURITY HEADER OMISSIONS — passive but flag for reporting
    # ──────────────────────────────────────────────────────────────
    sec_hdr = recon.get("security_headers", {})
    if base and not sec_hdr.get("csp"):
        out.append(AttackProposal(
            id="hdr_check_csp",
            category="Recon",
            severity="LOW",
            name="📋 Verify CSP header on live response",
            why=(
                "Source code did not reference Content-Security-Policy. CSP "
                "is the single most effective XSS mitigation. We check the "
                "live response to confirm it's truly absent."
            ),
            how="GET / and inspect response headers for CSP.",
            expected="No CSP header → XSS / clickjacking exploitation easier.",
            target=base + "/",
            payload_kind="header_check",
            confidence=0.85,
        ))

    # Sort: CRITICAL > HIGH > MEDIUM > LOW
    sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    out.sort(key=lambda p: (sev_rank.get(p.severity, 9), p.id))
    return [p.to_dict() for p in out]
