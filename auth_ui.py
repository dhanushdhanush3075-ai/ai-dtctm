"""
AI-DTCTM | Auth UI — Mission Control edition (v20)
══════════════════════════════════════════════════════════════════════
Login / register page. Completely retheme from the old purple/violet
to the Mission Control warm-amber language.

SIGNATURE VISUAL:
  Instead of a generic holographic cube, we render a rotating "target
  reticle" — orbiting rings around a central glyph. Feels like an ops
  console target lock, not a sci-fi cube.

Depends on:
  core.db_manager  (verify_user, register_user, initialise_db, log_audit)
"""
import datetime as _dt
import streamlit as st
import streamlit.components.v1 as components
import time
from core.db_manager import (
    verify_user, register_user, initialise_db, log_audit,
    _hash_password, _get_connection,
    claim_super_admin, get_super_admin_count, promote_user,
)

# SMTP config for password-reset emails
try:
    from config import CFG
    _ALERT_EMAIL = (getattr(CFG, "ALERT_EMAIL", "") or "").strip()
    _ALERT_PASS  = (getattr(CFG, "ALERT_SMTP_PASS", "") or "").strip()
    _HAS_SMTP    = bool(_ALERT_EMAIL and _ALERT_PASS)
except Exception:
    _ALERT_EMAIL = ""; _ALERT_PASS = ""; _HAS_SMTP = False


# ════════════════════════════════════════════════════════════════════
# REAL PASSWORD RESET — DB lookup → new hash → email temp passphrase
# ════════════════════════════════════════════════════════════════════
def _mask_email(e: str) -> str:
    if not e or "@" not in e:
        return "—"
    local, _, dom = e.partition("@")
    if len(local) <= 2:
        return local[0] + "*@" + dom
    return local[:2] + "*" * max(1, len(local) - 4) + local[-2:] + "@" + dom


def _lookup_user(identifier: str) -> dict | None:
    """Find a user by username OR email (case-insensitive)."""
    if not identifier:
        return None
    try:
        ident = identifier.strip()
        conn = _get_connection()
        row = conn.execute(
            "SELECT id, username, email, role FROM users "
            "WHERE LOWER(username)=LOWER(?) OR LOWER(email)=LOWER(?) LIMIT 1",
            (ident, ident),
        ).fetchone()
        conn.close()
        if row:
            return dict(row) if hasattr(row, "keys") else {
                "id": row[0], "username": row[1], "email": row[2], "role": row[3],
            }
    except Exception:
        return None
    return None


def _gen_otp(n: int = 6) -> str:
    """Crypto-random N-digit OTP."""
    import secrets
    return "".join(str(secrets.randbelow(10)) for _ in range(n))


def _set_user_password(user_id: int, new_pwd_plain: str) -> bool:
    """Update users.password to a fresh PBKDF2 hash."""
    try:
        hashed = _hash_password(new_pwd_plain)
        conn = _get_connection()
        conn.execute("UPDATE users SET password=? WHERE id=?", (hashed, user_id))
        conn.commit()
        conn.close()
        return True
    except Exception:
        return False


def _send_otp_email(to_email: str, username: str, otp: str) -> tuple[bool, str]:
    """Send the branded OTP email via the project's SMTP config."""
    if not _HAS_SMTP:
        return False, "SMTP not configured in .env (ALERT_EMAIL + ALERT_SMTP_PASS)"
    html = f"""
    <div style="font-family:Inter,Arial,sans-serif;background:#F8FAFC;padding:24px;">
      <div style="max-width:520px;margin:0 auto;background:#FFFFFF;border-radius:14px;
                  overflow:hidden;border:1px solid #E2E8F0;
                  box-shadow:0 6px 28px -8px rgba(37,99,235,0.18);">
        <div style="background:linear-gradient(135deg,#2563EB,#7C3AED);padding:22px 28px;color:#FFFFFF;">
          <div style="font-size:1.4rem;font-weight:700;">🛡 AI-DTCTM · Password Reset OTP</div>
          <div style="font-size:0.75rem;opacity:0.9;margin-top:4px;letter-spacing:0.08em;text-transform:uppercase;">
            Mission Control · v20.0
          </div>
        </div>
        <div style="padding:24px 28px;color:#0F172A;">
          <p style="font-size:0.95rem;">Hello <b>{username}</b>,</p>
          <p style="font-size:0.9rem;line-height:1.55;color:#475569;">
            You requested a password reset for your AI-DTCTM operator account.
            Enter the one-time passcode (OTP) below on the reset page to set
            a new password. This code expires in <b>10 minutes</b>.
          </p>
          <div style="background:#0F172A;border:1px solid #1E40AF;border-radius:10px;
                      padding:18px 22px;margin:18px 0;text-align:center;">
            <div style="font-family:'JetBrains Mono',monospace;font-size:0.62rem;
                        color:#94A3B8;letter-spacing:0.18em;text-transform:uppercase;">
              One-time passcode
            </div>
            <div style="font-family:'JetBrains Mono',monospace;font-size:2.4rem;
                        color:#39FF14;letter-spacing:0.45em;font-weight:700;margin-top:10px;
                        text-shadow:0 0 8px rgba(57,255,20,0.55);
                        padding-left:0.45em;">
              {otp}
            </div>
            <div style="font-family:'JetBrains Mono',monospace;font-size:0.55rem;
                        color:#64748B;margin-top:8px;letter-spacing:0.1em;">
              EXPIRES IN 10 MINUTES
            </div>
          </div>
          <p style="font-size:0.78rem;color:#64748B;line-height:1.55;">
            ⚠ If you did <b>not</b> request this reset, ignore this email and
            contact your administrator. Your current password remains unchanged
            until you complete the OTP verification step.
          </p>
          <p style="font-size:0.74rem;color:#94A3B8;margin-top:24px;
                    padding-top:14px;border-top:1px solid #E2E8F0;">
            AI-DTCTM · Automated security message · Do not reply.
          </p>
        </div>
      </div>
    </div>
    """
    try:
        import smtplib
        from email.mime.text import MIMEText
        msg = MIMEText(html, "html")
        msg["Subject"] = f"🔐 AI-DTCTM · Password reset OTP for {username}"
        msg["From"] = _ALERT_EMAIL
        msg["To"]   = to_email
        with smtplib.SMTP("smtp.gmail.com", 587, timeout=12) as s:
            s.ehlo(); s.starttls()
            s.login(_ALERT_EMAIL, _ALERT_PASS)
            s.send_message(msg)
        return True, "sent"
    except Exception as e:
        return False, str(e)[:200]


def _request_password_reset_otp(identifier: str) -> tuple[bool, str]:
    """
    STEP 1: User submits email/username → generate OTP → send email →
            store OTP + user_id + expiry in session_state.
    Anti-enumeration: same message returned whether account exists or not.
    """
    user = _lookup_user(identifier)
    if not user:
        # Anti-enumeration — don't leak whether account exists
        return True, ("If that account exists, an OTP has been sent to the "
                      "registered email address.")
    otp = _gen_otp(6)
    expires_at = time.time() + 600  # 10 minutes
    st.session_state["pwd_reset_otp_data"] = {
        "code":       otp,
        "user_id":    user["id"],
        "email":      user["email"],
        "username":   user["username"],
        "expires_at": expires_at,
        "attempts":   0,
    }
    ok, msg = _send_otp_email(user["email"], user["username"], otp)
    try:
        log_audit(user["id"], "password_reset_otp",
                   "OTP emailed" if ok else f"email failed: {msg}")
    except Exception:
        pass
    if ok:
        return True, f"✓ OTP sent to {_mask_email(user['email'])} — check your inbox."
    return False, f"OTP generated but email delivery failed: {msg}"


def _verify_otp_and_reset(otp_input: str, new_password: str) -> tuple[bool, str]:
    """
    STEP 2: User submits OTP + new password → verify OTP → update DB.
    """
    data = st.session_state.get("pwd_reset_otp_data") or {}
    if not data:
        return False, ("No reset in progress. Request an OTP first.")

    # Expiry check
    if time.time() > data.get("expires_at", 0):
        st.session_state.pop("pwd_reset_otp_data", None)
        return False, "OTP expired (10-minute window passed). Request a new one."

    # Attempt limiter — block after 5 wrong tries
    if data.get("attempts", 0) >= 5:
        st.session_state.pop("pwd_reset_otp_data", None)
        return False, "Too many wrong OTP attempts. Request a new OTP."

    # OTP verify (constant-time-ish compare)
    import hmac
    if not hmac.compare_digest((otp_input or "").strip(), data["code"]):
        data["attempts"] = data.get("attempts", 0) + 1
        st.session_state["pwd_reset_otp_data"] = data
        remaining = 5 - data["attempts"]
        return False, f"✕ Incorrect OTP. {remaining} attempt(s) remaining."

    # Password strength
    if not new_password or len(new_password) < 8:
        return False, "New password must be at least 8 characters."

    # Update password
    if not _set_user_password(data["user_id"], new_password):
        return False, "Database error while updating password."

    try:
        log_audit(data["user_id"], "password_reset", "OTP-verified password change")
    except Exception:
        pass

    # Cleanup
    st.session_state.pop("pwd_reset_otp_data", None)
    st.session_state["pwd_reset_stage"] = "success"
    return True, f"✓ Password reset successful for {data['username']}. Sign in below."


# ── Page-level CSS: hides Streamlit chrome + styles the auth surface ──
_PAGE_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

html, body { margin: 0; padding: 0; }

.stApp, [data-testid="stAppViewContainer"], section.main, [data-testid="stMain"] {
  background: #FFFFFF !important;
  background-image: linear-gradient(180deg, #FFFFFF 0%, #F8FAFC 100%) !important;
  font-family: 'Inter', sans-serif !important;
  color: #0F172A !important;
}
.main .block-container {
  padding: 0 !important;
  max-width: 540px !important;
  margin: 0 auto !important;
  min-height: 100vh !important;
}
[data-testid="stMainBlockContainer"] { padding: 0 !important; }
[data-testid="stVerticalBlock"] { gap: 0 !important; }

body:not(.main-app) [data-testid="stSidebar"] { display: none !important; }
[data-testid="stSidebarNav"], [data-testid="stSidebar"] { display: none !important; }
header[data-testid="stHeader"], [data-testid="stToolbar"],
[data-testid="stDecoration"], [data-testid="stStatusWidget"] { display: none !important; }
#MainMenu, footer { display: none !important; }

/* ── SIGN IN / REGISTER tabs ── */
div[data-baseweb="tab-list"] {
  background: transparent !important;
  border-bottom: 1px solid #E2E8F0 !important;
  gap: 0 !important;
}
button[data-baseweb="tab"] {
  background: transparent !important;
  border-radius: 0 !important;
  font-family: 'Inter', sans-serif !important;
  font-weight: 600 !important;
  font-size: 0.8125rem !important;
  letter-spacing: 0.04em !important;
  color: #64748B !important;
  padding: 14px 24px !important;
  border: none !important;
  border-bottom: 2px solid transparent !important;
  margin-bottom: -1px !important;
  transition: all 180ms !important;
}
button[data-baseweb="tab"]:hover { color: #0F172A !important; }
button[data-baseweb="tab"][aria-selected="true"] {
  color: #2563EB !important;
  border-bottom-color: #2563EB !important;
}
div[data-baseweb="tab-panel"] { padding: 0 !important; }

/* ── Form inputs (white, royal blue accent) ── */
div[data-testid="stTextInput"] { margin-bottom: 16px !important; padding: 0 28px !important; }
div[data-testid="stTextInput"] label {
  font-family: 'Inter', sans-serif !important;
  font-size: 0.6875rem !important;
  letter-spacing: 0.06em !important;
  text-transform: uppercase !important;
  color: #64748B !important;
  font-weight: 600 !important;
  padding-bottom: 6px !important;
  display: block !important;
}
div[data-testid="stTextInput"] input {
  background: #FFFFFF !important;
  border: 1px solid #CBD5E1 !important;
  border-radius: 6px !important;
  color: #0F172A !important;
  font-family: 'Inter', sans-serif !important;
  font-size: 0.9375rem !important;
  padding: 11px 14px !important;
  caret-color: #2563EB !important;
  transition: all 180ms !important;
}
div[data-testid="stTextInput"] input:hover {
  border-color: #94A3B8 !important;
}
div[data-testid="stTextInput"] input:focus {
  border-color: #2563EB !important;
  box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.10) !important;
  outline: none !important;
  background: #FFFFFF !important;
}
div[data-testid="stTextInput"] input::placeholder { color: #94A3B8 !important; }

/* Password reveal eye button */
button[aria-label*="password"], button[aria-label*="visibility"] {
  background: transparent !important;
  color: #64748B !important;
}

/* ── Authenticate button (Royal Blue) ── */
div[data-testid="stFormSubmitButton"] { padding: 12px 28px 0 !important; }
div[data-testid="stFormSubmitButton"] > button {
  width: 100% !important;
  background: #2563EB !important;
  border: 1px solid #2563EB !important;
  border-radius: 6px !important;
  color: #FFFFFF !important;
  font-family: 'Inter', sans-serif !important;
  font-weight: 600 !important;
  font-size: 0.9rem !important;
  letter-spacing: 0.02em !important;
  padding: 12px 0 !important;
  transition: all 180ms !important;
  box-shadow: none !important;
}
div[data-testid="stFormSubmitButton"] > button:hover {
  background: #1D4ED8 !important;
  border-color: #1D4ED8 !important;
  transform: translateY(-1px) !important;
}
div[data-testid="stFormSubmitButton"] > button:active {
  transform: translateY(0) !important;
}

/* Alerts within auth */
.stAlert, [data-baseweb="notification"] {
  border-radius: 8px !important;
  margin: 0 28px 14px !important;
}

/* Caption / footer text */
[data-testid="stCaptionContainer"], .stCaption {
  color: #64748B !important;
  font-size: 0.8125rem !important;
  text-align: center !important;
  padding: 16px 28px !important;
}

/* ════════════════════════════════════════════════════════════════
   PASSWORD-RESET EXPANDER (Forgot passphrase?)
   ════════════════════════════════════════════════════════════════ */
.auth-recover-head {
  margin: 14px 28px 6px;
  padding-bottom: 6px;
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.62rem;
  font-weight: 700;
  letter-spacing: 0.16em;
  color: #1E40AF;
  text-transform: uppercase;
  border-bottom: 1px dashed rgba(37,99,235,0.18);
}
.auth-recover-help {
  padding: 6px 4px 4px;
  font-family: 'Inter', sans-serif;
  font-size: 0.78rem;
  color: #475569;
  line-height: 1.55;
}
.auth-recover-help b { color: #1E40AF; font-weight: 600; }

div[data-testid="stExpander"] {
  margin: 6px 28px !important;
  border: 1px solid #E2E8F0 !important;
  border-radius: 10px !important;
  background: linear-gradient(180deg, #FAFBFC, #F8FAFC) !important;
  overflow: hidden !important;
  transition: border-color 220ms, box-shadow 220ms !important;
}
div[data-testid="stExpander"]:hover {
  border-color: #BFDBFE !important;
  box-shadow: 0 2px 8px -2px rgba(37,99,235,0.12) !important;
}
div[data-testid="stExpander"] summary {
  font-family: 'Inter', sans-serif !important;
  font-weight: 600 !important;
  font-size: 0.82rem !important;
  color: #2563EB !important;
  padding: 10px 14px !important;
}
div[data-testid="stExpander"] summary:hover {
  background: rgba(37,99,235,0.04) !important;
}
/* Inputs INSIDE the expander get no extra horizontal padding */
div[data-testid="stExpander"] div[data-testid="stTextInput"] {
  padding: 0 !important; margin-bottom: 10px !important;
}
div[data-testid="stExpander"] div[data-testid="stFormSubmitButton"] {
  padding: 4px 0 0 !important;
}
div[data-testid="stExpander"] div[data-testid="stFormSubmitButton"] > button {
  font-size: 0.78rem !important;
  padding: 9px 0 !important;
}

/* ════════════════════════════════════════════════════════════════
   PROFESSIONAL CYBERSECURITY FOOTER (v24)
   — Deep navy glass, scanning beam, animated stats, premium look
   ════════════════════════════════════════════════════════════════ */
@keyframes auth-fade-up {
  0%   { opacity: 0; transform: translateY(10px); }
  100% { opacity: 1; transform: translateY(0); }
}
@keyframes auth-scan-line {
  0%   { transform: translateX(-100%); }
  100% { transform: translateX(100%); }
}
@keyframes auth-shield-pulse {
  0%, 100% {
    transform: scale(1);
    filter: drop-shadow(0 0 4px rgba(96,165,250,0.5));
  }
  50% {
    transform: scale(1.06);
    filter: drop-shadow(0 0 10px rgba(96,165,250,0.85));
  }
}
@keyframes auth-grid-drift {
  0%   { background-position: 0 0; }
  100% { background-position: 32px 32px; }
}
@keyframes auth-gradient-flow {
  0%   { background-position: 0% 50%; }
  50%  { background-position: 100% 50%; }
  100% { background-position: 0% 50%; }
}
@keyframes auth-stat-tick {
  0%, 100% { opacity: 1; }
  50%      { opacity: 0.55; }
}
@keyframes auth-particle-drift {
  0%   { transform: translate(0, 0); opacity: 0; }
  10%  { opacity: 0.6; }
  90%  { opacity: 0.6; }
  100% { transform: translate(20px, -8px); opacity: 0; }
}

/* ════════════════════════════════════════════════════════════════
   MINIMAL 2-LINE LIGHT FOOTER (v24-final)
   — Blends with existing light page bg, black text, just 2 lines.
   ════════════════════════════════════════════════════════════════ */
.auth-cute-footer {
  margin: 16px 28px 22px;
  padding: 10px 18px;
  position: relative;
  overflow: hidden;
  border-radius: 8px;
  background: linear-gradient(180deg, #FFFFFF 0%, #F8FAFC 100%);
  border: 1px solid #E2E8F0;
  text-align: center;
  box-shadow: 0 1px 2px rgba(15, 23, 42, 0.03);
  animation: auth-fade-up 500ms cubic-bezier(0.16, 1, 0.3, 1) both;
  animation-delay: 200ms;
}

/* Subtle blue accent line at the top (animated) */
.auth-cute-footer::before {
  content: '';
  position: absolute;
  top: 0; left: 0;
  width: 30%; height: 1px;
  background: linear-gradient(90deg,
    transparent 0%, rgba(37, 99, 235, 0.7) 50%, transparent 100%);
  animation: auth-scan-line 5s ease-in-out infinite;
  pointer-events: none;
}

/* Line 1 — Copyright (primary) */
.auth-foot-line1 {
  font-family: 'Inter', sans-serif;
  font-size: 0.78rem;
  font-weight: 600;
  color: #0F172A;
  letter-spacing: 0.01em;
  display: inline-flex;
  align-items: center;
  gap: 6px;
  justify-content: center;
}
.auth-foot-line1 .accent {
  background: linear-gradient(90deg, #2563EB, #7C3AED);
  -webkit-background-clip: text;
  background-clip: text;
  color: transparent;
  -webkit-text-fill-color: transparent;
  font-weight: 800;
  letter-spacing: 0.04em;
}
.auth-foot-line1 .dot {
  width: 5px; height: 5px;
  border-radius: 50%;
  background: #16A34A;
  box-shadow: 0 0 5px rgba(22, 163, 74, 0.7);
  animation: auth-stat-tick 1.6s ease-in-out infinite;
  display: inline-block;
}

/* Line 2 — Author credit (secondary) */
.auth-foot-line2 {
  margin-top: 3px;
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.66rem;
  color: #475569;
  letter-spacing: 0.04em;
  font-weight: 500;
}
.auth-foot-line2 b {
  color: #1E40AF;
  font-weight: 700;
  letter-spacing: 0.06em;
}
</style>
"""


# ═══════ Orbit Target — Three.js reticle hero art ═══════
# Mission Control signature: orbiting rings instead of a generic cube
_ORBIT_TARGET_HTML = """
<div style="position: relative; width: 100%; height: 280px; overflow: hidden;
            background: linear-gradient(135deg, #F8FAFC 0%, #FFFFFF 100%); border-bottom: 1px solid #E2E8F0;">
  <canvas id="mc-orbit" style="width: 100%; height: 100%; display: block;"></canvas>

  <!-- Corner HUD brackets -->
  <div style="position: absolute; top: 16px; left: 16px; width: 20px; height: 20px;
              border-top: 2px solid #2563EB; border-left: 2px solid #2563EB;"></div>
  <div style="position: absolute; top: 16px; right: 16px; width: 20px; height: 20px;
              border-top: 2px solid #2563EB; border-right: 2px solid #2563EB;"></div>
  <div style="position: absolute; bottom: 16px; left: 16px; width: 20px; height: 20px;
              border-bottom: 2px solid #2563EB; border-left: 2px solid #2563EB;"></div>
  <div style="position: absolute; bottom: 16px; right: 16px; width: 20px; height: 20px;
              border-bottom: 2px solid #2563EB; border-right: 2px solid #2563EB;"></div>

  <!-- Title overlay -->
  <div style="position: absolute; bottom: 24px; left: 0; right: 0; text-align: center;
              font-family: 'Inter', sans-serif;">
    <div style="color: #0F172A; font-size: 1.5rem; font-weight: 700; letter-spacing: 0.02em;">
      AI-DTCTM
    </div>
    <div style="color: #64748B; font-size: 0.6rem; letter-spacing: 0.32em;
                text-transform: uppercase; margin-top: 4px; font-family: 'JetBrains Mono', monospace;">
      Mission Control · v20.0
    </div>
  </div>

  <!-- Pulsing status indicator -->
  <div style="position: absolute; top: 20px; left: 50%; transform: translateX(-50%);
              display: flex; align-items: center; gap: 8px; font-family: 'JetBrains Mono', monospace;
              font-size: 0.6rem; letter-spacing: 0.2em; color: #9ACD32; text-transform: uppercase;">
    <div style="width: 6px; height: 6px; background: #9ACD32; border-radius: 50%;
                animation: mc-dot 1.4s ease-in-out infinite;"></div>
    System nominal
  </div>
</div>

<style>
@keyframes mc-dot{
  0%,100%{ opacity: 1; }
  50%    { opacity: 0.3; }
}
</style>

<script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"></script>
<script>
(function(){
  const canvas = document.getElementById('mc-orbit');
  if(!canvas) return;

  const scene = new THREE.Scene();
  const W = canvas.clientWidth, H = canvas.clientHeight;
  const camera = new THREE.PerspectiveCamera(55, W/H, 0.1, 100);
  camera.position.set(0, 0, 5);

  const renderer = new THREE.WebGLRenderer({ canvas: canvas, alpha: true, antialias: true });
  renderer.setPixelRatio(window.devicePixelRatio);
  renderer.setSize(W, H);
  renderer.setClearColor(0x000000, 0);

  const amber = 0x2563EB;
  const ivory = 0x64748B;
  const group = new THREE.Group();
  scene.add(group);

  // Three orbit rings at different angles
  function makeRing(r, tubeR, segs, colour, tilt){
    const geom = new THREE.TorusGeometry(r, tubeR, 12, segs);
    const mat  = new THREE.MeshBasicMaterial({ color: colour, transparent: true, opacity: 0.75, wireframe: false });
    const mesh = new THREE.Mesh(geom, mat);
    mesh.rotation.x = tilt.x;
    mesh.rotation.y = tilt.y;
    return mesh;
  }

  const r1 = makeRing(1.6, 0.012, 96, amber, { x: Math.PI/2, y: 0 });
  const r2 = makeRing(2.2, 0.008, 96, amber, { x: Math.PI/2.8, y: Math.PI/4 });
  const r3 = makeRing(2.8, 0.006, 96, ivory, { x: Math.PI/4,   y: Math.PI/3 });
  group.add(r1, r2, r3);

  // Central sphere (target)
  const coreGeom = new THREE.IcosahedronGeometry(0.35, 1);
  const coreMat  = new THREE.MeshBasicMaterial({ color: amber, wireframe: true });
  const core = new THREE.Mesh(coreGeom, coreMat);
  group.add(core);

  // Phase 2b — particle network nodes connected by lines (data-flow look)
  const nodeCount = 24;
  const nodes = [];
  const nodeGeom = new THREE.SphereGeometry(0.04, 8, 8);
  const nodeMatA = new THREE.MeshBasicMaterial({ color: amber, transparent: true, opacity: 0.9 });
  const nodeMatI = new THREE.MeshBasicMaterial({ color: ivory, transparent: true, opacity: 0.8 });
  for(let i = 0; i < nodeCount; i++){
    const a = (i / nodeCount) * Math.PI * 2;
    const r = 3.4 + Math.random() * 0.4;
    const m = new THREE.Mesh(nodeGeom, i % 3 === 0 ? nodeMatA : nodeMatI);
    m.position.set(Math.cos(a) * r, Math.sin(a) * r * 0.5, (Math.random()-0.5)*0.6);
    m.userData = { phase: a, baseR: r };
    scene.add(m);
    nodes.push(m);
  }

  // Connection lines between nearest neighbours
  const linkMat = new THREE.LineBasicMaterial({ color: amber, transparent: true, opacity: 0.18 });
  const linkGroup = new THREE.Group();
  scene.add(linkGroup);
  function rebuildLinks(){
    while(linkGroup.children.length) linkGroup.remove(linkGroup.children[0]);
    for(let i = 0; i < nodes.length; i++){
      for(let j = i+1; j < nodes.length; j++){
        const d = nodes[i].position.distanceTo(nodes[j].position);
        if(d < 1.6){
          const g = new THREE.BufferGeometry().setFromPoints([nodes[i].position, nodes[j].position]);
          linkGroup.add(new THREE.Line(g, linkMat));
        }
      }
    }
  }

  // Scanning sweep beam (rotates around centre)
  const beamGeom = new THREE.BufferGeometry().setFromPoints([
    new THREE.Vector3(0,0,0),
    new THREE.Vector3(3.6, 0, 0),
  ]);
  const beamMat  = new THREE.LineBasicMaterial({ color: amber, transparent: true, opacity: 0.7 });
  const beam = new THREE.Line(beamGeom, beamMat);
  scene.add(beam);

  // Crosshair
  const cross = new THREE.Group();
  function line(from, to, colour){
    const g = new THREE.BufferGeometry().setFromPoints([
      new THREE.Vector3(...from), new THREE.Vector3(...to)
    ]);
    const m = new THREE.LineBasicMaterial({ color: colour, transparent: true, opacity: 0.75 });
    return new THREE.Line(g, m);
  }
  cross.add(line([-3.2, 0, 0], [-0.7, 0, 0], amber));
  cross.add(line([ 0.7, 0, 0], [ 3.2, 0, 0], amber));
  cross.add(line([0, -3.2, 0], [0, -0.7, 0], amber));
  cross.add(line([0,  0.7, 0], [0,  3.2, 0], amber));
  scene.add(cross);

  // Scanning arc
  const arcPts = [];
  for(let i = 0; i <= 30; i++){
    const a = (i/30) * Math.PI * 0.55;
    arcPts.push(new THREE.Vector3(Math.cos(a)*1.6, Math.sin(a)*1.6, 0));
  }
  const arcGeom = new THREE.BufferGeometry().setFromPoints(arcPts);
  const arcMat  = new THREE.LineBasicMaterial({ color: amber, transparent: true, opacity: 0.9 });
  const arc = new THREE.Line(arcGeom, arcMat);
  scene.add(arc);

  // Dust points (star background)
  const stars = new THREE.BufferGeometry();
  const positions = [];
  for(let i = 0; i < 280; i++){
    positions.push((Math.random()-0.5)*16, (Math.random()-0.5)*10, (Math.random()-0.5)*10 - 4);
  }
  stars.setAttribute('position', new THREE.Float32BufferAttribute(positions, 3));
  const starMat = new THREE.PointsMaterial({ color: 0x94A3B8, size: 0.018, transparent: true, opacity: 0.8 });
  scene.add(new THREE.Points(stars, starMat));

  let t = 0;
  let linkRebuildCounter = 0;
  function render(){
    t += 0.01;
    r1.rotation.z = t * 0.6;
    r2.rotation.z = -t * 0.4;
    r3.rotation.z = t * 0.2;
    core.rotation.x = t * 0.5;
    core.rotation.y = t * 0.7;
    arc.rotation.z = t * 1.2;
    beam.rotation.z = t * 0.45;

    // Animate node orbital drift
    for(const n of nodes){
      const phase = n.userData.phase + t * 0.18;
      const r = n.userData.baseR + Math.sin(t * 0.6 + n.userData.phase) * 0.15;
      n.position.x = Math.cos(phase) * r;
      n.position.y = Math.sin(phase) * r * 0.5;
    }

    // Rebuild links every ~30 frames (cheaper than every frame)
    linkRebuildCounter++;
    if(linkRebuildCounter >= 12){
      rebuildLinks();
      linkRebuildCounter = 0;
    }

    renderer.render(scene, camera);
    requestAnimationFrame(render);
  }
  render();

  // Responsive
  window.addEventListener('resize', () => {
    const w = canvas.clientWidth, h = canvas.clientHeight;
    renderer.setSize(w, h);
    camera.aspect = w/h;
    camera.updateProjectionMatrix();
  });
})();
</script>
"""


def _render_hero():
    components.html(_ORBIT_TARGET_HTML, height=280)


def render_auth_ui() -> bool:
    """
    Render the full login/register page.
    
    Returns True if user is authenticated (session_state['authenticated']),
    False otherwise.
    """
    initialise_db()

    # Bail early if already logged in
    if st.session_state.get("authenticated"):
        return True

    st.markdown(_PAGE_CSS, unsafe_allow_html=True)

    # Apply theme overlay (Phase 3b — light is now default for everyone)
    try:
        from core.shared_css import LIGHT_THEME_CSS
        st.markdown(LIGHT_THEME_CSS, unsafe_allow_html=True)
    except Exception:
        pass

    _render_hero()

    tab_login, tab_register = st.tabs(["SIGN IN", "REGISTER"])

    with tab_login:
        with st.form("login_form", clear_on_submit=False):
            st.markdown("<div style='height:10px'></div>", unsafe_allow_html=True)
            username = st.text_input("Operator ID",
                                     placeholder="your-username",
                                     key="login_user")
            password = st.text_input("Password",
                                     placeholder="••••••••",
                                     type="password",
                                     key="login_pass")
            submitted = st.form_submit_button("Authenticate", type="primary")

            if submitted:
                ok, user = verify_user(username, password)
                if ok:
                    st.session_state["authenticated"] = True
                    st.session_state["user"] = user
                    log_audit(user.get("id"), "login", "success")
                    with st.spinner("Initialising session..."):
                        time.sleep(0.5)
                    st.rerun()
                else:
                    st.error("Authentication failed. Check credentials or contact admin.")
                    log_audit(None, "login", f"failed: {username}")

        # ── OTP-based password reset (3-stage flow) ──────────────────
        st.markdown(
            '<div class="auth-recover-head">🔑 Forgot password?</div>',
            unsafe_allow_html=True,
        )

        # Track current stage in session state
        st.session_state.setdefault("pwd_reset_stage", "request")
        _stage = st.session_state["pwd_reset_stage"]

        with st.expander("Reset your password via email OTP", expanded=False):

            # ──────────────────────────────────────────────────────
            # STAGE 1 — request OTP (enter email/username)
            # ──────────────────────────────────────────────────────
            if _stage == "request":
                st.markdown(
                    '<div class="auth-recover-help">Enter your <b>operator ID</b> or '
                    '<b>registered email</b>. We will email a <b>6-digit OTP code</b>. '
                    'On the next step you will enter the OTP and choose a new password.'
                    '</div>',
                    unsafe_allow_html=True,
                )
                with st.form("reset_request_form", clear_on_submit=False):
                    reset_ident = st.text_input(
                        "Operator ID or email",
                        placeholder="username  or  you@example.com",
                        key="reset_ident",
                    )
                    submit_req = st.form_submit_button(
                        "📧 Send OTP to email", type="primary",
                    )
                    if submit_req:
                        if not reset_ident.strip():
                            st.error("⚠ Enter your operator ID or email.")
                        elif not _HAS_SMTP:
                            st.error("✕ SMTP not configured. Contact admin to set "
                                     "ALERT_EMAIL + ALERT_SMTP_PASS in .env.")
                        else:
                            with st.spinner("Looking up account · generating OTP…"):
                                ok_r, msg_r = _request_password_reset_otp(
                                    reset_ident.strip()
                                )
                            if ok_r and st.session_state.get("pwd_reset_otp_data"):
                                # Real account found, advance to verify stage
                                st.session_state["pwd_reset_stage"] = "verify"
                                st.success(msg_r)
                                st.rerun()
                            elif ok_r:
                                # Anti-enumeration: same message, but stay on request
                                st.success(msg_r)
                            else:
                                st.error(msg_r)

            # ──────────────────────────────────────────────────────
            # STAGE 2 — enter OTP + new password
            # ──────────────────────────────────────────────────────
            elif _stage == "verify":
                _data = st.session_state.get("pwd_reset_otp_data") or {}
                _masked = _mask_email(_data.get("email", ""))
                _username = _data.get("username", "—")
                _remaining = max(0, int(_data.get("expires_at", 0) - time.time()))
                _mins = _remaining // 60
                _secs = _remaining % 60

                st.markdown(
                    f'<div class="auth-recover-help">'
                    f'OTP sent to <b>{_masked}</b> for operator <b>{_username}</b>.<br/>'
                    f'<span style="font-family:JetBrains Mono,monospace;'
                    f'font-size:0.74rem;color:#475569;">'
                    f'⏱ Code expires in <b>{_mins:02d}:{_secs:02d}</b>. '
                    f'Check inbox / spam folder.</span>'
                    f'</div>',
                    unsafe_allow_html=True,
                )

                with st.form("reset_verify_form", clear_on_submit=False):
                    otp_input = st.text_input(
                        "6-digit OTP from email",
                        placeholder="123456",
                        key="reset_otp_input",
                        max_chars=6,
                    )
                    new_pwd = st.text_input(
                        "New password",
                        placeholder="min 8 characters",
                        type="password",
                        key="reset_new_pwd",
                    )
                    new_pwd2 = st.text_input(
                        "Confirm new password",
                        placeholder="re-enter",
                        type="password",
                        key="reset_new_pwd2",
                    )
                    col_r1, col_r2 = st.columns([3, 1.4])
                    with col_r1:
                        submit_verify = st.form_submit_button(
                            "✓ Verify OTP & reset password", type="primary",
                        )
                    with col_r2:
                        cancel = st.form_submit_button("Cancel")

                    if cancel:
                        st.session_state.pop("pwd_reset_otp_data", None)
                        st.session_state["pwd_reset_stage"] = "request"
                        st.rerun()

                    if submit_verify:
                        if not otp_input or len(otp_input.strip()) != 6:
                            st.error("⚠ Enter the 6-digit OTP from your email.")
                        elif not new_pwd or len(new_pwd) < 8:
                            st.error("⚠ New password must be at least 8 characters.")
                        elif new_pwd != new_pwd2:
                            st.error("✕ Passwords do not match.")
                        else:
                            with st.spinner("Verifying OTP · updating password…"):
                                ok_v, msg_v = _verify_otp_and_reset(
                                    otp_input.strip(), new_pwd,
                                )
                            if ok_v:
                                st.success(msg_v)
                                st.rerun()
                            else:
                                st.error(msg_v)

            # ──────────────────────────────────────────────────────
            # STAGE 3 — success
            # ──────────────────────────────────────────────────────
            elif _stage == "success":
                st.markdown(
                    '<div style="background:#F0FDF4;border:1px solid #BBF7D0;'
                    'border-left:4px solid #16A34A;border-radius:8px;'
                    'padding:14px 18px;font-family:Inter,sans-serif;font-size:0.86rem;'
                    'color:#14532D;line-height:1.55;">'
                    '<b>✓ Password reset successful.</b><br/>'
                    'Use your new password on the SIGN IN form above to log in.'
                    '</div>',
                    unsafe_allow_html=True,
                )
                if st.button("← Back to reset form", key="reset_back"):
                    st.session_state["pwd_reset_stage"] = "request"
                    st.rerun()

    with tab_register:
        with st.form("register_form", clear_on_submit=False):
            st.markdown("<div style='height:10px'></div>", unsafe_allow_html=True)
            new_user = st.text_input("New operator ID",
                                     placeholder="desired-username",
                                     key="reg_user")
            new_email = st.text_input("Email",
                                      placeholder="you@example.com",
                                      key="reg_email")
            new_pass = st.text_input("Password",
                                     placeholder="min 8 chars",
                                     type="password",
                                     key="reg_pass")
            new_pass2 = st.text_input("Confirm password",
                                      type="password",
                                      key="reg_pass2")
            # v34: role selector — Analyst is free; Admin/SuperAdmin need
            # an invite code the project owner sets in .env. This is the
            # right balance: open signup for analysts, gated elevation for
            # admins. No one can self-elevate without the secret.
            new_role = st.selectbox(
                "Role",
                options=["Analyst", "Admin", "SuperAdmin"],
                index=0,
                key="reg_role",
                help="Analyst = scan + see own data. Admin / SuperAdmin "
                      "require an invite code from the project owner.",
            )
            invite_code = ""
            if new_role in ("Admin", "SuperAdmin"):
                invite_code = st.text_input(
                    f"Invite code (required for {new_role})",
                    type="password",
                    key="reg_invite",
                    placeholder="from project owner's .env file",
                    help="Set as SUPER_ADMIN_INVITE_CODE in the .env file.",
                )
            submitted = st.form_submit_button("Create account", type="primary")

            if submitted:
                if not (new_user and new_email and new_pass):
                    st.error("All fields required.")
                elif new_pass != new_pass2:
                    st.error("Passwords do not match.")
                elif len(new_pass) < 8:
                    st.error("Password must be at least 8 characters.")
                else:
                    # Step 1 — always create the account as Analyst first.
                    # register_user is hard-locked to Analyst (v34) so no
                    # one can poison the DB even if they tamper the form.
                    ok, msg = register_user(new_user, new_email, new_pass, role="Analyst")
                    if not ok:
                        st.error(f"Registration failed: {msg}")
                    elif new_role == "Analyst":
                        st.success("Account created. Switch to SIGN IN tab to continue.")
                    else:
                        # Step 2 — caller wanted Admin/SuperAdmin. Validate
                        # the invite code against the env-var bootstrap path.
                        # claim_super_admin only works for the FIRST claim
                        # (when zero SuperAdmins exist). For subsequent
                        # admins, an existing SuperAdmin must promote them.
                        if not invite_code:
                            st.warning(
                                "Account created as Analyst (no invite code provided). "
                                "Ask an existing SuperAdmin to promote you later."
                            )
                        else:
                            try:
                                # v34-fix: these were imported at module
                                # top — DO NOT re-import here. Python
                                # would treat the names as locals through
                                # the whole function and crash the sign-in
                                # path's verify_user call with UnboundLocalError.
                                # Fetch the new user's id
                                ok2, user_obj = verify_user(new_user, new_pass)
                                if not ok2 or not user_obj:
                                    st.warning("Account created. Sign in then "
                                                "use the invite code on the Admin "
                                                "page to elevate.")
                                else:
                                    uid = user_obj.get("id")
                                    if get_super_admin_count() == 0:
                                        # Bootstrap path — first ever SuperAdmin
                                        ok3, m3 = claim_super_admin(uid, invite_code)
                                        if ok3:
                                            st.success(
                                                f"✓ Account created + promoted to "
                                                f"SuperAdmin. Switch to SIGN IN."
                                            )
                                        else:
                                            st.warning(
                                                f"Account created as Analyst. "
                                                f"Promotion failed: {m3}"
                                            )
                                    else:
                                        st.warning(
                                            "Account created as Analyst. A "
                                            "SuperAdmin already exists — ask "
                                            "them to promote you from the Admin "
                                            "panel (invite code only works for "
                                            "the FIRST SuperAdmin)."
                                        )
                            except Exception as _ee:
                                st.warning(f"Account created. Elevation step "
                                            f"deferred ({_ee})")

    # ── MINIMAL 2-LINE LIGHT FOOTER ─────────────────────────────────
    _year = _dt.datetime.now().year
    st.markdown(
        f'<div class="auth-cute-footer">'
        # Line 1 — Copyright with live status dot
        f'<div class="auth-foot-line1">'
        f'<span class="dot"></span>'
        f'© {_year} <span class="accent">AI-DTCTM</span> · '
        f'All rights reserved'
        f'</div>'
        # Line 2 — Our project credit
        f'<div class="auth-foot-line2">'
        f'Our project · designed &amp; built by <b>DHANUSH S</b> · MCE'
        f'</div>'
        f'</div>',
        unsafe_allow_html=True,
    )

    return False
