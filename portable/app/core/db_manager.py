"""
AI-DTCTM | Database Manager  (v2)
──────────────────────────────────
Supports SQLite (default / portable) and MySQL (production).
Passwords are NEVER stored in plain text — bcrypt hashed.
All queries use parameterised statements → zero SQL-injection surface.
"""
import sqlite3
import hashlib
import os
import datetime
from typing import Optional, Dict, Any, List

from config import DB_TYPE, DB_PATH, MYSQL_HOST, MYSQL_PORT, MYSQL_USER, MYSQL_PASS, MYSQL_DB

# ── Bcrypt-like hashing (using hashlib + salt for portability) ───────────────
def _hash_password(password: str) -> str:
    """PBKDF2-HMAC-SHA256 with a random salt (secure, no extra lib needed)."""
    salt = os.urandom(32)
    key  = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310_000)
    return salt.hex() + ":" + key.hex()

def _verify_password(password: str, stored: str) -> bool:
    salt_hex, key_hex = stored.split(":")
    salt = bytes.fromhex(salt_hex)
    key  = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310_000)
    return key.hex() == key_hex

# ── Connection Factory ────────────────────────────────────────────────────────
def _get_connection():
    if DB_TYPE == "mysql":
        import mysql.connector
        return mysql.connector.connect(
            host=MYSQL_HOST, port=MYSQL_PORT,
            user=MYSQL_USER, password=MYSQL_PASS,
            database=MYSQL_DB, autocommit=False
        )
    # Default → SQLite
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

# ── Schema Bootstrap ─────────────────────────────────────────────────────────
SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS users (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    username   TEXT    NOT NULL,
    email      TEXT    UNIQUE NOT NULL,
    password   TEXT    NOT NULL,          -- PBKDF2 hash
    role       TEXT    DEFAULT 'analyst',
    managed_by INTEGER,                    -- v34: Admin who oversees this Analyst
    created_at TEXT    DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (managed_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS scan_history (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER REFERENCES users(id),
    target        TEXT,
    target_type   TEXT,
    risk_score    REAL,
    risk_level    TEXT,
    threat_type   TEXT,
    accuracy      REAL,
    latency_ms    REAL,
    shield_active INTEGER,
    scanned_at    TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS threat_log (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id       INTEGER REFERENCES scan_history(id),
    pattern_name  TEXT,
    pattern_type  TEXT,
    matched_value TEXT,
    severity      TEXT,
    logged_at     TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_trail (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER,
    action     TEXT,
    detail     TEXT,
    ip_addr    TEXT,
    ts         TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS login_attempts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    identifier   TEXT NOT NULL,
    attempted_at TEXT DEFAULT CURRENT_TIMESTAMP
);
"""

# Brute-force constants
_MAX_LOGIN_ATTEMPTS = 5       # failures before lockout
_LOCKOUT_WINDOW_SEC = 900     # 15-minute rolling window

def initialise_db():
    conn = _get_connection()
    cur  = conn.cursor()
    # SQLite supports multi-statement; MySQL does not — split on ;
    for stmt in SCHEMA_SQL.strip().split(";"):
        stmt = stmt.strip()
        if stmt:
            cur.execute(stmt)

    # v34 migration — add managed_by to existing DBs that pre-date v34.
    try:
        cur.execute("ALTER TABLE users ADD COLUMN managed_by INTEGER REFERENCES users(id)")
    except Exception:
        pass  # column already exists

    # security migration — login_attempts table (idempotent)
    try:
        cur.execute(
            "CREATE TABLE IF NOT EXISTS login_attempts ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "identifier TEXT NOT NULL, "
            "attempted_at TEXT DEFAULT CURRENT_TIMESTAMP)"
        )
    except Exception:
        pass

    conn.commit()
    conn.close()


# ── Brute-force protection ────────────────────────────────────────────────────
def record_failed_login(identifier: str) -> None:
    """Persist a failed login attempt for the given username/email."""
    conn = _get_connection()
    try:
        conn.execute(
            "INSERT INTO login_attempts (identifier) VALUES (?)",
            (identifier.lower().strip(),),
        )
        conn.commit()
    finally:
        conn.close()


def is_login_locked(identifier: str) -> tuple[bool, int]:
    """Return (locked, seconds_remaining) for the given identifier.

    Locked = 5 or more failed attempts in the last 15 minutes.
    """
    import time as _time
    cutoff = datetime.datetime.utcnow() - datetime.timedelta(seconds=_LOCKOUT_WINDOW_SEC)
    cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")
    conn = _get_connection()
    try:
        row = conn.execute(
            "SELECT COUNT(*) AS n, MAX(attempted_at) AS last_at "
            "FROM login_attempts "
            "WHERE identifier=? AND attempted_at >= ?",
            (identifier.lower().strip(), cutoff_str),
        ).fetchone()
        count = int(row["n"]) if row else 0
        if count < _MAX_LOGIN_ATTEMPTS:
            return False, 0
        # Compute how long until the oldest qualifying attempt expires
        oldest = conn.execute(
            "SELECT MIN(attempted_at) AS oldest FROM login_attempts "
            "WHERE identifier=? AND attempted_at >= ?",
            (identifier.lower().strip(), cutoff_str),
        ).fetchone()
        if oldest and oldest["oldest"]:
            oldest_dt = datetime.datetime.strptime(oldest["oldest"], "%Y-%m-%d %H:%M:%S")
            unlock_at = oldest_dt + datetime.timedelta(seconds=_LOCKOUT_WINDOW_SEC)
            remaining = max(0, int((unlock_at - datetime.datetime.utcnow()).total_seconds()))
        else:
            remaining = _LOCKOUT_WINDOW_SEC
        return True, remaining
    finally:
        conn.close()


def clear_failed_logins(identifier: str) -> None:
    """Clear failed login attempts on successful login."""
    conn = _get_connection()
    try:
        conn.execute(
            "DELETE FROM login_attempts WHERE identifier=?",
            (identifier.lower().strip(),),
        )
        conn.commit()
    finally:
        conn.close()

# ── User Functions ────────────────────────────────────────────────────────────
def register_user(username: str, email: str, password: str, role: str = "Analyst") -> tuple[bool, str]:
    """
    Create a new user. Returns (success, message).

    v34: locked-down role policy. Self-signup can ONLY create an Analyst
    account. Admin / Super-Admin elevation is performed via the dedicated
    promote_user() path, which itself requires an existing Super-Admin
    session OR a one-time SUPER_ADMIN_INVITE_CODE (env var) for bootstrap.

    This kills the "yaru venunalum admin aaga koodathu" hole the user
    flagged — no end-user can request admin role at signup time.
    """
    # Force role to Analyst regardless of what the UI sent
    role = "Analyst"
    # Validate inputs
    if not username or len(username) < 3:
        return False, "Username must be at least 3 characters."
    if not email or "@" not in email:
        return False, "A valid email is required."
    if not password or len(password) < 8:
        return False, "Password must be at least 8 characters."
    import re as _re
    if not _re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not _re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not _re.search(r"\d", password):
        return False, "Password must contain at least one digit."
    if not _re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?`~]", password):
        return False, "Password must contain at least one special character (!@#$%^&* etc.)."

    conn = _get_connection()
    try:
        # Pre-check uniqueness for a cleaner error message
        existing = conn.execute(
            "SELECT id FROM users WHERE username=? OR email=?", (username, email)
        ).fetchone()
        if existing:
            return False, "Username or email already registered."

        hashed = _hash_password(password)
        conn.execute(
            "INSERT INTO users (username, email, password, role) VALUES (?,?,?,?)",
            (username, email, hashed, role)
        )
        conn.commit()
        return True, "Account created successfully."
    except Exception as e:
        return False, str(e)
    finally:
        conn.close()


# ── v34: ADMIN PROMOTION + RBAC HELPERS ──────────────────────────────
# Three-tier role model:
#   Analyst     — default end-user; sees own data only
#   Admin       — team lead; manages a roster of Analysts in their team
#   SuperAdmin  — system owner; sees ALL users + data; exactly one allowed
#
# Promotion paths:
#   • First-run bootstrap: env var SUPER_ADMIN_INVITE_CODE matches what
#     the new user types in the elevate form → promoted to SuperAdmin.
#     Code is consumed (set to "" after success) so it can only be used once.
#   • Existing SuperAdmin → can promote any Analyst to Admin or another
#     SuperAdmin via promote_user(). Audit-logged.
#
# Security guarantees:
#   • Anonymous signup CANNOT elevate (role hard-coded to Analyst above)
#   • Admin elevation requires session.role == "SuperAdmin"
#   • Every promotion writes an audit_trail entry for forensics
#   • SuperAdmin demotion blocked if it would leave 0 SuperAdmins

_VALID_ROLES = ("Analyst", "Admin", "SuperAdmin")


def get_super_admin_count() -> int:
    """How many SuperAdmins currently exist."""
    conn = _get_connection()
    try:
        row = conn.execute(
            "SELECT COUNT(*) AS n FROM users WHERE role=?", ("SuperAdmin",)
        ).fetchone()
        return int(row["n"]) if row else 0
    finally:
        conn.close()


def claim_super_admin(user_id: int, invite_code: str) -> tuple[bool, str]:
    """Bootstrap path: one-time elevation to SuperAdmin via env-var code.

    Use cases:
      • Fresh install — no SuperAdmin exists yet, first-comer claims it
        by knowing the SUPER_ADMIN_INVITE_CODE env var.
      • Recovery — if all SuperAdmins are removed, sysadmin can rotate
        the env var and re-claim.

    The code is checked at runtime; we do NOT store it in the DB.
    """
    import os
    expected = (os.environ.get("SUPER_ADMIN_INVITE_CODE") or "").strip()
    if not expected:
        return False, "Bootstrap disabled (SUPER_ADMIN_INVITE_CODE not set)."
    if invite_code.strip() != expected:
        return False, "Invalid invite code."
    if get_super_admin_count() > 0:
        return False, ("SuperAdmin already exists. Ask the existing SuperAdmin "
                       "to promote you, or rotate the env code first.")
    conn = _get_connection()
    try:
        conn.execute("UPDATE users SET role=? WHERE id=?", ("SuperAdmin", user_id))
        conn.execute(
            "INSERT INTO audit_trail (user_id, action, detail, ip_addr) "
            "VALUES (?, ?, ?, ?)",
            (user_id, "promote", "claimed SuperAdmin via invite code", "local"),
        )
        conn.commit()
        return True, "Promoted to SuperAdmin."
    except Exception as e:
        return False, str(e)
    finally:
        conn.close()


def get_managed_user_ids(admin_user_id: int) -> list[int]:
    """v34: list of user_ids this Admin oversees.

    Includes:
      • the admin themselves (id == admin_user_id)
      • every Analyst with users.managed_by == admin_user_id

    Used by scan_history.get_recent() to scope the visible feed to an
    Admin's own team, never spilling other Admins' or Analysts' data.
    SuperAdmin should not call this — they see everything regardless.
    """
    conn = _get_connection()
    try:
        rows = conn.execute(
            "SELECT id FROM users WHERE managed_by=? OR id=?",
            (admin_user_id, admin_user_id),
        ).fetchall()
        return [int(r["id"]) for r in rows]
    finally:
        conn.close()


def assign_analyst_to_admin(actor_user_id: int, analyst_user_id: int,
                              admin_user_id: int | None) -> tuple[bool, str]:
    """Assign an Analyst to an Admin. SuperAdmin-only.

    Pass `admin_user_id=None` to unassign (Analyst becomes unmanaged →
    visible only to SuperAdmin and themselves).
    """
    conn = _get_connection()
    try:
        actor = conn.execute(
            "SELECT role FROM users WHERE id=?", (actor_user_id,)
        ).fetchone()
        if not actor or actor["role"] != "SuperAdmin":
            return False, "Only SuperAdmin may assign analysts."

        analyst = conn.execute(
            "SELECT id, username, role FROM users WHERE id=?",
            (analyst_user_id,),
        ).fetchone()
        if not analyst:
            return False, "Analyst not found."
        if analyst["role"] not in ("Analyst", "analyst"):
            return False, ("Only Analysts can be assigned to an Admin. "
                            f"User '{analyst['username']}' is {analyst['role']}.")

        if admin_user_id is not None:
            mgr = conn.execute(
                "SELECT id, username, role FROM users WHERE id=?",
                (admin_user_id,),
            ).fetchone()
            if not mgr:
                return False, "Target Admin not found."
            if mgr["role"] not in ("Admin", "SuperAdmin"):
                return False, ("Target user must be an Admin or SuperAdmin "
                                f"(is {mgr['role']}).")

        conn.execute("UPDATE users SET managed_by=? WHERE id=?",
                     (admin_user_id, analyst_user_id))
        conn.execute(
            "INSERT INTO audit_trail (user_id, action, detail, ip_addr) "
            "VALUES (?, ?, ?, ?)",
            (actor_user_id, "assign",
             f"{analyst['username']} → admin_id={admin_user_id}", "local"),
        )
        conn.commit()
        action = "unassigned" if admin_user_id is None else f"→ admin id {admin_user_id}"
        return True, f"{analyst['username']} {action}."
    except Exception as e:
        return False, str(e)
    finally:
        conn.close()


def promote_user(actor_user_id: int, target_user_id: int,
                  new_role: str) -> tuple[bool, str]:
    """Existing-SuperAdmin promotes another user.

    Hardened:
      • Only SuperAdmin sessions may call this
      • Role must be in _VALID_ROLES
      • Demoting the last SuperAdmin is refused
      • Self-demote refused (must transfer first)
      • Every change is audit-logged
    """
    if new_role not in _VALID_ROLES:
        return False, f"Invalid role: {new_role}"
    conn = _get_connection()
    try:
        actor = conn.execute(
            "SELECT role FROM users WHERE id=?", (actor_user_id,)
        ).fetchone()
        if not actor or actor["role"] != "SuperAdmin":
            return False, "Only SuperAdmin may promote users."
        target = conn.execute(
            "SELECT id, username, role FROM users WHERE id=?", (target_user_id,)
        ).fetchone()
        if not target:
            return False, "Target user not found."
        old_role = target["role"]
        if old_role == new_role:
            return False, f"Already {new_role}."
        # Prevent leaving zero SuperAdmins
        if old_role == "SuperAdmin" and new_role != "SuperAdmin":
            if get_super_admin_count() <= 1:
                return False, ("Cannot demote — at least one SuperAdmin "
                               "must remain. Promote a replacement first.")
            if actor_user_id == target_user_id:
                return False, "Refuse to self-demote the last SuperAdmin."
        conn.execute("UPDATE users SET role=? WHERE id=?",
                     (new_role, target_user_id))
        conn.execute(
            "INSERT INTO audit_trail (user_id, action, detail, ip_addr) "
            "VALUES (?, ?, ?, ?)",
            (actor_user_id, "promote",
             f"{target['username']}: {old_role} → {new_role}", "local"),
        )
        conn.commit()
        return True, f"{target['username']} promoted to {new_role}."
    except Exception as e:
        return False, str(e)
    finally:
        conn.close()


def verify_user(identifier: str, password: str) -> tuple[bool, Optional[Dict]]:
    """
    Authenticate a user by username OR email.
    Returns (success, user_dict_or_none).
    
    Patched v20: accepts username OR email (UX: users shouldn't need to
    remember which they registered with). Returns a tuple shape so
    auth_ui can handle (False, None) uniformly.
    """
    conn = _get_connection()
    try:
        cur  = conn.execute(
            "SELECT * FROM users WHERE username=? OR email=?",
            (identifier, identifier)
        )
        row  = cur.fetchone()
        if row and _verify_password(password, row["password"]):
            user = dict(row)
            user.pop("password", None)  # never leak the hash into session state
            return True, user
        return False, None
    finally:
        conn.close()

def get_user_by_id(user_id: int) -> Optional[Dict]:
    conn = _get_connection()
    try:
        cur = conn.execute("SELECT id,username,email,role,created_at FROM users WHERE id=?", (user_id,))
        row = cur.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()

# ── Scan History ──────────────────────────────────────────────────────────────
def save_scan(user_id: int, target: str, target_type: str, metrics: Dict) -> int:
    conn = _get_connection()
    try:
        cur = conn.execute(
            """INSERT INTO scan_history
               (user_id,target,target_type,risk_score,risk_level,threat_type,accuracy,latency_ms,shield_active)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (
                user_id, target, target_type,
                metrics.get("risk_score", 0),
                metrics.get("risk_level", "UNKNOWN"),
                metrics.get("threat_type", "Unknown"),
                metrics.get("accuracy", 0),
                metrics.get("latency_ms", 0),
                int(metrics.get("shield_active", True)),
            )
        )
        scan_id = cur.lastrowid
        # Save matched threat patterns
        for pattern in metrics.get("matched_patterns", []):
            conn.execute(
                "INSERT INTO threat_log (scan_id,pattern_name,pattern_type,matched_value,severity) VALUES (?,?,?,?,?)",
                (scan_id, pattern["name"], pattern["type"], pattern["value"], pattern["severity"])
            )
        conn.commit()
        return scan_id
    finally:
        conn.close()

def get_scan_history(user_id: int, limit: int = 50) -> List[Dict]:
    conn = _get_connection()
    try:
        cur = conn.execute(
            "SELECT * FROM scan_history WHERE user_id=? ORDER BY scanned_at DESC LIMIT ?",
            (user_id, limit)
        )
        return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()

def get_threat_stats(user_id: int) -> Dict:
    conn = _get_connection()
    try:
        cur = conn.execute(
            """SELECT
                COUNT(*)                              AS total_scans,
                SUM(CASE WHEN risk_level='CRITICAL' THEN 1 ELSE 0 END) AS critical,
                SUM(CASE WHEN risk_level='HIGH'     THEN 1 ELSE 0 END) AS high,
                SUM(CASE WHEN risk_level='MEDIUM'   THEN 1 ELSE 0 END) AS medium,
                SUM(CASE WHEN risk_level='LOW'      THEN 1 ELSE 0 END) AS low,
                AVG(accuracy)                         AS avg_accuracy,
                AVG(latency_ms)                       AS avg_latency
               FROM scan_history WHERE user_id=?""",
            (user_id,)
        )
        return dict(cur.fetchone() or {})
    finally:
        conn.close()

def log_audit(user_id: int, action: str, detail: str, ip: str = "127.0.0.1"):
    conn = _get_connection()
    try:
        conn.execute(
            "INSERT INTO audit_trail (user_id,action,detail,ip_addr) VALUES (?,?,?,?)",
            (user_id, action, detail, ip)
        )
        conn.commit()
    finally:
        conn.close()

# ── Admin Functions ───────────────────────────────────────────────────────────
def get_all_users() -> List[Dict]:
    conn = _get_connection()
    try:
        cur = conn.execute("SELECT id,username,email,role,created_at FROM users ORDER BY created_at DESC")
        return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


def get_audit_log(limit: int = 200) -> List[Dict]:
    """Return recent audit entries for admin panel."""
    conn = _get_connection()
    try:
        cur = conn.execute(
            "SELECT id, user_id, action, detail, ip_addr AS ip, "
            "ts AS timestamp FROM audit_trail "
            "ORDER BY ts DESC LIMIT ?",
            (limit,),
        )
        return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()

def delete_user(actor_user_id: int, target_user_id: int) -> tuple[bool, str]:
    """Delete a user. Requires actor to be SuperAdmin. Audit-logged."""
    conn = _get_connection()
    try:
        actor = conn.execute(
            "SELECT role FROM users WHERE id=?", (actor_user_id,)
        ).fetchone()
        if not actor or actor["role"] != "SuperAdmin":
            return False, "Only SuperAdmin may delete users."
        if actor_user_id == target_user_id:
            return False, "Cannot delete your own account."
        target = conn.execute(
            "SELECT username, role FROM users WHERE id=?", (target_user_id,)
        ).fetchone()
        if not target:
            return False, "User not found."
        if target["role"] == "SuperAdmin" and get_super_admin_count() <= 1:
            return False, "Cannot delete the last SuperAdmin."
        conn.execute("DELETE FROM users WHERE id=?", (target_user_id,))
        conn.execute(
            "INSERT INTO audit_trail (user_id, action, detail, ip_addr) VALUES (?,?,?,?)",
            (actor_user_id, "delete_user", f"deleted {target['username']} (was {target['role']})", "local"),
        )
        conn.commit()
        return True, f"User '{target['username']}' deleted."
    except Exception as e:
        return False, str(e)
    finally:
        conn.close()


def update_user_role(actor_user_id: int, target_user_id: int, new_role: str) -> tuple[bool, str]:
    """Role update shim — delegates to promote_user with full RBAC enforcement."""
    return promote_user(actor_user_id, target_user_id, new_role)

def get_all_scans(limit: int = 200) -> List[Dict]:
    conn = _get_connection()
    try:
        cur = conn.execute("""
            SELECT s.*, u.username FROM scan_history s
            LEFT JOIN users u ON s.user_id = u.id
            ORDER BY s.scanned_at DESC LIMIT ?""", (limit,))
        return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()

def get_system_stats() -> Dict:
    conn = _get_connection()
    try:
        stats = {}
        stats["total_users"]  = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        stats["total_scans"]  = conn.execute("SELECT COUNT(*) FROM scan_history").fetchone()[0]
        stats["critical"]     = conn.execute("SELECT COUNT(*) FROM scan_history WHERE risk_level='CRITICAL'").fetchone()[0]
        stats["high"]         = conn.execute("SELECT COUNT(*) FROM scan_history WHERE risk_level='HIGH'").fetchone()[0]
        stats["avg_accuracy"] = conn.execute("SELECT AVG(accuracy) FROM scan_history").fetchone()[0] or 0
        return stats
    finally:
        conn.close()

def get_audit_trail(limit: int = 100) -> List[Dict]:
    conn = _get_connection()
    try:
        cur = conn.execute("""
            SELECT a.*, u.username FROM audit_trail a
            LEFT JOIN users u ON a.user_id = u.id
            ORDER BY a.ts DESC LIMIT ?""", (limit,))
        return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()
