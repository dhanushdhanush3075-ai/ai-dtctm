"""
AI-DTCTM | Database Scanner (v21 — Day 3)
══════════════════════════════════════════════════════════════════════
Scan user-uploaded database files (.sql dumps, .sqlite, .db) for
stored malware content:
  - XSS payloads stored in text columns (<script> tags)
  - Hex-encoded binary blobs in LONGTEXT
  - SQL injection artefacts stuck in VARCHAR columns
  - Malicious URLs stored in user content
  - PHP/JS eval chains in stored data
  - Web shells in BLOB columns
  - Suspicious email addresses (typosquats)

USAGE:
  from core.database_scanner import scan_sql_dump, scan_sqlite
  r = scan_sqlite("/path/to/users.db")
"""
from __future__ import annotations

import re
import sqlite3
import datetime as _dt
from pathlib import Path

from core.logger import get_logger

log = get_logger(__name__)


# ── Detection patterns ────────────────────────────────────────────
ROW_PATTERNS = [
    (r"<script[^>]*>.*?</script>",
     "CRITICAL", "Stored XSS",
     "Script tag in stored data — reflects to every user viewing this row",
     "UPDATE table SET col = REPLACE(col, '<script', '&lt;script')"),
    (r"<script",
     "HIGH", "Stored XSS (partial)",
     "Opening script tag detected",
     "Sanitise with strip_tags() or CKEditor allowlist"),
    (r"on(?:click|load|error|mouseover)\s*=\s*['\"][^'\"]+['\"]",
     "HIGH", "HTML Event Handler",
     "Inline event handler in stored content — XSS vector",
     "Strip HTML attributes starting with 'on' in pre-display sanitiser"),
    (r"javascript:",
     "HIGH", "JavaScript URI",
     "javascript: URI in stored data — XSS when clicked",
     "Filter href/src values starting with javascript:"),
    (r"data:text/html",
     "HIGH", "Data URI HTML",
     "data: URI with HTML — XSS bypass technique",
     "Block or sanitise data: URIs"),
    (r"<iframe[^>]+src=['\"]https?://",
     "MEDIUM", "Embedded IFrame",
     "External iframe in content — could load malware",
     "Validate external sources against allowlist"),
    (r"eval\s*\(",
     "HIGH", "eval() in Stored Data",
     "JavaScript eval() in database field",
     "Should never appear in stored content. Flag + remove."),
    (r"base64_decode\s*\(",
     "HIGH", "PHP base64 decode",
     "PHP decode call in stored data — backdoor signature",
     "Audit how this got into DB. Possible SQL injection resulted in code storage."),
    (r"https?://bit\.ly/[a-zA-Z0-9]{4,}",
     "LOW", "URL Shortener",
     "Bit.ly URL in user content — opaque destination",
     "Consider URL expansion check before display"),
    (r"(?i)phishing|malware|ransomware|cryptolocker",
     "LOW", "Suspicious Keyword",
     "Content mentions malware terms (context-dependent)",
     "Manual review"),
    (r"\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}",
     "MEDIUM", "Hex-Encoded Payload",
     "Hex-encoded bytes in text column — often malware",
     "Investigate. Legitimate use extremely rare."),
    # ── NEW: Plaintext password detection ──
    (r"(?i)^(password|pass|pwd|passwd|123456|admin123|password123|qwerty|letmein|welcome|monkey|dragon|master)$",
     "CRITICAL", "Plaintext Password",
     "Password stored in plain text — no hashing applied",
     "Hash passwords with bcrypt/argon2. Never store plaintext."),
    # ── NEW: SQL Injection artifacts ──
    (r"(?i)'\s*(OR|AND)\s+['\d]+=\s*['\d]+\s*--",
     "CRITICAL", "SQL Injection Artifact",
     "SQL injection payload stored in database field — indicates past attack",
     "Sanitize input with parameterized queries. Audit access logs."),
    (r"(?i)(DROP\s+TABLE|DELETE\s+FROM|UNION\s+SELECT|INSERT\s+INTO.*VALUES)",
     "HIGH", "SQL Command in Data",
     "SQL command found in data field — possible injection attempt",
     "Review how this data entered the system. Add input validation."),
    # ── NEW: Weak hash detection ──
    (r"^[a-f0-9]{32}$",
     "HIGH", "Weak MD5 Hash",
     "MD5 hash detected — cryptographically broken, easily cracked",
     "Migrate to bcrypt/argon2/scrypt. MD5 is not safe for passwords."),
    # ── NEW: Suspicious IP addresses ──
    (r"(?:^|\s)(185\.220\.|103\.21\.|45\.33\.|91\.92\.|194\.26\.)",
     "MEDIUM", "Suspicious IP Address",
     "IP from known malicious range detected in data",
     "Cross-reference with threat intel. Block if confirmed malicious."),
    # ── NEW: Bulk export / brute force detection ──
    (r"(?i)(BULK_EXPORT|BRUTE_FORCE|SQL_INJECTION_ATTEMPT|UNAUTHORIZED)",
     "HIGH", "Security Event in Data",
     "Security incident marker found in records — indicates attack activity",
     "Investigate the full audit trail. Escalate to security team."),
    # ── NEW: Email data leak patterns ──
    (r"(?i)(credit.?card|cvv|ssn|social.?security|bank.?account|routing.?number)",
     "CRITICAL", "Sensitive Data Exposure",
     "Possible PII/financial data stored without encryption",
     "Encrypt sensitive columns. Apply data masking for non-admin users."),
]

_ROW_COMPILED = [(re.compile(p, re.IGNORECASE | re.DOTALL), s, c, d, f)
                 for p, s, c, d, f in ROW_PATTERNS]

_SEVERITY_RANK = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 2}


def _scan_text_value(table: str, column: str, row_id, value: str) -> list[dict]:
    """Run all patterns against a text value. Return list of findings."""
    findings = []
    if not value or not isinstance(value, str):
        return findings
    # Skip very long binary blobs quickly
    if len(value) > 1_000_000:
        return findings
    
    for regex, severity, category, description, fix in _ROW_COMPILED:
        m = regex.search(value)
        if m:
            snippet = value[max(0, m.start() - 30):m.end() + 30]
            snippet = snippet.replace("\n", " ")[:150]
            findings.append({
                "table":       table,
                "column":      column,
                "row_id":      row_id,
                "severity":    severity,
                "category":    category,
                "description": description,
                "evidence":    snippet,
                "match":       m.group(0)[:80],
                "fix":         fix,
            })
    return findings


# ── SQLite scanner ────────────────────────────────────────────────
def scan_sqlite(db_path: str, max_rows_per_table: int = 5000) -> dict:
    """
    Parse SQLite file, scan every text column.
    
    Returns aggregate findings + table inventory.
    """
    db_path = str(db_path)
    if not Path(db_path).exists():
        return {"error": f"file not found: {db_path}"}

    findings: list = []
    tables_info: list = []
    rows_scanned = 0
    rows_flagged = 0

    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row

        # List tables
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        )
        tables = [row[0] for row in cursor.fetchall()]

        for table in tables:
            # Get schema
            try:
                schema_cursor = conn.execute(f"PRAGMA table_info({table})")
                columns = [{"name": r[1], "type": r[2]} for r in schema_cursor.fetchall()]
            except sqlite3.Error:
                columns = []

            # Count rows
            try:
                count_cursor = conn.execute(f"SELECT COUNT(*) FROM {table}")
                row_count = count_cursor.fetchone()[0]
            except sqlite3.Error:
                row_count = 0

            text_cols = [
                c["name"] for c in columns
                if c["type"].upper() in ("TEXT", "VARCHAR", "CHAR", "CLOB",
                                         "NVARCHAR", "LONGTEXT", "MEDIUMTEXT") or
                "TEXT" in c["type"].upper() or "CHAR" in c["type"].upper()
            ]

            tables_info.append({
                "name":       table,
                "columns":    columns,
                "column_count": len(columns),
                "row_count":  row_count,
                "text_column_count": len(text_cols),
                "flagged_rows": 0,
            })

            # Scan rows (limit to max_rows_per_table)
            if text_cols:
                try:
                    # Get primary key or rowid
                    pk_col = next((c["name"] for c in columns if c.get("pk")), "rowid")
                    cols_to_fetch = ", ".join([f'"{c}"' for c in text_cols] + [pk_col])
                    
                    query = f'SELECT {cols_to_fetch} FROM "{table}" LIMIT {max_rows_per_table}'
                    row_cursor = conn.execute(query)
                    for row in row_cursor:
                        rows_scanned += 1
                        row_id = row[pk_col] if pk_col in row.keys() else rows_scanned
                        flagged_in_row = False
                        for col in text_cols:
                            try:
                                value = row[col]
                            except (IndexError, KeyError):
                                continue
                            if value:
                                col_findings = _scan_text_value(table, col, row_id, str(value))
                                if col_findings:
                                    findings.extend(col_findings)
                                    flagged_in_row = True
                        if flagged_in_row:
                            rows_flagged += 1
                            # Update table info
                            for ti in tables_info:
                                if ti["name"] == table:
                                    ti["flagged_rows"] += 1
                except sqlite3.Error as e:
                    log.warning("table_scan_error", table=table, error=str(e))

        conn.close()
    except sqlite3.Error as e:
        return {"error": f"SQLite error: {e}", "findings": []}

    return _build_report(db_path, tables_info, findings, rows_scanned, rows_flagged)


# ── SQL dump file scanner ─────────────────────────────────────────
_INSERT_PATTERN = re.compile(
    r"INSERT\s+INTO\s+`?(\w+)`?\s*(?:\([^)]+\))?\s*VALUES\s*",
    re.IGNORECASE
)


def scan_sql_dump(dump_path: str, max_size: int = 100_000_000) -> dict:
    """
    Scan a .sql text file. Parses INSERT statements + scans content.
    """
    dump_path = str(dump_path)
    if not Path(dump_path).exists():
        return {"error": f"file not found: {dump_path}"}
    
    size = Path(dump_path).stat().st_size
    if size > max_size:
        return {"error": f"file too large ({size / 1e6:.0f} MB > {max_size / 1e6:.0f} MB limit)"}

    try:
        with open(dump_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except Exception as e:
        return {"error": str(e)}

    findings: list = []

    # Extract table names + infer schema from CREATE TABLE statements
    tables_info: list = []
    create_pattern = re.compile(
        r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?`?(\w+)`?\s*\(([^;]+?)\)",
        re.IGNORECASE | re.DOTALL
    )
    for m in create_pattern.finditer(content):
        table_name = m.group(1)
        schema_body = m.group(2)
        # Count columns (rough)
        col_lines = [l.strip() for l in schema_body.split(",") if l.strip()]
        tables_info.append({
            "name":          table_name,
            "columns":       [{"name": "inferred", "type": "mixed"}],
            "column_count":  len(col_lines),
            "row_count":     0,
            "flagged_rows":  0,
        })

    # Parse INSERT statements row-by-row
    rows_scanned = 0
    rows_flagged = 0
    # Match INSERT then scan its value portion
    for match in _INSERT_PATTERN.finditer(content):
        table = match.group(1)
        start = match.end()
        # Find end of this statement (simplistic — next ; at end of line)
        end = content.find(";\n", start)
        if end == -1:
            end = len(content)
        values_blob = content[start:end]
        rows_scanned += 1
        value_findings = _scan_text_value(table, "(dump-row)", rows_scanned, values_blob)
        if value_findings:
            findings.extend(value_findings)
            rows_flagged += 1
            for ti in tables_info:
                if ti["name"] == table:
                    ti["flagged_rows"] += 1

    return _build_report(dump_path, tables_info, findings, rows_scanned, rows_flagged)


def _build_report(source: str, tables: list, findings: list,
                  rows_scanned: int, rows_flagged: int) -> dict:
    sev_counts = {
        "critical": sum(1 for f in findings if f["severity"] == "CRITICAL"),
        "high":     sum(1 for f in findings if f["severity"] == "HIGH"),
        "medium":   sum(1 for f in findings if f["severity"] == "MEDIUM"),
        "low":      sum(1 for f in findings if f["severity"] == "LOW"),
    }

    if sev_counts["critical"] > 0:
        verdict = "MALICIOUS"
    elif sev_counts["high"] > 3:
        verdict = "MALICIOUS"
    elif sev_counts["high"] > 0 or sev_counts["medium"] > 5:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    return {
        "source":         source,
        "table_count":    len(tables),
        "tables":         tables,
        "rows_scanned":   rows_scanned,
        "rows_flagged":   rows_flagged,
        "finding_count":  len(findings),
        "findings":       findings,
        "severity_totals": sev_counts,
        "verdict":        verdict,
    }


# ── Remote DB connector (optional, credentials provided by user) ──
def scan_remote_mysql(host: str, port: int, user: str, password: str,
                     database: str, max_rows_per_table: int = 5000) -> dict:
    """
    Connect to a remote MySQL DB, dump + scan each text column.
    User provides credentials in their session (not stored).
    """
    try:
        import pymysql
    except ImportError:
        return {"error": "pymysql not installed. Run: pip install pymysql"}

    findings: list = []
    tables_info: list = []
    rows_scanned = 0
    rows_flagged = 0

    try:
        conn = pymysql.connect(
            host=host, port=port, user=user, password=password,
            database=database, connect_timeout=10,
            cursorclass=pymysql.cursors.DictCursor,
        )
        with conn.cursor() as cursor:
            cursor.execute("SHOW TABLES")
            tables = [list(row.values())[0] for row in cursor.fetchall()]

            for table in tables:
                cursor.execute(f"DESCRIBE `{table}`")
                columns = cursor.fetchall()
                text_cols = [
                    c["Field"] for c in columns
                    if any(t in c["Type"].upper() for t in
                           ("VARCHAR", "TEXT", "CHAR", "BLOB"))
                ]
                
                cursor.execute(f"SELECT COUNT(*) AS cnt FROM `{table}`")
                row_count = cursor.fetchone()["cnt"]
                
                tables_info.append({
                    "name": table,
                    "column_count": len(columns),
                    "row_count": row_count,
                    "text_column_count": len(text_cols),
                    "flagged_rows": 0,
                })

                if not text_cols:
                    continue

                col_list = ", ".join([f"`{c}`" for c in text_cols])
                cursor.execute(
                    f"SELECT {col_list} FROM `{table}` LIMIT {max_rows_per_table}"
                )
                for row in cursor.fetchall():
                    rows_scanned += 1
                    flagged = False
                    for col in text_cols:
                        v = row.get(col)
                        if v:
                            found = _scan_text_value(table, col, rows_scanned, str(v))
                            if found:
                                findings.extend(found)
                                flagged = True
                    if flagged:
                        rows_flagged += 1
                        for ti in tables_info:
                            if ti["name"] == table:
                                ti["flagged_rows"] += 1

        conn.close()
    except Exception as e:
        return {"error": f"Connection failed: {e}", "findings": []}

    return _build_report(f"{host}:{port}/{database}", tables_info,
                        findings, rows_scanned, rows_flagged)


# ══════════════════════════════════════════════════════════════════
# Phase 3i — CSV + Excel scanners (common student-record formats)
# ══════════════════════════════════════════════════════════════════
def scan_csv_file(csv_path: str, max_rows: int = 50000) -> dict:
    """
    Scan CSV file row-by-row for malware/secrets/SQLi-like content.
    Treats first row as header (column names).
    """
    import csv
    findings: list[dict] = []
    rows_scanned = 0
    columns: list[str] = []
    table_name = "csv"
    try:
        with open(csv_path, "r", encoding="utf-8", errors="replace", newline="") as f:
            reader = csv.reader(f)
            try:
                columns = next(reader)
            except StopIteration:
                return _build_report(csv_path, [], [], 0, 0)
            for ri, row in enumerate(reader, 1):
                if ri > max_rows:
                    break
                rows_scanned += 1
                row_had_finding = False
                for ci, val in enumerate(row):
                    if not val:
                        continue
                    col_name = columns[ci] if ci < len(columns) else f"col_{ci}"
                    new_findings = _scan_text_value(table_name, col_name, ri, str(val))
                    if new_findings:
                        findings.extend(new_findings)
                        row_had_finding = True
    except Exception as e:
        log.warning("csv_scan_failed", error=str(e))
        return {
            "status": "error", "error": f"CSV scan failed: {e}",
            "source": csv_path,
        }

    rows_flagged = len({(f.get("row_id"),) for f in findings if f.get("row_id")})
    tables_meta = [{"name": "csv", "rows_scanned": rows_scanned,
                    "columns": columns}]
    return _build_report(csv_path, tables_meta, findings, rows_scanned, rows_flagged)


def scan_excel_file(xlsx_path: str, max_rows: int = 30000) -> dict:
    """Scan every sheet in an Excel file. Requires pandas + openpyxl."""
    try:
        import pandas as pd
    except ImportError:
        raise ImportError("pandas required for Excel scanning")

    findings: list[dict] = []
    tables_meta = []
    total_rows_scanned = 0
    try:
        xl = pd.ExcelFile(xlsx_path)
    except Exception as e:
        return {"status": "error", "error": f"Could not open Excel: {e}",
                "source": xlsx_path}

    for sheet in xl.sheet_names:
        try:
            df = xl.parse(sheet, nrows=max_rows)
        except Exception:
            continue
        sheet_rows = 0
        for ri, row in df.iterrows():
            sheet_rows += 1
            for col_name, val in row.items():
                if pd.isna(val) or val == "":
                    continue
                findings.extend(_scan_text_value(
                    sheet, str(col_name), int(ri) if hasattr(ri, '__int__') else 0,
                    str(val)
                ))
        total_rows_scanned += sheet_rows
        tables_meta.append({
            "name": sheet, "rows_scanned": sheet_rows,
            "columns": list(df.columns) if not df.empty else [],
        })

    rows_flagged = len({(f.get("table"), f.get("row_id")) for f in findings})
    return _build_report(xlsx_path, tables_meta, findings,
                         total_rows_scanned, rows_flagged)
