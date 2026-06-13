"""
AI-DTCTM | Scan History Database (v21 — Day 3)
══════════════════════════════════════════════════════════════════════
SQLite table tracking every scan performed. Replaces hardcoded demo
numbers in Overview page with REAL counts from actual user activity.

Schema:
  scans:
    id INTEGER PRIMARY KEY AUTOINCREMENT
    case_id      TEXT UNIQUE
    scan_type    TEXT    -- 'url' | 'file' | 'database' | 'twin_attack'
    target       TEXT    -- URL or filename
    target_ip    TEXT
    verdict      TEXT    -- CLEAN | SUSPICIOUS | MALICIOUS | DEAD_DOMAIN
    score        REAL    -- 0-10
    sources_queried INTEGER
    sources_available INTEGER
    duration_ms  REAL
    user_id      INTEGER
    created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    detail_json  TEXT    -- full case dict serialised

USAGE:
  from core.scan_history import record_scan, get_kpis, get_recent
  record_scan(case)
  kpis = get_kpis()   # → {"scans_today": 14, "threats_blocked": 7, ...}
"""
from __future__ import annotations

import datetime
import json
import sqlite3
from pathlib import Path
from typing import Optional

from config import CFG
from core.logger import get_logger

log = get_logger(__name__)


DB_PATH = Path(__file__).parent.parent / "data" / "scan_history.db"


def _get_conn() -> sqlite3.Connection:
    """Connection factory. Creates DB + schema if missing."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    _ensure_schema(conn)
    return conn


def _ensure_schema(conn: sqlite3.Connection) -> None:
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS scans (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id           TEXT UNIQUE,
            scan_type         TEXT NOT NULL,
            target            TEXT,
            target_ip         TEXT,
            verdict           TEXT,
            score             REAL,
            sources_queried   INTEGER DEFAULT 0,
            sources_available INTEGER DEFAULT 0,
            duration_ms       REAL,
            user_id           INTEGER,
            created_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            detail_json       TEXT
        );
        CREATE TABLE IF NOT EXISTS threat_correlations (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            correlation_id    TEXT UNIQUE,
            threat1_id        TEXT,
            threat2_id        TEXT,
            relationship_type TEXT,
            confidence        REAL,
            created_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS ml_models (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            model_id          TEXT UNIQUE,
            version           TEXT,
            model_type        TEXT,
            training_date     TIMESTAMP,
            accuracy          REAL,
            precision         REAL,
            recall            REAL,
            roc_auc           REAL,
            status            TEXT,
            training_params   TEXT,
            dataset_info      TEXT,
            created_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS ab_test_results (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id           TEXT,
            model_a_id        TEXT,
            model_b_id        TEXT,
            model_a_verdict   TEXT,
            model_b_verdict   TEXT,
            ground_truth      TEXT,
            created_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS alert_rules (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_id           TEXT UNIQUE,
            user_id           INTEGER,
            trigger_condition TEXT,
            channels          TEXT,
            enabled           INTEGER DEFAULT 1,
            created_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS model_performance (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            model_id          TEXT,
            metric_date       DATE,
            accuracy          REAL,
            precision         REAL,
            recall            REAL,
            f1_score          REAL,
            scans_evaluated   INTEGER,
            created_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at);
        CREATE INDEX IF NOT EXISTS idx_scans_verdict ON scans(verdict);
        CREATE INDEX IF NOT EXISTS idx_scans_type    ON scans(scan_type);
        CREATE INDEX IF NOT EXISTS idx_correlations_threat1 ON threat_correlations(threat1_id);
        CREATE INDEX IF NOT EXISTS idx_ml_models_status ON ml_models(status);
        CREATE INDEX IF NOT EXISTS idx_ab_results_scan ON ab_test_results(scan_id);
        CREATE INDEX IF NOT EXISTS idx_alert_rules_user ON alert_rules(user_id);
        CREATE INDEX IF NOT EXISTS idx_model_perf_date ON model_performance(metric_date);
    """)
    conn.commit()


# ── Record a scan ─────────────────────────────────────────────────
def record_scan(case: dict, scan_type: str = "url",
                user_id: Optional[int] = None) -> Optional[int]:
    """Write a completed scan case to the DB. Returns row ID or None on error."""
    try:
        # v34: queue cloud push BEFORE local write so we capture the exact
        # payload the caller meant. Cloud push is non-blocking — never
        # delays the local commit.
        _cloud_row = {
            "case_id":    case.get("case_id"),
            "user_id":    user_id,
            "scan_type":  scan_type,
            "target":     case.get("target") or case.get("source") or case.get("archive"),
            "target_ip": case.get("target_ip"),
            "verdict":    case.get("fused_verdict") or case.get("verdict"),
            "score":      case.get("fused_score") or case.get("risk_score"),
            "detail_json": json.dumps(case, default=str)[:500000],
        }
        try:
            from core.cloud_sync import get_cloud_sync
            get_cloud_sync().push_scan(_cloud_row)
        except Exception:
            pass   # cloud is best-effort; local write must always succeed

        with _get_conn() as conn:
            cur = conn.execute("""
                INSERT OR REPLACE INTO scans
                (case_id, scan_type, target, target_ip, verdict, score,
                 sources_queried, sources_available, duration_ms, user_id, detail_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                case.get("case_id"),
                scan_type,
                case.get("target") or case.get("source") or case.get("archive"),
                case.get("target_ip"),
                case.get("fused_verdict") or case.get("verdict"),
                case.get("fused_score") or case.get("risk_score"),
                case.get("sources_queried", 0),
                case.get("sources_available", 0),
                case.get("duration_ms", 0),
                user_id,
                json.dumps(case, default=str)[:500000],  # cap at 500KB
            ))
            return cur.lastrowid
    except Exception as e:
        log.error("scan_record_failed", error=str(e), case_id=case.get("case_id"))
        return None


# ── Queries for dashboard KPIs ────────────────────────────────────
def get_kpis() -> dict:
    """Compute live KPIs from scan_history table for the Overview page."""
    try:
        with _get_conn() as conn:
            now = datetime.datetime.utcnow()
            today_iso = now.strftime("%Y-%m-%d")
            
            # Scans today
            scans_today = conn.execute("""
                SELECT COUNT(*) FROM scans
                WHERE DATE(created_at) = ?
            """, (today_iso,)).fetchone()[0]

            # Threats blocked (MALICIOUS verdicts) today
            threats_today = conn.execute("""
                SELECT COUNT(*) FROM scans
                WHERE DATE(created_at) = ? AND verdict IN ('MALICIOUS', 'SUSPICIOUS')
            """, (today_iso,)).fetchone()[0]

            # Total scans (all-time)
            total_scans = conn.execute("""
                SELECT COUNT(*) FROM scans
            """).fetchone()[0]

            # Total threats (all-time)
            total_threats = conn.execute("""
                SELECT COUNT(*) FROM scans WHERE verdict IN ('MALICIOUS', 'SUSPICIOUS')
            """).fetchone()[0]

            # 7-day scan trend (for sparkline)
            seven_day_trend = []
            for days_ago in range(6, -1, -1):
                day = (now - datetime.timedelta(days=days_ago)).strftime("%Y-%m-%d")
                count = conn.execute("""
                    SELECT COUNT(*) FROM scans WHERE DATE(created_at) = ?
                """, (day,)).fetchone()[0]
                seven_day_trend.append(count)

            # 7-day threat trend
            seven_day_threats = []
            for days_ago in range(6, -1, -1):
                day = (now - datetime.timedelta(days=days_ago)).strftime("%Y-%m-%d")
                count = conn.execute("""
                    SELECT COUNT(*) FROM scans 
                    WHERE DATE(created_at) = ? AND verdict IN ('MALICIOUS', 'SUSPICIOUS')
                """, (day,)).fetchone()[0]
                seven_day_threats.append(count)

            # Last scan timestamp
            last_scan = conn.execute("""
                SELECT MAX(created_at) FROM scans
            """).fetchone()[0]

            return {
                "scans_today":         scans_today,
                "threats_today":       threats_today,
                "total_scans":         total_scans,
                "total_threats":       total_threats,
                "seven_day_scan_trend":   seven_day_trend,
                "seven_day_threat_trend": seven_day_threats,
                "last_scan_at":        last_scan,
            }
    except Exception as e:
        log.error("kpi_fetch_failed", error=str(e))
        return {
            "scans_today": 0, "threats_today": 0,
            "total_scans": 0, "total_threats": 0,
            "seven_day_scan_trend":   [0]*7,
            "seven_day_threat_trend": [0]*7,
            "last_scan_at": None,
        }


def get_recent(limit: int = 20, *,
                viewer_user_id: Optional[int] = None,
                viewer_role: Optional[str] = None) -> list[dict]:
    """Recent N scans for activity feed.

    v34 multi-tenant + cloud-merged. Behaviour:
      • Pull local rows (always, source of truth for the device)
      • Pull cloud rows if Supabase is configured (cross-device sync)
      • Merge by case_id (cloud server_ts is canonical when present)
      • Apply role filter: Analyst/Admin see own; SuperAdmin sees all
    """
    is_super = (viewer_role or "").lower() == "superadmin"

    # v34: build the user-id list the viewer may see
    #   SuperAdmin  → no filter (sees all)
    #   Admin       → own + their Analysts (managed_by relationship)
    #   Analyst     → own only
    visible_ids: list[int] | None = None
    if viewer_user_id is not None and not is_super:
        if (viewer_role or "").lower() == "admin":
            try:
                from core.db_manager import get_managed_user_ids
                visible_ids = get_managed_user_ids(viewer_user_id)
            except Exception as e:
                log.warning("managed_ids_lookup_failed", error=str(e))
                visible_ids = [viewer_user_id]
        else:
            visible_ids = [viewer_user_id]

    # ── local ────────────────────────────────────────────────────
    local_rows: list[dict] = []
    try:
        with _get_conn() as conn:
            if visible_ids is not None:
                if not visible_ids:
                    return []
                placeholders = ",".join("?" * len(visible_ids))
                cursor = conn.execute(f"""
                    SELECT case_id, scan_type, target, verdict, score,
                           created_at, target_ip, user_id
                    FROM scans
                    WHERE user_id IN ({placeholders})
                    ORDER BY created_at DESC
                    LIMIT ?
                """, (*visible_ids, limit * 2))
            else:
                cursor = conn.execute("""
                    SELECT case_id, scan_type, target, verdict, score,
                           created_at, target_ip, user_id
                    FROM scans
                    ORDER BY created_at DESC
                    LIMIT ?
                """, (limit * 2,))
            local_rows = [dict(r) for r in cursor.fetchall()]
    except Exception as e:
        log.error("recent_local_fetch_failed", error=str(e))

    # ── cloud (best-effort) ──────────────────────────────────────
    cloud_rows: list[dict] = []
    try:
        from core.cloud_sync import get_cloud_sync
        cs = get_cloud_sync()
        if cs.is_enabled():
            cloud_rows = cs.pull_recent(
                viewer_user_id=viewer_user_id,
                viewer_role=viewer_role,
                limit=limit * 2,
            )
            # Normalise cloud row shape to match local row shape
            for r in cloud_rows:
                r.setdefault("created_at", r.get("client_ts"))
    except Exception:
        cloud_rows = []

    # ── merge by case_id, prefer the row with the later timestamp ──
    by_case: dict[str, dict] = {}
    for row in (*local_rows, *cloud_rows):
        cid = row.get("case_id") or ""
        if not cid:
            continue
        prev = by_case.get(cid)
        if prev is None:
            by_case[cid] = row
            continue
        # Keep whichever has the later created_at / client_ts
        prev_ts = str(prev.get("created_at") or "")
        new_ts  = str(row.get("created_at") or row.get("client_ts") or "")
        if new_ts > prev_ts:
            by_case[cid] = row
    merged = sorted(by_case.values(),
                     key=lambda r: str(r.get("created_at") or ""),
                     reverse=True)
    return merged[:limit]


def get_threat_origins(limit: int = 50) -> list[dict]:
    """Grouped IP counts for globe visualisation. Only malicious/suspicious."""
    try:
        with _get_conn() as conn:
            rows = conn.execute("""
                SELECT target_ip, COUNT(*) as hit_count,
                       MAX(score) as max_score,
                       verdict
                FROM scans
                WHERE target_ip IS NOT NULL
                  AND verdict IN ('MALICIOUS', 'SUSPICIOUS')
                GROUP BY target_ip
                ORDER BY hit_count DESC
                LIMIT ?
            """, (limit,)).fetchall()
            return [dict(r) for r in rows]
    except Exception as e:
        log.error("origins_fetch_failed", error=str(e))
        return []


def get_case(case_id: str) -> Optional[dict]:
    """Retrieve a full case by its ID."""
    try:
        with _get_conn() as conn:
            row = conn.execute("""
                SELECT * FROM scans WHERE case_id = ?
            """, (case_id,)).fetchone()
            if not row:
                return None
            d = dict(row)
            if d.get("detail_json"):
                try:
                    d["case"] = json.loads(d["detail_json"])
                except json.JSONDecodeError:
                    pass
            return d
    except Exception as e:
        log.error("case_fetch_failed", error=str(e))
        return None


def get_spark_data(metric: str, days: int = 7) -> list[int]:
    """
    Return N-day trend data for a KPI metric — sparkline arrays.

    metric can be:
      "scans_today"     → daily count of scans
      "threats_blocked" → daily count of MALICIOUS/SUSPICIOUS scans
    """
    try:
        with _get_conn() as conn:
            if metric == "scans_today":
                rows = conn.execute(f"""
                    SELECT DATE(created_at) AS day, COUNT(*) AS n
                    FROM scans
                    WHERE created_at >= datetime('now', '-{days} days')
                    GROUP BY day
                    ORDER BY day
                """).fetchall()
            elif metric == "threats_blocked":
                rows = conn.execute(f"""
                    SELECT DATE(created_at) AS day, COUNT(*) AS n
                    FROM scans
                    WHERE created_at >= datetime('now', '-{days} days')
                      AND verdict IN ('MALICIOUS','SUSPICIOUS','DEAD_DOMAIN')
                    GROUP BY day
                    ORDER BY day
                """).fetchall()
            else:
                return [0]*days

            # Build zero-padded array for last N days
            today = datetime.date.today()
            buckets = {(today - datetime.timedelta(days=i)).isoformat(): 0
                       for i in range(days)}
            for r in rows:
                day = r["day"]
                if day in buckets:
                    buckets[day] = r["n"]
            # Return in chronological order (oldest first)
            return [buckets[d] for d in sorted(buckets)]
    except Exception as e:
        log.error("spark_fetch_failed", metric=metric, error=str(e))
        return [0]*days


def get_all(limit: int = 5000) -> list[dict]:
    """Return all scans for analytics page (capped at limit)."""
    try:
        with _get_conn() as conn:
            rows = conn.execute(
                """SELECT case_id, scan_type, target, target_ip, verdict, score,
                          duration_ms, user_id, created_at
                   FROM scans
                   ORDER BY created_at DESC
                   LIMIT ?""",
                (limit,),
            ).fetchall()
            return [dict(r) for r in rows]
    except Exception as e:
        log.error("scan_history_get_all_failed", error=str(e))
        return []


# ── Advanced Analytics Functions (Phase 1) ───────────────────────────

def get_kpi_trending(interval: str = "hourly", days: int = 7) -> dict:
    """
    Get KPI metrics trending over time.
    interval: "hourly", "daily", "weekly"
    Returns dict with trending data for scans, threats, detection rates.
    """
    try:
        with _get_conn() as conn:
            if interval == "hourly":
                query = """
                    SELECT
                        STRFTIME('%Y-%m-%d %H:00', created_at) as bucket,
                        COUNT(*) as scan_count,
                        SUM(CASE WHEN verdict IN ('MALICIOUS','SUSPICIOUS') THEN 1 ELSE 0 END) as threat_count,
                        AVG(score) as avg_score,
                        MAX(score) as max_score
                    FROM scans
                    WHERE created_at >= datetime('now', '-' || ? || ' days')
                    GROUP BY bucket
                    ORDER BY bucket ASC
                """
            elif interval == "daily":
                query = """
                    SELECT
                        DATE(created_at) as bucket,
                        COUNT(*) as scan_count,
                        SUM(CASE WHEN verdict IN ('MALICIOUS','SUSPICIOUS') THEN 1 ELSE 0 END) as threat_count,
                        AVG(score) as avg_score,
                        MAX(score) as max_score
                    FROM scans
                    WHERE created_at >= datetime('now', '-' || ? || ' days')
                    GROUP BY bucket
                    ORDER BY bucket ASC
                """
            else:  # weekly
                query = """
                    SELECT
                        STRFTIME('%Y-W%W', created_at) as bucket,
                        COUNT(*) as scan_count,
                        SUM(CASE WHEN verdict IN ('MALICIOUS','SUSPICIOUS') THEN 1 ELSE 0 END) as threat_count,
                        AVG(score) as avg_score,
                        MAX(score) as max_score
                    FROM scans
                    WHERE created_at >= datetime('now', '-' || ? || ' days')
                    GROUP BY bucket
                    ORDER BY bucket ASC
                """

            rows = conn.execute(query, (days,)).fetchall()
            return {
                "interval": interval,
                "days": days,
                "data": [dict(r) for r in rows],
                "count": len(rows)
            }
    except Exception as e:
        log.error("kpi_trending_failed", error=str(e))
        return {"interval": interval, "days": days, "data": [], "count": 0}


def get_threat_distribution(timerange: str = "24h") -> dict:
    """
    Get threat severity distribution (CRITICAL/HIGH/MEDIUM/LOW/CLEAN).
    Returns breakdown by verdict type and severity levels.
    """
    try:
        with _get_conn() as conn:
            # Map timerange to SQL
            if timerange == "24h":
                where = "created_at >= datetime('now', '-1 day')"
            elif timerange == "7d":
                where = "created_at >= datetime('now', '-7 days')"
            elif timerange == "30d":
                where = "created_at >= datetime('now', '-30 days')"
            else:
                where = "1=1"

            # Get verdict distribution
            verdicts = conn.execute(f"""
                SELECT verdict, COUNT(*) as count
                FROM scans
                WHERE {where}
                GROUP BY verdict
            """).fetchall()

            # Get severity distribution (based on score ranges)
            severity = conn.execute(f"""
                SELECT
                    CASE
                        WHEN score >= 9.0 THEN 'CRITICAL'
                        WHEN score >= 7.0 THEN 'HIGH'
                        WHEN score >= 5.0 THEN 'MEDIUM'
                        WHEN score >= 3.0 THEN 'LOW'
                        ELSE 'CLEAN'
                    END as severity,
                    COUNT(*) as count
                FROM scans
                WHERE {where}
                GROUP BY severity
            """).fetchall()

            # Get scan type distribution
            scan_types = conn.execute(f"""
                SELECT scan_type, COUNT(*) as count, AVG(score) as avg_score
                FROM scans
                WHERE {where}
                GROUP BY scan_type
            """).fetchall()

            return {
                "timerange": timerange,
                "verdicts": [dict(r) for r in verdicts],
                "severity": [dict(r) for r in severity],
                "scan_types": [dict(r) for r in scan_types]
            }
    except Exception as e:
        log.error("threat_distribution_failed", error=str(e))
        return {"timerange": timerange, "verdicts": [], "severity": [], "scan_types": []}


def get_batch_summary(batch_id: str) -> dict:
    """Get summary statistics for a batch of scans."""
    try:
        with _get_conn() as conn:
            # This assumes batch_id is stored in detail_json or a separate table
            rows = conn.execute("""
                SELECT
                    COUNT(*) as total_scans,
                    SUM(CASE WHEN verdict = 'MALICIOUS' THEN 1 ELSE 0 END) as malicious_count,
                    SUM(CASE WHEN verdict = 'SUSPICIOUS' THEN 1 ELSE 0 END) as suspicious_count,
                    SUM(CASE WHEN verdict = 'CLEAN' THEN 1 ELSE 0 END) as clean_count,
                    AVG(score) as avg_score,
                    MAX(score) as max_score,
                    MIN(score) as min_score,
                    AVG(duration_ms) as avg_duration
                FROM scans
                WHERE detail_json LIKE ?
            """, (f'%"{batch_id}"%',)).fetchone()

            if rows:
                return dict(rows)
            return {}
    except Exception as e:
        log.error("batch_summary_failed", batch_id=batch_id, error=str(e))
        return {}


def get_batch_correlations(batch_id: str) -> list[dict]:
    """Find correlated threats within a batch (same hash, same malware family, etc)."""
    try:
        with _get_conn() as conn:
            rows = conn.execute("""
                SELECT * FROM threat_correlations
                WHERE threat1_id IN (
                    SELECT case_id FROM scans WHERE detail_json LIKE ?
                ) OR threat2_id IN (
                    SELECT case_id FROM scans WHERE detail_json LIKE ?
                )
                ORDER BY confidence DESC
            """, (f'%"{batch_id}"%', f'%"{batch_id}"%')).fetchall()

            return [dict(r) for r in rows]
    except Exception as e:
        log.error("batch_correlations_failed", batch_id=batch_id, error=str(e))
        return []


def get_api_health_status() -> dict:
    """Get threat intelligence API health based on recent scan attempts."""
    try:
        with _get_conn() as conn:
            # Analyze sources_available vs sources_queried from recent scans
            stats = conn.execute("""
                SELECT
                    AVG(CASE WHEN sources_available > 0 THEN CAST(sources_available AS FLOAT) / CAST(sources_queried AS FLOAT) ELSE 0 END) as availability_pct,
                    COUNT(*) as scans_sampled,
                    MIN(created_at) as sampling_start,
                    MAX(created_at) as sampling_end
                FROM scans
                WHERE created_at >= datetime('now', '-24 hours')
                  AND sources_queried > 0
            """).fetchone()

            if stats:
                return {
                    "availability_pct": dict(stats)["availability_pct"] or 0,
                    "scans_sampled": dict(stats)["scans_sampled"],
                    "sampling_start": dict(stats)["sampling_start"],
                    "sampling_end": dict(stats)["sampling_end"],
                    "status": "HEALTHY" if (dict(stats)["availability_pct"] or 0) > 0.8 else "DEGRADED"
                }
            return {"availability_pct": 0, "status": "UNKNOWN"}
    except Exception as e:
        log.error("api_health_status_failed", error=str(e))
        return {"availability_pct": 0, "status": "ERROR"}


def record_threat_correlation(threat1_id: str, threat2_id: str,
                              relationship: str = "same_hash",
                              confidence: float = 1.0) -> Optional[int]:
    """Record a correlation between two threats."""
    try:
        correlation_id = f"{threat1_id[:20]}-{threat2_id[:20]}-{relationship}"
        with _get_conn() as conn:
            cur = conn.execute("""
                INSERT OR REPLACE INTO threat_correlations
                (correlation_id, threat1_id, threat2_id, relationship_type, confidence)
                VALUES (?, ?, ?, ?, ?)
            """, (correlation_id, threat1_id, threat2_id, relationship, confidence))
            return cur.lastrowid
    except Exception as e:
        log.error("record_correlation_failed", error=str(e))
        return None
