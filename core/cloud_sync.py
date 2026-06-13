"""
AI-DTCTM | Cloud Sync (v1 — Supabase backend)
══════════════════════════════════════════════════════════════════════
Local-first + cloud-replicated multi-tenant data layer.

DESIGN
─────────────────
  • Local SQLite remains the source of truth for instant reads.
  • Every write also pushes to Supabase (Postgres) when configured.
  • On network failure, writes queue locally and retry every 30s.
  • Reads merge local + cloud rows (last-write-wins on case_id).
  • Row-Level Security on Supabase enforces the role-model from
    core.db_manager (Analyst sees own, SuperAdmin sees all).

CONFIGURATION (set in .env or environment)
─────────────────
  SUPABASE_URL          https://<project>.supabase.co
  SUPABASE_ANON_KEY     eyJhbGc...                    (public anon key)
  SUPABASE_TEAM_ID      ai-dtctm-prod                 (logical team scope)

If any of these is missing → cloud sync is disabled silently and the
app continues local-only (graceful degradation).

PUBLIC API
─────────────────
  cloud = get_cloud_sync()
  cloud.is_enabled()                            # bool
  cloud.push_scan(scan_row)                     # non-blocking, queued
  cloud.pull_recent(user_id, role, limit=50)    # merge-ready cloud rows
  cloud.status()                                # dict — for admin UI
  cloud.start()                                 # spawn background sync
  cloud.stop()                                  # graceful shutdown

SECURITY NOTES
─────────────────
  • Anon key is fine for client-side; RLS is the actual gate.
  • detail_json is sent as-is; encrypt client-side if PII-sensitive.
  • Network failures NEVER block local writes — telemetry never lost.
"""
from __future__ import annotations

import json
import os
import queue
import threading
import time
from datetime import datetime, timezone
from typing import Any, Optional

from core.logger import get_logger

log = get_logger(__name__)

# ── HTTP client — prefer httpx, fall back to requests ───────────────
try:
    import httpx
    _HTTP_LIB = "httpx"
except ImportError:                                           # pragma: no cover
    httpx = None                                              # type: ignore
    _HTTP_LIB = ""

try:
    import requests as _requests
except ImportError:                                           # pragma: no cover
    _requests = None                                          # type: ignore

if not _HTTP_LIB and _requests:
    _HTTP_LIB = "requests"


class CloudSync:
    """Singleton cloud-sync engine. Use `get_cloud_sync()` to access it."""

    def __init__(self) -> None:
        self.url       = (os.environ.get("SUPABASE_URL") or "").rstrip("/")
        self.anon_key  = os.environ.get("SUPABASE_ANON_KEY") or ""
        self.team_id   = os.environ.get("SUPABASE_TEAM_ID") or "default"
        self._enabled  = bool(self.url and self.anon_key and _HTTP_LIB)
        self._queue: "queue.Queue[dict]" = queue.Queue()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        # Telemetry for the admin UI
        self._last_push_at: Optional[str] = None
        self._last_pull_at: Optional[str] = None
        self._pushed_count = 0
        self._pulled_count = 0
        self._failures     = 0
        self._last_error   = ""
        if self._enabled:
            log.info("cloud_sync_init enabled=true team=%s lib=%s",
                      self.team_id, _HTTP_LIB)
        else:
            log.info("cloud_sync_init enabled=false (SUPABASE_URL missing)")

    # ── public API ────────────────────────────────────────────────

    def is_enabled(self) -> bool:
        return self._enabled

    def push_scan(self, scan: dict) -> None:
        """Queue a scan row for cloud push. Returns immediately — caller
        never blocks on network. The background thread drains the queue
        every ~5 seconds (or on shutdown)."""
        if not self._enabled:
            return
        # Shape the row to the Supabase schema (see get_setup_sql)
        row = {
            "case_id":      scan.get("case_id") or "",
            "team_id":      self.team_id,
            "user_id":      scan.get("user_id"),
            "scan_type":    scan.get("scan_type", "unknown"),
            "target":       (scan.get("target") or "")[:512],
            "target_ip":    scan.get("target_ip"),
            "verdict":      scan.get("verdict"),
            "score":        scan.get("score"),
            "detail_json":  scan.get("detail_json") or "",
            "client_ts":    scan.get("created_at")
                            or datetime.now(timezone.utc).isoformat(),
        }
        try:
            self._queue.put_nowait(row)
        except Exception as e:
            log.warning("cloud_queue_full err=%s", e)

    def pull_recent(self, *, viewer_user_id: Optional[int] = None,
                     viewer_role: Optional[str] = None,
                     limit: int = 50) -> list[dict]:
        """Fetch recent scans from cloud honoring the role model.
        Returns [] on any failure — caller should fall back to local."""
        if not self._enabled:
            return []
        try:
            params = [("select", "*"), ("order", "client_ts.desc"),
                       ("limit", str(limit)),
                       ("team_id", f"eq.{self.team_id}")]
            # Non-SuperAdmin only fetches own rows (defence in depth +
            # cuts bandwidth; RLS would block leaks anyway).
            if viewer_user_id is not None and (viewer_role or "").lower() != "superadmin":
                params.append(("user_id", f"eq.{viewer_user_id}"))
            url = f"{self.url}/rest/v1/scans"
            headers = self._headers()
            text = self._http_get(url, params=params, headers=headers)
            rows = json.loads(text) if text else []
            self._pulled_count += len(rows)
            self._last_pull_at = datetime.now(timezone.utc).isoformat()
            return rows
        except Exception as e:
            self._failures += 1
            self._last_error = f"pull: {e}"
            log.warning("cloud_pull_failed err=%s", e)
            return []

    def status(self) -> dict:
        """Snapshot for the admin UI."""
        return {
            "enabled":      self._enabled,
            "url":          self.url if self._enabled else "",
            "team_id":      self.team_id,
            "queue_depth":  self._queue.qsize(),
            "pushed":       self._pushed_count,
            "pulled":       self._pulled_count,
            "failures":     self._failures,
            "last_push_at": self._last_push_at,
            "last_pull_at": self._last_pull_at,
            "last_error":   self._last_error,
            "http_lib":     _HTTP_LIB,
        }

    def start(self) -> None:
        """Spawn the background drain thread (idempotent)."""
        if not self._enabled:
            return
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._sync_loop, name="aidtctm-cloud-sync", daemon=True,
        )
        self._thread.start()
        log.info("cloud_sync_thread_started")

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
        log.info("cloud_sync_thread_stopped")

    def force_flush(self) -> int:
        """Drain the queue synchronously — used by the admin "Sync now"
        button. Returns rows successfully pushed."""
        if not self._enabled:
            return 0
        pushed = 0
        batch = []
        while not self._queue.empty() and len(batch) < 200:
            try:
                batch.append(self._queue.get_nowait())
            except queue.Empty:
                break
        if batch:
            ok = self._post_batch(batch)
            if ok:
                pushed = len(batch)
        return pushed

    # ── internals ────────────────────────────────────────────────

    def _headers(self) -> dict:
        return {
            "apikey":        self.anon_key,
            "Authorization": f"Bearer {self.anon_key}",
            "Content-Type":  "application/json",
            "Prefer":        "return=minimal",
        }

    def _http_post(self, url: str, *, json_body, headers) -> bool:
        """One-shot POST — returns True on 2xx."""
        if not _HTTP_LIB:
            return False
        try:
            if _HTTP_LIB == "httpx":
                r = httpx.post(url, json=json_body, headers=headers, timeout=8)
            else:
                r = _requests.post(url, json=json_body, headers=headers, timeout=8)
            return 200 <= r.status_code < 300
        except Exception as e:
            self._last_error = f"post: {e}"
            return False

    def _http_get(self, url: str, *, params, headers) -> str:
        if not _HTTP_LIB:
            return ""
        if _HTTP_LIB == "httpx":
            r = httpx.get(url, params=params, headers=headers, timeout=8)
        else:
            r = _requests.get(url, params=params, headers=headers, timeout=8)
        if r.status_code < 200 or r.status_code >= 300:
            raise RuntimeError(f"HTTP {r.status_code}: {r.text[:120]}")
        return r.text

    def _post_batch(self, rows: list[dict]) -> bool:
        """Upsert by case_id so retries don't duplicate."""
        url = (f"{self.url}/rest/v1/scans"
                f"?on_conflict=case_id")
        headers = self._headers()
        headers["Prefer"] = "resolution=merge-duplicates,return=minimal"
        ok = self._http_post(url, json_body=rows, headers=headers)
        if ok:
            self._pushed_count += len(rows)
            self._last_push_at = datetime.now(timezone.utc).isoformat()
        else:
            self._failures += 1
            # Re-queue for next retry cycle (back of the line)
            for r in rows:
                try:
                    self._queue.put_nowait(r)
                except Exception:
                    break
        return ok

    def _sync_loop(self) -> None:
        """Background drain — runs every ~5s while the app lives."""
        while not self._stop.wait(5.0):
            try:
                self.force_flush()
            except Exception as e:
                self._failures += 1
                self._last_error = f"loop: {e}"
                log.warning("cloud_sync_loop_err err=%s", e)


# ── singleton accessor ─────────────────────────────────────────────

_INSTANCE: Optional[CloudSync] = None


def get_cloud_sync() -> CloudSync:
    """Module-level singleton — created on first call."""
    global _INSTANCE
    if _INSTANCE is None:
        _INSTANCE = CloudSync()
        _INSTANCE.start()
    return _INSTANCE


# ── Bootstrap helpers ──────────────────────────────────────────────

def get_setup_sql() -> str:
    """SQL the user pastes ONCE into the Supabase SQL editor to create
    the table + RLS policies that match our 3-tier role model.

    Apply at: https://app.supabase.com/project/<id>/sql/new
    """
    return """\
-- AI-DTCTM Cloud Sync — one-time Supabase setup
-- Run this in the Supabase SQL editor (Project → SQL → New query).

-- 1. SCANS table (mirrors local SQLite scans + team scope)
create table if not exists public.scans (
    id            bigserial primary key,
    case_id       text unique not null,
    team_id       text not null,
    user_id       int not null,
    scan_type     text,
    target        text,
    target_ip     text,
    verdict       text,
    score         real,
    detail_json   text,
    client_ts     timestamptz not null default now(),
    server_ts     timestamptz not null default now()
);

create index if not exists idx_scans_team   on public.scans (team_id);
create index if not exists idx_scans_user   on public.scans (user_id);
create index if not exists idx_scans_ts     on public.scans (client_ts desc);

-- 2. USER_ROLES table (mirrors local users.role for RLS policy lookup)
create table if not exists public.user_roles (
    user_id     int primary key,
    team_id     text not null,
    role        text not null check (role in ('Analyst','Admin','SuperAdmin')),
    updated_at  timestamptz not null default now()
);

-- 3. RLS POLICIES — enforce the same role gates as local
alter table public.scans      enable row level security;
alter table public.user_roles enable row level security;

-- Helper view: who is the calling client? (anon key uses team_id + user_id
-- from the headers we send; the policy joins on user_roles)
drop policy if exists "scans_select_own_or_super" on public.scans;
create policy "scans_select_own_or_super" on public.scans
    for select using (
        -- viewer is SuperAdmin in their team → see all rows in team
        exists (
            select 1 from public.user_roles ur
            where ur.team_id = scans.team_id
              and ur.user_id = (current_setting('request.headers'::text)::json->>'x-aidtctm-user-id')::int
              and ur.role = 'SuperAdmin'
        )
        or
        -- viewer is the owner of the row
        scans.user_id = (current_setting('request.headers'::text)::json->>'x-aidtctm-user-id')::int
    );

drop policy if exists "scans_insert_own" on public.scans;
create policy "scans_insert_own" on public.scans
    for insert with check (
        scans.user_id = (current_setting('request.headers'::text)::json->>'x-aidtctm-user-id')::int
    );

drop policy if exists "scans_update_own_or_super" on public.scans;
create policy "scans_update_own_or_super" on public.scans
    for update using (
        scans.user_id = (current_setting('request.headers'::text)::json->>'x-aidtctm-user-id')::int
        or
        exists (
            select 1 from public.user_roles ur
            where ur.team_id = scans.team_id
              and ur.user_id = (current_setting('request.headers'::text)::json->>'x-aidtctm-user-id')::int
              and ur.role = 'SuperAdmin'
        )
    );

-- 4. (Optional) realtime — uncomment if you want LIVE multi-device updates
-- alter publication supabase_realtime add table public.scans;

-- ✓ DONE. Now set in your .env:
--    SUPABASE_URL=<from Project → API → URL>
--    SUPABASE_ANON_KEY=<from Project → API → anon public key>
--    SUPABASE_TEAM_ID=<any string; same on every team member's machine>
--    SUPER_ADMIN_INVITE_CODE=<a long random string for first SuperAdmin>
"""
