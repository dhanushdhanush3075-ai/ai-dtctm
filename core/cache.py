"""
AI-DTCTM | SQLite TTL Cache
════════════════════════════════════════════════════════════════════
A small, dependency-free cache that stores API responses in SQLite
with time-to-live (TTL) expiry.

WHY THIS EXISTS:
  - VirusTotal free tier = 4 requests/minute. Without caching, a live
    demo that scans 10 URLs will hit the rate limit and crash.
  - Shodan free tier = 100/month. One accidental retry loop burns it.
  - Every external API we use has limits. Cache = safety net.

HOW IT WORKS:
  @cached(ttl=300)
  def virustotal_lookup(url): ...
  
  First call → hits API → stores result in cache.db with expiry.
  Second call within 5 minutes → returns cached result (no API hit).
  After 5 minutes → cache entry expired, next call hits API again.

DESIGN CHOICES:
  - SQLite (not Redis) — zero install, portable, works on Windows/Mac/Linux
  - Key = SHA256 of (function name + args) — safe against long keys
  - Value = JSON-serialised return value
  - Thread-safe via SQLite's built-in locking

USAGE:
  from core.cache import cached, get_cache

  @cached(ttl=300)
  def scan_url(url: str) -> dict:
      return requests.get(f"https://api.example.com/scan?url={url}").json()

  # Manual use:
  cache = get_cache()
  cache.set("my_key", {"result": "hi"}, ttl=60)
  cache.get("my_key")  # → {"result": "hi"} or None if expired
"""
from __future__ import annotations

import functools
import hashlib
import json
import sqlite3
import time
from pathlib import Path
from typing import Any, Callable, Optional

from config import CACHE_DB, CFG


class TTLCache:
    """SQLite-backed key-value cache with time-to-live expiry."""

    def __init__(self, db_path: Path = CACHE_DB):
        self.db_path = db_path
        self._init_db()

    def _init_db(self) -> None:
        """Create the cache table if it doesn't exist."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cache (
                    key        TEXT PRIMARY KEY,
                    value      TEXT NOT NULL,
                    expires_at REAL NOT NULL,
                    created_at REAL NOT NULL
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_expires ON cache(expires_at)")

    def get(self, key: str) -> Optional[Any]:
        """Fetch a value if present and not expired. Returns None otherwise."""
        now = time.time()
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT value FROM cache WHERE key = ? AND expires_at > ?",
                (key, now)
            ).fetchone()
        if row is None:
            return None
        try:
            return json.loads(row[0])
        except json.JSONDecodeError:
            return None

    def set(self, key: str, value: Any, ttl: int = None) -> None:
        """Store a value with TTL (seconds). Defaults to CFG.CACHE_DEFAULT_TTL."""
        if ttl is None:
            ttl = CFG.CACHE_DEFAULT_TTL
        now = time.time()
        serialised = json.dumps(value, default=str)  # default=str for datetime etc.
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO cache (key, value, expires_at, created_at) VALUES (?, ?, ?, ?)",
                (key, serialised, now + ttl, now)
            )

    def delete(self, key: str) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM cache WHERE key = ?", (key,))

    def clear(self) -> int:
        """Wipe the whole cache. Returns count of deleted entries."""
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.execute("DELETE FROM cache")
            return cur.rowcount

    def purge_expired(self) -> int:
        """Remove expired entries. Call periodically or on app start."""
        now = time.time()
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.execute("DELETE FROM cache WHERE expires_at <= ?", (now,))
            return cur.rowcount

    def stats(self) -> dict:
        """Cache diagnostic info — useful for an admin panel."""
        now = time.time()
        with sqlite3.connect(self.db_path) as conn:
            total = conn.execute("SELECT COUNT(*) FROM cache").fetchone()[0]
            active = conn.execute(
                "SELECT COUNT(*) FROM cache WHERE expires_at > ?", (now,)
            ).fetchone()[0]
            size_bytes = self.db_path.stat().st_size if self.db_path.exists() else 0
        return {
            "total_entries":   total,
            "active_entries":  active,
            "expired_entries": total - active,
            "db_size_bytes":   size_bytes,
        }

    def clear_pattern(self, substring: str) -> int:
        """Phase 2f: delete cached rows whose key contains substring."""
        with self._lock, sqlite3.connect(self.db_path) as conn:
            cur = conn.execute(
                "DELETE FROM cache WHERE key LIKE ?", (f"%{substring}%",)
            )
            return cur.rowcount or 0

    def clear_all(self) -> int:
        """Wipe entire cache."""
        with self._lock, sqlite3.connect(self.db_path) as conn:
            n = conn.execute("SELECT COUNT(*) FROM cache").fetchone()[0]
            conn.execute("DELETE FROM cache")
            return n


# ── Module-level singleton (one cache instance per process) ───────
_cache_instance: Optional[TTLCache] = None


def get_cache() -> TTLCache:
    """Get the shared cache singleton."""
    global _cache_instance
    if _cache_instance is None:
        _cache_instance = TTLCache()
    return _cache_instance


# ── Decorator: @cached(ttl=300) ───────────────────────────────────
def cached(ttl: int = None):
    """
    Cache a function's return value for `ttl` seconds keyed on its arguments.
    
    Example:
        @cached(ttl=600)
        def virustotal_lookup(url: str) -> dict:
            return requests.get(...).json()
    
    Notes:
      - Skips caching if return value is None or {} (don't cache failures)
      - Demo profile uses 3x longer TTL automatically (no rate surprises)
      - Function args must be JSON-serialisable (strings, numbers, dicts, lists)
    """
    def decorator(fn: Callable) -> Callable:
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            cache = get_cache()

            # Profile-aware TTL
            actual_ttl = ttl if ttl is not None else CFG.CACHE_DEFAULT_TTL
            if CFG.is_demo:
                actual_ttl *= 3  # aggressive caching during demos

            # Build a deterministic cache key
            key_raw = json.dumps(
                {"fn": fn.__module__ + "." + fn.__name__, "args": args, "kwargs": kwargs},
                sort_keys=True,
                default=str,
            )
            key = hashlib.sha256(key_raw.encode()).hexdigest()[:32]

            # Cache hit?
            hit = cache.get(key)
            if hit is not None:
                return hit

            # Cache miss — call real function
            result = fn(*args, **kwargs)

            # Don't cache empty failures
            if result is not None and result != {} and result != []:
                cache.set(key, result, ttl=actual_ttl)

            return result
        return wrapper
    return decorator


def clear_for_url(url: str) -> int:
    """
    Phase 3f — when force-fresh is requested, wipe the WHOLE cache.
    
    Why nuclear: cached keys are SHA-256 hashes of (function_name, args).
    A URL substring match against hex hashes always misses.
    User asked for "always fresh scan" so wiping all is correct.
    """
    try:
        c = get_cache()
        return c.clear_all()
    except Exception:
        return 0
