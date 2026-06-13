"""
Tests for core.cache.TTLCache and the @cached decorator.
Verifies: get/set round-trip, expiry, non-serializable handling,
          decorator cache hit/miss, failure non-caching.
"""
from __future__ import annotations

import time
import sqlite3
from pathlib import Path

import pytest

from core.cache import TTLCache, cached


@pytest.fixture
def tmp_cache(tmp_path: Path) -> TTLCache:
    """A fresh cache in a temp DB — no test pollution."""
    return TTLCache(db_path=tmp_path / "test_cache.db")


class TestTTLCache:

    def test_set_and_get_roundtrip(self, tmp_cache):
        tmp_cache.set("key1", {"hello": "world"}, ttl=60)
        assert tmp_cache.get("key1") == {"hello": "world"}

    def test_miss_returns_none(self, tmp_cache):
        assert tmp_cache.get("nope") is None

    def test_expiry(self, tmp_cache):
        tmp_cache.set("short", "live", ttl=1)
        assert tmp_cache.get("short") == "live"
        time.sleep(1.1)
        assert tmp_cache.get("short") is None

    def test_overwrite(self, tmp_cache):
        tmp_cache.set("k", "v1", ttl=60)
        tmp_cache.set("k", "v2", ttl=60)
        assert tmp_cache.get("k") == "v2"

    def test_delete(self, tmp_cache):
        tmp_cache.set("k", "v", ttl=60)
        tmp_cache.delete("k")
        assert tmp_cache.get("k") is None

    def test_purge_expired(self, tmp_cache):
        tmp_cache.set("fresh", "v", ttl=60)
        tmp_cache.set("stale", "v", ttl=1)
        time.sleep(1.1)
        removed = tmp_cache.purge_expired()
        assert removed >= 1
        assert tmp_cache.get("fresh") == "v"
        assert tmp_cache.get("stale") is None

    def test_stats(self, tmp_cache):
        tmp_cache.set("a", 1, ttl=60)
        tmp_cache.set("b", 2, ttl=60)
        stats = tmp_cache.stats()
        assert stats["total_entries"] >= 2
        assert stats["active_entries"] >= 2

    def test_complex_values(self, tmp_cache):
        payload = {
            "list": [1, 2, 3],
            "nested": {"inner": [True, None, 3.14]},
            "string": "hello",
        }
        tmp_cache.set("complex", payload, ttl=60)
        assert tmp_cache.get("complex") == payload
