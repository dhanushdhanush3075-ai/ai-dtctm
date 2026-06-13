"""
AI-DTCTM | External API Clients
════════════════════════════════════════════════════════════════════
One module per external service. Every client follows the same pattern:

  1. Check config for API key; if missing → return {"available": False, ...}
  2. Check cache; if hit → return cached result
  3. Make HTTP call with timeout
  4. Parse response into a stable schema
  5. Cache + return

ALL CLIENTS RETURN A DICT WITH THESE KEYS:
  - "available": bool      # False if API key missing or network down
  - "source":    str       # "virustotal" | "google_sb" | ...
  - "verdict":   str       # "CLEAN" | "SUSPICIOUS" | "MALICIOUS" | "UNKNOWN"
  - "score":     float     # 0-10 normalised risk score
  - "detail":    dict      # Raw useful fields from the API
  - "error":     str|None  # If something went wrong
  - "ts":        str       # ISO timestamp of the lookup

This schema lets url_analyzer / file_scanner aggregate multiple sources
easily without knowing the specifics of each API.
"""
from typing import TypedDict, Optional, Any


class APIResult(TypedDict):
    """Stable schema returned by every api_clients/* module."""
    available: bool
    source:    str
    verdict:   str      # CLEAN | SUSPICIOUS | MALICIOUS | UNKNOWN
    score:     float    # 0-10
    detail:    dict[str, Any]
    error:     Optional[str]
    ts:        str


def _now_iso() -> str:
    """UTC timestamp in ISO format with milliseconds."""
    import datetime
    return datetime.datetime.utcnow().isoformat(timespec="milliseconds") + "Z"


def _unavailable(source: str, reason: str = "API key not configured") -> APIResult:
    """Standard response when API can't be called."""
    return {
        "available": False,
        "source":    source,
        "verdict":   "UNKNOWN",
        "score":     0.0,
        "detail":    {},
        "error":     reason,
        "ts":        _now_iso(),
    }


def _error(source: str, error: str) -> APIResult:
    """Standard response when API call failed."""
    return {
        "available": True,
        "source":    source,
        "verdict":   "UNKNOWN",
        "score":     0.0,
        "detail":    {},
        "error":     error,
        "ts":        _now_iso(),
    }
