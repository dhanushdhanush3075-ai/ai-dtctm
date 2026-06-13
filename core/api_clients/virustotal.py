"""
AI-DTCTM | VirusTotal API Client
════════════════════════════════════════════════════════════════════
HOW IT WORKS:
  VirusTotal has 87 antivirus engines. You submit a URL/file → they
  run it through all 87 → return "23/87 flagged malicious" verdict.

FREE TIER LIMITS:
  - 4 requests/minute
  - 500 requests/day
  - Our cache layer (@cached) makes this plenty for demos.

ENDPOINT DOCS:
  https://docs.virustotal.com/reference/overview

USAGE:
  from core.api_clients.virustotal import scan_url, scan_file_hash

  result = scan_url("http://example.com")
  # → {"available": True, "source": "virustotal", "verdict": "SUSPICIOUS",
  #    "score": 6.5, "detail": {"malicious": 3, "suspicious": 2, "total": 87, ...},
  #    "error": None, "ts": "2026-04-19T..."}
"""
from __future__ import annotations

import base64
from typing import Optional

import requests

from config import CFG
from core.cache import cached
from core.logger import get_logger
from core.api_clients import APIResult, _unavailable, _error, _now_iso

log = get_logger(__name__)

_BASE = "https://www.virustotal.com/api/v3"


def _headers() -> dict:
    return {
        "x-apikey": CFG.VIRUSTOTAL_API_KEY,
        "accept":   "application/json",
    }


def _verdict_from_stats(stats: dict) -> tuple[str, float]:
    """
    Convert VT's 'last_analysis_stats' into our unified verdict + 0-10 score.
    
    stats = {"malicious": 3, "suspicious": 2, "undetected": 50, "harmless": 32}
    """
    malicious  = stats.get("malicious",  0)
    suspicious = stats.get("suspicious", 0)
    total      = sum(stats.values()) or 1

    # Score weighted: malicious counts double
    raw = (malicious * 2 + suspicious) / total
    score = round(min(raw * 10, 10.0), 2)

    if malicious >= 5:
        verdict = "MALICIOUS"
    elif malicious >= 1 or suspicious >= 3:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    return verdict, score


@cached(ttl=600)  # 10-minute cache; VT results change slowly
def scan_url(url: str) -> APIResult:
    """
    Look up a URL in VirusTotal. If not previously scanned, submits it.
    
    Returns standard APIResult dict.
    """
    if not CFG.VIRUSTOTAL_API_KEY:
        return _unavailable("virustotal")

    # VT identifies URLs by base64url-encoded string (no padding)
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

    try:
        # Try existing report first
        r = requests.get(
            f"{_BASE}/urls/{url_id}",
            headers=_headers(),
            timeout=10,
        )

        if r.status_code == 404:
            # Not in database — submit it for analysis
            log.info("vt_submitting_new_url", url=url)
            submit = requests.post(
                f"{_BASE}/urls",
                headers=_headers(),
                data={"url": url},
                timeout=10,
            )
            if submit.status_code not in (200, 201):
                return _error("virustotal", f"submit failed: {submit.status_code}")

            # VT queues it — return "pending"
            return {
                "available": True,
                "source":    "virustotal",
                "verdict":   "UNKNOWN",
                "score":     0.0,
                "detail":    {"status": "queued_for_analysis"},
                "error":     None,
                "ts":        _now_iso(),
            }

        if r.status_code != 200:
            return _error("virustotal", f"HTTP {r.status_code}")

        data = r.json()
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        verdict, score = _verdict_from_stats(stats)

        return {
            "available": True,
            "source":    "virustotal",
            "verdict":   verdict,
            "score":     score,
            "detail": {
                "malicious":        stats.get("malicious",  0),
                "suspicious":       stats.get("suspicious", 0),
                "harmless":         stats.get("harmless",   0),
                "undetected":       stats.get("undetected", 0),
                "total_engines":    sum(stats.values()),
                "reputation":       attrs.get("reputation", 0),
                "last_analysis_ts": attrs.get("last_analysis_date"),
                "categories":       attrs.get("categories", {}),
            },
            "error": None,
            "ts":    _now_iso(),
        }

    except requests.Timeout:
        return _error("virustotal", "timeout")
    except requests.RequestException as e:
        log.error("vt_request_failed", error=str(e))
        return _error("virustotal", str(e))


@cached(ttl=3600)  # File hashes don't change — 1hr cache
def scan_file_hash(sha256: str) -> APIResult:
    """
    Look up a file by SHA-256 hash. Safer than uploading the file itself.
    """
    if not CFG.VIRUSTOTAL_API_KEY:
        return _unavailable("virustotal")

    try:
        r = requests.get(
            f"{_BASE}/files/{sha256}",
            headers=_headers(),
            timeout=10,
        )

        if r.status_code == 404:
            return {
                "available": True,
                "source":    "virustotal",
                "verdict":   "UNKNOWN",
                "score":     0.0,
                "detail":    {"status": "hash_not_in_database"},
                "error":     None,
                "ts":        _now_iso(),
            }

        if r.status_code != 200:
            return _error("virustotal", f"HTTP {r.status_code}")

        data = r.json()
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        verdict, score = _verdict_from_stats(stats)

        return {
            "available": True,
            "source":    "virustotal",
            "verdict":   verdict,
            "score":     score,
            "detail": {
                "malicious":   stats.get("malicious",  0),
                "suspicious":  stats.get("suspicious", 0),
                "total":       sum(stats.values()),
                "file_type":   attrs.get("type_description"),
                "file_size":   attrs.get("size"),
                "names":       attrs.get("names", [])[:5],  # known filenames
                "reputation":  attrs.get("reputation", 0),
            },
            "error": None,
            "ts":    _now_iso(),
        }

    except requests.RequestException as e:
        return _error("virustotal", str(e))
