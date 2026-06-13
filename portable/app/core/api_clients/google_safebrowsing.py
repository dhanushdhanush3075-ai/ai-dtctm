"""
AI-DTCTM | Google Safe Browsing API Client
════════════════════════════════════════════════════════════════════
Google's Safe Browsing API checks URLs against Google's continuously
updated phishing/malware blocklist. Returns threat types like:

  - MALWARE
  - SOCIAL_ENGINEERING (phishing)
  - UNWANTED_SOFTWARE
  - POTENTIALLY_HARMFUL_APPLICATION

FREE TIER: 10,000 requests/day — very generous.

ENDPOINT DOCS:
  https://developers.google.com/safe-browsing/v4/lookup-api

USAGE:
  from core.api_clients.google_safebrowsing import scan_url
  result = scan_url("http://suspicious.example.com")
"""
from __future__ import annotations

import requests

from config import CFG
from core.cache import cached
from core.logger import get_logger
from core.api_clients import APIResult, _unavailable, _error, _now_iso

log = get_logger(__name__)

_BASE = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

# Threat type → severity score
_THREAT_SCORES = {
    "MALWARE":                           9.5,
    "SOCIAL_ENGINEERING":                9.0,
    "UNWANTED_SOFTWARE":                 6.5,
    "POTENTIALLY_HARMFUL_APPLICATION":   6.0,
    "THREAT_TYPE_UNSPECIFIED":           4.0,
}


@cached(ttl=3600)  # GSB is authoritative — long cache OK
def scan_url(url: str) -> APIResult:
    """Check URL against Google's Safe Browsing database."""
    if not CFG.GOOGLE_SB_API_KEY:
        return _unavailable("google_sb")

    payload = {
        "client": {
            "clientId":      "ai-dtctm",
            "clientVersion": CFG.APP_VERSION,
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes":    ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries":    [{"url": url}],
        },
    }

    try:
        r = requests.post(
            f"{_BASE}?key={CFG.GOOGLE_SB_API_KEY}",
            json=payload,
            timeout=10,
        )

        if r.status_code != 200:
            return _error("google_sb", f"HTTP {r.status_code}")

        data = r.json()
        matches = data.get("matches", [])

        if not matches:
            return {
                "available": True,
                "source":    "google_sb",
                "verdict":   "CLEAN",
                "score":     0.0,
                "detail":    {"threats_found": 0},
                "error":     None,
                "ts":        _now_iso(),
            }

        # Found at least one threat — return the highest-severity one
        threat_types = [m.get("threatType", "THREAT_TYPE_UNSPECIFIED") for m in matches]
        max_score = max(_THREAT_SCORES.get(t, 4.0) for t in threat_types)

        return {
            "available": True,
            "source":    "google_sb",
            "verdict":   "MALICIOUS",
            "score":     round(max_score, 2),
            "detail": {
                "threats_found":  len(matches),
                "threat_types":   threat_types,
                "primary_threat": threat_types[0],
            },
            "error": None,
            "ts":    _now_iso(),
        }

    except requests.Timeout:
        return _error("google_sb", "timeout")
    except requests.RequestException as e:
        log.error("gsb_request_failed", error=str(e))
        return _error("google_sb", str(e))
