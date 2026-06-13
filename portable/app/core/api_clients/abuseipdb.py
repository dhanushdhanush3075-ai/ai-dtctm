"""
AI-DTCTM | AbuseIPDB API Client
════════════════════════════════════════════════════════════════════
IP reputation database. Given an IP address, returns how many abuse
reports it has received in the past 90 days and its confidence score
(0-100, higher = more malicious).

Perfect for the Shield Monitor: "this IP hitting your server has 1247
reports of SSH brute force, block it."

FREE TIER: 1,000 checks/day.
DOCS: https://docs.abuseipdb.com/
USAGE:
  from core.api_clients.abuseipdb import check_ip
  result = check_ip("198.51.100.42")
"""
from __future__ import annotations

import requests

from config import CFG
from core.cache import cached
from core.logger import get_logger
from core.api_clients import APIResult, _unavailable, _error, _now_iso

log = get_logger(__name__)

_BASE = "https://api.abuseipdb.com/api/v2/check"


@cached(ttl=3600)
def check_ip(ip: str, max_age_days: int = 90) -> APIResult:
    """Check IP reputation. Returns standard APIResult."""
    if not CFG.ABUSEIPDB_API_KEY:
        return _unavailable("abuseipdb")

    try:
        r = requests.get(
            _BASE,
            headers={
                "Key":    CFG.ABUSEIPDB_API_KEY,
                "Accept": "application/json",
            },
            params={"ipAddress": ip, "maxAgeInDays": max_age_days, "verbose": ""},
            timeout=10,
        )

        if r.status_code == 401:
            return _error("abuseipdb", "invalid API key")
        if r.status_code == 429:
            return _error("abuseipdb", "rate limit (1000/day exceeded)")
        if r.status_code != 200:
            return _error("abuseipdb", f"HTTP {r.status_code}")

        body = r.json().get("data", {})

        confidence = body.get("abuseConfidenceScore", 0)  # 0-100
        score = round(confidence / 10, 2)  # Normalise to 0-10

        if confidence >= 75:
            verdict = "MALICIOUS"
        elif confidence >= 25:
            verdict = "SUSPICIOUS"
        else:
            verdict = "CLEAN"

        return {
            "available": True,
            "source":    "abuseipdb",
            "verdict":   verdict,
            "score":     score,
            "detail": {
                "ip":               body.get("ipAddress"),
                "confidence":       confidence,
                "country":          body.get("countryCode"),
                "country_name":     body.get("countryName"),
                "usage_type":       body.get("usageType"),
                "isp":              body.get("isp"),
                "domain":           body.get("domain"),
                "total_reports":    body.get("totalReports", 0),
                "distinct_users":   body.get("numDistinctUsers", 0),
                "last_reported":    body.get("lastReportedAt"),
                "is_tor":           body.get("isTor", False),
                "is_public":        body.get("isPublic", True),
            },
            "error": None,
            "ts":    _now_iso(),
        }

    except requests.RequestException as e:
        log.error("abuseipdb_failed", error=str(e))
        return _error("abuseipdb", str(e))
