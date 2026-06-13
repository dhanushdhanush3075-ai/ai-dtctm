"""
AI-DTCTM | ThreatFox API Client (abuse.ch)
════════════════════════════════════════════════════════════════════
IoC (Indicators of Compromise) feed — IPs, domains, URLs, file hashes
that have been observed in malware campaigns. Updated in near-real-time.

FREE: no key. Fair use.
DOCS: https://threatfox.abuse.ch/api/
USAGE:
  from core.api_clients.threatfox import search_ioc
  result = search_ioc("198.51.100.42")
"""
from __future__ import annotations

import requests

from config import CFG
from core.cache import cached
from core.logger import get_logger
from core.api_clients import APIResult, _error, _now_iso

log = get_logger(__name__)

_BASE = "https://threatfox-api.abuse.ch/api/v1/"


def _get_auth_headers() -> dict:
    """abuse.ch API now requires auth key. Free registration: https://auth.abuse.ch/"""
    headers = {"User-Agent": f"ai-dtctm/{CFG.APP_VERSION}"}
    key = getattr(CFG, "THREATFOX_KEY", "") or getattr(CFG, "ABUSE_CH_KEY", "")
    if key:
        headers["Auth-Key"] = key
    return headers


@cached(ttl=3600)
def search_ioc(ioc: str) -> APIResult:
    """
    Search ThreatFox for an indicator (IP/domain/URL/hash).
    Requires a free API key from: https://auth.abuse.ch/
    Add THREATFOX_KEY or ABUSE_CH_KEY to your .env file.
    """
    try:
        r = requests.post(
            _BASE,
            json={"query": "search_ioc", "search_term": ioc},
            headers=_get_auth_headers(),
            timeout=10,
        )

        # abuse.ch now requires auth
        if r.status_code == 401:
            log.warning("threatfox_auth_required",
                        msg="Register free at https://auth.abuse.ch/ then add THREATFOX_KEY to .env")
            return {
                "available": False,
                "source":    "threatfox",
                "verdict":   "UNKNOWN",
                "score":     0.0,
                "detail":    {
                    "reason":   "API key required",
                    "register": "https://auth.abuse.ch/ (free)",
                    "env_key":  "THREATFOX_KEY",
                },
                "error": "API key required — free registration at auth.abuse.ch",
                "ts":    _now_iso(),
            }

        if r.status_code != 200:
            return _error("threatfox", f"HTTP {r.status_code}")

        body = r.json()
        status = body.get("query_status", "")

        if status == "no_result":
            return {
                "available": True, "source": "threatfox", "verdict": "CLEAN",
                "score": 0.0, "detail": {"matches": 0},
                "error": None, "ts": _now_iso(),
            }

        if status != "ok":
            return _error("threatfox", f"query_status={status}")

        data = body.get("data", [])
        if not data:
            return {
                "available": True, "source": "threatfox", "verdict": "CLEAN",
                "score": 0.0, "detail": {"matches": 0},
                "error": None, "ts": _now_iso(),
            }

        # Average the confidence scores across matches
        confidences = [d.get("confidence_level", 0) for d in data]
        avg_conf = sum(confidences) / len(confidences) if confidences else 0
        score = round(avg_conf / 10, 2)

        families = list({d.get("malware_printable") for d in data if d.get("malware_printable")})[:5]
        threat_types = list({d.get("threat_type") for d in data if d.get("threat_type")})[:5]

        return {
            "available": True,
            "source":    "threatfox",
            "verdict":   "MALICIOUS" if avg_conf >= 75 else "SUSPICIOUS",
            "score":     score,
            "detail": {
                "matches":         len(data),
                "malware_families": families,
                "threat_types":    threat_types,
                "first_seen":      data[0].get("first_seen"),
                "last_seen":       data[0].get("last_seen"),
                "tags":            data[0].get("tags", []),
            },
            "error": None,
            "ts":    _now_iso(),
        }

    except requests.RequestException as e:
        log.error("threatfox_failed", error=str(e))
        return _error("threatfox", str(e))
