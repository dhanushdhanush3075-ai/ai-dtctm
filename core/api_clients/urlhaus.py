"""
AI-DTCTM | URLhaus API Client (abuse.ch)
════════════════════════════════════════════════════════════════════
Community-maintained malicious URL feed. Focus is on URLs that
distribute malware payloads (droppers, loaders, C2 beacons).

FREE: no key. Fair use.
DOCS: https://urlhaus-api.abuse.ch/
USAGE:
  from core.api_clients.urlhaus import lookup_url
  result = lookup_url("http://bad.example.com/payload.exe")
"""
from __future__ import annotations

import requests

from config import CFG
from core.cache import cached
from core.logger import get_logger
from core.api_clients import APIResult, _error, _now_iso

log = get_logger(__name__)

_BASE = "https://urlhaus-api.abuse.ch/v1/url/"


def _get_auth_headers() -> dict:
    """abuse.ch API now requires auth key. Free registration: https://auth.abuse.ch/"""
    headers = {"User-Agent": f"ai-dtctm/{CFG.APP_VERSION}"}
    key = getattr(CFG, "URLHAUS_KEY", "") or getattr(CFG, "ABUSE_CH_KEY", "")
    if key:
        headers["Auth-Key"] = key
    return headers


@cached(ttl=3600)
def lookup_url(url: str) -> APIResult:
    """
    Check if URL is in URLhaus malicious URL database (abuse.ch).
    Requires a free API key from: https://auth.abuse.ch/
    Add URLHAUS_KEY or ABUSE_CH_KEY to your .env file.
    """
    try:
        r = requests.post(
            _BASE,
            data={"url": url},
            headers=_get_auth_headers(),
            timeout=10,
        )

        # abuse.ch now requires auth — return clear unavailable message
        if r.status_code == 401:
            log.warning("urlhaus_auth_required",
                        msg="Register free at https://auth.abuse.ch/ then add URLHAUS_KEY to .env")
            return {
                "available": False,
                "source":    "urlhaus",
                "verdict":   "UNKNOWN",
                "score":     0.0,
                "detail":    {
                    "reason": "API key required",
                    "register": "https://auth.abuse.ch/ (free)",
                    "env_key":  "URLHAUS_KEY",
                },
                "error": "API key required — free registration at auth.abuse.ch",
                "ts":    _now_iso(),
            }

        if r.status_code != 200:
            return _error("urlhaus", f"HTTP {r.status_code}")

        body = r.json()
        status = body.get("query_status", "")

        if status == "no_results":
            return {
                "available": True, "source": "urlhaus", "verdict": "CLEAN",
                "score": 0.0, "detail": {"listed": False},
                "error": None, "ts": _now_iso(),
            }

        if status != "ok":
            return _error("urlhaus", f"query_status={status}")

        url_status = body.get("url_status", "unknown")
        threat = body.get("threat", "unknown")
        tags   = body.get("tags", []) or []

        # Online & serving malware = critical; offline but historical = still bad
        if url_status == "online":
            verdict, score = "MALICIOUS", 9.5
        else:
            verdict, score = "MALICIOUS", 7.5

        return {
            "available": True,
            "source":    "urlhaus",
            "verdict":   verdict,
            "score":     score,
            "detail": {
                "url_status":    url_status,
                "threat":        threat,
                "tags":          tags,
                "date_added":    body.get("date_added"),
                "host":          body.get("host"),
                "payloads":      [p.get("file_name") for p in body.get("payloads", [])[:5]],
                "malware_families": list({p.get("signature") for p in body.get("payloads", []) if p.get("signature")})[:5],
            },
            "error": None,
            "ts":    _now_iso(),
        }

    except requests.RequestException as e:
        log.error("urlhaus_failed", error=str(e))
        return _error("urlhaus", str(e))
