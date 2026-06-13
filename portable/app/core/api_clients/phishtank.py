"""
AI-DTCTM | PhishTank API Client
════════════════════════════════════════════════════════════════════
Community-verified phishing URL database. Every entry is voted on by
humans → extremely low false-positive rate. Unlimited free tier.

DOCS: https://www.phishtank.com/api_info.php
USAGE:
  from core.api_clients.phishtank import check_url
  result = check_url("http://paypal-verify.fake.com")
"""
from __future__ import annotations

import requests

from config import CFG
from core.cache import cached
from core.logger import get_logger
from core.api_clients import APIResult, _unavailable, _error, _now_iso

log = get_logger(__name__)

_BASE = "https://checkurl.phishtank.com/checkurl/"


@cached(ttl=1800)  # 30-min cache
def check_url(url: str) -> APIResult:
    """
    Check if URL is a known phishing site in PhishTank database.
    Works without an API key (unauthenticated, lower rate limit).
    If PHISHTANK_API_KEY is set, uses authenticated mode (higher rate limit).
    """
    try:
        data_payload: dict = {"url": url, "format": "json"}
        if CFG.PHISHTANK_API_KEY:
            data_payload["app_key"] = CFG.PHISHTANK_API_KEY

        r = requests.post(
            _BASE,
            data=data_payload,
            headers={"User-Agent": f"phishtank/ai-dtctm-{CFG.APP_VERSION}"},
            timeout=10,
        )

        if r.status_code != 200:
            return _error("phishtank", f"HTTP {r.status_code}")

        data = r.json()
        results = data.get("results", {})

        in_database = results.get("in_database", False)
        verified    = results.get("verified", False)
        valid       = results.get("valid", False)

        if in_database and valid:
            verdict = "MALICIOUS"
            score   = 9.5 if verified else 7.5
        else:
            verdict = "CLEAN"
            score   = 0.0

        return {
            "available": True,
            "source":    "phishtank",
            "verdict":   verdict,
            "score":     score,
            "detail": {
                "in_database":  in_database,
                "verified":     verified,
                "valid":        valid,
                "phish_id":     results.get("phish_id"),
                "phish_detail_page": results.get("phish_detail_page"),
            },
            "error": None,
            "ts":    _now_iso(),
        }

    except requests.RequestException as e:
        log.error("phishtank_failed", error=str(e))
        return _error("phishtank", str(e))
