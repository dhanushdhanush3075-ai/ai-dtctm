"""
AI-DTCTM | AlienVault OTX API Client
════════════════════════════════════════════════════════════════════
Open Threat Exchange — community-driven threat intel feed. Given an
indicator (IP, domain, URL, file hash), returns how many OTX "pulses"
(threat reports) reference it.

High pulse count = high confidence this is malicious.

FREE TIER: Unlimited (fair use).
DOCS: https://otx.alienvault.com/api/
USAGE:
  from core.api_clients.otx import lookup_indicator
  result = lookup_indicator("http://bad.example.com", ioc_type="url")
"""
from __future__ import annotations

import requests
from typing import Literal

from config import CFG
from core.cache import cached
from core.logger import get_logger
from core.api_clients import APIResult, _unavailable, _error, _now_iso

log = get_logger(__name__)

_BASE = "https://otx.alienvault.com/api/v1/indicators"

_INDICATOR_PATH = {
    "ip":     "IPv4",
    "domain": "domain",
    "url":    "url",
    "hash":   "file",
}


@cached(ttl=1800)
def lookup_indicator(indicator: str, ioc_type: Literal["ip","domain","url","hash"] = "url") -> APIResult:
    """Look up an IoC in OTX. Returns pulse count and categorisation."""
    if not CFG.OTX_API_KEY:
        return _unavailable("otx")

    path = _INDICATOR_PATH.get(ioc_type)
    if not path:
        return _error("otx", f"invalid ioc_type: {ioc_type}")

    try:
        r = requests.get(
            f"{_BASE}/{path}/{indicator}/general",
            headers={"X-OTX-API-KEY": CFG.OTX_API_KEY},
            timeout=10,
        )

        if r.status_code == 404:
            return {
                "available": True,
                "source":    "otx",
                "verdict":   "CLEAN",
                "score":     0.0,
                "detail":    {"pulse_count": 0},
                "error":     None,
                "ts":        _now_iso(),
            }

        if r.status_code != 200:
            return _error("otx", f"HTTP {r.status_code}")

        data = r.json()
        pulse_info  = data.get("pulse_info", {})
        pulse_count = pulse_info.get("count", 0)
        reputation  = data.get("reputation", 0)   # negative = bad, 0 = neutral/good
        validation  = data.get("validation", []) or []

        # ── OTX scoring — reputation is primary, pulse count is secondary ──
        # HIGH PULSE COUNT on a CLEAN reputation domain (e.g. google.com, github.com)
        # = that domain APPEARS IN threat reports as a lure target — NOT that the
        # domain itself is malicious. Use reputation as the ground truth.
        #
        # reputation < 0  → community has marked it bad  → weight pulses heavily
        # reputation = 0  → neutral / no community feedback → cautious weighting
        # reputation > 0  → community-verified clean → trust even with pulses

        if reputation > 0:
            # Positively verified clean — ignore pulse count
            verdict, score = "CLEAN", 0.0
        elif reputation < -5:
            # Strong negative reputation
            verdict = "MALICIOUS"
            score   = round(min(7.0 + abs(reputation) * 0.1, 10.0), 2)
        elif reputation < 0:
            # Mildly negative
            verdict = "SUSPICIOUS"
            score   = round(min(4.0 + abs(reputation) * 0.3, 6.5), 2)
        elif pulse_count == 0:
            verdict, score = "CLEAN", 0.0
        elif pulse_count <= 2:
            # Very few pulses, neutral reputation → mild suspicion
            verdict, score = "SUSPICIOUS", round(2.5 + pulse_count, 2)
        elif pulse_count <= 10:
            # Some pulses, neutral reputation → suspicious
            verdict, score = "SUSPICIOUS", round(min(4.0 + pulse_count * 0.2, 5.5), 2)
        else:
            # Many pulses (>10), neutral reputation → could be lure target or truly bad
            # Cap at SUSPICIOUS — only reputation makes it MALICIOUS
            verdict, score = "SUSPICIOUS", 5.5

        # Collect tags from pulses
        tags = set()
        for p in pulse_info.get("pulses", [])[:10]:
            tags.update(p.get("tags", []))

        return {
            "available": True,
            "source":    "otx",
            "verdict":   verdict,
            "score":     score,
            "detail": {
                "pulse_count": pulse_count,
                "tags":        list(tags)[:15],
                "reputation":  data.get("reputation", 0),
                "country":     data.get("country_name"),
                "city":        data.get("city"),
                "first_pulse": pulse_info.get("pulses", [{}])[0].get("created") if pulse_info.get("pulses") else None,
            },
            "error": None,
            "ts":    _now_iso(),
        }

    except requests.RequestException as e:
        log.error("otx_failed", error=str(e))
        return _error("otx", str(e))


def fetch_subscribed_pulses(limit: int = 30) -> dict:
    """Fetch user's subscribed pulses for Threat Intel page."""
    import os
    import requests as _r
    api_key = os.environ.get("OTX_API_KEY", "").strip()
    if not api_key:
        return {"available": False, "error": "OTX_API_KEY missing", "pulses": []}
    try:
        r = _r.get(
            "https://otx.alienvault.com/api/v1/pulses/subscribed",
            headers={"X-OTX-API-KEY": api_key},
            params={"limit": limit},
            timeout=15,
        )
        if r.status_code != 200:
            return {"available": False, "error": f"OTX HTTP {r.status_code}",
                    "pulses": []}
        data = r.json()
        return {"available": True, "pulses": data.get("results", [])[:limit]}
    except Exception as e:
        return {"available": False, "error": str(e), "pulses": []}
