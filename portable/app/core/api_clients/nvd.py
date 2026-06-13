"""
AI-DTCTM | NVD (National Vulnerability Database) Client
════════════════════════════════════════════════════════════════════
US government's official CVE database. Every known CVE with CVSS
scores, descriptions, affected products, and references.

FREE: no API key required. Rate-limited to ~50 requests / 30 seconds;
cache heavily (24hr TTL).

DOCS: https://nvd.nist.gov/developers/vulnerabilities
USAGE:
  from core.api_clients.nvd import search_cves, get_cve
  results = search_cves("apache 2.4", limit=5)
  cve = get_cve("CVE-2021-44228")
"""
from __future__ import annotations

import requests
from typing import Optional

from config import CFG
from core.cache import cached
from core.logger import get_logger
from core.api_clients import APIResult, _error, _now_iso

log = get_logger(__name__)

_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _severity_from_cvss(score: float) -> str:
    if score >= 9.0: return "CRITICAL"
    if score >= 7.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    if score >  0.0: return "LOW"
    return "NONE"


@cached(ttl=86400)
def get_cve(cve_id: str) -> dict:
    """Fetch a single CVE by ID (e.g. 'CVE-2021-44228')."""
    try:
        r = requests.get(
            _BASE,
            params={"cveId": cve_id},
            timeout=15,
            headers={"User-Agent": f"ai-dtctm/{CFG.APP_VERSION}"},
        )
        if r.status_code != 200:
            return {"error": f"HTTP {r.status_code}", "cve_id": cve_id}

        data = r.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return {"error": "not found", "cve_id": cve_id}

        cve = vulns[0].get("cve", {})
        metrics = cve.get("metrics", {})

        cvss_v3 = (metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or [{}])[0]
        cvss_score = cvss_v3.get("cvssData", {}).get("baseScore", 0.0)

        description = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                description = d.get("value", "")
                break

        return {
            "cve_id":      cve_id,
            "description": description,
            "cvss":        cvss_score,
            "severity":    _severity_from_cvss(cvss_score),
            "published":   cve.get("published"),
            "modified":    cve.get("lastModified"),
            "references":  [r.get("url") for r in cve.get("references", [])[:5]],
            "cwe":         [w.get("description", [{}])[0].get("value")
                            for w in cve.get("weaknesses", [])],
        }

    except requests.RequestException as e:
        log.error("nvd_get_cve_failed", cve_id=cve_id, error=str(e))
        return {"error": str(e), "cve_id": cve_id}


@cached(ttl=86400)
def search_cves(keyword: str, limit: int = 10) -> list[dict]:
    """Search CVEs by keyword (product name, tech, etc.)."""
    try:
        r = requests.get(
            _BASE,
            params={"keywordSearch": keyword, "resultsPerPage": limit},
            timeout=15,
            headers={"User-Agent": f"ai-dtctm/{CFG.APP_VERSION}"},
        )
        if r.status_code != 200:
            return []

        out = []
        for item in r.json().get("vulnerabilities", []):
            cve = item.get("cve", {})
            metrics = cve.get("metrics", {})
            cvss_v3 = (metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or [{}])[0]
            score = cvss_v3.get("cvssData", {}).get("baseScore", 0.0)
            desc = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")[:280]
                    break
            out.append({
                "cve_id":      cve.get("id"),
                "description": desc,
                "cvss":        score,
                "severity":    _severity_from_cvss(score),
                "published":   cve.get("published"),
            })
        return out

    except requests.RequestException as e:
        log.error("nvd_search_failed", keyword=keyword, error=str(e))
        return []


def fetch_recent(days: int = 7, limit: int = 50) -> dict:
    """Fetch recent CVEs published in the last N days."""
    import datetime as _dt
    import requests as _r

    end = _dt.datetime.utcnow()
    start = end - _dt.timedelta(days=days)
    fmt = "%Y-%m-%dT%H:%M:%S.000"

    params = {
        "pubStartDate": start.strftime(fmt),
        "pubEndDate":   end.strftime(fmt),
        "resultsPerPage": min(limit, 200),
    }
    try:
        r = _r.get("https://services.nvd.nist.gov/rest/json/cves/2.0",
                   params=params, timeout=15)
        if r.status_code != 200:
            return {"available": False, "error": f"NVD HTTP {r.status_code}",
                    "cves": []}
        data = r.json()
        cves = []
        for item in data.get("vulnerabilities", []):
            c = item.get("cve", {})
            cve_id = c.get("id", "?")
            descs = c.get("descriptions", [])
            desc_en = next((d.get("value") for d in descs if d.get("lang") == "en"),
                           "")
            metrics = c.get("metrics", {})
            cvss = 0
            severity = "NONE"
            for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if metrics.get(k):
                    m0 = metrics[k][0]
                    cvss = m0.get("cvssData", {}).get("baseScore", 0)
                    severity = m0.get("cvssData", {}).get("baseSeverity",
                               m0.get("baseSeverity", "NONE"))
                    break
            cves.append({
                "cve_id":      cve_id,
                "description": desc_en[:500],
                "cvss_score":  cvss,
                "severity":    severity,
                "published":   c.get("published", ""),
                "modified":    c.get("lastModified", ""),
            })
        return {"available": True, "cves": cves[:limit]}
    except Exception as e:
        return {"available": False, "error": str(e), "cves": []}
