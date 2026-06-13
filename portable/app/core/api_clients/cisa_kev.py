"""
AI-DTCTM | CISA KEV (Known Exploited Vulnerabilities) Client
════════════════════════════════════════════════════════════════════
US Cybersecurity & Infrastructure Security Agency maintains a list of
CVEs that are ACTIVELY being exploited in the wild. This is the most
prioritised threat intel feed in the industry — if a CVE is in KEV, you
patch it yesterday.

FREE: no API key, just a public JSON feed updated daily.
DOCS: https://www.cisa.gov/known-exploited-vulnerabilities-catalog

USAGE:
  from core.api_clients.cisa_kev import is_actively_exploited, get_catalog
  exploited = is_actively_exploited("CVE-2021-44228")   # True — log4shell
  catalog = get_catalog()                                # full list
"""
from __future__ import annotations

import requests

from config import CFG
from core.cache import cached
from core.logger import get_logger

log = get_logger(__name__)

_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


@cached(ttl=21600)  # 6-hour cache; CISA updates ~daily
def get_catalog() -> dict:
    """Fetch the full KEV catalog. Returns dict with 'vulnerabilities' list."""
    try:
        r = requests.get(_FEED_URL, timeout=15,
                         headers={"User-Agent": f"ai-dtctm/{CFG.APP_VERSION}"})
        if r.status_code != 200:
            return {"error": f"HTTP {r.status_code}", "vulnerabilities": []}

        data = r.json()
        return {
            "catalog_version":  data.get("catalogVersion"),
            "date_released":    data.get("dateReleased"),
            "count":            data.get("count", 0),
            "vulnerabilities":  data.get("vulnerabilities", []),
        }
    except requests.RequestException as e:
        log.error("cisa_kev_fetch_failed", error=str(e))
        return {"error": str(e), "vulnerabilities": []}


def is_actively_exploited(cve_id: str) -> dict:
    """
    Check if a CVE appears in CISA's actively-exploited catalog.
    
    Returns:
        {"exploited": bool, "entry": dict|None, "severity_boost": float}
    """
    catalog = get_catalog()
    cve_id_upper = cve_id.upper()
    for v in catalog.get("vulnerabilities", []):
        if v.get("cveID", "").upper() == cve_id_upper:
            return {
                "exploited":      True,
                "severity_boost": 2.0,  # Add 2.0 to any risk score if in KEV
                "entry": {
                    "vendor":          v.get("vendorProject"),
                    "product":         v.get("product"),
                    "vulnerability":   v.get("vulnerabilityName"),
                    "date_added":      v.get("dateAdded"),
                    "due_date":        v.get("dueDate"),
                    "required_action": v.get("requiredAction"),
                    "ransomware":      v.get("knownRansomwareCampaignUse"),
                    "short_desc":      v.get("shortDescription"),
                },
            }
    return {"exploited": False, "severity_boost": 0.0, "entry": None}


def ransomware_cves() -> list[dict]:
    """Filter KEV catalog to only ransomware-linked CVEs."""
    catalog = get_catalog()
    return [
        v for v in catalog.get("vulnerabilities", [])
        if v.get("knownRansomwareCampaignUse", "").lower() == "known"
    ]


def fetch_full() -> dict:
    """Wrapper used by Threat Intel page — returns whole catalog."""
    catalog = get_catalog()
    if catalog.get("error"):
        return {"available": False, "error": catalog["error"], "vulnerabilities": []}
    return {
        "available":       True,
        "vulnerabilities": catalog.get("vulnerabilities", []),
        "catalog_version": catalog.get("catalogVersion"),
        "date_released":   catalog.get("dateReleased"),
    }
