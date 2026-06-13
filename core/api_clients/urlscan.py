"""
AI-DTCTM | URLScan.io API Client
════════════════════════════════════════════════════════════════════
URLScan.io *visits* the URL in a sandbox browser, takes a screenshot,
and maps all network requests, DOM structure, and external resources.

Unlike VirusTotal (AV signature matching), URLScan actually executes
the page — great for catching newly-spun-up phishing sites that aren't
in any blocklist yet.

FREE TIER:
  - 100 scan submissions/day
  - 1000 searches/day
  - Scans are PUBLIC by default — use 'visibility': 'private' for sensitive

DOCS: https://urlscan.io/docs/api/

USAGE:
  from core.api_clients.urlscan import scan_url
  result = scan_url("http://suspicious.example.com")
  # Scan takes ~30 seconds; result includes screenshot URL, DOM tree, etc.
"""
from __future__ import annotations

import time
import requests

from config import CFG
from core.cache import cached
from core.logger import get_logger
from core.api_clients import APIResult, _unavailable, _error, _now_iso

log = get_logger(__name__)

_BASE = "https://urlscan.io/api/v1"


@cached(ttl=3600)
def search_existing(url: str) -> dict | None:
    """
    Search URLScan for a RECENT, COMPLETED scan of this URL/domain.
    Returns the result dict or None if not found.
    Much faster than submitting a new scan (~200ms vs ~30s).
    """
    if not CFG.URLSCAN_API_KEY:
        return None
    from urllib.parse import urlparse
    try:
        domain = urlparse(url).hostname or ""
        # Search by exact URL first, then by domain
        queries = [f'page.url:"{url}"', f"domain:{domain}"]
        headers = {"API-Key": CFG.URLSCAN_API_KEY}
        for q in queries:
            r = requests.get(
                f"{_BASE}/search/",
                headers=headers,
                params={"q": q, "size": 1},   # no 'sort' — 403 on free tier
                timeout=6,
            )
            if r.status_code == 200:
                results = r.json().get("results", [])
                if results:
                    hit = results[0]
                    task = hit.get("task", {})
                    page = hit.get("page", {})
                    stats = hit.get("stats", {})
                    verdicts = hit.get("verdicts", {})
                    overall  = verdicts.get("overall", {})
                    scan_uuid = task.get("uuid", "")
                    score_pct = overall.get("score", 0)
                    score     = round(max(0, min(score_pct, 100)) / 10, 2)
                    malicious = overall.get("malicious", False)
                    verdict   = ("MALICIOUS" if malicious else
                                 "SUSPICIOUS" if score >= 3 else "CLEAN")
                    return {
                        "uuid":       scan_uuid,
                        "screenshot": f"https://urlscan.io/screenshots/{scan_uuid}.png" if scan_uuid else None,
                        "report_url": task.get("reportURL", f"https://urlscan.io/result/{scan_uuid}/"),
                        "verdict":    verdict,
                        "score":      score,
                        "country":    page.get("country"),
                        "ip":         page.get("ip"),
                        "server":     page.get("server"),
                        "domain":     page.get("domain"),
                        "requests":   stats.get("requests", 0),
                        "domains_contacted": stats.get("uniqDomains", 0),
                        "brands":     [],
                        "status":     "found",
                    }
    except Exception as e:
        log.debug("urlscan_search_failed", error=str(e))
    return None


@cached(ttl=3600)
def scan_url(url: str, wait_for_result: bool = True) -> APIResult:
    """
    Step 1: Search URLScan for existing scan of this URL (fast, ~200ms).
    Step 2: If not found, submit a new scan.
    Step 3: If wait_for_result=True, poll up to 35s for result.
    """
    if not CFG.URLSCAN_API_KEY:
        return _unavailable("urlscan")

    headers = {
        "API-Key":      CFG.URLSCAN_API_KEY,
        "Content-Type": "application/json",
    }

    # ── Step 0: Check for existing scan (fast path) ───────────────
    existing = search_existing(url)
    if existing and existing.get("screenshot"):
        log.info("urlscan_existing_found", url=url[:60], uuid=existing.get("uuid","")[:8])
        return {
            "available": True,
            "source":    "urlscan",
            "verdict":   existing.get("verdict", "UNKNOWN"),
            "score":     existing.get("score", 0.0),
            "detail":    {
                "uuid":            existing.get("uuid"),
                "screenshot":      existing.get("screenshot"),
                "report_url":      existing.get("report_url"),
                "country":         existing.get("country"),
                "ip":              existing.get("ip"),
                "server":          existing.get("server"),
                "domain":          existing.get("domain"),
                "requests":        existing.get("requests", 0),
                "domains_contacted": existing.get("domains_contacted", 0),
                "brands":          existing.get("brands", []),
                "status":          "existing_scan",
            },
            "error": None,
            "ts":    _now_iso(),
        }

    # ── Step 1: Submit new scan ───────────────────────────────────
    try:
        submit = requests.post(
            f"{_BASE}/scan/",
            headers=headers,
            json={"url": url, "visibility": "private"},
            timeout=10,
        )

        if submit.status_code == 429:
            return _error("urlscan", "rate limit (100/day exceeded)")
        if submit.status_code not in (200, 201):
            return _error("urlscan", f"submit failed: HTTP {submit.status_code}")

        submission = submit.json()
        scan_uuid  = submission.get("uuid")

        if not scan_uuid:
            return _error("urlscan", "no UUID returned")

        if not wait_for_result:
            return {
                "available": True,
                "source":    "urlscan",
                "verdict":   "UNKNOWN",
                "score":     0.0,
                "detail": {
                    "status":     "submitted",
                    "uuid":       scan_uuid,
                    "screenshot": f"https://urlscan.io/screenshots/{scan_uuid}.png",
                    "report_url": f"https://urlscan.io/result/{scan_uuid}/",
                },
                "error": None,
                "ts":    _now_iso(),
            }

        # Step 2 — poll for result (up to ~45 seconds)
        result_url = f"{_BASE}/result/{scan_uuid}/"
        for attempt in range(15):
            time.sleep(3)
            r = requests.get(result_url, timeout=10)
            if r.status_code == 200:
                break
        else:
            return _error("urlscan", "scan timed out after 45s")

        data = r.json()
        verdicts = data.get("verdicts", {})
        overall  = verdicts.get("overall", {})

        malicious = overall.get("malicious", False)
        score_pct = overall.get("score", 0)  # URLScan uses -100 to +100
        # Normalise: +100 = max malicious → 10.0, 0 = clean → 0.0
        score = round(max(0, min(score_pct, 100)) / 10, 2)

        if malicious:
            verdict = "MALICIOUS"
        elif score >= 3:
            verdict = "SUSPICIOUS"
        else:
            verdict = "CLEAN"

        page = data.get("page", {})
        stats = data.get("stats", {})

        return {
            "available": True,
            "source":    "urlscan",
            "verdict":   verdict,
            "score":     score,
            "detail": {
                "uuid":            scan_uuid,
                "screenshot":      data.get("task", {}).get("screenshotURL"),
                "report_url":      data.get("task", {}).get("reportURL"),
                "country":         page.get("country"),
                "ip":              page.get("ip"),
                "server":          page.get("server"),
                "domain":          page.get("domain"),
                "requests":        stats.get("requests", 0),
                "domains_contacted": stats.get("uniqDomains", 0),
                "malicious_reasons": overall.get("categories", []),
                "brands":          [b.get("name") for b in verdicts.get("community", {}).get("brands", [])],
            },
            "error": None,
            "ts":    _now_iso(),
        }

    except requests.RequestException as e:
        log.error("urlscan_failed", error=str(e))
        return _error("urlscan", str(e))
