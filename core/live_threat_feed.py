"""
AI-DTCTM | Live Threat Feed Fetcher (v24)
══════════════════════════════════════════════════════════════════════
Pulls REAL, currently-live malicious URLs from public threat feeds so
the URL scanner can be tested against actual in-the-wild threats.

Sources (all FREE, no key needed for the public CSV endpoints):

  • URLhaus  — abuse.ch's curated malware-distribution URL feed
      https://urlhaus.abuse.ch/downloads/csv_recent/   (last ~1 day)
      https://urlhaus.abuse.ch/downloads/csv_online/   (currently online only)

  • OpenPhish — community phishing feed
      https://openphish.com/feed.txt  (last few hours of verified phishing)

  • PhishStats — live phishing IOCs
      https://phishstats.info:2096/api/phishing  (recent verified phishing)

USAGE:
    from core.live_threat_feed import fetch_live_malicious_urls
    urls = fetch_live_malicious_urls(limit=10)
    # → [{"url": "...", "type": "malware", "source": "URLhaus",
    #      "first_seen": "2026-06-10", "threat": "Mirai"}, ...]

Results are cached for 15 min to be a good citizen to the feeds.
"""
from __future__ import annotations

import csv
import io
import time
import datetime as _dt
import requests
from urllib.parse import urlparse

from core.logger import get_logger

log = get_logger(__name__)


_USER_AGENT = "ai-dtctm/24 (defensive-security-research)"
_TIMEOUT    = 10

# Module-level cache (15 min)
_cache: dict[str, tuple[float, list[dict]]] = {}
_CACHE_TTL = 900  # 15 minutes


# ── URLhaus public CSV feed (no auth) ────────────────────────────
def _fetch_urlhaus_online(limit: int = 15) -> list[dict]:
    """
    Pull currently-ONLINE malicious URLs from URLhaus public CSV.
    These are verified malware-distribution URLs confirmed live.
    """
    url = "https://urlhaus.abuse.ch/downloads/csv_online/"
    try:
        r = requests.get(url, timeout=_TIMEOUT,
                          headers={"User-Agent": _USER_AGENT})
        if r.status_code != 200:
            log.warning("urlhaus_feed_status", code=r.status_code)
            return []
        # CSV format with leading comment lines starting with #
        lines = [l for l in r.text.splitlines()
                 if l and not l.startswith("#")]
        out: list[dict] = []
        rdr = csv.reader(lines, quotechar='"')
        for row in rdr:
            if len(row) < 9:
                continue
            # Columns: id, dateadded, url, url_status, last_online,
            #           threat, tags, urlhaus_link, reporter
            try:
                date_added  = row[1]
                threat_url  = row[2]
                url_status  = row[3]
                last_online = row[4]
                threat_type = row[5]
                tags        = row[6]
                reporter    = row[8]
            except IndexError:
                continue
            if url_status.lower() != "online":
                continue
            out.append({
                "url":        threat_url,
                "type":       "malware",
                "source":     "URLhaus",
                "first_seen": date_added[:10] if date_added else "",
                "last_seen":  last_online[:10] if last_online else "",
                "threat":     threat_type or "malware_download",
                "tags":       (tags.split(",") if tags else [])[:4],
                "reporter":   reporter or "abuse.ch",
            })
            if len(out) >= limit:
                break
        return out
    except Exception as e:
        log.error("urlhaus_feed_failed", error=str(e))
        return []


# ── OpenPhish community feed ─────────────────────────────────────
def _fetch_openphish(limit: int = 15) -> list[dict]:
    """
    Pull live phishing URLs from OpenPhish public feed.
    Returns recently-verified phishing URLs.
    """
    url = "https://openphish.com/feed.txt"
    try:
        r = requests.get(url, timeout=_TIMEOUT,
                          headers={"User-Agent": _USER_AGENT})
        if r.status_code != 200:
            log.warning("openphish_feed_status", code=r.status_code)
            return []
        today = _dt.datetime.now().strftime("%Y-%m-%d")
        out: list[dict] = []
        for line in r.text.splitlines():
            line = line.strip()
            if not line or not line.lower().startswith(("http://", "https://")):
                continue
            # Try to extract brand from the URL for context
            host = ""
            try:
                host = urlparse(line).netloc.lower()
            except Exception:
                pass
            out.append({
                "url":        line,
                "type":       "phishing",
                "source":     "OpenPhish",
                "first_seen": today,
                "last_seen":  today,
                "threat":     "phishing",
                "tags":       _detect_brand(host + line),
                "reporter":   "openphish.com",
            })
            if len(out) >= limit:
                break
        return out
    except Exception as e:
        log.error("openphish_feed_failed", error=str(e))
        return []


# ── PhishStats public feed ───────────────────────────────────────
def _fetch_phishstats(limit: int = 15) -> list[dict]:
    """
    Pull live phishing IOCs from PhishStats.
    JSON API, no auth required.
    """
    url = ("https://phishstats.info:2096/api/phishing"
           "?_sort=-id&_size=" + str(limit))
    try:
        r = requests.get(url, timeout=_TIMEOUT,
                          headers={"User-Agent": _USER_AGENT})
        if r.status_code != 200:
            log.warning("phishstats_status", code=r.status_code)
            return []
        data = r.json()
        if not isinstance(data, list):
            return []
        out: list[dict] = []
        for entry in data[:limit]:
            if not isinstance(entry, dict):
                continue
            u = entry.get("url") or ""
            if not u.startswith(("http://", "https://")):
                continue
            host = ""
            try: host = urlparse(u).netloc.lower()
            except Exception: pass
            out.append({
                "url":        u,
                "type":       "phishing",
                "source":     "PhishStats",
                "first_seen": (entry.get("date") or "")[:10],
                "last_seen":  (entry.get("date") or "")[:10],
                "threat":     entry.get("title") or "phishing",
                "tags":       _detect_brand(host + u),
                "reporter":   "phishstats.info",
            })
        return out
    except Exception as e:
        log.error("phishstats_failed", error=str(e))
        return []


# ── Brand extractor for tagging ──────────────────────────────────
_BRAND_HINTS = [
    "paypal", "apple", "microsoft", "google", "amazon", "netflix",
    "facebook", "instagram", "linkedin", "twitter", "github",
    "coinbase", "binance", "metamask", "blockchain",
    "chase", "wellsfargo", "hsbc", "barclays", "santander",
    "irs", "hmrc", "fedex", "ups", "dhl", "usps",
    "office365", "outlook", "onedrive", "icloud", "dropbox",
    "spotify", "ebay", "etsy", "shopify", "steam",
]
def _detect_brand(blob: str) -> list[str]:
    b = blob.lower()
    return [k for k in _BRAND_HINTS if k in b][:3]


# ── Combined fetch with cache + fallback chain ───────────────────
def fetch_live_malicious_urls(limit: int = 10) -> list[dict]:
    """
    Pull a mix of currently-live malicious URLs from multiple feeds.

    Returns up to `limit` entries, prefering diversity:
      ~50% malware (URLhaus), ~50% phishing (OpenPhish + PhishStats).
    """
    now = time.time()
    cache_key = f"combined_{limit}"
    if cache_key in _cache:
        ts, val = _cache[cache_key]
        if now - ts < _CACHE_TTL:
            return val

    # Aim for diversity: ~half malware + ~half phishing
    n_each = max(3, limit // 2 + 2)
    mal   = _fetch_urlhaus_online(limit=n_each)
    phish = _fetch_openphish(limit=n_each)
    if len(phish) < n_each:
        # Top up with PhishStats if OpenPhish came back light
        phish += _fetch_phishstats(limit=n_each - len(phish))

    # Interleave: 1 malware, 1 phishing, 1 malware, ...
    combined: list[dict] = []
    i = j = 0
    while len(combined) < limit and (i < len(mal) or j < len(phish)):
        if i < len(mal):
            combined.append(mal[i]); i += 1
            if len(combined) >= limit: break
        if j < len(phish):
            combined.append(phish[j]); j += 1
    combined = combined[:limit]
    _cache[cache_key] = (now, combined)
    return combined


def feed_status() -> dict:
    """Quick health-check of each feed (lightweight HEAD-style probe)."""
    out = {}
    for name, url in (
        ("URLhaus",    "https://urlhaus.abuse.ch/downloads/csv_online/"),
        ("OpenPhish",  "https://openphish.com/feed.txt"),
        ("PhishStats", "https://phishstats.info:2096/api/phishing?_size=1"),
    ):
        try:
            t0 = time.monotonic()
            r = requests.head(url, timeout=4,
                               headers={"User-Agent": _USER_AGENT},
                               allow_redirects=True)
            out[name] = {
                "online": r.status_code in (200, 301, 302),
                "code":   r.status_code,
                "ms":     int((time.monotonic() - t0) * 1000),
            }
        except Exception as e:
            out[name] = {"online": False, "code": 0, "error": str(e)[:80], "ms": 0}
    return out
