"""
AI-DTCTM | Shodan Client — InternetDB + API fallback
════════════════════════════════════════════════════════════════════
Primary:  Shodan InternetDB  (https://internetdb.shodan.io/{ip})
          FREE, no API key, returns open ports + CVEs + tags + CPEs.

Fallback: Shodan /shodan/host/{ip}  (requires paid API key)

InternetDB is Shodan's free public endpoint launched 2021.
Returns the same port/vuln data as paid API without a key.

USAGE:
  from core.api_clients.shodan_client import host_info
  result = host_info("184.84.233.209")
"""
from __future__ import annotations

import requests

from config import CFG
from core.cache import cached
from core.logger import get_logger
from core.api_clients import APIResult, _error, _now_iso

log = get_logger(__name__)

_INTERNETDB  = "https://internetdb.shodan.io"
_SHODAN_BASE = "https://api.shodan.io"


@cached(ttl=86400)   # 24-hour cache — port data doesn't change often
def host_info(ip: str) -> APIResult:
    """
    Fetch host info for an IP.
    Uses Shodan InternetDB (free, no key) as primary source.
    Falls back to paid Shodan API if key is configured.
    """
    # ── Primary: InternetDB (always free) ─────────────────────────
    try:
        r = requests.get(
            f"{_INTERNETDB}/{ip}",
            headers={"User-Agent": f"ai-dtctm/{CFG.APP_VERSION}"},
            timeout=8,
        )

        if r.status_code == 404:
            # IP not indexed — not necessarily suspicious
            return {
                "available": True,
                "source":    "shodan",
                "verdict":   "CLEAN",
                "score":     0.0,
                "detail":    {
                    "source":  "InternetDB",
                    "status":  "not_indexed",
                    "ip":      ip,
                },
                "error": None,
                "ts":    _now_iso(),
            }

        if r.status_code == 200:
            data = r.json()

            open_ports = data.get("ports", [])
            vulns      = data.get("vulns", []) or []    # CVE IDs
            tags       = data.get("tags", [])           # "cdn", "cloud", "tor", etc.
            hostnames  = data.get("hostnames", [])
            cpes       = data.get("cpes", [])           # Software fingerprints
            cve_count  = len(vulns)

            # ── Detect shared / CDN / cloud hosting ───────────────────
            # CVEs on a GoDaddy or AWS shared-hosting IP do NOT mean
            # the website is malicious — they mean the HOST server needs patching.
            # Only flag MALICIOUS for IPs known to be used for actual attacks.
            HOSTING_PATTERNS = (
                "secureserver.net", "hostgator", "bluehost", "dreamhost",
                "a2hosting", "siteground", "godaddy", "namecheap",
                "amazonaws.com", "azure", "googlecloud", "googleusercontent",
                "akamai", "fastly", "cloudflare", "incapsula",
                "linode", "digitalocean", "vultr", "hetzner",
                "ovh", "leaseweb", "softlayer",
            )
            is_shared_hosting = any(
                pat in h.lower()
                for pat in HOSTING_PATTERNS
                for h in hostnames
            )
            # Also detect via CPE (cpanel, exim, phpmyadmin = shared hosting)
            HOSTING_CPES = ("cpanel", "exim", "pureftpd", "phpmyadmin")
            is_shared_hosting = is_shared_hosting or any(
                hcpe in c.lower() for hcpe in HOSTING_CPES for c in cpes
            )
            # CDN tag check
            is_cdn = "cdn" in [t.lower() for t in tags]

            # Tags that indicate genuine malicious infrastructure
            BAD_TAGS = {"tor", "vpn", "proxy", "scanner", "bot",
                        "malware", "c2", "botnet", "phishing"}
            tag_hit = bool(set(t.lower() for t in tags) & BAD_TAGS)

            # Scoring — context-aware
            if tag_hit:
                # Actual malicious indicator (TOR exit, scanner, malware)
                verdict = "MALICIOUS"
                score   = round(min(7.0 + cve_count * 0.1, 10.0), 2)
            elif is_shared_hosting or is_cdn:
                # Shared hosting / CDN: CVEs are server-level, not URL-level
                if cve_count >= 10:
                    verdict = "SUSPICIOUS"
                    score   = 3.5
                elif cve_count >= 3:
                    verdict = "SUSPICIOUS"
                    score   = 2.5
                else:
                    verdict = "CLEAN"
                    score   = 1.0
            elif cve_count >= 5:
                # Non-shared host with many CVEs = exposed server
                verdict = "SUSPICIOUS"
                score   = round(min(4.0 + cve_count * 0.2, 7.0), 2)
            elif cve_count >= 1:
                verdict = "SUSPICIOUS"
                score   = round(min(3.0 + cve_count * 0.3, 5.0), 2)
            elif len(open_ports) > 20:
                verdict = "SUSPICIOUS"
                score   = 2.5
            else:
                verdict = "CLEAN"
                score   = 0.5 if open_ports else 0.0

            log.info("shodan_internetdb_ok", ip=ip, ports=len(open_ports),
                     cves=cve_count, tags=tags)

            return {
                "available": True,
                "source":    "shodan",
                "verdict":   verdict,
                "score":     score,
                "detail": {
                    "source":       "Shodan InternetDB (free)",
                    "ip":           ip,
                    "open_ports":   open_ports,
                    "port_count":   len(open_ports),
                    "cves":         vulns[:15],
                    "cve_count":    cve_count,
                    "tags":         tags,
                    "hostnames":    hostnames[:5],
                    "cpes":         cpes[:5],
                },
                "error": None,
                "ts":    _now_iso(),
            }

    except requests.RequestException as e:
        log.warning("shodan_internetdb_failed", ip=ip, error=str(e))
        # Fall through to paid API if key available

    # ── Fallback: Paid Shodan API ──────────────────────────────────
    if not CFG.SHODAN_API_KEY:
        return _error("shodan", "InternetDB unreachable and no API key configured")

    try:
        r2 = requests.get(
            f"{_SHODAN_BASE}/shodan/host/{ip}",
            params={"key": CFG.SHODAN_API_KEY},
            timeout=12,
        )

        if r2.status_code == 404:
            return {
                "available": True, "source": "shodan", "verdict": "CLEAN",
                "score": 0.0, "detail": {"status": "ip_not_indexed"},
                "error": None, "ts": _now_iso(),
            }
        if r2.status_code in (401, 403):
            return _error("shodan", "API key requires paid plan for /shodan/host/")
        if r2.status_code != 200:
            return _error("shodan", f"HTTP {r2.status_code}")

        data2     = r2.json()
        open_ports = data2.get("ports", [])
        vulns2     = data2.get("vulns", []) or []
        cve_count2 = len(vulns2)

        if cve_count2 >= 5:
            verdict2, score2 = "MALICIOUS", round(min(7 + cve_count2 * 0.2, 10), 2)
        elif cve_count2 >= 1:
            verdict2, score2 = "SUSPICIOUS", round(4 + cve_count2, 2)
        elif len(open_ports) > 15:
            verdict2, score2 = "SUSPICIOUS", 5.0
        else:
            verdict2, score2 = "CLEAN", 1.0

        return {
            "available": True,
            "source":    "shodan",
            "verdict":   verdict2,
            "score":     score2,
            "detail": {
                "source":      "Shodan API (paid)",
                "ip":          data2.get("ip_str"),
                "hostnames":   data2.get("hostnames", [])[:5],
                "country":     data2.get("country_name"),
                "city":        data2.get("city"),
                "org":         data2.get("org"),
                "isp":         data2.get("isp"),
                "open_ports":  open_ports,
                "port_count":  len(open_ports),
                "cves":        vulns2[:15],
                "cve_count":   cve_count2,
                "last_update": data2.get("last_update"),
            },
            "error": None,
            "ts":    _now_iso(),
        }

    except requests.RequestException as e:
        log.error("shodan_api_failed", ip=ip, error=str(e))
        return _error("shodan", str(e))
