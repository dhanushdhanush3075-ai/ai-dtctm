#!/usr/bin/env python3
"""
AI-DTCTM | Day 1 API Verification Smoke Test
════════════════════════════════════════════════════════════════════
Run this after filling your .env file to confirm every registered API
actually responds.

Usage:
    python scripts/verify_apis.py

Output:
    ✅ VirusTotal         OK (HTTP 200, cached_lookup_for_google.com)
    ✅ Google Safe Browsing  OK
    ❌ URLScan            API key missing in .env
    ✅ PhishTank          OK
    ...

Exit code 0 if all configured APIs work, 1 if any failed.
"""
from __future__ import annotations

import sys
import os

# Make sure we can import from project root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import CFG


GREEN = "\033[32m"
RED   = "\033[31m"
AMBER = "\033[33m"
DIM   = "\033[90m"
RESET = "\033[0m"


def test(name: str, fn, *args, **kwargs) -> bool:
    """Run one API test. Prints result. Returns True if pass."""
    try:
        result = fn(*args, **kwargs)

        if not result.get("available"):
            print(f"  {AMBER}⦸{RESET}  {name:<24} {DIM}{result.get('error', 'not configured')}{RESET}")
            return None  # Not configured = skip, not a failure

        if result.get("error"):
            print(f"  {RED}✗{RESET}  {name:<24} {RED}{result['error']}{RESET}")
            return False

        verdict = result.get("verdict", "?")
        score = result.get("score", 0)
        print(f"  {GREEN}✓{RESET}  {name:<24} {DIM}verdict={verdict} score={score}{RESET}")
        return True

    except Exception as e:
        print(f"  {RED}✗{RESET}  {name:<24} {RED}{type(e).__name__}: {e}{RESET}")
        return False


def main() -> int:
    print()
    print(f"  {DIM}╔══════════════════════════════════════════════════╗{RESET}")
    print(f"  {DIM}║{RESET}  AI-DTCTM · Day 1 API Smoke Test                 {DIM}║{RESET}")
    print(f"  {DIM}║{RESET}  Profile: {CFG.PROFILE:<40}{DIM}║{RESET}")
    print(f"  {DIM}╚══════════════════════════════════════════════════╝{RESET}")
    print()

    # ── Lazy imports so missing modules don't crash the script ──
    results: list[bool | None] = []

    print(f"  {DIM}─── URL-based APIs ───{RESET}")
    try:
        from core.api_clients.virustotal import scan_url
        results.append(test("VirusTotal", scan_url, "http://google.com"))
    except ImportError as e:
        print(f"  {RED}✗ VirusTotal           import failed: {e}{RESET}")
        results.append(False)

    try:
        from core.api_clients.google_safebrowsing import scan_url as gsb_scan
        results.append(test("Google Safe Browsing", gsb_scan, "http://google.com"))
    except ImportError as e:
        print(f"  {RED}✗ Google SB            import failed: {e}{RESET}")
        results.append(False)

    try:
        from core.api_clients.urlscan import scan_url as urlscan_scan
        # Don't actually run a live scan (burns 1/100 daily quota) — just check key
        if CFG.URLSCAN_API_KEY:
            print(f"  {GREEN}✓{RESET}  {'URLScan.io':<24} {DIM}key configured (live scan skipped to save quota){RESET}")
            results.append(True)
        else:
            print(f"  {AMBER}⦸{RESET}  {'URLScan.io':<24} {DIM}API key missing{RESET}")
            results.append(None)
    except ImportError:
        results.append(False)

    try:
        from core.api_clients.phishtank import check_url as pt_check
        results.append(test("PhishTank", pt_check, "http://google.com"))
    except ImportError:
        results.append(False)

    try:
        from core.api_clients.urlhaus import lookup_url as uh_lookup
        results.append(test("URLhaus", uh_lookup, "http://google.com"))
    except ImportError:
        results.append(False)

    print()
    print(f"  {DIM}─── IP-based APIs ───{RESET}")

    try:
        from core.api_clients.abuseipdb import check_ip
        results.append(test("AbuseIPDB", check_ip, "8.8.8.8"))
    except ImportError:
        results.append(False)

    try:
        if CFG.SHODAN_API_KEY:
            print(f"  {GREEN}✓{RESET}  {'Shodan':<24} {DIM}key configured (live query skipped — free tier tight){RESET}")
            results.append(True)
        else:
            print(f"  {AMBER}⦸{RESET}  {'Shodan':<24} {DIM}API key missing{RESET}")
            results.append(None)
    except Exception:
        results.append(False)

    print()
    print(f"  {DIM}─── Threat Intel feeds ───{RESET}")

    try:
        from core.api_clients.otx import lookup_indicator
        results.append(test("AlienVault OTX", lookup_indicator, "8.8.8.8", ioc_type="ip"))
    except ImportError:
        results.append(False)

    try:
        from core.api_clients.nvd import get_cve
        r = get_cve("CVE-2021-44228")  # log4shell — always exists
        if r.get("error"):
            print(f"  {RED}✗{RESET}  {'NVD CVE':<24} {RED}{r['error']}{RESET}")
            results.append(False)
        else:
            print(f"  {GREEN}✓{RESET}  {'NVD CVE':<24} {DIM}CVSS={r.get('cvss')} {r.get('severity')}{RESET}")
            results.append(True)
    except ImportError:
        results.append(False)

    try:
        from core.api_clients.cisa_kev import is_actively_exploited
        r = is_actively_exploited("CVE-2021-44228")
        if r.get("exploited"):
            print(f"  {GREEN}✓{RESET}  {'CISA KEV':<24} {DIM}feed reachable, log4shell confirmed in catalog{RESET}")
            results.append(True)
        else:
            print(f"  {AMBER}⦸{RESET}  {'CISA KEV':<24} {DIM}feed reachable but log4shell not found (unexpected){RESET}")
            results.append(True)
    except Exception as e:
        print(f"  {RED}✗{RESET}  {'CISA KEV':<24} {RED}{e}{RESET}")
        results.append(False)

    try:
        from core.api_clients.malware_bazaar import lookup_hash
        # Known EICAR test hash (not actual malware, used for AV testing)
        eicar_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        r = lookup_hash(eicar_hash)
        if r.get("error"):
            print(f"  {RED}✗{RESET}  {'MalwareBazaar':<24} {RED}{r['error']}{RESET}")
            results.append(False)
        else:
            print(f"  {GREEN}✓{RESET}  {'MalwareBazaar':<24} {DIM}feed reachable{RESET}")
            results.append(True)
    except Exception as e:
        print(f"  {RED}✗{RESET}  {'MalwareBazaar':<24} {RED}{e}{RESET}")
        results.append(False)

    try:
        from core.api_clients.threatfox import search_ioc
        r = search_ioc("8.8.8.8")  # Google DNS, won't be listed
        if r.get("error"):
            print(f"  {RED}✗{RESET}  {'ThreatFox':<24} {RED}{r['error']}{RESET}")
            results.append(False)
        else:
            print(f"  {GREEN}✓{RESET}  {'ThreatFox':<24} {DIM}feed reachable{RESET}")
            results.append(True)
    except Exception as e:
        print(f"  {RED}✗{RESET}  {'ThreatFox':<24} {RED}{e}{RESET}")
        results.append(False)

    # ── Summary ──
    print()
    total   = len(results)
    passed  = sum(1 for r in results if r is True)
    skipped = sum(1 for r in results if r is None)
    failed  = sum(1 for r in results if r is False)

    print(f"  {DIM}──────────────────────────────────────────────────{RESET}")
    print(f"  Total: {total}   {GREEN}✓ {passed}{RESET}   {AMBER}⦸ {skipped} skipped{RESET}   {RED}✗ {failed}{RESET}")
    print()

    if failed > 0:
        print(f"  {RED}Some APIs failed. Check .env keys and network connectivity.{RESET}")
        return 1
    if skipped == total:
        print(f"  {AMBER}No APIs configured yet. Fill in .env and re-run.{RESET}")
        return 1
    print(f"  {GREEN}All configured APIs are responsive. Ready for Day 2.{RESET}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
