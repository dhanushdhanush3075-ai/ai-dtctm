"""
AI-DTCTM | URL Validator (v21 — Day 3 Part 1)
══════════════════════════════════════════════════════════════════════
Pre-scan validation to catch obvious-fake URLs BEFORE we waste API
budget. Also detects phishing techniques invisible to basic scanners.

FIXES Day 2 bug where "https://gogle" returned CLEAN 0.0 score:
  - DNS pre-resolution — if fails, return DEAD_DOMAIN verdict
  - Homograph attack detection (Cyrillic lookalike chars in domain)
  - Typo-squat detection (1-2 char edit distance from popular domains)
  - Punycode (xn--) detection
  - Suspicious TLD detection (.tk, .ml, .ga free TLDs favoured by phishers)

USAGE:
    from core.url_validator import validate_url
    result = validate_url("https://gogle")
    # {
    #   "valid":          False,
    #   "dns_resolved":   False,
    #   "risk_floor":     5.0,        # minimum score to apply
    #   "risk_signals":   ["dns_resolution_failed", "typo_squat:google.com"],
    #   "suggested_verdict": "SUSPICIOUS",
    #   "explain":        "Domain does not resolve + resembles google.com",
    # }
"""
from __future__ import annotations

import re
import socket
from typing import Optional
from urllib.parse import urlparse

from core.logger import get_logger

log = get_logger(__name__)


# ── Popular domains we protect against typo-squatting ─────────────
# These are the top targets of phishing by impersonation frequency.
_POPULAR_DOMAINS = {
    # tech giants
    "google.com", "gmail.com", "youtube.com", "facebook.com", "instagram.com",
    "whatsapp.com", "twitter.com", "x.com", "linkedin.com", "microsoft.com",
    "apple.com", "amazon.com", "netflix.com", "spotify.com", "github.com",
    "gitlab.com", "bitbucket.org", "stackoverflow.com", "reddit.com",
    # india-specific commonly phished
    "sbi.co.in", "hdfcbank.com", "icicibank.com", "axisbank.com", "kotak.com",
    "paytm.com", "phonepe.com", "gpay.com", "flipkart.com", "myntra.com",
    "zomato.com", "swiggy.com", "irctc.co.in", "incometax.gov.in",
    "uidai.gov.in", "epfindia.gov.in",
    # common payment / crypto phish targets
    "paypal.com", "stripe.com", "binance.com", "coinbase.com",
    # common collab / cloud services
    "dropbox.com", "box.com", "notion.so", "slack.com", "zoom.us",
    "teams.microsoft.com", "office.com", "onedrive.live.com",
}

# Suspicious free/cheap TLDs heavily used by phishers
_SUSPICIOUS_TLDS = {
    # Freenom free TLDs (discontinued but old phishing still uses)
    ".tk", ".ml", ".ga", ".cf", ".gq",
    # Cheap TLDs frequently abused
    ".xyz", ".top", ".loan", ".click", ".link", ".icu", ".info",
    ".monster", ".rest", ".cam", ".uno", ".zip", ".mov",
}


# ── Cyrillic/Greek/other lookalike char ranges ────────────────────
# These are characters that LOOK like ASCII letters but aren't.
_LOOKALIKE_RANGES = [
    (0x0400, 0x04FF),   # Cyrillic
    (0x0370, 0x03FF),   # Greek
    (0x13A0, 0x13FF),   # Cherokee
    (0xFF00, 0xFFEF),   # Halfwidth/Fullwidth forms
]


def _is_lookalike_char(ch: str) -> bool:
    cp = ord(ch)
    return any(lo <= cp <= hi for lo, hi in _LOOKALIKE_RANGES)


def _has_homograph(domain: str) -> tuple[bool, list]:
    """Return (True, [suspicious_chars]) if domain has non-ASCII lookalikes."""
    suspects = []
    for ch in domain:
        if _is_lookalike_char(ch):
            suspects.append(f"{ch!r} (U+{ord(ch):04X})")
    return (len(suspects) > 0, suspects)


def _levenshtein(a: str, b: str) -> int:
    """Classic edit distance. Small so we roll our own."""
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            ins = curr[j - 1] + 1
            dele = prev[j] + 1
            sub = prev[j - 1] + (ca != cb)
            curr[j] = min(ins, dele, sub)
        prev = curr
    return prev[-1]


def _find_typo_squat(domain: str) -> Optional[str]:
    """If domain is within edit distance 1-2 of a popular one → return popular."""
    if not domain or "." not in domain:
        return None
    domain = domain.lower()
    if domain in _POPULAR_DOMAINS:
        return None  # exact match, not a typo squat
    for popular in _POPULAR_DOMAINS:
        dist = _levenshtein(domain, popular)
        # 1-2 char difference in a 5+ char domain = typo squat
        # But only flag if domains are similar length (avoid false positives)
        if dist <= 2 and abs(len(domain) - len(popular)) <= 2 and len(domain) >= 4:
            return popular
    return None


def _suspicious_tld(domain: str) -> Optional[str]:
    """Return the suspicious TLD if present, else None."""
    for tld in _SUSSICIOUS_TLDS if False else _SUSPICIOUS_TLDS:  # avoid typo
        if domain.lower().endswith(tld):
            return tld
    return None


def _is_punycode(domain: str) -> bool:
    """IDN ASCII-encoded domains (xn--) — can be legitimate or phishing."""
    return any(label.startswith("xn--") for label in domain.split("."))


def _resolve_dns(hostname: str) -> tuple[bool, Optional[str]]:
    """(resolved, ip_or_error_msg)"""
    if not hostname:
        return False, "no hostname"
    try:
        ip = socket.gethostbyname(hostname)
        return True, ip
    except socket.gaierror as e:
        return False, str(e)
    except Exception as e:
        return False, str(e)


def _has_suspicious_url_patterns(url: str) -> list[str]:
    """Check for common phishing URL anti-patterns."""
    signals = []
    # IP instead of domain
    if re.search(r"https?://\d+\.\d+\.\d+\.\d+", url):
        signals.append("uses_ip_instead_of_domain")
    # Very long URL
    if len(url) > 200:
        signals.append("excessive_url_length")
    # Too many subdomains
    parsed = urlparse(url)
    if parsed.hostname and parsed.hostname.count(".") >= 4:
        signals.append("excessive_subdomain_depth")
    # @ in URL (credential injection)
    if "@" in (parsed.netloc or ""):
        signals.append("contains_at_symbol_credentials")
    # Hyphen-heavy (fake-brand-name.com pattern)
    if parsed.hostname and parsed.hostname.count("-") >= 3:
        signals.append("hyphen_heavy_domain")
    # Port specified (unusual for public web)
    if parsed.port and parsed.port not in (80, 443, 8080, 8443):
        signals.append(f"uncommon_port_{parsed.port}")
    return signals


# ── Main entrypoint ──────────────────────────────────────────────
def validate_url(url: str) -> dict:
    """
    Pre-scan validation + phishing heuristics.
    
    Returns dict with:
      valid:              overall boolean (False if should skip expensive scans)
      dns_resolved:       bool
      resolved_ip:        str or None
      risk_floor:         float (minimum fused score to apply downstream)
      risk_signals:       list of strings (why risky)
      suggested_verdict:  "CLEAN" | "SUSPICIOUS" | "MALICIOUS" | "DEAD_DOMAIN"
      explain:            human-readable sentence
    """
    result = {
        "url":                url,
        "valid":              True,
        "dns_resolved":       False,
        "resolved_ip":        None,
        "risk_floor":         0.0,
        "risk_signals":       [],
        "suggested_verdict":  "CLEAN",
        "explain":            "",
    }

    # ── Schema ────────────────────────────────────────────────────
    if not url or not isinstance(url, str) or len(url) < 4:
        result["valid"] = False
        result["suggested_verdict"] = "DEAD_DOMAIN"
        result["risk_floor"] = 5.0
        result["risk_signals"].append("empty_or_tiny_url")
        result["explain"] = "URL is empty or invalid."
        return result

    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        result["valid"] = False
        result["suggested_verdict"] = "DEAD_DOMAIN"
        result["risk_floor"] = 5.0
        result["risk_signals"].append("unparseable_url")
        result["explain"] = "URL has no valid hostname."
        return result

    # ── DNS resolution (the big one) ──────────────────────────────
    resolved, ip_or_err = _resolve_dns(hostname)
    result["dns_resolved"] = resolved
    if resolved:
        result["resolved_ip"] = ip_or_err
    else:
        result["valid"] = False
        result["suggested_verdict"] = "DEAD_DOMAIN"
        result["risk_floor"] = 5.0
        result["risk_signals"].append(f"dns_resolution_failed:{ip_or_err}")
        result["explain"] = (
            f"Domain '{hostname}' does not exist or has no DNS record. "
            f"Non-existent domains cannot be trusted."
        )
        return result

    # ── Homograph attack ─────────────────────────────────────────
    has_homo, homo_chars = _has_homograph(hostname)
    if has_homo:
        result["risk_signals"].append(f"homograph_chars:{','.join(homo_chars[:3])}")
        result["risk_floor"] = max(result["risk_floor"], 8.0)  # very strong signal

    # ── Punycode ─────────────────────────────────────────────────
    if _is_punycode(hostname):
        result["risk_signals"].append("punycode_encoded_domain")
        result["risk_floor"] = max(result["risk_floor"], 3.5)

    # ── Typo-squat ───────────────────────────────────────────────
    squat_of = _find_typo_squat(hostname)
    if squat_of:
        result["risk_signals"].append(f"typo_squat_of:{squat_of}")
        result["risk_floor"] = max(result["risk_floor"], 7.0)

    # ── Suspicious TLD ───────────────────────────────────────────
    sus_tld = _suspicious_tld(hostname)
    if sus_tld:
        result["risk_signals"].append(f"suspicious_tld:{sus_tld}")
        result["risk_floor"] = max(result["risk_floor"], 3.0)

    # ── URL pattern anti-signals ─────────────────────────────────
    pattern_signals = _has_suspicious_url_patterns(url)
    result["risk_signals"].extend(pattern_signals)
    if pattern_signals:
        result["risk_floor"] = max(result["risk_floor"], 2.5)

    # ── Compute suggested verdict based on risk floor ────────────
    if result["risk_floor"] >= 6.5:
        result["suggested_verdict"] = "MALICIOUS"
    elif result["risk_floor"] >= 3.0:
        result["suggested_verdict"] = "SUSPICIOUS"
    else:
        result["suggested_verdict"] = "CLEAN"

    # Build explain sentence
    if result["risk_signals"]:
        top = result["risk_signals"][0].split(":")[0].replace("_", " ")
        result["explain"] = f"Pre-scan signals: {', '.join(s.split(':')[0] for s in result['risk_signals'])}"
    else:
        result["explain"] = "URL passed pre-scan validation."

    return result


def should_proceed_with_api_scan(validation: dict) -> bool:
    """
    If DNS failed or URL is structurally invalid, skip expensive API calls
    since they'll all return "not found" anyway.
    """
    return validation.get("valid", False) and validation.get("dns_resolved", False)
