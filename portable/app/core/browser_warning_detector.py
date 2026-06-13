"""
AI-DTCTM | Browser Warning Detector (v24)
══════════════════════════════════════════════════════════════════════
Predicts what a real browser (Chrome / Edge / Safari) would show when
a user visits the analyzed URL. Aggregates signals from:

  • Google Safe Browsing  → authoritative; same DB Chrome itself uses
  • PhishTank             → community-verified phishing
  • URLhaus               → community-verified malware distribution
  • ThreatFox             → IOC database (C2, malware)
  • OTX                   → researcher-reported threats
  • Heuristic phishing    → brand-impersonation, suspicious TLD, IDN,
                             newly-registered, URL-shortener, IP-URL,
                             deceptive paths, free-hosting brand abuse

Returns a structured prediction:
  {
    "will_warn":     True / False,
    "warning_type":  "deceptive" | "malware" | "phishing" | "unwanted" | None,
    "browser_label": "Deceptive site ahead",
    "confidence":    0.0 - 1.0,
    "signals":       [ "Google Safe Browsing flagged SOCIAL_ENGINEERING", ... ],
    "chrome_title":  "Deceptive site ahead",
    "chrome_body":   "Attackers on this site may trick you into ...",
  }

Use directly:
    from core.browser_warning_detector import predict_browser_warning
    bw = predict_browser_warning(case)
"""
from __future__ import annotations

import re
from urllib.parse import urlparse


# ── Known phishing brand keywords (URL contains → flag) ────────────
_BRAND_KEYWORDS = {
    "paypal", "apple", "icloud", "microsoft", "office365", "outlook",
    "google", "gmail", "amazon", "aws", "netflix", "spotify",
    "facebook", "instagram", "whatsapp", "telegram",
    "twitter", "linkedin", "github", "gitlab",
    "chase", "wellsfargo", "citi", "citibank", "hsbc", "barclays",
    "santander", "natwest", "lloyds", "halifax",
    "bankofamerica", "boa", "capitalone", "fidelity", "schwab",
    "coinbase", "binance", "metamask", "blockchain", "trezor", "ledger",
    "dropbox", "onedrive", "drive", "icloud",
    "irs", "hmrc", "ato", "ssa",
    "fedex", "ups", "dhl", "usps",
    "ebay", "etsy", "shopify",
    "steam", "epicgames", "playstation", "nintendo", "xbox",
    "verify", "secure-login", "account-verify", "support-team",
}

# Suspicious / often-abused TLDs (free, weakly verified)
_SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq",         # Freenom (most abused for phishing)
    "top", "xyz", "work", "live", "site", # cheap & high abuse rates
    "click", "online", "fit", "rest",
    "buzz", "icu", "cyou", "monster", "best",
    "wang", "loan", "win", "review",
    "country", "kim", "stream", "men",
}

# Common URL-shortener hosts (hide the real destination)
_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "is.gd", "buff.ly",
    "ow.ly", "shorte.st", "adf.ly", "rb.gy", "lnkd.in", "cutt.ly",
    "rebrand.ly", "shorturl.at", "bl.ink", "snip.ly", "tiny.cc",
    "0rz.tw", "v.gd", "1url.com",
}

# Free hosting platforms often abused for phishing
_FREE_HOSTING_SUBSTR = {
    "000webhost", "weebly", "wixsite", "blogspot", "tumblr",
    "github.io", "netlify.app", "vercel.app", "pages.dev",
    "herokuapp", "glitch.me", "repl.co", "duckdns", "ddns",
    "myftp", "myvnc", "freedynamicdns",
}

# Words frequently used in deceptive paths
_DECEPTIVE_PATH_WORDS = {
    "verify", "verification", "confirm", "account-locked", "suspended",
    "update-info", "update-payment", "billing-issue", "winner", "prize",
    "free-gift", "claim-now", "urgent", "security-alert", "unlock",
    "tax-refund", "refund-pending", "delivery-failed", "package-pending",
}


def _safe_get_host(url: str) -> str:
    try:
        p = urlparse(url if "://" in url else "http://" + url)
        return (p.netloc or "").lower()
    except Exception:
        return ""


def _safe_get_path(url: str) -> str:
    try:
        p = urlparse(url if "://" in url else "http://" + url)
        return (p.path or "").lower()
    except Exception:
        return ""


def _is_ip_address(host: str) -> bool:
    """Detect host that's just an IP address (a classic phishing tactic)."""
    if not host:
        return False
    h = host.split(":")[0]
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", h):
        return True
    # IPv6 in brackets
    if h.startswith("[") and h.endswith("]"):
        return True
    return False


def _get_tld(host: str) -> str:
    parts = host.split(".")
    return parts[-1] if len(parts) >= 2 else ""


def _has_punycode(host: str) -> bool:
    """Punycode prefix xn-- signals an IDN (potential homograph attack)."""
    return "xn--" in host.lower()


def _detect_brand_impersonation(host: str, path: str) -> str | None:
    """If a brand keyword appears in a subdomain or path with another domain,
    that's classic phishing (e.g. 'paypal-login.bad.tk')."""
    host_main = host.split(":")[0]
    # If the brand appears in the subdomain BUT the registrable domain isn't
    # owned by the brand, that's impersonation.
    for brand in _BRAND_KEYWORDS:
        # Skip if it's the legitimate brand domain (paypal.com etc.)
        if host_main == brand + ".com" or host_main.endswith("." + brand + ".com"):
            continue
        # Brand in host part (e.g. paypal-secure.evil.com)
        if brand in host_main.split(".")[0] or brand in host_main:
            # And the registrable domain isn't the brand itself
            parts = host_main.split(".")
            if len(parts) >= 2 and parts[-2] != brand:
                return brand
        # Brand in path (e.g. evil.com/paypal-login)
        if brand in path and brand not in host_main:
            return brand
    return None


# ════════════════════════════════════════════════════════════════════
# MAIN PREDICTOR
# ════════════════════════════════════════════════════════════════════
def predict_browser_warning(case: dict) -> dict:
    """
    Take a full URL-analyzer case and predict the browser warning.
    Returns a dict the UI can render directly.
    """
    url       = case.get("target", "")
    per_src   = case.get("per_source", {}) or {}
    enrich    = case.get("enrichment", {}) or {}
    hygiene   = case.get("hygiene", {}) or {}
    validation= case.get("validation", {}) or {}
    ml        = case.get("ml", {}) or {}

    host = _safe_get_host(url)
    path = _safe_get_path(url)

    signals: list[str] = []
    threat_types: set[str] = set()      # 'malware' | 'phishing' | 'unwanted' | 'deceptive'
    confidence = 0.0                    # accumulated 0.0–1.0

    # ── 1. Google Safe Browsing — same data Chrome itself uses ────
    gsb = per_src.get("google_sb", {})
    if gsb.get("available") and gsb.get("verdict") == "MALICIOUS":
        d = gsb.get("detail") or {}
        gsb_types = d.get("threat_types", []) or []
        for gt in gsb_types:
            if "MALWARE" in gt:               threat_types.add("malware")
            elif "SOCIAL_ENGINEERING" in gt:  threat_types.add("phishing")
            elif "UNWANTED" in gt:            threat_types.add("unwanted")
            elif "HARMFUL" in gt:             threat_types.add("unwanted")
        if gsb_types:
            signals.append(
                f"🛡 Google Safe Browsing flagged: "
                f"{', '.join(t.replace('_', ' ').title() for t in gsb_types)}"
            )
            confidence = max(confidence, 0.98)   # Chrome WILL warn — authoritative

    # ── 2. PhishTank — community-verified phishing ───────────────
    pt = per_src.get("phishtank", {})
    if pt.get("available") and pt.get("verdict") in ("MALICIOUS", "SUSPICIOUS"):
        d = pt.get("detail") or {}
        if d.get("verified") or pt.get("verdict") == "MALICIOUS":
            signals.append("🎣 PhishTank: verified phishing URL")
            threat_types.add("phishing")
            confidence = max(confidence, 0.92)

    # ── 3. URLhaus — community-verified malware ──────────────────
    uh = per_src.get("urlhaus", {})
    if uh.get("available") and uh.get("verdict") == "MALICIOUS":
        d = uh.get("detail") or {}
        mw_family = d.get("malware") or d.get("threat") or ""
        signals.append(
            f"🦠 URLhaus: active malware distribution"
            + (f" ({mw_family})" if mw_family else "")
        )
        threat_types.add("malware")
        confidence = max(confidence, 0.95)

    # ── 4. ThreatFox — IOC for C2 / malware ──────────────────────
    tf = per_src.get("threatfox", {})
    if tf.get("available") and tf.get("verdict") == "MALICIOUS":
        d = tf.get("detail") or {}
        ioc_type = d.get("ioc_type") or d.get("threat_type") or "C2"
        signals.append(f"☠ ThreatFox: matched IOC ({ioc_type})")
        threat_types.add("malware")
        confidence = max(confidence, 0.88)

    # ── 5. VirusTotal — multi-engine consensus ───────────────────
    vt = per_src.get("virustotal", {})
    if vt.get("available"):
        d = vt.get("detail") or {}
        mal = d.get("malicious") or 0
        total = d.get("total_engines") or 0
        if mal >= 3:
            signals.append(f"🦠 VirusTotal: {mal}/{total} engines detect threat")
            threat_types.add("malware")
            confidence = max(confidence, min(0.6 + mal * 0.05, 0.94))
        elif mal >= 1:
            signals.append(f"⚠ VirusTotal: {mal}/{total} engines detect threat")
            threat_types.add("malware")
            confidence = max(confidence, 0.55)

    # ── 6. AbuseIPDB high-confidence ─────────────────────────────
    ab = per_src.get("abuseipdb", {})
    if ab.get("available"):
        d = ab.get("detail") or {}
        conf = d.get("confidence", 0) or 0
        if conf >= 80:
            signals.append(f"🚨 AbuseIPDB: high-confidence abuse ({conf}/100)")
            threat_types.add("malware")
            confidence = max(confidence, 0.85)
        elif conf >= 50:
            signals.append(f"⚠ AbuseIPDB confidence {conf}/100")
            confidence = max(confidence, 0.55)
        if d.get("is_tor"):
            signals.append("🕶 IP is TOR exit node (anonymisation)")
            confidence = max(confidence, 0.45)

    # ── 7. HEURISTIC SIGNALS (browser-like rules) ────────────────

    # 7a. IP-only URL (no domain) — Chrome warns on these
    if _is_ip_address(host):
        signals.append("📍 URL uses raw IP address (no domain — classic phishing)")
        threat_types.add("deceptive")
        confidence = max(confidence, 0.7)

    # 7b. Punycode / IDN homograph
    if _has_punycode(host):
        signals.append("🔤 Internationalised domain (xn--) — possible homograph attack")
        threat_types.add("deceptive")
        confidence = max(confidence, 0.78)

    # 7c. Suspicious TLD
    tld = _get_tld(host)
    if tld in _SUSPICIOUS_TLDS:
        signals.append(f"🌐 Suspicious TLD '.{tld}' (heavily abused for phishing)")
        threat_types.add("deceptive")
        confidence = max(confidence, 0.65)

    # 7d. URL shortener (hides real destination)
    if any(s == host or host.endswith("." + s) for s in _SHORTENERS):
        signals.append(
            f"🔗 URL shortener ({host}) — actual destination hidden until clicked"
        )
        confidence = max(confidence, 0.5)

    # 7e. Free hosting that often abuses brand names
    for fh in _FREE_HOSTING_SUBSTR:
        if fh in host:
            # Free hosting alone isn't bad, but combined with brand impersonation it is
            brand = _detect_brand_impersonation(host, path)
            if brand:
                signals.append(
                    f"🪤 Free hosting ({fh}) impersonating <b>{brand.upper()}</b> brand"
                )
                threat_types.add("phishing")
                confidence = max(confidence, 0.88)
            break

    # 7f. Brand impersonation in host/path
    brand = _detect_brand_impersonation(host, path)
    if brand and "brand" not in " ".join(signals).lower():
        signals.append(
            f"🎭 Possible brand impersonation: <b>{brand.upper()}</b> appears in "
            f"non-{brand}.com URL"
        )
        threat_types.add("phishing")
        confidence = max(confidence, 0.8)

    # 7g. Deceptive path words (verify-account, claim-prize, etc.)
    dep_hits = [w for w in _DECEPTIVE_PATH_WORDS if w in path]
    if len(dep_hits) >= 2:
        signals.append(
            f"⚠ Deceptive URL path contains: {', '.join(dep_hits[:3])}"
        )
        threat_types.add("phishing")
        confidence = max(confidence, 0.7)

    # 7h. Newly registered domain (< 7 days = high phishing risk)
    whois = enrich.get("whois", {}) or {}
    age_days = whois.get("age_days")
    if isinstance(age_days, (int, float)):
        if age_days < 7:
            signals.append(f"🆕 Domain only {int(age_days)} days old (high phishing risk)")
            threat_types.add("phishing")
            confidence = max(confidence, 0.75)
        elif age_days < 30:
            signals.append(f"🆕 Domain only {int(age_days)} days old")
            confidence = max(confidence, 0.55)

    # 7i. ML classifier strong phishing signal
    ml_label = (ml.get("label") or "").upper()
    ml_conf  = ml.get("confidence") or 0
    try: ml_conf = float(ml_conf)
    except Exception: ml_conf = 0.0
    if ml_label in ("PHISHING", "MALICIOUS") and ml_conf >= 0.85:
        signals.append(
            f"🤖 ML classifier: {ml_label.lower()} ({ml_conf:.0%} confidence)"
        )
        threat_types.add("phishing")
        confidence = max(confidence, ml_conf * 0.9)

    # 7j. Typo-squat / homograph from validation
    risk_sigs = (validation.get("risk_signals") or [])
    for s in risk_sigs:
        if s.startswith("typo_squat"):
            signals.append(f"🎯 Typo-squat detected: <code>{s}</code>")
            threat_types.add("phishing")
            confidence = max(confidence, 0.85)
        elif s.startswith("homograph"):
            signals.append(f"🔤 Cyrillic homograph: <code>{s}</code>")
            threat_types.add("phishing")
            confidence = max(confidence, 0.9)

    # ── DECIDE final verdict ─────────────────────────────────────
    # Browsers warn at ~0.70 confidence in our calibration
    will_warn = confidence >= 0.70

    # Pick primary warning type
    if not threat_types:
        primary = None
    elif "malware" in threat_types:
        primary = "malware"
    elif "phishing" in threat_types:
        primary = "phishing"
    elif "deceptive" in threat_types:
        primary = "deceptive"
    elif "unwanted" in threat_types:
        primary = "unwanted"
    else:
        primary = "deceptive"

    # Browser warning text (mimics actual Chrome / Edge wording)
    if primary == "malware":
        chrome_title = "The site ahead contains malware"
        chrome_body  = ("Attackers currently on this site might attempt to install "
                        "dangerous programs on your computer that steal or delete "
                        "your information (for example, photos, passwords, messages, "
                        "and credit cards).")
        browser_label = "Dangerous site"
    elif primary == "phishing":
        chrome_title = "Deceptive site ahead"
        chrome_body  = ("Attackers on this site may trick you into doing something "
                        "dangerous like installing software or revealing your personal "
                        "information (for example, passwords, phone numbers, or "
                        "credit cards).")
        browser_label = "Deceptive site ahead"
    elif primary == "deceptive":
        chrome_title = "Deceptive site ahead"
        chrome_body  = ("Attackers on this site may attempt to install deceptive "
                        "software that misleads you or makes unexpected changes to "
                        "your computer (for example, changing your homepage or "
                        "showing extra ads on sites you visit).")
        browser_label = "Deceptive site ahead"
    elif primary == "unwanted":
        chrome_title = "The site ahead contains harmful programs"
        chrome_body  = ("Attackers on this site might attempt to trick you into "
                        "installing programs that harm your browsing experience.")
        browser_label = "Harmful programs"
    else:
        chrome_title = "Connection not secure"
        chrome_body  = "This site doesn't appear to be a known threat."
        browser_label = "Site appears safe"

    return {
        "will_warn":     will_warn,
        "warning_type":  primary,
        "browser_label": browser_label,
        "confidence":    round(confidence, 2),
        "signals":       signals,
        "chrome_title":  chrome_title,
        "chrome_body":   chrome_body,
        "threat_categories": sorted(threat_types),
    }
