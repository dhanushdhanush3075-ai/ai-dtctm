"""
AI-DTCTM | URL Analyzer (v20 — Day 2)
══════════════════════════════════════════════════════════════════════
The orchestrator. Takes a URL, fans out to all 11 threat intelligence
APIs IN PARALLEL, fuses their verdicts into a single 0-10 risk score,
and emits a forensic case file.

WHY PARALLEL QUERIES:
  - Sequential would take 30-60 seconds total (10 APIs × 3-6s each)
  - ThreadPoolExecutor cuts this to ~5-8 seconds (slowest API wins)
  - User sees live per-API progress → feels responsive
  - If 3 APIs down, 8 still complete — graceful degradation

FUSION SCORING ALGORITHM:
  1. Each API returns a normalised score 0-10 via APIResult schema
  2. Weighted average based on source authority:
       VirusTotal, Google SB, CISA KEV → weight 1.0 (authoritative)
       URLScan, AbuseIPDB, NVD           → weight 0.8 (reliable)
       OTX, ThreatFox, URLhaus           → weight 0.6 (community)
       PhishTank, MalwareBazaar          → weight 0.7
  3. Maximum-score boost: if any source returns MALICIOUS, minimum
     score floor is 7.0 (prevents dilution when one AV flags)
  4. Unavailable APIs simply excluded from the average — not zero'd

RESULT SCHEMA:
  {
    "case_id":   "CASE-2026-04-19-A7F3",
    "target":    "http://example.com",
    "target_ip": "93.184.216.34",
    "fused_score":  7.4,
    "fused_verdict":"MALICIOUS",
    "per_source":   { "virustotal": {...}, "google_sb": {...}, ... },
    "timeline":     [ {ts, event, source}, ... ],
    "duration_ms":  4821,
    "started_at":   "2026-04-19T14:32:07.384Z",
    "finished_at":  "2026-04-19T14:32:12.205Z",
  }

USAGE:
  from core.url_analyzer import analyse_url
  
  result = analyse_url("http://testphp.vulnweb.com")
  # Blocks ~5-8s while parallel queries run.

  # For Streamlit live progress:
  for update in analyse_url_live("http://..."):
      # update = {"source": "virustotal", "status": "complete", "result": {...}}
      ...
"""
from __future__ import annotations

import socket
import time
import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Iterator, Optional
from urllib.parse import urlparse

from core.api_clients import virustotal, google_safebrowsing, urlscan, phishtank
from core.api_clients import abuseipdb, otx, shodan_client, nvd, cisa_kev
from core.api_clients import malware_bazaar, urlhaus, threatfox
from core.cache import cached
from core.logger import get_logger
from core.shared_css import case_id as generate_case_id

log = get_logger(__name__)


# ── Source authority weights (higher = more trusted) ──────────────
_WEIGHTS = {
    "virustotal":     1.0,
    "google_sb":      1.0,
    "cisa_kev":       1.0,
    "urlscan":        0.8,
    "abuseipdb":      0.8,
    "nvd":            0.8,
    "phishtank":      0.7,
    "malware_bazaar": 0.7,
    "otx":            0.6,
    "threatfox":      0.6,
    "urlhaus":        0.7,
    "shodan":         0.7,
}


# ── Helper: resolve hostname to IP ────────────────────────────────
def _resolve_ip(url: str) -> Optional[str]:
    """Extract hostname from URL, resolve via DNS. None on failure."""
    try:
        hostname = urlparse(url).hostname
        if not hostname:
            return None
        return socket.gethostbyname(hostname)
    except (socket.gaierror, ValueError):
        return None


# ── Internal: wrapper that times each API call ────────────────────
def _timed_call(source_name: str, fn, *args, **kwargs) -> dict:
    """Run an API client, return its result with a duration_ms field."""
    t0 = time.monotonic()
    try:
        result = fn(*args, **kwargs)
    except Exception as e:
        log.error("api_client_crashed", source=source_name, error=str(e))
        result = {
            "available": False,
            "source":    source_name,
            "verdict":   "UNKNOWN",
            "score":     0.0,
            "detail":    {},
            "error":     f"crashed: {e}",
            "ts":        _now_iso(),
        }
    result["duration_ms"] = round((time.monotonic() - t0) * 1000, 1)
    return result


def _now_iso() -> str:
    return datetime.datetime.utcnow().isoformat(timespec="milliseconds") + "Z"


# ── Fusion scorer ─────────────────────────────────────────────────
def _fuse(per_source: dict[str, dict]) -> tuple[float, str]:
    """
    Combine per-source scores into a single 0-10 fused score + verdict.

    Algorithm (v24, stricter):
      1. Filter to available, non-error sources only
      2. Weighted mean of their scores
      3. If any MALICIOUS present, score = max(weighted_mean, 7.0)
      4. If any SUSPICIOUS source scored >= 4.0, raise floor to 3.0
         (don't let CLEAN sources dilute a real flag into "CLEAN")
      5. If any SUSPICIOUS source scored >= 6.5, raise floor to 4.0
      6. Verdict thresholds: <3=CLEAN, <5.5=SUSPICIOUS, >=5.5=MALICIOUS
    """
    usable = [r for r in per_source.values()
              if r.get("available") and not r.get("error")]

    if not usable:
        return 0.0, "UNKNOWN"

    total_weight = 0.0
    weighted_sum = 0.0
    any_malicious = False
    max_susp_score = 0.0
    for r in usable:
        w = _WEIGHTS.get(r["source"], 0.5)
        weighted_sum += r["score"] * w
        total_weight += w
        if r["verdict"] == "MALICIOUS":
            any_malicious = True
        elif r["verdict"] == "SUSPICIOUS":
            max_susp_score = max(max_susp_score, float(r.get("score") or 0))

    score = round(weighted_sum / total_weight, 2) if total_weight else 0.0

    # MALICIOUS floor — one authority flagged
    if any_malicious and score < 7.0:
        score = 7.0
    # NEW: SUSPICIOUS floor — don't let CLEAN sources mask a real flag
    elif max_susp_score >= 6.5 and score < 4.0:
        score = 4.0
    elif max_susp_score >= 4.0 and score < 3.0:
        score = 3.0

    if score >= 5.5:
        verdict = "MALICIOUS"
    elif score >= 3.0:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    return round(score, 2), verdict


# ── Post-fusion reality check (v24) ───────────────────────────────
def _post_fusion_adjust(
    score: float, verdict: str,
    per_source: dict, hygiene: dict | None, ml: dict | None,
) -> tuple[float, str, list[str]]:
    """
    Second-pass adjustment that brings *hygiene, SSL, Shodan CVEs and ML*
    into the final verdict. Fixes 'looks clean but isn't' false-negatives
    like scanme.nmap.org (108 CVEs, no SSL, hygiene D — was rated CLEAN).

    Returns (new_score, new_verdict, reasons[]) so the UI can show
    *why* the verdict shifted.
    """
    reasons: list[str] = []
    hygiene = hygiene or {}
    ml      = ml or {}

    # 1. Hygiene grade D / F → host poorly secured
    grade = (hygiene.get("grade") or "").upper()
    if grade == "F":
        score += 1.8; reasons.append("Hygiene grade F (very poor)")
    elif grade == "D":
        score += 1.2; reasons.append("Hygiene grade D (poor security headers)")

    # Hygiene numeric score below 50 also bumps (defensive double-check)
    h_num = hygiene.get("score") or 0
    try: h_num = float(h_num)
    except Exception: h_num = 0.0
    if h_num and h_num < 30 and "Hygiene grade F" not in " ".join(reasons):
        score += 0.6; reasons.append(f"Hygiene score {int(h_num)}/100 very low")

    # 2. Missing / invalid SSL
    ssl_info = hygiene.get("ssl") or hygiene.get("tls") or {}
    if isinstance(ssl_info, dict):
        if ssl_info.get("present") is False or ssl_info.get("valid") is False:
            score += 1.0; reasons.append("No valid SSL certificate")

    # 3. Shodan CVE count — high vulnerability surface
    shodan_r = per_source.get("shodan") or {}
    if shodan_r.get("available"):
        detail   = shodan_r.get("detail") or {}
        cve_count = (
            detail.get("cve_count")
            or (len(detail.get("cves") or []) if isinstance(detail.get("cves"), list) else 0)
            or (len(detail.get("vulns") or []) if isinstance(detail.get("vulns"), list) else 0)
        )
        try: cve_count = int(cve_count)
        except Exception: cve_count = 0
        if cve_count >= 100:
            score += 2.0; reasons.append(f"Shodan: {cve_count} CVEs on host (critical attack surface)")
        elif cve_count >= 50:
            score += 1.5; reasons.append(f"Shodan: {cve_count} CVEs on host (high attack surface)")
        elif cve_count >= 20:
            score += 1.0; reasons.append(f"Shodan: {cve_count} CVEs on host")
        elif cve_count >= 5:
            score += 0.5; reasons.append(f"Shodan: {cve_count} CVEs on host")

    # 4. ML classifier flagged with high confidence
    ml_label = (ml.get("label") or "").upper()
    ml_conf  = ml.get("confidence") or 0
    try: ml_conf = float(ml_conf)
    except Exception: ml_conf = 0.0
    if ml_label in ("PHISHING", "MALICIOUS") and ml_conf >= 0.7:
        bump = 1.5 if ml_conf >= 0.9 else 1.0
        score += bump
        reasons.append(f"ML classifier: {ml_label.lower()} ({ml_conf:.0%} confidence)")

    # 5. Multiple suspicious sources agreeing — also a signal
    susp_n = sum(1 for r in per_source.values()
                  if r.get("available") and r.get("verdict") == "SUSPICIOUS")
    if susp_n >= 2:
        score += 0.5
        reasons.append(f"{susp_n} threat-intel sources flagged SUSPICIOUS")

    score = min(round(score, 2), 10.0)

    if score >= 5.5:
        verdict = "MALICIOUS"
    elif score >= 3.0:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    return score, verdict, reasons


# ── Main entrypoint (blocking) ────────────────────────────────────
# NOTE: do NOT wrap analyse_url itself in @cached — we rely on individual
# API clients having their own caching (which IS appropriate per-source).
# Caching the whole case dict here caused user-visible "0.1s completed"
# bugs where an entire prior scan was reused for the next call.
def analyse_url(url: str) -> dict:
    """
    Scan a URL through every available threat-intel source IN PARALLEL.
    Returns a full forensic result dict. Blocks ~5-8 seconds.
    """
    started = _now_iso()
    t0 = time.monotonic()
    ip = _resolve_ip(url)

    # Build the list of (source_name, callable, args) tuples
    tasks: list[tuple[str, callable, tuple]] = [
        ("virustotal",     virustotal.scan_url,              (url,)),
        ("google_sb",      google_safebrowsing.scan_url,     (url,)),
        ("urlscan",        urlscan.scan_url,                 (url, False)),  # async mode
        ("phishtank",      phishtank.check_url,              (url,)),
        ("otx_url",        otx.lookup_indicator,             (url, "url")),
        ("urlhaus",        urlhaus.lookup_url,               (url,)),
    ]
    # IP-based sources (only if we resolved an IP)
    if ip:
        tasks.extend([
            ("abuseipdb",  abuseipdb.check_ip,               (ip,)),
            ("shodan",     shodan_client.host_info,          (ip,)),
            ("otx_ip",     otx.lookup_indicator,             (ip, "ip")),
            ("threatfox",  threatfox.search_ioc,             (ip,)),
        ])

    per_source: dict[str, dict] = {}
    timeline: list[dict] = [{"ts": started, "event": "scan_started", "source": "orchestrator"}]

    # ── Parallel execution ─────────────────────────────────────────
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = {
            pool.submit(_timed_call, name, fn, *args): name
            for name, fn, args in tasks
        }
        for fut in as_completed(futures):
            name = futures[fut]
            try:
                result = fut.result()
            except Exception as e:
                log.error("future_failed", source=name, error=str(e))
                continue
            per_source[name] = result
            timeline.append({
                "ts":     _now_iso(),
                "event":  "source_returned",
                "source": name,
                "verdict": result.get("verdict"),
                "score":   result.get("score"),
                "ms":      result.get("duration_ms"),
            })

    fused_score, fused_verdict = _fuse(per_source)

    finished = _now_iso()
    duration_ms = round((time.monotonic() - t0) * 1000, 1)

    case = {
        "case_id":       generate_case_id("URL"),
        "target":        url,
        "target_ip":     ip,
        "fused_score":   fused_score,
        "fused_verdict": fused_verdict,
        "per_source":    per_source,
        "timeline":      timeline,
        "duration_ms":   duration_ms,
        "started_at":    started,
        "finished_at":   finished,
        "sources_queried": len(tasks),
        "sources_available": sum(1 for r in per_source.values() if r.get("available")),
    }

    log.info("url_scan_complete",
             target=url,
             verdict=fused_verdict,
             score=fused_score,
             duration_ms=duration_ms,
             sources=case["sources_available"])

    return case


# ── Streaming entrypoint (for live Streamlit progress) ────────────
def analyse_url_live(url: str) -> Iterator[dict]:
    """
    Generator version — yields progress updates as each source completes.
    Use this in Streamlit to show per-API live status.

    v21 (Day 3) pipeline additions:
      - Pre-scan URL validation (catches gogle.com style fake URLs)
      - ML classifier (phishing probability)
      - Security hygiene score (0-100 + letter grade)
      - Scan history DB write on finish

    Yields:
      {"phase": "init", ...}
      {"phase": "pre_validation", "result": {...}}       ← Day 3
      {"phase": "source_complete", "source": "virustotal", "result": {...}}
      ...
      {"phase": "ml_classification", "result": {...}}    ← Day 3
      {"phase": "enriching"}
      {"phase": "hygiene_scoring"}                        ← Day 3
      {"phase": "finished", "case": {...}}
    """
    from core.url_validator import validate_url

    started = _now_iso()
    t0 = time.monotonic()

    # ── PRE-SCAN VALIDATION (NEW Day 3) ─────────────────────────────
    # Catches fake URLs like "https://gogle" before wasting API budget
    validation = validate_url(url)
    yield {"phase": "pre_validation", "result": validation}

    ip = validation.get("resolved_ip")

    tasks: list[tuple[str, callable, tuple]] = [
        ("virustotal",     virustotal.scan_url,              (url,)),
        ("google_sb",      google_safebrowsing.scan_url,     (url,)),
        ("urlscan",        urlscan.scan_url,                 (url, False)),
        ("phishtank",      phishtank.check_url,              (url,)),
        ("otx_url",        otx.lookup_indicator,             (url, "url")),
        ("urlhaus",        urlhaus.lookup_url,               (url,)),
    ]
    if ip:
        tasks.extend([
            ("abuseipdb",  abuseipdb.check_ip,               (ip,)),
            ("shodan",     shodan_client.host_info,          (ip,)),
            ("otx_ip",     otx.lookup_indicator,             (ip, "ip")),
            ("threatfox",  threatfox.search_ioc,             (ip,)),
        ])

    # Initial yield — tell UI which sources will be hit
    yield {
        "phase":  "init",
        "target": url,
        "ip":     ip,
        "sources_planned": [name for name, _, _ in tasks],
    }

    per_source: dict[str, dict] = {}
    timeline: list[dict] = [{"ts": started, "event": "scan_started", "source": "orchestrator"}]

    # ── Early exit if domain is dead (saves API budget) ─────────────
    if not validation.get("dns_resolved") and not validation.get("valid"):
        log.info("url_scan_skipped_dead_domain", target=url)
        fused_score = validation.get("risk_floor", 5.0)
        fused_verdict = validation.get("suggested_verdict", "SUSPICIOUS")
    else:
        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = {
                pool.submit(_timed_call, name, fn, *args): name
                for name, fn, args in tasks
            }
            for fut in as_completed(futures):
                name = futures[fut]
                try:
                    result = fut.result()
                except Exception as e:
                    result = {
                        "available": False, "source": name,
                        "verdict": "UNKNOWN", "score": 0.0,
                        "detail": {}, "error": str(e), "ts": _now_iso(),
                        "duration_ms": 0,
                    }
                per_source[name] = result
                timeline.append({
                    "ts":     _now_iso(),
                    "event":  "source_returned",
                    "source": name,
                    "verdict": result.get("verdict"),
                    "score":   result.get("score"),
                    "ms":      result.get("duration_ms"),
                })
                yield {
                    "phase":   "source_complete",
                    "source":  name,
                    "result":  result,
                }

        fused_score, fused_verdict = _fuse(per_source)

        # Apply validation risk floor (typo-squat, homograph, etc.)
        risk_floor = validation.get("risk_floor", 0)
        if risk_floor > fused_score:
            fused_score = risk_floor
            if fused_score >= 5.5 and fused_verdict == "CLEAN":
                fused_verdict = "SUSPICIOUS"

    finished = _now_iso()
    duration_ms = round((time.monotonic() - t0) * 1000, 1)

    # ── ML classification (NEW Day 3) ───────────────────────────────
    try:
        from core.ml_classifier import classify_url
        ml_result = classify_url(url)
        yield {"phase": "ml_classification", "result": ml_result}
    except Exception as e:
        log.error("ml_classify_failed", error=str(e))
        ml_result = {"error": str(e)}

    # ── Security hygiene score (NEW Day 3) ──────────────────────────
    yield {"phase": "hygiene_scoring"}
    try:
        from core.hygiene_scorer import hygiene_scan
        hygiene = hygiene_scan(url)
    except Exception as e:
        log.error("hygiene_score_failed", error=str(e))
        hygiene = {"error": str(e), "score": 0, "grade": "N/A"}

    # ── Enrichment phase (parallel deep-dive lookups) ────────────
    yield {"phase": "enriching"}
    try:
        from core.url_intelligence import enrich_url
        enrichment = enrich_url(url)
    except Exception as e:
        log.error("enrichment_failed", error=str(e))
        enrichment = {"error": str(e)}

    # ── POST-FUSION REALITY CHECK (v24) ──────────────────────────────
    # Bring hygiene grade / SSL / Shodan CVE count / ML signal into the
    # final verdict so noisy hosts like scanme.nmap.org no longer slip
    # past as "All Clear" when they have 108 CVEs and no SSL.
    _pre_score, _pre_verdict = fused_score, fused_verdict
    fused_score, fused_verdict, verdict_reasons = _post_fusion_adjust(
        fused_score, fused_verdict, per_source, hygiene, ml_result,
    )
    if verdict_reasons:
        timeline.append({
            "ts": _now_iso(),
            "event": "verdict_adjusted",
            "source": "fusion_v2",
            "verdict": fused_verdict,
            "score": fused_score,
            "from_score": _pre_score,
            "from_verdict": _pre_verdict,
            "reasons": verdict_reasons,
        })

    case = {
        "case_id":       generate_case_id("URL"),
        "target":        url,
        "target_ip":     ip,
        "fused_score":   fused_score,
        "fused_verdict": fused_verdict,
        "verdict_reasons": verdict_reasons,
        "verdict_pre_adjust": {"score": _pre_score, "verdict": _pre_verdict},
        "per_source":    per_source,
        "validation":    validation,
        "ml":            ml_result,
        "hygiene":       hygiene,
        "enrichment":    enrichment,
        "timeline":      timeline,
        "duration_ms":   duration_ms,
        "started_at":    started,
        "finished_at":   finished,
        "sources_queried": len(tasks),
        "sources_available": sum(1 for r in per_source.values() if r.get("available")),
    }

    # ── BROWSER-WARNING PREDICTION (v24) ───────────────────────────
    # Predicts whether Chrome / Edge / Safari would block this URL,
    # and what specific warning they would show.
    try:
        from core.browser_warning_detector import predict_browser_warning
        case["browser_warning"] = predict_browser_warning(case)
        timeline.append({
            "ts": _now_iso(),
            "event": "browser_warning_predicted",
            "source": "browser_detector",
            "verdict": case["browser_warning"]["warning_type"] or "none",
            "score": case["browser_warning"]["confidence"],
            "will_warn": case["browser_warning"]["will_warn"],
        })
    except Exception as e:
        log.error("browser_warning_failed", error=str(e))
        case["browser_warning"] = {
            "will_warn": False, "warning_type": None,
            "browser_label": "—", "confidence": 0,
            "signals": [], "chrome_title": "—", "chrome_body": "—",
            "threat_categories": [], "error": str(e),
        }

    # ── Write to scan_history DB (NEW Day 3) ────────────────────────
    try:
        from core.scan_history import record_scan
        record_scan(case, scan_type="url")
    except Exception as e:
        log.error("scan_history_write_failed", error=str(e))

    yield {"phase": "finished", "case": case}
