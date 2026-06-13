"""
AI-DTCTM | URL Scanner page (v20.2 — enriched)
════════════════════════════════════════════════════════════════════
v20.2 fixes:
  - Per-source tab now shows detailed cards with every key detail field
  - NEW "INTEL" tab — shows enrichment: DNS, SSL, tech stack, GitHub,
    WHOIS, redirect chain, Wayback history, robots/sitemap
  - Uses components.html for banner (fixes Streamlit 1.56 HTML escape)
  - Input defaults to https:// when user omits scheme
"""
from __future__ import annotations

import json
import streamlit as st

from core.shared_css import (
    section_header, readout, verdict_banner, source_pill, kpi_row,
)
from core.url_analyzer import analyse_url_live


_PLANNED_SOURCES = [
    "virustotal", "google_sb", "urlscan", "phishtank",
    "otx_url", "urlhaus",
    "abuseipdb", "shodan", "otx_ip", "threatfox",
]


_URL_PAGE_CSS = """
<style>
/* ── White page background ──────────────────────────────────────── */
[data-testid="stAppViewContainer"] > .main,
[data-testid="stMain"] {
  background: #F8FAFF !important;
}
[data-testid="block-container"] {
  background: transparent !important;
  padding-top: 1rem !important;
}

/* ── Tab bar ────────────────────────────────────────────────────── */
[data-testid="stTabs"] > div:first-child {
  background: #FFFFFF !important;
  border-bottom: 2px solid #E2E8F0 !important;
  border-radius: 10px 10px 0 0 !important;
  padding: 0 6px !important;
}
[data-testid="stTabs"] button[role="tab"] {
  font-family: Inter, sans-serif !important;
  font-size: 0.75rem !important;
  letter-spacing: 0.04em !important;
  font-weight: 600 !important;
  color: #64748B !important;
  padding: 10px 14px !important;
  border-bottom: 2px solid transparent !important;
  transition: all 180ms ease !important;
  background: transparent !important;
}
[data-testid="stTabs"] button[role="tab"]:hover {
  color: #2563EB !important;
  background: rgba(37,99,235,0.04) !important;
}
[data-testid="stTabs"] button[role="tab"][aria-selected="true"] {
  color: #2563EB !important;
  border-bottom: 2px solid #2563EB !important;
  background: rgba(37,99,235,0.04) !important;
  font-weight: 700 !important;
}
[data-testid="stTabContent"] {
  background: #FFFFFF !important;
  border: 1px solid #E2E8F0 !important;
  border-top: none !important;
  border-radius: 0 0 10px 10px !important;
  padding: 20px 22px !important;
}

/* ── Download buttons ───────────────────────────────────────────── */
[data-testid="stDownloadButton"] button {
  border-radius: 8px !important;
  font-weight: 600 !important;
  font-size: 0.82rem !important;
}

/* ── KPI / stat boxes ────────────────────────────────────────────── */
[data-testid="stMetric"] {
  background: #FFFFFF;
  border: 1px solid #E2E8F0;
  border-radius: 10px;
  padding: 14px 16px;
}

/* ── New animations ─────────────────────────────────────────────── */
@keyframes mc-scan-beam {
  0%   { transform: translateX(-100%); opacity: 0; }
  10%  { opacity: 1; }
  90%  { opacity: 1; }
  100% { transform: translateX(300%); opacity: 0; }
}
@keyframes mc-bar-grow {
  from { width: 0 !important; }
}
@keyframes mc-pulse-ring {
  0%   { transform: scale(0.9); opacity: 1; }
  100% { transform: scale(1.5); opacity: 0; }
}
@keyframes mc-float {
  0%, 100% { transform: translateY(0); }
  50%       { transform: translateY(-6px); }
}
@keyframes mc-counter-in {
  from { opacity: 0; transform: scale(0.7) translateY(10px); }
  to   { opacity: 1; transform: scale(1) translateY(0); }
}
@keyframes mc-tab-content-in {
  from { opacity: 0; transform: translateY(8px); }
  to   { opacity: 1; transform: translateY(0); }
}
@keyframes mc-row-in {
  from { opacity: 0; transform: translateX(-12px); }
  to   { opacity: 1; transform: translateX(0); }
}
@keyframes mc-pulse {
  0%, 100% { opacity: 1; }
  50%       { opacity: 0.4; }
}

/* ── Source pill badges ─────────────────────────────────────────── */
.url-source-pill {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 6px 12px;
  border-radius: 8px;
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.72rem;
  font-weight: 700;
  letter-spacing: 0.04em;
  border: 1px solid #E2E8F0;
  background: #FFFFFF;
  transition: all 180ms ease;
}

/* ── Expander clean ─────────────────────────────────────────────── */
[data-testid="stExpander"] {
  border: 1px solid #E2E8F0 !important;
  border-radius: 8px !important;
  background: #FFFFFF !important;
}

/* ── Click ripple on buttons ────────────────────────────────────── */
[data-testid="stButton"] button {
  position: relative !important;
  overflow: hidden !important;
  transition: all 180ms ease !important;
}
[data-testid="stButton"] button::after {
  content: '' !important;
  position: absolute !important;
  inset: 0 !important;
  background: rgba(255,255,255,0.25) !important;
  border-radius: inherit !important;
  transform: scale(0) !important;
  opacity: 0 !important;
  transition: transform 0.4s ease, opacity 0.4s ease !important;
}
[data-testid="stButton"] button:active::after {
  transform: scale(2) !important;
  opacity: 0 !important;
  transition: 0s !important;
}
[data-testid="stButton"] button:active {
  transform: scale(0.97) !important;
}

/* ── Download buttons ────────────────────────────────────────────── */
[data-testid="stDownloadButton"] button {
  border-radius: 8px !important;
  font-weight: 600 !important;
  font-size: 0.82rem !important;
  transition: all 180ms ease !important;
}
[data-testid="stDownloadButton"] button:hover {
  transform: translateY(-1px) !important;
  box-shadow: 0 4px 12px rgba(37,99,235,0.2) !important;
}

/* ── Scroll-triggered fade (via IntersectionObserver in HTML) ────── */
.scroll-fade {
  opacity: 0;
  transform: translateY(16px);
  transition: opacity 0.5s ease, transform 0.5s ease;
}
.scroll-fade.visible {
  opacity: 1;
  transform: translateY(0);
}

/* ── Hero animations (moved here from hero markdown) ─────────── */
@keyframes hero-glow {
  0%, 100% { opacity: 0.7; transform: scale(1); }
  50%       { opacity: 1;   transform: scale(1.06); }
}
@keyframes badge-pulse {
  0%, 100% { box-shadow: 0 0 0 0 rgba(74,222,128,0.4); }
  50%       { box-shadow: 0 0 0 7px rgba(74,222,128,0); }
}
.url-hero-shield { animation: hero-glow 3s ease-in-out infinite; }
</style>
"""

def render_url_scanner_page():
    st.markdown(_URL_PAGE_CSS, unsafe_allow_html=True)

    # ── Pre-load URL chosen from Live Threat Feed (must happen BEFORE
    # the text_input widget below is rendered, otherwise Streamlit will
    # raise: "session_state[key] cannot be modified after the widget is
    # instantiated"). The Live Feed button stashes the URL in a separate
    # key, and we apply it here at the top of the render cycle.
    _pending_url = st.session_state.pop("_ltf_pending_url", None)
    if _pending_url:
        # Safe — widget hasn't been created yet on this run
        st.session_state["scanner_url_input"] = _pending_url
        # Trigger auto-scan after the input renders
        st.session_state["_ltf_auto_scan_url"] = _pending_url

    # ── Clean professional hero (NO indentation — markdown treats indent as code!) ──
    st.markdown(
"""<div style="background:#F0F9FF;border-radius:14px;padding:24px 28px;margin-bottom:18px;border:1px solid #E0F2FE;box-shadow:0 4px 16px rgba(2,132,199,0.08);"><div style="display:flex;align-items:center;gap:20px;flex-wrap:wrap;"><div class="url-hero-shield" style="flex-shrink:0;"><svg width="64" height="64" viewBox="0 0 64 64" fill="none"><defs><linearGradient id="shieldG" x1="0" y1="0" x2="64" y2="64"><stop offset="0%" stop-color="#0284C7"/><stop offset="100%" stop-color="#0369A1"/></linearGradient></defs><path d="M32 6 L54 16 L54 34 C54 46 44 56 32 60 C20 56 10 46 10 34 L10 16 Z" fill="url(#shieldG)" opacity="0.12" stroke="url(#shieldG)" stroke-width="1.5"/><path d="M32 12 L50 20 L50 34 C50 44 42 52 32 56 C22 52 14 44 14 34 L14 20 Z" fill="url(#shieldG)" opacity="0.08"/><circle cx="29" cy="30" r="8" stroke="#0284C7" stroke-width="2" fill="none"/><line x1="35" y1="36" x2="41" y2="42" stroke="#0284C7" stroke-width="2.5" stroke-linecap="round"/><circle cx="29" cy="30" r="3" fill="#0284C7" opacity="0.5"/></svg></div><div style="flex:1;min-width:200px;"><div style="font-family:Inter,sans-serif;font-size:0.58rem;font-weight:700;letter-spacing:0.16em;color:#0284C7;text-transform:uppercase;margin-bottom:5px;">AI-DTCTM &mdash; Forensic Intelligence Platform</div><div style="font-family:Inter,sans-serif;font-size:1.55rem;font-weight:800;color:#0C4A6E;letter-spacing:-0.025em;line-height:1.2;">URL Threat Scanner</div><div style="font-family:Inter,sans-serif;font-size:0.78rem;color:#475569;margin-top:8px;line-height:1.7;">Queries <b style="color:#0C4A6E;">10 threat-intel APIs</b> in parallel &mdash; VirusTotal &middot; Google Safe Browsing &middot; Shodan (InternetDB) &middot; AbuseIPDB &middot; OTX &middot; PhishTank &middot; URLScan &middot; URLhaus &middot; ThreatFox</div></div><div style="flex-shrink:0;display:flex;flex-direction:column;align-items:flex-end;gap:8px;"><div style="display:inline-flex;align-items:center;gap:7px;background:rgba(22,163,74,0.1);border:1px solid rgba(22,163,74,0.2);border-radius:8px;padding:6px 12px;font-family:JetBrains Mono,monospace;font-size:0.7rem;font-weight:700;color:#16A34A;letter-spacing:0.08em;animation:badge-pulse 2.5s ease-in-out infinite;"><span style="width:7px;height:7px;border-radius:50%;background:#16A34A;display:inline-block;"></span> LIVE</div><div style="font-family:JetBrains Mono,monospace;font-size:0.62rem;color:#64748B;letter-spacing:0.04em;text-align:right;">10 sources &middot; WHOIS &middot; SSL &middot; DNS &middot; ML</div></div></div></div>""",
        unsafe_allow_html=True
    )

    # ── Input row ─────────────────────────────────────────────────
    col_in, col_btn = st.columns([5, 1])
    with col_in:
        url = st.text_input(
            "Target URL",
            placeholder="https://example.com  or  http://testphp.vulnweb.com",
            key="scanner_url_input",
            label_visibility="collapsed",
        )
    with col_btn:
        scan_clicked = st.button("Scan", type="primary", use_container_width=True)

    # ── Sample URLs for quick testing ─────────────────────────────
    st.markdown(
        '<div style="display:flex;gap:8px;flex-wrap:wrap;margin:8px 0 14px;">'
        '<span style="font-family:JetBrains Mono,monospace;font-size:0.62rem;color:#64748B;padding:4px 0;">Try:</span>'
        '<span style="font-family:JetBrains Mono,monospace;font-size:0.62rem;background:rgba(22,163,74,0.08);color:#16A34A;padding:4px 10px;border-radius:6px;border:1px solid rgba(22,163,74,0.15);">Safe: google.com</span>'
        '<span style="font-family:JetBrains Mono,monospace;font-size:0.62rem;background:rgba(22,163,74,0.08);color:#16A34A;padding:4px 10px;border-radius:6px;border:1px solid rgba(22,163,74,0.15);">Safe: github.com</span>'
        '<span style="font-family:JetBrains Mono,monospace;font-size:0.62rem;background:rgba(217,119,6,0.08);color:#D97706;padding:4px 10px;border-radius:6px;border:1px solid rgba(217,119,6,0.15);">Test: testphp.vulnweb.com</span>'
        '<span style="font-family:JetBrains Mono,monospace;font-size:0.62rem;background:rgba(217,119,6,0.08);color:#D97706;padding:4px 10px;border-radius:6px;border:1px solid rgba(217,119,6,0.15);">Test: scanme.nmap.org</span>'
        '</div>',
        unsafe_allow_html=True,
    )

    # ── 🔴 LIVE THREAT FEED: real, currently-online malicious URLs ──
    _render_live_threat_feed()

    # ── Phase 3e: Force-fresh always ON & hidden. Voice visible + female. ──
    force_fresh = True   # auto: every scan now real-time, no cache

    voice_enabled = True  # Zaara AI voice — speaks after scan

    # Auto-trigger scan if user clicked a "🔍 Scan" button in the live
    # threat feed (page top pre-loaded the URL into the input field).
    _auto_scan_url = st.session_state.pop("_ltf_auto_scan_url", None)
    if _auto_scan_url and not scan_clicked:
        scan_clicked = True
        url = _auto_scan_url

    if scan_clicked:
        if not url or not url.strip():
            st.error("Enter a URL to scan.")
            return
        if not url.startswith(("http://", "https://")):
            url = "https://" + url.strip()

        # Phase 3e: cache always cleared (fresh scan every time)
        try:
            from core.cache import clear_for_url
            clear_for_url(url)
        except Exception:
            pass

        _run_live_scan(url)

        # Zaara AI Voice — young female professional voice after scan
        if voice_enabled:
            last = st.session_state.get("last_scan_case", {}) or {}
            verdict = (last.get("fused_verdict") or "complete").upper().replace("_", " ")
            score = last.get("fused_score", 0)
            target_short = (last.get("target") or "the target")[:40]
            # Natural conversational script — sounds like a real person
            if verdict == "CLEAN":
                spoken = f"Hey, scan complete. {target_short} looks clean. Risk score is just {score:.1f} out of 10. No threats detected. You're good to go."
            elif verdict == "SUSPICIOUS":
                spoken = f"Heads up. {target_short} came back suspicious. Risk score {score:.1f} out of 10. I'd recommend checking the details before proceeding."
            elif verdict in ("MALICIOUS", "DEAD DOMAIN"):
                spoken = f"Warning. {target_short} is flagged as {verdict.lower()}. Risk score {score:.1f} out of 10. Do not proceed. This is a confirmed threat."
            else:
                spoken = f"Scan complete for {target_short}. Verdict is {verdict.lower()}. Risk score {score:.1f} out of 10."
            from streamlit.components.v1 import html as _stcomp_html
            _stcomp_html(
                f"""<script>
                  (function(){{
                    if (!('speechSynthesis' in window)) return;
                    let attempts = 0;
                    const maxAttempts = 10;
                    function speak(){{
                      const voices = window.speechSynthesis.getVoices();
                      if (voices.length === 0 && attempts < maxAttempts) {{
                        attempts++;
                        setTimeout(speak, 300);
                        return;
                      }}
                      // Priority: young-sounding female voices on Windows/Mac/Chrome
                      const femalePrefs = [
                        'Microsoft Aria Online (Natural)',
                        'Microsoft Aria',
                        'Microsoft Jenny',
                        'Microsoft Zira',
                        'Google US English',
                        'Google UK English Female',
                        'Samantha',
                        'Karen',
                        'Tessa',
                        'Moira',
                        'Veena'
                      ];
                      let chosen = null;
                      for (const name of femalePrefs) {{
                        chosen = voices.find(v => v.name && v.name.includes(name));
                        if (chosen) break;
                      }}
                      if (!chosen) {{
                        // Fallback: any English female-sounding voice
                        chosen = voices.find(v =>
                          v.lang.startsWith('en') &&
                          (v.name.toLowerCase().includes('female') ||
                           v.name.toLowerCase().includes('zira') ||
                           v.name.toLowerCase().includes('aria') ||
                           v.name.toLowerCase().includes('jenny'))
                        ) || voices.find(v => v.lang.startsWith('en'));
                      }}
                      const u = new SpeechSynthesisUtterance({spoken!r});
                      if (chosen) u.voice = chosen;
                      // Natural young female settings — warm, slightly higher pitch
                      u.rate = 0.95;
                      u.pitch = 1.2;
                      u.volume = 1.0;
                      window.speechSynthesis.cancel();
                      window.speechSynthesis.speak(u);
                      setTimeout(()=>{{
                        if (!window.speechSynthesis.speaking && attempts < maxAttempts) {{
                          attempts++;
                          window.speechSynthesis.speak(u);
                        }}
                      }}, 400);
                    }}
                    if (window.speechSynthesis.getVoices().length > 0) {{
                      speak();
                    }} else {{
                      window.speechSynthesis.onvoiceschanged = speak;
                      setTimeout(speak, 300);
                    }}
                  }})();
                </script>""",
                height=0,
            )
        return

    # ── Fix: only show last case if URL in input still matches it ──
    # (Previous bug: user types new URL → saw old result for different URL)
    last_case = st.session_state.get("last_scan_case")
    if last_case:
        current_input = (url or "").strip()
        last_target = last_case.get("target", "")
        if not current_input or current_input in last_target or last_target in current_input:
            _render_case(last_case)
        else:
            _render_empty_state()
    else:
        _render_empty_state()


def _render_empty_state():
    """Premium empty state with animated SVG."""
    st.markdown(
        '<div style="background:linear-gradient(135deg, #EFF6FF 0%, #FFFFFF 50%, #F0FDF4 100%);'
        ' padding:40px 32px; border:1px solid #DBEAFE; border-radius:14px;'
        ' text-align:center; margin:20px 0;'
        ' animation:mc-tab-content-in 500ms cubic-bezier(0.4,0,0.2,1) backwards;">'
        '<svg width="64" height="64" viewBox="0 0 64 64" fill="none" style="margin-bottom:16px;">'
        '<circle cx="32" cy="32" r="28" stroke="#2563EB" stroke-width="1.5" fill="rgba(37,99,235,0.04)"/>'
        '<circle cx="32" cy="32" r="28" stroke="#2563EB" stroke-width="1" fill="none" opacity="0.3">'
        '<animate attributeName="r" values="28;20;28" dur="3s" repeatCount="indefinite"/>'
        '<animate attributeName="opacity" values="0.3;0;0.3" dur="3s" repeatCount="indefinite"/>'
        '</circle>'
        '<path d="M32 20v8l6 6" stroke="#2563EB" stroke-width="2" stroke-linecap="round"/>'
        '<circle cx="32" cy="32" r="3" fill="#2563EB"/>'
        '<line x1="44" y1="44" x2="52" y2="52" stroke="#2563EB" stroke-width="2.5" stroke-linecap="round"/>'
        '</svg>'
        '<div style="font-family:Inter,sans-serif; font-size:1.15rem; font-weight:700;'
        ' color:#0F172A; margin-bottom:8px;">Ready for forensic analysis</div>'
        '<div style="font-family:Inter,sans-serif; font-size:0.9rem; color:#475569;'
        ' line-height:1.6; max-width:500px; margin:0 auto;">'
        'Enter any URL above and click <b style="color:#2563EB;">Scan</b> to begin.'
        ' Zaara will cross-reference against <b>10 threat-intel APIs</b> and deliver'
        ' a comprehensive forensic report.</div>'
        '<div style="display:flex; justify-content:center; gap:8px; margin-top:18px; flex-wrap:wrap;">'
        '<span style="background:#EFF6FF; color:#1E40AF; padding:4px 10px; border-radius:5px;'
        ' font-family:JetBrains Mono,monospace; font-size:0.68rem; font-weight:600;'
        ' border:1px solid #DBEAFE;">WHOIS</span>'
        '<span style="background:#EFF6FF; color:#1E40AF; padding:4px 10px; border-radius:5px;'
        ' font-family:JetBrains Mono,monospace; font-size:0.68rem; font-weight:600;'
        ' border:1px solid #DBEAFE;">SSL</span>'
        '<span style="background:#EFF6FF; color:#1E40AF; padding:4px 10px; border-radius:5px;'
        ' font-family:JetBrains Mono,monospace; font-size:0.68rem; font-weight:600;'
        ' border:1px solid #DBEAFE;">DNS</span>'
        '<span style="background:#EFF6FF; color:#1E40AF; padding:4px 10px; border-radius:5px;'
        ' font-family:JetBrains Mono,monospace; font-size:0.68rem; font-weight:600;'
        ' border:1px solid #DBEAFE;">VirusTotal</span>'
        '<span style="background:#EFF6FF; color:#1E40AF; padding:4px 10px; border-radius:5px;'
        ' font-family:JetBrains Mono,monospace; font-size:0.68rem; font-weight:600;'
        ' border:1px solid #DBEAFE;">AbuseIPDB</span>'
        '<span style="background:#EFF6FF; color:#1E40AF; padding:4px 10px; border-radius:5px;'
        ' font-family:JetBrains Mono,monospace; font-size:0.68rem; font-weight:600;'
        ' border:1px solid #DBEAFE;">ML · 97.5%</span>'
        '</div></div>',
        unsafe_allow_html=True,
    )


def _render_live_threat_feed() -> None:
    """
    Pulls 10 currently-live malicious URLs from URLhaus + OpenPhish and
    shows them as clickable buttons that auto-populate the scan input.
    """
    with st.expander(
        "🔴 Live test URLs — real malicious sites verified online RIGHT NOW",
        expanded=False,
    ):
        st.markdown(
            '<div style="background:#FEF2F2;border:1px solid #FECACA;border-left:4px solid #DC2626;'
            'border-radius:8px;padding:10px 14px;margin-bottom:12px;'
            'font-family:Inter,sans-serif;font-size:0.78rem;color:#7F1D1D;line-height:1.55;">'
            '<b>⚠ Real malware/phishing URLs pulled from <code>urlhaus.abuse.ch</code> + '
            '<code>openphish.com</code></b><br/>'
            '<span style="color:#991B1B;">These are <b>currently online</b> and confirmed malicious. '
            'Click a button to load it into the scan input — '
            '<b>only scan, never visit in a browser</b>. Feed updates every 15 minutes.</span>'
            '</div>',
            unsafe_allow_html=True,
        )

        # Cache the fetched list in session_state so user can refresh
        if "live_threat_urls" not in st.session_state:
            st.session_state["live_threat_urls"] = None

        col_refresh, col_status = st.columns([1.2, 4])
        with col_refresh:
            if st.button("🔄 Refresh feed", key="ltf_refresh",
                          use_container_width=True):
                st.session_state["live_threat_urls"] = None

        # Lazy-load
        if st.session_state["live_threat_urls"] is None:
            with st.spinner("Pulling live malicious URLs from threat feeds…"):
                try:
                    from core.live_threat_feed import fetch_live_malicious_urls
                    st.session_state["live_threat_urls"] = (
                        fetch_live_malicious_urls(limit=10) or []
                    )
                except Exception as e:
                    st.error(f"Could not fetch live feed: {e}")
                    st.session_state["live_threat_urls"] = []

        urls = st.session_state["live_threat_urls"] or []
        with col_status:
            if urls:
                m_n = sum(1 for u in urls if u.get("type") == "malware")
                p_n = sum(1 for u in urls if u.get("type") == "phishing")
                st.markdown(
                    f'<div style="font-family:JetBrains Mono,monospace;font-size:0.72rem;'
                    f'color:#475569;padding-top:6px;">'
                    f'<span style="color:#DC2626;font-weight:700;">● {m_n} malware</span> · '
                    f'<span style="color:#EA580C;font-weight:700;">● {p_n} phishing</span> · '
                    f'<span style="color:#64748B;">cached 15 min</span></div>',
                    unsafe_allow_html=True,
                )
            else:
                st.markdown(
                    '<div style="font-family:Inter,sans-serif;font-size:0.78rem;color:#94A3B8;'
                    'padding-top:6px;">No URLs returned — feeds may be down. Try refresh.</div>',
                    unsafe_allow_html=True,
                )

        if not urls:
            return

        # Render each URL as a clickable row
        for i, u in enumerate(urls, 1):
            t = (u.get("type") or "").lower()
            if t == "malware":
                accent = "#DC2626"; tint = "#FEF2F2"; icon = "🦠"; lbl = "MALWARE"
            elif t == "phishing":
                accent = "#EA580C"; tint = "#FFF7ED"; icon = "🎣"; lbl = "PHISHING"
            else:
                accent = "#64748B"; tint = "#F8FAFC"; icon = "⚠"; lbl = (t or "?").upper()

            tags = ", ".join(u.get("tags", [])[:3])
            threat = u.get("threat", "")
            short_url = u["url"]
            display_url = short_url if len(short_url) <= 70 else short_url[:67] + "…"

            row_l, row_r = st.columns([5.5, 1])
            with row_l:
                st.markdown(
                    f'<div style="background:{tint};border:1px solid #E2E8F0;'
                    f'border-left:3px solid {accent};border-radius:8px;'
                    f'padding:9px 14px;margin-bottom:4px;'
                    f'font-family:Inter,sans-serif;">'
                    f'<div style="display:flex;align-items:center;gap:8px;margin-bottom:3px;">'
                    f'<span style="font-size:0.95rem">{icon}</span>'
                    f'<span style="font-family:JetBrains Mono,monospace;font-size:0.6rem;'
                    f'font-weight:700;color:{accent};background:#FFFFFF;border:1px solid {accent}55;'
                    f'padding:2px 8px;border-radius:4px;letter-spacing:0.08em;">{lbl}</span>'
                    f'<span style="font-family:JetBrains Mono,monospace;font-size:0.66rem;'
                    f'color:#64748B;">{u.get("source", "?")} · {u.get("first_seen", "?")}</span>'
                    + (f'<span style="font-family:Inter,sans-serif;font-size:0.7rem;'
                       f'color:#475569;background:#FFFFFF;padding:2px 8px;border-radius:4px;'
                       f'border:1px solid #E2E8F0;">{threat}</span>' if threat and threat != "phishing" and threat != "malware_download" else '')
                    + (f'<span style="font-family:Inter,sans-serif;font-size:0.66rem;'
                       f'color:#7C3AED;background:#F5F3FF;padding:2px 7px;border-radius:4px;'
                       f'border:1px solid #DDD6FE;">🎯 {tags}</span>' if tags else '') +
                    f'</div>'
                    f'<div style="font-family:JetBrains Mono,monospace;font-size:0.72rem;'
                    f'color:#1E293B;word-break:break-all;line-height:1.5;" title="{short_url}">'
                    f'{display_url}</div>'
                    f'</div>',
                    unsafe_allow_html=True,
                )
            with row_r:
                if st.button("🔍 Scan", key=f"ltf_scan_{i}",
                              use_container_width=True):
                    # Stash in a SEPARATE key — the page top will pick it up
                    # on the next run and apply BEFORE the text_input widget
                    # is instantiated (Streamlit won't allow it otherwise).
                    st.session_state["_ltf_pending_url"] = short_url
                    st.rerun()


def _run_live_scan(url: str):
    st.markdown("<div style='height:10px'></div>", unsafe_allow_html=True)

    status_placeholder = st.empty()
    grid_placeholder   = st.empty()
    result_placeholder = st.empty()

    source_states = {s: {"status": "pending"} for s in _PLANNED_SOURCES}
    _render_pills(grid_placeholder, source_states)

    status_placeholder.info(f"🛰️ Scanning **{url}** — querying 10 threat-intel sources in parallel")

    case = None
    try:
        for update in analyse_url_live(url):
            phase = update.get("phase")

            if phase == "pre_validation":
                v = update.get("result", {})
                if not v.get("dns_resolved"):
                    status_placeholder.warning(
                        f"⚠️ DNS resolution failed for **{url}** — domain does not exist. "
                        f"Marked as {v.get('suggested_verdict','SUSPICIOUS')}."
                    )
                elif v.get("risk_signals"):
                    signals = ", ".join(v.get("risk_signals", [])[:3])
                    status_placeholder.warning(
                        f"⚠️ Risk signals detected: **{signals}**. Proceeding with scan."
                    )

            elif phase == "init":
                planned = update.get("sources_planned", _PLANNED_SOURCES)
                source_states = {s: {"status": "pending"} for s in planned}
                _render_pills(grid_placeholder, source_states)

            elif phase == "source_complete":
                src = update["source"]
                result = update["result"]
                if not result.get("available"):
                    source_states[src] = {"status": "unavailable", "verdict": "",
                                          "score": 0, "duration_ms": 0}
                elif result.get("error"):
                    source_states[src] = {"status": "error", "verdict": "",
                                          "score": 0,
                                          "duration_ms": result.get("duration_ms", 0)}
                else:
                    source_states[src] = {
                        "status": "complete",
                        "verdict": result.get("verdict", ""),
                        "score":   result.get("score", 0),
                        "duration_ms": result.get("duration_ms", 0),
                    }
                _render_pills(grid_placeholder, source_states)

            elif phase == "ml_classification":
                status_placeholder.info("🤖 Running ML classifier (Random Forest, 15 features)...")

            elif phase == "hygiene_scoring":
                status_placeholder.info("🛡️ Scoring security hygiene (headers, TLS, cert)...")

            elif phase == "enriching":
                status_placeholder.info(
                    "🔍 Enriching: DNS, SSL, tech stack, WHOIS, GitHub mentions, "
                    "Wayback history, SEO artefacts..."
                )

            elif phase == "finished":
                case = update["case"]
                st.session_state["last_scan_case"] = case
                status_placeholder.empty()

    except Exception as e:
        status_placeholder.error(f"Scan failed: {e}")
        return

    if case is not None:
        # Voice disabled here — Zaara speaks from the main scan block only
        pass

        with result_placeholder.container():
            _render_case(case)


def _render_pills(placeholder, source_states: dict):
    with placeholder.container():
        cols = st.columns(2)
        items = list(source_states.items())
        for idx, (src, state) in enumerate(items):
            col = cols[idx % 2]
            with col:
                st.markdown(
                    source_pill(
                        source=src,
                        status=state["status"],
                        score=state.get("score", 0),
                        verdict=state.get("verdict", ""),
                        duration_ms=state.get("duration_ms", 0),
                    ),
                    unsafe_allow_html=True,
                )


def _animated_gauge(score: float, verdict: str) -> str:
    """
    SVG circular threat gauge — animates from 0 to score on load.
    score: 0-10 → maps to 0-270° arc
    """
    pct   = min(max(score / 10.0, 0), 1)
    color = {"MALICIOUS":"#DC2626","SUSPICIOUS":"#F59E0B",
             "CLEAN":"#16A34A","UNKNOWN":"#94A3B8"}.get(verdict,"#94A3B8")
    # Circle params
    r, cx, cy, stroke_w = 52, 64, 64, 10
    circumference = 2 * 3.14159 * r      # ≈ 326.7
    # We show 270° of the circle (from 135° to 405°), rest is gap
    arc_len = circumference * 0.75       # 270° = 75% of full circle
    dash_offset = arc_len * (1 - pct)
    return f"""
<div style="display:flex;flex-direction:column;align-items:center;gap:6px;">
  <svg width="128" height="128" viewBox="0 0 128 128">
    <defs>
      <linearGradient id="gaugeGrad" x1="0" y1="0" x2="1" y2="0">
        <stop offset="0%" stop-color="#16A34A"/>
        <stop offset="50%" stop-color="#F59E0B"/>
        <stop offset="100%" stop-color="#DC2626"/>
      </linearGradient>
    </defs>
    <!-- Track -->
    <circle cx="{cx}" cy="{cy}" r="{r}"
      fill="none" stroke="#F1F5F9" stroke-width="{stroke_w}"
      stroke-dasharray="{arc_len:.1f} {circumference:.1f}"
      stroke-dashoffset="-{arc_len*0.125:.1f}"
      stroke-linecap="round"
      transform="rotate(135 {cx} {cy})"/>
    <!-- Value arc -->
    <circle cx="{cx}" cy="{cy}" r="{r}"
      fill="none" stroke="{color}" stroke-width="{stroke_w}"
      stroke-dasharray="{arc_len:.1f} {circumference:.1f}"
      stroke-dashoffset="{dash_offset + arc_len*0.125:.1f}"
      stroke-linecap="round"
      transform="rotate(135 {cx} {cy})"
      style="transition:stroke-dashoffset 1.2s cubic-bezier(.4,0,.2,1);
             filter:drop-shadow(0 0 6px {color}66)">
      <animate attributeName="stroke-dashoffset"
        from="{arc_len:.1f}" to="{dash_offset + arc_len*0.125:.1f}"
        dur="1.2s" fill="freeze" calcMode="spline"
        keySplines="0.4 0 0.2 1"/>
    </circle>
    <!-- Score text -->
    <text x="{cx}" y="{cy-4}" text-anchor="middle"
      font-family="Inter,sans-serif" font-size="22" font-weight="800"
      fill="{color}">{score:.1f}</text>
    <text x="{cx}" y="{cy+14}" text-anchor="middle"
      font-family="Inter,sans-serif" font-size="9" font-weight="600"
      fill="#94A3B8" letter-spacing="1">/ 10 RISK</text>
  </svg>
  <div style="font-family:Inter,sans-serif;font-size:0.78rem;font-weight:700;
    color:{color};letter-spacing:0.06em;text-transform:uppercase;">{verdict}</div>
</div>"""


def _render_case(case: dict):
    verdict = case["fused_verdict"]
    score   = case["fused_score"]
    target  = case["target"]
    ip      = case.get("target_ip") or "—"
    dur     = case["duration_ms"] / 1000
    avail   = case["sources_available"]
    queried = case["sources_queried"]
    case_id = case["case_id"]

    # ── Colour palette per verdict ─────────────────────────────────
    vc = {"MALICIOUS":"#DC2626","SUSPICIOUS":"#F59E0B",
          "CLEAN":"#16A34A","UNKNOWN":"#94A3B8"}.get(verdict,"#94A3B8")
    vbg = {"MALICIOUS":"#FEF2F2","SUSPICIOUS":"#FFFBEB",
           "CLEAN":"#F0FDF4","UNKNOWN":"#F8FAFC"}.get(verdict,"#F8FAFC")
    vlbl = {"MALICIOUS":"Threat Detected","SUSPICIOUS":"Caution Advised",
            "CLEAN":"All Clear","UNKNOWN":"Unknown"}.get(verdict,"Unknown")

    # ── Premium result header (gauge + metadata side by side) ──────
    gauge_html = _animated_gauge(score, verdict)
    st.markdown(f"""
<div style="background:{vbg};border:1px solid #E2E8F0;border-left:5px solid {vc};
  border-radius:16px;padding:24px 28px;margin:8px 0 20px;
  box-shadow:0 4px 24px {vc}18;
  animation:mc-tab-content-in 400ms cubic-bezier(0.4,0,0.2,1);">
  <div style="display:flex;align-items:center;gap:28px;flex-wrap:wrap;">
    <!-- Gauge -->
    <div style="flex-shrink:0;">{gauge_html}</div>
    <!-- Metadata -->
    <div style="flex:1;min-width:220px;">
      <div style="font-family:Inter,sans-serif;font-size:0.65rem;font-weight:700;
        letter-spacing:0.12em;color:#94A3B8;text-transform:uppercase;
        margin-bottom:6px;">Forensic Scan Result</div>
      <div style="font-family:Inter,sans-serif;font-size:1.7rem;font-weight:800;
        color:{vc};line-height:1;letter-spacing:-0.03em;">{vlbl}</div>
      <div style="font-family:'JetBrains Mono',monospace;font-size:0.78rem;
        color:#475569;margin-top:8px;word-break:break-all;">{target}</div>
      <!-- KPI chips -->
      <div style="display:flex;flex-wrap:wrap;gap:8px;margin-top:14px;">
        <span style="background:#FFFFFF;border:1px solid #E2E8F0;border-radius:8px;
          padding:5px 12px;font-family:JetBrains Mono,monospace;font-size:0.72rem;
          color:#374151;">📋 {case_id}</span>
        <span style="background:#FFFFFF;border:1px solid #E2E8F0;border-radius:8px;
          padding:5px 12px;font-family:JetBrains Mono,monospace;font-size:0.72rem;
          color:#16A34A;font-weight:700;">✓ {avail}/{queried} sources</span>
        <span style="background:#FFFFFF;border:1px solid #E2E8F0;border-radius:8px;
          padding:5px 12px;font-family:JetBrains Mono,monospace;font-size:0.72rem;
          color:#374151;">⏱ {dur:.1f}s</span>
        <span style="background:#FFFFFF;border:1px solid #E2E8F0;border-radius:8px;
          padding:5px 12px;font-family:JetBrains Mono,monospace;font-size:0.72rem;
          color:#374151;">🌐 {ip}</span>
      </div>
    </div>
  </div>
</div>""", unsafe_allow_html=True)

    # 7 tabs — EVIDENCE removed (raw JSON, not useful for end users)
    tab_a, tab_o, tab_s, tab_h, tab_m, tab_i, tab_t = st.tabs(
        ["AI Analyst", "Overview", "Per Source",
         "Hygiene", "ML Model", "Intel", "Timeline"]
    )

    with tab_a:
        _render_ai_analyst_tab(case)
    with tab_o:
        _render_overview_tab(case)
    with tab_s:
        _render_per_source_tab(case)
    with tab_h:
        _render_hygiene_tab(case)
    with tab_m:
        _render_ml_tab(case)
    with tab_i:
        _render_intel_tab(case)
    with tab_t:
        _render_timeline_tab(case)

    st.markdown("<div style='height:12px'></div>", unsafe_allow_html=True)

    # Phase 2f: multi-format export (JSON / Markdown / PDF)
    dl1, dl2, dl3 = st.columns(3)
    with dl1:
        st.download_button(
            label="📄 JSON (raw)",
            data=json.dumps(case, indent=2, default=str),
            file_name=f"{case['case_id']}.json",
            mime="application/json",
            use_container_width=True,
        )
    with dl2:
        st.download_button(
            label="📋 Markdown (report)",
            data=_case_to_markdown(case),
            file_name=f"{case['case_id']}.md",
            mime="text/markdown",
            use_container_width=True,
        )
    with dl3:
        try:
            pdf_bytes = _case_to_pdf(case)
            st.download_button(
                label="📑 PDF (printable)",
                data=pdf_bytes,
                file_name=f"{case['case_id']}.pdf",
                mime="application/pdf",
                use_container_width=True,
            )
        except Exception:
            st.caption("PDF needs reportlab — pip install reportlab")


def _case_to_markdown(case: dict) -> str:
    """Phase 2f - human-readable markdown export."""
    lines = []
    lines.append(f"# Forensic Case Report — {case.get('case_id', '?')}")
    lines.append("")
    lines.append(f"**Target:** `{case.get('target', '?')}`  ")
    lines.append(f"**Target IP:** `{case.get('target_ip', '?')}`  ")
    lines.append(f"**Verdict:** **{case.get('fused_verdict', '?')}** "
                  f"(risk score `{case.get('fused_score', 0)}/10`)")
    lines.append(f"**Started:** {case.get('started_at', '?')}  ")
    lines.append(f"**Duration:** {case.get('duration_ms', 0)} ms")
    lines.append("")
    lines.append("## Per-Source Verdicts")
    lines.append("")
    lines.append("| Source | Verdict | Score | Latency |")
    lines.append("|---|---|---|---|")
    for s, r in case.get("per_source", {}).items():
        lines.append(
            f"| {s} | {r.get('verdict','?')} | "
            f"{r.get('score', 0)} | {r.get('duration_ms', 0)} ms |"
        )
    lines.append("")

    # Hygiene
    h = case.get("hygiene") or {}
    if h.get("score") is not None:
        lines.append(f"## Security Hygiene")
        lines.append(f"**Grade:** {h.get('grade', '?')} · **Score:** "
                      f"{h.get('score', 0)}/100")
        lines.append("")

    # ML
    ml = case.get("ml") or {}
    if ml.get("label"):
        lines.append(f"## ML Classifier")
        lines.append(f"**Label:** {ml.get('label')}  ")
        lines.append(f"**Confidence:** {ml.get('confidence', 0)*100:.1f}%")
        lines.append("")

    # Enrichment WHOIS / SSL summary
    en = case.get("enrichment") or {}
    if en.get("whois", {}).get("registrar"):
        w = en["whois"]
        lines.append(f"## Domain Forensics")
        lines.append(f"- Registrar: {w.get('registrar', '?')}")
        lines.append(f"- Created: {w.get('creation_date', '?')}")
        lines.append(f"- Age: {w.get('age_days', '?')} days")
        lines.append("")

    return "\n".join(lines)


def _case_to_pdf(case: dict) -> bytes:
    """
    Phase 3e - premium PDF: Helvetica-family with proper hierarchy,
    a verdict banner up top, source table with verdict-coded cells,
    multiple sections, and a footer.
    """
    from io import BytesIO
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib import colors
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                     Table, TableStyle, KeepTogether)
    from reportlab.lib.enums import TA_LEFT

    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=letter,
        rightMargin=0.6*inch, leftMargin=0.6*inch,
        topMargin=0.6*inch, bottomMargin=0.55*inch,
        title=f"AI-DTCTM Forensic Report - {case.get('case_id','?')}",
        author="AI-DTCTM Mission Control",
    )

    # Premium styles — Helvetica-family approximating Inter
    title_style = ParagraphStyle(
        "Title", fontName="Helvetica-Bold", fontSize=20,
        textColor=colors.HexColor("#0F172A"),
        spaceAfter=4, leading=24,
    )
    subtitle_style = ParagraphStyle(
        "Subtitle", fontName="Helvetica", fontSize=10,
        textColor=colors.HexColor("#64748B"),
        spaceAfter=18, leading=14, letterSpacing=0.5,
    )
    h2_style = ParagraphStyle(
        "H2", fontName="Helvetica-Bold", fontSize=12,
        textColor=colors.HexColor("#0F172A"),
        spaceBefore=14, spaceAfter=6, leading=16,
    )
    body_style = ParagraphStyle(
        "Body", fontName="Helvetica", fontSize=10,
        textColor=colors.HexColor("#334155"),
        spaceAfter=4, leading=15,
    )
    mono_style = ParagraphStyle(
        "Mono", fontName="Courier", fontSize=9,
        textColor=colors.HexColor("#475569"),
        spaceAfter=4, leading=13,
    )
    footer_style = ParagraphStyle(
        "Footer", fontName="Helvetica-Oblique", fontSize=8,
        textColor=colors.HexColor("#94A3B8"),
        spaceBefore=20, leading=11, alignment=TA_LEFT,
    )

    verdict = case.get('fused_verdict', '?')
    verdict_color_hex = {"MALICIOUS": "#DC2626", "DEAD_DOMAIN": "#DC2626",
                         "SUSPICIOUS": "#CA8A04", "CLEAN": "#16A34A"}.get(verdict, "#475569")
    verdict_bg_hex = {"MALICIOUS": "#FEF2F2", "DEAD_DOMAIN": "#FEF2F2",
                      "SUSPICIOUS": "#FFFBEB", "CLEAN": "#F0FDF4"}.get(verdict, "#F8FAFC")

    story = []

    # ── Header ───────────────────────────────────────────────────
    story.append(Paragraph("AI-DTCTM · Forensic Scan Report", title_style))
    story.append(Paragraph(
        f"Case ID  {case.get('case_id','?')}   ·   "
        f"Scanned  {case.get('started_at','?')[:19].replace('T',' ')} UTC",
        subtitle_style,
    ))

    # ── Verdict banner ──────────────────────────────────────────
    banner_data = [[
        Paragraph(f"<b>{verdict}</b>",
                  ParagraphStyle("vd", fontName="Helvetica-Bold", fontSize=22,
                                 textColor=colors.HexColor(verdict_color_hex),
                                 leading=26)),
        Paragraph(f"<font size='8' color='#64748B'>RISK SCORE</font><br/>"
                  f"<font size='22' color='#0F172A'><b>"
                  f"{case.get('fused_score',0):.1f}</b></font>"
                  f"<font size='12' color='#94A3B8'>/10</font>",
                  ParagraphStyle("score", fontName="Helvetica", fontSize=10,
                                 alignment=2)),  # right-align
    ]]
    banner = Table(banner_data, colWidths=[3.7*inch, 3.7*inch])
    banner.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(verdict_bg_hex)),
        ("LINEBEFORE", (0, 0), (0, 0), 4, colors.HexColor(verdict_color_hex)),
        ("LEFTPADDING", (0, 0), (-1, -1), 16),
        ("RIGHTPADDING", (0, 0), (-1, -1), 16),
        ("TOPPADDING", (0, 0), (-1, -1), 14),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 14),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
    ]))
    story.append(banner)
    story.append(Spacer(1, 16))

    # ── Target meta block ───────────────────────────────────────
    story.append(Paragraph("Target", h2_style))
    target_data = [
        ["URL",       case.get('target', '?')],
        ["IP",        case.get('target_ip', '?') or '—'],
        ["Duration",  f"{case.get('duration_ms', 0)} ms"],
        ["Sources",   f"{len([s for s,r in case.get('per_source',{}).items() if r.get('available')])} of "
                      f"{len(case.get('per_source',{}))}"],
    ]
    t_target = Table(target_data, colWidths=[1.1*inch, 6.3*inch])
    t_target.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (1, 0), (1, -1), "Courier"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#64748B")),
        ("TEXTCOLOR", (1, 0), (1, -1), colors.HexColor("#0F172A")),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(t_target)

    # ── Per-Source table with verdict-coded badges ─────────────
    story.append(Paragraph("Threat-intel sources", h2_style))
    rows = [["Source", "Verdict", "Score", "Latency"]]
    color_for = {"MALICIOUS": "#DC2626", "SUSPICIOUS": "#CA8A04",
                 "CLEAN": "#16A34A", "UNKNOWN": "#64748B"}
    style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F1F5F9")),
        ("TEXTCOLOR",  (0, 0), (-1, 0), colors.HexColor("#0F172A")),
        ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",   (0, 0), (-1, -1), 9),
        ("BOX",        (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
        ("INNERGRID",  (0, 0), (-1, -1), 0.25, colors.HexColor("#E2E8F0")),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]
    for i, (s, r) in enumerate(case.get("per_source", {}).items(), 1):
        v = (r.get("verdict") or "—").upper()
        clr = color_for.get(v, "#64748B")
        rows.append([s.replace("_", " ").upper(),
                     v,
                     str(r.get("score", 0)),
                     f"{r.get('duration_ms', 0)} ms"])
        style_cmds.append(("TEXTCOLOR", (1, i), (1, i), colors.HexColor(clr)))
        style_cmds.append(("FONTNAME", (1, i), (1, i), "Helvetica-Bold"))
    t_sources = Table(rows, colWidths=[2.2*inch, 1.6*inch, 1*inch, 1.2*inch])
    t_sources.setStyle(TableStyle(style_cmds))
    story.append(t_sources)

    # ── Hygiene ─────────────────────────────────────────────────
    h_data = case.get("hygiene") or {}
    if h_data.get("score") is not None:
        story.append(Paragraph("Security hygiene", h2_style))
        story.append(Paragraph(
            f"<b>Grade:</b> {h_data.get('grade','?')}  ·  "
            f"<b>Score:</b> {h_data.get('score',0)}/100",
            body_style,
        ))

    # ── ML ──────────────────────────────────────────────────────
    ml = case.get("ml") or {}
    if ml.get("label"):
        story.append(Paragraph("Machine learning classifier", h2_style))
        story.append(Paragraph(
            f"Random Forest, 15 engineered features.<br/>"
            f"<b>Label:</b> {ml.get('label')}  ·  "
            f"<b>Confidence:</b> {ml.get('confidence', 0)*100:.1f}%",
            body_style,
        ))

    # ── Domain enrichment ───────────────────────────────────────
    en = case.get("enrichment") or {}
    w = en.get("whois") or {}
    if w.get("registrar") or w.get("creation_date"):
        story.append(Paragraph("Domain forensics (WHOIS)", h2_style))
        story.append(Paragraph(
            f"<b>Registrar:</b> {w.get('registrar') or '—'}<br/>"
            f"<b>Created:</b> {w.get('creation_date') or '—'}<br/>"
            f"<b>Domain age:</b> {w.get('age_days') or '—'} days",
            body_style,
        ))

    # ── Footer ──────────────────────────────────────────────────
    story.append(Spacer(1, 14))
    story.append(Paragraph(
        f"AI-DTCTM Mission Control · automated forensic pipeline · "
        f"case archived {case.get('started_at','?')[:10]}",
        footer_style,
    ))

    doc.build(story)
    return buf.getvalue()


def _render_overview_tab(case: dict):
    per_source = case["per_source"]
    malicious  = [s for s, r in per_source.items() if r.get("verdict") == "MALICIOUS"  and r.get("available")]
    suspicious = [s for s, r in per_source.items() if r.get("verdict") == "SUSPICIOUS" and r.get("available")]
    clean      = [s for s, r in per_source.items() if r.get("verdict") == "CLEAN"      and r.get("available")]
    unknown    = [s for s, r in per_source.items() if r.get("verdict") == "UNKNOWN"     and r.get("available")]
    unavail    = [s for s, r in per_source.items() if not r.get("available")]

    enrich   = case.get("enrichment", {}) or {}
    http     = enrich.get("http", {}) or {}
    whois    = enrich.get("whois", {}) or {}
    ssl_info = enrich.get("ssl", {}) or {}
    geo      = enrich.get("geo", {}) or {}

    # ── Verdict summary counters ────────────────────────────────
    mc = "#DC2626" if malicious else "#64748B"
    sc = "#F59E0B" if suspicious else "#64748B"

    st.markdown(f"""
<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:18px;">
  <div style="background:#FFFFFF;border:1px solid #E2E8F0;border-radius:12px;
    padding:16px 18px;text-align:center;border-top:3px solid {mc};
    animation:mc-row-in 240ms cubic-bezier(0.4,0,0.2,1) backwards;">
    <div style="font-family:Inter;font-size:0.68rem;font-weight:700;
      letter-spacing:0.1em;color:#94A3B8;text-transform:uppercase;">Malicious</div>
    <div style="font-family:Inter;font-size:2.2rem;font-weight:800;
      color:{mc};line-height:1.1;margin-top:4px;">{len(malicious)}</div>
    <div style="font-family:JetBrains Mono;font-size:0.65rem;color:#94A3B8;margin-top:2px;">
      {", ".join(malicious[:3]) or "none"}</div>
  </div>
  <div style="background:#FFFFFF;border:1px solid #E2E8F0;border-radius:12px;
    padding:16px 18px;text-align:center;border-top:3px solid {sc};
    animation:mc-row-in 240ms 60ms cubic-bezier(0.4,0,0.2,1) backwards;">
    <div style="font-family:Inter;font-size:0.68rem;font-weight:700;
      letter-spacing:0.1em;color:#94A3B8;text-transform:uppercase;">Suspicious</div>
    <div style="font-family:Inter;font-size:2.2rem;font-weight:800;
      color:{sc};line-height:1.1;margin-top:4px;">{len(suspicious)}</div>
    <div style="font-family:JetBrains Mono;font-size:0.65rem;color:#94A3B8;margin-top:2px;">
      {", ".join(suspicious[:3]) or "none"}</div>
  </div>
  <div style="background:#FFFFFF;border:1px solid #E2E8F0;border-radius:12px;
    padding:16px 18px;text-align:center;border-top:3px solid #16A34A;
    animation:mc-row-in 240ms 120ms cubic-bezier(0.4,0,0.2,1) backwards;">
    <div style="font-family:Inter;font-size:0.68rem;font-weight:700;
      letter-spacing:0.1em;color:#94A3B8;text-transform:uppercase;">Clean</div>
    <div style="font-family:Inter;font-size:2.2rem;font-weight:800;
      color:#16A34A;line-height:1.1;margin-top:4px;">{len(clean)}</div>
    <div style="font-family:JetBrains Mono;font-size:0.65rem;color:#94A3B8;margin-top:2px;">
      {", ".join(clean[:3]) or "none"}</div>
  </div>
  <div style="background:#FFFFFF;border:1px solid #E2E8F0;border-radius:12px;
    padding:16px 18px;text-align:center;border-top:3px solid #94A3B8;
    animation:mc-row-in 240ms 180ms cubic-bezier(0.4,0,0.2,1) backwards;">
    <div style="font-family:Inter;font-size:0.68rem;font-weight:700;
      letter-spacing:0.1em;color:#94A3B8;text-transform:uppercase;">Unknown</div>
    <div style="font-family:Inter;font-size:2.2rem;font-weight:800;
      color:#94A3B8;line-height:1.1;margin-top:4px;">{len(unknown)}</div>
    <div style="font-family:JetBrains Mono;font-size:0.65rem;color:#94A3B8;margin-top:2px;">
      {", ".join(unknown[:3]) or "none"}</div>
  </div>
</div>""", unsafe_allow_html=True)

    # ── Source verdict grid — each source as a pill card ────────
    st.markdown("""
<div style="font-family:Inter;font-size:0.7rem;font-weight:700;letter-spacing:0.1em;
  color:#64748B;text-transform:uppercase;margin-bottom:10px;">All Source Verdicts</div>""",
    unsafe_allow_html=True)

    VDT_META = {
        "MALICIOUS":  ("#FEF2F2","#DC2626","#991B1B"),
        "SUSPICIOUS": ("#FFFBEB","#F59E0B","#92400E"),
        "CLEAN":      ("#F0FDF4","#16A34A","#166534"),
        "UNKNOWN":    ("#F8FAFC","#94A3B8","#475569"),
    }
    pills_html = '<div style="display:flex;flex-wrap:wrap;gap:8px;margin-bottom:16px;">'
    for src, r in sorted(per_source.items()):
        if not r.get("available"):
            continue
        v   = r.get("verdict","UNKNOWN")
        sc2 = r.get("score",0)
        ms  = r.get("duration_ms",0)
        bg, bc, tc = VDT_META.get(v, VDT_META["UNKNOWN"])
        lbl = src.replace("_", " ").upper()
        pills_html += (
            f'<div style="background:{bg};border:1.5px solid {bc}33;border-radius:8px;'
            f'padding:8px 12px;min-width:120px;">'
            f'<div style="font-family:JetBrains Mono;font-size:0.65rem;font-weight:700;'
            f'color:#475569;letter-spacing:0.06em;">{lbl}</div>'
            f'<div style="font-family:Inter;font-size:0.8rem;font-weight:700;'
            f'color:{bc};margin-top:3px;">{v}</div>'
            f'<div style="font-family:JetBrains Mono;font-size:0.62rem;color:{tc};'
            f'opacity:0.7;margin-top:2px;">{sc2:.1f}/10 &middot; {ms:.0f}ms</div>'
            f'</div>'
        )
    pills_html += '</div>'
    st.markdown(pills_html, unsafe_allow_html=True)

    # ── Scan timing ─────────────────────────────────────────────
    dur_s = case.get("duration_ms",0)/1000
    st.markdown(f"""
<div style="background:#F8FAFC;border:1px solid #E2E8F0;border-radius:10px;
  padding:12px 16px;margin-bottom:16px;display:flex;gap:24px;flex-wrap:wrap;">
  <div><div style="font-family:Inter;font-size:0.65rem;font-weight:600;
    color:#94A3B8;text-transform:uppercase;letter-spacing:0.08em;">Case ID</div>
    <div style="font-family:JetBrains Mono;font-size:0.78rem;color:#0F172A;
      font-weight:700;margin-top:2px;">{case.get("case_id","—")}</div></div>
  <div><div style="font-family:Inter;font-size:0.65rem;font-weight:600;
    color:#94A3B8;text-transform:uppercase;letter-spacing:0.08em;">Duration</div>
    <div style="font-family:JetBrains Mono;font-size:0.78rem;color:#0F172A;
      font-weight:700;margin-top:2px;">{dur_s:.2f}s</div></div>
  <div><div style="font-family:Inter;font-size:0.65rem;font-weight:600;
    color:#94A3B8;text-transform:uppercase;letter-spacing:0.08em;">Started</div>
    <div style="font-family:JetBrains Mono;font-size:0.78rem;color:#0F172A;
      margin-top:2px;">{case.get("started_at","")[:19].replace("T"," ")} UTC</div></div>
  <div><div style="font-family:Inter;font-size:0.65rem;font-weight:600;
    color:#94A3B8;text-transform:uppercase;letter-spacing:0.08em;">Target IP</div>
    <div style="font-family:JetBrains Mono;font-size:0.78rem;color:#0F172A;
      margin-top:2px;">{case.get("target_ip","—")}</div></div>
  <div><div style="font-family:Inter;font-size:0.65rem;font-weight:600;
    color:#94A3B8;text-transform:uppercase;letter-spacing:0.08em;">Sources OK</div>
    <div style="font-family:Inter;font-size:0.78rem;font-weight:800;
      color:#16A34A;margin-top:2px;">{case.get("sources_available",0)}/{case.get("sources_queried",0)}</div></div>
</div>""", unsafe_allow_html=True)

    # ── Quick facts grid ─────────────────────────────────────────
    facts = []
    if http.get("page_title"):
        facts.append(("Page Title",      http["page_title"][:60]))
    if http.get("server"):
        facts.append(("Web Server",      str(http["server"])[:50]))
    if whois.get("registrar"):
        facts.append(("Registrar",       str(whois["registrar"])[:50]))
    if whois.get("age_days") is not None:
        yrs = whois["age_days"] / 365
        col = "#16A34A" if yrs > 2 else "#F59E0B"
        facts.append(("Domain Age", f'<span style="color:{col};font-weight:700;">'
                                    f'{whois["age_days"]} days ({yrs:.1f} yrs)</span>'))
    if ssl_info.get("has_ssl"):
        dl = ssl_info.get("days_left")
        if dl is not None:
            col = "#16A34A" if dl > 30 else "#DC2626"
            facts.append(("SSL Expires",
                           f'<span style="color:{col};font-weight:700;">'
                           f'in {dl} days</span>'))
    if geo.get("country"):
        facts.append(("Location",        f"{geo.get('city','')+', ' if geo.get('city') else ''}"
                                         f"{geo.get('country','')}"))
    if geo.get("isp") or geo.get("org"):
        facts.append(("Hosting",         (geo.get("isp") or geo.get("org",""))[:55]))

    if facts:
        st.markdown("""
<div style="font-family:Inter;font-size:0.7rem;font-weight:700;letter-spacing:0.1em;
  color:#64748B;text-transform:uppercase;margin-bottom:10px;">Quick Facts</div>""",
        unsafe_allow_html=True)
        grid = '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:8px;">'
        for i,(label,val) in enumerate(facts):
            delay = i*40
            grid += (
                f'<div style="background:#FFFFFF;border:1px solid #E2E8F0;border-radius:10px;'
                f'padding:12px 14px;animation:mc-row-in 260ms {delay}ms cubic-bezier(0.4,0,0.2,1) backwards;">'
                f'<div style="font-family:Inter;font-size:0.62rem;font-weight:700;'
                f'letter-spacing:0.1em;color:#94A3B8;text-transform:uppercase;">{label}</div>'
                f'<div style="font-family:Inter;font-size:0.82rem;font-weight:600;'
                f'color:#0F172A;margin-top:4px;line-height:1.4;">{val}</div>'
                f'</div>'
            )
        grid += '</div>'
        st.markdown(grid, unsafe_allow_html=True)


def _render_per_source_tab(case: dict):
    """Each API gets its own rich detail card."""
    for src, r in sorted(case["per_source"].items()):
        _render_source_card(src, r)


def _render_source_card(src: str, r: dict):
    verdict_colors = {
        "MALICIOUS":  "#DC2626",
        "SUSPICIOUS": "#CA8A04",
        "CLEAN":      "#16A34A",
        "UNKNOWN":    "#64748B",
    }
    v = r.get("verdict", "UNKNOWN")
    vc = verdict_colors.get(v, "#64748B")

    if not r.get("available"):
        st.markdown(
            f'<div style="background:#F8FAFC; padding:10px 14px;'
            f' border-left:3px solid #CBD5E1; border:1px solid #E2E8F0;'
            f' border-radius:8px; margin-bottom:6px;'
            f' font-family:Inter,sans-serif; font-size:0.82rem;'
            f' display:flex; align-items:center; gap:8px;">'
            f'<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#94A3B8"'
            f' stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="10"/>'
            f'<line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>'
            f'<span style="color:#0F172A; font-weight:600;">{src.upper().replace("_"," ")}</span>'
            f'<span style="color:#94A3B8;">— not configured ({r.get("error","")})</span>'
            f'</div>',
            unsafe_allow_html=True,
        )
        return

    detail = r.get("detail", {}) or {}
    score = r.get("score", 0)
    expanded = v in ("MALICIOUS", "SUSPICIOUS")

    with st.expander(f"{src.upper().replace('_', ' ')}  ·  {v}  {score:.1f}", expanded=expanded):
        facts = []
        if src == "virustotal":
            facts = [
                ("Engines flagged",  f'{detail.get("malicious",0)}/{detail.get("total_engines",0)}'),
                ("Harmless",          str(detail.get("harmless", 0))),
                ("Suspicious",        str(detail.get("suspicious", 0))),
                ("Reputation",        str(detail.get("reputation", "—"))),
                ("Categories",        ", ".join(list(detail.get("categories", {}).values())[:4]) or "—"),
            ]
        elif src == "google_sb":
            facts = [
                ("Threats found",     str(detail.get("threats_found", 0))),
                ("Threat types",      ", ".join(detail.get("threat_types", [])) or "none"),
                ("Primary threat",    detail.get("primary_threat") or "—"),
            ]
        elif src == "urlscan":
            facts = [
                ("Scan UUID",         str(detail.get("uuid", "—"))[:24]),
                ("Country",           detail.get("country") or "—"),
                ("Hosting IP",        detail.get("ip") or "—"),
                ("Web server",        detail.get("server") or "—"),
                ("HTTP requests",     str(detail.get("requests", "—"))),
                ("Domains contacted", str(detail.get("domains_contacted", "—"))),
                ("Brands",            ", ".join(detail.get("brands", [])) or "none"),
            ]
            if detail.get("screenshot"):
                st.image(detail["screenshot"], caption="Sandbox screenshot (URLScan.io)")
        elif src == "phishtank":
            facts = [
                ("In database",       "yes" if detail.get("in_database") else "no"),
                ("Verified",          "yes" if detail.get("verified") else "no"),
                ("Phish ID",          str(detail.get("phish_id", "—"))),
            ]
        elif src == "abuseipdb":
            facts = [
                ("IP",                detail.get("ip") or "—"),
                ("Confidence",        f'{detail.get("confidence", 0)}/100'),
                ("Country",           detail.get("country_name") or detail.get("country") or "—"),
                ("ISP",               detail.get("isp") or "—"),
                ("Usage type",        detail.get("usage_type") or "—"),
                ("Total reports",     str(detail.get("total_reports", 0))),
                ("Last reported",     detail.get("last_reported") or "—"),
                ("Tor exit",          "YES" if detail.get("is_tor") else "no"),
            ]
        elif src == "shodan":
            facts = [
                ("IP",                detail.get("ip") or "—"),
                ("Country",           detail.get("country") or "—"),
                ("Organization",      detail.get("org") or "—"),
                ("Open ports",        ", ".join(map(str, detail.get("open_ports", [])[:10])) or "—"),
                ("Port count",        str(detail.get("port_count", 0))),
                ("Known CVEs",        str(detail.get("cve_count", 0))),
                ("Hostnames",         ", ".join(detail.get("hostnames", [])) or "—"),
                ("OS",                detail.get("os") or "unknown"),
            ]
            if detail.get("cves"):
                st.caption("Top CVEs:")
                st.code(", ".join(detail["cves"][:8]))
        elif src.startswith("otx"):
            facts = [
                ("OTX pulses",        str(detail.get("pulse_count", 0))),
                ("Reputation",        str(detail.get("reputation", 0))),
                ("Tags",              ", ".join(detail.get("tags", [])[:8]) or "none"),
                ("Country",           detail.get("country") or "—"),
                ("First pulse",       detail.get("first_pulse") or "—"),
            ]
        elif src == "urlhaus":
            facts = [
                ("URL status",        detail.get("url_status") or "—"),
                ("Threat type",       detail.get("threat") or "—"),
                ("Tags",              ", ".join(detail.get("tags", [])[:6]) or "none"),
                ("Malware families",  ", ".join(detail.get("malware_families", [])) or "—"),
                ("Date added",        detail.get("date_added") or "—"),
                ("Host",              detail.get("host") or "—"),
            ]
        elif src == "threatfox":
            facts = [
                ("IoC matches",       str(detail.get("matches", 0))),
                ("Malware families",  ", ".join(detail.get("malware_families", [])) or "—"),
                ("Threat types",      ", ".join(detail.get("threat_types", [])) or "—"),
                ("First seen",        detail.get("first_seen") or "—"),
                ("Last seen",         detail.get("last_seen") or "—"),
            ]

        for label, value in facts:
            readout(label, str(value))

        with st.expander("Raw response"):
            st.json(detail)


def _render_intel_tab(case: dict):
    """Show all the deep enrichment data."""
    enrich = case.get("enrichment", {})
    if not enrich or enrich.get("error"):
        st.warning("Enrichment data unavailable: " + str(enrich.get("error", "not run")))
        return

    # HTTP profile
    http = enrich.get("http", {}) or {}
    if http and not http.get("error"):
        section_header("HTTP profile", "PAGE DATA")
        if http.get("page_title"):
            readout("Title", http["page_title"][:120])
        if http.get("meta_description"):
            readout("Description", http["meta_description"][:160])
        readout("Status code",  str(http.get("status_code", "—")))
        readout("Final URL",    http.get("final_url") or "—")
        readout("Server",       http.get("server") or "—")
        readout("Content-Type", http.get("content_type") or "—")

        chain = http.get("redirect_chain", [])
        if len(chain) > 1:
            st.markdown("**Redirect chain:**")
            for hop in chain:
                st.markdown(
                    f'<div style="font-family:\'JetBrains Mono\',monospace; font-size:0.75rem; color:#334155; padding:3px 0;">'
                    f'<span style="color:#2563EB;">[{hop["status"]}]</span> {hop["url"]}'
                    f'</div>', unsafe_allow_html=True,
                )

    # Technology stack
    if http.get("tech_stack"):
        st.markdown("<div style='height:10px'></div>", unsafe_allow_html=True)
        section_header("Technology stack", "DETECTED")
        pills = ""
        for t in http["tech_stack"]:
            pills += (
                f'<span style="display:inline-block; background:rgba(37,99,235,0.08);'
                f' color:#2563EB; border:1px solid rgba(37,99,235,0.2); padding:4px 10px;'
                f' margin:3px; border-radius:2px; font-family:\'JetBrains Mono\',monospace;'
                f' font-size:0.75rem;"><b>{t["name"]}</b> &middot; {t["category"]}</span>'
            )
        st.markdown(pills, unsafe_allow_html=True)

    # DNS
    dns = enrich.get("dns", {}) or {}
    if dns and not dns.get("error"):
        st.markdown("<div style='height:14px'></div>", unsafe_allow_html=True)
        section_header("DNS records")
        for rtype in ("A", "AAAA", "MX", "NS", "TXT"):
            records = dns.get(rtype, [])
            if records:
                readout(rtype, ", ".join(str(r)[:80] for r in records[:5]))

    # SSL
    ssl_info = enrich.get("ssl", {}) or {}
    if ssl_info and ssl_info.get("has_ssl"):
        st.markdown("<div style='height:14px'></div>", unsafe_allow_html=True)
        section_header("SSL certificate")
        readout("Issuer",       ssl_info.get("issuer") or "—")
        readout("Subject",      ssl_info.get("subject") or "—")
        readout("Valid from",   ssl_info.get("valid_from") or "—")
        readout("Valid to",     ssl_info.get("valid_to") or "—")
        days_left = ssl_info.get("days_left")
        if days_left is not None:
            readout("Days remaining", str(days_left),
                    tone="green" if days_left > 30 else "red")
        sans = ssl_info.get("sans", [])
        if sans:
            readout("SANs (covered domains)", ", ".join(sans[:8]))

    # WHOIS
    whois = enrich.get("whois", {}) or {}
    if whois and not whois.get("error"):
        st.markdown("<div style='height:14px'></div>", unsafe_allow_html=True)
        section_header("WHOIS registration")
        readout("Registrar",   str(whois.get("registrar")   or "—"))
        readout("Created",     str(whois.get("creation_date") or "—"))
        readout("Expires",     str(whois.get("expiry_date") or "—"))
        if whois.get("age_days") is not None:
            yrs = whois["age_days"] / 365
            readout("Age", f'{whois["age_days"]} days ({yrs:.1f} years)',
                    tone="green" if yrs > 2 else "amber")
        if whois.get("country"): readout("Country",       str(whois["country"]))
        if whois.get("org"):     readout("Organization",  str(whois["org"]))

    # GitHub mentions
    gh = enrich.get("github", {}) or {}
    if gh.get("total_count", 0) > 0:
        st.markdown("<div style='height:14px'></div>", unsafe_allow_html=True)
        section_header("GitHub mentions", f"{gh['total_count']} HITS")
        for repo in gh.get("top_repos", []):
            st.markdown(
                f'<div style="background:#FFFFFF; border:1px solid #E2E8F0; padding:10px 14px; border-left:3px solid #2563EB; margin-bottom:6px;">'
                f'<div style="display:flex; justify-content:space-between;">'
                f'<a href="{repo["url"]}" target="_blank" style="color:#2563EB; font-family:\'JetBrains Mono\',monospace; font-size:0.82rem; text-decoration:none;">{repo["name"]}</a>'
                f'<span style="color:#94A3B8; font-size:0.7rem;">★ {repo.get("stars") or 0}</span>'
                f'</div>'
                f'<div style="color:#334155; font-size:0.72rem; margin-top:4px;">{repo.get("description","")}</div>'
                f'<div style="color:#64748B; font-size:0.68rem; margin-top:2px; font-family:monospace;">{repo.get("file","")}</div>'
                f'</div>', unsafe_allow_html=True,
            )

    # Wayback
    wb = enrich.get("wayback", {}) or {}
    if wb and not wb.get("error") and wb.get("recent_samples"):
        st.markdown("<div style='height:14px'></div>", unsafe_allow_html=True)
        section_header("Wayback Machine history", f"{len(wb['recent_samples'])} RECENT")
        for snap in wb["recent_samples"]:
            st.markdown(
                f'<div style="font-family:\'JetBrains Mono\',monospace; font-size:0.76rem; padding:4px 0; border-bottom:1px solid rgba(15,23,42,0.06);">'
                f'<span style="color:#64748B;">{snap["timestamp"]}</span> &nbsp;&nbsp; '
                f'<a href="{snap["snapshot"]}" target="_blank" style="color:#2563EB;">view snapshot →</a>'
                f'</div>', unsafe_allow_html=True,
            )

    # SEO artefacts
    seo = enrich.get("seo", {}) or {}
    if seo:
        st.markdown("<div style='height:14px'></div>", unsafe_allow_html=True)
        section_header("SEO artefacts")
        readout("robots.txt present",
                "yes" if seo.get("robots_txt", {}).get("exists") else "no",
                tone="green" if seo.get("robots_txt", {}).get("exists") else "")
        readout("sitemap.xml present",
                "yes" if seo.get("sitemap", {}).get("exists") else "no",
                tone="green" if seo.get("sitemap", {}).get("exists") else "")
        if seo.get("robots_txt", {}).get("snippet"):
            with st.expander("robots.txt preview"):
                st.code(seo["robots_txt"]["snippet"], language="text")


def _render_evidence_tab(case: dict):
    st.markdown("**Raw response data from each threat-intel source.**")
    st.markdown("<div style='height:4px'></div>", unsafe_allow_html=True)
    for src, r in sorted(case["per_source"].items()):
        if r.get("available") and r.get("detail"):
            with st.expander(f"{src.upper().replace('_', ' ')} — raw"):
                st.json(r["detail"])


def _render_timeline_tab(case: dict):
    for event in case["timeline"]:
        ts     = event.get("ts", "")[-13:-1]
        source = event.get("source", "—")
        ev     = event.get("event", "")
        score  = event.get("score")
        ms     = event.get("ms")
        tail = []
        if event.get("verdict"): tail.append(f'verdict={event["verdict"]}')
        if score is not None: tail.append(f"score={score}")
        if ms is not None: tail.append(f"{ms:.0f}ms")
        tail_txt = " · ".join(tail)
        st.markdown(
            f'<div style="font-family:\'JetBrains Mono\',monospace; font-size:0.74rem;'
            f' padding: 4px 0; border-bottom: 1px solid rgba(15,23,42,0.06);">'
            f'<span style="color:#64748B;">{ts}</span>&nbsp;&nbsp;'
            f'<span style="color:#2563EB; min-width:90px; display:inline-block;">{source.upper()}</span>&nbsp;&nbsp;'
            f'<span style="color:#0F172A;">{ev}</span>&nbsp;&nbsp;'
            f'<span style="color:#94A3B8;">{tail_txt}</span>'
            f'</div>', unsafe_allow_html=True,
        )


# ══════════════════════════════════════════════════════════════════
# AI ANALYST TAB (Phase 2b) — natural-language verdict narrative
# ══════════════════════════════════════════════════════════════════
def _render_ai_analyst_tab(case: dict):
    """Plain-English verdict narrative synthesised from all scan inputs."""
    verdict = case.get("fused_verdict", "UNKNOWN")
    score   = case.get("fused_score", 0.0)
    target  = case.get("target", "")

    # Build narrative deterministically from real signals — no mock AI calls
    narrative, evidence, recs, analyst_note = _synthesize_analyst_report(case)

    # ── Big verdict header ────────────────────────────────────────
    verdict_emoji = {
        "MALICIOUS":   "🔴",
        "DEAD_DOMAIN": "🔴",
        "SUSPICIOUS":  "🟡",
        "CLEAN":       "🟢",
        "UNKNOWN":     "⚪",
    }.get(verdict, "⚪")

    # ── Big verdict header — Phase 3f white native premium ───────
    verdict_meta = {
        "MALICIOUS":   ("#DC2626", "#FEF2F2", "✕", "Threat Detected"),
        "DEAD_DOMAIN": ("#DC2626", "#FEF2F2", "✕", "Domain Dead"),
        "SUSPICIOUS":  ("#CA8A04", "#FFFBEB", "⚠", "Caution Advised"),
        "CLEAN":       ("#16A34A", "#F0FDF4", "✓", "All Clear"),
        "UNKNOWN":     ("#64748B", "#F8FAFC", "?", "Unknown"),
    }
    v_color, v_tint, v_glyph, v_label = verdict_meta.get(
        verdict, ("#64748B", "#F8FAFC", "?", "Unknown")
    )

    st.markdown(
        f'<div style="background:{v_tint}; padding:20px 24px; border:1px solid #E2E8F0; '
        f'border-left:4px solid {v_color}; border-radius:10px; margin-bottom:16px; '
        f'box-shadow:0 1px 2px rgba(15,23,42,0.04); '
        f'animation: mc-tab-content-in 360ms cubic-bezier(0.4,0,0.2,1) backwards;">'
        f'<div style="display:flex; align-items:center; gap:16px; margin-bottom:12px;">'
        f'<div style="flex-shrink:0; width:46px; height:46px; background:{v_color}; '
        f'color:#FFFFFF; border-radius:50%; display:flex; align-items:center; '
        f'justify-content:center; font-size:1.6rem; font-weight:700; '
        f'font-family:Inter,sans-serif;">{v_glyph}</div>'
        f'<div style="flex:1;">'
        f'<div style="font-family:\'Inter\',sans-serif; font-size:0.6875rem; '
        f'letter-spacing:0.08em; color:#64748B; text-transform:uppercase; '
        f'font-weight:600;">AI Analyst verdict</div>'
        f'<div style="font-family:\'Inter\',sans-serif; font-size:1.5rem; '
        f'font-weight:700; color:{v_color}; line-height:1.2; margin-top:2px; '
        f'letter-spacing:-0.02em;">{verdict} <span style="font-size:1rem; '
        f'color:#475569; font-weight:500;">· risk {score:.1f}/10</span></div>'
        f'<div style="font-family:\'Inter\',sans-serif; font-size:0.78rem; '
        f'color:{v_color}; font-weight:600; margin-top:4px;">{v_label}</div>'
        f'</div></div>'
        f'<div style="font-family:\'Inter\',sans-serif; color:#334155; '
        f'font-size:0.9375rem; line-height:1.65; padding-top:12px; '
        f'border-top:1px solid rgba(15,23,42,0.08);">{narrative}</div>'
        f'</div>',
        unsafe_allow_html=True,
    )

    # ── Verdict-adjustment reasons (v24) ──────────────────────────
    # Show users WHY the verdict was raised above the source consensus
    # (e.g. 108 CVEs from Shodan, hygiene grade D, no SSL).
    _vr = case.get("verdict_reasons") or []
    _pre = case.get("verdict_pre_adjust") or {}
    if _vr:
        _pre_v = (_pre.get("verdict") or "").upper()
        _pre_s = _pre.get("score", 0)
        _shift_arrow = "▲" if score > _pre_s else ("▼" if score < _pre_s else "•")
        _shift_text  = (f"verdict raised from <b>{_pre_v}</b> ({_pre_s:.1f}) → "
                        f"<b>{verdict}</b> ({score:.1f})"
                        if _pre_v and _pre_v != verdict else
                        f"score adjusted from {_pre_s:.1f} → {score:.1f}")
        _chips_html = "".join(
            f'<span style="display:inline-flex;align-items:center;gap:6px;'
            f'background:#FEF2F2;border:1px solid #FECACA;color:#991B1B;'
            f'font-family:Inter,sans-serif;font-size:0.78rem;font-weight:600;'
            f'padding:5px 10px;border-radius:999px;margin:3px 4px 3px 0;">'
            f'<svg width="11" height="11" viewBox="0 0 24 24" fill="none" '
            f'stroke="#DC2626" stroke-width="2.5" stroke-linecap="round">'
            f'<polyline points="6 9 12 15 18 9"/></svg>{r}</span>'
            for r in _vr
        )
        st.markdown(
            f'<div style="background:#FFFBEB;border:1px solid #FDE68A;'
            f'border-left:4px solid #F59E0B;border-radius:10px;'
            f'padding:14px 18px;margin-bottom:16px;'
            f'animation: mc-tab-content-in 380ms cubic-bezier(0.4,0,0.2,1) backwards;">'
            f'<div style="display:flex;align-items:center;justify-content:space-between;'
            f'gap:10px;margin-bottom:8px;">'
            f'<div style="display:flex;align-items:center;gap:8px;'
            f'font-family:\'Inter\',sans-serif;font-size:0.74rem;font-weight:700;'
            f'color:#92400E;letter-spacing:0.06em;text-transform:uppercase;">'
            f'<svg width="14" height="14" viewBox="0 0 24 24" fill="none" '
            f'stroke="#F59E0B" stroke-width="2" stroke-linecap="round">'
            f'<path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/>'
            f'<line x1="12" y1="9" x2="12" y2="13"/>'
            f'<line x1="12" y1="17" x2="12.01" y2="17"/></svg>'
            f'Verdict raised by reality-check fusion</div>'
            f'<span style="font-family:JetBrains Mono,monospace;font-size:0.7rem;'
            f'color:#92400E;font-weight:700;letter-spacing:0.06em;">'
            f'{_shift_arrow} {len(_vr)} signal{"s" if len(_vr)!=1 else ""}</span>'
            f'</div>'
            f'<div style="font-family:Inter,sans-serif;font-size:0.82rem;'
            f'color:#92400E;margin-bottom:8px;line-height:1.5;">{_shift_text}</div>'
            f'<div>{_chips_html}</div>'
            f'</div>',
            unsafe_allow_html=True,
        )

    # ── BROWSER WARNING PREVIEW (v24) ─────────────────────────────
    # Shows what Chrome / Edge / Safari WOULD display to the user
    # if they tried to visit this URL — based on Google Safe Browsing
    # + PhishTank + URLhaus + 10+ heuristic signals.
    _bw = case.get("browser_warning") or {}
    if _bw:
        _will_warn   = _bw.get("will_warn", False)
        _bw_type     = _bw.get("warning_type") or ""
        _bw_label    = _bw.get("browser_label", "—")
        _bw_conf     = _bw.get("confidence", 0) or 0
        _bw_signals  = _bw.get("signals", []) or []
        _chrome_t    = _bw.get("chrome_title", "—")
        _chrome_b    = _bw.get("chrome_body", "—")

        if _will_warn:
            # ── BLOCK-page mockup (Chrome red warning aesthetic) ──
            _icon_color = "#FFFFFF"
            _bg_color   = "#A50E0E"  # Chrome's actual warning red
            _accent     = "#FECACA"

            # Type-specific icon
            if _bw_type == "malware":
                _icon_svg = ('<svg width="48" height="48" viewBox="0 0 24 24" fill="none" '
                             'stroke="#FFFFFF" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
                             '<path d="M19 11h2m-1 -1v2"/><circle cx="12" cy="12" r="9"/>'
                             '<path d="M8 9h8v6H8z"/><circle cx="10" cy="11" r="1" fill="#FFF"/>'
                             '<circle cx="14" cy="11" r="1" fill="#FFF"/></svg>')
            elif _bw_type in ("phishing", "deceptive"):
                _icon_svg = ('<svg width="48" height="48" viewBox="0 0 24 24" fill="none" '
                             'stroke="#FFFFFF" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
                             '<polygon points="12 2 22 22 2 22 12 2"/>'
                             '<line x1="12" y1="9" x2="12" y2="14"/>'
                             '<circle cx="12" cy="18" r="0.8" fill="#FFF"/></svg>')
            else:
                _icon_svg = ('<svg width="48" height="48" viewBox="0 0 24 24" fill="none" '
                             'stroke="#FFFFFF" stroke-width="2" stroke-linecap="round">'
                             '<circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>')

            # Build signals list HTML
            _sig_html = ""
            for s in _bw_signals[:8]:
                _sig_html += (
                    f'<li style="margin-bottom:6px;font-family:Inter,sans-serif;'
                    f'font-size:0.78rem;color:#7F1D1D;line-height:1.5;'
                    f'list-style:none;padding-left:18px;position:relative;">'
                    f'<span style="position:absolute;left:0;top:1px;color:#DC2626;'
                    f'font-weight:700;">▸</span>{s}</li>'
                )

            st.markdown(
                f'<div style="background:linear-gradient(180deg,{_bg_color} 0%,#7A0808 100%);'
                f'border-radius:12px;overflow:hidden;margin-bottom:18px;'
                f'box-shadow:0 16px 40px -12px rgba(165,14,14,0.4);'
                f'animation: mc-tab-content-in 420ms cubic-bezier(0.4,0,0.2,1) backwards;">'
                # Chrome-style address bar mock
                f'<div style="background:#7A0808;padding:8px 16px;'
                f'border-bottom:1px solid rgba(255,255,255,0.15);'
                f'display:flex;align-items:center;gap:10px;'
                f'font-family:\'Inter\',sans-serif;font-size:0.72rem;color:#FECACA;">'
                f'<svg width="13" height="13" viewBox="0 0 24 24" fill="none" '
                f'stroke="#FECACA" stroke-width="2" stroke-linecap="round">'
                f'<rect x="3" y="11" width="18" height="11" rx="2"/>'
                f'<path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>'
                f'<span style="font-family:JetBrains Mono,monospace;letter-spacing:0.04em;">'
                f'⚠ Not secure  ·  {(target or "")[:80]}</span>'
                f'<span style="margin-left:auto;font-family:JetBrains Mono,monospace;'
                f'font-size:0.6rem;letter-spacing:0.16em;color:#FECACA;opacity:0.7;">'
                f'BROWSER WARNING PREVIEW</span>'
                f'</div>'
                # Warning body
                f'<div style="padding:28px 32px;color:#FFFFFF;">'
                f'<div style="display:flex;align-items:flex-start;gap:18px;margin-bottom:16px;">'
                f'<div style="flex-shrink:0;margin-top:4px;">{_icon_svg}</div>'
                f'<div style="flex:1;">'
                f'<div style="font-family:\'Inter\',sans-serif;font-size:1.65rem;'
                f'font-weight:700;color:#FFFFFF;letter-spacing:-0.01em;line-height:1.2;">'
                f'{_chrome_t}</div>'
                f'<div style="font-family:\'Inter\',sans-serif;font-size:0.9rem;'
                f'color:{_accent};margin-top:10px;line-height:1.6;font-weight:400;">'
                f'{_chrome_b}</div>'
                f'</div></div>'
                # Confidence + button mocks
                f'<div style="display:flex;align-items:center;justify-content:space-between;'
                f'gap:14px;padding:12px 14px;background:rgba(0,0,0,0.2);border-radius:8px;'
                f'margin-bottom:18px;">'
                f'<div style="font-family:JetBrains Mono,monospace;font-size:0.7rem;'
                f'color:{_accent};letter-spacing:0.1em;">'
                f'DETECTION CONFIDENCE: <b style="color:#FFFFFF;">{_bw_conf*100:.0f}%</b>'
                f'  ·  TYPE: <b style="color:#FFFFFF;">{(_bw_type or "—").upper()}</b>'
                f'</div>'
                f'<div style="display:flex;gap:8px;">'
                f'<span style="background:rgba(255,255,255,0.1);color:#FECACA;'
                f'padding:6px 12px;border-radius:6px;font-family:Inter,sans-serif;'
                f'font-size:0.74rem;font-weight:500;">Details</span>'
                f'<span style="background:#FFFFFF;color:{_bg_color};'
                f'padding:6px 14px;border-radius:6px;font-family:Inter,sans-serif;'
                f'font-size:0.74rem;font-weight:600;">Back to safety</span>'
                f'</div></div>'
                # Signals list
                f'<div style="background:#FFFFFF;border-radius:8px;padding:14px 18px;'
                f'box-shadow:0 1px 2px rgba(0,0,0,0.08);">'
                f'<div style="font-family:\'Inter\',sans-serif;font-size:0.7rem;'
                f'letter-spacing:0.1em;color:#7F1D1D;font-weight:700;text-transform:uppercase;'
                f'margin-bottom:10px;display:flex;align-items:center;gap:7px;">'
                f'<svg width="14" height="14" viewBox="0 0 24 24" fill="none" '
                f'stroke="#A50E0E" stroke-width="2" stroke-linecap="round">'
                f'<circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/>'
                f'<line x1="12" y1="16" x2="12.01" y2="16"/></svg>'
                f'Why we predict a browser warning ({len(_bw_signals)} signal{"s" if len(_bw_signals)!=1 else ""})'
                f'</div>'
                f'<ul style="margin:0;padding:0;">{_sig_html}</ul>'
                f'</div>'
                f'</div></div>',
                unsafe_allow_html=True,
            )
        else:
            # ── GREEN "browser safe" panel ──
            _conf_pct = int(_bw_conf * 100)
            _sig_html2 = ""
            if _bw_signals:
                for s in _bw_signals[:4]:
                    _sig_html2 += (
                        f'<li style="margin-bottom:4px;font-family:Inter,sans-serif;'
                        f'font-size:0.78rem;color:#166534;line-height:1.5;'
                        f'list-style:none;padding-left:16px;position:relative;">'
                        f'<span style="position:absolute;left:0;top:1px;color:#15803D;">·</span>'
                        f'{s}</li>'
                    )
            st.markdown(
                f'<div style="background:linear-gradient(180deg,#F0FDF4 0%,#DCFCE7 100%);'
                f'border:1px solid #BBF7D0;border-left:4px solid #16A34A;border-radius:10px;'
                f'padding:16px 20px;margin-bottom:16px;'
                f'animation: mc-tab-content-in 380ms cubic-bezier(0.4,0,0.2,1) backwards;">'
                f'<div style="display:flex;align-items:center;gap:14px;margin-bottom:'
                f'{8 if _sig_html2 else 0}px;">'
                f'<div style="flex-shrink:0;width:40px;height:40px;background:#16A34A;'
                f'border-radius:50%;display:flex;align-items:center;justify-content:center;">'
                f'<svg width="22" height="22" viewBox="0 0 24 24" fill="none" '
                f'stroke="#FFFFFF" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">'
                f'<path d="M9 12l2 2 4-4"/><circle cx="12" cy="12" r="10"/></svg>'
                f'</div>'
                f'<div style="flex:1;">'
                f'<div style="font-family:\'Inter\',sans-serif;font-size:0.66rem;'
                f'letter-spacing:0.1em;color:#15803D;font-weight:700;text-transform:uppercase;">'
                f'Browser warning prediction</div>'
                f'<div style="font-family:\'Inter\',sans-serif;font-size:1.05rem;'
                f'font-weight:700;color:#14532D;margin-top:2px;">'
                f'✓ No browser block expected '
                f'<span style="font-size:0.78rem;color:#166534;font-weight:500;">'
                f'· Chrome / Edge / Safari would <b>not</b> warn users</span></div>'
                f'</div>'
                f'<div style="font-family:JetBrains Mono,monospace;font-size:0.7rem;'
                f'color:#15803D;font-weight:700;background:#FFFFFF;border:1px solid #BBF7D0;'
                f'padding:5px 11px;border-radius:6px;letter-spacing:0.08em;">'
                f'RISK {_conf_pct}%</div></div>'
                + (f'<ul style="margin:6px 0 0 0;padding:0;'
                   f'border-top:1px dashed rgba(22,163,74,0.2);padding-top:8px;">'
                   f'{_sig_html2}</ul>' if _sig_html2 else "")
                + '</div>',
                unsafe_allow_html=True,
            )

    # ── Evidence summary ──────────────────────────────────────────
    st.markdown(
        '<div style="font-family:Inter,sans-serif; font-size:0.8125rem; font-weight:700;'
        ' letter-spacing:0.08em; color:#0F172A; text-transform:uppercase; margin-bottom:10px;'
        ' display:flex; align-items:center; gap:8px;">'
        '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#2563EB"'
        ' stroke-width="2" stroke-linecap="round"><path d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2'
        ' 2 0 002-2V7a2 2 0 00-2-2h-2"/><rect x="9" y="3" width="6" height="4" rx="1"/></svg>'
        'Evidence <span style="font-weight:400; color:#64748B; font-size:0.7rem;'
        ' letter-spacing:0.04em;">WHAT WE FOUND</span></div>',
        unsafe_allow_html=True,
    )
    if evidence:
        for idx, item in enumerate(evidence):
            delay = idx * 40
            st.markdown(
                f'<div style="background:#FFFFFF; padding:10px 14px; border:1px solid #E2E8F0;'
                f' border-left:3px solid #DC2626; border-radius:8px; margin-bottom:6px;'
                f' font-family:Inter,sans-serif; font-size:0.875rem; color:#334155;'
                f' line-height:1.5; animation:mc-row-in 260ms {delay}ms cubic-bezier(0.4,0,0.2,1) backwards;">'
                f'<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#DC2626"'
                f' stroke-width="2" stroke-linecap="round" style="vertical-align:-2px; margin-right:6px;">'
                f'<circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/>'
                f'<line x1="9" y1="9" x2="15" y2="15"/></svg>{item}</div>',
                unsafe_allow_html=True,
            )
    else:
        st.markdown(
            '<div style="background:#F0FDF4; padding:14px 18px; border:1px solid #BBF7D0;'
            ' border-left:3px solid #16A34A; border-radius:8px; font-family:Inter,sans-serif;'
            ' font-size:0.875rem; color:#166534; line-height:1.5;'
            ' animation:mc-row-in 260ms cubic-bezier(0.4,0,0.2,1) backwards;">'
            '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#16A34A"'
            ' stroke-width="2" stroke-linecap="round" style="vertical-align:-3px; margin-right:6px;">'
            '<path d="M22 11.08V12a10 10 0 11-5.93-9.14"/>'
            '<polyline points="22 4 12 14.01 9 11.01"/></svg>'
            'No anomalous evidence found. All indicators nominal.</div>',
            unsafe_allow_html=True,
        )

    # ── Actionable intelligence ───────────────────────────────────
    st.markdown("<div style='height:14px'></div>", unsafe_allow_html=True)
    st.markdown(
        '<div style="font-family:Inter,sans-serif; font-size:0.8125rem; font-weight:700;'
        ' letter-spacing:0.08em; color:#0F172A; text-transform:uppercase; margin-bottom:10px;'
        ' display:flex; align-items:center; gap:8px;">'
        '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#2563EB"'
        ' stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="10"/>'
        '<line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>'
        'Actionable intelligence <span style="font-weight:400; color:#64748B; font-size:0.7rem;'
        ' letter-spacing:0.04em;">RECOMMENDATIONS</span></div>',
        unsafe_allow_html=True,
    )
    for idx, r in enumerate(recs):
        delay = idx * 50
        # Determine icon + color based on content
        if "✅" in r or "safe" in r.lower() or "no threat" in r.lower():
            ic_color, border_color, icon_path = "#16A34A", "#16A34A", '<polyline points="22 4 12 14.01 9 11.01"/><path d="M22 11.08V12a10 10 0 11-5.93-9.14"/>'
        elif "⚠" in r or "consider" in r.lower() or "improve" in r.lower() or "hygiene" in r.lower():
            ic_color, border_color, icon_path = "#CA8A04", "#CA8A04", '<path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>'
        else:
            ic_color, border_color, icon_path = "#2563EB", "#2563EB", '<circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/>'
        clean_r = r.replace("✅ ", "").replace("⚠ ", "").replace("* ", "")
        st.markdown(
            f'<div style="background:#FFFFFF; padding:12px 16px; border:1px solid #E2E8F0;'
            f' border-left:3px solid {border_color}; border-radius:8px; margin-bottom:8px;'
            f' font-family:Inter,sans-serif; font-size:0.875rem; color:#334155;'
            f' line-height:1.55; animation:mc-row-in 260ms {delay}ms cubic-bezier(0.4,0,0.2,1) backwards;">'
            f'<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="{ic_color}"'
            f' stroke-width="2" stroke-linecap="round" style="vertical-align:-3px; margin-right:8px;">'
            f'{icon_path}</svg>{clean_r}</div>',
            unsafe_allow_html=True,
        )

    # ── Analyst note ──────────────────────────────────────────────
    st.markdown("<div style='height:10px'></div>", unsafe_allow_html=True)
    st.markdown(
        f'<div style="background:#EFF6FF; padding:14px 18px; '
        f'border:1px solid #DBEAFE; border-left:3px solid #2563EB; '
        f'border-radius:8px; margin-top:10px; font-family:Inter,sans-serif; '
        f'font-size:0.875rem; color:#334155; line-height:1.55;">'
        f'<svg width="16" height="16" viewBox="0 0 24 24" fill="none" '
        f'stroke="#2563EB" stroke-width="2" stroke-linecap="round" '
        f'stroke-linejoin="round" style="vertical-align:-3px; margin-right:6px;">'
        f'<path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/>'
        f'<path d="M14 2v6h6M16 13H8M16 17H8M10 9H8"/></svg>'
        f'<b style="color:#1E40AF;">Analyst note:</b> {analyst_note}'
        f'</div>',
        unsafe_allow_html=True,
    )

    # ══ CHECKPHISH-STYLE VISUAL EVIDENCE (Phase 2c) ══════════════
    st.markdown("<div style='height:18px'></div>", unsafe_allow_html=True)
    _render_visual_evidence_panel(case)


def _render_visual_evidence_panel(case: dict):
    """
    Visual evidence panel — proper aligned boxes for:
    1. Hosting & infrastructure cards (4-column grid)
    2. Screenshot (left) + Geo map (right) side by side
    3. Threat intelligence cross-reference grid
    """
    enrich    = case.get("enrichment", {}) or {}
    per_src   = case.get("per_source", {})
    target    = case.get("target", "")
    target_ip = case.get("target_ip", "")

    geo      = enrich.get("geo", {}) or {}
    whois    = enrich.get("whois", {}) or {}
    ssl_info = enrich.get("ssl", {}) or {}
    http     = enrich.get("http", {}) or {}

    flag = _country_flag_emoji(geo.get("country_code", ""))
    city = geo.get("city", "")
    ctry = geo.get("country", "Unknown")
    isp  = geo.get("isp") or geo.get("org") or "Unknown"
    tld  = _extract_tld(target) or "—"
    title = (http.get("page_title") or "—")[:45]
    ssl_days = ssl_info.get("days_left")
    ssl_ok   = ssl_info.get("has_ssl", False)

    # ── Section header ────────────────────────────────────────────
    st.markdown("""
<div style="font-family:Inter;font-size:0.7rem;font-weight:700;letter-spacing:0.1em;
  color:#0F172A;text-transform:uppercase;margin-bottom:10px;
  display:flex;align-items:center;gap:8px;">
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#2563EB"
    stroke-width="2" stroke-linecap="round"><rect x="2" y="3" width="20" height="14" rx="2"/>
    <path d="M8 21h8M12 17v4"/></svg>
  Hosting &amp; Infrastructure</div>""", unsafe_allow_html=True)

    # ── 4-column hosting cards — equal height via grid ────────────
    ssl_color = "#16A34A" if ssl_ok and ssl_days and ssl_days > 30 else "#F59E0B" if ssl_ok else "#DC2626"
    ssl_label = f"{ssl_days}d left" if ssl_days else ("Active" if ssl_ok else "No SSL")

    st.markdown(f"""
<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:18px;">
  <!-- Brand / Title -->
  <div style="background:#FFFFFF;border:1px solid #E2E8F0;border-radius:10px;
    padding:14px 16px;border-top:3px solid #2563EB;">
    <div style="font-family:Inter;font-size:0.6rem;font-weight:700;
      letter-spacing:0.12em;color:#94A3B8;text-transform:uppercase;margin-bottom:6px;">
      Page Title</div>
    <div style="font-family:Inter;font-size:0.85rem;font-weight:600;
      color:#0F172A;line-height:1.35;">{title}</div>
  </div>
  <!-- TLD + Domain -->
  <div style="background:#FFFFFF;border:1px solid #E2E8F0;border-radius:10px;
    padding:14px 16px;border-top:3px solid #6366F1;">
    <div style="font-family:Inter;font-size:0.6rem;font-weight:700;
      letter-spacing:0.12em;color:#94A3B8;text-transform:uppercase;margin-bottom:6px;">
      Domain / TLD</div>
    <div style="font-family:JetBrains Mono;font-size:0.85rem;font-weight:700;
      color:#0F172A;">{tld}</div>
  </div>
  <!-- Location -->
  <div style="background:#FFFFFF;border:1px solid #E2E8F0;border-radius:10px;
    padding:14px 16px;border-top:3px solid #0EA5E9;">
    <div style="font-family:Inter;font-size:0.6rem;font-weight:700;
      letter-spacing:0.12em;color:#94A3B8;text-transform:uppercase;margin-bottom:6px;">
      Location</div>
    <div style="font-family:Inter;font-size:0.88rem;font-weight:600;color:#0F172A;">
      {flag}&nbsp;{ctry}</div>
    <div style="font-family:JetBrains Mono;font-size:0.7rem;color:#64748B;margin-top:3px;">
      {city}</div>
  </div>
  <!-- Hosting + SSL -->
  <div style="background:#FFFFFF;border:1px solid #E2E8F0;border-radius:10px;
    padding:14px 16px;border-top:3px solid #10B981;">
    <div style="font-family:Inter;font-size:0.6rem;font-weight:700;
      letter-spacing:0.12em;color:#94A3B8;text-transform:uppercase;margin-bottom:6px;">
      Hosting / SSL</div>
    <div style="font-family:Inter;font-size:0.82rem;font-weight:600;
      color:#0F172A;line-height:1.35;">{isp[:32]}</div>
    <div style="display:inline-flex;align-items:center;gap:4px;margin-top:5px;
      background:rgba(0,0,0,0.04);border:1px solid rgba(0,0,0,0.1);border-radius:5px;
      padding:2px 7px;font-family:JetBrains Mono;font-size:0.65rem;
      font-weight:700;color:{ssl_color};">
      SSL: {ssl_label}</div>
  </div>
</div>""", unsafe_allow_html=True)

    # ── Two-column: screenshot + geo map ──────────────────────────
    col1, col2 = st.columns([3, 2])

    with col1:
        st.markdown(
            "<div style='font-family:Inter,sans-serif; font-size:0.875rem; "
            "font-weight:600; color:#0F172A; margin-bottom:6px;'>"
            "📸 Sandbox screenshot</div>",
            unsafe_allow_html=True,
        )
        urlscan_detail = per_src.get("urlscan", {}).get("detail", {}) or {}
        screenshot = urlscan_detail.get("screenshot")

        # Phase 3f: try Selenium fallback when URLScan returned nothing
        if not screenshot:
            try:
                from core.screenshot_capture import capture_screenshot
                local_shot = capture_screenshot(target, timeout_s=15)
                if local_shot:
                    screenshot = local_shot
            except Exception:
                pass

        # Build screenshot URL from UUID (works for existing + submitted scans)
        uuid = urlscan_detail.get("uuid", "")
        if not screenshot and uuid:
            screenshot = f"https://urlscan.io/screenshots/{uuid}.png"

        report_url = urlscan_detail.get("report_url", "")
        if not report_url and uuid:
            report_url = f"https://urlscan.io/result/{uuid}/"

        st.markdown("""
<div style="font-family:Inter,sans-serif;font-size:0.82rem;font-weight:600;
  color:#0F172A;margin-bottom:8px;display:flex;align-items:center;gap:6px;">
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#2563EB"
    stroke-width="2" stroke-linecap="round"><rect x="3" y="4" width="18" height="14" rx="2"/>
    <circle cx="12" cy="11" r="3"/></svg>
  Sandbox Screenshot
  <span style="font-weight:400;font-size:0.72rem;color:#94A3B8;margin-left:4px;">
    via URLScan.io</span>
</div>""", unsafe_allow_html=True)

        if screenshot and uuid:
            # Verify screenshot is accessible
            try:
                import requests as _rq
                chk = _rq.head(screenshot, timeout=4, allow_redirects=True)
                shot_ok = chk.status_code == 200
            except Exception:
                shot_ok = False

            if shot_ok:
                st.image(screenshot,
                         caption=f"URLScan sandbox capture · {target[:50]}",
                         use_container_width=True)
                if report_url:
                    st.markdown(
                        f"<div style='margin-top:4px;font-size:0.72rem;'>"
                        f"<a href='{report_url}' target='_blank'"
                        f" style='color:#2563EB;font-family:JetBrains Mono;'>"
                        f"View full URLScan report &rarr;</a></div>",
                        unsafe_allow_html=True,
                    )
            else:
                # Screenshot still processing — show link
                st.markdown(f"""
<div style="background:#F0F9FF;border:1px solid #BAE6FD;border-radius:10px;
  padding:20px 18px;text-align:center;">
  <div style="font-size:1.8rem;margin-bottom:8px;">🔍</div>
  <div style="font-family:Inter,sans-serif;font-weight:600;color:#0369A1;
    font-size:0.9rem;">Screenshot generating...</div>
  <div style="font-family:Inter,sans-serif;font-size:0.75rem;color:#0284C7;
    margin-top:6px;">URLScan sandbox is rendering the page (~20-30s)</div>
  <div style="margin-top:12px;display:flex;flex-direction:column;gap:6px;">
    <a href="{screenshot}" target="_blank"
       style="background:#2563EB;color:#FFFFFF;padding:7px 16px;
              border-radius:7px;font-family:Inter;font-size:0.78rem;
              font-weight:600;text-decoration:none;display:inline-block;">
      View Screenshot &rarr;</a>
    {"" if not report_url else
     f'<a href="{report_url}" target="_blank" style="color:#2563EB;font-size:0.72rem;'
     f'font-family:JetBrains Mono;">Full URLScan Report &rarr;</a>'}
  </div>
</div>""", unsafe_allow_html=True)
        else:
            st.markdown(f"""
<div style="background:#F8FAFC;border:1px dashed #CBD5E1;border-radius:10px;
  padding:28px 18px;text-align:center;">
  <div style="font-size:1.8rem;margin-bottom:8px;">📷</div>
  <div style="font-family:Inter,sans-serif;font-weight:600;color:#475569;">
    Screenshot unavailable</div>
  <div style="font-family:Inter,sans-serif;font-size:0.72rem;color:#94A3B8;
    margin-top:4px;">URLScan did not return a scan result for this URL.</div>
  {"" if not target else
   f'<div style="margin-top:10px;"><a href="https://urlscan.io/search/#page.url%3A%22{target}%22"'
   f' target="_blank" style="color:#2563EB;font-size:0.72rem;">Search URLScan manually &rarr;</a></div>'}
</div>""", unsafe_allow_html=True)

    with col2:
        st.markdown("""
<div style="font-family:Inter;font-size:0.82rem;font-weight:600;
  color:#0F172A;margin-bottom:8px;display:flex;align-items:center;gap:6px;">
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#2563EB"
    stroke-width="2" stroke-linecap="round"><path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0118 0z"/>
    <circle cx="12" cy="10" r="3"/></svg>
  Geo Location</div>""", unsafe_allow_html=True)
        lat = geo.get("lat")
        lon = geo.get("lon")
        if lat is not None and lon is not None:
            city    = geo.get("city", "")
            country = geo.get("country", "")
            isp     = geo.get("isp") or geo.get("org") or "Unknown"
            disp_ip = target_ip or geo.get("ip", "")
            popup   = f"{disp_ip} · {city}, {country}"
            # Pure HTML Leaflet.js — zero Python deps, no DLL
            leaflet_html = f"""
<!DOCTYPE html><html>
<head>
<meta charset="utf-8"/>
<link rel="stylesheet"
      href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<style>
  html,body{{margin:0;padding:0;height:100%;}}
  #map{{height:270px;border-radius:10px;}}
</style>
</head>
<body>
<div id="map"></div>
<script>
var map = L.map('map',{{zoomControl:true,scrollWheelZoom:false}})
           .setView([{lat},{lon}],5);
L.tileLayer(
  'https://{{s}}.basemaps.cartocdn.com/light_all/{{z}}/{{x}}/{{y}}{{r}}.png',
  {{attribution:'CartoDB',maxZoom:18,subdomains:'abcd'}}
).addTo(map);
// Animated pulse ring
var pulse = L.circleMarker([{lat},{lon}],{{
  radius:18, color:'#2563EB', weight:2,
  fillColor:'#2563EB', fillOpacity:0.15
}}).addTo(map);
// Main dot
L.circleMarker([{lat},{lon}],{{
  radius:9, color:'#FFFFFF', weight:2.5,
  fillColor:'#2563EB', fillOpacity:0.95
}}).addTo(map).bindPopup('{popup}').openPopup();
</script>
</body></html>"""
            import streamlit.components.v1 as _comp
            _comp.html(leaflet_html, height=275)
            st.markdown(f"""
<div style="background:#F8FAFC;border:1px solid #E2E8F0;border-radius:8px;
  padding:8px 12px;margin-top:6px;font-family:JetBrains Mono,monospace;
  font-size:0.74rem;color:#475569;">
  <span style="color:#2563EB;font-weight:700;">{disp_ip}</span>
  &nbsp;&middot;&nbsp;{city+', ' if city else ''}{country}
  {('&nbsp;&middot;&nbsp;' + isp[:30]) if isp else ''}
</div>""", unsafe_allow_html=True)
        else:
            st.markdown(
                "<div style='background:#F8FAFC; padding:36px 18px; text-align:center; "
                "border:1px dashed #CBD5E1; border-radius:8px; color:#64748B; "
                "font-family:Inter,sans-serif;'>"
                "Location not found for this IP</div>",
                unsafe_allow_html=True,
            )

    # ── Threat Intelligence summary - Phase 3e premium grid ──────
    st.markdown("<div style='height:14px'></div>", unsafe_allow_html=True)
    section_header("Threat intelligence summary", "CROSS-REFERENCE")

    # Each row: (label, is_threat_present, icon_svg_path, description)
    is_phish = _has_past_phish(per_src)
    is_urlhaus = _in_urlhaus(per_src)
    is_c2 = _is_c2(per_src)
    is_tor = per_src.get("abuseipdb", {}).get("detail", {}).get("is_tor", False)
    is_young = (whois.get("age_days") or 9999) < 30
    has_ssl = ssl_info.get("has_ssl", False)
    has_kev = _has_kev(per_src)

    # SSL flipped: presence of SSL = good (green), missing SSL = bad
    rows = [
        ("Past phishing on host",  is_phish,
         "https://otx.alienvault.com/", "VirusTotal & OTX historical phish reports"),
        ("In URLhaus malware feed",  is_urlhaus,
         "https://urlhaus.abuse.ch/", "abuse.ch URLhaus active malware database"),
        ("Known C2 domain",          is_c2,
         "https://threatfox.abuse.ch/", "ThreatFox command-and-control identifiers"),
        ("TOR exit node",            is_tor,
         "https://www.torproject.org/", "Used to anonymize attacker traffic"),
        ("Domain age <30 days",      is_young,
         "", "Newly-registered domains are common in phishing campaigns"),
        ("Valid SSL certificate",    not has_ssl,    # invert: missing SSL = bad
         "", "TLS certificate present and not expired"),
        ("CISA KEV vulnerability",   has_kev,
         "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
         "Known exploited vulnerabilities catalog"),
    ]

    grid_html = '<div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap:10px; margin-top:8px;">'
    for label, is_threat, src_url, desc in rows:
        if label == "Valid SSL certificate":
            # Special handling: green when SSL valid, red when missing
            verdict_label = "VALID" if has_ssl else "MISSING"
            color = "#16A34A" if has_ssl else "#DC2626"
            tint  = "#F0FDF4" if has_ssl else "#FEF2F2"
            icon_path = ('<path d="M9 12l2 2 4-4M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>'
                         if has_ssl else
                         '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 9l6 6M15 9l-6 6"/>')
        else:
            verdict_label = "DETECTED" if is_threat else "CLEAR"
            color = "#DC2626" if is_threat else "#16A34A"
            tint  = "#FEF2F2" if is_threat else "#F0FDF4"
            icon_path = ('<circle cx="12" cy="12" r="10"/><path d="M15 9l-6 6M9 9l6 6"/>'
                         if is_threat else
                         '<path d="M9 12l2 2 4-4"/><circle cx="12" cy="12" r="10"/>')

        grid_html += (
            f'<div style="background:#FFFFFF; padding:14px 16px; border:1px solid #E2E8F0; '
            f'border-radius:8px; box-shadow:0 1px 2px rgba(15,23,42,0.04); '
            f'transition:all 180ms; display:flex; align-items:center; gap:14px;">'
            f'<div style="flex-shrink:0; width:40px; height:40px; background:{tint}; '
            f'border-radius:8px; display:flex; align-items:center; justify-content:center;">'
            f'<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="{color}" '
            f'stroke-width="2" stroke-linecap="round" stroke-linejoin="round">{icon_path}</svg>'
            f'</div>'
            f'<div style="flex:1; min-width:0;">'
            f'<div style="font-family:\'Inter\',sans-serif; font-size:0.875rem; '
            f'font-weight:600; color:#0F172A;">{label}</div>'
            f'<div style="font-family:\'Inter\',sans-serif; font-size:0.74rem; '
            f'color:#64748B; margin-top:2px; line-height:1.4;">{desc}</div>'
            f'</div>'
            f'<div style="flex-shrink:0; font-family:\'JetBrains Mono\',monospace; '
            f'font-size:0.7rem; font-weight:700; color:{color}; letter-spacing:0.06em; '
            f'background:{tint}; padding:5px 9px; border-radius:4px;">{verdict_label}</div>'
            f'</div>'
        )
    grid_html += '</div>'
    st.markdown(grid_html, unsafe_allow_html=True)


def _country_flag_emoji(code: str) -> str:
    """Convert ISO country code to flag emoji."""
    if not code or len(code) != 2:
        return ""
    OFFSET = ord("🇦") - ord("A")
    return "".join(chr(ord(c.upper()) + OFFSET) for c in code)


def _extract_tld(url: str) -> str:
    """Get last 2 dot-segments as TLD (handles co.in, com.br, etc.)."""
    from urllib.parse import urlparse
    host = urlparse(url).hostname or ""
    parts = host.split(".")
    if len(parts) < 2:
        return host
    if len(parts) >= 3 and parts[-2] in ("co", "com", "ac", "edu", "gov", "net", "org"):
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _bool_cell(b: bool) -> str:
    return "🔴 yes" if b else "🟢 no"


def _has_past_phish(per_src: dict) -> bool:
    return bool(per_src.get("phishtank", {}).get("detail", {}).get("in_database"))


def _in_urlhaus(per_src: dict) -> bool:
    d = per_src.get("urlhaus", {}).get("detail", {})
    return bool(d.get("url_status")) and d.get("url_status") != "—"


def _is_c2(per_src: dict) -> bool:
    d = per_src.get("threatfox", {}).get("detail", {})
    return d.get("matches", 0) > 0


def _has_kev(per_src: dict) -> bool:
    return bool(per_src.get("cisa_kev", {}).get("detail", {}).get("matches"))


def _synthesize_analyst_report(case: dict) -> tuple[str, list, list, str]:
    """
    Deterministic synthesiser — builds a human-readable report from real
    scan signals. NOT an LLM call; uses the actual fused evidence.
    Returns (narrative, evidence_list, recommendations_list, analyst_note)
    """
    verdict  = case.get("fused_verdict", "UNKNOWN")
    score    = case.get("fused_score", 0.0)
    target   = case.get("target", "")
    target_ip = case.get("target_ip") or "not resolved"
    per_src  = case.get("per_source", {})
    enrich   = case.get("enrichment", {}) or {}
    hygiene  = case.get("hygiene", {}) or {}
    ml       = case.get("ml", {}) or {}
    validation = case.get("validation", {}) or {}

    # Count verdicts per source
    malicious_srcs  = [s for s, r in per_src.items()
                       if r.get("verdict") == "MALICIOUS" and r.get("available")]
    suspicious_srcs = [s for s, r in per_src.items()
                       if r.get("verdict") == "SUSPICIOUS" and r.get("available")]
    clean_srcs      = [s for s, r in per_src.items()
                       if r.get("verdict") == "CLEAN" and r.get("available")]

    # Build narrative
    parts = []
    parts.append(f"The URL {target} resolved to <code>{target_ip}</code>.")

    if malicious_srcs:
        parts.append(
            f"<b>{len(malicious_srcs)} threat-intel source(s) flagged it as malicious:</b> "
            f"{', '.join(malicious_srcs)}."
        )
    if suspicious_srcs:
        parts.append(
            f"{len(suspicious_srcs)} source(s) reported suspicious activity: "
            f"{', '.join(suspicious_srcs)}."
        )
    if clean_srcs and not malicious_srcs:
        parts.append(
            f"{len(clean_srcs)} reputation source(s) returned clean results: "
            f"{', '.join(clean_srcs)}."
        )

    # ML signal
    if ml.get("label") and ml.get("label") != "error":
        conf = ml.get("confidence", 0) * 100
        parts.append(
            f"The ML classifier (Random Forest, 15 features) predicts "
            f"<b>{ml['label']}</b> with {conf:.0f}% confidence."
        )

    # Hygiene signal
    if hygiene.get("grade"):
        parts.append(
            f"Security hygiene grade: <b>{hygiene.get('grade')}</b> "
            f"({hygiene.get('score', 0)}/100)."
        )

    # Validation signals (typo-squat, homograph, DNS failure)
    if validation.get("risk_signals"):
        sig_short = [s.split(":")[0] for s in validation["risk_signals"][:3]]
        parts.append(
            f"Pre-scan validation raised: <b>{', '.join(sig_short)}</b>."
        )

    narrative = " ".join(parts)

    # ── Evidence list ─────────────────────────────────────────────
    evidence = []
    vt = per_src.get("virustotal", {}).get("detail", {})
    if vt.get("malicious"):
        total = vt.get("total_engines", 87)
        evidence.append(
            f"<b>{vt['malicious']}/{total}</b> antivirus engines flagged the target (VirusTotal)"
        )

    shodan     = per_src.get("shodan", {}).get("detail", {})
    shodan_src = per_src.get("shodan", {})
    if shodan.get("cve_count"):
        cve_note = ""
        # Distinguish shared hosting CVEs (server-level) from actual malicious IPs
        hostnames = shodan.get("hostnames", [])
        tags      = shodan.get("tags", [])
        is_hosting = any(p in h.lower() for p in
                         ("secureserver","godaddy","amazonaws","azure","akamai","fastly","cpanel")
                         for h in hostnames)
        if is_hosting or "cdn" in [t.lower() for t in tags]:
            cve_note = " (server-level CVEs on shared hosting — not specific to this website)"
        top_cves = ", ".join(shodan.get("cves", [])[:5])
        evidence.append(
            f"Shodan: <b>{shodan['cve_count']} CVE(s)</b> on host IP{cve_note}: "
            f"<code style='font-size:0.78rem'>{top_cves}</code>"
        )

    abuse = per_src.get("abuseipdb", {}).get("detail", {})
    if abuse.get("is_tor"):
        evidence.append("Target IP is a <b>TOR exit node</b> — anonymised source")
    if abuse.get("confidence", 0) >= 50:
        evidence.append(
            f"AbuseIPDB confidence score: <b>{abuse['confidence']}/100</b> "
            f"({abuse.get('total_reports', 0)} reports)"
        )

    whois = enrich.get("whois", {}) or {}
    if whois.get("age_days") is not None and whois["age_days"] < 30:
        evidence.append(
            f"Domain is <b>only {whois['age_days']} days old</b> — "
            f"high-risk indicator for phishing"
        )

    ssl_info = enrich.get("ssl", {}) or {}
    days_left = ssl_info.get("days_left")
    if days_left is not None and days_left < 30:
        evidence.append(f"SSL certificate expires in <b>{days_left} days</b>")

    if validation.get("risk_signals"):
        for s in validation["risk_signals"]:
            if s.startswith("typo_squat"):
                evidence.append(f"Typo-squat detected: <code>{s}</code>")
            elif s.startswith("homograph"):
                evidence.append(f"Homograph attack (Cyrillic lookalike): <code>{s}</code>")
            elif s.startswith("suspicious_tld"):
                evidence.append(f"Suspicious TLD: <code>{s}</code>")

    # ── Recommendations ───────────────────────────────────────────
    recs = []
    if verdict == "MALICIOUS":
        recs.append("🚫 <b>Block this domain</b> on corporate firewall and DNS resolver immediately.")
        recs.append("🔐 <b>Do not enter credentials</b> or download files from this source.")
        recs.append("🔍 Review recent user access logs for anyone who visited this URL.")
        recs.append("📣 Share the case ID with your SOC team for incident investigation.")
    elif verdict == "DEAD_DOMAIN":
        recs.append("⚠️ Domain does not resolve. Verify URL is typed correctly.")
        recs.append("Non-existent domains in messages are often phishing lures with typos.")
    elif verdict == "SUSPICIOUS":
        recs.append("⚠️ <b>Treat with caution</b>. Additional review recommended before allowing traffic.")
        recs.append("Verify the domain's legitimacy via out-of-band channels (phone call, official website).")
        if whois.get("age_days") is not None and whois["age_days"] < 90:
            recs.append("Domain is recently registered — consider temporary block until reputation matures.")
    elif verdict == "CLEAN":
        recs.append("✅ No threat indicators found. URL appears safe based on current intel.")
        if hygiene.get("score", 0) < 60:
            recs.append(
                f"Note: the target's own security hygiene is <b>{hygiene.get('grade','?')}</b> — "
                f"consider requesting they improve security headers."
            )
    else:
        recs.append("Inconclusive result. Re-scan or consult additional sources.")

    # Always remind about evidence preservation
    recs.append(f"Download the JSON case file for forensic archival (case {case.get('case_id','?')}).")

    # ── Analyst note (one-sentence expert opinion) ────────────────
    note = _build_analyst_note(case, malicious_srcs, suspicious_srcs)

    return narrative, evidence, recs, note


def _build_analyst_note(case: dict, malicious_srcs: list, suspicious_srcs: list) -> str:
    """One-sentence expert summary."""
    verdict = case.get("fused_verdict", "UNKNOWN")
    enrich  = case.get("enrichment", {}) or {}
    per_src = case.get("per_source", {})

    if verdict == "DEAD_DOMAIN":
        return ("This domain does not resolve in DNS. Non-resolving domains in "
                "messages are classic phishing-lure typos — verify the sender.")
    if verdict == "MALICIOUS":
        shodan = per_src.get("shodan", {}).get("detail", {})
        if shodan.get("cve_count", 0) > 0:
            return ("Target hosts active CVE vulnerabilities AND is flagged by "
                    f"{len(malicious_srcs)} intel source(s) — exploit path is real.")
        if "virustotal" in malicious_srcs:
            return ("Multiple AV engines agree on malicious verdict — high-confidence threat.")
        return f"Confirmed malicious by {len(malicious_srcs)} independent intel source(s)."
    if verdict == "SUSPICIOUS":
        if suspicious_srcs:
            return (f"Weak signal from {', '.join(suspicious_srcs[:2])}. "
                    f"Treat as unverified — correlate with internal telemetry.")
        return "Low-confidence signals. Keep under watch but no immediate action."
    if verdict == "CLEAN":
        whois = enrich.get("whois", {}) or {}
        if whois.get("age_days") and whois["age_days"] > 365:
            return (f"Well-established domain ({whois['age_days']//365}+ years old) "
                    f"with no adverse intel. Low risk.")
        return "No adverse intelligence. URL appears safe at time of scan."
    return "Inconclusive scan — consider manual review."


# ══════════════════════════════════════════════════════════════════
# HYGIENE TAB (was missing since Part 1)
# ══════════════════════════════════════════════════════════════════
def _render_hygiene_tab(case: dict):
    h = case.get("hygiene", {})
    if not h or h.get("error"):
        st.info(f"Hygiene data unavailable: {h.get('error', 'not computed')}")
        return

    grade  = h.get("grade", "N/A")
    score  = h.get("score", 0)
    checks = h.get("checks", [])

    grade_meta = {
        "A+": ("#16A34A", "#F0FDF4"), "A":  ("#16A34A", "#F0FDF4"),
        "A-": ("#65A30D", "#F7FEE7"),
        "B":  ("#CA8A04", "#FFFBEB"), "B-": ("#CA8A04", "#FFFBEB"),
        "C":  ("#EA580C", "#FFF7ED"), "D":  ("#DC2626", "#FEF2F2"),
        "F":  ("#DC2626", "#FEF2F2"), "N/A":("#64748B", "#F8FAFC"),
    }
    grade_color, grade_tint = grade_meta.get(grade, ("#64748B", "#F8FAFC"))

    # Big grade display - Phase 3f white native premium
    st.markdown(
        f'<div style="background:{grade_tint}; padding:24px 28px; '
        f'border:1px solid #E2E8F0; border-left:4px solid {grade_color}; '
        f'border-radius:10px; display:flex; align-items:center; gap:24px; '
        f'margin-bottom:14px; box-shadow:0 1px 2px rgba(15,23,42,0.04);">'
        f'<div style="flex-shrink:0; width:80px; height:80px; background:{grade_color}; '
        f'color:#FFFFFF; border-radius:14px; display:flex; align-items:center; '
        f'justify-content:center; font-family:Inter,sans-serif; font-size:2.5rem; '
        f'font-weight:800; letter-spacing:-0.04em;">{grade}</div>'
        f'<div style="flex:1; min-width:0;">'
        f'<div style="font-family:Inter,sans-serif; font-size:0.6875rem; '
        f'letter-spacing:0.08em; color:#64748B; text-transform:uppercase; '
        f'font-weight:600;">Security hygiene score</div>'
        f'<div style="font-family:Inter,sans-serif; font-size:2rem; '
        f'color:#0F172A; margin-top:4px; font-weight:700; '
        f'letter-spacing:-0.025em; line-height:1;">'
        f'{score}<span style="color:#94A3B8; font-size:1.1rem; font-weight:500;"> / 100</span>'
        f'</div>'
        f'<div style="font-family:Inter,sans-serif; color:#475569; '
        f'font-size:0.875rem; margin-top:6px; line-height:1.5;">'
        f'Audits the target\'s own security posture — headers, TLS, cookies, DNS records'
        f'</div></div></div>',
        unsafe_allow_html=True,
    )

    # Per-check breakdown — Phase 3f premium grid
    section_header("Check breakdown", f"{len(checks)} CHECKS")
    grid = '<div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap:8px; margin-top:8px;">'
    for idx, c in enumerate(checks):
        passed   = c.get("status", "fail") == "pass"
        weight   = c.get("max", 0)
        awarded  = c.get("score", 0)
        cname    = c.get("name", "?")
        detail   = c.get("evidence", "") or c.get("detail", "")
        fix_hint = c.get("fix", "")
        delay    = idx * 30
        if passed:
            chk_color, chk_tint, chk_label = "#16A34A", "#F0FDF4", "PASS"
            icon = '<path d="M9 12l2 2 4-4"/><circle cx="12" cy="12" r="10"/>'
        elif awarded > 0:
            chk_color, chk_tint, chk_label = "#CA8A04", "#FFFBEB", "PARTIAL"
            icon = '<circle cx="12" cy="12" r="10"/><path d="M12 8v4M12 16h.01"/>'
        else:
            chk_color, chk_tint, chk_label = "#DC2626", "#FEF2F2", "FAIL"
            icon = '<circle cx="12" cy="12" r="10"/><path d="M15 9l-6 6M9 9l6 6"/>'
        grid += (
            f'<div style="background:#FFFFFF; padding:12px 14px; '
            f'border:1px solid #E2E8F0; border-left:3px solid {chk_color}; border-radius:8px; '
            f'display:flex; align-items:center; gap:12px; '
            f'animation:mc-row-in 260ms {delay}ms cubic-bezier(0.4,0,0.2,1) backwards; '
            f'box-shadow:0 1px 2px rgba(15,23,42,0.04);">'
            f'<div style="flex-shrink:0; width:32px; height:32px; background:{chk_tint}; '
            f'border-radius:8px; display:flex; align-items:center; justify-content:center;">'
            f'<svg width="18" height="18" viewBox="0 0 24 24" fill="none" '
            f'stroke="{chk_color}" stroke-width="2" stroke-linecap="round" '
            f'stroke-linejoin="round">{icon}</svg></div>'
            f'<div style="flex:1; min-width:0;">'
            f'<div style="font-family:Inter,sans-serif; font-size:0.875rem; '
            f'font-weight:600; color:#0F172A;">{cname}</div>'
            f'<div style="font-family:JetBrains Mono,monospace; font-size:0.72rem; '
            f'color:#64748B; margin-top:2px;">{awarded}/{weight} pts'
            f'{(" · " + detail[:60]) if detail else ""}</div>'
            f'{("<div style=font-size:0.7rem;color:#64748B;margin-top:3px;font-style:italic;>" + fix_hint[:80] + "</div>") if fix_hint and not passed else ""}'
            f'</div>'
            f'<div style="flex-shrink:0; font-family:JetBrains Mono,monospace; '
            f'font-size:0.65rem; font-weight:700; color:{chk_color}; '
            f'letter-spacing:0.06em; background:{chk_tint}; '
            f'padding:4px 8px; border-radius:4px;">{chk_label}</div>'
            f'</div>'
        )
    grid += '</div>'
    st.markdown(grid, unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════
# ML TAB — numpy ensemble, real samples, feature importance
# ══════════════════════════════════════════════════════════════════

# Pre-computed stump weights → feature importance (normalised by total weight)
_FEAT_IMPORTANCE = {
    "has_at_symbol":       3.00,
    "has_ip":              3.00,
    "is_typosquat":        3.00,
    "has_punycode":        2.80,
    "tld_is_suspicious":   2.50,
    "domain_age_log":      2.50,
    "has_https":           2.20,
    "has_suspicious_word": 2.20,
    "num_hyphens":         2.00,
    "url_length":          1.80,
    "subdomain_count":     1.50,
    "num_dots":            1.50,
    "num_digits_in_host":  1.20,
    "path_length":         0.90,
    "query_param_count":   0.70,
}
_FEAT_TOTAL = sum(_FEAT_IMPORTANCE.values())

# Real sample URLs for demonstration (classified live by the numpy model)
_ML_DEMO_SAMPLES = [
    # (url, expected)
    ("http://paypal-secure-verify-login.tk/account/update", "phishing"),
    ("http://192.168.1.1/admin/login",                      "phishing"),
    ("http://g00gle.com.phishing-kit.xyz/signin",           "phishing"),
    ("http://bank-secure-alert.cf/verify?user=test",        "phishing"),
    ("https://www.google.com/",                             "legitimate"),
    ("https://github.com/features",                         "legitimate"),
    ("https://mce.edu.in/",                                 "legitimate"),
    ("https://stackoverflow.com/questions/12345678",        "legitimate"),
]


def _render_ml_tab(case: dict):
    ml = case.get("ml", {})

    label      = ml.get("label", "unknown")
    conf       = ml.get("confidence", 0.0)
    prob_phish = ml.get("probability_phishing", 0.0)
    prob_legit = ml.get("probability_legit", 1.0 - prob_phish)
    feats      = ml.get("feature_values", {})
    avail      = ml.get("available", False)

    # ── Model info banner ────────────────────────────────────────
    if label == "phishing":
        lc, lt = "#DC2626", "#FEF2F2"
        icon, verdict_txt = "🚨", "PHISHING DETECTED"
    elif label == "legitimate":
        lc, lt = "#16A34A", "#F0FDF4"
        icon, verdict_txt = "✅", "LEGITIMATE"
    else:
        lc, lt = "#64748B", "#F8FAFC"
        icon, verdict_txt = "❓", "UNKNOWN"

    st.markdown(f"""
<div style="background:{lt};border:1px solid #E2E8F0;border-left:5px solid {lc};
  border-radius:12px;padding:20px 24px;margin-bottom:18px;
  animation:mc-tab-content-in 360ms cubic-bezier(0.4,0,0.2,1);">
  <div style="display:flex;align-items:center;gap:16px;flex-wrap:wrap;">
    <div style="font-size:2.5rem;line-height:1;">{icon}</div>
    <div style="flex:1;min-width:180px;">
      <div style="font-family:Inter,sans-serif;font-size:0.6rem;font-weight:700;
        letter-spacing:0.12em;color:#94A3B8;text-transform:uppercase;">
        ML Verdict · Numpy Ensemble · 15 URL Features</div>
      <div style="font-family:Inter,sans-serif;font-size:1.6rem;font-weight:800;
        color:{lc};letter-spacing:-0.03em;margin-top:2px;">{verdict_txt}</div>
      <div style="font-family:Inter,sans-serif;font-size:0.82rem;color:#475569;margin-top:6px;">
        Confidence: <b style="color:#0F172A;">{conf*100:.1f}%</b>
        &nbsp;·&nbsp;Algorithm: Weighted Decision Stump Ensemble (25 stumps)
        &nbsp;·&nbsp;Training ref: PhishTank + Alexa Top-1M</div>
    </div>
    <div style="flex-shrink:0;text-align:center;">
      <div style="font-family:Inter,sans-serif;font-size:2rem;font-weight:800;
        color:{lc};">{conf*100:.0f}<span style="font-size:1rem;color:#94A3B8;">%</span></div>
      <div style="font-family:Inter,sans-serif;font-size:0.65rem;font-weight:700;
        letter-spacing:0.1em;color:#94A3B8;text-transform:uppercase;">Confidence</div>
    </div>
  </div>
</div>""", unsafe_allow_html=True)

    # ── Probability split bar ────────────────────────────────────
    ph_pct = prob_phish * 100
    lg_pct = prob_legit * 100
    st.markdown(f"""
<div style="margin-bottom:20px;">
  <div style="font-family:Inter,sans-serif;font-size:0.72rem;font-weight:700;
    letter-spacing:0.1em;color:#0F172A;text-transform:uppercase;margin-bottom:8px;">
    Probability Distribution</div>
  <div style="display:flex;height:32px;border-radius:8px;overflow:hidden;
    border:1px solid #E2E8F0;box-shadow:0 1px 3px rgba(15,23,42,0.06);">
    <div style="background:linear-gradient(90deg,#991B1B,#DC2626);
      width:{ph_pct:.1f}%;min-width:50px;display:flex;align-items:center;
      padding:0 10px;color:#FFF;font-family:Inter,sans-serif;
      font-size:0.75rem;font-weight:700;
      animation:mc-bar-grow {ph_pct/100:.2f}s ease-out;">
      Phishing {ph_pct:.1f}%</div>
    <div style="background:linear-gradient(90deg,#16A34A,#22C55E);
      width:{lg_pct:.1f}%;min-width:50px;display:flex;align-items:center;
      padding:0 10px;color:#FFF;font-family:Inter,sans-serif;
      font-size:0.75rem;font-weight:700;">
      Legitimate {lg_pct:.1f}%</div>
  </div>
</div>""", unsafe_allow_html=True)

    col_feat, col_vals = st.columns([3, 2])

    # ── Feature importance chart ──────────────────────────────────
    with col_feat:
        st.markdown("""
<div style="font-family:Inter,sans-serif;font-size:0.72rem;font-weight:700;
  letter-spacing:0.1em;color:#0F172A;text-transform:uppercase;margin-bottom:10px;">
  Feature Importance (Pre-trained Weights)</div>""", unsafe_allow_html=True)

        sorted_feats = sorted(_FEAT_IMPORTANCE.items(), key=lambda x: -x[1])
        bars = ""
        for i, (fname, wt) in enumerate(sorted_feats):
            pct     = wt / max(_FEAT_IMPORTANCE.values()) * 100
            norm    = wt / _FEAT_TOTAL
            # Highlight if this feature fired for the scanned URL
            fval    = feats.get(fname, 0) if feats else 0
            active  = bool(fval)
            bar_col = "#2563EB" if not active else "#DC2626" if fname in (
                "has_ip","has_at_symbol","is_typosquat","has_punycode",
                "tld_is_suspicious","has_suspicious_word") else "#2563EB"
            badge   = (f'<span style="background:{bar_col}22;color:{bar_col};'
                       f'font-family:JetBrains Mono;font-size:0.62rem;font-weight:700;'
                       f'padding:1px 6px;border-radius:4px;margin-left:4px;">'
                       f'val={fval}</span>' if feats and active else "")
            bars += (
                f'<div style="display:flex;align-items:center;gap:8px;margin-bottom:5px;'
                f'animation:mc-row-in 240ms {i*35}ms cubic-bezier(0.4,0,0.2,1) backwards;">'
                f'<div style="width:145px;font-family:JetBrains Mono,monospace;'
                f'font-size:0.72rem;color:#334155;text-align:right;flex-shrink:0;">'
                f'{fname.replace("_"," ")}</div>'
                f'<div style="flex:1;height:18px;background:#F1F5F9;border-radius:4px;overflow:hidden;">'
                f'<div style="height:100%;width:{pct:.0f}%;'
                f'background:linear-gradient(90deg,{bar_col},{bar_col}CC);border-radius:4px;'
                f'animation:mc-bar-grow 0.7s {i*35}ms ease-out backwards;"></div></div>'
                f'<div style="width:36px;font-family:JetBrains Mono;font-size:0.68rem;'
                f'color:#94A3B8;text-align:right;">{norm:.3f}</div>'
                f'{badge}</div>'
            )
        st.markdown(bars, unsafe_allow_html=True)

    # ── Feature values for this URL ───────────────────────────────
    with col_vals:
        st.markdown("""
<div style="font-family:Inter,sans-serif;font-size:0.72rem;font-weight:700;
  letter-spacing:0.1em;color:#0F172A;text-transform:uppercase;margin-bottom:10px;">
  This URL's Feature Values</div>""", unsafe_allow_html=True)

        if feats:
            FEAT_LABELS = {
                "url_length":          ("URL length", "chars"),
                "num_dots":            ("Dots in URL", ""),
                "num_hyphens":         ("Hyphens", ""),
                "num_digits_in_host":  ("Digits in host", ""),
                "has_ip":              ("Raw IP in URL", "bool"),
                "has_at_symbol":       ("@ symbol", "bool"),
                "has_https":           ("HTTPS", "bool"),
                "tld_is_suspicious":   ("Suspicious TLD", "bool"),
                "domain_age_log":      ("Domain age (log)", "log10 days"),
                "has_suspicious_word": ("Suspicious keyword", "bool"),
                "is_typosquat":        ("Typo-squat", "bool"),
                "has_punycode":        ("Punycode (IDN)", "bool"),
                "subdomain_count":     ("Subdomains", ""),
                "path_length":         ("Path length", "chars"),
                "query_param_count":   ("Query params", ""),
            }
            DANGER_FEATS = {"has_ip","has_at_symbol","is_typosquat","has_punycode",
                            "tld_is_suspicious","has_suspicious_word"}
            rows = ""
            for fname, (label, unit) in FEAT_LABELS.items():
                val   = feats.get(fname, 0)
                danger = fname in DANGER_FEATS and val
                vc2   = "#DC2626" if danger else "#0F172A"
                bg2   = "#FEF2F2" if danger else "#FFFFFF"
                rows += (
                    f'<tr style="background:{bg2};">'
                    f'<td style="padding:4px 8px;font-family:JetBrains Mono;'
                    f'font-size:0.7rem;color:#64748B;border-bottom:1px solid #F1F5F9;">'
                    f'{label}</td>'
                    f'<td style="padding:4px 8px;font-family:JetBrains Mono;'
                    f'font-size:0.72rem;font-weight:700;color:{vc2};'
                    f'border-bottom:1px solid #F1F5F9;text-align:right;">'
                    f'{val}{" " + unit if unit and unit != "bool" else ""}'
                    f'{"  ⚠" if danger else ""}</td>'
                    f'</tr>'
                )
            st.markdown(
                f'<table style="width:100%;border-collapse:collapse;'
                f'background:#FFFFFF;border:1px solid #E2E8F0;border-radius:8px;'
                f'overflow:hidden;">{rows}</table>',
                unsafe_allow_html=True,
            )
        else:
            st.info("Feature values not available for this scan.")

    # ── Real sample dataset ───────────────────────────────────────
    st.markdown("<div style='height:20px'></div>", unsafe_allow_html=True)
    st.markdown("""
<div style="font-family:Inter,sans-serif;font-size:0.72rem;font-weight:700;
  letter-spacing:0.1em;color:#0F172A;text-transform:uppercase;margin-bottom:10px;
  display:flex;align-items:center;gap:8px;">
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#2563EB"
    stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="10"/>
    <path d="M12 8v4l3 3"/></svg>
  Live Demo — Real Sample Classifications (model running now)</div>""",
    unsafe_allow_html=True)

    try:
        from core.ml_classifier import classify_url as _clf
        rows_html = ""
        for i, (surl, expected) in enumerate(_ML_DEMO_SAMPLES):
            r    = _clf(surl)
            got  = r.get("label", "unknown")
            prob = r.get("probability_phishing", 0) * 100
            conf2 = r.get("confidence", 0) * 100
            is_phish = got == "phishing"
            row_bg   = "#FEF2F2" if is_phish else "#F0FDF4"
            row_c    = "#DC2626" if is_phish else "#16A34A"
            badge    = ("🚨 PHISHING" if is_phish else "✅ LEGITIMATE")
            correct  = (got == expected)
            corr_txt = "✓" if correct else "✗"
            corr_c   = "#16A34A" if correct else "#DC2626"
            rows_html += (
                f'<tr style="background:{row_bg if i%2==0 else "#FFFFFF"};">'
                f'<td style="padding:7px 10px;font-family:JetBrains Mono;font-size:0.7rem;'
                f'color:#334155;border-bottom:1px solid #F1F5F9;max-width:280px;'
                f'overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">'
                f'<a href="{surl}" style="color:#2563EB;text-decoration:none;">'
                f'{surl[:60]}{"…" if len(surl)>60 else ""}</a></td>'
                f'<td style="padding:7px 10px;font-family:Inter;font-size:0.72rem;'
                f'font-weight:700;color:{row_c};border-bottom:1px solid #F1F5F9;">'
                f'{badge}</td>'
                f'<td style="padding:7px 10px;font-family:JetBrains Mono;font-size:0.72rem;'
                f'color:#374151;border-bottom:1px solid #F1F5F9;text-align:right;">'
                f'{prob:.1f}%</td>'
                f'<td style="padding:7px 10px;font-family:JetBrains Mono;font-size:0.72rem;'
                f'text-align:center;color:{corr_c};font-weight:700;'
                f'border-bottom:1px solid #F1F5F9;">{corr_txt}</td>'
                f'</tr>'
            )
        st.markdown(f"""
<div style="overflow-x:auto;border:1px solid #E2E8F0;border-radius:10px;
  box-shadow:0 1px 4px rgba(15,23,42,0.06);">
<table style="width:100%;border-collapse:collapse;background:#FFFFFF;">
<thead><tr style="background:#F8FAFC;">
  <th style="padding:8px 10px;font-family:Inter;font-size:0.68rem;font-weight:700;
    letter-spacing:0.08em;color:#64748B;text-transform:uppercase;
    text-align:left;border-bottom:2px solid #E2E8F0;">URL</th>
  <th style="padding:8px 10px;font-family:Inter;font-size:0.68rem;font-weight:700;
    letter-spacing:0.08em;color:#64748B;text-transform:uppercase;
    text-align:left;border-bottom:2px solid #E2E8F0;">Classification</th>
  <th style="padding:8px 10px;font-family:Inter;font-size:0.68rem;font-weight:700;
    letter-spacing:0.08em;color:#64748B;text-transform:uppercase;
    text-align:right;border-bottom:2px solid #E2E8F0;">Phish %</th>
  <th style="padding:8px 10px;font-family:Inter;font-size:0.68rem;font-weight:700;
    letter-spacing:0.08em;color:#64748B;text-transform:uppercase;
    text-align:center;border-bottom:2px solid #E2E8F0;">Correct?</th>
</tr></thead>
<tbody>{rows_html}</tbody>
</table>
</div>
<div style="font-family:Inter,sans-serif;font-size:0.72rem;color:#94A3B8;
  margin-top:6px;">Model: Numpy Decision Stump Ensemble · 25 stumps · 15 features
  · Reference: PhishTank + Alexa Top-1M (Babu et al., 2019)</div>""",
            unsafe_allow_html=True)
    except Exception as e:
        st.warning(f"Sample classification error: {e}")
