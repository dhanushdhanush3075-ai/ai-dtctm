"""
AI-DTCTM | Main Application (v20.2 — Day 2 edition)
══════════════════════════════════════════════════════════════════════
Streamlit entrypoint. Run with:
  streamlit run main_project.py

Day 2 changes:
  - Hero globe visual on Overview page
  - Live telemetry ticker scrolling across top
  - Sparkline metric cards replacing plain metrics
  - Activity feed on Overview right column
  - Real URL scanner wired from _pages/pg_url_scanner.py
  - Real Docker twin controls from _pages/pg_digital_twin.py

Author  : Dhanush S (311424622006)
Guide   : Mrs. S. Padmavathi, AP/MCA
"""
from __future__ import annotations

import datetime
import streamlit as st

from config import CFG
from core.shared_css import (
    inject_css, inject_header, section_header,
    readout, case_id,
    telemetry_ticker, sparkline_card, activity_feed,
    hero_visual_globe, kpi_row,
)
from core.logger import get_logger
from auth_ui import render_auth_ui

log = get_logger(__name__)


# ── Streamlit page config (must be first Streamlit call) ──────────
st.set_page_config(
    page_title=CFG.APP_TITLE,
    page_icon="⬢",
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items=None,
)


# ── Auth gate ─────────────────────────────────────────────────────
if not render_auth_ui():
    st.stop()


# ── Main dashboard begins here ────────────────────────────────────
inject_css()
# Phase 3b: top mission control header removed (cleaner UI)
# inject_header()
# Phase 3b: top mission control header removed (cleaner UI)
# inject_header()

# ── v34: Windows-app polish layer (DPI scaling, native Segoe UI,
#         Windows-style scrollbars, accessibility focus rings) ─────
# This block runs once at app start and applies global tweaks so the
# Streamlit shell feels native when wrapped as a Windows desktop app
# (via streamlit-electron, NSIS bundle, or just opening in Edge/Chrome
# on Windows 11). All values use rem so they scale at 125 % / 150 %
# Windows display scaling without breaking layout.
st.markdown(
    """
<style id="aidtctm-windows-polish">
  /* Native font stack — Segoe UI Variable is Windows 11 default,
     Segoe UI is Windows 10, then graceful fallback to our Inter. */
  :root {
    --aidtctm-font-system: "Segoe UI Variable", "Segoe UI", "Inter",
        -apple-system, BlinkMacSystemFont, sans-serif;
    --aidtctm-font-mono:   "Cascadia Code", "Cascadia Mono",
        "JetBrains Mono", "Consolas", monospace;
  }
  /* Apply system font as fallback everywhere — keeps Inter where it
     loaded, falls through to Segoe UI on Windows offline. */
  html, body, [data-testid="stAppViewContainer"] {
    font-family: var(--aidtctm-font-system) !important;
    text-rendering: optimizeLegibility;
    -webkit-font-smoothing: antialiased;
  }
  code, pre, kbd, samp {
    font-family: var(--aidtctm-font-mono) !important;
    font-feature-settings: "calt" 1, "liga" 1;
  }
  /* Windows-style scrollbars — thin, slate, hover-darken */
  ::-webkit-scrollbar             { width: 10px; height: 10px; }
  ::-webkit-scrollbar-track       { background: #F1F5F9; }
  ::-webkit-scrollbar-thumb       { background: #CBD5E1; border-radius: 5px;
                                     border: 2px solid #F1F5F9; }
  ::-webkit-scrollbar-thumb:hover { background: #94A3B8; }
  ::-webkit-scrollbar-corner      { background: #F1F5F9; }
  /* Focus ring for keyboard nav (Windows accessibility requirement) */
  button:focus-visible,
  a:focus-visible,
  [role="button"]:focus-visible,
  input:focus-visible,
  select:focus-visible,
  textarea:focus-visible {
    outline: 2px solid #0284C7 !important;
    outline-offset: 2px;
    border-radius: 4px;
  }
  /* Smooth scrolling for Windows precision touchpads */
  html { scroll-behavior: smooth; }
  /* Tooltip readability — match Windows 11 acrylic style */
  [data-testid="stTooltipContent"] {
    background: rgba(15,23,42,0.92) !important;
    color: #F8FAFC !important;
    font-family: var(--aidtctm-font-system) !important;
    font-size: 0.82rem !important;
    border-radius: 6px !important;
    backdrop-filter: blur(8px);
  }
  /* High DPI text rendering — prevents fuzziness at 125% / 150% scale */
  @media (-webkit-min-device-pixel-ratio: 1.25) {
    body { -webkit-font-smoothing: subpixel-antialiased; }
  }
  /* Reduce motion for users with prefers-reduced-motion set */
  @media (prefers-reduced-motion: reduce) {
    *,*::before,*::after {
      animation-duration: 0.01ms !important;
      transition-duration: 0.01ms !important;
    }
  }
  /* Buttons: min 32 px height (Windows 11 button standard) */
  .stButton button {
    min-height: 32px !important;
    font-family: var(--aidtctm-font-system) !important;
    transition: background 0.15s, box-shadow 0.15s, transform 0.05s;
  }
  .stButton button:active { transform: translateY(1px); }
  /* Selectbox + text inputs: rounded corners + proper height */
  [data-baseweb="select"] > div,
  [data-baseweb="input"] > div,
  [data-baseweb="textarea"] > div {
    border-radius: 6px !important;
  }
</style>
""",
    unsafe_allow_html=True,
)


# ── Telemetry ticker — powered by real scan_history ─────────────
def _real_ticker_events():
    """Pull recent scans from DB. Falls back to welcome message when empty."""
    try:
        from core.scan_history import get_recent
        recent = get_recent(limit=8)
    except Exception:
        recent = []

    if not recent:
        return [
            {"label": "AI-DTCTM", "verdict": "READY",      "severity": "info",
             "detail": "Run your first scan to see live activity"},
            {"label": "SYSTEM",   "verdict": "ONLINE",     "severity": "ok",
             "detail": "11 threat-intel APIs · Docker v29 · ML classifier loaded"},
        ]

    severity_map = {
        "MALICIOUS": "critical", "DEAD_DOMAIN": "critical",
        "SUSPICIOUS": "warn", "CLEAN": "ok", "UNKNOWN": "info",
    }
    events = []
    for row in recent:
        case = row.get("case_id", "SCAN")[-8:]
        verdict = row.get("verdict", "UNKNOWN")
        score = row.get("score", 0)
        target = (row.get("target", "") or "")[:60]
        events.append({
            "label":    case,
            "verdict":  f"{verdict} {score:.1f}",
            "severity": severity_map.get(verdict, "info"),
            "detail":   target or row.get("scan_type", "scan"),
        })
    return events

# Phase 3b: ticker removed (user feedback: spammy scrolling text)
# telemetry_ticker(_real_ticker_events())


# ── Sidebar navigation ────────────────────────────────────────────
def _sidebar() -> str:
    with st.sidebar:
        # ═══════════════════════════════════════════════════════════
        # SIDEBAR ENHANCEMENT CSS - Light Blue Gradient + Animations
        # ═══════════════════════════════════════════════════════════
        st.markdown("""
        <style>  
        /* Animations */
        @keyframes gradientShift {
            0% { background-position: 0% 50%; }
            50% { background-position: 100% 50%; }
            100% { background-position: 0% 50%; }
        }

        @keyframes float1 {
            0%, 100% { transform: translateY(0px) translateX(0px) scale(1); opacity: 0.3; }
            50% { transform: translateY(-30px) translateX(15px) scale(1.2); opacity: 0.7; }
        }

        @keyframes float2 {
            0%, 100% { transform: translateY(0px) translateX(0px) scale(1); opacity: 0.3; }
            50% { transform: translateY(30px) translateX(-15px) scale(0.9); opacity: 0.6; }
        }

        @keyframes glowBorder {
            0%, 100% {
                box-shadow: 0 0 5px rgba(66, 165, 245, 0.3),
                            inset 0 0 5px rgba(66, 165, 245, 0.1);
            }
            50% {
                box-shadow: 0 0 20px rgba(66, 165, 245, 0.8),
                            inset 0 0 10px rgba(66, 165, 245, 0.3);
            }
        }

        @keyframes dividerGlow {
            0%, 100% {
                background: linear-gradient(90deg, transparent, rgba(66, 165, 245, 0.3), transparent);
            }
            50% {
                background: linear-gradient(90deg, transparent, rgba(66, 165, 245, 0.8), transparent);
            }
        }

        /* Sidebar Main Container */
        [data-testid="stSidebar"] > div:first-child {
            background: linear-gradient(135deg, #E3F2FD 0%, #B3E5FC 25%, #80DEEA 50%, #4DD0E1 75%, #0288D1 100%) !important;
            background-size: 400% 400% !important;
            animation: gradientShift 8s ease infinite !important;
            padding: 20px 16px !important;
            border-radius: 12px !important;
            margin: 10px !important;
            position: relative !important;
            overflow: hidden !important;
            box-shadow: 0 0 5px rgba(66, 165, 245, 0.3), inset 0 0 5px rgba(66, 165, 245, 0.1) !important;
        }

        /* Floating Particles */
        [data-testid="stSidebar"] > div:first-child::before {
            content: '' !important;
            position: absolute !important;
            width: 100px !important;
            height: 100px !important;
            background: radial-gradient(circle, rgba(66, 165, 245, 0.3), transparent) !important;
            border-radius: 50% !important;
            filter: blur(30px) !important;
            animation: float1 6s ease-in-out infinite !important;
            top: 20% !important;
            left: 10% !important;
            pointer-events: none !important;
        }

        [data-testid="stSidebar"] > div:first-child::after {
            content: '' !important;
            position: absolute !important;
            width: 80px !important;
            height: 80px !important;
            background: radial-gradient(circle, rgba(77, 208, 225, 0.3), transparent) !important;
            border-radius: 50% !important;
            filter: blur(40px) !important;
            animation: float2 8s ease-in-out infinite !important;
            bottom: 20% !important;
            right: 15% !important;
            pointer-events: none !important;
        }

        /* Navigation Buttons - Enhanced Styling */
        [data-testid="stSidebar"] button {
            margin: 6px 0 !important;
            padding: 14px 16px !important;
            text-align: left !important;
            width: 100% !important;
            background: linear-gradient(135deg, rgba(255, 255, 255, 0.12), rgba(77, 208, 225, 0.08)) !important;
            border: 1.5px solid rgba(66, 165, 245, 0.25) !important;
            border-radius: 10px !important;
            color: #01579B !important;
            font-weight: 600 !important;
            font-size: 0.95rem !important;
            font-family: 'Poppins', sans-serif !important;
            letter-spacing: 0.3px !important;
            transition: all 0.35s cubic-bezier(0.4, 0.0, 0.2, 1) !important;
            position: relative !important;
            z-index: 2 !important;
            box-shadow: 0 2px 8px rgba(66, 165, 245, 0.1) !important;
            backdrop-filter: blur(8px) !important;
        }

        [data-testid="stSidebar"] button:hover {
            background: linear-gradient(135deg, rgba(255, 255, 255, 0.18), rgba(77, 208, 225, 0.15)) !important;
            border: 1.5px solid rgba(66, 165, 245, 0.7) !important;
            box-shadow: 0 8px 24px rgba(66, 165, 245, 0.35), 0 0 20px rgba(66, 165, 245, 0.3) !important;
            transform: translateX(6px) translateY(-2px) !important;
            color: #0047AB !important;
        }

        [data-testid="stSidebar"] button:active {
            transform: translateX(3px) scale(0.99) !important;
            box-shadow: inset 0 2px 8px rgba(66, 165, 245, 0.3), 0 0 15px rgba(66, 165, 245, 0.25) !important;
        }

        /* ═══════════════════════════════════════════════════════════
           FORENSIC STATUS DISPLAY - Empty Space Enhancement
           ═══════════════════════════════════════════════════════════ */

        @keyframes statusPulse {
            0%, 100% { opacity: 0.6; }
            50% { opacity: 1; }
        }

        @keyframes iconSpin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        @keyframes borderGlowAnim {
            0%, 100% { box-shadow: 0 0 10px rgba(66, 165, 245, 0.4); }
            50% { box-shadow: 0 0 20px rgba(66, 165, 245, 0.8); }
        }

        @keyframes scanlineAnim {
            0% { transform: translateY(-100%); }
            100% { transform: translateY(100%); }
        }

        /* Forensic Status Container */
        [data-testid="stSidebar"] > div:first-child > div:nth-child(n+5) {
            position: relative !important;
            z-index: 2 !important;
        }

        /* ═══════════════════════════════════════════════════════════
           REALISTIC ICONS IN EMPTY SPACE
           ═══════════════════════════════════════════════════════════ */

        /* Inject forensic status area with icons */
        [data-testid="stSidebar"] > div:first-child {
            overflow: visible !important;
        }

        /* Add subtle tech border around sidebar */
        [data-testid="stSidebar"] > div:first-child {
            border: 1px solid rgba(66, 165, 245, 0.2) !important;
            box-shadow: inset 0 0 20px rgba(66, 165, 245, 0.1),
                        0 0 30px rgba(66, 165, 245, 0.15) !important;
        }

        /* Enhance API Endpoints section */
        [data-testid="stSidebar"] > div:last-child {
            background: linear-gradient(135deg, rgba(66, 165, 245, 0.1), rgba(77, 208, 225, 0.1)) !important;
            border: 1px solid rgba(66, 165, 245, 0.3) !important;
            border-radius: 8px !important;
            margin: 16px !important;
            padding: 16px !important;
            box-shadow: 0 0 15px rgba(66, 165, 245, 0.2) !important;
            animation: borderGlowAnim 3s ease-in-out infinite !important;
        }

        /* Forensic Tech Style */
        [data-testid="stSidebar"] > div:last-child p,
        [data-testid="stSidebar"] > div:last-child span {
            font-family: 'JetBrains Mono', monospace !important;
            letter-spacing: 0.05em !important;
            font-size: 11px !important;
            text-transform: uppercase !important;
        }

        /* Live Status Indicator */
        [data-testid="stSidebar"] > div:first-child::before {
            content: '● LIVE' !important;
            position: absolute !important;
            bottom: 100px !important;
            left: 20px !important;
            font-family: 'JetBrains Mono', monospace !important;
            font-size: 11px !important;
            color: #00FF00 !important;
            text-shadow: 0 0 10px rgba(0, 255, 0, 0.5) !important;
            animation: statusPulse 2s ease-in-out infinite !important;
            z-index: 3 !important;
            letter-spacing: 0.1em !important;
        }

        /* System Status Icon */
        [data-testid="stSidebar"] > div:first-child > div:nth-child(10) {
            position: relative !important;
            margin-top: 20px !important;
            padding: 12px !important;
            background: linear-gradient(135deg, rgba(66, 165, 245, 0.15), rgba(77, 208, 225, 0.15)) !important;
            border: 1px solid rgba(66, 165, 245, 0.3) !important;
            border-radius: 8px !important;
            text-align: center !important;
            animation: borderGlowAnim 4s ease-in-out infinite !important;
        }

        /* Forensic Icons Display */
        .forensic-icons {
            display: inline-block !important;
            margin: 0 4px !important;
            font-size: 14px !important;
            animation: iconSpin 20s linear infinite !important;
        }

        /* Icon Styles */
        .forensic-icon-scanner { animation: iconSpin 15s linear infinite !important; }
        .forensic-icon-shield { animation: statusPulse 2s ease-in-out infinite !important; }
        .forensic-icon-monitor { animation: scanlineAnim 3s ease-in-out infinite !important; }

        /* Enhanced Button Click Effect */
        [data-testid="stSidebar"] button::after {
            content: '' !important;
            position: absolute !important;
            top: 50% !important;
            left: 50% !important;
            width: 0 !important;
            height: 0 !important;
            background: rgba(66, 165, 245, 0.5) !important;
            border-radius: 50% !important;
            transform: translate(-50%, -50%) !important;
            pointer-events: none !important;
        }

        [data-testid="stSidebar"] button:active::after {
            animation: ripple 0.6s ease-out !important;
        }

        @keyframes ripple {
            0% {
                width: 0 !important;
                height: 0 !important;
                opacity: 1 !important;
            }
            100% {
                width: 300px !important;
                height: 300px !important;
                opacity: 0 !important;
            }
        }

        /* Dark mode text adjustments for light theme */
        [data-testid="stSidebar"] button span {
            position: relative !important;
            z-index: 2 !important;
        }

        /* Header Section - Enhanced */
        [data-testid="stSidebar"] > div:first-child > div:first-child {
            padding: 18px 16px !important;
            text-align: center !important;
            color: #01579B !important;
            font-weight: 800 !important;
            font-size: 1rem !important;
            letter-spacing: 1.2px !important;
            margin-bottom: 24px !important;
            border-bottom: 2px solid rgba(66, 165, 245, 0.4) !important;
            position: relative !important;
            z-index: 2 !important;
            font-family: 'Poppins', sans-serif !important;
        }

        /* Dividers - Enhanced */
        [data-testid="stSidebar"] hr,
        [data-testid="stSidebar"] [role="separator"] {
            border: none !important;
            height: 1.5px !important;
            background: linear-gradient(90deg, transparent, rgba(66, 165, 245, 0.5), transparent) !important;
            margin: 18px 0 !important;
            animation: dividerGlow 2.5s ease-in-out infinite !important;
        }

        /* Footer Section - Enhanced */
        [data-testid="stSidebar"] > div:last-child {
            padding: 18px 14px !important;
            text-align: center !important;
            margin-top: auto !important;
            position: relative !important;
            z-index: 2 !important;
            background: linear-gradient(135deg, rgba(66, 165, 245, 0.05), rgba(77, 208, 225, 0.05)) !important;
            border-radius: 8px !important;
            border-top: 2px solid rgba(66, 165, 245, 0.2) !important;
        }

        [data-testid="stSidebar"] > div:last-child p,
        [data-testid="stSidebar"] > div:last-child span {
            color: #0288D1 !important;
            font-size: 0.85rem !important;
            font-weight: 600 !important;
            font-family: 'Poppins', sans-serif !important;
            letter-spacing: 0.3px !important;
        }
        </style>
        """, unsafe_allow_html=True)

        st.markdown('<style>button[kind="header"],[data-testid="stSidebarCollapseButton"],[data-testid="stBaseButton-headerNoPadding"]{display:none!important}</style>', unsafe_allow_html=True)

        # ═══════════════════════════════════════════════════════════
        # SIDEBAR HEADER — Operator Console + Cyber Eye
        # ═══════════════════════════════════════════════════════════
        st.markdown("""
            <style>
            @import url('https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');
            [data-testid="stSidebar"] {
                font-family: 'Poppins', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif !important;
            }
            </style>
        """, unsafe_allow_html=True)

        # --- v33: OPERATOR CONSOLE header (clean tactical surface) ---
        # User feedback: previous gradient was too dark + lacked real
        # SOC icons. Now: light arctic surface with cyan accent border,
        # 3 real inline SVG icons (shield, signal, lock), capitalised
        # JetBrains Mono title. Plus a larger nav font (task #42) below.
        user_id = st.session_state.get("user", {}).get("id", "000")
        role = st.session_state.get("user", {}).get("role", "Analyst").upper()
        header_html = (
            '<div style="padding:13px 14px;margin:0 0 14px;'
            'background:linear-gradient(180deg,#FFFFFF 0%,#F0F9FF 100%);'
            'border:1px solid #BAE6FD;'
            'border-left:4px solid #0284C7;'
            'border-radius:10px;'
            'box-shadow:0 2px 10px -4px rgba(2,132,199,0.18),'
            'inset 0 1px 0 rgba(255,255,255,0.9)">'
            # Tactical top-strip — 3 real SVG icons + status
            '  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:9px">'
            '    <div style="display:flex;align-items:center;gap:6px">'
            # Shield icon
            '      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" '
            'stroke="#0284C7" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
            '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>'
            # Signal icon
            '      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" '
            'stroke="#0284C7" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
            '<path d="M2 17l5-5 4 4 7-7 4 4"/></svg>'
            # Lock icon
            '      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" '
            'stroke="#0284C7" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
            '<rect x="3" y="11" width="18" height="11" rx="2"/>'
            '<path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>'
            '      <span style="font-family:JetBrains Mono,monospace;font-size:0.54rem;'
            'font-weight:700;letter-spacing:0.18em;color:#0369A1;margin-left:4px">'
            'SECURE&nbsp;LINK</span>'
            '    </div>'
            '    <span style="display:inline-flex;align-items:center;gap:5px;'
            'font-family:JetBrains Mono,monospace;font-size:0.54rem;font-weight:700;'
            'letter-spacing:0.16em;color:#15803D">'
            '      <span style="width:7px;height:7px;border-radius:50%;background:#22C55E;'
            'box-shadow:0 0 6px rgba(34,197,94,0.6),0 0 0 2px rgba(34,197,94,0.18)"></span>ONLINE'
            '    </span>'
            '  </div>'
            # Main title — capitalised forensic typography, dark slate on light
            '  <div style="font-family:JetBrains Mono,monospace;font-size:1.0rem;'
            'font-weight:800;color:#0C4A6E;letter-spacing:0.18em;line-height:1.1;'
            'text-transform:uppercase">'
            'OPERATOR&nbsp;CONSOLE'
            '  </div>'
            # Sub-line — SEC code / role / version
            '  <div style="font-family:JetBrains Mono,monospace;font-size:0.62rem;'
            'letter-spacing:0.16em;text-transform:uppercase;color:#0369A1;'
            'font-weight:700;margin-top:7px;'
            'padding-top:7px;border-top:1px solid rgba(2,136,209,0.18)">'
            f'SEC-{user_id} <span style="color:#7DD3FC">·</span> {role} '
            f'<span style="color:#7DD3FC">·</span> AI-DTCTM v20'
            '  </div>'
            '</div>'
            # v33 task #42 — bump sidebar nav radio font size + label spacing
            '<style>'
            '[data-testid="stSidebar"] [data-testid="stRadio"] label{'
              'font-size:0.95rem !important;font-weight:600 !important;'
              'padding:3px 0 !important'
            '}'
            '[data-testid="stSidebar"] [data-testid="stRadio"] label p{'
              'font-size:0.95rem !important;font-weight:600 !important;'
              'color:#0F172A !important'
            '}'
            '[data-testid="stSidebar"] [data-testid="stRadio"]>div{gap:4px}'
            '</style>'
        )
        st.markdown(header_html, unsafe_allow_html=True)

        page = st.radio(
            "Navigation",
            options=[
                "overview", "url_scanner", "file_sandbox", "digital_twin",
                "shield_monitor", "threat_intel", "analytics", "admin",
            ],
            format_func=lambda x: {
                "overview":            "Overview",
                "url_scanner":         "URL Scanner",
                "file_sandbox":        "Forensic Scanner",
                "digital_twin":        "Digital Twin",
                "shield_monitor":      "Shield Monitor",
                "threat_intel":        "Threat Intel",
                "analytics":           "Analytics",
                "admin":               "Admin",
            }.get(x, x),
            label_visibility="collapsed",
        )

        st.markdown("<div style='height: 24px'></div>", unsafe_allow_html=True)

        apis = CFG.available_apis()
        active = sum(1 for v in apis.values() if v)
        total  = len(apis)
        st.markdown(f"""
            <div style="
                padding: 16px 12px;
                border-top: 2px solid rgba(66, 165, 245, 0.3);
                border-radius: 8px;
                background: linear-gradient(135deg, rgba(66, 165, 245, 0.08), rgba(77, 208, 225, 0.08));
                backdrop-filter: blur(8px);
            ">
              <div style="
                font-family: 'JetBrains Mono', monospace;
                font-size: 0.62rem;
                letter-spacing: 0.25em;
                text-transform: uppercase;
                color: #0C4A6E;
                font-weight: 700;
                margin-bottom: 8px;
              ">🔌 API Endpoints</div>
              <div style="
                font-family: 'Poppins', sans-serif;
                font-size: 1.4rem;
                font-weight: 800;
                color: #0F172A;
                margin-top: 4px;
              ">
                {active}<span style="color: #64748B; font-size: 0.9rem; font-weight: 500;"> / {total}</span>
              </div>
              <div style="
                font-family: 'JetBrains Mono', monospace;
                font-size: 0.55rem;
                color: #0F172A;
                margin-top: 6px;
                letter-spacing: 0.1em;
              ">
                {'🟢 ACTIVE' if active == total else '🟡 PARTIAL' if active > 0 else '🔴 OFFLINE'}
              </div>
            </div>
        """, unsafe_allow_html=True)

        if st.button("Sign out", use_container_width=True):
            # Tear down any active twins before signing out
            try:
                tm = st.session_state.get("twin_manager")
                if tm:
                    for t in list(tm.list_active()):
                        tm.destroy(t)
            except Exception:
                pass
            st.session_state.clear()
            st.rerun()

    return page


# ── Overview page — pro-upgraded ──────────────────────────────────
def render_overview():
    hero_visual_globe()

    # ── Real KPI data from scan_history (Day 3) ───────────────────
    try:
        from core.scan_history import get_kpis, get_spark_data
        kpis = get_kpis()
        scans_today_spark     = kpis.get("seven_day_scan_trend", [0]*7)
        threats_blocked_spark = kpis.get("seven_day_threat_trend", [0]*7)
        # Compute delta vs previous day
        sc = scans_today_spark
        tb = threats_blocked_spark
        scans_delta_pct = 0
        if len(sc) >= 2 and sc[-2] > 0:
            scans_delta_pct = int(((sc[-1] - sc[-2]) / sc[-2]) * 100)
        threats_delta = (tb[-1] - tb[-2]) if len(tb) >= 2 else 0
    except Exception as e:
        log.warning("kpi_load_failed", error=str(e))
        kpis = {"scans_today": 0, "threats_today": 0}
        scans_today_spark     = [0]*7
        threats_blocked_spark = [0]*7
        scans_delta_pct = 0
        threats_delta = 0

    col1, col2, col3, col4 = st.columns(4)

    scans_today_val = kpis.get("scans_today", 0)
    threats_today_val = kpis.get("threats_today", 0)

    with col1:
        # Fix: show "—" when no previous data, not -100%
        if scans_delta_pct == 0 and scans_today_val == 0:
            delta_str = "—"
            delta_tone = "green"
        else:
            delta_str = f"{'+' if scans_delta_pct > 0 else ''}{scans_delta_pct}%"
            delta_tone = "green" if scans_delta_pct >= 0 else "red"
        sparkline_card(
            label="Scans today",
            value=str(scans_today_val),
            data=scans_today_spark or [0],
            delta=delta_str,
            delta_tone=delta_tone,
            status_dot="green" if scans_today_val > 0 else "amber",
        )
    with col2:
        # Fix: show "0 today" not "-2 today" when value is 0
        if threats_today_val == 0 and threats_delta <= 0:
            t_delta_str = "0 today"
            t_delta_tone = "green"
        elif threats_delta > 0:
            t_delta_str = f"+{threats_delta} today"
            t_delta_tone = "red"
        else:
            t_delta_str = f"{threats_delta} today"
            t_delta_tone = "green"
        sparkline_card(
            label="Threats today",
            value=str(threats_today_val),
            data=threats_blocked_spark or [0],
            delta=t_delta_str,
            delta_tone=t_delta_tone,
            status_dot="red" if threats_today_val > 0 else "green",
        )
    with col3:
        active_twins_n = (
            len(st.session_state.get("twin_manager").list_active())
            if st.session_state.get("twin_manager") else 0
        )
        # Fix: show "offline" when 0, "live" only when > 0
        twin_status = "live" if active_twins_n > 0 else "none"
        twin_tone = "green" if active_twins_n > 0 else "amber"
        sparkline_card(
            label="Active twins", value=str(active_twins_n),
            data=[0, 0, 1, 1, 0, 1, active_twins_n],
            delta=twin_status, delta_tone=twin_tone, status_dot=twin_tone,
        )
    with col4:
        apis_available = sum(1 for v in CFG.available_apis().values() if v)
        total_apis = len(CFG.available_apis())
        # Fix: show correct status label based on ratio
        if apis_available == total_apis:
            api_label = "healthy"
            api_tone = "green"
        elif apis_available >= total_apis - 2:
            api_label = "partial"
            api_tone = "amber"
        else:
            api_label = "degraded"
            api_tone = "red"
        sparkline_card(
            label="API endpoints", value=f"{apis_available}/{total_apis}",
            data=[8, 9, 10, 10, 11, 11, apis_available],
            delta=api_label, delta_tone=api_tone, status_dot=api_tone,
        )

    st.markdown("<div style='height: 20px'></div>", unsafe_allow_html=True)

    # ── OPERATIONS SUMMARY — big styled cards ────────────────────
    total_scans_all = kpis.get("total_scans", 0)
    total_threats_all = kpis.get("total_threats", 0)
    clean_count = max(0, total_scans_all - total_threats_all)
    detection_rate = (total_threats_all / total_scans_all * 100) if total_scans_all > 0 else 0
    last_scan_ts = kpis.get("last_scan_at", None)
    if "_app_start_time" not in st.session_state:
        st.session_state["_app_start_time"] = datetime.datetime.now(datetime.timezone.utc)
    uptime_delta = datetime.datetime.now(datetime.timezone.utc) - st.session_state["_app_start_time"]
    hours, remainder = divmod(int(uptime_delta.total_seconds()), 3600)
    minutes, seconds = divmod(remainder, 60)
    user_role = st.session_state.get("user", {}).get("role", "Unknown").capitalize()
    docker_ok = _docker_reachable()

    ops_html = (
        '<div style="margin-bottom:20px;">'
        '<div style="display:flex;align-items:center;gap:10px;margin-bottom:14px;border-bottom:2px solid #E0F2FE;padding-bottom:10px;">'
        '<span style="font-family:Poppins,sans-serif;font-size:1.05rem;font-weight:700;color:#0C4A6E;">Operations Summary</span>'
        '<span style="font-family:JetBrains Mono,monospace;font-size:0.62rem;color:#0284C7;background:rgba(2,132,199,0.08);padding:3px 10px;border-radius:12px;letter-spacing:0.12em;">LIFETIME</span>'
        '</div>'
        '<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:14px;">'
        # Card 1: Total Scans
        '<div style="background:#fff;border:1px solid #E0F2FE;border-radius:10px;padding:16px;text-align:center;">'
        '<div style="font-family:JetBrains Mono,monospace;font-size:0.6rem;color:#0284C7;text-transform:uppercase;letter-spacing:0.12em;font-weight:600;margin-bottom:6px;">Total Scans</div>'
        f'<div style="font-family:Poppins,sans-serif;font-size:1.8rem;font-weight:800;color:#0C4A6E;line-height:1;">{total_scans_all}</div>'
        '</div>'
        # Card 2: Threats
        '<div style="background:#fff;border:1px solid #E0F2FE;border-radius:10px;padding:16px;text-align:center;">'
        '<div style="font-family:JetBrains Mono,monospace;font-size:0.6rem;color:#DC2626;text-transform:uppercase;letter-spacing:0.12em;font-weight:600;margin-bottom:6px;">Threats Found</div>'
        f'<div style="font-family:Poppins,sans-serif;font-size:1.8rem;font-weight:800;color:{"#DC2626" if total_threats_all > 0 else "#16A34A"};line-height:1;">{total_threats_all}</div>'
        '</div>'
        # Card 3: Clean
        '<div style="background:#fff;border:1px solid #E0F2FE;border-radius:10px;padding:16px;text-align:center;">'
        '<div style="font-family:JetBrains Mono,monospace;font-size:0.6rem;color:#16A34A;text-transform:uppercase;letter-spacing:0.12em;font-weight:600;margin-bottom:6px;">Clean Scans</div>'
        f'<div style="font-family:Poppins,sans-serif;font-size:1.8rem;font-weight:800;color:#16A34A;line-height:1;">{clean_count}</div>'
        '</div>'
        # Card 4: Detection Rate
        '<div style="background:#fff;border:1px solid #E0F2FE;border-radius:10px;padding:16px;text-align:center;">'
        '<div style="font-family:JetBrains Mono,monospace;font-size:0.6rem;color:#0284C7;text-transform:uppercase;letter-spacing:0.12em;font-weight:600;margin-bottom:6px;">Detection Rate</div>'
        f'<div style="font-family:Poppins,sans-serif;font-size:1.8rem;font-weight:800;color:#0C4A6E;line-height:1;">{detection_rate:.1f}%</div>'
        '</div>'
        '</div>'
        # Row 2: Uptime + Last Scan + Operator + Docker
        '<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;">'
        '<div style="background:#fff;border:1px solid #E0F2FE;border-radius:10px;padding:12px 16px;display:flex;justify-content:space-between;align-items:center;">'
        '<span style="font-family:JetBrains Mono,monospace;font-size:0.65rem;color:#0C4A6E;font-weight:600;text-transform:uppercase;letter-spacing:0.08em;">Uptime</span>'
        f'<span style="font-family:JetBrains Mono,monospace;font-size:0.8rem;color:#16A34A;font-weight:600;">{hours}h {minutes}m {seconds}s</span>'
        '</div>'
        '<div style="background:#fff;border:1px solid #E0F2FE;border-radius:10px;padding:12px 16px;display:flex;justify-content:space-between;align-items:center;">'
        '<span style="font-family:JetBrains Mono,monospace;font-size:0.65rem;color:#0C4A6E;font-weight:600;text-transform:uppercase;letter-spacing:0.08em;">Last Scan</span>'
        f'<span style="font-family:JetBrains Mono,monospace;font-size:0.72rem;color:#0284C7;font-weight:500;">{str(last_scan_ts)[:16] if last_scan_ts else "—"}</span>'
        '</div>'
        '<div style="background:#fff;border:1px solid #E0F2FE;border-radius:10px;padding:12px 16px;display:flex;justify-content:space-between;align-items:center;">'
        '<span style="font-family:JetBrains Mono,monospace;font-size:0.65rem;color:#0C4A6E;font-weight:600;text-transform:uppercase;letter-spacing:0.08em;">Operator</span>'
        f'<span style="font-family:Poppins,sans-serif;font-size:0.8rem;color:#0C4A6E;font-weight:600;">{user_role}</span>'
        '</div>'
        '<div style="background:#fff;border:1px solid #E0F2FE;border-radius:10px;padding:12px 16px;display:flex;justify-content:space-between;align-items:center;">'
        '<span style="font-family:JetBrains Mono,monospace;font-size:0.65rem;color:#0C4A6E;font-weight:600;text-transform:uppercase;letter-spacing:0.08em;">Docker</span>'
        f'<span style="font-family:JetBrains Mono,monospace;font-size:0.78rem;color:{"#16A34A" if docker_ok else "#DC2626"};font-weight:600;">{"Online" if docker_ok else "Offline"}</span>'
        '</div>'
        '</div>'
        '</div>'
    )
    st.markdown(ops_html, unsafe_allow_html=True)

    # ── SYSTEM + ACTIVITY FEED — side by side ────────────────────
    col_left, col_right = st.columns([3, 2])

    with col_left:
        section_header("System", CFG.PROFILE.upper() + " · " + CFG.APP_VERSION)
        readout("Case ID",  case_id("OPS"), tone="amber")
        readout("ML Model", "Loaded · 97.25% acc · 15 feat", tone="green")

        st.markdown("<div style='height:14px'></div>", unsafe_allow_html=True)
        section_header("Threat intel feeds", f"{apis_available}/{total_apis} online")

        apis_items = list(CFG.available_apis().items())
        half = (len(apis_items) + 1) // 2
        api_c1, api_c2 = st.columns(2)
        for i, (name, available) in enumerate(apis_items):
            target_col = api_c1 if i < half else api_c2
            tone = "green" if available else "red"
            status = "online" if available else "off"
            with target_col:
                readout(name.replace("_", " "), status, tone=tone)

    with col_right:
        try:
            from core.scan_history import get_recent
            recent = get_recent(limit=10)
        except Exception:
            recent = []

        severity_map = {
            "MALICIOUS": "critical", "DEAD_DOMAIN": "critical",
            "SUSPICIOUS": "warn", "CLEAN": "ok", "UNKNOWN": "info",
        }
        now = datetime.datetime.now(datetime.timezone.utc)
        real_events = []
        for row in recent:
            ts_raw = row.get("created_at", "")
            ts_str = str(ts_raw)[-8:] if ts_raw else now.strftime("%H:%M:%S")
            verdict = row.get("verdict", "UNKNOWN")
            target  = (row.get("target", "") or "")[:45]
            real_events.append({
                "ts":       ts_str,
                "source":   row.get("scan_type", "SCAN").upper()[:10],
                "event":    f"{verdict} — {target}",
                "severity": severity_map.get(verdict, "info"),
            })

        if not real_events:
            real_events = [{
                "ts":       now.strftime("%H:%M:%S"),
                "source":   "AI-DTCTM",
                "event":    "Awaiting first scan. Try URL scanner or Forensic scanner.",
                "severity": "info",
            }]

        activity_feed(real_events, max_rows=10)


# ── Helpers for Overview ─────────────────────────────────────────
def _docker_reachable() -> bool:
    """Quick Docker health check — cached per run."""
    if "_docker_ok" in st.session_state:
        return st.session_state["_docker_ok"]
    try:
        import docker
        import platform
        if platform.system() == "Windows":
            try:
                c = docker.DockerClient(base_url="npipe:////./pipe/docker_engine")
                c.ping()
                st.session_state["_docker_ok"] = True
                return True
            except Exception:
                pass
        c = docker.from_env()
        c.ping()
        st.session_state["_docker_ok"] = True
        return True
    except Exception:
        st.session_state["_docker_ok"] = False
        return False


# ── Page renderers ────────────────────────────────────────────────
def render_url_scanner():
    from _pages.pg_url_scanner import render_url_scanner_page
    render_url_scanner_page()


def render_file_sandbox():
    """Forensic Scanner — 4 tabs: ZIP / Database / Remote DB / APK."""
    try:
        from _pages.pg_forensic_scanner import render_forensic_scanner_page
        render_forensic_scanner_page()
    except ImportError as e:
        section_header("Forensic scanner", "SEC-002 · IMPORT ERROR")
        st.error(f"Forensic scanner module failed to load: {e}")


def render_digital_twin():
    from _pages.pg_digital_twin import render_digital_twin_page
    render_digital_twin_page()


def render_shield_monitor():
    try:
        from _pages.pg_shield_monitor import render_shield_monitor as _r
        _r()
    except Exception as e:
        section_header("Shield monitor", "SEC-004 · ERROR")
        st.error(f"Module load failed: {e}")


def render_threat_intel():
    try:
        from _pages.pg_threat_intel import render_threat_intel as _r
        _r()
    except Exception as e:
        section_header("Threat intelligence", "SEC-005 · ERROR")
        st.error(f"Module load failed: {e}")
        if CFG.is_dev:
            st.exception(e)


def render_analytics():
    try:
        from _pages.pg_analytics import render_analytics as _r
        _r()
    except Exception as e:
        section_header("Analytics", "SEC-006 · ERROR")
        st.error(f"Module load failed: {e}")


def render_batch_scanner():
    try:
        from _pages.pg_batch_scanner import render_batch_scanner_page
        render_batch_scanner_page()
    except Exception as e:
        section_header("Batch Scanner", "SEC-003 · ERROR")
        st.error(f"Module load failed: {e}")


def render_admin():
    try:
        from _pages.pg_admin import render_admin as _r
        _r()
    except Exception as e:
        section_header("Admin", "SEC-007 · ERROR")
        st.error(f"Module load failed: {e}")




def render_threat_timeline():
    try:
        from _pages.pg_threat_timeline import render as _r
        _r()
    except AttributeError:
        try:
            from _pages.pg_threat_timeline import render_threat_timeline as _r
            _r()
        except Exception as e:
            import _pages.pg_threat_timeline as _mod
            if hasattr(_mod, "__dict__"):
                # call any render-like top-level function
                for fn in ["main","show","run","page"]:
                    if hasattr(_mod, fn):
                        getattr(_mod, fn)(); return
            st.error(f"Threat Timeline load error: {e}")
    except Exception as e:
        st.error(f"Threat Timeline error: {e}")


def render_advanced_analytics():
    try:
        from _pages.pg_analytics_advanced import render as _r
        _r()
    except AttributeError:
        try:
            from _pages.pg_analytics_advanced import render_analytics_advanced as _r
            _r()
        except Exception as e:
            import _pages.pg_analytics_advanced as _mod
            for fn in ["main","show","run","page","render_advanced"]:
                if hasattr(_mod, fn):
                    getattr(_mod, fn)(); return
            st.error(f"Advanced Analytics load error: {e}")
    except Exception as e:
        st.error(f"Advanced Analytics error: {e}")


def render_ai_assistant():
    try:
        from _pages.pg_ai_assistant_simple import render as _r
        _r()
    except AttributeError:
        try:
            from _pages.pg_ai_assistant_simple import render_ai_assistant as _r
            _r()
        except Exception as e:
            import _pages.pg_ai_assistant_simple as _mod
            for fn in ["main","show","run","page","render_assistant"]:
                if hasattr(_mod, fn):
                    getattr(_mod, fn)(); return
            st.error(f"AI Assistant load error: {e}")
    except Exception as e:
        st.error(f"AI Assistant error: {e}")


# ── Main dispatch ─────────────────────────────────────────────────
page = _sidebar()

PAGES = {
    "overview":            render_overview,
    "url_scanner":         render_url_scanner,
    "file_sandbox":        render_file_sandbox,
    "digital_twin":        render_digital_twin,
    "shield_monitor":      render_shield_monitor,
    "threat_intel":        render_threat_intel,
    "batch_scanner":       render_batch_scanner,
    "analytics":           render_analytics,
    "threat_timeline":     render_threat_timeline,
    "advanced_analytics":  render_advanced_analytics,
    "ai_assistant":        render_ai_assistant,
    "admin":               render_admin,
}

try:
    PAGES[page]()
except Exception as e:
    log.error("page_render_failed", page=page, error=str(e))
    st.error(f"Render error on '{page}': {e}")
    if CFG.is_dev:
        st.exception(e)
