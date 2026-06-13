"""
AI-DTCTM | Mission Control Design System (v20)
════════════════════════════════════════════════════════════════════
Central CSS + utility functions used by ALL pages.

DESIGN DIRECTION: "Mission Control"
  - Inspired by NASA ops rooms + Bloomberg Terminal + SpaceX Dragon console
  - Warm black (#FFFFFF) instead of the generic cyber blue-black
  - Signal amber (#FF6B1A) instead of the generic cyan
  - IBM Plex Sans + Plex Mono — one family, intentional feel
  - Left-border accents on cards (not filled colored backgrounds)
  - No gradients, no glow, no shadows — everything flat and intentional
  - Data density > whitespace (like a real ops terminal)
  - Live millisecond UTC clock in header

WHY THIS STANDS OUT:
  99% of student cybersec projects use cyan-on-navy "hacker terminal" theme.
  This one uses warm amber — same genre, opposite palette. Classmate copies
  will be immediately distinguishable side-by-side.
"""
import streamlit as st
import streamlit.components.v1 as components

# ── Colour Tokens ─────────────────────────────────────────────────
# Source of truth for all colours used across the app.
AMBER        = "#FF6B1A"   # Primary accent — signal amber
AMBER_DIM    = "#BA5014"   # Darker amber (pressed state)
AMBER_GLOW   = "rgba(255,107,26,0.15)"  # Subtle tint for hover

BG_DEEP      = "#FFFFFF"   # Base background — warm near-black
BG_SURFACE   = "#F8FAFC"   # Raised panel
BG_ELEVATED  = "#F0F4F8"   # Cards, inputs
BG_HOVER     = "#E8EEF5"

TEXT_HIGH    = "#1a202c"   # Primary text — warm ivory (NOT white)
TEXT_MID     = "#718096"   # Secondary
TEXT_LOW     = "#4a5568"   # Tertiary, labels
TEXT_DIM     = "#2d3748"   # Disabled

BORDER_SOFT  = "rgba(245,232,216,0.08)"
BORDER_MID   = "rgba(255,107,26,0.2)"
BORDER_HARD  = "rgba(255,107,26,0.4)"

SIGNAL_OK    = "#9ACD32"   # Sodium green (readable on warm dark)
SIGNAL_WARN  = "#FFD23F"   # Amber-yellow
SIGNAL_CRIT  = "#E63946"   # Alert red


# ── LIGHT THEME TOKENS (Phase 2c — white-mode, CheckPhish-inspired) ──
# Toggleable theme via st.session_state["theme"] = "light" | "dark"
LIGHT_TOKENS = {
    "BG_DEEP":      "#FFFFFF",
    "BG_SURFACE":   "#F8FAFC",
    "BG_ELEVATED":  "#FFFFFF",
    "BG_HOVER":     "#F1F5F9",
    "TEXT_HIGH":    "#0F172A",   # Slate-900 — readable on white
    "TEXT_MID":     "#475569",
    "TEXT_LOW":     "#64748B",
    "TEXT_DIM":     "#94A3B8",
    "BORDER_SOFT":  "rgba(15,23,42,0.06)",
    "BORDER_MID":   "rgba(15,23,42,0.12)",
    "BORDER_HARD":  "rgba(15,23,42,0.20)",
    "AMBER":        "#FF6B1A",
    "AMBER_DIM":    "#BA5014",
    "AMBER_GLOW":   "rgba(255,107,26,0.10)",
    "SIGNAL_OK":    "#16A34A",   # Darker greens for white bg readability
    "SIGNAL_WARN":  "#CA8A04",
    "SIGNAL_CRIT":  "#DC2626",
    # Brand colour for light mode (CheckPhish-blue inspired)
    "ACCENT_BLUE":  "#1E40AF",
    "ACCENT_INDIGO":"#3730A3",
}


def get_active_theme() -> str:
    """Phase 3b — light is now default for everyone (was 'dark' until 3a)."""
    try:
        return st.session_state.get("theme", "light")
    except Exception:
        return "light"


DASHBOARD_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700&family=JetBrains+Mono:wght@300;400;500;600;700&family=IBM+Plex+Sans:wght@300;400;500;600;700&family=IBM+Plex+Mono:wght@300;400;500;600;700&display=swap');

/* ═══════ BASE — Phase 2b typography upgrade ═══════
   Space Grotesk for body = modern geometric feel, different from 
   typical tech demos. JetBrains Mono for code/labels = developer-grade
   ligatures. IBM Plex retained as fallback.
*/
html, body, .stApp, [data-testid="stAppViewContainer"], section.main, [data-testid="stMain"]{
  background: #F8FAFC !important;
  background-image: linear-gradient(135deg, #FFFFFF 0%, #F8FAFC 50%, #F0F4F8 100%) !important;
  color: #1a202c !important;
  font-family: 'Space Grotesk', 'IBM Plex Sans', -apple-system, system-ui, sans-serif !important;
  -webkit-font-smoothing: antialiased !important;
  letter-spacing: -0.005em !important;
}
.main .block-container{ max-width: 100% !important; padding: 0.6rem 1.75rem 2rem !important; }
/* Hide Streamlit branding but keep functional buttons */
[data-testid="stDecoration"] { display: none !important; }
[data-testid="stToolbar"] [data-testid="stActionButton"] { visibility: hidden !important; }
#MainMenu, footer{ visibility: hidden !important; }

/* Keep monospace identity for code / labels / metrics — JetBrains Mono */
code, pre, kbd, samp, [class*="language-"] {
  font-family: 'JetBrains Mono', 'IBM Plex Mono', monospace !important;
}

/* ═══════ SIDEBAR — Phase 2b: stronger contrast + animations ═══════ */
[data-testid="stSidebar"]{
  background: linear-gradient(180deg, #1E1A1D 0%, #14111A 100%) !important;
  border-right: 1px solid rgba(255,107,26,0.18) !important;
  box-shadow: 2px 0 24px rgba(0,0,0,0.4) !important;
  transition: width 0.28s cubic-bezier(0.4, 0, 0.2, 1) !important;
}

/* Phase 3O: sidebar header — hide native collapse button (we use custom ☰) */
  padding: 0 !important;
  min-height: 0 !important;
  height: 0 !important;
  overflow: hidden !important;
}
[data-testid="stSidebar"] *{ font-family: 'IBM Plex Sans', sans-serif !important; }
[data-testid="stSidebar"] label{
  font-family: 'IBM Plex Mono', monospace !important;
  font-size: 0.62rem !important;
  letter-spacing: 0.22em !important;
  text-transform: uppercase !important;
  color: #4a5568 !important;
  font-weight: 500 !important;
}
[data-testid="stSidebar"] input, [data-testid="stSidebar"] textarea{
  background: #F0F4F8 !important;
  border: 1px solid rgba(245,232,216,0.1) !important;
  border-radius: 2px !important;
  color: #1a202c !important;
  font-family: 'IBM Plex Mono', monospace !important;
  font-size: 0.85rem !important;
  caret-color: #FF6B1A !important;
  transition: border-color 0.12s !important;
}
[data-testid="stSidebar"] input:focus, [data-testid="stSidebar"] textarea:focus{
  border-color: #FF6B1A !important;
  outline: none !important;
  background: #FFFFFF !important;
}
[data-testid="stSidebar"] input::placeholder{ color: #0F172A !important; }

[data-testid="stSidebar"] [data-testid="stSelectbox"] > div > div{
  background: #F0F4F8 !important;
  border: 1px solid rgba(245,232,216,0.1) !important;
  border-radius: 2px !important;
  color: #1a202c !important;
  font-family: 'IBM Plex Mono', monospace !important;
}

/* Hide auto-generated pages nav (we build our own) */
[data-testid="stSidebarNav"], [data-testid="stSidebarNavItems"]{ display: none !important; }

/* ═══════ SIDEBAR RADIO NAV — Phase 2b animated nav ═══════
   Each option slides in on hover, amber line grows beneath active row,
   Lucide-style icon glow. This is the navigation a real ops console
   would have, not plain streamlit radio buttons.
*/
[data-testid="stSidebar"] [data-testid="stRadio"] > label{
  display: none !important;
}
[data-testid="stSidebar"] [data-testid="stRadio"] [role="radiogroup"]{
  gap: 2px !important;
}
[data-testid="stSidebar"] [data-testid="stRadio"] label[data-baseweb="radio"]{
  padding: 11px 14px !important;
  margin: 0 !important;
  border-radius: 2px !important;
  border-left: 2px solid transparent !important;
  transition: all 0.22s cubic-bezier(0.4, 0, 0.2, 1) !important;
  cursor: pointer !important;
  position: relative !important;
  overflow: hidden !important;
}
[data-testid="stSidebar"] [data-testid="stRadio"] label[data-baseweb="radio"]:hover{
  background: rgba(255,107,26,0.08) !important;
  border-left-color: rgba(255,107,26,0.45) !important;
  transform: translateX(2px) !important;
}
[data-testid="stSidebar"] [data-testid="stRadio"] label[data-baseweb="radio"]:hover div{
  color: #1a202c !important;
}
/* Active (checked) radio */
[data-testid="stSidebar"] [data-testid="stRadio"] label[data-baseweb="radio"]:has(input:checked){
  background: linear-gradient(90deg, rgba(255,107,26,0.18) 0%, rgba(255,107,26,0.04) 100%) !important;
  border-left-color: #FF6B1A !important;
  transform: translateX(0) !important;
}
[data-testid="stSidebar"] [data-testid="stRadio"] label[data-baseweb="radio"]:has(input:checked) div{
  color: #FF6B1A !important;
  font-weight: 500 !important;
  letter-spacing: 0.02em !important;
}
/* Hide the default radio dot — we use left-border as indicator */
[data-testid="stSidebar"] [data-testid="stRadio"] label[data-baseweb="radio"] > div:first-child{
  display: none !important;
}
[data-testid="stSidebar"] [data-testid="stRadio"] label[data-baseweb="radio"] > div:last-child{
  font-family: 'Space Grotesk', sans-serif !important;
  font-size: 0.88rem !important;
  font-weight: 400 !important;
  color: #4a5568 !important;
  letter-spacing: 0.01em !important;
  line-height: 1.2 !important;
  transition: color 0.18s !important;
}
/* Pulse dot for active nav item */
[data-testid="stSidebar"] [data-testid="stRadio"] label[data-baseweb="radio"]:has(input:checked)::before{
  content: '' !important;
  position: absolute !important;
  right: 14px !important;
  top: 50% !important;
  transform: translateY(-50%) !important;
  width: 6px !important;
  height: 6px !important;
  border-radius: 50% !important;
  background: #FF6B1A !important;
  box-shadow: 0 0 10px #FF6B1A !important;
  animation: mc-nav-pulse 1.8s ease-in-out infinite !important;
}
@keyframes mc-nav-pulse {
  0%, 100% { opacity: 1; transform: translateY(-50%) scale(1); }
  50%      { opacity: 0.5; transform: translateY(-50%) scale(1.4); }
}

/* ═══════ NAV LINKS (legacy / page-based) ═══════ */
[data-testid="stSidebarNavLink"]{
  font-family: 'IBM Plex Sans', sans-serif !important;
  font-size: 0.88rem !important;
  font-weight: 400 !important;
  color: #4a5568 !important;
  border-radius: 2px !important;
  padding: 10px 14px !important;
  border-left: 2px solid transparent !important;
  transition: all 0.12s !important;
}
[data-testid="stSidebarNavLink"]:hover{
  color: #1a202c !important;
  background: rgba(255,107,26,0.08) !important;
  border-left-color: rgba(255,107,26,0.4) !important;
}
[data-testid="stSidebarNavLink"][aria-current="page"]{
  color: #FF6B1A !important;
  background: rgba(255,107,26,0.1) !important;
  border-left-color: #FF6B1A !important;
}

/* ═══════ HEADER ═══════ */
header[data-testid="stHeader"]{
  background: rgba(15,13,16,0.95) !important;
  border-bottom: 1px solid rgba(245,232,216,0.08) !important;
  backdrop-filter: blur(12px) !important;
}

/* ═══════ METRIC CARDS (Mission Control signature) ═══════ */
/* Flat panels with amber left-border accent — no filled backgrounds */
div[data-testid="stMetric"]{
  background: #F8FAFC !important;
  border: none !important;
  border-left: 2px solid #FF6B1A !important;
  border-radius: 0 !important;
  padding: 14px 18px !important;
  position: relative !important;
  transition: background 0.12s !important;
}
div[data-testid="stMetric"]:hover{
  background: #F0F4F8 !important;
}
div[data-testid="stMetricLabel"] > div{
  font-family: 'IBM Plex Mono', monospace !important;
  font-size: 0.6rem !important;
  letter-spacing: 0.24em !important;
  text-transform: uppercase !important;
  color: #4a5568 !important;
  font-weight: 500 !important;
}
div[data-testid="stMetricValue"]{
  color: #1a202c !important;
  font-size: 2rem !important;
  font-weight: 500 !important;
  font-family: 'IBM Plex Mono', monospace !important;
  letter-spacing: -0.02em !important;
  line-height: 1.1 !important;
}
div[data-testid="stMetricDelta"]{
  font-family: 'IBM Plex Mono', monospace !important;
  font-size: 0.68rem !important;
  letter-spacing: 0.05em !important;
}

/* ═══════ BUTTONS ═══════ */
/* Primary — amber fill, reads as "do the thing" */
div[data-testid="stButton"] > button[kind="primary"],
div[data-testid="stFormSubmitButton"] > button{
  background: #FF6B1A !important;
  border: 1px solid #FF6B1A !important;
  border-radius: 2px !important;
  color: #FFFFFF !important;
  font-family: 'IBM Plex Sans', sans-serif !important;
  font-weight: 600 !important;
  font-size: 0.78rem !important;
  letter-spacing: 0.18em !important;
  text-transform: uppercase !important;
  box-shadow: none !important;
  transition: all 0.12s !important;
}
div[data-testid="stButton"] > button[kind="primary"]:hover,
div[data-testid="stFormSubmitButton"] > button:hover{
  background: #FFD23F !important;
  border-color: #FFD23F !important;
}
div[data-testid="stButton"] > button[kind="primary"]:active{
  transform: translateY(1px) !important;
  background: #BA5014 !important;
}

/* Secondary — amber outline */
div[data-testid="stButton"] > button{
  background: transparent !important;
  border: 1px solid rgba(255,107,26,0.35) !important;
  border-radius: 2px !important;
  color: #FF6B1A !important;
  font-family: 'IBM Plex Sans', sans-serif !important;
  font-weight: 500 !important;
  font-size: 0.78rem !important;
  letter-spacing: 0.12em !important;
  text-transform: uppercase !important;
  transition: all 0.12s !important;
}
div[data-testid="stButton"] > button:hover{
  background: rgba(255,107,26,0.08) !important;
  border-color: #FF6B1A !important;
  color: #FFD23F !important;
}

/* Download button — sodium green accent (different affordance) */
div[data-testid="stDownloadButton"] > button{
  background: transparent !important;
  border: 1px solid rgba(154,205,50,0.4) !important;
  border-radius: 2px !important;
  color: #9ACD32 !important;
  font-family: 'IBM Plex Sans', sans-serif !important;
  font-weight: 500 !important;
  font-size: 0.78rem !important;
  letter-spacing: 0.12em !important;
  text-transform: uppercase !important;
  transition: all 0.12s !important;
}
div[data-testid="stDownloadButton"] > button:hover{
  background: rgba(154,205,50,0.08) !important;
  border-color: #9ACD32 !important;
}

/* ═══════ TABS ═══════ */
div[data-baseweb="tab-list"]{
  background: transparent !important;
  border-bottom: 1px solid rgba(245,232,216,0.08) !important;
  gap: 0 !important;
}
button[data-baseweb="tab"]{
  background: transparent !important;
  border-radius: 0 !important;
  font-family: 'IBM Plex Mono', monospace !important;
  font-size: 0.7rem !important;
  letter-spacing: 0.18em !important;
  text-transform: uppercase !important;
  color: #4a5568 !important;
  padding: 11px 20px !important;
  border: none !important;
  border-bottom: 2px solid transparent !important;
  margin-bottom: -1px !important;
  transition: all 0.12s !important;
  font-weight: 500 !important;
}
button[data-baseweb="tab"]:hover{ color: #718096 !important; }
button[data-baseweb="tab"][aria-selected="true"]{
  color: #FF6B1A !important;
  border-bottom-color: #FF6B1A !important;
}
div[data-baseweb="tab-panel"]{ padding-top: 1rem !important; }

/* ═══════ TEXT INPUTS ═══════ */
div[data-testid="stTextInput"]{ margin-bottom: 10px !important; }
div[data-testid="stTextInput"] label{
  font-family: 'IBM Plex Mono', monospace !important;
  font-size: 0.6rem !important;
  letter-spacing: 0.24em !important;
  text-transform: uppercase !important;
  color: #4a5568 !important;
  font-weight: 500 !important;
}
div[data-testid="stTextInput"] input{
  background: #F0F4F8 !important;
  border: 1px solid rgba(245,232,216,0.1) !important;
  border-radius: 2px !important;
  color: #1a202c !important;
  font-family: 'IBM Plex Mono', monospace !important;
  font-size: 0.9rem !important;
  caret-color: #FF6B1A !important;
  transition: all 0.12s !important;
}
div[data-testid="stTextInput"] input:focus{
  border-color: #FF6B1A !important;
  box-shadow: 0 0 0 2px rgba(255,107,26,0.15) !important;
  outline: none !important;
  background: #FFFFFF !important;
}
div[data-testid="stTextInput"] input::placeholder{ color: #0F172A !important; }

/* ═══════ TEXTAREA ═══════ */
div[data-testid="stTextArea"] label{
  font-family: 'IBM Plex Mono', monospace !important;
  font-size: 0.6rem !important;
  letter-spacing: 0.24em !important;
  text-transform: uppercase !important;
  color: #4a5568 !important;
}
div[data-testid="stTextArea"] textarea{
  background: #F0F4F8 !important;
  border: 1px solid rgba(245,232,216,0.1) !important;
  border-radius: 2px !important;
  color: #1a202c !important;
  font-family: 'IBM Plex Mono', monospace !important;
  font-size: 0.88rem !important;
}
div[data-testid="stTextArea"] textarea:focus{
  border-color: #FF6B1A !important;
  outline: none !important;
}
div[data-testid="stTextArea"] textarea::placeholder{ color: #0F172A !important; }

/* ═══════ SELECTBOX ═══════ */
div[data-testid="stSelectbox"] label{
  font-family: 'IBM Plex Mono', monospace !important;
  font-size: 0.6rem !important;
  letter-spacing: 0.24em !important;
  text-transform: uppercase !important;
  color: #4a5568 !important;
}
div[data-testid="stSelectbox"] > div > div{
  background: #F0F4F8 !important;
  border: 1px solid rgba(245,232,216,0.1) !important;
  border-radius: 2px !important;
  color: #1a202c !important;
  font-family: 'IBM Plex Mono', monospace !important;
}

/* ═══════ TOGGLE ═══════ */
div[data-testid="stToggle"] label{
  color: #1a202c !important;
  font-family: 'IBM Plex Sans', sans-serif !important;
  font-weight: 500 !important;
  font-size: 0.9rem !important;
}

/* ═══════ FILE UPLOADER (Arctic Frost) ═══════ */
[data-testid="stFileUploader"]{
  background: #F0F9FF !important;
  border: 1px dashed #BAE6FD !important;
  border-radius: 8px !important;
}
[data-testid="stFileUploader"] label{
  font-family: 'JetBrains Mono', monospace !important;
  font-size: 0.6rem !important;
  letter-spacing: 0.24em !important;
  text-transform: uppercase !important;
  color: #0284C7 !important;
  padding: 6px 10px 2px !important;
  display: block !important;
}
[data-testid="stFileUploaderDropzone"] span{
  color: #0369A1 !important;
  font-family: 'JetBrains Mono', monospace !important;
}
/* Uploaded-file chip — was amber, now ice blue (no more black/sandal look) */
[data-testid="stFileUploaderFile"]{
  background: #FFFFFF !important;
  border: 1px solid #BAE6FD !important;
  border-radius: 8px !important;
  font-family: 'JetBrains Mono', monospace !important;
  font-size: 0.8rem !important;
  color: #0C4A6E !important;
}
[data-testid="stFileUploaderFile"] *{ color: #0C4A6E !important; }
[data-testid="stFileUploaderDeleteBtn"] svg{ fill: #0284C7 !important; }

/* ═══════ DATAFRAME (Bloomberg-style table) ═══════ */
div[data-testid="stDataFrame"]{
  border: 1px solid rgba(245,232,216,0.08) !important;
  border-radius: 2px !important;
  overflow: hidden !important;
}
div[data-testid="stDataFrame"] table{
  font-family: 'IBM Plex Mono', monospace !important;
  font-size: 0.82rem !important;
}
div[data-testid="stDataFrame"] th{
  background: #F8FAFC !important;
  color: #4a5568 !important;
  font-size: 0.6rem !important;
  letter-spacing: 0.22em !important;
  text-transform: uppercase !important;
  border: none !important;
  border-bottom: 1px solid rgba(255,107,26,0.25) !important;
  font-weight: 500 !important;
}
div[data-testid="stDataFrame"] td{
  color: #1a202c !important;
  border-color: rgba(245,232,216,0.05) !important;
}

/* ═══════ STATUS / ALERTS / EXPANDER ═══════ */
div[data-testid="stAlert"]{
  border-radius: 2px !important;
  font-family: 'IBM Plex Sans', sans-serif !important;
  font-size: 0.85rem !important;
  border-left-width: 3px !important;
}
div[data-testid="stStatus"]{
  background: #F8FAFC !important;
  border: 1px solid rgba(255,107,26,0.25) !important;
  border-radius: 2px !important;
  font-family: 'IBM Plex Mono', monospace !important;
}
[data-testid="stExpander"] summary{
  font-family: 'IBM Plex Mono', monospace !important;
  font-size: 0.76rem !important;
  letter-spacing: 0.12em !important;
  color: #718096 !important;
  background: #F8FAFC !important;
  border-radius: 2px !important;
  text-transform: uppercase !important;
}
.stSpinner > div{ border-top-color: #FF6B1A !important; }

/* ═══════ SCROLLBAR ═══════ */
::-webkit-scrollbar{ width: 6px; height: 6px; }
::-webkit-scrollbar-track{ background: #FFFFFF; }
::-webkit-scrollbar-thumb{ background: rgba(255,107,26,0.25); border-radius: 0; }
::-webkit-scrollbar-thumb:hover{ background: rgba(255,107,26,0.45); }

/* ═══════ CODE BLOCKS ═══════ */
code, pre, [data-testid="stCode"]{
  font-family: 'IBM Plex Mono', monospace !important;
  background: #FFFFFF !important;
  color: #FFD23F !important;
  border: 1px solid rgba(245,232,216,0.08) !important;
  border-radius: 2px !important;
}

/* ═══════ CUSTOM UTILITY CLASSES ═══════ */
/* Use these in components.html(...) calls for signature Mission Control elements */

/* Case ID pill (forensic serial number) */
.mc-case-id{
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.65rem;
  letter-spacing: 0.22em;
  color: #4a5568;
  text-transform: uppercase;
}

/* Data readout (monospace label + value pair) */
.mc-readout{
  display: flex; justify-content: space-between; align-items: center;
  font-family: 'JetBrains Mono', monospace; font-size: 0.8rem;
  padding: 8px 12px; margin: 3px 0; border-radius: 6px;
  background: rgba(240,249,255,0.5); border: 1px solid #E0F2FE;
}
.mc-readout .k{ color: #0C4A6E; letter-spacing: 0.1em; text-transform: uppercase; font-size: 0.68rem; font-weight: 600; }
.mc-readout .v{ color: #0F172A; font-weight: 500; font-size: 0.78rem; }
.mc-readout .v.amber{ color: #0284C7; }
.mc-readout .v.green{ color: #16A34A; }
.mc-readout .v.red  { color: #DC2626; }

/* Vertical risk bar (Bloomberg-style) */
.mc-risk-bar{
  display: inline-flex; align-items: flex-end; gap: 1px; height: 28px; margin-left: 8px;
}
.mc-risk-bar .seg{ width: 4px; background: rgba(245,232,216,0.08); }
.mc-risk-bar .seg.on{ background: #FF6B1A; }
.mc-risk-bar .seg.crit{ background: #E63946; }

/* Section header with serial number */
.mc-section-header{
  display: flex; align-items: center; gap: 12px;
  border-bottom: 2px solid #E0F2FE;
  padding-bottom: 10px; margin-bottom: 14px; margin-top: 8px;
}
.mc-section-header h2{
  font-family: 'Poppins', sans-serif; font-weight: 700;
  font-size: 1.05rem; color: #0C4A6E; margin: 0; letter-spacing: 0.01em;
}
.mc-section-header .sn{
  font-family: 'JetBrains Mono', monospace; font-size: 0.62rem;
  letter-spacing: 0.15em; color: #0284C7; text-transform: uppercase;
  background: rgba(2,132,199,0.08); padding: 3px 10px; border-radius: 12px;
}

</style>
"""


# ═══════ Header bar with live UTC millisecond clock ═══════
# The signature "mission control" moving detail — live clock that ticks.
MISSION_HEADER_HTML = """
<div style="
  display: flex; align-items: center; justify-content: space-between;
  padding: 10px 20px; margin: -0.6rem -1.75rem 1rem;
  background: #FFFFFF; border-bottom: 1px solid rgba(255,107,26,0.18);
  font-family: 'IBM Plex Mono', monospace;
">
  <div style="display: flex; align-items: center; gap: 24px;">
    <div style="display: flex; align-items: center; gap: 10px;">
      <div style="width: 8px; height: 8px; background: #9ACD32; border-radius: 50%;
                  animation: mc-pulse 1.5s ease-in-out infinite;"></div>
      <span style="color: #1a202c; font-size: 0.78rem; font-weight: 500; letter-spacing: 0.06em;">
        AI-DTCTM · MISSION CONTROL
      </span>
    </div>
    <span style="color: #4a5568; font-size: 0.68rem; letter-spacing: 0.18em;">v20.0.0</span>
  </div>
  <div style="display: flex; gap: 20px; align-items: center;">
    <div style="display: flex; flex-direction: column; align-items: flex-end;">
      <span style="color: #4a5568; font-size: 0.54rem; letter-spacing: 0.24em; text-transform: uppercase;">UTC</span>
      <span id="mc-utc-clock" style="color: #FF6B1A; font-size: 0.88rem; font-weight: 500; letter-spacing: 0.04em;">--:--:--.---</span>
    </div>
    <div style="width: 1px; height: 28px; background: rgba(245,232,216,0.1);"></div>
    <div style="display: flex; flex-direction: column; align-items: flex-end;">
      <span style="color: #4a5568; font-size: 0.54rem; letter-spacing: 0.24em; text-transform: uppercase;">UPTIME</span>
      <span id="mc-uptime" style="color: #9ACD32; font-size: 0.88rem; font-weight: 500;">00:00:00</span>
    </div>
  </div>
</div>
<style>
@keyframes mc-pulse{
  0%, 100%{ opacity: 1; }
  50%     { opacity: 0.35; }
}
</style>
<script>
(function(){
  const start = Date.now();
  function tick(){
    const d = new Date();
    const pad = (n, w=2) => String(n).padStart(w,'0');
    const utc = pad(d.getUTCHours()) + ':' + pad(d.getUTCMinutes()) + ':' + pad(d.getUTCSeconds()) + '.' + pad(d.getUTCMilliseconds(), 3);
    const clock = document.getElementById('mc-utc-clock');
    if(clock) clock.textContent = utc;
    const elapsed = Math.floor((Date.now() - start) / 1000);
    const h = pad(Math.floor(elapsed/3600));
    const m = pad(Math.floor((elapsed%3600)/60));
    const s = pad(elapsed%60);
    const up = document.getElementById('mc-uptime');
    if(up) up.textContent = h + ':' + m + ':' + s;
    requestAnimationFrame(tick);
  }
  tick();
})();
</script>
"""


def inject_css() -> None:
    """Phase 3f - skip dark CSS entirely when light is active."""
    if get_active_theme() == "light":
        st.markdown(LIGHT_THEME_CSS, unsafe_allow_html=True)
    else:
        st.markdown(DASHBOARD_CSS, unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════
# LIGHT THEME OVERLAY — Phase 2c
# Applied AFTER dark theme to override colours where appropriate.
# Inspired by CheckPhish.bolster.ai (clean, white, professional)
# ══════════════════════════════════════════════════════════════════════
# ══════════════════════════════════════════════════════════════════════
# PHASE 3a — PREMIUM WHITE THEME
# ══════════════════════════════════════════════════════════════════════
# Design language: medical/laboratory software vibe.
#   - Pure white #FFFFFF base (not off-white)
#   - Slate-900 #0F172A primary text (high contrast)
#   - Royal Blue #2563EB primary accent (replaces amber for light mode)
#   - Amber #FF6B1A retained for critical alerts only (semantic)
#   - Sharp borders (#E2E8F0) — no gradients, no glow, no shadows
#   - Inter for UI body, JetBrains Mono for data/code
#   - Micro-interactions: subtle, fast (180-220ms cubic-bezier)
#
# Anti-AI-slop principles applied:
#   - No purple/teal Gemini palette
#   - No drop-shadows on cards (only 1px borders)
#   - No emoji buttons, no "✨ Sparkles ✨" labels
#   - Semantic colour: green=safe, amber=warn, red=critical (not decorative)
# ══════════════════════════════════════════════════════════════════════
LIGHT_THEME_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700;800&family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@300;400;500;600;700&display=swap');

/* ════════════ BASE ENHANCED TYPOGRAPHY ════════════ */
html, body, .stApp, [data-testid="stAppViewContainer"], section.main,
[data-testid="stMain"] {
  background: #F8FBFF !important;
  background-image: none !important;
  color: #0C4A6E !important;
  font-family: 'Poppins', 'Inter', -apple-system, BlinkMacSystemFont, system-ui, sans-serif !important;
  font-feature-settings: 'cv02', 'cv03', 'cv04', 'cv11' !important;  /* Inter optical alts */
  -webkit-font-smoothing: antialiased !important;
  letter-spacing: 0.2px !important;
  line-height: 1.6 !important;
}

/* Enhanced Typography */
h1, h2, h3, h4, h5, h6 {
  font-family: 'Poppins', sans-serif !important;
  font-weight: 700 !important;
  letter-spacing: 0.5px !important;
  color: #0C4A6E !important;
}

h1 { font-size: 2.4rem !important; font-weight: 800 !important; margin-bottom: 1.5rem !important; }
h2 { font-size: 1.9rem !important; font-weight: 800 !important; margin-top: 2rem !important; margin-bottom: 1rem !important; }
h3 { font-size: 1.5rem !important; font-weight: 700 !important; margin-top: 1.5rem !important; }
h4 { font-size: 1.2rem !important; font-weight: 700 !important; }

strong, b { font-weight: 700 !important; color: #0C4A6E !important; }

.main .block-container {
  max-width: 1280px !important;
  padding: 1.25rem 2rem 3rem !important;
}

/* Code, mono, data — JetBrains Mono with proper ligature feel */
code, pre, kbd, samp, [class*="language-"], .stCodeBlock,
[data-testid="stCodeBlock"] code {
  font-family: 'JetBrains Mono', 'SF Mono', 'Cascadia Code', monospace !important;
  font-feature-settings: 'liga' 1, 'calt' 1 !important;
}

/* Hide Streamlit chrome */
[data-testid="stDecoration"] { display: none !important; }
[data-testid="stToolbar"] [data-testid="stActionButton"] { visibility: hidden !important; }
#MainMenu, footer { visibility: hidden !important; }

/* ════════════ TYPOGRAPHY HIERARCHY ════════════ */
h1, h2, h3, h4, h5, h6 {
  color: #0C4A6E !important;
  font-family: 'Inter', sans-serif !important;
  letter-spacing: -0.025em !important;
  font-weight: 700 !important;
  line-height: 1.2 !important;
}
h1 { font-size: 1.875rem !important; margin-bottom: 0.5rem !important; }
h2 { font-size: 1.5rem !important; margin-bottom: 0.5rem !important; }
h3 { font-size: 1.25rem !important; }

.stMarkdown, .stMarkdown p, .stMarkdown li {
  color: #334155 !important;
  font-size: 0.9375rem !important;
  line-height: 1.6 !important;
}
[data-testid="stCaptionContainer"], .stCaption,
[data-testid="stCaption"] {
  color: #64748B !important;
  font-size: 0.8125rem !important;
}

/* ════════════ SIDEBAR ════════════ */
[data-testid="stSidebar"] {
  background: #F0F9FF !important;
  border-right: 1px solid #E0F2FE !important;
  box-shadow: none !important;
}
[data-testid="stSidebar"] > div {
  padding-top: 1rem !important;
}

/* "Operator Console" heading in sidebar */
[data-testid="stSidebar"] h1, [data-testid="stSidebar"] h2,
[data-testid="stSidebar"] h3 {
  color: #0F172A !important;
  font-size: 1rem !important;
  font-weight: 700 !important;
  letter-spacing: -0.01em !important;
  margin-bottom: 4px !important;
}

[data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p,
[data-testid="stSidebar"] .stMarkdown p {
  color: #475569 !important;
  font-size: 0.75rem !important;
}

/* Sidebar nav radio — premium, sharp, no gradients */
[data-testid="stSidebar"] [data-testid="stRadio"] > label {
  display: none !important;
}
[data-testid="stSidebar"] [data-testid="stRadio"] [role="radiogroup"] {
  gap: 1px !important;
  margin-top: 4px !important;
}
[data-testid="stSidebar"] [data-testid="stRadio"] label[data-baseweb="radio"] {
  padding: 9px 12px !important;
  margin: 0 !important;
  border-radius: 6px !important;
  border: 1px solid transparent !important;
  background: transparent !important;
  cursor: pointer !important;
  transition: all 180ms cubic-bezier(0.4, 0, 0.2, 1) !important;
  position: relative !important;
}
[data-testid="stSidebar"] [data-testid="stRadio"] label[data-baseweb="radio"]:hover {
  background: #E0F2FE !important;
  border-color: #BAE6FD !important;
}
[data-testid="stSidebar"] [data-testid="stRadio"] label[data-baseweb="radio"]:has(input:checked) {
  background: #BAE6FD !important;
  border-color: #7DD3FC !important;
  box-shadow: inset 3px 0 0 #0284C7 !important;
}
/* Hide default radio dot */
[data-testid="stSidebar"] [data-testid="stRadio"] label[data-baseweb="radio"] > div:first-child {
  display: none !important;
}
[data-testid="stSidebar"] [data-testid="stRadio"] label[data-baseweb="radio"] > div:last-child {
  font-family: 'Inter', sans-serif !important;
  font-size: 0.875rem !important;
  font-weight: 500 !important;
  color: #475569 !important;
  letter-spacing: -0.005em !important;
  line-height: 1.3 !important;
  transition: color 180ms !important;
}
[data-testid="stSidebar"] [data-testid="stRadio"] label[data-baseweb="radio"]:hover > div:last-child {
  color: #0F172A !important;
}
[data-testid="stSidebar"] [data-testid="stRadio"] label[data-baseweb="radio"]:has(input:checked) > div:last-child {
  color: #0C4A6E !important;
  font-weight: 600 !important;
}

/* ════════════ TEXT INPUTS — Phase 3d high specificity ════════════ */
.stTextInput input, .stTextArea textarea, [data-baseweb="input"] input,
div[data-testid="stTextInput"] input,
div[data-testid="stNumberInput"] input,
div[data-testid="stTextArea"] textarea {
  background: #FFFFFF !important;
  background-color: #FFFFFF !important;
  color: #0F172A !important;
  border: 1px solid #CBD5E1 !important;
  border-radius: 6px !important;
  font-family: 'Inter', sans-serif !important;
  font-size: 0.9375rem !important;
  padding: 10px 14px !important;
  transition: all 180ms !important;
}
.stTextInput input:hover, .stTextArea textarea:hover,
div[data-testid="stTextInput"] input:hover,
div[data-testid="stNumberInput"] input:hover {
  border-color: #94A3B8 !important;
}
.stTextInput input:focus, .stTextArea textarea:focus,
div[data-testid="stTextInput"] input:focus,
div[data-testid="stNumberInput"] input:focus {
  border-color: #0284C7 !important;
  box-shadow: 0 0 0 3px rgba(2, 132, 199, 0.12) !important;
  outline: none !important;
}
div[data-testid="stTextInput"] input::placeholder,
div[data-testid="stNumberInput"] input::placeholder {
  color: #0F172A !important;
}
/* Number input +/- buttons */
div[data-testid="stNumberInput"] button {
  background: #F1F5F9 !important;
  color: #475569 !important;
  border: 1px solid #CBD5E1 !important;
}

/* Selectbox + dropdowns - Phase 3k full contrast */
[data-baseweb="select"] {
  background: #FFFFFF !important;
}
[data-baseweb="select"] > div {
  background: #FFFFFF !important;
  border: 1px solid #CBD5E1 !important;
  border-radius: 6px !important;
}
[data-baseweb="select"] > div > div,
[data-baseweb="select"] [class*="ValueContainer"] *,
[data-baseweb="select"] [class*="SingleValue"] * {
  color: #0F172A !important;
  font-family: 'Inter', sans-serif !important;
  font-weight: 500 !important;
}
/* Dropdown popup options */
[data-baseweb="popover"] [role="listbox"],
[data-baseweb="menu"] {
  background: #FFFFFF !important;
  border: 1px solid #E2E8F0 !important;
  border-radius: 8px !important;
  box-shadow: 0 4px 12px rgba(15,23,42,0.10) !important;
}
[data-baseweb="popover"] [role="option"],
[data-baseweb="menu"] li {
  color: #0F172A !important;
  font-family: 'Inter', sans-serif !important;
  background: #FFFFFF !important;
  padding: 10px 14px !important;
}
[data-baseweb="popover"] [role="option"]:hover,
[data-baseweb="menu"] li:hover,
[data-baseweb="popover"] [role="option"][aria-selected="true"] {
  background: #E0F2FE !important;
  color: #0C4A6E !important;
}

/* ════════════ BUTTONS ════════════ */
.stButton > button[kind="primary"], .stDownloadButton > button[kind="primary"] {
  background: #0284C7 !important;
  color: #FFFFFF !important;
  border: 1px solid #0284C7 !important;
  border-radius: 6px !important;
  font-weight: 600 !important;
  font-family: 'Inter', sans-serif !important;
  font-size: 0.875rem !important;
  letter-spacing: -0.005em !important;
  padding: 9px 18px !important;
  transition: all 180ms !important;
  box-shadow: none !important;
}
.stButton > button[kind="primary"]:hover {
  background: #0369A1 !important;
  border-color: #0369A1 !important;
  transform: translateY(-1px) !important;
}
.stButton > button[kind="primary"]:active {
  transform: translateY(0) !important;
}

.stButton > button:not([kind="primary"]),
.stDownloadButton > button:not([kind="primary"]) {
  background: #FFFFFF !important;
  color: #334155 !important;
  border: 1px solid #CBD5E1 !important;
  border-radius: 6px !important;
  font-weight: 500 !important;
  font-family: 'Inter', sans-serif !important;
  font-size: 0.875rem !important;
  padding: 8px 16px !important;
  transition: all 180ms !important;
}
.stButton > button:not([kind="primary"]):hover {
  background: #F8FAFC !important;
  border-color: #94A3B8 !important;
  color: #0F172A !important;
}

/* ════════════ TABS ════════════ */
.stTabs [data-baseweb="tab-list"],
div[data-baseweb="tab-list"] {
  background: transparent !important;
  border-bottom: 1px solid #E2E8F0 !important;
  gap: 0 !important;
  padding: 0 !important;
}
.stTabs [data-baseweb="tab"],
button[data-baseweb="tab"] {
  color: #64748B !important;
  background: transparent !important;
  font-family: 'Inter', sans-serif !important;
  font-size: 0.8125rem !important;
  font-weight: 600 !important;
  letter-spacing: 0.02em !important;
  padding: 12px 18px !important;
  border-bottom: 2px solid transparent !important;
  margin-bottom: -1px !important;
  transition: all 180ms !important;
}
.stTabs [data-baseweb="tab"]:hover,
button[data-baseweb="tab"]:hover {
  color: #0F172A !important;
}
.stTabs [aria-selected="true"],
button[data-baseweb="tab"][aria-selected="true"] {
  color: #0284C7 !important;
  border-bottom: 2px solid #0284C7 !important;
  border-bottom-color: #0284C7 !important;
}

/* ════════════ CARDS / EXPANDERS / METRICS ════════════ */
[data-testid="stMetric"] {
  background: #FFFFFF !important;
  border: 1px solid #E0F2FE !important;
  border-radius: 8px !important;
  padding: 14px 18px !important;
  box-shadow: none !important;
}
[data-testid="stMetricLabel"] {
  color: #64748B !important;
  font-size: 0.6875rem !important;
  font-weight: 600 !important;
  letter-spacing: 0.06em !important;
  text-transform: uppercase !important;
}
[data-testid="stMetricValue"] {
  color: #0F172A !important;
  font-size: 1.625rem !important;
  font-weight: 700 !important;
  font-family: 'Inter', sans-serif !important;
  letter-spacing: -0.025em !important;
}

div[data-testid="stExpander"] {
  background: #FFFFFF !important;
  border: 1px solid #E0F2FE !important;
  border-radius: 8px !important;
  box-shadow: none !important;
}
div[data-testid="stExpander"] summary {
  color: #0C4A6E !important;
  font-weight: 600 !important;
}

/* ════════════ ALERTS ════════════ */
.stAlert, [data-baseweb="notification"] {
  background: #FFFFFF !important;
  border-radius: 8px !important;
  border: 1px solid #E2E8F0 !important;
}
[data-testid="stAlertContentInfo"] {
  background: #E0F2FE !important;
  border-left: 3px solid #0284C7 !important;
  color: #0C4A6E !important;
}
[data-testid="stAlertContentSuccess"] {
  background: #F0FDF4 !important;
  border-left: 3px solid #16A34A !important;
  color: #14532D !important;
}
[data-testid="stAlertContentWarning"] {
  background: #FFFBEB !important;
  border-left: 3px solid #CA8A04 !important;
  color: #713F12 !important;
}
[data-testid="stAlertContentError"] {
  background: #FEF2F2 !important;
  border-left: 3px solid #DC2626 !important;
  color: #7F1D1D !important;
}

/* ════════════ DATAFRAMES / TABLES ════════════ */
[data-testid="stDataFrame"] {
  border: 1px solid #E2E8F0 !important;
  border-radius: 8px !important;
}

/* ════════════ FILE UPLOADER ════════════ */
[data-testid="stFileUploader"] section {
  background: #F0F9FF !important;
  border: 2px dashed #BAE6FD !important;
  border-radius: 8px !important;
  transition: all 180ms !important;
}
[data-testid="stFileUploader"] section:hover {
  border-color: #0284C7 !important;
  background: #E0F2FE !important;
}
[data-testid="stFileUploader"] button {
  background: #0284C7 !important;
  color: #FFFFFF !important;
  border: none !important;
  border-radius: 6px !important;
  font-weight: 600 !important;
}

/* ════════════ PROGRESS BAR ════════════ */
.stProgress > div > div > div {
  background: linear-gradient(90deg, #0284C7 0%, #38BDF8 100%) !important;
  border-radius: 4px !important;
}
.stProgress > div > div {
  background: #E2E8F0 !important;
  border-radius: 4px !important;
}

/* ════════════ CHECKBOX / RADIO (main area) ════════════ */
.stCheckbox label {
  color: #334155 !important;
  font-family: 'Inter', sans-serif !important;
  font-size: 0.875rem !important;
}

/* ════════════ MISSION CONTROL HEADER ════════════ */
/* Catch the embedded HTML header */
.mc-header, [class*="mc-header"], iframe[title*="Mission"] {
  background: #FFFFFF !important;
  border-bottom: 1px solid #E2E8F0 !important;
}

/* ════════════ TICKER BAND ════════════ */
.mc-ticker-band {
  background: #F8FAFC !important;
  border-top: 1px solid #E2E8F0 !important;
  border-bottom: 1px solid #E2E8F0 !important;
}
.mc-ticker-event { color: #475569 !important; font-weight: 500 !important; }
.mc-ticker-event .verdict-ok   { color: #16A34A !important; font-weight: 600 !important; }
.mc-ticker-event .verdict-warn { color: #CA8A04 !important; font-weight: 600 !important; }
.mc-ticker-event .verdict-crit { color: #DC2626 !important; font-weight: 600 !important; }
.mc-ticker-event .verdict-info { color: #2563EB !important; font-weight: 600 !important; }

/* ════════════ SECTION HEADERS / READOUTS ════════════ */
.mc-section-header > div {
  color: #0C4A6E !important;
  font-family: 'Poppins', sans-serif !important;
  font-weight: 700 !important;
  letter-spacing: 0.01em !important;
}
.mc-section-header > span {
  color: #0284C7 !important;
  font-family: 'JetBrains Mono', monospace !important;
  font-size: 0.65rem !important;
  letter-spacing: 0.12em !important;
  font-weight: 600 !important;
  background: rgba(2,132,199,0.08) !important;
  padding: 3px 10px !important;
  border-radius: 12px !important;
}

.mc-readout-row {
  border-bottom: 1px solid #E0F2FE !important;
}
.mc-readout-label {
  color: #0C4A6E !important;
  font-family: 'JetBrains Mono', monospace !important;
  font-size: 0.72rem !important;
  font-weight: 600 !important;
  letter-spacing: 0.08em !important;
  text-transform: uppercase !important;
}
.mc-readout-value {
  color: #0F172A !important;
  font-family: 'JetBrains Mono', monospace !important;
  font-size: 0.82rem !important;
  font-weight: 600 !important;
}
.mc-readout-value.tone-amber  { color: #0284C7 !important; }
.mc-readout-value.tone-green  { color: #16A34A !important; }
.mc-readout-value.tone-red    { color: #DC2626 !important; }
.mc-readout-value.tone-yellow { color: #CA8A04 !important; }

/* ════════════ SPARKLINE / KPI CARDS ════════════ */
.mc-sparkline-card {
  background: #FFFFFF !important;
  border: 1px solid #E2E8F0 !important;
  border-radius: 8px !important;
  box-shadow: none !important;
}
.mc-sparkline-card .label {
  color: #64748B !important;
  font-size: 0.6875rem !important;
  font-weight: 600 !important;
  letter-spacing: 0.06em !important;
  text-transform: uppercase !important;
}
.mc-sparkline-card .value {
  color: #0F172A !important;
  font-size: 1.875rem !important;
  font-weight: 700 !important;
  font-family: 'Inter', sans-serif !important;
}
.mc-sparkline-card svg path {
  stroke: #2563EB !important;
}

/* ════════════ ACTIVITY FEED ════════════ */
.mc-activity-feed {
  background: #FFFFFF !important;
  border: 1px solid #E2E8F0 !important;
  border-radius: 8px !important;
}
.mc-activity-row {
  border-bottom: 1px solid #F1F5F9 !important;
  padding: 12px 16px !important;
}
.mc-activity-row .ts {
  color: #94A3B8 !important;
  font-family: 'JetBrains Mono', monospace !important;
  font-size: 0.75rem !important;
}
.mc-activity-row .source {
  color: #2563EB !important;
  font-weight: 600 !important;
  font-size: 0.75rem !important;
  letter-spacing: 0.05em !important;
}
.mc-activity-row .event { color: #334155 !important; font-size: 0.875rem !important; }

/* ════════════ VERDICT BANNER ════════════ */
.mc-verdict-banner {
  background: #FFFFFF !important;
  border: 1px solid #E2E8F0 !important;
  border-radius: 8px !important;
  box-shadow: none !important;
}
.mc-verdict-clean   { border-left: 4px solid #16A34A !important; }
.mc-verdict-warn    { border-left: 4px solid #CA8A04 !important; }
.mc-verdict-crit    { border-left: 4px solid #DC2626 !important; }
.mc-verdict-unknown { border-left: 4px solid #64748B !important; }

/* ════════════ SOURCE PILL ════════════ */
.mc-source-pill {
  background: #FFFFFF !important;
  border: 1px solid #E2E8F0 !important;
  border-radius: 6px !important;
  padding: 10px 14px !important;
  transition: all 180ms !important;
}
.mc-source-pill:hover {
  border-color: #CBD5E1 !important;
  background: #F8FAFC !important;
}
.mc-source-pill .name { color: #0F172A !important; font-weight: 600 !important; }
.mc-source-pill .meta { color: #64748B !important; }

/* ════════════ MISC OVERRIDES (catch ALL dark inline styles) ════════════ */
/* Phase 3c: aggressive matching — handle every spacing / casing variant */
[style*="background: #F8FAFC"], [style*="background:#F8FAFC"],
[style*="background: #F0F4F8"], [style*="background:#F0F4F8"],
[style*="background: #FFFFFF"], [style*="background:#FFFFFF"],
[style*="background: #14111A"], [style*="background:#14111A"],
[style*="background: #1C1619"], [style*="background:#1C1619"],
[style*="background: #1E1A1D"], [style*="background:#1E1A1D"] {
  background: #FFFFFF !important;
  border: 1px solid #E2E8F0 !important;
  color: #0F172A !important;
}

/* Light / muted-grey inline backgrounds — keep light but adjust */
[style*="background:rgba(255,107,26,0.05)"],
[style*="background: rgba(255,107,26,0.05)"],
[style*="background:rgba(255,107,26,0.06)"],
[style*="background: rgba(255,107,26,0.06)"],
[style*="background:rgba(255,107,26,0.08)"],
[style*="background: rgba(255,107,26,0.08)"] {
  background: rgba(37,99,235,0.04) !important;
}

/* Text colour overrides - dark theme creme/amber → slate */
[style*="color: #1a202c"], [style*="color:#1a202c"] { color: #0F172A !important; }
[style*="color: #718096"], [style*="color:#718096"] { color: #475569 !important; }
[style*="color: #4a5568"], [style*="color:#4a5568"] { color: #64748B !important; }
[style*="color: #2d3748"], [style*="color:#2d3748"] { color: #94A3B8 !important; }
[style*="color: #FF6B1A"], [style*="color:#FF6B1A"] { color: #2563EB !important; }

/* Keep semantic green/red/yellow but darken for white-bg contrast */
[style*="color: #9ACD32"], [style*="color:#9ACD32"] { color: #16A34A !important; }
[style*="color: #FFD23F"], [style*="color:#FFD23F"] { color: #CA8A04 !important; }
[style*="color: #E63946"], [style*="color:#E63946"] { color: #DC2626 !important; }

/* Borders */
[style*="border-left: 2px solid #FF6B1A"],
[style*="border-left:2px solid #FF6B1A"] {
  border-left-color: #2563EB !important;
}
[style*="border-left: 3px solid #FF6B1A"],
[style*="border-left:3px solid #FF6B1A"] {
  border-left-color: #2563EB !important;
}
[style*="border-left: 2px solid #9ACD32"],
[style*="border-left:2px solid #9ACD32"] {
  border-left-color: #16A34A !important;
}
[style*="border-left: 3px solid #9ACD32"],
[style*="border-left:3px solid #9ACD32"] {
  border-left-color: #16A34A !important;
}
[style*="border-left: 2px solid #E63946"],
[style*="border-left:2px solid #E63946"] {
  border-left-color: #DC2626 !important;
}
[style*="border-left: 3px solid #E63946"],
[style*="border-left:3px solid #E63946"] {
  border-left-color: #DC2626 !important;
}
[style*="border-left: 2px solid #FFD23F"],
[style*="border-left:2px solid #FFD23F"] {
  border-left-color: #CA8A04 !important;
}

/* Code-style inline blocks */
[style*="background:rgba(255,107,26,0.1)"],
[style*="background: rgba(255,107,26,0.1)"] {
  background: rgba(37,99,235,0.10) !important;
  color: #1E40AF !important;
}

/* Top "AI-DTCTM Mission Control" header iframe (legacy) */
iframe[title*="streamlit_components"] {
  display: none !important;   /* Phase 3b removed call but iframe might persist */
}

/* Phase 3d - kill the dark Streamlit auto header that was overlaying */
header[data-testid="stHeader"] {
  background: #FFFFFF !important;
  background-color: #FFFFFF !important;
  border-bottom: 1px solid #E2E8F0 !important;
  backdrop-filter: none !important;
  display: none !important;   /* nuclear: just hide it entirely */
}

/* Force the dark gradient background OFF on main app shell */
.stApp::before, [data-testid="stApp"]::before {
  background: #FFFFFF !important;
  background-image: none !important;
}

/* Black bar at top often comes from default app top padding region */
[data-testid="stAppViewContainer"] > section:first-child {
  background: #FFFFFF !important;
}

/* If anything still dark - force */
[data-testid="stMain"]::before, [data-testid="stMain"]::after {
  background: #FFFFFF !important;
}

/* Operator Console sidebar header — readable contrast */
[data-testid="stSidebar"] > div > div > div:first-child {
  color: #0F172A !important;
}
[data-testid="stSidebar"] [style*="color: #1a202c"],
[data-testid="stSidebar"] [style*="color:#1a202c"] {
  color: #0F172A !important;
}
[data-testid="stSidebar"] [style*="color: #4a5568"],
[data-testid="stSidebar"] [style*="color:#4a5568"] {
  color: #64748B !important;
}

/* "11 / 12" API endpoints — Royal Blue */
[data-testid="stSidebar"] [style*="color: #FF6B1A; font-weight: 500;"] {
  color: #2563EB !important;
}

/* Checkboxes — readable on white */
[data-testid="stCheckbox"] label {
  color: #334155 !important;
}
[data-testid="stCheckbox"] label > span:first-child {
  background: #FFFFFF !important;
  border: 1.5px solid #CBD5E1 !important;
  border-radius: 4px !important;
}
[data-testid="stCheckbox"] label > span:first-child:has(input:checked) {
  background: #2563EB !important;
  border-color: #2563EB !important;
}

/* File uploader 'Upload' button → Royal Blue */
[data-testid="stFileUploader"] button[kind="secondary"],
[data-testid="stFileUploader"] button {
  background: #2563EB !important;
  color: #FFFFFF !important;
  border: 1px solid #2563EB !important;
}

/* Critical/red kept as red (semantic) */
[style*="border-left:3px solid #E63946"],
[style*="border-left:2px solid #E63946"] {
  border-left-color: #DC2626 !important;
}

/* ════════════ TAB CONTENT FADE-IN (Phase 3e) ════════════ */
@keyframes mc-tab-content-in {
  from { opacity: 0; transform: translateY(6px); }
  to   { opacity: 1; transform: translateY(0); }
}
div[data-baseweb="tab-panel"] {
  animation: mc-tab-content-in 240ms cubic-bezier(0.4, 0, 0.2, 1) backwards !important;
}

/* ════════════ SOURCE PILL STAGGER ENTRY (Phase 3e) ════════════ */
.mc-source-pill,
[style*="font-family: 'JetBrains Mono', monospace; margin-bottom: 6px"] {
  animation: mc-tab-content-in 320ms cubic-bezier(0.4, 0, 0.2, 1) backwards !important;
}

/* ════════════ URL SCANNER HERO IMAGE STRIP (Phase 3e) ════════════ */
.mc-url-hero {
  background:
    linear-gradient(135deg, rgba(37,99,235,0.04) 0%, rgba(255,255,255,0) 60%),
    radial-gradient(ellipse at top right, rgba(37,99,235,0.06), transparent 50%);
  border: 1px solid #E2E8F0;
  border-radius: 12px;
  padding: 18px 22px;
  margin-bottom: 14px;
  position: relative;
  overflow: hidden;
}
.mc-url-hero::before {
  content: '';
  position: absolute;
  top: 0; left: 0; right: 0; height: 2px;
  background: linear-gradient(90deg, transparent 0%, #2563EB 50%, transparent 100%);
  opacity: 0.5;
  animation: mc-hero-line 4s linear infinite;
}
@keyframes mc-hero-line {
  0%   { transform: translateX(-100%); }
  100% { transform: translateX(100%); }
}

/* ════════════ FORENSIC SCANNER HERO (Phase 3g) ════════════ */
.mc-forensic-hero {
  background:
    linear-gradient(135deg, rgba(37,99,235,0.05) 0%, rgba(255,255,255,0) 50%),
    radial-gradient(ellipse at top left, rgba(22,163,74,0.05), transparent 55%),
    radial-gradient(ellipse at bottom right, rgba(220,38,38,0.04), transparent 55%);
  border: 1px solid #E2E8F0;
  border-radius: 12px;
  padding: 20px 24px;
  margin-bottom: 14px;
  position: relative;
  overflow: hidden;
}
.mc-forensic-hero::before {
  content: '';
  position: absolute;
  inset: 0;
  background-image:
    radial-gradient(circle at 12% 30%, rgba(37,99,235,0.07) 0, transparent 8px),
    radial-gradient(circle at 78% 22%, rgba(22,163,74,0.07) 0, transparent 6px),
    radial-gradient(circle at 35% 78%, rgba(220,38,38,0.06) 0, transparent 5px),
    radial-gradient(circle at 88% 75%, rgba(202,138,4,0.06) 0, transparent 6px),
    radial-gradient(circle at 55% 40%, rgba(37,99,235,0.05) 0, transparent 4px);
  opacity: 0.65;
  animation: mc-forensic-particles 8s ease-in-out infinite alternate;
  pointer-events: none;
}
@keyframes mc-forensic-particles {
  0%   { transform: translateY(0) translateX(0); }
  50%  { transform: translateY(-3px) translateX(2px); }
  100% { transform: translateY(2px) translateX(-2px); }
}
.mc-forensic-hero::after {
  content: '';
  position: absolute;
  top: 0; left: 0; right: 0; height: 2px;
  background: linear-gradient(90deg,
    transparent 0%, #16A34A 25%, #2563EB 50%, #DC2626 75%, transparent 100%);
  opacity: 0.55;
  animation: mc-hero-line 5s linear infinite;
}

/* ════════════ FORENSIC SCANNING ANIMATION (Phase 3g) ════════════ */
.mc-scan-progress {
  background: #FFFFFF;
  border: 1px solid #E2E8F0;
  border-radius: 12px;
  padding: 18px 22px;
  margin: 12px 0 16px;
  position: relative;
  overflow: hidden;
}
.mc-scan-progress::before {
  content: '';
  position: absolute;
  top: 0; left: 0;
  height: 100%; width: 5px;
  background: linear-gradient(180deg, #16A34A 0%, #2563EB 50%, #16A34A 100%);
  background-size: 100% 200%;
  animation: mc-scan-line 1.6s ease-in-out infinite;
}
@keyframes mc-scan-line {
  0%, 100% { background-position: 0% 0%; }
  50%      { background-position: 0% 100%; }
}

/* ════════════ DIGITAL TWIN HERO (Phase 3h) ════════════ */
/* ════════════ SIDEBAR TOGGLE — minimal safe fix ════════════ */
[data-testid="stSidebar"] svg {
  color: #2563EB !important;
}
[data-testid="stSidebar"] [data-testid*="collapse"],
[data-testid="stSidebar"] header button {
  display: none !important;
}

/* ════════════ PHASE 3j SURGICAL FIXES ════════════ */

/* Drop ZIP / Drop APK / Drop files text — readable BLACK */
[data-testid="stFileUploader"] label,
[data-testid="stFileUploader"] label > div,
[data-testid="stFileUploader"] label p,
[data-testid="stFileUploaderDropzoneInstructions"],
[data-testid="stFileUploaderDropzoneInstructions"] span,
[data-testid="stFileUploaderDropzoneInstructions"] div {
  color: #0F172A !important;
  font-family: 'Inter', sans-serif !important;
  font-weight: 600 !important;
  font-size: 0.95rem !important;
  opacity: 1 !important;
}
[data-testid="stFileUploaderDropzoneInstructions"] small,
[data-testid="stFileUploaderDropzoneInstructions"] [data-testid="stFileUploaderInfoText"] {
  color: #64748B !important;
  font-weight: 500 !important;
  font-size: 0.78rem !important;
}

/* "Drag and drop file here" specific fix - was sandal/peach */
[data-testid="stFileUploader"] [data-testid="stFileDropzone"] *,
[data-testid="stFileUploaderDropzone"] * {
  color: #0F172A !important;
}
[data-testid="stFileUploaderDropzone"] {
  background: #FFFFFF !important;
  border: 2px dashed #CBD5E1 !important;
  border-radius: 10px !important;
}
[data-testid="stFileUploaderDropzone"]:hover {
  border-color: #2563EB !important;
  background: #F8FAFC !important;
}

/* Browse Files / Upload button inside uploader = Royal Blue */
[data-testid="stFileUploader"] section button,
[data-testid="stFileUploader"] button[kind="secondary"],
[data-testid="stFileUploader"] button {
  background: #2563EB !important;
  color: #FFFFFF !important;
  border: 1px solid #2563EB !important;
  font-weight: 600 !important;
  font-family: 'Inter', sans-serif !important;
}
[data-testid="stFileUploader"] section button *,
[data-testid="stFileUploader"] button * {
  color: #FFFFFF !important;
}

/* EICAR Inject button + Remove test button — proper colors */
[data-testid="stMain"] button[kind="secondary"] {
  background: #FFFFFF !important;
  color: #0F172A !important;
  border: 1px solid #CBD5E1 !important;
  font-weight: 600 !important;
}
[data-testid="stMain"] button[kind="secondary"]:hover {
  border-color: #2563EB !important;
  color: #1E40AF !important;
  background: #F8FAFC !important;
}
[data-testid="stMain"] button[kind="secondary"] * {
  color: inherit !important;
}

/* Expanders — Detected stack / Generated Dockerfile / Inject test threats */
div[data-testid="stExpander"] {
  background: #FFFFFF !important;
  border: 1px solid #E2E8F0 !important;
  border-radius: 10px !important;
  margin: 8px 0 !important;
  overflow: hidden !important;
  transition: all 200ms cubic-bezier(0.4, 0, 0.2, 1) !important;
}
div[data-testid="stExpander"]:hover {
  border-color: #CBD5E1 !important;
  box-shadow: 0 1px 3px rgba(15,23,42,0.06) !important;
}
div[data-testid="stExpander"] summary {
  background: linear-gradient(90deg, #F8FAFC 0%, #FFFFFF 100%) !important;
  padding: 12px 16px !important;
  font-family: 'Inter', sans-serif !important;
  font-weight: 600 !important;
  font-size: 0.9rem !important;
  color: #0F172A !important;
  cursor: pointer !important;
  border: none !important;
}
div[data-testid="stExpander"] summary:hover {
  background: linear-gradient(90deg, #EFF6FF 0%, #F8FAFC 100%) !important;
}
div[data-testid="stExpander"] summary * {
  color: #0F172A !important;
}
div[data-testid="stExpander"] [data-testid="stExpanderDetails"] {
  padding: 14px 16px !important;
  background: #FFFFFF !important;
  animation: mc-tab-content-in 220ms cubic-bezier(0.4, 0, 0.2, 1) !important;
}

/* JSON viewer / code block in expanders — keep dark theme but with blue accent */
[data-testid="stExpander"] pre,
[data-testid="stExpander"] code {
  background: #F8FAFC !important;
  color: #0F172A !important;
  border: 1px solid #E2E8F0 !important;
  border-radius: 6px !important;
}
.stJson, [data-testid="stJson"] {
  background: #F8FAFC !important;
  border: 1px solid #E2E8F0 !important;
  border-radius: 6px !important;
}

/* ════════════ MAIN-AREA RADIO READABLE (Phase 3i) ════════════ */
[data-testid="stMain"] [data-testid="stRadio"] > label,
[data-testid="stMain"] [data-testid="stRadio"] label > div {
  color: #0F172A !important;
  font-family: 'Inter', sans-serif !important;
  font-weight: 500 !important;
}
[data-testid="stMain"] [data-testid="stRadio"] > label {
  font-size: 0.95rem !important;
  font-weight: 600 !important;
  color: #0F172A !important;
  margin-bottom: 8px !important;
}
[data-testid="stMain"] [data-testid="stRadio"] [role="radiogroup"] {
  gap: 14px !important;
}
[data-testid="stMain"] [data-testid="stRadio"] label[data-baseweb="radio"] {
  background: #FFFFFF !important;
  border: 1px solid #E2E8F0 !important;
  border-radius: 8px !important;
  padding: 10px 14px !important;
  cursor: pointer !important;
  transition: all 180ms !important;
}
[data-testid="stMain"] [data-testid="stRadio"] label[data-baseweb="radio"]:hover {
  border-color: #2563EB !important;
  background: #F8FAFC !important;
  transform: translateY(-1px) !important;
}
[data-testid="stMain"] [data-testid="stRadio"] label[data-baseweb="radio"] div {
  color: #0F172A !important;
  font-size: 0.9rem !important;
  font-weight: 500 !important;
}
[data-testid="stMain"] [data-testid="stRadio"] label[data-baseweb="radio"]:has(input:checked) {
  border-color: #2563EB !important;
  background: #EFF6FF !important;
  box-shadow: 0 0 0 1px #2563EB !important;
}
[data-testid="stMain"] [data-testid="stRadio"] label[data-baseweb="radio"]:has(input:checked) div {
  color: #1E40AF !important;
  font-weight: 600 !important;
}

/* ════════════ MORE VISIBLE PAGE BG ANIMATION (Phase 3i) ════════════ */
@keyframes mc-page-bg-pulse {
  0%, 100% {
    background-position: 0% 0%, 100% 0%, 50% 100%;
  }
  50% {
    background-position: 5% 3%, 95% 5%, 50% 95%;
  }
}
[data-testid="stAppViewContainer"] .main {
  background-image:
    radial-gradient(circle 380px at 5% 8%, rgba(37,99,235,0.06) 0, transparent 100%),
    radial-gradient(circle 320px at 95% 12%, rgba(22,163,74,0.05) 0, transparent 100%),
    radial-gradient(circle 400px at 50% 90%, rgba(37,99,235,0.045) 0, transparent 100%) !important;
  background-size: 200% 200%, 200% 200%, 200% 200% !important;
  background-attachment: fixed !important;
  animation: mc-page-bg-pulse 12s ease-in-out infinite !important;
}

/* Original Phase 3h */
.mc-twin-hero {
  background:
    linear-gradient(135deg, rgba(37,99,235,0.05) 0%, rgba(255,255,255,0) 50%),
    radial-gradient(ellipse at 80% 30%, rgba(22,163,74,0.05), transparent 50%),
    radial-gradient(ellipse at 20% 80%, rgba(220,38,38,0.04), transparent 50%);
  border: 1px solid #E2E8F0;
  border-radius: 12px;
  padding: 20px 24px;
  margin-bottom: 14px;
  position: relative;
  overflow: hidden;
}
.mc-twin-hero::before {
  content: '';
  position: absolute;
  inset: 0;
  background-image:
    linear-gradient(0deg, transparent 0%, rgba(37,99,235,0.04) 50%, transparent 100%);
  background-size: 100% 200%;
  animation: mc-twin-sweep 4s ease-in-out infinite;
  pointer-events: none;
}
@keyframes mc-twin-sweep {
  0%, 100% { background-position: 0% 0%; }
  50%      { background-position: 0% 100%; }
}
.mc-twin-hero::after {
  content: '';
  position: absolute;
  top: 0; left: 0; right: 0; height: 2px;
  background: linear-gradient(90deg, transparent 0%, #2563EB 50%, transparent 100%);
  opacity: 0.55;
  animation: mc-hero-line 4.5s linear infinite;
}

/* ════════════ PREMIUM ATTACK RESULT CARDS (Phase 3h) ════════════ */
.mc-attack-result {
  background: #FFFFFF;
  border: 1px solid #E2E8F0;
  border-radius: 10px;
  padding: 16px 20px;
  margin: 8px 0;
  display: flex;
  align-items: center;
  gap: 14px;
  box-shadow: 0 1px 2px rgba(15,23,42,0.04);
  transition: all 200ms cubic-bezier(0.4, 0, 0.2, 1);
}
.mc-attack-result:hover {
  border-color: #CBD5E1;
  transform: translateX(2px);
}
.mc-attack-result-CLEAN     { border-left: 4px solid #16A34A; }
.mc-attack-result-VULNERABLE { border-left: 4px solid #DC2626; }
.mc-attack-result-WARN      { border-left: 4px solid #CA8A04; }

/* (Phase 3i replaced subtle gradients with animated mc-page-bg-pulse above) */

/* ════════════ FORENSIC FINDING CARDS (Phase 3g) ════════════ */
.mc-finding-card {
  background: #FFFFFF;
  border: 1px solid #E2E8F0;
  border-radius: 8px;
  padding: 14px 16px;
  margin-bottom: 8px;
  display: flex;
  gap: 14px;
  transition: all 180ms cubic-bezier(0.4, 0, 0.2, 1);
  box-shadow: 0 1px 2px rgba(15,23,42,0.04);
}
.mc-finding-card:hover {
  border-color: #CBD5E1;
  transform: translateX(2px);
  box-shadow: 0 2px 4px rgba(15,23,42,0.06);
}
.mc-finding-sev-CRITICAL { border-left: 4px solid #DC2626; }
.mc-finding-sev-HIGH     { border-left: 4px solid #EA580C; }
.mc-finding-sev-MEDIUM   { border-left: 4px solid #CA8A04; }
.mc-finding-sev-LOW      { border-left: 4px solid #65A30D; }
.mc-finding-sev-NONE     { border-left: 4px solid #94A3B8; }

/* Drop zone — premium */
[data-testid="stFileUploader"] section {
  background: linear-gradient(135deg, #F8FAFC 0%, #FFFFFF 100%) !important;
  border: 2px dashed #CBD5E1 !important;
  border-radius: 10px !important;
  transition: all 220ms cubic-bezier(0.4, 0, 0.2, 1) !important;
  padding: 20px !important;
}
[data-testid="stFileUploader"] section:hover {
  border-color: #2563EB !important;
  background: linear-gradient(135deg, #EFF6FF 0%, #F8FAFC 100%) !important;
  transform: scale(1.005);
}

/* ════════════ SUBTLE ENTRY ANIMATIONS ════════════ */
@keyframes fadeUpIn {
  from { opacity: 0; transform: translateY(4px); }
  to   { opacity: 1; transform: translateY(0); }
}
[data-testid="stMetric"], div[data-testid="stExpander"], .stAlert,
.mc-verdict-banner, .mc-sparkline-card {
  animation: fadeUpIn 280ms cubic-bezier(0.4, 0, 0.2, 1) backwards !important;
}

/* Pulse for live indicators */
@keyframes mcPulse {
  0%, 100% { opacity: 1; }
  50%      { opacity: 0.5; }
}
.mc-pulse, [class*="pulse"] {
  animation: mcPulse 2s ease-in-out infinite !important;
}

/* ════════════ AUTH PAGE OVERRIDES ════════════ */
div:has(> #mc-orbit) {
  background: linear-gradient(135deg, #F8FAFC 0%, #FFFFFF 100%) !important;
  border-bottom-color: #E2E8F0 !important;
}
div[data-testid="stForm"] {
  background: #FFFFFF !important;
  border: 1px solid #E2E8F0 !important;
  border-radius: 10px !important;
  padding: 20px !important;
  box-shadow: none !important;
}

/* ════════════ SIDEBAR NAV — UNIQUE SVG ICONS PER ITEM (Phase 3b) ════════════
   Each of the 8 nav items gets its own hand-crafted SVG icon, embedded
   as data-URI background, plus its own unique hover micro-animation.
   This is the signature visual feature requested by user.
*/

/* Make space for icon + reset radio circle */
[data-testid="stSidebar"] [data-testid="stRadio"] label[data-baseweb="radio"] > div:last-child {
  padding-left: 30px !important;
  position: relative !important;
  display: flex !important;
  align-items: center !important;
  min-height: 22px !important;
}

/* Common icon container — positioned absolutely before text */
[data-testid="stSidebar"] [data-testid="stRadio"] label[data-baseweb="radio"] > div:last-child::before {
  content: '' !important;
  position: absolute !important;
  left: 4px !important;
  top: 50% !important;
  transform: translateY(-50%) !important;
  width: 18px !important;
  height: 18px !important;
  background-repeat: no-repeat !important;
  background-position: center !important;
  background-size: contain !important;
  transition: transform 280ms cubic-bezier(0.34, 1.56, 0.64, 1),
              filter 220ms ease,
              opacity 220ms ease !important;
  opacity: 0.65 !important;
}

/* Icon 1 — Overview = Concentric circles (radar / dashboard) */
[data-testid="stSidebar"] [data-testid="stRadio"] label[data-baseweb="radio"]:nth-of-type(1) > div:last-child::before {
  background-image: url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23475569' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'><circle cx='12' cy='12' r='9'/><circle cx='12' cy='12' r='5'/><circle cx='12' cy='12' r='1.5' fill='%23475569'/></svg>");
}
[data-testid="stSidebar"] [data-testid="stRadio"] label[data-baseweb="radio"]:nth-of-type(1):hover > div:last-child::before {
  transform: translateY(-50%) rotate(45deg) !important;     /* radar sweep */
}

/* Icon 2 — URL scanner = arrow into globe */
[data-testid="stSidebar"] [data-testid="stRadio"] label[data-baseweb="radio"]:nth-of-type(2) > div:last-child::before {
  background-image: url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23475569' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'><circle cx='13' cy='12' r='7'/><path d='M6 12h14'/><path d='M13 5a14 14 0 010 14M13 5a14 14 0 000 14'/><path d='M2 12l4-3v6z' fill='%23475569'/></svg>");
}
[data-testid="stSidebar"] [data-testid="stRadio"] label[data-baseweb="radio"]:nth-of-type(2):hover > div:last-child::before {
  transform: translateY(-50%) translateX(2px) !important;   /* arrow nudge */
}

/* Icon 3 — Forensic scanner = magnifier over code lines */
[data-testid="stSidebar"] [data-testid="stRadio"] label[data-baseweb="radio"]:nth-of-type(3) > div:last-child::before {
  background-image: url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23475569' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'><rect x='3' y='4' width='12' height='16' rx='1.5'/><path d='M6 8h6M6 12h4M6 16h5'/><circle cx='17' cy='15' r='3.5'/><path d='M19.5 17.5l2.5 2.5'/></svg>");
}
[data-testid="stSidebar"] [data-testid="stRadio"] label[data-baseweb="radio"]:nth-of-type(3):hover > div:last-child::before {
  transform: translateY(-50%) scale(1.12) !important;       /* magnifier zoom */
}

/* Icon 4 — Digital twin = mirrored boxes */
[data-testid="stSidebar"] [data-testid="stRadio"] label[data-baseweb="radio"]:nth-of-type(4) > div:last-child::before {
  background-image: url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23475569' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'><rect x='3' y='5' width='8' height='14' rx='1.5'/><rect x='13' y='5' width='8' height='14' rx='1.5' stroke-dasharray='2 2'/><path d='M11.5 12h1'/></svg>");
}
[data-testid="stSidebar"] [data-testid="stRadio"] label[data-baseweb="radio"]:nth-of-type(4):hover > div:last-child::before {
  transform: translateY(-50%) scaleX(-1) !important;        /* twin flip */
}

/* Icon 5 — Shield monitor = shield with pulse line */
[data-testid="stSidebar"] [data-testid="stRadio"] label[data-baseweb="radio"]:nth-of-type(5) > div:last-child::before {
  background-image: url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23475569' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'><path d='M12 3l8 3v6c0 5-4 8-8 9-4-1-8-4-8-9V6z'/><path d='M7 12h2l1.5-3 2 5 1.5-2h3'/></svg>");
}
@keyframes mc-shield-pulse {
  0%, 100% { transform: translateY(-50%) scale(1); }
  50%      { transform: translateY(-50%) scale(1.10); }
}
[data-testid="stSidebar"] [data-testid="stRadio"] label[data-baseweb="radio"]:nth-of-type(5):hover > div:last-child::before {
  animation: mc-shield-pulse 800ms ease-in-out infinite !important;
}

/* Icon 6 — Threat intel = signal/transmission rings */
[data-testid="stSidebar"] [data-testid="stRadio"] label[data-baseweb="radio"]:nth-of-type(6) > div:last-child::before {
  background-image: url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23475569' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'><circle cx='12' cy='12' r='2' fill='%23475569'/><path d='M8 12a4 4 0 018 0M5.5 12a6.5 6.5 0 0113 0M3 12a9 9 0 0118 0'/></svg>");
}
@keyframes mc-signal-emit {
  0%   { opacity: 0.5; transform: translateY(-50%) scale(0.92); }
  60%  { opacity: 1;   transform: translateY(-50%) scale(1.08); }
  100% { opacity: 0.65;transform: translateY(-50%) scale(1); }
}
[data-testid="stSidebar"] [data-testid="stRadio"] label[data-baseweb="radio"]:nth-of-type(6):hover > div:last-child::before {
  animation: mc-signal-emit 900ms ease-out infinite !important;
}

/* Icon 7 — Analytics = bars rising */
[data-testid="stSidebar"] [data-testid="stRadio"] label[data-baseweb="radio"]:nth-of-type(7) > div:last-child::before {
  background-image: url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23475569' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'><path d='M3 21V9'/><path d='M9 21V13'/><path d='M15 21V5'/><path d='M21 21V11'/><path d='M3 21h18'/></svg>");
}
@keyframes mc-bar-grow {
  0%   { transform: translateY(-50%) scaleY(0.55); }
  100% { transform: translateY(-50%) scaleY(1); }
}
[data-testid="stSidebar"] [data-testid="stRadio"] label[data-baseweb="radio"]:nth-of-type(7):hover > div:last-child::before {
  animation: mc-bar-grow 320ms cubic-bezier(0.34, 1.56, 0.64, 1) !important;
  transform-origin: bottom !important;
}

/* Icon 8 — Admin = key */
[data-testid="stSidebar"] [data-testid="stRadio"] label[data-baseweb="radio"]:nth-of-type(8) > div:last-child::before {
  background-image: url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23475569' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'><circle cx='8' cy='12' r='4'/><path d='M12 12h9'/><path d='M17 12v3'/><path d='M21 12v3'/></svg>");
}
[data-testid="stSidebar"] [data-testid="stRadio"] label[data-baseweb="radio"]:nth-of-type(8):hover > div:last-child::before {
  transform: translateY(-50%) rotate(15deg) !important;     /* key turn */
}

/* Active state — recolour icons to Royal Blue + 100% opacity */
[data-testid="stSidebar"] [data-testid="stRadio"] label[data-baseweb="radio"]:hover > div:last-child::before {
  opacity: 1 !important;
  filter: drop-shadow(0 0 4px rgba(37, 99, 235, 0.18)) !important;
}
[data-testid="stSidebar"] [data-testid="stRadio"] label[data-baseweb="radio"]:has(input:checked) > div:last-child::before {
  opacity: 1 !important;
  filter: brightness(0) saturate(100%) invert(28%) sepia(100%) saturate(2590%) hue-rotate(218deg) brightness(94%) contrast(91%) !important;
}

/* ════════════ SUBTLE BUTTON PRESS FEEDBACK ════════════ */
.stButton > button[kind="primary"]:active,
.stButton > button:not([kind="primary"]):active {
  transform: scale(0.98) !important;
  transition: transform 80ms ease !important;
}

/* Card lift on hover */
[data-testid="stMetric"]:hover {
  border-color: #CBD5E1 !important;
  transform: translateY(-1px) !important;
  transition: all 180ms !important;
}

/* Sign-out button — softer in light mode */
[data-testid="stSidebar"] .stButton > button {
  background: #F8FAFC !important;
  color: #475569 !important;
  border: 1px solid #E2E8F0 !important;
}
[data-testid="stSidebar"] .stButton > button:hover {
  background: #EFF6FF !important;
  color: #2563EB !important;
  border-color: #2563EB !important;
}

/* ════════════ ADMIN PAGE ANIMATIONS (Phase 3d) ════════════ */

/* Admin card slide-in animation */
@keyframes adminCardSlideIn {
  from { opacity: 0; transform: translateX(-8px); }
  to { opacity: 1; transform: translateX(0); }
}

/* Admin table row hover effect */
@keyframes adminTableRowHover {
  from { background: #FFFFFF; }
  to { background: #F8FAFC; border-left: 3px solid #2563EB; }
}

/* Status indicator pulse (for online/healthy status) */
@keyframes statusPulse {
  0%, 100% { box-shadow: 0 0 0 0 rgba(22, 163, 74, 0.7); }
  50% { box-shadow: 0 0 0 10px rgba(22, 163, 74, 0); }
}

/* Role badge gradient animation */
@keyframes roleBadgeGradient {
  0% { background-position: 0% 50%; }
  50% { background-position: 100% 50%; }
  100% { background-position: 0% 50%; }
}

/* Data counter increment animation */
@keyframes dataCounterIncrement {
  from { transform: translateY(4px); opacity: 0; }
  to { transform: translateY(0); opacity: 1; }
}

/* Docker status visual rotation */
@keyframes dockerStatusSpin {
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
}

/* Table row wave-in stagger effect */
.admin-row-animate {
  animation: adminCardSlideIn 160ms cubic-bezier(0.4, 0, 0.2, 1) forwards !important;
}
.admin-row-animate:nth-child(1) { animation-delay: 0ms !important; }
.admin-row-animate:nth-child(2) { animation-delay: 40ms !important; }
.admin-row-animate:nth-child(3) { animation-delay: 80ms !important; }
.admin-row-animate:nth-child(4) { animation-delay: 120ms !important; }
.admin-row-animate:nth-child(5) { animation-delay: 160ms !important; }
.admin-row-animate:nth-child(6) { animation-delay: 200ms !important; }

/* Admin role badge styling */
.admin-role-badge {
  background: linear-gradient(135deg, #FF6B1A, #FF8C42) !important;
  background-size: 200% 200% !important;
  animation: roleBadgeGradient 8s infinite !important;
  color: white !important;
  padding: 4px 12px !important;
  border-radius: 6px !important;
  font-weight: 600 !important;
  font-size: 0.8rem !important;
}

/* Analyst role badge styling */
.analyst-role-badge {
  background: linear-gradient(135deg, #9ACD32, #B0DE50) !important;
  background-size: 200% 200% !important;
  color: #1F2937 !important;
  padding: 4px 12px !important;
  border-radius: 6px !important;
  font-weight: 600 !important;
  font-size: 0.8rem !important;
}

/* Status indicator (online/offline dot) */
.status-online {
  width: 8px !important;
  height: 8px !important;
  background: #16A34A !important;
  border-radius: 50% !important;
  animation: statusPulse 2.5s infinite !important;
  display: inline-block !important;
  margin-right: 6px !important;
}
.status-offline {
  width: 8px !important;
  height: 8px !important;
  background: #94A3B8 !important;
  border-radius: 50% !important;
  display: inline-block !important;
  margin-right: 6px !important;
}

/* Timeline-style audit log visualization */
.audit-timeline-item {
  border-left: 2px solid #E2E8F0 !important;
  padding-left: 20px !important;
  position: relative !important;
  margin-left: 10px !important;
}
.audit-timeline-item::before {
  content: '' !important;
  position: absolute !important;
  left: -5px !important;
  top: 4px !important;
  width: 8px !important;
  height: 8px !important;
  background: #2563EB !important;
  border-radius: 50% !important;
  border: 2px solid white !important;
}
.audit-timeline-item.login::before {
  background: #16A34A !important;
}
.audit-timeline-item.logout::before {
  background: #CA8A04 !important;
}
.audit-timeline-item.kill_switch::before {
  background: #DC2626 !important;
}

/* Action type badge styling */
.action-badge-login {
  background: #D1FAE5 !important;
  color: #065F46 !important;
  padding: 2px 8px !important;
  border-radius: 4px !important;
  font-size: 0.75rem !important;
  font-weight: 500 !important;
}
.action-badge-logout {
  background: #FEF3C7 !important;
  color: #78350F !important;
  padding: 2px 8px !important;
  border-radius: 4px !important;
  font-size: 0.75rem !important;
  font-weight: 500 !important;
}
.action-badge-kill_switch {
  background: #FEE2E2 !important;
  color: #7F1D1D !important;
  padding: 2px 8px !important;
  border-radius: 4px !important;
  font-size: 0.75rem !important;
  font-weight: 500 !important;
}
.action-badge-config_change {
  background: #DBEAFE !important;
  color: #0C2340 !important;
  padding: 2px 8px !important;
  border-radius: 4px !important;
  font-size: 0.75rem !important;
  font-weight: 500 !important;
}

/* Docker status visual */
.docker-status-circle {
  width: 100px !important;
  height: 100px !important;
  border-radius: 50% !important;
  display: flex !important;
  align-items: center !important;
  justify-content: center !important;
  font-weight: 700 !important;
  font-size: 2rem !important;
  position: relative !important;
  margin: 0 auto 16px !important;
}
.docker-online {
  background: #D1FAE5 !important;
  color: #065F46 !important;
  border: 3px solid #10B981 !important;
  box-shadow: 0 0 0 4px rgba(16, 185, 129, 0.15) !important;
  animation: statusPulse 2.5s infinite !important;
}
.docker-offline {
  background: #FEE2E2 !important;
  color: #7F1D1D !important;
  border: 3px solid #DC2626 !important;
  box-shadow: 0 0 0 4px rgba(220, 38, 38, 0.15) !important;
}

/* System metric cards */
.system-metric-card {
  background: #FFFFFF !important;
  border: 1px solid #E2E8F0 !important;
  border-radius: 8px !important;
  padding: 16px !important;
  animation: adminCardSlideIn 200ms cubic-bezier(0.4, 0, 0.2, 1) forwards !important;
}
.system-metric-card:nth-child(1) { animation-delay: 0ms !important; }
.system-metric-card:nth-child(2) { animation-delay: 50ms !important; }
.system-metric-card:nth-child(3) { animation-delay: 100ms !important; }
.system-metric-card:nth-child(4) { animation-delay: 150ms !important; }
.system-metric-card:hover {
  border-color: #2563EB !important;
  box-shadow: 0 4px 12px rgba(37, 99, 235, 0.1) !important;
  transform: translateY(-2px) !important;
  transition: all 180ms cubic-bezier(0.4, 0, 0.2, 1) !important;
}

/* API health grid */
.api-health-grid {
  display: grid !important;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)) !important;
  gap: 12px !important;
}
.api-health-item {
  background: #FFFFFF !important;
  border: 1px solid #E2E8F0 !important;
  border-radius: 6px !important;
  padding: 12px !important;
  animation: adminCardSlideIn 160ms cubic-bezier(0.4, 0, 0.2, 1) forwards !important;
}
.api-health-item:nth-child(1) { animation-delay: 0ms !important; }
.api-health-item:nth-child(2) { animation-delay: 30ms !important; }
.api-health-item:nth-child(3) { animation-delay: 60ms !important; }
.api-health-item:nth-child(4) { animation-delay: 90ms !important; }
.api-health-item:nth-child(5) { animation-delay: 120ms !important; }
.api-health-item:nth-child(6) { animation-delay: 150ms !important; }
.api-health-item:hover {
  background: #F8FAFC !important;
  border-color: #2563EB !important;
  transform: translateY(-1px) !important;
  transition: all 140ms ease !important;
}

/* Secret key cards */
.secret-card {
  background: #FFFFFF !important;
  border: 1px solid #E2E8F0 !important;
  border-radius: 8px !important;
  padding: 14px !important;
  animation: adminCardSlideIn 160ms cubic-bezier(0.4, 0, 0.2, 1) forwards !important;
}
.secret-card.missing {
  opacity: 0.6 !important;
  background: #F8FAFC !important;
  border-color: #FCA5A5 !important;
}
.secret-card:nth-child(1) { animation-delay: 0ms !important; }
.secret-card:nth-child(2) { animation-delay: 50ms !important; }
.secret-card:nth-child(3) { animation-delay: 100ms !important; }
.secret-card:nth-child(4) { animation-delay: 150ms !important; }
.secret-card:nth-child(5) { animation-delay: 200ms !important; }
.secret-card:nth-child(6) { animation-delay: 250ms !important; }
.secret-card:nth-child(7) { animation-delay: 300ms !important; }
.secret-card:nth-child(8) { animation-delay: 350ms !important; }
.secret-card:hover:not(.missing) {
  border-color: #2563EB !important;
  background: #F0F9FF !important;
  transform: translateY(-2px) !important;
  transition: all 180ms ease !important;
}

/* Character count animation */
.char-count-animate {
  animation: dataCounterIncrement 300ms cubic-bezier(0.34, 1.56, 0.64, 1) !important;
}

/* Email status card */
.email-status-card {
  background: linear-gradient(135deg, #EFF6FF, #FFFFFF) !important;
  border: 1px solid #2563EB !important;
  border-left: 4px solid #2563EB !important;
  border-radius: 8px !important;
  padding: 16px !important;
  animation: adminCardSlideIn 240ms cubic-bezier(0.4, 0, 0.2, 1) !important;
}

/* Report action buttons */
.report-action-btn {
  transition: all 180ms cubic-bezier(0.4, 0, 0.2, 1) !important;
}
.report-action-btn:hover {
  transform: translateY(-2px) !important;
  box-shadow: 0 8px 16px rgba(37, 99, 235, 0.15) !important;
}
.report-action-btn:active {
  transform: translateY(0) !important;
}

/* Success toast animation */
@keyframes successToastSlideIn {
  from { opacity: 0; transform: translateY(8px); }
  to { opacity: 1; transform: translateY(0); }
}
.success-toast {
  animation: successToastSlideIn 200ms cubic-bezier(0.4, 0, 0.2, 1) !important;
}

</style>
"""


def inject_header() -> None:
    """Render the Mission Control header bar with live clock."""
    components.html(MISSION_HEADER_HTML, height=56)


def section_header(title: str, serial: str = "") -> None:
    """
    Render a section title with optional serial-number metadata.
    
    Example:
        section_header("Threat Scanner", "SEC-001 · ONLINE")
    """
    serial_html = f'<span class="sn">{serial}</span>' if serial else ""
    st.markdown(
        f'<div class="mc-section-header"><h2>{title}</h2>{serial_html}</div>',
        unsafe_allow_html=True,
    )


def readout(label: str, value: str, tone: str = "") -> None:
    """
    Render a monospace data readout row (Bloomberg-style).
    
    Args:
        label: left-side key (auto-uppercased in CSS)
        value: right-side value
        tone:  "" | "amber" | "green" | "red"
    
    Example:
        readout("Target", "http://example.com")
        readout("Verdict", "MALICIOUS", tone="red")
    """
    st.markdown(
        f'<div class="mc-readout"><span class="k">{label}</span>'
        f'<span class="v {tone}"> {value}</span></div>',
        unsafe_allow_html=True,
    )


def risk_bar(score: float, max_score: float = 10.0, segments: int = 10) -> str:
    """
    Return HTML for a vertical risk bar (Bloomberg-style).
    
    Example:
        st.markdown(risk_bar(7.5), unsafe_allow_html=True)
    """
    filled = int(round((score / max_score) * segments))
    filled = max(0, min(segments, filled))
    crit_threshold = int(segments * 0.8)
    parts = []
    for i in range(segments):
        cls = "seg"
        if i < filled:
            cls += " crit" if i >= crit_threshold else " on"
        parts.append(f'<div class="{cls}"></div>')
    return f'<div class="mc-risk-bar">{"".join(parts)}</div>'


def case_id(prefix: str = "CASE") -> str:
    """
    Generate a forensic-style case ID like 'CASE-2026-04-19-A7F3'.
    
    Used on every threat scan, file upload, twin session — gives the app
    a documentary / evidentiary feel instead of a game feel.
    """
    import datetime, secrets
    today = datetime.datetime.now().strftime("%Y-%m-%d")
    suffix = secrets.token_hex(2).upper()
    return f"{prefix}-{today}-{suffix}"


# ═══════════════════════════════════════════════════════════════════
# DAY 2 PRO HELPERS — added v20.2 for pro-topper UI upgrade
# ═══════════════════════════════════════════════════════════════════

def telemetry_ticker(events: list[dict]) -> None:
    """
    Signature Mission Control element: a scrolling ticker strip.
    
    Renders continuously-scrolling headlines like a trading terminal:
       SCAN #4891 • MALICIOUS 9.4 • TOR EXIT • 198.51.100.42 • CVE-2021-44228 KEV
    
    Args:
        events: list of dicts with keys:
                  label (str, e.g. "SCAN #4891")
                  verdict (str, e.g. "MALICIOUS")
                  severity (str, "critical" | "warn" | "ok" | "info")
                  detail (str, free text)
    """
    if not events:
        events = [{"label": "NO EVENTS", "verdict": "IDLE",
                   "severity": "info", "detail": "awaiting first scan"}]

    # Duplicate for seamless loop
    items_html = ""
    color_map = {
        "critical": "#E63946",
        "warn":     "#FFD23F",
        "ok":       "#9ACD32",
        "info":     "#4a5568",
    }
    for e in events * 2:  # repeat so scroll doesn't have a gap
        c = color_map.get(e.get("severity", "info"), "#4a5568")
        items_html += (
            f'<span style="display:inline-flex; align-items:center; gap:10px;'
            f' margin-right:32px; white-space:nowrap;">'
            f'<span style="color:#4a5568; font-weight:500;">{e.get("label","")}</span>'
            f'<span style="width:6px; height:6px; border-radius:50%; background:{c};"></span>'
            f'<span style="color:{c}; font-weight:500;">{e.get("verdict","")}</span>'
            f'<span style="color:#718096;">{e.get("detail","")}</span>'
            f'</span>'
        )

    html = f"""
    <div style="
        position: relative; overflow: hidden;
        background: #FFFFFF;
        border-top:    1px solid rgba(255,107,26,0.18);
        border-bottom: 1px solid rgba(255,107,26,0.18);
        padding: 7px 0; margin: -0.3rem -1.75rem 1rem;
        font-family: 'IBM Plex Mono', monospace; font-size: 0.72rem;
        letter-spacing: 0.08em;">
      <div style="
          display: inline-block; white-space: nowrap;
          animation: mc-ticker 55s linear infinite;
          padding-left: 100%;">
        {items_html}
      </div>
    </div>
    <style>
    @keyframes mc-ticker {{
      from {{ transform: translateX(0); }}
      to   {{ transform: translateX(-50%); }}
    }}
    </style>
    """
    st.markdown(html, unsafe_allow_html=True)


def sparkline_card(label: str, value: str, data: list[float],
                   delta: str = "", delta_tone: str = "",
                   status_dot: str = "") -> None:
    """
    Phase 3d - rewritten for native white theme.
    A metric card with an inline SVG sparkline.
    """
    tone_colors = {
        "amber": "#2563EB",   # remapped to Royal Blue
        "green": "#16A34A",
        "red":   "#DC2626",
        "":      "#64748B",
    }
    delta_color = tone_colors.get(delta_tone, "#64748B")
    dot_color   = tone_colors.get(status_dot, "")

    # Build sparkline SVG path - Royal Blue line on white
    if data and len(data) >= 2:
        w, h = 120, 32
        mn, mx = min(data), max(data)
        rng = (mx - mn) or 1
        pts = []
        for i, v in enumerate(data):
            x = (i / (len(data) - 1)) * w
            y = h - ((v - mn) / rng) * h * 0.8 - h * 0.1
            pts.append(f"{x:.1f},{y:.1f}")
        path_d = "M" + " L".join(pts)
        last_x = w
        last_y = h - ((data[-1] - mn) / rng) * h * 0.8 - h * 0.1
        spark_svg = f"""
          <svg width="{w}" height="{h}" style="display:block;">
            <defs>
              <linearGradient id="sparkfill" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stop-color="#2563EB" stop-opacity="0.18"/>
                <stop offset="100%" stop-color="#2563EB" stop-opacity="0"/>
              </linearGradient>
            </defs>
            <path d="{path_d} L {w},{h} L 0,{h} Z" fill="url(#sparkfill)"/>
            <path d="{path_d}" stroke="#2563EB" stroke-width="2" fill="none"
                  stroke-linecap="round" stroke-linejoin="round"/>
            <circle cx="{last_x - 2}" cy="{last_y}" r="3" fill="#2563EB"/>
            <circle cx="{last_x - 2}" cy="{last_y}" r="6" fill="#2563EB" opacity="0.2">
              <animate attributeName="r" from="3" to="9" dur="1.4s" repeatCount="indefinite"/>
              <animate attributeName="opacity" from="0.4" to="0" dur="1.4s" repeatCount="indefinite"/>
            </circle>
          </svg>
        """
    else:
        spark_svg = ""

    dot_html = (
        f'<span style="display:inline-block; width:7px; height:7px; '
        f'border-radius:50%; background:{dot_color}; '
        f'animation: mc-pulse 1.6s ease-in-out infinite; margin-right:6px;"></span>'
        if dot_color else ""
    )

    html = f"""
    <div style="
        background: #FFFFFF; padding: 16px 20px; border-radius: 8px;
        border: 1px solid #E2E8F0; min-height: 120px;
        display: flex; flex-direction: column; justify-content: space-between;
        transition: all 180ms ease;
        box-shadow: 0 1px 2px rgba(15,23,42,0.04);">
      <div style="display:flex; align-items:center; justify-content:space-between;">
        <div style="
            font-family: 'Inter', sans-serif; font-size: 0.6875rem;
            letter-spacing: 0.06em; color: #64748B;
            text-transform: uppercase; font-weight: 600;">
          {dot_html}{label}
        </div>
        <div style="color:{delta_color}; font-family: 'JetBrains Mono', monospace;
                    font-size: 0.7rem; font-weight: 600;">
          {delta}
        </div>
      </div>
      <div style="display:flex; align-items:flex-end; justify-content:space-between;
                  margin-top: 6px;">
        <div style="
            color: #0F172A; font-size: 1.875rem; font-weight: 700;
            font-family: 'Inter', sans-serif; line-height: 1;
            letter-spacing: -0.025em;">
          {value}
        </div>
        <div>{spark_svg}</div>
      </div>
    </div>
    <style>
    @keyframes mc-pulse {{
      0%, 100% {{ opacity: 1; }}
      50%      {{ opacity: 0.35; }}
    }}
    </style>
    """
    st.markdown(html, unsafe_allow_html=True)


def activity_feed(events: list[dict], max_rows: int = 8) -> None:
    """
    Scrolling log-style activity feed (right sidebar of dashboards).
    
    Args:
        events: newest-first list of dicts with keys:
                ts (str timestamp), source (str), event (str),
                severity (str: "info" | "warn" | "critical" | "ok")
        max_rows: how many entries to show
    """
    color_map = {
        "critical": "#DC2626",
        "warn":     "#CA8A04",
        "ok":       "#16A34A",
        "info":     "#64748B",
    }
    rows_html = ""
    for e in events[:max_rows]:
        c = color_map.get(e.get("severity", "info"), "#64748B")
        rows_html += f"""
        <div style="display: flex; align-items: flex-start; gap: 10px;
                    padding: 8px 0; border-bottom: 1px solid #F1F5F9;
                    font-family: 'JetBrains Mono', monospace; font-size: 0.75rem;">
          <div style="color: #94A3B8; min-width: 64px; font-weight: 500;">{e.get('ts', '')}</div>
          <div style="width: 3px; height: 16px; background: {c}; flex-shrink: 0;
                      margin-top: 1px; border-radius: 2px;"></div>
          <div style="color: #2563EB; min-width: 72px; text-transform: uppercase;
                      letter-spacing: 0.05em; font-weight: 600;">
            {e.get('source', '—')}
          </div>
          <div style="color: #334155; flex: 1; line-height: 1.5;">{e.get('event', '')}</div>
        </div>
        """
    if not rows_html:
        rows_html = """
        <div style="padding: 24px 0; color: #94A3B8;
                    font-family: 'Inter', sans-serif;
                    font-size: 0.85rem; text-align: center;">
          No events yet — run a scan to populate activity feed
        </div>
        """

    st.markdown(f"""
      <div style="background: #FFFFFF; padding: 14px 18px; border-radius: 8px;
                  border: 1px solid #E2E8F0;
                  box-shadow: 0 1px 2px rgba(15,23,42,0.04);">
        <div style="font-family: 'Inter', sans-serif; font-size: 0.6875rem;
                    letter-spacing: 0.06em; color: #64748B; text-transform: uppercase;
                    font-weight: 600;
                    padding-bottom: 10px; border-bottom: 1px solid #E2E8F0;
                    margin-bottom: 4px;">
          Live Activity Feed
        </div>
        {rows_html}
      </div>
    """, unsafe_allow_html=True)


def verdict_banner(verdict: str, score: float, target: str = "") -> None:
    """
    Phase 3e - White-native verdict banner with semantic accent.
    """
    # Semantic colors for verdict (darkened for white-bg legibility)
    color_map = {
        "MALICIOUS":  "#DC2626",
        "SUSPICIOUS": "#CA8A04",
        "CLEAN":      "#16A34A",
        "UNKNOWN":    "#64748B",
        "COMPROMISED":"#DC2626",
        "RESISTED":   "#16A34A",
        "DEAD_DOMAIN":"#DC2626",
    }
    c = color_map.get(verdict.upper(), "#64748B")

    # Soft tinted background per verdict
    bg_tint = {
        "MALICIOUS":  "#FEF2F2",
        "DEAD_DOMAIN":"#FEF2F2",
        "SUSPICIOUS": "#FFFBEB",
        "CLEAN":      "#F0FDF4",
        "UNKNOWN":    "#F8FAFC",
        "COMPROMISED":"#FEF2F2",
        "RESISTED":   "#F0FDF4",
    }.get(verdict.upper(), "#F8FAFC")

    # Verdict icon (inline SVG)
    icon_svg = {
        "CLEAN":     '<svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#16A34A" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M9 12l2 2 4-4"/><circle cx="12" cy="12" r="10"/></svg>',
        "SUSPICIOUS":'<svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#CA8A04" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 9v4M12 17h.01"/><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/></svg>',
        "MALICIOUS": '<svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#DC2626" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M15 9l-6 6M9 9l6 6"/></svg>',
        "UNKNOWN":   '<svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#64748B" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 015.83 1c0 2-3 3-3 3M12 17h.01"/></svg>',
    }.get(verdict.upper(),
        '<svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#64748B" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/></svg>')

    safe_target = (target or "").replace("<", "&lt;").replace(">", "&gt;")
    target_block = ""
    if safe_target:
        target_block = (
            f'<div style="font-family:\'JetBrains Mono\',monospace; font-size:0.82rem; '
            f'color:#475569; word-break:break-all; margin-top:14px; padding-top:14px; '
            f'border-top:1px solid #E2E8F0;">{safe_target}</div>'
        )

    html = f"""
    <style>
      body {{ margin:0; padding:0; background:transparent;
              font-family:'Inter',-apple-system,system-ui,sans-serif; }}
      @keyframes mc-verdict-in {{
        from {{ opacity:0; transform: translateY(6px); }}
        to   {{ opacity:1; transform: translateY(0);  }}
      }}
    </style>
    <div style="background:{bg_tint}; padding:22px 26px; border-radius:10px;
                border:1px solid #E2E8F0; border-left:4px solid {c};
                animation: mc-verdict-in 360ms cubic-bezier(0.4,0,0.2,1) backwards;">
      <div style="display:flex; align-items:flex-start; justify-content:space-between; gap:24px;">
        <div style="display:flex; align-items:center; gap:14px;">
          <div style="flex-shrink:0;">{icon_svg}</div>
          <div>
            <div style="font-family:'Inter',sans-serif; font-size:0.6875rem;
                        letter-spacing:0.08em; color:#64748B; text-transform:uppercase;
                        font-weight:600; margin-bottom:4px;">Forensic Finding</div>
            <div style="font-family:'Inter',sans-serif; font-size:2rem; font-weight:700;
                        color:{c}; line-height:1; letter-spacing:-0.025em;">{verdict.upper()}</div>
          </div>
        </div>
        <div style="text-align:right;">
          <div style="font-family:'Inter',sans-serif; font-size:0.6875rem;
                      letter-spacing:0.08em; color:#64748B; text-transform:uppercase;
                      font-weight:600; margin-bottom:4px;">Risk score</div>
          <div style="font-family:'JetBrains Mono',monospace; font-size:2rem;
                      font-weight:700; color:#0F172A; line-height:1;">
            {score:.1f}<span style="color:#94A3B8; font-size:1.05rem; font-weight:500;">/10</span>
          </div>
        </div>
      </div>
      {target_block}
    </div>
    """
    h = 175 if safe_target else 130
    components.html(html, height=h)


def source_pill(source: str, status: str, score: float = 0,
                verdict: str = "", duration_ms: float = 0) -> str:
    """
    Return HTML for one per-API result pill (used in URL scanner live view).
    
    status: "pending" | "complete" | "error" | "unavailable"
    """
    status_colors = {
        "pending":     ("#64748B", "WAITING"),
        "complete":    ("#16A34A", "COMPLETE"),
        "error":       ("#DC2626", "ERROR"),
        "unavailable": ("#94A3B8", "OFFLINE"),
    }
    dot_color, status_label = status_colors.get(status, ("#64748B", status.upper()))

    verdict_colors = {
        "MALICIOUS":  "#DC2626",
        "SUSPICIOUS": "#CA8A04",
        "CLEAN":      "#16A34A",
        "UNKNOWN":    "#64748B",
    }
    v_color = verdict_colors.get(verdict.upper(), "#64748B")

    pulse = "animation: mc-pulse 1.4s ease-in-out infinite;" if status == "pending" else ""
    score_html = (
        f'<div style="color:{v_color}; font-weight:600; font-size:0.82rem;">'
        f'{verdict} {score:.1f}</div>'
    ) if status == "complete" else (
        f'<div style="color:#94A3B8; font-size:0.72rem;">{status_label}</div>'
    )
    dur_html = f'<div style="color:#94A3B8; font-size:0.65rem;">{duration_ms:.0f}ms</div>' \
               if duration_ms else ""

    return f"""
    <div style="background: #FFFFFF; padding: 11px 14px; border-radius: 6px;
                border: 1px solid #E2E8F0; border-left: 2px solid {dot_color}; display: flex;
                align-items: center; justify-content: space-between;
                font-family: 'JetBrains Mono', monospace; margin-bottom: 6px;">
      <div style="display: flex; align-items: center; gap: 10px;">
        <span style="width: 7px; height: 7px; border-radius: 50%;
                     background: {dot_color}; {pulse}"></span>
        <span style="color: #0F172A; font-size: 0.82rem; font-weight: 600;
                     letter-spacing: 0.04em;">
          {source.replace('_', ' ').upper()}
        </span>
      </div>
      <div style="text-align: right;">
        {score_html}
        {dur_html}
      </div>
    </div>
    <style>
    @keyframes mc-pulse {{
      0%, 100% {{ opacity: 1; }}
      50%      {{ opacity: 0.3; }}
    }}
    </style>
    """


def kpi_row(items: list[dict]) -> None:
    """
    Horizontal row of compact KPI readouts. For scan result summaries.
    
    Example:
        kpi_row([
            {"label": "Sources", "value": "10/11", "tone": "green"},
            {"label": "Duration", "value": "4.8s", "tone": ""},
            {"label": "Target IP", "value": "1.2.3.4", "tone": "amber"},
        ])
    """
    tone_colors = {
        "amber": "#2563EB",   # remap amber→Royal Blue
        "green": "#16A34A",
        "red":   "#DC2626",
        "":      "#0F172A",
    }
    cells = ""
    for it in items:
        c = tone_colors.get(it.get("tone", ""), "#0F172A")
        cells += (
            f'<div style="flex:1; padding:14px 18px; '
            f'border-right:1px solid #F1F5F9;">'
            f'<div style="font-family:Inter,sans-serif; font-size:0.6875rem; '
            f'letter-spacing:0.06em; color:#64748B; text-transform:uppercase; '
            f'font-weight:600; margin-bottom:5px;">{it.get("label","")}</div>'
            f'<div style="font-family:JetBrains Mono,monospace; font-size:1.1rem; '
            f'color:{c}; font-weight:600;">{it.get("value","—")}</div>'
            f'</div>'
        )
    st.markdown(
        f'<div style="display:flex; background:#FFFFFF; border-radius:8px; '
        f'border:1px solid #E2E8F0; margin-bottom:14px; overflow:hidden; '
        f'box-shadow:0 1px 2px rgba(15,23,42,0.04);">{cells}</div>',
        unsafe_allow_html=True,
    )


def hero_visual_globe() -> None:
    """
    Phase 3d - rewritten with light/white aesthetic.
    Hero animated visual for the Overview page — a pulsing globe with
    threat origin beacons. Pure SVG + CSS, no JS library needed.
    """
    html = """
    <style>
    body { margin: 0; padding: 0; background: #FFFFFF; }
    @keyframes mc-pulse-light {
      0%, 100% { opacity: 1; }
      50%      { opacity: 0.4; }
    }
    </style>
    <div style="position: relative; height: 220px; overflow: hidden;
                background: linear-gradient(135deg, #F8FAFC 0%, #FFFFFF 60%, #EFF6FF 100%);
                border-radius: 8px; border: 1px solid #E2E8F0;
                font-family: 'Inter', sans-serif;">
      <div style="position: absolute; top: 14px; left: 16px; font-size: 0.6875rem;
                  letter-spacing: 0.06em; color: #64748B; text-transform: uppercase;
                  font-weight: 600;">
        Global Threat Map · Live
      </div>
      <div style="position: absolute; top: 14px; right: 16px; font-size: 0.6875rem;
                  letter-spacing: 0.06em; color: #16A34A; text-transform: uppercase;
                  font-weight: 600;
                  display: flex; align-items: center; gap: 6px;">
        <span style="width: 6px; height: 6px; background: #16A34A; border-radius: 50%;
                     animation: mc-pulse-light 1.5s ease-in-out infinite;"></span>
        Streaming
      </div>
      <svg viewBox="0 0 600 220" width="100%" height="100%"
           style="position: absolute; top: 0; left: 0;"
           xmlns="http://www.w3.org/2000/svg">
        <defs>
          <radialGradient id="globeGlowLight" cx="50%" cy="50%" r="50%">
            <stop offset="0%"   stop-color="#2563EB" stop-opacity="0.10"/>
            <stop offset="70%"  stop-color="#2563EB" stop-opacity="0.03"/>
            <stop offset="100%" stop-color="#2563EB" stop-opacity="0"/>
          </radialGradient>
        </defs>
        <circle cx="300" cy="110" r="100" fill="url(#globeGlowLight)"/>
        <g stroke="#CBD5E1" fill="none" stroke-width="0.8">
          <circle cx="300" cy="110" r="85"/>
          <ellipse cx="300" cy="110" rx="85" ry="30"/>
          <ellipse cx="300" cy="110" rx="85" ry="55"/>
          <line x1="215" y1="110" x2="385" y2="110"/>
          <line x1="300" y1="25"  x2="300" y2="195"/>
          <ellipse cx="300" cy="110" rx="25" ry="85"/>
          <ellipse cx="300" cy="110" rx="55" ry="85"/>
        </g>
        <g>
          <circle cx="245" cy="85"  r="3.5" fill="#DC2626">
            <animate attributeName="opacity" values="0.3;1;0.3" dur="1.8s" repeatCount="indefinite"/>
          </circle>
          <circle cx="330" cy="95"  r="3.5" fill="#CA8A04">
            <animate attributeName="opacity" values="0.3;1;0.3" dur="2.2s" begin="0.4s" repeatCount="indefinite"/>
          </circle>
          <circle cx="360" cy="135" r="3.5" fill="#DC2626">
            <animate attributeName="opacity" values="0.3;1;0.3" dur="1.4s" begin="0.8s" repeatCount="indefinite"/>
          </circle>
          <circle cx="270" cy="150" r="3.5" fill="#CA8A04">
            <animate attributeName="opacity" values="0.3;1;0.3" dur="2.0s" begin="0.2s" repeatCount="indefinite"/>
          </circle>
          <circle cx="310" cy="60"  r="3.5" fill="#DC2626">
            <animate attributeName="opacity" values="0.3;1;0.3" dur="2.4s" begin="0.6s" repeatCount="indefinite"/>
          </circle>
          <circle cx="225" cy="130" r="3.5" fill="#16A34A">
            <animate attributeName="opacity" values="0.3;1;0.3" dur="2.6s" begin="0.1s" repeatCount="indefinite"/>
          </circle>
        </g>
        <circle cx="300" cy="110" r="4" fill="#2563EB"/>
        <circle cx="300" cy="110" r="3" fill="none" stroke="#2563EB" stroke-width="1.5">
          <animate attributeName="r"       values="3;60" dur="2.5s" repeatCount="indefinite"/>
          <animate attributeName="opacity" values="1;0"  dur="2.5s" repeatCount="indefinite"/>
        </circle>
        <circle cx="300" cy="110" r="3" fill="none" stroke="#2563EB" stroke-width="1.5">
          <animate attributeName="r"       values="3;60" dur="2.5s" begin="1.25s" repeatCount="indefinite"/>
          <animate attributeName="opacity" values="1;0"  dur="2.5s" begin="1.25s" repeatCount="indefinite"/>
        </circle>
        <g stroke="#2563EB" stroke-width="1.5" fill="none">
          <polyline points="20,30 20,15 35,15"/>
          <polyline points="580,15 595,15 595,30"/>
          <polyline points="595,190 595,205 580,205"/>
          <polyline points="35,205 20,205 20,190"/>
        </g>
      </svg>
      <div style="position: absolute; bottom: 0; left: 0; right: 0;
                  background: rgba(255,255,255,0.92); padding: 9px 16px;
                  display: flex; justify-content: space-between;
                  border-top: 1px solid #E2E8F0;
                  font-family: 'JetBrains Mono', monospace;
                  font-size: 0.7rem;">
        <span style="color: #475569; letter-spacing: 0.04em; font-weight: 500;">
          <span style="color: #DC2626;">&#9679;</span> CRITICAL 3 &nbsp;
          <span style="color: #CA8A04;">&#9679;</span> WARN 2 &nbsp;
          <span style="color: #16A34A;">&#9679;</span> INFO 1
        </span>
        <span style="color: #64748B; letter-spacing: 0.04em;">
          NORTH 45.2&deg; &middot; WEST 122.4&deg; &middot; ORBITAL VIEW
        </span>
      </div>
    </div>
    """
    components.html(html, height=230)


def twin_status_card(twin_meta: dict) -> None:
    """
    Display twin container status — used on Digital Twin page.
    
    twin_meta: dict with keys label, status, url, container_id, uptime_s, image
    """
    status = twin_meta.get("status", "offline").lower()
    status_colors = {
        "running":  "#9ACD32",
        "ready":    "#9ACD32",
        "pending":  "#FFD23F",
        "starting": "#FFD23F",
        "stopped":  "#2d3748",
        "error":    "#E63946",
        "offline":  "#2d3748",
    }
    c = status_colors.get(status, "#4a5568")

    html = f"""
    <div style="background: #F8FAFC; padding: 14px 18px; border-radius: 2px;
                border-left: 2px solid {c}; margin-bottom: 10px;">
      <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px;">
        <div style="display: flex; align-items: center; gap: 10px;">
          <span style="width: 8px; height: 8px; border-radius: 50%; background: {c};
                       animation: {'mc-pulse 1.4s ease-in-out infinite' if status in ('running','ready','pending') else 'none'};"></span>
          <span style="font-family: 'IBM Plex Sans'; font-size: 1rem; font-weight: 500;
                       color: #1a202c;">{twin_meta.get('label','Twin')}</span>
          <span style="color: {c}; font-family: 'IBM Plex Mono', monospace; font-size: 0.62rem;
                       letter-spacing: 0.2em; text-transform: uppercase;">{status}</span>
        </div>
        <div style="font-family: 'IBM Plex Mono', monospace; font-size: 0.66rem; color: #4a5568;">
          {twin_meta.get('container_id', '—')}
        </div>
      </div>
      <div style="display: flex; gap: 24px; font-family: 'IBM Plex Mono', monospace;
                  font-size: 0.72rem; color: #718096;">
        <span><span style="color: #2d3748;">URL</span> {twin_meta.get('url', '—')}</span>
        <span><span style="color: #2d3748;">IMAGE</span> {twin_meta.get('image', '—')}</span>
      </div>
    </div>
    """
    st.markdown(html, unsafe_allow_html=True)
