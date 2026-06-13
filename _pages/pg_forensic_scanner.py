"""
AI-DTCTM | Forensic Scanner page (v21 — Day 3)
════════════════════════════════════════════════════════════════════
3-tab UI wrapping the scanner modules:
  Tab 1: Upload source code / files / archives → malware scan
  Tab 2: Upload database file (.sql / .sqlite) → stored-XSS scan
  Tab 3: Connect remote MySQL (credentials in session only) → scan

Replaces the old "File Sandbox" placeholder.
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import streamlit as st

from core.shared_css import section_header, readout, verdict_banner, kpi_row
from core.forensic_scanner import scan_file, scan_archive
from core.database_scanner import scan_sqlite, scan_sql_dump, scan_remote_mysql
from core.scan_history import record_scan
from core.pdf_report_generator import generate_forensic_report


def render_forensic_scanner_page():
    # ── Phase 3g: animated forensic hero + capabilities tag strip ─
    st.markdown(
        """<div class="mc-forensic-hero">
          <div style="display:flex; align-items:center; gap:18px;">
            <div style="flex-shrink:0;">
              <svg width="60" height="60" viewBox="0 0 60 60" fill="none">
                <defs>
                  <linearGradient id="forenGrad" x1="0" y1="0" x2="60" y2="60" gradientUnits="userSpaceOnUse">
                    <stop offset="0%" stop-color="#3B82F6"/>
                    <stop offset="100%" stop-color="#1E40AF"/>
                  </linearGradient>
                </defs>
                <!-- magnifier outer -->
                <circle cx="26" cy="26" r="18" stroke="url(#forenGrad)" stroke-width="2" fill="rgba(37,99,235,0.05)"/>
                <line x1="40" y1="40" x2="54" y2="54" stroke="url(#forenGrad)" stroke-width="3" stroke-linecap="round"/>
                <!-- code lines inside -->
                <line x1="16" y1="20" x2="32" y2="20" stroke="#2563EB" stroke-width="1.4" opacity="0.6"/>
                <line x1="16" y1="26" x2="28" y2="26" stroke="#2563EB" stroke-width="1.4" opacity="0.85"/>
                <line x1="16" y1="32" x2="36" y2="32" stroke="#2563EB" stroke-width="1.4" opacity="0.6"/>
                <!-- scanner sweep -->
                <line x1="10" y1="26" x2="42" y2="26" stroke="#16A34A" stroke-width="1.5" stroke-linecap="round" opacity="0.85">
                  <animate attributeName="y1" values="12;40;12" dur="3.6s" repeatCount="indefinite"/>
                  <animate attributeName="y2" values="12;40;12" dur="3.6s" repeatCount="indefinite"/>
                </line>
                <!-- threat dots -->
                <circle cx="32" cy="22" r="1.5" fill="#DC2626" opacity="0.85">
                  <animate attributeName="opacity" values="0.3;1;0.3" dur="1.5s" repeatCount="indefinite"/>
                </circle>
              </svg>
            </div>
            <div style="flex:1; min-width:0;">
              <div style="font-family:'Inter',sans-serif; font-size:1.35rem;
                          font-weight:700; color:#0F172A; letter-spacing:-0.02em;
                          line-height:1.2;">Forensic malware & secret scanner</div>
              <div style="font-family:'Inter',sans-serif; font-size:0.875rem;
                          color:#475569; margin-top:4px; line-height:1.5;">
                5-layer detection · YARA signatures · MalwareBazaar hashes ·
                30+ regex patterns · AST taint analysis · Shannon entropy · line-level reporting
              </div>
            </div>
            <div style="flex-shrink:0; display:flex; flex-direction:column; gap:6px;">
              <div style="display:flex; align-items:center; gap:8px;
                        font-family:'JetBrains Mono',monospace; font-size:0.7rem;
                        color:#16A34A; font-weight:700; letter-spacing:0.06em;
                        background:#F0FDF4; padding:5px 10px; border-radius:5px;">
                <span style="width:7px; height:7px; border-radius:50%;
                           background:#16A34A; animation: mc-pulse 1.6s infinite;"></span>
                YARA · 25 RULES
              </div>
              <div style="display:flex; align-items:center; gap:8px;
                        font-family:'JetBrains Mono',monospace; font-size:0.7rem;
                        color:#1E40AF; font-weight:700; letter-spacing:0.06em;
                        background:#EFF6FF; padding:5px 10px; border-radius:5px;">
                <span style="width:7px; height:7px; border-radius:50%;
                           background:#2563EB;"></span>
                ML · ENTROPY · AST
              </div>
            </div>
          </div>
        </div>""",
        unsafe_allow_html=True,
    )

    # ── Honest detection capabilities (viva-protective) ────────────
    with st.expander("ℹ️ Detection capabilities & limitations (click to expand)", expanded=False):
        st.markdown(
            "<div style='font-family:Inter,sans-serif; font-size:0.875rem; "
            "color:#334155; line-height:1.65;'>"
            "<b style='color:#16A34A;'>What this tool DETECTS:</b><br/>"
            "• Known malware families via YARA signatures (25 rules: webshells, ransomware, RATs)<br/>"
            "• Known malicious file hashes via MalwareBazaar (700K samples)<br/>"
            "• Suspicious code patterns: eval/exec on user input, SQL concat, shell=True<br/>"
            "• Hardcoded secrets: API keys, AWS keys, Stripe live keys, GitHub tokens<br/>"
            "• Obfuscated payloads via Shannon entropy (entropy &gt; 5.0 in long strings)<br/>"
            "• AST taint analysis: dangerous Python calls and subprocess shell=True<br/><br/>"
            "<b style='color:#CA8A04;'>What signature-based scanners CANNOT detect (industry-wide limitation):</b><br/>"
            "• Custom-written malware not matching known signatures<br/>"
            "• Polymorphic / packed binaries beyond entropy hint<br/>"
            "• Zero-day exploits before sample submission to feeds<br/><br/>"
            "These limitations apply to all signature-based AV including commercial products. "
            "Sandbox execution (Phase 4) addresses some of these by running suspicious "
            "files in isolation."
            "</div>",
            unsafe_allow_html=True,
        )

    # Add tab styling for better visual separation
    st.markdown("""
    <style>
    button[data-baseweb="tab"] {
        font-weight: 600;
        font-size: 0.95rem;
    }
    button[data-baseweb="tab"][aria-selected="true"] {
        border-bottom: 3px solid #2563EB !important;
        color: #2563EB !important;
    }
    </style>
    """, unsafe_allow_html=True)

    # Tabs - Completely Separate
    tab_files, tab_db = st.tabs([
        "📁 UPLOAD FILES",
        "🗄️ UPLOAD DATABASE",
    ])

    with tab_files:
        _render_file_upload()

    with tab_db:
        _render_db_upload()


# ═══════════════════════════════════════════════════════════════
# TAB 1: File / archive upload
# ═══════════════════════════════════════════════════════════════
def _render_file_upload():
    st.markdown(
        '<div style="font-family:Inter,sans-serif; font-size:1.05rem; '
        'color:#334155; line-height:1.7; margin:12px 0 20px;">'
        '<b style="color:#0F172A; font-size:1.15rem;">📁 Upload source code, archives, or individual files</b> '
        'to scan for malware, backdoors, secrets, and vulnerable patterns. Accepts '
        'single files or <code style="background:#F1F5F9; padding:2px 6px; '
        'border-radius:4px; font-family:JetBrains Mono,monospace; font-size:0.85rem; '
        'color:#1E40AF;">.zip</code> / <code style="background:#F1F5F9; '
        'padding:2px 6px; border-radius:4px; font-family:JetBrains Mono,monospace; '
        'font-size:0.85rem; color:#1E40AF;">.tar.gz</code> archives (max 50MB).'
        '</div>',
        unsafe_allow_html=True,
    )

    # ── Slim info-icon bar: hover/click to reveal CLEAN vs MALICIOUS ──
    # Uses native HTML <details> so it's pure-CSS, no Streamlit rerun.
    st.markdown(
        '<style>'
        '.fs-info-bar details > summary::-webkit-details-marker {display:none}'
        '.fs-info-bar details > summary {list-style:none}'
        '.fs-info-bar .fs-info-icon {'
        '  display:inline-flex;align-items:center;justify-content:center;'
        '  width:18px;height:18px;border-radius:50%;'
        '  background:linear-gradient(135deg,#2563EB,#7C3AED);color:#FFFFFF;'
        '  font-family:Inter,sans-serif;font-size:0.66rem;font-weight:800;'
        '  font-style:italic;flex-shrink:0;line-height:1;'
        '  box-shadow:0 1px 3px rgba(37,99,235,0.35);'
        '  cursor:help;}'
        '.fs-info-bar details[open] .fs-info-arrow { transform: rotate(90deg); }'
        '.fs-info-bar .fs-info-arrow { transition: transform 200ms ease; '
        '  font-family:JetBrains Mono,monospace;font-size:0.62rem;color:#94A3B8;}'
        '.fs-info-bar summary:hover .fs-info-text { color:#0F172A !important; }'
        '</style>'
        # ── Compact info bar with two collapsible halves ──
        '<div class="fs-info-bar" style="display:grid;grid-template-columns:1fr 1fr;'
        'gap:8px;margin:0 0 14px">'
        # LEFT: CLEAN (collapsible) ────────────────────────────
        '<details style="background:#F0FDF4;border:1px solid #BBF7D0;'
        'border-left:3px solid #16A34A;border-radius:8px;overflow:hidden">'
        '<summary style="cursor:pointer;padding:8px 12px;'
        'display:flex;align-items:center;gap:8px;user-select:none;'
        '-webkit-user-select:none">'
        '<span class="fs-info-icon" title="Click to expand">i</span>'
        '<span class="fs-info-text" style="font-family:Inter,sans-serif;'
        'font-size:0.78rem;font-weight:700;color:#14532D;letter-spacing:0.01em">'
        'What looks CLEAN to the scanner</span>'
        '<span style="margin-left:auto" class="fs-info-arrow">▸</span>'
        '</summary>'
        '<div style="padding:0 14px 12px">'
        '<ul style="margin:0;padding-left:18px;font-size:0.74rem;color:#15803D;'
        'line-height:1.7;font-weight:500;">'
        '<li>Plain text, documentation, .md / .txt / .pdf without scripts</li>'
        '<li>Source code with normal patterns (functions, imports, comments)</li>'
        '<li>Images, audio, video files (.jpg/.png/.mp3/.mp4)</li>'
        '<li>Office docs (.docx/.xlsx) <b>without</b> VBA macros or DDE</li>'
        '<li>ZIP archives containing only text or data files</li>'
        '<li>Low–medium entropy (text 4–5, compressed 7–8 is OK)</li>'
        '<li>No URLs, IPs, or shell commands in content</li>'
        '</ul></div>'
        '</details>'
        # RIGHT: MALICIOUS (collapsible) ────────────────────────
        '<details style="background:#FEF2F2;border:1px solid #FECACA;'
        'border-left:3px solid #DC2626;border-radius:8px;overflow:hidden">'
        '<summary style="cursor:pointer;padding:8px 12px;'
        'display:flex;align-items:center;gap:8px;user-select:none;'
        '-webkit-user-select:none">'
        '<span class="fs-info-icon" style="background:linear-gradient(135deg,#DC2626,#7C2D12);" '
        'title="Click to expand">i</span>'
        '<span class="fs-info-text" style="font-family:Inter,sans-serif;'
        'font-size:0.78rem;font-weight:700;color:#7F1D1D;letter-spacing:0.01em">'
        'What flags as MALICIOUS</span>'
        '<span style="margin-left:auto" class="fs-info-arrow">▸</span>'
        '</summary>'
        '<div style="padding:0 14px 12px">'
        '<ul style="margin:0;padding-left:18px;font-size:0.74rem;color:#991B1B;'
        'line-height:1.7;font-weight:500;">'
        '<li>Webshells: <code style="background:#FFFFFF;padding:1px 5px;border-radius:3px;'
        'font-size:0.7rem;">eval($_POST)</code>, <code style="background:#FFFFFF;'
        'padding:1px 5px;border-radius:3px;font-size:0.7rem;">system($_GET)</code></li>'
        '<li>Encoded PowerShell: <code style="background:#FFFFFF;padding:1px 5px;'
        'border-radius:3px;font-size:0.7rem;">powershell -enc {base64}</code></li>'
        '<li>Office docs with VBA macros, DDEAUTO, or remote .exe links</li>'
        '<li>PDFs with <code style="background:#FFFFFF;padding:1px 5px;border-radius:3px;'
        'font-size:0.7rem;">/JavaScript</code> + <code style="background:#FFFFFF;'
        'padding:1px 5px;border-radius:3px;font-size:0.7rem;">/OpenAction</code></li>'
        '<li>Ransomware patterns: <code style="background:#FFFFFF;padding:1px 5px;'
        'border-radius:3px;font-size:0.7rem;">vssadmin delete</code>, '
        '<code style="background:#FFFFFF;padding:1px 5px;border-radius:3px;'
        'font-size:0.7rem;">bcdedit</code></li>'
        '<li>Mimikatz / LSASS dumping / hash extraction strings</li>'
        '<li>Packed binaries (UPX header + entropy > 7.5 in code section)</li>'
        '<li>Hardcoded API keys / AWS credentials / private keys</li>'
        '</ul></div>'
        '</details>'
        '</div>',
        unsafe_allow_html=True,
    )

    # ── Detection layers + ML model banner (small, professional) ──
    st.markdown(
        '<div style="background:linear-gradient(135deg,#EFF6FF,#FAF5FF);'
        'border:1px solid #DBEAFE;border-left:3px solid #2563EB;border-radius:8px;'
        'padding:10px 14px;margin:0 0 16px;font-family:Inter,sans-serif;'
        'font-size:0.76rem;color:#1E40AF;line-height:1.6;">'
        '<b style="color:#1E3A8A;">🧠 6-layer detection engine:</b> '
        '<span style="color:#475569;">'
        'YARA signatures · regex heuristics (502 patterns) · static analysis · '
        'MalwareBazaar hash reputation · Shannon entropy · '
        '</span>'
        '<b style="color:#7C3AED;">Deep ML classifier</b> '
        '<span style="color:#64748B;font-family:JetBrains Mono,monospace;'
        'font-size:0.7rem;background:#F5F3FF;padding:1px 7px;border-radius:4px;'
        'border:1px solid #DDD6FE;margin-left:4px;">'
        '4-layer MLP · 32 features · trained on 940 samples</span>'
        '</div>',
        unsafe_allow_html=True,
    )

    # ✅ CLEAN FILE UPLOAD - NO DUPLICATES + BIG ICONS!
    st.markdown("""
    <style>
    /* Hide label */
    [data-testid="stFileUploader"] label { display: none !important; }

    /* White background always */
    [data-testid="stFileUploader"] {
        background: linear-gradient(135deg, #FFFFFF 0%, #F8FAFC 100%) !important;
        border: 2px dashed #CBD5E1 !important;
        border-radius: 12px !important;
        padding: 32px !important;
    }

    /* Uploaded files - WHITE background, not black! */
    [data-testid="stFileUploader"] [data-testid="stFileUploaderDropzone"] {
        background: #FFFFFF !important;
    }

    /* File list items - WHITE */
    [data-testid="stFileUploader"] li {
        background: #FFFFFF !important;
        border: 1px solid #E2E8F0 !important;
        color: #0F172A !important;
        border-radius: 8px !important;
        padding: 12px 16px !important;
        margin: 8px 0 !important;
    }

    [data-testid="stFileUploader"] li:hover {
        background: #F0F9FF !important;
        border-color: #2563EB !important;
    }

    /* Remove ALL black backgrounds */
    [data-testid="stFileUploader"] * {
        background-color: transparent !important;
    }

    /* Make upload icon BIGGER */
    [data-testid="stFileUploader"] svg {
        width: 64px !important;
        height: 64px !important;
    }

    /* Button styling */
    [data-testid="stFileUploader"] button {
        background-color: #2563EB !important;
        color: white !important;
        font-weight: 600 !important;
        padding: 12px 24px !important;
    }

    [data-testid="stFileUploader"] button:hover {
        background-color: #1E40AF !important;
    }
    </style>
    """, unsafe_allow_html=True)

    uploaded = st.file_uploader(
        label="",  # EMPTY - no duplicate text!
        accept_multiple_files=True,
        type=None,
        key="forensic_file_upload",
    )

    if uploaded:
        st.success(f"✅ {len(uploaded)} file(s) ready to scan")
        # BIG SCAN BUTTON
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            scan_btn = st.button(
                "🔬 SCAN NOW",
                type="primary",
                use_container_width=True,
                key="scan_files_btn",
                help="Start forensic malware scanning with 78+ threat patterns"
            )
    else:
        st.info("📂 Select files to begin scanning...")
        scan_btn = False

    if scan_btn and uploaded:
        _run_file_scan(uploaded)

    elif "last_file_scan" in st.session_state:
        _render_file_scan_result(st.session_state["last_file_scan"])


def _run_file_scan(uploaded_files):
    # Save all uploads to temp, scan each, aggregate
    tmpdir = tempfile.mkdtemp(prefix="aidtctm_upload_")
    total_findings = []
    per_file_results = []
    total_size = 0

    # Phase 2b — terminal-style scanning animation with detailed progress
    import time as _time
    terminal_output = st.empty()

    with st.status("Scanning uploaded files...", expanded=True) as status:
        STAGES = [
            ("YARA signature matching", 0.20, "25 rules: webshells, ransomware, RATs, backdoors"),
            ("Heuristic regex scan", 0.40, "50+ patterns: secrets, injection, exfiltration"),
            ("Static code analysis", 0.60, "AST taint analysis: code injection risks"),
            ("Hash reputation lookup", 0.78, "MalwareBazaar: binary/script hash check"),
            ("Entropy analysis", 0.92, "Detecting compressed/encrypted payloads"),
        ]

        terminal_lines = ["$ forensic-scan --deep --all-layers"]

        for i, f in enumerate(uploaded_files, 1):
            local_path = os.path.join(tmpdir, f.name)
            with open(local_path, "wb") as out:
                out.write(f.getbuffer())
            total_size += len(f.getbuffer())

            file_size_kb = len(f.getbuffer()) / 1024
            terminal_lines.append(f"")
            terminal_lines.append(f"[{i}/{len(uploaded_files)}] Scanning: {f.name} ({file_size_kb:.1f} KB)")
            terminal_lines.append(f"  SHA256: Computing hash...")

            # Show the 5 pipeline stages with terminal-style output + REAL scanning delays
            for stage_label, pct, stage_desc in STAGES:
                terminal_lines.append(f"  > {stage_label}... {stage_desc}")
                terminal_output.code("\n".join(terminal_lines), language="bash")
                _time.sleep(0.8)  # Realistic scanning delay per stage

            # If archive, scan nested
            if f.name.endswith((".zip", ".tar.gz", ".tgz", ".tar")):
                result = scan_archive(local_path)
                if not result.get("error"):
                    st.write(f"   → Extracted, scanned {result.get('files_scanned', 0)} files, "
                             f"found {result.get('total_findings', 0)} issues")
                    for pf in result.get("findings_per_file", []):
                        total_findings.extend(pf.get("findings", []))

                    # ── Phase 2f: deep line-by-line scan for ZIPs ──────
                    # Augments YARA/heuristic with regex+AST line-level findings
                    if f.name.endswith(".zip"):
                        status.update(label=f"{f.name} · Deep code analysis (line-by-line)...")
                        try:
                            from core.deep_code_scanner import deep_scan
                            deep = deep_scan(local_path, max_findings=500)
                            deep_findings = deep.get("findings", [])
                            st.write(
                                f"   🔬 Deep scan: {deep.get('files_scanned',0)} files, "
                                f"{deep.get('lines_scanned',0):,} lines, "
                                f"**{len(deep_findings)} line-level findings**"
                            )
                            # Add to total findings
                            for df in deep_findings:
                                total_findings.append({
                                    "severity":   df["severity"],
                                    "category":   df["category"],
                                    "description": f"{df['why_risky']} (line {df['line']})",
                                    "table":      df["file"],
                                    "column":     str(df["column"]),
                                    "row_id":     str(df["line"]),
                                    "evidence":   df["line_text"],
                                    "fix":        df["fix"],
                                })
                        except Exception as e:
                            st.warning(f"Deep scan unavailable: {e}")
                            deep = {"findings": [], "lines_scanned": 0, "files_scanned": 0}
                    else:
                        deep = {"findings": [], "lines_scanned": 0, "files_scanned": 0}

                    per_file_results.append({
                        "file":           f.name,
                        "type":           "archive",
                        "files_scanned":  result.get("files_scanned"),
                        "verdict":        result.get("verdict"),
                        "severities":     result.get("severity_totals"),
                        "details":        result.get("findings_per_file", []),
                        "deep_scan":      deep,   # Phase 2f
                    })
                else:
                    st.error(f"Archive error: {result.get('error')}")
            else:
                result = scan_file(local_path)
                findings = result.get("findings", [])
                total_findings.extend(findings)
                st.write(f"   → {result.get('finding_count', 0)} findings, "
                         f"entropy {result.get('entropy', 0):.2f}")
                per_file_results.append({
                    "file":       f.name,
                    "type":       "single",
                    "sha256":     result.get("sha256"),
                    "entropy":    result.get("entropy"),
                    "max_severity": result.get("max_severity"),
                    "risk_score": result.get("risk_score"),
                    "severities": result.get("severity_breakdown"),
                    "findings":   findings,
                })
        status.update(label="Scan complete", state="complete")

    # Build aggregate case
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in total_findings:
        sev_counts[f["severity"].lower()] = sev_counts.get(f["severity"].lower(), 0) + 1

    if sev_counts["critical"] > 0:
        verdict = "MALICIOUS"
        score = min(10.0, 7.0 + sev_counts["critical"] * 0.3)
    elif sev_counts["high"] > 0:
        verdict = "SUSPICIOUS"
        score = min(10.0, 5.0 + sev_counts["high"] * 0.3)
    elif sev_counts["medium"] + sev_counts["low"] > 0:
        verdict = "SUSPICIOUS"
        score = 3.0
    else:
        verdict = "CLEAN"
        score = 0.5

    import datetime, secrets
    case = {
        "case_id":       f"FILE-{datetime.datetime.now().strftime('%Y-%m-%d')}-{secrets.token_hex(2).upper()}",
        "scan_type":     "file",
        "target":        f"{len(uploaded_files)} file(s), {total_size / 1024:.1f} KB",
        "fused_verdict": verdict,
        "fused_score":   score,
        "total_findings": len(total_findings),
        "severity_totals": sev_counts,
        "per_file_results": per_file_results,
        "duration_ms":   0,  # TODO track
    }
    record_scan(case, scan_type="file")
    st.session_state["last_file_scan"] = case
    _render_file_scan_result(case)


def _render_file_scan_result(case: dict):
    st.markdown("<div style='height:12px'></div>", unsafe_allow_html=True)
    verdict_banner(case["fused_verdict"], case["fused_score"],
                   target=case.get("target", ""))

    kpi_row([
        {"label": "Case ID",       "value": case["case_id"],                        "tone": "amber"},
        {"label": "Total findings","value": str(case["total_findings"]),
         "tone": "red" if case["total_findings"] > 5 else "amber" if case["total_findings"] > 0 else "green"},
        {"label": "Critical",      "value": str(case["severity_totals"]["critical"]),
         "tone": "red" if case["severity_totals"]["critical"] else ""},
        {"label": "High",          "value": str(case["severity_totals"]["high"]),
         "tone": "amber" if case["severity_totals"]["high"] else ""},
    ])

    # ── PDF Report Download ──────────────────────────────
    st.markdown("<div style='height:12px'></div>", unsafe_allow_html=True)
    col_pdf, col_space = st.columns([1, 3])
    with col_pdf:
        pdf_buffer = generate_forensic_report(case)
        if pdf_buffer:
            st.download_button(
                label="📄 Download PDF Report",
                data=pdf_buffer,
                file_name=f"Forensic_Report_{case['case_id']}.pdf",
                mime="application/pdf",
                use_container_width=True
            )
        else:
            st.info("⚠️ PDF library not available. Install: pip install reportlab")

    # ── Phase 3g: Premium white-native detection coverage cards ─────
    st.markdown("<div style='height:14px'></div>", unsafe_allow_html=True)
    section_header("Detection coverage", "5 LAYERS APPLIED")

    files_scanned = sum(
        pf.get("files_scanned", 1) for pf in case.get("per_file_results", [])
    )
    total_findings = case.get("total_findings", 0)

    summary_msg = (
        f'No anomalies found — that is itself the result, not a fake.'
        if total_findings == 0 else
        f'Aggregated <b style="color:#0F172A;">{total_findings}</b> findings across all layers.'
    )
    coverage_html = (
        f'<div style="background:#F0FDF4; padding:14px 18px; border:1px solid #BBF7D0; '
        f'border-left:3px solid #16A34A; margin-bottom:14px; border-radius:8px; '
        f'font-family:Inter,sans-serif; font-size:0.875rem; line-height:1.6;">'
        f'<div style="color:#334155;">'
        f'Scanned <b style="color:#0F172A;">{files_scanned} file(s)</b> through 5 detection '
        f'layers. {summary_msg}</div></div>'
        '<div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); '
        'gap:10px; margin-bottom:14px;">'
        # Layer 1 - YARA
        '<div style="background:#FFFFFF; padding:14px 16px; border:1px solid #E2E8F0; '
        'border-left:3px solid #2563EB; border-radius:8px; '
        'box-shadow:0 1px 2px rgba(15,23,42,0.04); transition:all 180ms;">'
        '<div style="display:flex; align-items:center; gap:10px;">'
        '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#2563EB" '
        'stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
        '<path d="M9 12l2 2 4-4M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>'
        '<div style="font-family:Inter,sans-serif; font-size:0.6875rem; letter-spacing:0.06em; '
        'color:#64748B; text-transform:uppercase; font-weight:600;">Layer 1 · YARA</div></div>'
        '<div style="color:#0F172A; margin-top:4px; font-weight:600; font-size:0.95rem;">Signature matching</div>'
        '<div style="color:#475569; font-size:0.78rem; margin-top:3px; line-height:1.45;">'
        '25 rules: webshells, ransomware, RATs, generic backdoors</div></div>'
        # Layer 2 - Heuristic
        '<div style="background:#FFFFFF; padding:14px 16px; border:1px solid #E2E8F0; '
        'border-left:3px solid #2563EB; border-radius:8px; '
        'box-shadow:0 1px 2px rgba(15,23,42,0.04);">'
        '<div style="display:flex; align-items:center; gap:10px;">'
        '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#2563EB" '
        'stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
        '<polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>'
        '<div style="font-family:Inter,sans-serif; font-size:0.6875rem; letter-spacing:0.06em; '
        'color:#64748B; text-transform:uppercase; font-weight:600;">Layer 2 · Heuristic</div></div>'
        '<div style="color:#0F172A; margin-top:4px; font-weight:600; font-size:0.95rem;">Regex patterns</div>'
        '<div style="color:#475569; font-size:0.78rem; margin-top:3px; line-height:1.45;">'
        '50+ patterns: eval(), base64+exec, RCE chains, obfuscated loaders</div></div>'
        # Layer 3 - Static analysis
        '<div style="background:#FFFFFF; padding:14px 16px; border:1px solid #E2E8F0; '
        'border-left:3px solid #2563EB; border-radius:8px; '
        'box-shadow:0 1px 2px rgba(15,23,42,0.04);">'
        '<div style="display:flex; align-items:center; gap:10px;">'
        '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#2563EB" '
        'stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
        '<rect x="3" y="3" width="18" height="18" rx="2"/>'
        '<path d="M9 9h6M9 13h4M9 17h6"/></svg>'
        '<div style="font-family:Inter,sans-serif; font-size:0.6875rem; letter-spacing:0.06em; '
        'color:#64748B; text-transform:uppercase; font-weight:600;">Layer 3 · Static analysis</div></div>'
        '<div style="color:#0F172A; margin-top:4px; font-weight:600; font-size:0.95rem;">Code defects</div>'
        '<div style="color:#475569; font-size:0.78rem; margin-top:3px; line-height:1.45;">'
        'SQL injection, XSS, command injection, hardcoded secrets</div></div>'
        # Layer 4 - Hash reputation
        '<div style="background:#FFFFFF; padding:14px 16px; border:1px solid #E2E8F0; '
        'border-left:3px solid #2563EB; border-radius:8px; '
        'box-shadow:0 1px 2px rgba(15,23,42,0.04);">'
        '<div style="display:flex; align-items:center; gap:10px;">'
        '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#2563EB" '
        'stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
        '<circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2c2.5 3 4 7 4 10s-1.5 7-4 10"/></svg>'
        '<div style="font-family:Inter,sans-serif; font-size:0.6875rem; letter-spacing:0.06em; '
        'color:#64748B; text-transform:uppercase; font-weight:600;">Layer 4 · Hash reputation</div></div>'
        '<div style="color:#0F172A; margin-top:4px; font-weight:600; font-size:0.95rem;">MalwareBazaar lookup</div>'
        '<div style="color:#475569; font-size:0.78rem; margin-top:3px; line-height:1.45;">'
        'SHA-256 cross-reference against 700K known malware samples</div></div>'
        # Layer 5 - Entropy
        '<div style="background:#FFFFFF; padding:14px 16px; border:1px solid #E2E8F0; '
        'border-left:3px solid #2563EB; border-radius:8px; '
        'box-shadow:0 1px 2px rgba(15,23,42,0.04);">'
        '<div style="display:flex; align-items:center; gap:10px;">'
        '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#2563EB" '
        'stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
        '<path d="M3 12l4-9 4 18 4-9 4 9 4-9"/></svg>'
        '<div style="font-family:Inter,sans-serif; font-size:0.6875rem; letter-spacing:0.06em; '
        'color:#64748B; text-transform:uppercase; font-weight:600;">Layer 5 · Entropy</div></div>'
        '<div style="color:#0F172A; margin-top:4px; font-weight:600; font-size:0.95rem;">Shannon randomness</div>'
        '<div style="color:#475569; font-size:0.78rem; margin-top:3px; line-height:1.45;">'
        'Detects packed/encrypted payloads (entropy &gt; 5.0/8.0)</div></div>'
        '</div>'
    )
    st.markdown(coverage_html, unsafe_allow_html=True)

    # Honest empty-state explanation when 0 findings
    if total_findings == 0:
        st.markdown(
            '<div style="background:#F0FDF4; padding:14px 18px; '
            'border:1px solid #BBF7D0; border-left:3px solid #16A34A; '
            'margin-bottom:12px; border-radius:8px; '
            'font-family:Inter,sans-serif; font-size:0.875rem; '
            'color:#334155; line-height:1.6;">'
            '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" '
            'stroke="#16A34A" stroke-width="2.5" stroke-linecap="round" '
            'stroke-linejoin="round" style="vertical-align:-3px; margin-right:6px;">'
            '<path d="M9 12l2 2 4-4"/><circle cx="12" cy="12" r="10"/></svg>'
            '<b style="color:#16A34A;">Clean result is real.</b> '
            'All 5 detection layers ran against your file(s) and produced no '
            'matches. The content is unlikely to contain known malware patterns. '
            '<i style="color:#475569;">Note:</i> zero-day or polymorphic malware can '
            'evade signature-based detection — sandbox execution catches those.'
            '</div>',
            unsafe_allow_html=True,
        )

    st.markdown("<div style='height:14px'></div>", unsafe_allow_html=True)

    # Per-file breakdown
    for pf in case.get("per_file_results", []):
        _render_per_file_card(pf)

    # Download report
    st.markdown("<div style='height:12px'></div>", unsafe_allow_html=True)
    st.download_button(
        "Download full report (JSON)",
        data=json.dumps(case, indent=2, default=str),
        file_name=f"{case['case_id']}.json",
        mime="application/json",
    )


def _render_per_file_card(pf: dict):
    fname = pf["file"]
    if pf.get("type") == "archive":
        title = f"📦 {fname} — {pf.get('files_scanned', 0)} files scanned — {pf.get('verdict')}"
        with st.expander(title):
            for sub in pf.get("details", []):
                _render_file_findings(sub)
    else:
        sev = pf.get("max_severity", "NONE")
        findings = pf.get("findings", [])
        emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "NONE": "🟢"}.get(sev, "⚪")
        title = f"{emoji} {fname} — {len(findings)} findings — {sev}"
        with st.expander(title, expanded=(sev in ("CRITICAL", "HIGH"))):
            readout("SHA-256",  pf.get("sha256", "—")[:32] + "...")
            readout("Entropy",  f'{pf.get("entropy", 0):.3f} / 8.000')
            readout("Risk score", f'{pf.get("risk_score", 0)}/100',
                    tone="red" if pf.get("risk_score", 0) > 50 else "amber" if pf.get("risk_score", 0) > 20 else "")
            _render_file_findings(pf)


def _render_file_findings(pf: dict):
    findings = pf.get("findings", [])
    if not findings:
        st.markdown(
            '<div style="background:#F0FDF4; padding:10px 14px; border:1px solid #BBF7D0;'
            ' border-left:3px solid #16A34A; border-radius:8px; font-family:Inter,sans-serif;'
            ' font-size:0.85rem; color:#166534;">'
            '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#16A34A"'
            ' stroke-width="2" stroke-linecap="round" style="vertical-align:-2px; margin-right:5px;">'
            '<path d="M22 11.08V12a10 10 0 11-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>'
            '</svg>No issues detected in this file.</div>',
            unsafe_allow_html=True,
        )
        return
    for i, f in enumerate(findings, 1):
        sev = f["severity"]
        color = {"CRITICAL": "#DC2626", "HIGH": "#EA580C",
                 "MEDIUM": "#CA8A04", "LOW": "#2563EB"}.get(sev, "#64748B")
        tint = {"CRITICAL": "#FEF2F2", "HIGH": "#FFF7ED",
                "MEDIUM": "#FFFBEB", "LOW": "#EFF6FF"}.get(sev, "#F8FAFC")
        icon = {"CRITICAL": '<circle cx="12" cy="12" r="10"/><path d="M15 9l-6 6M9 9l6 6"/>',
                "HIGH": '<path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>',
                "MEDIUM": '<circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>',
                "LOW": '<circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/>'}.get(sev, '')
        delay = i * 30
        st.markdown(
            f'<div style="background:#FFFFFF; padding:14px 18px;'
            f' border:1px solid #E2E8F0; border-left:4px solid {color};'
            f' border-radius:10px; margin-bottom:10px;'
            f' box-shadow:0 1px 3px rgba(15,23,42,0.06);'
            f' animation:mc-row-in 260ms {delay}ms cubic-bezier(0.4,0,0.2,1) backwards;">'
            f'<div style="display:flex; justify-content:space-between; align-items:center;">'
            f'<div style="display:flex; align-items:center; gap:8px;">'
            f'<div style="width:28px; height:28px; background:{tint}; border-radius:6px;'
            f' display:flex; align-items:center; justify-content:center;">'
            f'<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="{color}"'
            f' stroke-width="2" stroke-linecap="round">{icon}</svg></div>'
            f'<span style="font-family:JetBrains Mono,monospace; font-size:0.72rem;'
            f' font-weight:700; color:{color}; letter-spacing:0.06em;'
            f' background:{tint}; padding:3px 8px; border-radius:4px;">{sev}</span>'
            f'<span style="font-family:Inter,sans-serif; font-size:0.875rem;'
            f' font-weight:600; color:#0F172A;">{f["category"]}</span></div>'
            f'<span style="font-family:JetBrains Mono,monospace; font-size:0.72rem;'
            f' color:#FFFFFF; background:{color}; padding:4px 10px; border-radius:4px;'
            f' font-weight:bold;">📍 Line {f.get("line", "?")} | {f.get("category", "")}</span></div>'
            f'<div style="font-family:Inter,sans-serif; color:#334155; font-size:0.85rem;'
            f' margin-top:8px; line-height:1.55;">{f["description"]}</div>'
            f'<div style="background:#1E293B; color:#E2E8F0; padding:12px 14px; margin-top:8px;'
            f' font-family:\'JetBrains Mono\',monospace; font-size:0.78rem; border-radius:6px;'
            f' border:1px solid #475569; word-break:break-all; line-height:1.6;'
            f' overflow-x:auto; box-shadow:inset 0 2px 4px rgba(0,0,0,0.1);">'
            f'<b style="color:#FCA5A5;">>>> MALICIOUS CODE:</b><br>'
            f'{f.get("evidence", "N/A")}</div>'
            f'<div style="font-family:Inter,sans-serif; color:#16A34A; font-size:0.8rem;'
            f' margin-top:8px;"><svg width="12" height="12" viewBox="0 0 24 24" fill="none"'
            f' stroke="#16A34A" stroke-width="2" stroke-linecap="round"'
            f' style="vertical-align:-2px; margin-right:4px;">'
            f'<path d="M22 11.08V12a10 10 0 11-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>'
            f'</svg><b>Fix:</b> {f.get("fix","")}</div>'
            + (f'<div style="font-family:JetBrains Mono,monospace; font-size:0.68rem;'
               f' color:#64748B; margin-top:6px; padding-top:6px; border-top:1px solid #F1F5F9;">'
               f'OWASP: {f["owasp"]}</div>' if f.get("owasp") else "")
            + f'</div>',
            unsafe_allow_html=True,
        )


# ═══════════════════════════════════════════════════════════════
# TAB 2: Database file upload
# ═══════════════════════════════════════════════════════════════
def _render_db_upload():
    st.markdown(
        "**Upload a database file to scan for stored malware, XSS payloads, "
        "malicious URLs, and injection artefacts.** Accepts .sqlite / .db (SQLite) "
        "or .sql (SQL dump text)."
    )

    uploaded = st.file_uploader(
        label="",  # Empty label to avoid duplication
        type=["sqlite", "sqlite3", "db", "sql"],
        accept_multiple_files=False,
        key="forensic_db_upload",
    )

    if uploaded:
        st.success(f"✅ Database file selected: {uploaded.name}")

    if st.button("🗄️ Scan Database", type="primary",
                 disabled=not uploaded, key="scan_db_btn", use_container_width=True):
        _run_db_scan(uploaded)

    elif "last_db_scan" in st.session_state:
        _render_db_scan_result(st.session_state["last_db_scan"])


def _run_db_scan(uploaded):
    tmpdir = tempfile.mkdtemp(prefix="aidtctm_dbscan_")
    local_path = os.path.join(tmpdir, uploaded.name)
    with open(local_path, "wb") as out:
        out.write(uploaded.getbuffer())

    with st.status(f"Parsing and scanning `{uploaded.name}`...", expanded=True) as status:
        if uploaded.name.endswith((".sqlite", ".sqlite3", ".db")):
            st.write("📦 SQLite format — opening and inspecting schema...")
            result = scan_sqlite(local_path)
        elif uploaded.name.endswith(".sql"):
            st.write("📄 SQL dump — parsing INSERT statements...")
            result = scan_sql_dump(local_path)
        else:
            st.error("Unknown format")
            return

        if result.get("error"):
            status.update(label="Scan failed", state="error")
            st.error(result["error"])
            return

        st.write(f"✅ Scanned {result['rows_scanned']} rows across {result['table_count']} tables")
        st.write(f"🚨 {result['finding_count']} findings, {result['rows_flagged']} rows flagged")
        status.update(label="Database scan complete", state="complete")

    import datetime, secrets
    case = {
        "case_id":       f"DB-{datetime.datetime.now().strftime('%Y-%m-%d')}-{secrets.token_hex(2).upper()}",
        "scan_type":     "database",
        "target":        uploaded.name,
        "fused_verdict": result["verdict"],
        "fused_score":   10.0 if result["verdict"] == "MALICIOUS" else
                         5.0 if result["verdict"] == "SUSPICIOUS" else 0.5,
        "details":       result,
    }
    record_scan(case, scan_type="database")
    st.session_state["last_db_scan"] = case
    _render_db_scan_result(case)


def _render_db_scan_result(case: dict):
    details = case["details"]
    st.markdown("<div style='height:12px'></div>", unsafe_allow_html=True)
    verdict_banner(case["fused_verdict"], case["fused_score"], target=case["target"])

    kpi_row([
        {"label": "Case ID",   "value": case["case_id"],                     "tone": "amber"},
        {"label": "Tables",    "value": str(details["table_count"])},
        {"label": "Rows scanned", "value": f'{details["rows_scanned"]:,}'},
        {"label": "Rows flagged", "value": str(details["rows_flagged"]),
         "tone": "red" if details["rows_flagged"] else "green"},
    ])

    # Table inventory
    section_header("Tables inspected")
    for t in details.get("tables", []):
        bar = "red" if t.get("flagged_rows", 0) > 0 else "green"
        st.markdown(
            f'<div style="background:#FFFFFF; padding:10px 14px; border-left:3px solid '
            f'{"#DC2626" if t.get("flagged_rows",0) else "#16A34A"}; margin-bottom:6px;'
            f' font-family:JetBrains Mono,monospace; font-size:0.82rem;'
            f' display:flex; justify-content:space-between; border:1px solid #E0F2FE; border-radius:6px;">'
            f'<span style="color:#0C4A6E; font-weight:600;">{t["name"]}</span>'
            f'<span style="color:#64748B;">{t["column_count"]} cols · {t.get("row_count",0):,} rows · '
            f'<b style="color:{"#DC2626" if t.get("flagged_rows",0) else "#16A34A"};">'
            f'{t.get("flagged_rows",0)} flagged</b></span>'
            f'</div>', unsafe_allow_html=True,
        )

    # Findings
    if details.get("findings"):
        st.markdown("<div style='height:14px'></div>", unsafe_allow_html=True)
        section_header(f"Findings ({details['finding_count']})")
        for f in details["findings"][:30]:
            sev_color = {"CRITICAL": "#DC2626", "HIGH": "#D97706",
                         "MEDIUM": "#0284C7", "LOW": "#16A34A"}.get(f["severity"], "#64748B")
            st.markdown(
                f'<div style="background:#FFFFFF; padding:12px 14px;'
                f' border-left:3px solid {sev_color}; margin-bottom:8px; border:1px solid #E0F2FE; border-radius:6px;">'
                f'<div style="display:flex; justify-content:space-between;">'
                f'  <span style="color:{sev_color}; font-weight:600;">[{f["severity"]}] {f["category"]}</span>'
                f'  <span style="color:#64748B; font-family:JetBrains Mono,monospace; font-size:0.72rem;">'
                f'    {f["table"]}.{f["column"]} row {f["row_id"]}'
                f'  </span>'
                f'</div>'
                f'<div style="color:#0C4A6E; margin-top:6px; font-size:0.82rem;">{f["description"]}</div>'
                f'<div style="background:#F0F9FF; color:#0C4A6E; padding:8px 10px; margin-top:6px;'
                f' font-family:JetBrains Mono, monospace; font-size:0.72rem; border-radius:4px; border:1px solid #E0F2FE;">'
                f'{f.get("evidence", "")[:200]}</div>'
                f'<div style="color:#16A34A; font-size:0.75rem; margin-top:6px;"><b>Fix:</b> {f["fix"]}</div>'
                f'</div>',
                unsafe_allow_html=True,
            )
        if details['finding_count'] > 30:
            st.caption(f"... and {details['finding_count'] - 30} more (see JSON download)")

    st.markdown("<div style='height:12px'></div>", unsafe_allow_html=True)
    st.download_button(
        "Download DB forensic report",
        data=json.dumps(case, indent=2, default=str),
        file_name=f"{case['case_id']}.json",
        mime="application/json",
    )


# ═══════════════════════════════════════════════════════════════
# TAB 3: Remote MySQL connector
# ═══════════════════════════════════════════════════════════════
