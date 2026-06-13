"""
AI-DTCTM | PDF Report Generator for Forensic Scanner
=====================================================
Generates professional PDF reports for scan findings.
"""
from __future__ import annotations

from datetime import datetime
from io import BytesIO
from pathlib import Path

try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False


def generate_forensic_report(case: dict) -> BytesIO | None:
    """
    Generate professional PDF report for forensic scan results.
    Returns BytesIO object ready for download, or None if reportlab unavailable.
    """
    if not HAS_REPORTLAB:
        return None

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter,
                           topMargin=0.5*inch, bottomMargin=0.5*inch,
                           leftMargin=0.75*inch, rightMargin=0.75*inch)

    styles = getSampleStyleSheet()
    story = []

    # ── Header ────────────────────────────────────────────
    header_style = ParagraphStyle(
        'CustomHeader',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=colors.HexColor('#2563EB'),
        spaceAfter=6,
        fontName='Helvetica-Bold'
    )
    story.append(Paragraph("AI-DTCTM Forensic Report", header_style))

    subtitle_style = ParagraphStyle(
        'Subtitle',
        parent=styles['Normal'],
        fontSize=9,
        textColor=colors.HexColor('#64748B'),
        spaceAfter=18
    )
    story.append(Paragraph(f"Case ID: {case.get('case_id', 'N/A')}", subtitle_style))

    # ── Summary KPIs ──────────────────────────────────────
    summary_data = [
        ['Metric', 'Value'],
        ['Scan Date', datetime.now().strftime('%Y-%m-%d %H:%M:%S')],
        ['Total Findings', str(case.get('total_findings', 0))],
        ['Critical Issues', str(case.get('severity_totals', {}).get('critical', 0))],
        ['High Issues', str(case.get('severity_totals', {}).get('high', 0))],
        ['Medium Issues', str(case.get('severity_totals', {}).get('medium', 0))],
        ['Verdict', case.get('fused_verdict', 'UNKNOWN')],
        ['Risk Score', f"{case.get('fused_score', 0.0):.1f}/10"],
    ]

    summary_table = Table(summary_data, colWidths=[2.5*inch, 2.5*inch])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2563EB')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 11),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#F8FAFC')),
        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#E2E8F0')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#F8FAFC')]),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 0.3*inch))

    # ── Findings ──────────────────────────────────────────
    if case.get('total_findings', 0) > 0:
        findings_title = ParagraphStyle(
            'FindingsTitle',
            parent=styles['Heading2'],
            fontSize=14,
            textColor=colors.HexColor('#0F172A'),
            spaceAfter=12,
            fontName='Helvetica-Bold'
        )
        story.append(Paragraph("Detailed Findings", findings_title))

        findings_data = [
            ['File', 'Type', 'Severity', 'Line', 'Finding', 'Evidence']
        ]

        for pf in case.get('per_file_results', []):
            for finding in pf.get('findings', [])[:20]:  # Max 20 per page
                findings_data.append([
                    pf.get('filename', 'N/A')[:20],
                    finding.get('category', 'N/A')[:15],
                    finding.get('severity', 'N/A'),
                    str(finding.get('line', 'N/A')),
                    finding.get('title', 'N/A')[:30],
                    finding.get('evidence', 'N/A')[:30],
                ])

        findings_table = Table(findings_data, colWidths=[1*inch, 0.8*inch, 0.7*inch, 0.5*inch, 1.3*inch, 1.2*inch])
        findings_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2563EB')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 9),
            ('FONTSIZE', (0, 1), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#E2E8F0')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#F8FAFC')]),
        ]))
        story.append(findings_table)

    story.append(Spacer(1, 0.2*inch))

    # ── Detection Layers ──────────────────────────────────
    layers_title = ParagraphStyle(
        'LayersTitle',
        parent=styles['Heading2'],
        fontSize=14,
        textColor=colors.HexColor('#0F172A'),
        spaceAfter=12,
        fontName='Helvetica-Bold'
    )
    story.append(Paragraph("Detection Layers Applied", layers_title))

    layers_text = """
    <b>Layer 1 - YARA Signatures:</b> 25 rules for webshells, ransomware, RATs, backdoors<br/>
    <b>Layer 2 - Heuristic Regex:</b> 50+ patterns for suspicious calls, hardcoded secrets, data exfiltration<br/>
    <b>Layer 3 - Static Code Analysis (AST):</b> Control-flow taint analysis, code injection risks<br/>
    <b>Layer 4 - Hash Reputation (MalwareBazaar):</b> Binary/script hash lookup against abuse.ch<br/>
    <b>Layer 5 - Entropy Analysis:</b> Detects high-entropy (compressed/encrypted) payloads<br/>
    """
    story.append(Paragraph(layers_text, styles['Normal']))

    # ── Footer ────────────────────────────────────────────
    story.append(Spacer(1, 0.3*inch))
    footer_text = f"Report generated by AI-DTCTM v20.0 on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    story.append(Paragraph(footer_text, ParagraphStyle(
        'Footer',
        parent=styles['Normal'],
        fontSize=8,
        textColor=colors.HexColor('#94A3B8'),
        alignment=TA_CENTER
    )))

    # Build PDF
    doc.build(story)
    buffer.seek(0)
    return buffer


# ── OWASP Top 10 mapping for attack types ─────────────────────────
_OWASP_MAP: dict[str, tuple[str, str]] = {
    "eicar":              ("A08:2021", "Software & Data Integrity Failures"),
    "php_webshell":       ("A08:2021", "Software & Data Integrity Failures"),
    "php_dropper":        ("A08:2021", "Software & Data Integrity Failures"),
    "path_traversal":     ("A01:2021", "Broken Access Control"),
    "header_injection":   ("A03:2021", "Injection"),
    "file_upload_exploit":("A04:2021", "Insecure Design"),
    "sqli":               ("A03:2021", "Injection"),
    "xss":                ("A03:2021", "Injection"),
    "ssrf":               ("A10:2021", "Server-Side Request Forgery"),
    "open_redirect":      ("A01:2021", "Broken Access Control"),
    "rce":                ("A03:2021", "Injection"),
}

_ALL_OWASP = [
    ("A01:2021", "Broken Access Control"),
    ("A02:2021", "Cryptographic Failures"),
    ("A03:2021", "Injection"),
    ("A04:2021", "Insecure Design"),
    ("A05:2021", "Security Misconfiguration"),
    ("A06:2021", "Vulnerable & Outdated Components"),
    ("A07:2021", "Identification & Auth Failures"),
    ("A08:2021", "Software & Data Integrity Failures"),
    ("A09:2021", "Security Logging Failures"),
    ("A10:2021", "Server-Side Request Forgery"),
]


def generate_dt_report(
    target_url: str,
    stack: dict,
    attack_logs: dict[str, list[dict]],
    clone_id: str = "",
) -> "BytesIO | None":
    """
    Generate a professional PDF Security Assessment Report for Digital Twin results.

    attack_logs: {sample_key: [event_dicts]}  — from state["lab_log_*"]
    Returns BytesIO ready for st.download_button, or None if reportlab missing.
    """
    if not HAS_REPORTLAB:
        return None

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    case_id = f"DT-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    lang = (stack or {}).get("language", "unknown")

    buffer = BytesIO()
    # v33: tighter margins + on-page header/footer via canvas callbacks
    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        topMargin=0.85*inch, bottomMargin=0.65*inch,
        leftMargin=0.7*inch, rightMargin=0.7*inch,
        title=f"AI-DTCTM Security Assessment — {case_id}",
        author="AI-DTCTM",
        subject="Digital Twin Live Attack Assessment",
    )
    styles = getSampleStyleSheet()
    story  = []

    # v33: polished typography hierarchy. ParagraphStyle gets distinct
    # sizes/colors for each level + consistent leading and spacing so
    # the layout no longer feels cramped or mismatched.
    def _h1(text, color="#0F172A"):
        return Paragraph(text, ParagraphStyle("H1", parent=styles["Heading1"],
            fontSize=24, leading=28, textColor=colors.HexColor(color),
            spaceAfter=2, spaceBefore=0, fontName="Helvetica-Bold",
            letterSpacing=0.4))

    def _subtitle(text, color="#1E40AF"):
        return Paragraph(text, ParagraphStyle("ST", parent=styles["Normal"],
            fontSize=10, leading=14, textColor=colors.HexColor(color),
            spaceAfter=2, fontName="Helvetica-Bold"))

    def _h2(text, color="#0F172A"):
        # Section heading with subtle bottom border feel via spaceAfter
        return Paragraph(text, ParagraphStyle("H2", parent=styles["Heading2"],
            fontSize=14, leading=18, textColor=colors.HexColor(color),
            spaceAfter=8, spaceBefore=16, fontName="Helvetica-Bold",
            borderPadding=(0, 0, 4, 0)))

    def _h3(text, color="#1E40AF"):
        return Paragraph(text, ParagraphStyle("H3", parent=styles["Heading3"],
            fontSize=11, leading=14, textColor=colors.HexColor(color),
            spaceAfter=4, spaceBefore=10, fontName="Helvetica-Bold"))

    def _body(text):
        return Paragraph(text, ParagraphStyle("B", parent=styles["Normal"],
            fontSize=9.5, leading=14.5,
            textColor=colors.HexColor("#1F2937"),
            spaceAfter=4, fontName="Helvetica"))

    def _caption(text):
        return Paragraph(text, ParagraphStyle("C", parent=styles["Normal"],
            fontSize=8, leading=11,
            textColor=colors.HexColor("#64748B"), fontName="Helvetica"))

    # Reusable accent rule (thin colored bar above a heading)
    def _accent_bar(width=6.7*inch, color="#1E40AF"):
        bar = Table([[" "]], colWidths=[width], rowHeights=[2])
        bar.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,-1), colors.HexColor(color)),
            ("LEFTPADDING",(0,0), (-1,-1), 0),
            ("RIGHTPADDING",(0,0),(-1,-1), 0),
            ("TOPPADDING", (0,0), (-1,-1), 0),
            ("BOTTOMPADDING",(0,0),(-1,-1), 0),
        ]))
        return bar

    # ── Cover section — accent bar + classification banner + brand row ─
    cls_banner = Table(
        [["RESTRICTED · INTERNAL USE", f"Case {case_id}"]],
        colWidths=[3.35*inch, 3.35*inch]
    )
    cls_banner.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (0,0), colors.HexColor("#DC2626")),
        ("BACKGROUND", (1,0), (1,0), colors.HexColor("#1E40AF")),
        ("TEXTCOLOR",  (0,0), (-1,-1), colors.whitesmoke),
        ("FONTNAME",   (0,0), (-1,-1), "Helvetica-Bold"),
        ("FONTSIZE",   (0,0), (-1,-1), 8),
        ("ALIGN",      (0,0), (0,0), "LEFT"),
        ("ALIGN",      (1,0), (1,0), "RIGHT"),
        ("LEFTPADDING",(0,0), (-1,-1), 10),
        ("RIGHTPADDING",(0,0),(-1,-1), 10),
        ("TOPPADDING", (0,0), (-1,-1), 5),
        ("BOTTOMPADDING",(0,0),(-1,-1), 5),
    ]))
    story.append(cls_banner)
    story.append(Spacer(1, 0.22*inch))
    story.append(_accent_bar())
    story.append(Spacer(1, 0.08*inch))
    story.append(_h1("AI-DTCTM Security Assessment Report"))
    story.append(_subtitle("Digital Twin · Live Attack Simulation · ML Detection Pipeline"))
    story.append(_caption(
        f"Generated {now_str}   ·   Engine AI-DTCTM Digital Twin v24   ·   "
        f"Methodology docker exec + HTTP exploitation + numpy-MLP ML"
    ))
    story.append(Spacer(1, 0.18*inch))

    # Meta table
    meta = [
        ["Assessment Type", "Digital Twin Live Attack Simulation"],
        ["Target",          target_url or "—"],
        ["Stack",           lang.title()],
        ["Clone ID",        clone_id or "—"],
        ["Assessment Date", now_str],
        ["Methodology",     "docker exec primary · HTTP secondary · ML detection"],
    ]
    mt = Table(meta, colWidths=[2*inch, 4.5*inch])
    mt.setStyle(TableStyle([
        ("BACKGROUND",   (0,0), (0,-1), colors.HexColor("#EFF6FF")),
        ("TEXTCOLOR",    (0,0), (0,-1), colors.HexColor("#1E40AF")),
        ("FONTNAME",     (0,0), (0,-1), "Helvetica-Bold"),
        ("FONTSIZE",     (0,0), (-1,-1), 9),
        ("GRID",         (0,0), (-1,-1), 0.5, colors.HexColor("#DBEAFE")),
        ("ROWBACKGROUNDS",(0,0),(-1,-1), [colors.white, colors.HexColor("#F8FAFC")]),
        ("BOTTOMPADDING",(0,0),(-1,-1), 7),
        ("TOPPADDING",   (0,0),(-1,-1), 7),
    ]))
    story.append(mt)
    story.append(Spacer(1, 0.2*inch))

    # ── Attack summary ────────────────────────────────────────────
    total_crits  = sum(1 for log in attack_logs.values() for e in log if e.get("status") == "crit")
    total_events = sum(len(log) for log in attack_logs.values())
    attacks_run  = sum(1 for log in attack_logs.values() if log)
    risk_level   = "CRITICAL" if total_crits >= 3 else "HIGH" if total_crits >= 1 else "LOW"
    risk_color   = "#DC2626" if risk_level == "CRITICAL" else "#EA580C" if risk_level == "HIGH" else "#16A34A"

    story.append(_h2("Executive Summary"))
    exec_rows = [
        ["Metric",              "Value"],
        ["Overall Risk Level",  risk_level],
        ["Attacks Executed",    str(attacks_run)],
        ["Total Events",        str(total_events)],
        ["Critical Findings",   str(total_crits)],
        ["Container Access",    "root via docker exec (100% of stacks)"],
        ["Verdict",             "COMPROMISED" if total_crits > 0 else "RESILIENT"],
    ]
    et = Table(exec_rows, colWidths=[2.5*inch, 4*inch])
    et.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0),  colors.HexColor("#1E40AF")),
        ("TEXTCOLOR",     (0,0), (-1,0),  colors.whitesmoke),
        ("FONTNAME",      (0,0), (-1,0),  "Helvetica-Bold"),
        ("FONTSIZE",      (0,0), (-1,-1), 9),
        ("GRID",          (0,0), (-1,-1), 0.5, colors.HexColor("#E2E8F0")),
        ("ROWBACKGROUNDS",(0,1),(-1,-1), [colors.white, colors.HexColor("#F8FAFC")]),
        ("BOTTOMPADDING", (0,0),(-1,-1), 7),
        ("TOPPADDING",    (0,0),(-1,-1), 7),
        ("TEXTCOLOR",     (1,2),(1,2),   colors.HexColor(risk_color)),
        ("FONTNAME",      (1,2),(1,2),   "Helvetica-Bold"),
    ]))
    story.append(et)
    story.append(Spacer(1, 0.2*inch))

    # ── OWASP Top 10 coverage ─────────────────────────────────────
    story.append(_h2("OWASP Top 10 (2021) Coverage"))
    tested_ids = {_OWASP_MAP.get(k, ("",""))[0] for k in attack_logs if attack_logs[k]}
    owasp_rows = [["ID", "Category", "Status"]]
    for oid, oname in _ALL_OWASP:
        hit = any(
            _OWASP_MAP.get(k, ("",""))[0] == oid and attack_logs.get(k)
            for k in attack_logs
        )
        status = "✓ Tested" if oid in tested_ids else "— Not tested"
        owasp_rows.append([oid, oname, status])
    ot = Table(owasp_rows, colWidths=[1.1*inch, 3.8*inch, 1.5*inch])
    ot.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0), colors.HexColor("#1E40AF")),
        ("TEXTCOLOR",     (0,0), (-1,0), colors.whitesmoke),
        ("FONTNAME",      (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",      (0,0), (-1,-1), 8),
        ("GRID",          (0,0), (-1,-1), 0.5, colors.HexColor("#E2E8F0")),
        ("ROWBACKGROUNDS",(0,1),(-1,-1), [colors.white, colors.HexColor("#F8FAFC")]),
        ("BOTTOMPADDING", (0,0),(-1,-1), 6),
        ("TOPPADDING",    (0,0),(-1,-1), 6),
    ]))
    story.append(ot)
    story.append(Spacer(1, 0.2*inch))

    # ── Per-attack findings ───────────────────────────────────────
    story.append(_h2("Attack-by-Attack Findings"))
    _LABELS = {
        "eicar": "EICAR AV Test", "php_webshell": "PHP Webshell (RCE)",
        "php_dropper": "Live Malware Drop", "path_traversal": "Path Traversal (LFI)",
        "header_injection": "Header Injection", "file_upload_exploit": "File Upload → Shell",
    }
    atk_rows = [["Attack", "Result", "Critical Events", "OWASP", "Risk"]]
    for key, log in attack_logs.items():
        if not log:
            continue
        crits = sum(1 for e in log if e.get("status") == "crit")
        oid, _ = _OWASP_MAP.get(key, ("—", "—"))
        verdict = "COMPROMISED" if crits > 0 else "CLEAN"
        risk = "CRITICAL" if crits >= 2 else "HIGH" if crits == 1 else "LOW"
        atk_rows.append([
            _LABELS.get(key, key), verdict, str(crits), oid, risk
        ])
    if len(atk_rows) > 1:
        at = Table(atk_rows, colWidths=[1.7*inch, 1.2*inch, 1.1*inch, 0.9*inch, 0.9*inch])
        at.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,0), colors.HexColor("#1E40AF")),
            ("TEXTCOLOR",     (0,0), (-1,0), colors.whitesmoke),
            ("FONTNAME",      (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE",      (0,0), (-1,-1), 8),
            ("GRID",          (0,0), (-1,-1), 0.5, colors.HexColor("#E2E8F0")),
            ("ROWBACKGROUNDS",(0,1),(-1,-1), [colors.white, colors.HexColor("#F8FAFC")]),
            ("BOTTOMPADDING", (0,0),(-1,-1), 6),
            ("TOPPADDING",    (0,0),(-1,-1), 6),
        ]))
        story.append(at)

    story.append(Spacer(1, 0.2*inch))

    # ── Recommendations ───────────────────────────────────────────
    story.append(_h2("Recommendations"))
    recs = [
        "1. Restrict docker exec access — never expose the Docker socket to untrusted processes.",
        "2. Run containers as non-root (USER directive in Dockerfile) to limit exec impact.",
        "3. Disable PHP execution in upload directories (php_admin_flag off).",
        "4. Sanitise ALL user inputs including HTTP headers (X-Forwarded-For, User-Agent).",
        "5. Implement Content-Security-Policy and file-type validation on upload endpoints.",
        "6. Deploy AV scanning on every file write path — EICAR test must be caught at upload.",
        "7. Use read-only container filesystems where possible (--read-only Docker flag).",
        "8. Regularly scan images with Trivy / Grype for known CVEs before deployment.",
    ]
    for r in recs:
        story.append(_body(r))
        story.append(Spacer(1, 0.04*inch))

    # ── Footer ────────────────────────────────────────────────────
    story.append(Spacer(1, 0.3*inch))
    story.append(Paragraph(
        f"AI-DTCTM Security Assessment · Case {case_id} · {now_str} · CONFIDENTIAL",
        ParagraphStyle("Footer", parent=styles["Normal"], fontSize=7,
                       textColor=colors.HexColor("#94A3B8"), alignment=TA_CENTER)
    ))

    # v33: on-every-page header/footer with brand bar + page number
    def _on_page(canvas, doc_):
        canvas.saveState()
        # Top header band
        canvas.setFillColor(colors.HexColor("#1E40AF"))
        canvas.rect(0, A4[1] - 0.45*inch, A4[0], 0.45*inch, fill=1, stroke=0)
        canvas.setFillColor(colors.whitesmoke)
        canvas.setFont("Helvetica-Bold", 8.5)
        canvas.drawString(0.7*inch, A4[1] - 0.27*inch,
                           "AI-DTCTM   ·   DIGITAL TWIN SECURITY ASSESSMENT")
        canvas.setFont("Helvetica", 7.5)
        canvas.drawRightString(A4[0] - 0.7*inch, A4[1] - 0.27*inch,
                                f"{case_id}   ·   RESTRICTED")
        # Bottom footer
        canvas.setStrokeColor(colors.HexColor("#CBD5E1"))
        canvas.setLineWidth(0.4)
        canvas.line(0.7*inch, 0.5*inch, A4[0] - 0.7*inch, 0.5*inch)
        canvas.setFillColor(colors.HexColor("#64748B"))
        canvas.setFont("Helvetica", 7)
        canvas.drawString(0.7*inch, 0.34*inch,
                           f"Generated {now_str}   ·   AI-DTCTM v24")
        canvas.drawRightString(A4[0] - 0.7*inch, 0.34*inch,
                                f"Page {doc_.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=_on_page, onLaterPages=_on_page)
    buffer.seek(0)
    return buffer


def generate_apk_report(report: dict, workbench: dict | None,
                         attack_results: dict | None) -> "BytesIO | None":
    """
    Generate a professional PDF for APK static analysis results.
    """
    if not HAS_REPORTLAB:
        return None

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    case_id = f"APK-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    md = report.get("metadata", {})
    sev = report.get("severity", "UNKNOWN")
    score = report.get("score", 0)

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4,
                            topMargin=0.6*inch, bottomMargin=0.6*inch,
                            leftMargin=0.8*inch, rightMargin=0.8*inch)
    styles = getSampleStyleSheet()
    story  = []

    def _h1(t, c="#1E40AF"): return Paragraph(t, ParagraphStyle("H1b",
        parent=styles["Heading1"], fontSize=22, textColor=colors.HexColor(c),
        spaceAfter=4, fontName="Helvetica-Bold"))
    def _h2(t, c="#0F172A"): return Paragraph(t, ParagraphStyle("H2b",
        parent=styles["Heading2"], fontSize=13, textColor=colors.HexColor(c),
        spaceAfter=6, spaceBefore=14, fontName="Helvetica-Bold"))
    def _body(t): return Paragraph(t, ParagraphStyle("Bb",
        parent=styles["Normal"], fontSize=9, textColor=colors.HexColor("#374151"), leading=14))
    def _cell_style(t): return TableStyle([
        ("BACKGROUND",    (0,0), (-1,0), colors.HexColor("#1E40AF")),
        ("TEXTCOLOR",     (0,0), (-1,0), colors.whitesmoke),
        ("FONTNAME",      (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",      (0,0), (-1,-1), 8),
        ("GRID",          (0,0), (-1,-1), 0.5, colors.HexColor("#E2E8F0")),
        ("ROWBACKGROUNDS",(0,1),(-1,-1), [colors.white, colors.HexColor("#F8FAFC")]),
        ("BOTTOMPADDING", (0,0),(-1,-1), 6),
        ("TOPPADDING",    (0,0),(-1,-1), 6),
    ])

    # Cover
    story.append(_h1("AI-DTCTM — APK Security Analysis Report"))
    story.append(Paragraph(
        f"Case ID: {case_id}  ·  Generated: {now_str}",
        ParagraphStyle("C", parent=styles["Normal"], fontSize=8,
                       textColor=colors.HexColor("#64748B"), leading=12)
    ))
    story.append(Spacer(1, 0.15*inch))

    sev_color = {"CRITICAL":"#DC2626","HIGH":"#EA580C","MEDIUM":"#D97706",
                 "LOW":"#16A34A","CLEAN":"#16A34A"}.get(sev, "#64748B")
    meta_rows = [
        ["Package",        md.get("package", "—")],
        ["SHA-256",        (md.get("sha256","")[:48] + "…") if md.get("sha256") else "—"],
        ["Size",           f"{md.get('size_bytes',0)//1024} KB"],
        ["Signed",         str(md.get("signed","—"))],
        ["Verdict",        sev],
        ["Risk Score",     f"{score}/10"],
        ["DEX files",      str(md.get("dex_count","—"))],
        ["Native libs",    str(len(md.get("native_libs",[])))],
        ["Assessment Date",now_str],
    ]
    mt = Table(meta_rows, colWidths=[1.8*inch, 4.7*inch])
    mt.setStyle(_cell_style(None))
    story.append(mt)
    story.append(Spacer(1, 0.2*inch))

    # Permissions
    story.append(_h2("Dangerous Permissions"))
    danger = report.get("permissions", [])
    if danger:
        perm_rows = [["Permission", "Severity", "Risk"]]
        for p in danger[:30]:
            perm_rows.append([
                p.get("name","?").split(".")[-1],
                p.get("severity","?"),
                p.get("description","?")[:60],
            ])
        pt = Table(perm_rows, colWidths=[1.8*inch, 0.9*inch, 3.8*inch])
        pt.setStyle(_cell_style(None))
        story.append(pt)
    else:
        story.append(_body("No dangerous permissions detected."))
    story.append(Spacer(1, 0.15*inch))

    # Permission combos
    combos = report.get("permission_combos", [])
    if combos:
        story.append(_h2("Malware Permission Combos", "#DC2626"))
        combo_rows = [["Combo", "Severity", "Description"]]
        for c in combos[:15]:
            combo_rows.append([
                " + ".join(p.split(".")[-1] for p in c.get("permissions", []))[:30],
                c.get("severity","?"),
                c.get("description","?")[:55],
            ])
        ct = Table(combo_rows, colWidths=[1.8*inch, 0.9*inch, 3.8*inch])
        ct.setStyle(_cell_style(None))
        story.append(ct)
        story.append(Spacer(1, 0.15*inch))

    # Suspicious strings / secrets
    story.append(_h2("Hardcoded Secrets & Suspicious Strings"))
    susp = report.get("suspicious_strings", [])
    if susp:
        ss_rows = [["Severity", "Description", "Match"]]
        for s in susp[:25]:
            ss_rows.append([
                s.get("severity","?"),
                s.get("description","?")[:35],
                s.get("match","?")[:40],
            ])
        st2 = Table(ss_rows, colWidths=[0.8*inch, 2.4*inch, 3.3*inch])
        st2.setStyle(_cell_style(None))
        story.append(st2)
    else:
        story.append(_body("No hardcoded secrets or suspicious strings detected."))
    story.append(Spacer(1, 0.15*inch))

    # 30-attack results
    if attack_results:
        story.append(_h2("30-Pattern Static Attack Suite Results"))
        sc = attack_results.get("score", 0)
        lbl = attack_results.get("label", "?")
        bysev = attack_results.get("by_severity", {})
        story.append(_body(
            f"Security Score: <b>{sc}/100</b>  ·  Label: <b>{lbl}</b>  ·  "
            f"CRITICAL: {bysev.get('CRITICAL',0)}  HIGH: {bysev.get('HIGH',0)}  "
            f"MEDIUM: {bysev.get('MEDIUM',0)}"
        ))
        story.append(Spacer(1, 0.08*inch))
        triggered = [f for f in attack_results.get("findings",[]) if f.get("triggered")]
        if triggered:
            tr_rows = [["Pattern", "Severity", "Description"]]
            for f in triggered[:20]:
                tr_rows.append([
                    f.get("name","?")[:28],
                    f.get("severity","?"),
                    f.get("description","?")[:50],
                ])
            trt = Table(tr_rows, colWidths=[2*inch, 0.9*inch, 3.6*inch])
            trt.setStyle(_cell_style(None))
            story.append(trt)

    # Attack surface
    surf = (workbench or {}).get("attack_surface", {})
    urls = surf.get("urls", [])
    secrets = (surf.get("aws",[]) + surf.get("google",[]) +
               surf.get("github",[]) + surf.get("secrets",[]))
    if urls or secrets:
        story.append(Spacer(1, 0.15*inch))
        story.append(_h2("Attack Surface — URLs & Secrets Found in APK"))
        if urls:
            story.append(_body(f"<b>{len(urls)} URLs</b> extracted from DEX strings:"))
            for url, _ in urls[:10]:
                story.append(_body(f"  • {url[:80]}"))
        if secrets:
            story.append(_body(f"<b>{len(secrets)} secrets/tokens</b> detected:"))
            for path, match in secrets[:10]:
                story.append(_body(f"  • {match[:70]}  (in {path[:30]})"))

    # Recommendations
    story.append(Spacer(1, 0.2*inch))
    story.append(_h2("Recommendations"))
    recs = [
        "1. Remove ALL hardcoded API keys, tokens and passwords from source code.",
        "2. Implement certificate pinning to prevent MITM interception.",
        "3. Obfuscate DEX bytecode with R8/ProGuard to prevent string extraction.",
        "4. Review every permission — remove any not strictly required (least privilege).",
        "5. Sanitise exported Activity/Service/Receiver components in AndroidManifest.xml.",
        "6. Use Android Keystore for all sensitive key material — never hardcode.",
        "7. Implement root/emulator detection for sensitive user flows.",
        "8. Run automated SAST (MobSF, QARK) in CI/CD pipeline on every build.",
    ]
    for r in recs:
        story.append(_body(r))
        story.append(Spacer(1, 0.04*inch))

    # Footer
    story.append(Spacer(1, 0.3*inch))
    story.append(Paragraph(
        f"AI-DTCTM APK Analysis · Case {case_id} · {now_str} · CONFIDENTIAL",
        ParagraphStyle("Footer", parent=styles["Normal"], fontSize=7,
                       textColor=colors.HexColor("#94A3B8"), alignment=TA_CENTER)
    ))
    doc.build(story)
    buffer.seek(0)
    return buffer
