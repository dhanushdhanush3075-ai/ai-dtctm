"""
AI-DTCTM | Shield Monitor (v24 — Phase 3M)
══════════════════════════════════════════════════════════════════════
Full system monitoring — your device only:
  1. Network Monitor   — live connections + geo + AbuseIPDB threat check
  2. Process Monitor   — all running processes, flag suspicious ones
  3. System Info       — OS, CPU, RAM, disk usage (platform + psutil)
  4. USB / Disk Monitor — connected storage devices, flag new insertions
  5. LAN Scanner       — find devices on your local network

NOT included: packet capture, screenshot exfiltration, remote control.
This monitors YOUR device to verify clone containment safety.
"""
from __future__ import annotations

import time
import socket
import platform
import concurrent.futures
from typing import Optional

import streamlit as st

from core.shared_css import section_header, kpi_row
from core.logger import get_logger

log = get_logger(__name__)

try:
    import psutil
    _PSUTIL = True
except ImportError:
    _PSUTIL = False


# ══════════════════════════════════════════════════════════════════
# EMAIL ALERT MODULE (Phase 3M)
# ══════════════════════════════════════════════════════════════════
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


def _send_threat_alert(
    recipient: str,
    subject: str,
    body_html: str,
    smtp_server: str = "smtp.gmail.com",
    smtp_port: int = 587,
    sender_email: str = "",
    sender_password: str = "",
) -> bool:
    """
    Send HTML email alert when threat detected.
    
    For Gmail: user must generate App Password:
    Google Account → Security → 2-Step Verification → App Passwords
    """
    if not sender_email or not sender_password:
        log.warning("email_alert_skipped_no_creds")
        return False

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = sender_email
        msg["To"]      = recipient
        msg.attach(MIMEText(body_html, "html"))

        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.ehlo()
            server.starttls()
            server.login(sender_email, sender_password)
            server.send_message(msg)

        log.info("threat_alert_sent", to=recipient, subject=subject[:50])
        return True
    except Exception as e:
        log.error("email_alert_failed", error=str(e)[:200])
        return False


def _build_threat_email(threats: list[dict], scan_type: str = "Network") -> str:
    """Build HTML email body from list of threat findings."""
    rows = ""
    for t in threats[:20]:
        rows += (
            f'<tr style="border-bottom:1px solid #E2E8F0;">'
            f'<td style="padding:8px 12px; color:#DC2626; font-weight:bold;">'
            f'{t.get("verdict", "SUSPICIOUS")}</td>'
            f'<td style="padding:8px 12px;">{t.get("process", "—")}</td>'
            f'<td style="padding:8px 12px; font-family:monospace;">'
            f'{t.get("remote_ip", "—")}:{t.get("remote_port", "—")}</td>'
            f'<td style="padding:8px 12px;">{t.get("country", "?")}</td>'
            f'</tr>'
        )

    return f"""
    <html><body style="font-family:Arial,sans-serif; background:#F8FAFC; padding:20px;">
    <div style="max-width:600px; margin:0 auto; background:#FFFFFF;
                border-radius:12px; overflow:hidden;
                box-shadow:0 4px 12px rgba(0,0,0,0.1);">
      <div style="background:linear-gradient(90deg,#DC2626,#991B1B);
                  padding:20px 24px; color:#FFFFFF;">
        <h2 style="margin:0;">🚨 AI-DTCTM Threat Alert</h2>
        <p style="margin:6px 0 0; opacity:0.9;">{scan_type} scan detected suspicious activity</p>
      </div>
      <div style="padding:20px 24px;">
        <p style="color:#334155; font-size:14px;">
          <strong>{len(threats)}</strong> suspicious connection(s) detected on your device.
          Review immediately.
        </p>
        <table style="width:100%; border-collapse:collapse; margin-top:16px;
                      font-size:13px;">
          <thead>
            <tr style="background:#F1F5F9;">
              <th style="padding:8px 12px; text-align:left; color:#64748B;">Verdict</th>
              <th style="padding:8px 12px; text-align:left; color:#64748B;">Process</th>
              <th style="padding:8px 12px; text-align:left; color:#64748B;">Remote IP</th>
              <th style="padding:8px 12px; text-align:left; color:#64748B;">Country</th>
            </tr>
          </thead>
          <tbody>{rows}</tbody>
        </table>
        <p style="color:#94A3B8; font-size:12px; margin-top:20px;">
          Sent by AI-DTCTM Shield Monitor · {time.strftime('%Y-%m-%d %H:%M:%S')}
        </p>
      </div>
    </div>
    </body></html>
    """


# ── Known-safe process names (won't flag these) ─────────────────
SAFE_PROCESSES = {
    "system", "system idle process", "registry", "smss.exe", "csrss.exe",
    "wininit.exe", "services.exe", "lsass.exe", "lsaiso.exe",
    "svchost.exe", "explorer.exe", "taskhostw.exe", "sihost.exe",
    "fontdrvhost.exe", "dwm.exe", "winlogon.exe", "audiodg.exe",
    "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe",
    "code.exe", "python.exe", "pythonw.exe", "node.exe", "streamlit",
    "cmd.exe", "powershell.exe", "conhost.exe", "wsl.exe",
    "searchindexer.exe", "onedrive.exe", "teams.exe", "zoom.exe",
    "discord.exe", "slack.exe", "notepad.exe", "notepad++.exe",
    "nvcontainer.exe", "nvidia share.exe", "docker desktop.exe",
    "com.docker.backend.exe", "com.docker.proxy.exe",
    "antimalware service executable", "windows defender",
    "mpdefensecoreservice.exe", "msmpeng.exe", "securityhealthservice.exe",
    "spoolsv.exe", "ctfmon.exe", "taskmgr.exe", "wmiprvse.exe",
    "dllhost.exe", "runtimebroker.exe", "applicationframehost.exe",
    "officeclicktorun.exe", "officec2rclient.exe",
    "gamebarftserver.exe", "gamebar.exe", "gamebarftserver.exe",
    "rtkaududservice64.exe", "rtkaudservice64.exe",
    "anydesk.exe", "teamviewer.exe",
    "memcompression", "backgroundtaskhost.exe",
    "claude.exe", "antigravity.exe", "uihost.exe",
    "language_server_windows_x64.exe", "mc-fw-host.exe",
    # Phase 3N: Windows services that match suspicious keywords but are SAFE
    "wmiregistrationservice.exe",    # Windows Management Instrumentation
    "wmiadap.exe", "wmiprvse.exe",   # WMI providers
    "searchprotocolhost.exe",        # Windows Search
    "searchfilterhost.exe",
    "shellexperiencehost.exe",
    "startmenuexperiencehost.exe",
    "textinputhost.exe",
    "widgetservice.exe",
}

# Phase 3N: more precise — only match FULL suspicious tool names
SUSPICIOUS_KEYWORDS = [
    "keylogger", "spyware", "hookdll", "inject.exe", "payload.exe",
    "trojan", "backdoor.exe", "cryptominer", "xmrig",
    "stealer.exe", "grabber.exe", "mimikatz", "netcat.exe",
    "ncat.exe", "meterpreter", "cobaltstrike", "empire.exe",
    "pupy", "lazagne", "procdump", "sharphound",
]

# Processes to ALWAYS skip in display (noise)
SKIP_PROCESSES = {"system idle process", "idle", ""}

PRIVATE_PREFIXES = (
    "10.", "127.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    "169.254.", "::1", "fe80:", "fc00:", "0.0.0.0",
)


def _is_public_ip(ip: str) -> bool:
    return bool(ip) and not ip.startswith(PRIVATE_PREFIXES)


def _country_flag(code: str) -> str:
    if not code or len(code) < 2:
        return "🌐"
    try:
        return chr(ord(code[0].upper()) + 127397) + chr(ord(code[1].upper()) + 127397)
    except Exception:
        return "🌐"


def _geo_lookup(ip: str) -> dict:
    try:
        import requests
        r = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,country,countryCode,city,isp,org"},
            timeout=4,
        )
        if r.status_code == 200:
            d = r.json()
            if d.get("status") == "success":
                return {
                    "country":      d.get("country", "?"),
                    "country_code": d.get("countryCode", ""),
                    "city":         d.get("city", ""),
                    "isp":          d.get("isp") or d.get("org") or "?",
                }
    except Exception:
        pass
    return {"country": "?", "country_code": "", "city": "", "isp": "?"}


def _check_ip_reputation(ip: str) -> dict:
    try:
        from core.api_clients.abuseipdb import lookup_ip
        result = lookup_ip(ip)
        if result.get("available") and result.get("detail"):
            d = result["detail"]
            return {
                "country_code":  d.get("country") or "",
                "is_tor":        d.get("is_tor", False),
                "isp":           d.get("isp") or "?",
                "verdict":       result.get("verdict", "UNKNOWN"),
                "confidence":    d.get("confidence", 0),
                "total_reports": d.get("total_reports", 0),
            }
    except Exception as e:
        log.error("abuseipdb_failed", ip=ip, error=str(e))
    return {"verdict": "UNKNOWN", "confidence": 0}


# ══════════════════════════════════════════════════════════════════
# MODULE 1 — Network Monitor
# ══════════════════════════════════════════════════════════════════
def _get_network_connections() -> list[dict]:
    if not _PSUTIL:
        return []
    connections = []
    seen = set()
    try:
        for conn in psutil.net_connections(kind="inet"):
            if not conn.raddr:
                continue
            rip, rport = conn.raddr.ip, conn.raddr.port
            if not _is_public_ip(rip):
                continue
            if (rip, rport) in seen:
                continue
            seen.add((rip, rport))
            process = "—"
            try:
                if conn.pid:
                    process = psutil.Process(conn.pid).name()
            except Exception:
                pass
            connections.append({
                "remote_ip":   rip,
                "remote_port": rport,
                "process":     process,
                "status":      conn.status or "?",
                "country":     "?",
                "country_code": "",
                "isp":         "?",
                "is_tor":      False,
                "verdict":     "NOT_CHECKED",
                "confidence":  0,
            })
    except Exception as e:
        log.warning("net_conn_error", error=str(e))
    return connections[:50]


def _render_network_tab(connections: list[dict]) -> None:
    total      = len(connections)
    suspicious = sum(1 for c in connections
                     if c.get("verdict") in ("MALICIOUS", "SUSPICIOUS"))
    tor_count  = sum(1 for c in connections if c.get("is_tor"))
    countries  = len({c.get("country") for c in connections
                      if c.get("country") and c.get("country") != "?"})

    kpi_row([
        {"label": "Public connections", "value": str(total),      "tone": ""},
        {"label": "Suspicious",         "value": str(suspicious),
         "tone": "red" if suspicious else "green"},
        {"label": "TOR exits",          "value": str(tor_count),
         "tone": "red" if tor_count else "green"},
        {"label": "Countries",          "value": str(countries),  "tone": ""},
    ])

    if not connections:
        st.markdown(
            '<div style="background:#F0FDF4; padding:14px 18px; border:1px solid #BBF7D0;'
            ' border-left:3px solid #16A34A; border-radius:8px; font-family:Inter,sans-serif;'
            ' font-size:0.875rem; color:#334155; margin-top:12px;">No public connections detected.</div>',
            unsafe_allow_html=True,
        )
        return

    verdict_meta = {
        "MALICIOUS":   ("#DC2626", "#FEF2F2", "🔴", "MALICIOUS"),
        "SUSPICIOUS":  ("#CA8A04", "#FFFBEB", "🟡", "SUSPICIOUS"),
        "CLEAN":       ("#16A34A", "#F0FDF4", "🟢", "CLEAN"),
        "NOT_CHECKED": ("#64748B", "#F8FAFC", "⚪", "NOT CHK"),
        "UNKNOWN":     ("#64748B", "#F8FAFC", "⚪", "UNKNOWN"),
    }

    sorted_conns = sorted(connections, key=lambda c: (
        0 if c.get("verdict") == "MALICIOUS"  else
        1 if c.get("verdict") == "SUSPICIOUS" else 2,
        c.get("remote_ip", ""),
    ))

    rows_html = ""
    for i, c in enumerate(sorted_conns[:30]):
        verdict = c.get("verdict", "UNKNOWN")
        v_color, v_tint, v_dot, v_label = verdict_meta.get(
            verdict, ("#64748B", "#F8FAFC", "⚪", verdict[:8]))
        flag       = _country_flag(c.get("country_code", ""))
        country_s  = (f"{flag}&nbsp;{c.get('country','?')[:12]}"
                      if c.get("country") and c.get("country") != "?" else "🌐&nbsp;—")
        delay      = i * 25
        row_bg     = v_tint if verdict in ("MALICIOUS", "SUSPICIOUS") else "#FFFFFF"

        tor_html = ('&nbsp;<span style="background:#7C3AED;color:#FFF;font-size:0.6rem;'
                    'padding:2px 5px;border-radius:3px;">TOR</span>'
                    if c.get("is_tor") else "")
        rows_html += (
            f'<tr style="background:{row_bg}; border-bottom:1px solid #F1F5F9;'
            f'animation: mc-row-in 260ms {delay}ms cubic-bezier(0.4,0,0.2,1) backwards;">'
            f'<td style="padding:10px 12px; white-space:nowrap;">'
            f'<span style="font-family:JetBrains Mono,monospace; font-size:0.7rem;'
            f'font-weight:700; color:{v_color}; background:{v_tint}; padding:4px 9px;'
            f'border-radius:5px; border:1px solid {v_color}33;">{v_dot} {v_label}</span></td>'
            f'<td style="padding:10px 12px; font-family:JetBrains Mono,monospace;'
            f'font-size:0.78rem; color:#0F172A; font-weight:600;">'
            f'<span style="width:7px; height:7px; border-radius:50%; background:#16A34A;'
            f'display:inline-block; animation:mc-pulse 2s infinite; margin-right:7px;"></span>'
            f'{c["process"][:18]}</td>'
            f'<td style="padding:10px 12px; font-family:JetBrains Mono,monospace;'
            f'font-size:0.8rem; color:#1E40AF; font-weight:600;">'
            f'{c["remote_ip"]}:{c["remote_port"]}{tor_html}</td>'
            f'<td style="padding:10px 12px; font-family:Inter,sans-serif;'
            f'font-size:0.82rem; color:#334155;">{country_s}</td>'
            f'<td style="padding:10px 12px; font-family:Inter,sans-serif;'
            f'font-size:0.78rem; color:#475569; max-width:150px; overflow:hidden;'
            f'text-overflow:ellipsis; white-space:nowrap;">{(c.get("isp") or "?")[:20]}</td>'
            f'<td style="padding:10px 12px; font-family:JetBrains Mono,monospace;'
            f'font-size:0.7rem; color:#64748B;">{c.get("status","?")[:10]}</td>'
            f'</tr>'
        )

    st.markdown(
        '<style>@keyframes mc-row-in{from{opacity:0;transform:translateX(-10px)}'
        'to{opacity:1;transform:translateX(0)}}</style>'
        '<div style="overflow-x:auto; border:1px solid #E2E8F0; border-radius:10px;'
        'box-shadow:0 1px 3px rgba(15,23,42,0.06); margin-top:12px;">'
        '<table style="width:100%; border-collapse:collapse;">'
        '<thead><tr style="background:linear-gradient(90deg,#F8FAFC,#FFFFFF);'
        'border-bottom:2px solid #E2E8F0;">'
        + ''.join(
            f'<th style="padding:11px 12px; font-family:Inter,sans-serif; font-size:0.6875rem;'
            f'letter-spacing:0.06em; color:#64748B; text-transform:uppercase;'
            f'font-weight:600; text-align:left;">{h}</th>'
            for h in ["Verdict", "Process", "Remote IP : Port", "Country", "ISP", "Status"]
        )
        + f'</tr></thead><tbody>{rows_html}</tbody></table></div>',
        unsafe_allow_html=True,
    )

    # ── Plotly charts: verdict pie + top countries bar ────────────────
    try:
        import plotly.graph_objects as go

        ch1, ch2 = st.columns(2)

        # Verdict distribution pie
        with ch1:
            verdicts = {}
            for c in connections:
                v = c.get("verdict", "UNKNOWN")
                verdicts[v] = verdicts.get(v, 0) + 1
            if verdicts:
                colors_map = {
                    "MALICIOUS": "#DC2626", "SUSPICIOUS": "#CA8A04",
                    "CLEAN": "#16A34A", "NOT_CHECKED": "#64748B", "UNKNOWN": "#94A3B8"
                }
                labels = list(verdicts.keys())
                values = list(verdicts.values())
                fig = go.Figure(go.Pie(
                    labels=labels, values=values,
                    marker_colors=[colors_map.get(l, "#94A3B8") for l in labels],
                    hole=0.45, textfont_size=11,
                    hovertemplate="%{label}: %{value} (%{percent})<extra></extra>",
                ))
                fig.update_layout(
                    title=dict(text="Verdict Distribution", font=dict(size=13, color="#0F172A")),
                    paper_bgcolor="#FAFAFA", plot_bgcolor="#FAFAFA",
                    margin=dict(l=10, r=10, t=40, b=10),
                    legend=dict(font=dict(size=10), orientation="h", y=-0.1),
                    height=250,
                )
                st.plotly_chart(fig, use_container_width=True)

        # Top countries bar chart
        with ch2:
            countries_count = {}
            for c in connections:
                ctry = c.get("country", "Unknown")
                if ctry and ctry != "?":
                    countries_count[ctry] = countries_count.get(ctry, 0) + 1
            if countries_count:
                top = sorted(countries_count.items(), key=lambda x: -x[1])[:8]
                c_labels, c_values = zip(*top)
                fig2 = go.Figure(go.Bar(
                    x=list(c_values), y=list(c_labels),
                    orientation="h",
                    marker_color=["#DC2626" if v > 2 else "#3B82F6" for v in c_values],
                    text=list(c_values), textposition="outside",
                    hovertemplate="%{y}: %{x} connections<extra></extra>",
                ))
                fig2.update_layout(
                    title=dict(text="Top Countries", font=dict(size=13, color="#0F172A")),
                    paper_bgcolor="#FAFAFA", plot_bgcolor="#FAFAFA",
                    xaxis=dict(showgrid=False, zeroline=False),
                    yaxis=dict(autorange="reversed"),
                    margin=dict(l=10, r=30, t=40, b=10),
                    height=250,
                )
                st.plotly_chart(fig2, use_container_width=True)

    except ImportError:
        st.caption("Install plotly for visual charts: `pip install plotly`")


# ══════════════════════════════════════════════════════════════════
# MODULE 2 — Process Monitor
# ══════════════════════════════════════════════════════════════════
def _get_processes() -> list[dict]:
    if not _PSUTIL:
        return []
    procs = []
    for proc in psutil.process_iter(
        ["pid", "name", "cpu_percent", "memory_info", "status", "username"]
    ):
        try:
            info = proc.info
            name_lower = (info.get("name") or "").lower()

            # Phase 3N: skip noise processes
            if name_lower in SKIP_PROCESSES or not name_lower:
                continue

            is_suspicious = any(kw in name_lower for kw in SUSPICIOUS_KEYWORDS)
            # Phase 3N: if in safe list, override suspicious flag
            if name_lower in SAFE_PROCESSES:
                is_suspicious = False

            is_safe = name_lower in SAFE_PROCESSES
            mem_mb = round(
                (info.get("memory_info") or type("", (), {"rss": 0})()).rss
                / 1024 / 1024, 1
            )
            # Phase 3N: cap CPU per-process at 100% (psutil reports
            # cumulative across cores for System Idle etc.)
            cpu_raw = info.get("cpu_percent", 0) or 0
            cpu_display = min(cpu_raw, 100.0)

            # Skip python.exe from HIGH CPU alert (that's us — Streamlit)
            is_high_cpu = cpu_display > 50 and name_lower not in (
                "python.exe", "pythonw.exe", "system idle process",
                "system", "memcompression",
            )

            procs.append({
                "pid":          info.get("pid", 0),
                "name":         info.get("name", "?"),
                "cpu":          cpu_display,
                "cpu_raw":      cpu_raw,
                "mem_mb":       mem_mb,
                "status":       info.get("status", "?"),
                "username":     (info.get("username") or "?").split("\\")[-1][:12],
                "suspicious":   is_suspicious,
                "high_cpu":     is_high_cpu,
                "safe":         is_safe,
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return sorted(procs, key=lambda p: (0 if p["suspicious"] else 1, -p["cpu"]))


def _render_process_tab() -> None:
    procs = _get_processes()
    suspicious_procs = [p for p in procs if p["suspicious"]]
    high_cpu = [p for p in procs if p.get("high_cpu")]

    kpi_row([
        {"label": "Total processes", "value": str(len(procs)),         "tone": ""},
        {"label": "Suspicious",      "value": str(len(suspicious_procs)),
         "tone": "red" if suspicious_procs else "green"},
        {"label": "High CPU (>50%)", "value": str(len(high_cpu)),
         "tone": "amber" if high_cpu else "green"},
    ])

    # Suspicious alert
    if suspicious_procs:
        for p in suspicious_procs:
            st.markdown(
                f'<div style="background:#FEF2F2; padding:12px 16px; '
                f'border:1px solid #FECACA; border-left:4px solid #DC2626; '
                f'border-radius:8px; margin:8px 0; font-family:Inter,sans-serif; '
                f'font-size:0.875rem; color:#991B1B;">'
                f'🚨 <b>Suspicious process detected:</b> '
                f'<code style="background:#FEE2E2; padding:2px 6px; border-radius:4px;">'
                f'{p["name"]}</code> (PID {p["pid"]}) — '
                f'matches known malware keyword pattern</div>',
                unsafe_allow_html=True,
            )

    # Search
    search = st.text_input("🔍 Filter process name",
                           placeholder="chrome, python, docker...",
                           key="proc_search")

    filtered = [
        p for p in procs
        if not search or search.lower() in p["name"].lower()
    ][:50]

    rows_html = ""
    for i, p in enumerate(filtered):
        if p["suspicious"]:
            row_bg  = "#FEF2F2"
            name_c  = "#DC2626"
            badge   = '<span style="background:#DC2626; color:#FFF; font-size:0.6rem; padding:2px 6px; border-radius:4px; margin-left:6px; font-weight:700;">⚠ SUSPICIOUS</span>'
        elif p.get("high_cpu"):
            row_bg  = "#FFFBEB"
            name_c  = "#CA8A04"
            badge   = '<span style="background:#CA8A04; color:#FFF; font-size:0.6rem; padding:2px 6px; border-radius:4px; margin-left:6px;">HIGH CPU</span>'
        else:
            row_bg  = "#FFFFFF"
            name_c  = "#0F172A"
            badge   = ""

        cpu_bar_w = min(int(p["cpu"]), 100)
        cpu_color = "#DC2626" if p["cpu"] > 80 else "#CA8A04" if p["cpu"] > 40 else "#16A34A"

        rows_html += (
            f'<tr style="background:{row_bg}; border-bottom:1px solid #F1F5F9;">'
            f'<td style="padding:9px 12px; font-family:JetBrains Mono,monospace;'
            f'font-size:0.75rem; color:#64748B;">{p["pid"]}</td>'
            f'<td style="padding:9px 12px; font-family:Inter,sans-serif;'
            f'font-size:0.85rem; color:{name_c}; font-weight:600;">'
            f'{p["name"]}{badge}</td>'
            f'<td style="padding:9px 12px; font-family:Inter,sans-serif; font-size:0.82rem;">'
            f'<div style="display:flex; align-items:center; gap:8px;">'
            f'<div style="background:#F1F5F9; border-radius:4px; height:6px; width:80px;">'
            f'<div style="background:{cpu_color}; border-radius:4px; height:6px;'
            f'width:{cpu_bar_w}%;"></div></div>'
            f'<span style="color:#475569; font-size:0.78rem;">{p["cpu"]:.1f}%</span>'
            f'</div></td>'
            f'<td style="padding:9px 12px; font-family:JetBrains Mono,monospace;'
            f'font-size:0.78rem; color:#475569;">{p["mem_mb"]:.1f} MB</td>'
            f'<td style="padding:9px 12px; font-family:Inter,sans-serif;'
            f'font-size:0.78rem; color:#64748B;">{p["status"]}</td>'
            f'<td style="padding:9px 12px; font-family:Inter,sans-serif;'
            f'font-size:0.78rem; color:#64748B;">{p["username"]}</td>'
            f'</tr>'
        )

    st.markdown(
        '<div style="overflow-x:auto; border:1px solid #E2E8F0; border-radius:10px;'
        'margin-top:10px; box-shadow:0 1px 3px rgba(15,23,42,0.06);">'
        '<table style="width:100%; border-collapse:collapse;">'
        '<thead><tr style="background:linear-gradient(90deg,#F8FAFC,#FFFFFF);'
        'border-bottom:2px solid #E2E8F0;">'
        + ''.join(
            f'<th style="padding:11px 12px; font-family:Inter,sans-serif; font-size:0.6875rem;'
            f'letter-spacing:0.06em; color:#64748B; text-transform:uppercase;'
            f'font-weight:600; text-align:left;">{h}</th>'
            for h in ["PID", "Name", "CPU", "Memory", "Status", "User"]
        )
        + f'</tr></thead><tbody>{rows_html}</tbody></table></div>',
        unsafe_allow_html=True,
    )


# ══════════════════════════════════════════════════════════════════
# MODULE 3 — System Info
# ══════════════════════════════════════════════════════════════════
def _render_sysinfo_tab() -> None:
    uname     = platform.uname()
    cpu_pct   = psutil.cpu_percent(interval=1) if _PSUTIL else 0
    cpu_count = psutil.cpu_count() if _PSUTIL else 0
    mem       = psutil.virtual_memory() if _PSUTIL else None
    disk      = psutil.disk_usage("/") if _PSUTIL else None

    # Phase 3N: uptime + boot time + battery
    import datetime
    boot_ts     = psutil.boot_time() if _PSUTIL else 0
    boot_time   = datetime.datetime.fromtimestamp(boot_ts).strftime("%Y-%m-%d %H:%M:%S") if boot_ts else "?"
    uptime_sec  = time.time() - boot_ts if boot_ts else 0
    uptime_h    = int(uptime_sec // 3600)
    uptime_m    = int((uptime_sec % 3600) // 60)
    uptime_str  = f"{uptime_h}h {uptime_m}m"

    battery_str = "N/A"
    battery_pct = None
    try:
        bat = psutil.sensors_battery()
        if bat:
            battery_pct = bat.percent
            plug = "🔌 Plugged in" if bat.power_plugged else "🔋 On battery"
            battery_str = f"{bat.percent}% ({plug})"
    except Exception:
        pass

    # System identity card
    info_items = [
        ("System",    uname.system or "?"),
        ("Hostname",  uname.node[:20] or "?"),
        ("Release",   uname.release or "?"),
        ("Version",   (uname.version or "?")[:40]),
        ("Machine",   uname.machine or "?"),
        ("Processor", (uname.processor or "?")[:32]),
        ("Boot time", boot_time),
        ("Uptime",    uptime_str),
        ("Battery",   battery_str),
    ]

    st.markdown(
        '<div style="background:#FFFFFF; padding:20px 24px; border:1px solid #E2E8F0;'
        'border-radius:10px; margin-bottom:14px; box-shadow:0 1px 2px rgba(15,23,42,0.04);">'
        '<div style="font-family:Inter,sans-serif; font-size:0.6875rem; letter-spacing:0.08em;'
        'color:#64748B; text-transform:uppercase; font-weight:600; margin-bottom:14px;">'
        'System identity</div>'
        '<div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));'
        'gap:14px;">'
        + ''.join(
            f'<div><div style="font-family:Inter,sans-serif; font-size:0.6875rem;'
            f'color:#94A3B8; text-transform:uppercase; letter-spacing:0.06em;'
            f'font-weight:600;">{label}</div>'
            f'<div style="font-family:JetBrains Mono,monospace; font-size:0.9rem;'
            f'color:#0F172A; font-weight:600; margin-top:4px;">{value}</div></div>'
            for label, value in info_items
        )
        + '</div></div>',
        unsafe_allow_html=True,
    )

    # Live resource meters
    col1, col2, col3 = st.columns(3)
    with col1:
        cpu_color = "#DC2626" if cpu_pct > 80 else "#CA8A04" if cpu_pct > 60 else "#16A34A"
        st.markdown(
            f'<div style="background:#FFFFFF; padding:16px 18px; border:1px solid #E2E8F0;'
            f'border-radius:10px; text-align:center;">'
            f'<div style="font-family:Inter,sans-serif; font-size:0.6875rem; color:#64748B;'
            f'text-transform:uppercase; letter-spacing:0.06em; font-weight:600;">CPU Usage</div>'
            f'<div style="font-family:Inter,sans-serif; font-size:2.5rem; font-weight:800;'
            f'color:{cpu_color}; line-height:1; margin:8px 0;">{cpu_pct:.0f}%</div>'
            f'<div style="font-family:Inter,sans-serif; font-size:0.78rem; color:#64748B;">'
            f'{cpu_count} cores</div></div>',
            unsafe_allow_html=True,
        )
    with col2:
        if mem:
            mem_pct   = mem.percent
            mem_used  = round(mem.used  / 1024**3, 1)
            mem_total = round(mem.total / 1024**3, 1)
            mem_color = "#DC2626" if mem_pct > 85 else "#CA8A04" if mem_pct > 65 else "#16A34A"
            st.markdown(
                f'<div style="background:#FFFFFF; padding:16px 18px; border:1px solid #E2E8F0;'
                f'border-radius:10px; text-align:center;">'
                f'<div style="font-family:Inter,sans-serif; font-size:0.6875rem; color:#64748B;'
                f'text-transform:uppercase; letter-spacing:0.06em; font-weight:600;">RAM</div>'
                f'<div style="font-family:Inter,sans-serif; font-size:2.5rem; font-weight:800;'
                f'color:{mem_color}; line-height:1; margin:8px 0;">{mem_pct:.0f}%</div>'
                f'<div style="font-family:Inter,sans-serif; font-size:0.78rem; color:#64748B;">'
                f'{mem_used} / {mem_total} GB</div></div>',
                unsafe_allow_html=True,
            )
    with col3:
        if disk:
            d_pct   = disk.percent
            d_used  = round(disk.used  / 1024**3, 1)
            d_total = round(disk.total / 1024**3, 1)
            d_color = "#DC2626" if d_pct > 90 else "#CA8A04" if d_pct > 75 else "#16A34A"
            st.markdown(
                f'<div style="background:#FFFFFF; padding:16px 18px; border:1px solid #E2E8F0;'
                f'border-radius:10px; text-align:center;">'
                f'<div style="font-family:Inter,sans-serif; font-size:0.6875rem; color:#64748B;'
                f'text-transform:uppercase; letter-spacing:0.06em; font-weight:600;">Disk</div>'
                f'<div style="font-family:Inter,sans-serif; font-size:2.5rem; font-weight:800;'
                f'color:{d_color}; line-height:1; margin:8px 0;">{d_pct:.0f}%</div>'
                f'<div style="font-family:Inter,sans-serif; font-size:0.78rem; color:#64748B;">'
                f'{d_used} / {d_total} GB</div></div>',
                unsafe_allow_html=True,
            )


# ══════════════════════════════════════════════════════════════════
# MODULE 4 — USB / Disk Monitor
# ══════════════════════════════════════════════════════════════════
def _render_usb_tab() -> None:
    if not _PSUTIL:
        st.error("psutil not installed.")
        return

    partitions = psutil.disk_partitions(all=False)
    prev_devs   = st.session_state.get("usb_prev_devices", set())
    curr_devs   = {p.device for p in partitions}

    # Detect newly inserted devices
    new_devs = curr_devs - prev_devs
    st.session_state["usb_prev_devices"] = curr_devs

    if new_devs:
        for d in new_devs:
            st.markdown(
                f'<div style="background:#FFFBEB; padding:12px 16px; '
                f'border:1px solid #FDE68A; border-left:4px solid #CA8A04; '
                f'border-radius:8px; margin-bottom:10px; font-family:Inter,sans-serif; '
                f'font-size:0.875rem; color:#78350F;">'
                f'⚡ <b>New device inserted:</b> <code>{d}</code></div>',
                unsafe_allow_html=True,
            )

    st.markdown(
        f'<div style="font-family:Inter,sans-serif; font-size:0.875rem; color:#475569;'
        f'margin:10px 0;">{len(partitions)} storage device(s) connected</div>',
        unsafe_allow_html=True,
    )

    grid = (
        '<div style="display:grid; grid-template-columns: repeat(auto-fit,'
        ' minmax(280px, 1fr)); gap:10px; margin-top:8px;">'
    )
    for p in partitions:
        try:
            usage  = psutil.disk_usage(p.mountpoint)
            used_g = round(usage.used  / 1024**3, 1)
            tot_g  = round(usage.total / 1024**3, 1)
            pct    = usage.percent
            bar_c  = "#DC2626" if pct > 90 else "#CA8A04" if pct > 75 else "#2563EB"
        except Exception:
            used_g = tot_g = 0
            pct    = 0
            bar_c  = "#94A3B8"

        is_new  = p.device in new_devs
        card_bg = "#FFFBEB" if is_new else "#FFFFFF"
        new_tag = ('<span style="background:#CA8A04; color:#FFF; font-size:0.6rem;'
                   'padding:2px 6px; border-radius:4px; margin-left:6px; font-weight:700;">'
                   'NEW</span>' if is_new else "")

        grid += (
            f'<div style="background:{card_bg}; padding:16px; border:1px solid #E2E8F0;'
            f'border-radius:10px; box-shadow:0 1px 2px rgba(15,23,42,0.04);">'
            f'<div style="display:flex; align-items:center; justify-content:space-between;">'
            f'<div style="font-family:JetBrains Mono,monospace; font-size:0.9rem;'
            f'font-weight:700; color:#2563EB;">{p.device}{new_tag}</div>'
            f'<div style="font-family:JetBrains Mono,monospace; font-size:0.75rem;'
            f'color:#64748B;">{p.fstype or "?"}</div></div>'
            f'<div style="font-family:Inter,sans-serif; font-size:0.78rem; color:#64748B;'
            f'margin-top:4px;">{p.mountpoint} · {p.opts[:20]}</div>'
            f'<div style="margin-top:10px;">'
            f'<div style="display:flex; justify-content:space-between; margin-bottom:4px;">'
            f'<span style="font-family:Inter,sans-serif; font-size:0.75rem; color:#64748B;">'
            f'{used_g} GB / {tot_g} GB used</span>'
            f'<span style="font-family:JetBrains Mono,monospace; font-size:0.75rem;'
            f'color:{bar_c}; font-weight:700;">{pct:.0f}%</span></div>'
            f'<div style="background:#F1F5F9; border-radius:6px; height:8px;">'
            f'<div style="background:{bar_c}; border-radius:6px; height:8px;'
            f'width:{min(pct,100):.0f}%; transition:width 500ms;"></div></div>'
            f'</div></div>'
        )
    grid += '</div>'
    st.markdown(grid, unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════
# MODULE 5 — LAN Scanner
# ══════════════════════════════════════════════════════════════════
def _scan_lan() -> list[dict]:
    """Phase 3N: use subprocess ping (works without admin on Windows)."""
    import subprocess as _sp
    import sys
    devices = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        parts = local_ip.split(".")
        if len(parts) != 4:
            return []
        prefix = ".".join(parts[:3])

        def _ping_host(host: str) -> Optional[dict]:
            try:
                start = time.time()
                if sys.platform == "win32":
                    cmd = ["ping", "-n", "1", "-w", "500", host]
                else:
                    cmd = ["ping", "-c", "1", "-W", "1", host]
                result = _sp.run(cmd, capture_output=True, text=True, timeout=2)
                ms = int((time.time() - start) * 1000)
                if result.returncode == 0:
                    try:
                        hostname = socket.gethostbyaddr(host)[0]
                    except Exception:
                        hostname = host
                    return {"ip": host, "hostname": hostname,
                            "latency_ms": ms, "open_port": "ping"}
            except Exception:
                pass
            return None

        targets = [f"{prefix}.{i}" for i in range(1, 31)]
        with concurrent.futures.ThreadPoolExecutor(max_workers=15) as ex:
            devices = [d for d in ex.map(_ping_host, targets) if d]
    except Exception as e:
        log.warning("lan_scan_error", error=str(e))
    return devices


def _render_openports_tab() -> None:
    """List all listening ports with process name, exposure scope, and known CVE risk."""
    _RISKY_PORTS: dict[int, tuple[str, str]] = {
        21:    ("CRITICAL", "FTP — plaintext auth, brute-force target"),
        22:    ("LOW",      "SSH — secure if patched & key-auth only"),
        23:    ("CRITICAL", "Telnet — plaintext, never use in production"),
        25:    ("HIGH",     "SMTP — open relay risk"),
        80:    ("MEDIUM",   "HTTP — unencrypted, cookie theft risk"),
        135:   ("HIGH",     "RPC — EternalBlue / MS exploits"),
        139:   ("HIGH",     "NetBIOS — SMB lateral movement"),
        443:   ("LOW",      "HTTPS — TLS encrypted, watch for expired certs"),
        445:   ("CRITICAL", "SMB — WannaCry / EternalBlue / NotPetya"),
        1433:  ("HIGH",     "MSSQL — database, restrict to localhost"),
        3306:  ("HIGH",     "MySQL — database, restrict to localhost"),
        3389:  ("CRITICAL", "RDP — #1 ransomware entry point, patch urgently"),
        5432:  ("HIGH",     "PostgreSQL — database, restrict to localhost"),
        5900:  ("HIGH",     "VNC — remote desktop, often unencrypted"),
        6379:  ("CRITICAL", "Redis — unauthenticated by default, crypto theft target"),
        8080:  ("MEDIUM",   "HTTP alt — dev server, often left open accidentally"),
        8443:  ("LOW",      "HTTPS alt — encrypted, verify cert validity"),
        9200:  ("CRITICAL", "Elasticsearch — unauthenticated by default, data leak"),
        27017: ("CRITICAL", "MongoDB — unauthenticated default, many breaches"),
    }
    _RISK_COLOR = {
        "CRITICAL": ("#DC2626", "#FEF2F2"),
        "HIGH":     ("#EA580C", "#FFF7ED"),
        "MEDIUM":   ("#D97706", "#FFFBEB"),
        "LOW":      ("#16A34A", "#F0FDF4"),
        "SAFE":     ("#64748B", "#F8FAFC"),
    }

    c1, c2 = st.columns([1, 5])
    with c1:
        if st.button("🔄 Refresh", key="ports_refresh", use_container_width=True):
            st.session_state.pop("shield_ports", None)

    if "shield_ports" not in st.session_state:
        try:
            raw = psutil.net_connections(kind="inet")
        except Exception as e:
            st.error(f"Cannot read ports (try running as Administrator): {e}")
            return
        # v33-fix: dedup pass. psutil returns SEPARATE entries for each
        # (port, ipv4/ipv6, pid) tuple, so the same logical service shows
        # up 2-3 times (e.g. docker.backend.exe binds 0.0.0.0 AND :: for
        # port 8090, plus wslrelay.exe binds 127.0.0.1 — three rows for
        # one service). We collapse by (port, pid) and merge exposure +
        # IP families into a single row.
        dedup: dict[tuple, dict] = {}
        for c in raw:
            if c.status != "LISTEN":
                continue
            laddr = c.laddr
            if not laddr:
                continue
            port = laddr.port
            ip   = laddr.ip
            pid  = c.pid or 0
            key = (port, pid)
            if key in dedup:
                row = dedup[key]
                row["ips"].add(ip)
                if ip in ("0.0.0.0", "::"):
                    row["exposed"] = True
                continue
            proc = "?"
            user = ""
            try:
                p = psutil.Process(pid)
                proc = p.name()
                user = p.username()
            except Exception:
                pass
            risk_key, risk_desc = _RISKY_PORTS.get(port, ("SAFE", ""))
            dedup[key] = {
                "port": port, "pid": pid, "ips": {ip},
                "exposed": ip in ("0.0.0.0", "::"),
                "process": proc, "user": user,
                "risk": risk_key, "desc": risk_desc,
            }
        listening = []
        for row in dedup.values():
            # Build human-readable exposure label from collected IPs
            if row["exposed"]:
                exposure = "🌐 Exposed (0.0.0.0)"
            elif row["ips"] <= {"127.0.0.1", "::1"}:
                exposure = "🔒 Localhost"
            else:
                exposure = "🔒 LAN"
            # Honest description for unknown ports + better wording
            risk_key = row["risk"]
            desc = row["desc"]
            if not desc:
                if risk_key == "SAFE":
                    if 49152 <= row["port"] <= 65535:
                        desc = "Dynamic / ephemeral port (Windows RPC range)"
                    elif row["port"] >= 8000 and row["port"] < 9000:
                        desc = "Common app-dev port (no CVE)"
                    elif row["port"] == 0:
                        desc = "Wildcard bind"
                    else:
                        desc = "No known CVE association"
                else:
                    desc = f"{risk_key.title()}-class port — review service"
            ip_list = ", ".join(sorted(row["ips"]))
            listening.append({
                "port": row["port"], "ip": ip_list, "pid": row["pid"],
                "process": row["process"], "user": row["user"],
                "exposure": exposure,
                "risk": risk_key, "desc": desc,
            })
        st.session_state["shield_ports"] = sorted(listening, key=lambda x: (
            {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "SAFE": 4}.get(x["risk"], 5),
            x["port"]
        ))

    ports = st.session_state.get("shield_ports", [])
    if not ports:
        st.info("No listening ports found (or requires Administrator to read all ports).")
        return

    crit  = sum(1 for p in ports if p["risk"] == "CRITICAL")
    high  = sum(1 for p in ports if p["risk"] == "HIGH")
    expo  = sum(1 for p in ports if "Exposed" in p["exposure"])

    # KPI strip
    st.markdown(
        '<div style="display:flex;gap:12px;margin:10px 0 14px;flex-wrap:wrap">'
        f'<div style="background:#FEF2F2;border:1px solid #FCA5A5;border-radius:8px;'
        f'padding:10px 18px;text-align:center">'
        f'<div style="font-size:1.4rem;font-weight:800;color:#DC2626;font-family:Poppins,sans-serif">{crit}</div>'
        f'<div style="font-size:0.7rem;color:#64748B;font-family:Inter,sans-serif">CRITICAL ports</div></div>'
        f'<div style="background:#FFF7ED;border:1px solid #FDBA74;border-radius:8px;'
        f'padding:10px 18px;text-align:center">'
        f'<div style="font-size:1.4rem;font-weight:800;color:#EA580C;font-family:Poppins,sans-serif">{high}</div>'
        f'<div style="font-size:0.7rem;color:#64748B;font-family:Inter,sans-serif">HIGH risk ports</div></div>'
        f'<div style="background:#EFF6FF;border:1px solid #BFDBFE;border-radius:8px;'
        f'padding:10px 18px;text-align:center">'
        f'<div style="font-size:1.4rem;font-weight:800;color:#1D4ED8;font-family:Poppins,sans-serif">{expo}</div>'
        f'<div style="font-size:0.7rem;color:#64748B;font-family:Inter,sans-serif">Network-exposed</div></div>'
        f'<div style="background:#F8FAFC;border:1px solid #E2E8F0;border-radius:8px;'
        f'padding:10px 18px;text-align:center">'
        f'<div style="font-size:1.4rem;font-weight:800;color:#0F172A;font-family:Poppins,sans-serif">{len(ports)}</div>'
        f'<div style="font-size:0.7rem;color:#64748B;font-family:Inter,sans-serif">Total listening</div></div>'
        '</div>',
        unsafe_allow_html=True,
    )

    # Table
    rows_html = ""
    for p in ports:
        rc, rb = _RISK_COLOR.get(p["risk"], _RISK_COLOR["SAFE"])
        exp_col = "#DC2626" if "Exposed" in p["exposure"] else "#16A34A"
        rows_html += (
            f'<tr style="border-bottom:1px solid #F1F5F9;">'
            f'<td style="padding:8px 12px;font-family:JetBrains Mono,monospace;'
            f'font-size:0.9rem;font-weight:700;color:#0F172A">{p["port"]}</td>'
            f'<td style="padding:8px 12px">'
            f'<span style="background:{rb};color:{rc};font-family:JetBrains Mono,monospace;'
            f'font-size:0.65rem;font-weight:700;border-radius:10px;padding:2px 8px">'
            f'{p["risk"]}</span></td>'
            f'<td style="padding:8px 12px;font-family:Inter,sans-serif;font-size:0.78rem;'
            f'color:{exp_col};font-weight:600">{p["exposure"]}</td>'
            f'<td style="padding:8px 12px;font-family:JetBrains Mono,monospace;'
            f'font-size:0.78rem;color:#1D4ED8">{p["process"]}</td>'
            f'<td style="padding:8px 12px;font-family:JetBrains Mono,monospace;'
            f'font-size:0.7rem;color:#64748B">{p["pid"]}</td>'
            f'<td style="padding:8px 12px;font-family:Inter,sans-serif;font-size:0.72rem;'
            f'color:#475569">{p["desc"]}</td>'
            f'</tr>'
        )

    st.markdown(
        '<div style="overflow-x:auto;border:1px solid #E2E8F0;border-radius:10px;'
        'box-shadow:0 1px 3px rgba(15,23,42,0.06)">'
        '<table style="width:100%;border-collapse:collapse">'
        '<thead><tr style="background:linear-gradient(90deg,#F8FAFC,#FFFFFF)">'
        '<th style="padding:9px 12px;text-align:left;font-family:Inter,sans-serif;'
        'font-size:0.72rem;color:#64748B;font-weight:600">PORT</th>'
        '<th style="padding:9px 12px;text-align:left;font-family:Inter,sans-serif;'
        'font-size:0.72rem;color:#64748B;font-weight:600">RISK</th>'
        '<th style="padding:9px 12px;text-align:left;font-family:Inter,sans-serif;'
        'font-size:0.72rem;color:#64748B;font-weight:600">EXPOSURE</th>'
        '<th style="padding:9px 12px;text-align:left;font-family:Inter,sans-serif;'
        'font-size:0.72rem;color:#64748B;font-weight:600">PROCESS</th>'
        '<th style="padding:9px 12px;text-align:left;font-family:Inter,sans-serif;'
        'font-size:0.72rem;color:#64748B;font-weight:600">PID</th>'
        '<th style="padding:9px 12px;text-align:left;font-family:Inter,sans-serif;'
        'font-size:0.72rem;color:#64748B;font-weight:600">NOTES</th>'
        '</tr></thead>'
        f'<tbody>{rows_html}</tbody>'
        '</table></div>',
        unsafe_allow_html=True,
    )

    if crit > 0:
        st.markdown(
            f'<div style="background:#FEF2F2;border:1px solid #FCA5A5;border-left:4px solid #DC2626;'
            f'border-radius:8px;padding:10px 16px;margin-top:12px;font-family:Inter,sans-serif;'
            f'font-size:0.8rem;color:#7F1D1D">'
            f'⚠️ <b>{crit} CRITICAL port(s) open.</b> Ports 445 (SMB), 3389 (RDP), 6379 (Redis), '
            f'9200 (Elasticsearch) and 27017 (MongoDB) are common ransomware and data-breach entry points. '
            f'Close or firewall them immediately if not intentionally exposed.</div>',
            unsafe_allow_html=True,
        )


# ══════════════════════════════════════════════════════════════════
# MAIN RENDER
# ══════════════════════════════════════════════════════════════════
def render_shield_monitor():
    # ════════════════════════════════════════════════════════════════
    # LIVE ANIMATIONS
    # ════════════════════════════════════════════════════════════════

    st.markdown("""
    <style>
        /* ── Auto (30s) checkbox label → black ── */
        .stCheckbox label, .stCheckbox label p {
            color: #0F172A !important;
            font-weight: 600 !important;
        }

        @keyframes shieldPulse {
            0%, 100% { filter: drop-shadow(0 0 8px rgba(59, 130, 246, 0.3)); }
            50% { filter: drop-shadow(0 0 20px rgba(59, 130, 246, 0.8)); }
        }

        @keyframes iconGlow {
            0%, 100% { opacity: 1; filter: drop-shadow(0 0 5px rgba(59, 130, 246, 0.4)); }
            50% { opacity: 0.8; filter: drop-shadow(0 0 15px rgba(59, 130, 246, 0.8)); }
        }

        @keyframes buttonHoverGlow {
            0%, 100% { box-shadow: 0 4px 12px rgba(59, 130, 246, 0.2); }
            50% { box-shadow: 0 8px 24px rgba(59, 130, 246, 0.5); }
        }

        @keyframes tabPulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.7; }
        }

        @keyframes slideInLeft {
            from { opacity: 0; transform: translateX(-20px); }
            to { opacity: 1; transform: translateX(0); }
        }

        @keyframes fadeInUp {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }

        @keyframes shimmer {
            0% { background-position: -1000px 0; }
            100% { background-position: 1000px 0; }
        }

        .shield-icon-live {
            animation: shieldPulse 2.4s ease-in-out infinite;
        }

        .tab-icon-live {
            animation: iconGlow 2s ease-in-out infinite;
        }

        .scan-button-live:hover {
            animation: buttonHoverGlow 1.5s ease-in-out infinite !important;
        }

        .live-indicator {
            animation: tabPulse 1.6s ease-in-out infinite;
        }

        .shield-tab-content {
            animation: fadeInUp 0.5s ease-out;
        }

        .threat-row {
            animation: fadeInUp 0.4s ease-out;
            transition: all 0.3s ease;
        }

        .threat-row:hover {
            box-shadow: 0 4px 12px rgba(220, 38, 38, 0.1);
            transform: translateX(4px);
        }

        .status-badge {
            animation: slideInLeft 0.6s ease-out;
        }
    </style>
    """, unsafe_allow_html=True)

    # Hero
    st.markdown(
        '<div class="mc-url-hero">'
        '<div style="display:flex; align-items:center; gap:18px;">'
        '<div style="flex-shrink:0;" class="shield-icon-live">'
        '<svg width="52" height="52" viewBox="0 0 52 52" fill="none">'
        '<defs><linearGradient id="shG" x1="0" y1="0" x2="52" y2="52"'
        ' gradientUnits="userSpaceOnUse">'
        '<stop offset="0%" stop-color="#3B82F6"/>'
        '<stop offset="100%" stop-color="#1E40AF"/></linearGradient></defs>'
        '<path d="M26 4 L46 13 L46 28 C46 40 26 48 26 48 C26 48 6 40 6 28 L6 13 Z"'
        ' stroke="url(#shG)" stroke-width="2" fill="rgba(37,99,235,0.06)"/>'
        '<circle cx="26" cy="26" r="5" fill="url(#shG)"/>'
        '<circle cx="26" cy="26" r="5" fill="none" stroke="#2563EB" stroke-width="1.5">'
        '<animate attributeName="r" values="5;18;5" dur="2.4s" repeatCount="indefinite"/>'
        '<animate attributeName="opacity" values="1;0;1" dur="2.4s" repeatCount="indefinite"/>'
        '</circle></svg></div>'
        '<div style="flex:1; min-width:0;">'
        '<div style="font-family:Inter,sans-serif; font-size:1.35rem; font-weight:700;'
        ' color:#0F172A; letter-spacing:-0.02em;">Shield monitor · live system</div>'
        '<div style="font-family:Inter,sans-serif; font-size:0.875rem; color:#475569;'
        ' margin-top:4px; line-height:1.5;">'
        'Full device monitoring: network connections, running processes, '
        'system resources, USB devices, LAN discovery.</div></div>'
        '<div style="flex-shrink:0; font-family:JetBrains Mono,monospace; font-size:0.7rem;'
        ' color:#16A34A; font-weight:700; background:#F0FDF4; padding:6px 11px;'
        ' border-radius:6px; display:flex; align-items:center; gap:7px; '
        'animation: slideInLeft 0.6s ease-out; box-shadow: 0 0 10px rgba(22, 163, 74, 0.2);">'
        '<span style="width:7px; height:7px; border-radius:50%; background:#16A34A;'
        ' animation:mc-pulse 1.6s infinite; box-shadow: 0 0 8px rgba(22, 163, 74, 0.6);"></span>LIVE</div>'
        '</div></div>',
        unsafe_allow_html=True,
    )

    if not _PSUTIL:
        st.error("psutil not installed.\n\n```powershell\npip install psutil\n```")
        return

    # ── Tab legend (hover-friendly hints) ────────────────────────
    st.markdown(
        '<div style="display:flex; flex-wrap:wrap; gap:10px; margin:10px 0 16px;'
        ' font-family:Inter,sans-serif; font-size:0.78rem;">'
        '<div style="background:#EFF6FF; padding:6px 12px; border-radius:6px;'
        ' color:#1E40AF; border:1px solid #DBEAFE;">'
        '🌐 <b>Network</b> — Live TCP connections + geo + threat reputation</div>'
        '<div style="background:#F0FDF4; padding:6px 12px; border-radius:6px;'
        ' color:#15803D; border:1px solid #BBF7D0;">'
        '⚙️ <b>Processes</b> — Running apps with CPU/RAM + suspicious detection</div>'
        '<div style="background:#FFF7ED; padding:6px 12px; border-radius:6px;'
        ' color:#9A3412; border:1px solid #FED7AA;">'
        '💻 <b>System</b> — OS, CPU, RAM, disk, battery, uptime</div>'
        '<div style="background:#FFFBEB; padding:6px 12px; border-radius:6px;'
        ' color:#92400E; border:1px solid #FDE68A;">'
        '🔌 <b>USB/Disk</b> — Storage devices + new insertion alerts</div>'
        '<div style="background:#F5F3FF; padding:6px 12px; border-radius:6px;'
        ' color:#5B21B6; border:1px solid #DDD6FE;">'
        '🔓 <b>Open Ports</b> — All listening ports · process · exposure · CVE risk</div>'
        '</div>',
        unsafe_allow_html=True,
    )

    # 5 tabs
    tab_net, tab_proc, tab_sys, tab_usb, tab_ports = st.tabs([
        "🌐 Network",
        "⚙️ Processes",
        "💻 System info",
        "🔌 USB / Disk",
        "🔓 Open Ports",
    ])

    with tab_net:
        col_scan, col_auto, _ = st.columns([1, 1.3, 4])
        with col_scan:
            scan_clicked = st.button("🔍 Scan", type="primary",
                                     use_container_width=True, key="net_scan")
        with col_auto:
            auto_refresh = st.checkbox("⏱ Auto (30s)", key="shield_auto")

        if scan_clicked or auto_refresh or "shield_net" not in st.session_state:
            with st.spinner("Enumerating connections..."):
                conns = _get_network_connections()

            with st.status("🔍 AbuseIPDB + geo lookup...", expanded=False) as s:
                for i, c in enumerate(conns[:10]):
                    rep = _check_ip_reputation(c["remote_ip"])
                    c.update({
                        "verdict":    rep.get("verdict", "UNKNOWN"),
                        "confidence": rep.get("confidence", 0),
                        "is_tor":     rep.get("is_tor", False),
                    })
                    s.write(f"{i+1}/{min(10,len(conns))}: {c['remote_ip']} → {rep.get('verdict','?')}")

                def _geo(args):
                    idx, c = args
                    return idx, _geo_lookup(c["remote_ip"])
                with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
                    for idx, geo in ex.map(_geo, enumerate(conns)):
                        if geo.get("country") and geo["country"] != "?":
                            conns[idx]["country"]      = geo["country"]
                            conns[idx]["country_code"] = geo.get("country_code", "")
                        if conns[idx].get("isp") in ("?", None, ""):
                            conns[idx]["isp"] = geo.get("isp", "?")
                s.update(label="Scan complete", state="complete")

            st.session_state["shield_net"] = conns
            st.session_state["shield_ts"]  = time.strftime("%H:%M:%S")

        conns = st.session_state.get("shield_net", [])
        _render_network_tab(conns)

        # ── Email report (on-demand button OR auto every 15 min) ──
        def _send_full_report(conns_list: list[dict], reason: str = "Manual"):
            """Send comprehensive email with all connections + system summary."""
            try:
                from config import CFG
                alert_email = getattr(CFG, "ALERT_EMAIL", "") or ""
                smtp_pass   = getattr(CFG, "ALERT_SMTP_PASS", "") or ""
                if not alert_email or not smtp_pass:
                    return False, "Email not configured in .env"

                total    = len(conns_list)
                threats  = [c for c in conns_list if c.get("verdict") in ("MALICIOUS", "SUSPICIOUS")]
                countries = len({c.get("country") for c in conns_list if c.get("country","?") != "?"})

                # Build full report rows
                rows = ""
                for c in conns_list[:30]:
                    v = c.get("verdict", "?")
                    v_color = "#DC2626" if v == "MALICIOUS" else "#CA8A04" if v == "SUSPICIOUS" else "#16A34A" if v == "CLEAN" else "#64748B"
                    flag = _country_flag(c.get("country_code", ""))
                    rows += (
                        f'<tr style="border-bottom:1px solid #F1F5F9;">'
                        f'<td style="padding:6px 10px; color:{v_color}; font-weight:bold; font-size:12px;">{v}</td>'
                        f'<td style="padding:6px 10px; font-size:12px;">{c.get("process","—")[:16]}</td>'
                        f'<td style="padding:6px 10px; font-family:monospace; font-size:12px;">'
                        f'{c.get("remote_ip","?")}:{c.get("remote_port","?")}</td>'
                        f'<td style="padding:6px 10px; font-size:12px;">{flag} {c.get("country","?")[:12]}</td>'
                        f'<td style="padding:6px 10px; font-size:12px;">{(c.get("isp","?"))[:18]}</td>'
                        f'</tr>'
                    )

                sys_info = ""
                try:
                    uname = platform.uname()
                    mem = psutil.virtual_memory()
                    cpu = psutil.cpu_percent(interval=0.5)
                    sys_info = (
                        f'<div style="margin-top:16px; padding:14px; background:#F8FAFC;'
                        f'border-radius:8px; font-size:12px; color:#334155;">'
                        f'<b>System:</b> {uname.system} {uname.release} · {uname.node}<br/>'
                        f'<b>CPU:</b> {cpu:.0f}% · <b>RAM:</b> {mem.percent:.0f}% '
                        f'({round(mem.used/1024**3,1)}/{round(mem.total/1024**3,1)} GB)<br/>'
                        f'<b>Scan time:</b> {time.strftime("%Y-%m-%d %H:%M:%S")}'
                        f'</div>'
                    )
                except Exception:
                    pass

                banner_bg = "linear-gradient(90deg,#DC2626,#991B1B)" if threats else "linear-gradient(90deg,#16A34A,#15803D)"
                status_text = f"{len(threats)} THREAT(S) DETECTED" if threats else "ALL CLEAR — No threats"

                html_body = f"""
                <html><body style="font-family:Arial,sans-serif; background:#F8FAFC; padding:20px;">
                <div style="max-width:650px; margin:0 auto; background:#FFFFFF;
                            border-radius:12px; overflow:hidden;
                            box-shadow:0 4px 12px rgba(0,0,0,0.1);">
                  <div style="background:{banner_bg}; padding:20px 24px; color:#FFFFFF;">
                    <h2 style="margin:0;">🛡️ AI-DTCTM Shield Monitor Report</h2>
                    <p style="margin:6px 0 0; opacity:0.9;">{reason} · {status_text}</p>
                  </div>
                  <div style="padding:20px 24px;">
                    <div style="display:flex; gap:20px; margin-bottom:16px;">
                      <div style="text-align:center; flex:1; padding:12px; background:#F8FAFC; border-radius:8px;">
                        <div style="font-size:24px; font-weight:bold; color:#0F172A;">{total}</div>
                        <div style="font-size:11px; color:#64748B;">Connections</div>
                      </div>
                      <div style="text-align:center; flex:1; padding:12px; background:{'#FEF2F2' if threats else '#F0FDF4'}; border-radius:8px;">
                        <div style="font-size:24px; font-weight:bold; color:{'#DC2626' if threats else '#16A34A'};">{len(threats)}</div>
                        <div style="font-size:11px; color:#64748B;">Suspicious</div>
                      </div>
                      <div style="text-align:center; flex:1; padding:12px; background:#F8FAFC; border-radius:8px;">
                        <div style="font-size:24px; font-weight:bold; color:#0F172A;">{countries}</div>
                        <div style="font-size:11px; color:#64748B;">Countries</div>
                      </div>
                    </div>
                    <table style="width:100%; border-collapse:collapse; font-size:12px;">
                      <thead><tr style="background:#F1F5F9;">
                        <th style="padding:8px 10px; text-align:left; color:#64748B;">Verdict</th>
                        <th style="padding:8px 10px; text-align:left; color:#64748B;">Process</th>
                        <th style="padding:8px 10px; text-align:left; color:#64748B;">Remote IP</th>
                        <th style="padding:8px 10px; text-align:left; color:#64748B;">Country</th>
                        <th style="padding:8px 10px; text-align:left; color:#64748B;">ISP</th>
                      </tr></thead>
                      <tbody>{rows}</tbody>
                    </table>
                    {sys_info}
                    <p style="color:#94A3B8; font-size:11px; margin-top:16px;">
                      AI-DTCTM Shield Monitor · {time.strftime('%Y-%m-%d %H:%M:%S')}
                    </p>
                  </div>
                </div>
                </body></html>
                """

                ok = _send_threat_alert(
                    recipient=alert_email,
                    subject=f"🛡️ AI-DTCTM Report: {total} connections · {len(threats)} threats · {time.strftime('%H:%M')}",
                    body_html=html_body,
                    sender_email=alert_email,
                    sender_password=smtp_pass,
                )
                return ok, "Sent" if ok else "Failed"
            except Exception as e:
                return False, str(e)

        # On-demand report — triggered from Admin page (hidden)
        if st.session_state.get("send_report_now"):
            ok, msg = _send_full_report(conns, reason="Admin-triggered report")
            st.session_state["send_report_now"] = False
            if ok:
                st.toast("📧 Report sent!", icon="✅")

        # Auto-report every 15 min (only when auto-refresh ON + email configured)
        if auto_refresh and conns:
            last_report_ts = st.session_state.get("last_auto_report", 0)
            if time.time() - last_report_ts > 900:  # 15 min = 900 sec
                ok, _ = _send_full_report(conns, reason="Auto-report (15min)")
                if ok:
                    st.session_state["last_auto_report"] = time.time()

        if auto_refresh:
            time.sleep(30)
            st.rerun()

    with tab_proc:
        if st.button("🔄 Refresh processes", key="proc_refresh"):
            st.rerun()
        _render_process_tab()

    with tab_sys:
        if st.button("🔄 Refresh metrics", key="sys_refresh"):
            st.rerun()
        _render_sysinfo_tab()

    with tab_usb:
        if st.button("🔄 Refresh devices", key="usb_refresh"):
            st.rerun()
        _render_usb_tab()

    with tab_ports:
        _render_openports_tab()
