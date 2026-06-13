"""
AI-DTCTM | Analytics Dashboard (v24 — clean, no-pandas rendering)
══════════════════════════════════════════════════════════════════════
• All charts: native HTML/SVG — does NOT import pandas (Windows WDAC safe)
• Standard tab: at-a-glance operations view
• Advanced tab: deep KPI trending + threat landscape + capabilities
• Date range: compact top-right slider, 1–30 days
• Today's Activity always visible above tabs
"""
from __future__ import annotations

import datetime
import streamlit as st

from core.shared_css import section_header, kpi_row
from core.logger import get_logger

log = get_logger(__name__)


# ── colour palette ─────────────────────────────────────────────────
_C_PRIMARY = "#2563EB"
_C_PRIMARY_DK = "#1E40AF"
_C_PRIMARY_BG = "#EFF6FF"
_C_RED = "#DC2626"
_C_AMBER = "#F59E0B"
_C_GREEN = "#16A34A"
_C_PURPLE = "#8B5CF6"
_C_SLATE = "#64748B"
_C_INK = "#0F172A"
_C_PAGE_BG = "#FFFFFF"

# Verdict → (icon, colour, label)
_VERDICT_META = {
    "MALICIOUS":   ("🔴", _C_RED,    "Malicious"),
    "SUSPICIOUS":  ("🟠", _C_AMBER,  "Suspicious"),
    "CLEAN":       ("🟢", _C_GREEN,  "Clean"),
    "DEAD_DOMAIN": ("🟣", _C_PURPLE, "Dead domain"),
    "UNKNOWN":     ("⚪", _C_SLATE,  "Unknown"),
}


# ══════════════════════════════════════════════════════════════════════
# DATA LOADING
# ══════════════════════════════════════════════════════════════════════
def _load_rows() -> list[dict] | None:
    """Pull scan history from SQLite (no pandas)."""
    try:
        from core.scan_history import get_all
        return get_all(limit=5000) or []
    except Exception as e:
        st.error(f"scan_history error: {e}")
        return None


def _normalise(rows: list[dict], date_range_days: int) -> list[dict]:
    """Parse rows into uniform shape, filtered by date range."""
    now = datetime.datetime.now()
    cutoff = now - datetime.timedelta(days=date_range_days)
    out: list[dict] = []
    for row in rows or []:
        try:
            raw_ts = row.get("created_at")
            if isinstance(raw_ts, str):
                created_at = datetime.datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
                if created_at.tzinfo is not None:
                    created_at = created_at.replace(tzinfo=None)
            elif isinstance(raw_ts, datetime.datetime):
                created_at = raw_ts.replace(tzinfo=None) if raw_ts.tzinfo else raw_ts
            else:
                continue
        except Exception:
            continue

        if created_at < cutoff:
            continue

        try:
            score = float(row.get("score") or 0)
        except (ValueError, TypeError):
            score = 0.0

        verdict = (row.get("verdict") or "UNKNOWN").upper()
        out.append({
            "created_at": created_at,
            "scan_type":  (row.get("scan_type") or "scan"),
            "target":     row.get("target") or "",
            "verdict":    verdict,
            "score":      score,
        })
    return out


# ══════════════════════════════════════════════════════════════════════
# RENDER PRIMITIVES (custom, pandas-free)
# ══════════════════════════════════════════════════════════════════════
def _hero(title: str, subtitle: str, tag_label: str, tag_color: str = _C_PRIMARY) -> None:
    """Compact top hero strip — no full-width banner."""
    st.markdown(
        f"<div style='display:flex;align-items:center;justify-content:space-between;"
        f"gap:14px;padding:10px 16px;background:linear-gradient(90deg,{_C_PRIMARY_BG},#FFFFFF);"
        f"border:1px solid #DBEAFE;border-left:4px solid {tag_color};border-radius:10px;"
        f"margin-bottom:12px;'>"
        f"<div>"
        f"<div style='font-family:Inter,sans-serif;font-size:1.05rem;font-weight:700;color:{_C_INK};"
        f"letter-spacing:-0.01em;'>{title}</div>"
        f"<div style='font-family:Inter,sans-serif;font-size:0.78rem;color:#475569;margin-top:3px;'>"
        f"{subtitle}</div>"
        f"</div>"
        f"<div style='font-family:JetBrains Mono,monospace;font-size:0.62rem;font-weight:700;"
        f"color:{tag_color};background:{tag_color}14;border:1px solid {tag_color}44;"
        f"padding:5px 11px;border-radius:6px;letter-spacing:0.1em;white-space:nowrap;"
        f"display:flex;align-items:center;gap:6px;'>"
        f"<span style='width:6px;height:6px;border-radius:50%;background:{tag_color};"
        f"animation:mc-pulse 1.6s infinite;'></span>"
        f"{tag_label}"
        f"</div></div>",
        unsafe_allow_html=True,
    )


def _section(label: str, sub: str = "", icon_svg: str = "") -> None:
    """Compact section header — smaller font, professional spacing."""
    st.markdown(
        f"<div style='display:flex;align-items:center;justify-content:space-between;"
        f"gap:10px;margin:18px 0 10px;padding-bottom:6px;border-bottom:1px solid #E2E8F0;'>"
        f"<div style='display:flex;align-items:center;gap:8px;'>"
        f"{icon_svg}"
        f"<span style='font-family:Inter,sans-serif;font-size:0.92rem;font-weight:700;color:{_C_INK};'>"
        f"{label}</span></div>"
        f"<span style='font-family:JetBrains Mono,monospace;font-size:0.6rem;font-weight:600;"
        f"color:{_C_SLATE};letter-spacing:0.18em;text-transform:uppercase;'>{sub}</span></div>",
        unsafe_allow_html=True,
    )


def _bar_row(label: str, value: int, total: int, color: str) -> str:
    """One horizontal stacked-bar row (HTML only)."""
    pct = (value / total * 100) if total else 0
    return (
        f"<div style='display:grid;grid-template-columns:130px 1fr 70px;gap:10px;"
        f"align-items:center;margin-bottom:7px;'>"
        f"<div style='font-family:Inter,sans-serif;font-size:0.78rem;color:{_C_INK};"
        f"font-weight:600;'>{label}</div>"
        f"<div style='background:#F1F5F9;border-radius:6px;height:9px;overflow:hidden;'>"
        f"<div style='background:{color};width:{pct:.1f}%;height:100%;border-radius:6px;'></div></div>"
        f"<div style='font-family:JetBrains Mono,monospace;font-size:0.72rem;color:{_C_SLATE};"
        f"text-align:right;'>{value} · {pct:.0f}%</div>"
        f"</div>"
    )


def _native_daily_bars(data: list[dict], range_days: int) -> None:
    """HTML/CSS day-by-day bar chart (no pandas, no Streamlit charts)."""
    # Bucket per day
    daily: dict[str, int] = {}
    today = datetime.datetime.now().date()
    for d_offset in range(range_days, -1, -1):
        key = (today - datetime.timedelta(days=d_offset)).strftime("%m-%d")
        daily[key] = 0
    for d in data:
        key = d["created_at"].strftime("%m-%d")
        if key in daily:
            daily[key] += 1

    max_v = max(daily.values()) or 1
    cells = []
    for key, val in daily.items():
        h_pct = (val / max_v * 100) if max_v else 0
        h_pct = max(h_pct, 2 if val > 0 else 0)
        c = _C_PRIMARY if val > 0 else "#E2E8F0"
        cells.append(
            f"<div style='flex:1;min-width:0;display:flex;flex-direction:column;"
            f"justify-content:flex-end;align-items:center;gap:4px;'>"
            f"<div style='font-family:JetBrains Mono,monospace;font-size:0.6rem;color:{_C_SLATE};'>"
            f"{val if val else ''}</div>"
            f"<div style='background:{c};width:78%;height:{h_pct}%;min-height:2px;"
            f"border-radius:3px 3px 0 0;transition:height 600ms ease;' title='{key}: {val}'></div>"
            f"<div style='font-family:JetBrains Mono,monospace;font-size:0.55rem;"
            f"color:#94A3B8;letter-spacing:0.04em;'>{key}</div>"
            f"</div>"
        )

    st.markdown(
        f"<div style='background:#FFFFFF;border:1px solid #E2E8F0;border-radius:10px;"
        f"padding:14px 16px;'>"
        f"<div style='display:flex;align-items:flex-end;gap:5px;height:140px;'>"
        + "".join(cells) +
        f"</div></div>",
        unsafe_allow_html=True,
    )


def _icon(path: str, color: str = _C_PRIMARY) -> str:
    """SVG icon helper — produces a 16×16 line icon."""
    return (f"<svg width='16' height='16' viewBox='0 0 24 24' fill='none' "
            f"stroke='{color}' stroke-width='2' stroke-linecap='round' "
            f"stroke-linejoin='round'>{path}</svg>")


# Icon library — professional line icons
_I_CALENDAR = "<rect x='3' y='4' width='18' height='18' rx='2'/><line x1='16' y1='2' x2='16' y2='6'/><line x1='8' y1='2' x2='8' y2='6'/><line x1='3' y1='10' x2='21' y2='10'/>"
_I_CHART    = "<path d='M3 3v18h18'/><path d='M7 14l4-4 4 4 5-5'/>"
_I_SHIELD   = "<path d='M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z'/>"
_I_ACTIVITY = "<polyline points='22 12 18 12 15 21 9 3 6 12 2 12'/>"
_I_PIE      = "<path d='M21 15.5A8.5 8.5 0 1 1 8.5 3v9H21z'/>"
_I_TARGET   = "<circle cx='12' cy='12' r='10'/><circle cx='12' cy='12' r='6'/><circle cx='12' cy='12' r='2'/>"
_I_ZAP      = "<polygon points='13 2 3 14 12 14 11 22 21 10 12 10 13 2'/>"
_I_TREND    = "<polyline points='23 6 13.5 15.5 8.5 10.5 1 18'/><polyline points='17 6 23 6 23 12'/>"
_I_API      = "<polyline points='16 18 22 12 16 6'/><polyline points='8 6 2 12 8 18'/>"
_I_LIST     = "<line x1='8' y1='6' x2='21' y2='6'/><line x1='8' y1='12' x2='21' y2='12'/><line x1='8' y1='18' x2='21' y2='18'/><circle cx='3.5' cy='6' r='1'/><circle cx='3.5' cy='12' r='1'/><circle cx='3.5' cy='18' r='1'/>"


# ══════════════════════════════════════════════════════════════════════
# TODAY'S ACTIVITY — always at the top (above tabs)
# ══════════════════════════════════════════════════════════════════════
def _render_todays_activity(rows: list[dict]) -> None:
    now = datetime.datetime.now()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    today_end   = today_start + datetime.timedelta(days=1)
    today_data  = _normalise(rows, date_range_days=1)
    today_data  = [d for d in today_data if today_start <= d["created_at"] < today_end]

    total   = len(today_data)
    threats = sum(1 for d in today_data if d["verdict"] in ("MALICIOUS", "SUSPICIOUS", "DEAD_DOMAIN"))
    clean   = sum(1 for d in today_data if d["verdict"] == "CLEAN")
    avg     = round(sum(d["score"] for d in today_data) / len(today_data), 2) if today_data else 0.0

    _section("Today's activity", "LIVE · " + now.strftime("%b %d"),
             icon_svg=_icon(_I_CALENDAR, _C_PRIMARY))

    # 4 KPI tiles — compact, custom-styled (no st.metric pandas dep)
    def _tile(label: str, value: str, sub: str, color: str) -> str:
        return (
            f"<div style='background:#FFFFFF;border:1px solid #E2E8F0;border-radius:10px;"
            f"padding:12px 14px;border-left:3px solid {color};'>"
            f"<div style='font-family:JetBrains Mono,monospace;font-size:0.6rem;color:{_C_SLATE};"
            f"letter-spacing:0.16em;text-transform:uppercase;font-weight:600;'>{label}</div>"
            f"<div style='font-family:Inter,sans-serif;font-size:1.7rem;font-weight:700;color:{color};"
            f"line-height:1;margin-top:4px;'>{value}</div>"
            f"<div style='font-family:Inter,sans-serif;font-size:0.7rem;color:{_C_SLATE};"
            f"margin-top:3px;'>{sub}</div>"
            f"</div>"
        )

    st.markdown(
        "<div style='display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:8px;'>"
        + _tile("Scans today",   str(total),   f"{total} scans",      _C_PRIMARY)
        + _tile("Threats today", str(threats), f"{threats} detected", _C_RED if threats else _C_GREEN)
        + _tile("Avg risk",      f"{avg:.1f}/10", "today's mean",     _C_AMBER)
        + _tile("Clean today",   str(clean),   f"{clean} safe",       _C_GREEN)
        + "</div>",
        unsafe_allow_html=True,
    )


# ══════════════════════════════════════════════════════════════════════
# TOP-RIGHT CORNER DATE SELECTOR — compact, 1–30 days slider
# ══════════════════════════════════════════════════════════════════════
def _render_date_selector() -> int:
    """Small top-right corner date slider. Returns selected number of days."""
    if "date_range" not in st.session_state:
        st.session_state.date_range = 7

    spacer, picker = st.columns([3, 1.1])
    with picker:
        st.markdown(
            f"<div style='font-family:JetBrains Mono,monospace;font-size:0.6rem;"
            f"font-weight:700;color:{_C_PRIMARY_DK};background:{_C_PRIMARY_BG};"
            f"border:1px solid #DBEAFE;border-radius:6px;padding:4px 9px;"
            f"text-align:center;letter-spacing:0.12em;'>"
            f"📅 RANGE · {st.session_state.date_range}d</div>",
            unsafe_allow_html=True,
        )
        new_range = st.slider(
            label="date_slider",
            min_value=1, max_value=30,
            value=st.session_state.date_range,
            step=1,
            key="date_range_slider",
            label_visibility="collapsed",
        )
        if new_range != st.session_state.date_range:
            st.session_state.date_range = new_range
            st.rerun()
    return st.session_state.date_range


# ══════════════════════════════════════════════════════════════════════
# STANDARD ANALYTICS — at-a-glance operations view
# ══════════════════════════════════════════════════════════════════════
def _render_standard(rows: list[dict], date_range: int) -> None:
    range_label = f"{date_range}d" if date_range != 1 else "1d"

    _hero(
        title="Analytics · operations view",
        subtitle="At-a-glance daily metrics from your live scan_history.db",
        tag_label="LIVE DATA",
    )

    data = _normalise(rows, date_range)

    if not data:
        st.info(f"No scans in the last {date_range} day(s). Run a scan to see metrics here.")
        return

    # ── KPI row for the selected window ────────────────────────────
    total   = len(data)
    threats = sum(1 for d in data if d["verdict"] in ("MALICIOUS", "SUSPICIOUS", "DEAD_DOMAIN"))
    clean   = sum(1 for d in data if d["verdict"] == "CLEAN")
    avg     = round(sum(d["score"] for d in data) / len(data), 2) if data else 0.0
    threat_pct = round(threats / total * 100, 1) if total else 0
    posture = max(0, min(100, round(100 - (threat_pct * 1.5), 1)))

    _section(f"Window overview · last {range_label}",
             "OPS",
             icon_svg=_icon(_I_CHART, _C_PRIMARY))
    kpi_row([
        {"label": "Total scans",      "value": str(total),           "tone": "amber"},
        {"label": "Threats detected", "value": str(threats),
         "tone": "red" if threats else "green"},
        {"label": "Avg risk score",   "value": f"{avg:.1f}/10"},
        {"label": "Posture score",    "value": f"{posture:.0f}/100",
         "tone": "green" if posture >= 80 else "amber" if posture >= 60 else "red"},
    ])

    # ── Daily activity chart (HTML/SVG only) ───────────────────────
    _section("Daily scanning activity", range_label.upper(),
             icon_svg=_icon(_I_ACTIVITY, _C_PRIMARY))
    _native_daily_bars(data, date_range)

    # ── Verdict distribution (horizontal bars, HTML only) ──────────
    _section("Threat distribution", "BREAKDOWN",
             icon_svg=_icon(_I_PIE, _C_AMBER))

    vcounts: dict[str, int] = {}
    for d in data:
        vcounts[d["verdict"]] = vcounts.get(d["verdict"], 0) + 1

    bars_html = "<div style='background:#FFFFFF;border:1px solid #E2E8F0;border-radius:10px;padding:14px 16px;'>"
    for verdict in ("MALICIOUS", "SUSPICIOUS", "CLEAN", "DEAD_DOMAIN", "UNKNOWN"):
        n = vcounts.get(verdict, 0)
        if n == 0:
            continue
        icon, color, label = _VERDICT_META[verdict]
        bars_html += _bar_row(f"{icon} {label}", n, total, color)
    bars_html += "</div>"
    st.markdown(bars_html, unsafe_allow_html=True)

    # ── Recent scans list ──────────────────────────────────────────
    _section("Recent scans", f"LAST 15 · {range_label.upper()}",
             icon_svg=_icon(_I_LIST, _C_SLATE))
    data_sorted = sorted(data, key=lambda x: x["created_at"], reverse=True)[:15]
    rows_html = "<div style='background:#FFFFFF;border:1px solid #E2E8F0;border-radius:10px;overflow:hidden;'>"
    for i, d in enumerate(data_sorted):
        icon, color, _ = _VERDICT_META.get(d["verdict"], _VERDICT_META["UNKNOWN"])
        target = (d["target"] or "—")[:64]
        ts = d["created_at"].strftime("%b %d · %H:%M")
        bg = "#FFFFFF" if i % 2 == 0 else "#F8FAFC"
        rows_html += (
            f"<div style='display:grid;grid-template-columns:30px 1fr 100px 110px 70px;"
            f"gap:10px;padding:9px 14px;background:{bg};border-bottom:1px solid #F1F5F9;"
            f"align-items:center;'>"
            f"<div style='font-size:1rem'>{icon}</div>"
            f"<div style='font-family:JetBrains Mono,monospace;font-size:0.72rem;color:{_C_INK};"
            f"overflow:hidden;text-overflow:ellipsis;white-space:nowrap;' title='{target}'>{target}</div>"
            f"<div style='font-family:Inter,sans-serif;font-size:0.7rem;color:{color};font-weight:700;'>"
            f"{d['verdict']}</div>"
            f"<div style='font-family:JetBrains Mono,monospace;font-size:0.68rem;color:{_C_SLATE};'>{ts}</div>"
            f"<div style='font-family:JetBrains Mono,monospace;font-size:0.72rem;color:{_C_INK};"
            f"text-align:right;font-weight:600;'>{d['score']:.1f}/10</div>"
            f"</div>"
        )
    rows_html += "</div>"
    st.markdown(rows_html, unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════
# ADVANCED ANALYTICS — KPI trending, threat landscape, capabilities,
# scan type breakdown, API health (all pandas-free)
# ══════════════════════════════════════════════════════════════════════
def _render_advanced(rows: list[dict], date_range: int) -> None:
    range_label = f"{date_range}d"

    _hero(
        title="Advanced analytics · deep telemetry",
        subtitle="KPI trending, scan-type breakdown, capabilities map, ML model details",
        tag_label="DEEP VIEW",
        tag_color=_C_PURPLE,
    )

    data = _normalise(rows, date_range)
    if not data:
        st.info(f"No scans in the last {date_range} day(s).")
        return

    # ── 1. KPI trending — Scans per day + threats per day (twin chart) ─
    _section("KPI trending", range_label.upper(),
             icon_svg=_icon(_I_TREND, _C_PURPLE))

    # Build daily series
    today = datetime.datetime.now().date()
    days = [(today - datetime.timedelta(days=i)) for i in range(date_range, -1, -1)]
    scan_series:   list[int] = []
    threat_series: list[int] = []
    for day in days:
        day_scans = [d for d in data if d["created_at"].date() == day]
        scan_series.append(len(day_scans))
        threat_series.append(sum(1 for d in day_scans
                                  if d["verdict"] in ("MALICIOUS", "SUSPICIOUS")))

    max_s = max(scan_series) or 1
    max_t = max(threat_series) or 1
    max_y = max(max_s, max_t)

    width  = 700
    height = 180
    pad_l, pad_r, pad_t, pad_b = 30, 10, 10, 22
    n_days = len(days)
    if n_days > 1:
        step = (width - pad_l - pad_r) / (n_days - 1)
    else:
        step = 0

    def _polyline(series: list[int], color: str) -> str:
        pts = []
        for i, v in enumerate(series):
            x = pad_l + i * step
            y = pad_t + (height - pad_t - pad_b) * (1 - v / max_y) if max_y else height - pad_b
            pts.append(f"{x:.0f},{y:.0f}")
        return (f"<polyline points='{' '.join(pts)}' fill='none' "
                f"stroke='{color}' stroke-width='2.2' stroke-linecap='round' "
                f"stroke-linejoin='round'/>"
                + "".join(
                    f"<circle cx='{p.split(',')[0]}' cy='{p.split(',')[1]}' r='3' "
                    f"fill='{color}'/>"
                    for p in pts
                ))

    # Grid lines
    grid = ""
    for frac in (0.25, 0.5, 0.75, 1.0):
        y = pad_t + (height - pad_t - pad_b) * (1 - frac)
        grid += (f"<line x1='{pad_l}' y1='{y}' x2='{width - pad_r}' y2='{y}' "
                 f"stroke='#F1F5F9' stroke-width='1'/>"
                 f"<text x='{pad_l - 5}' y='{y + 3}' text-anchor='end' "
                 f"font-size='9' fill='{_C_SLATE}' font-family='JetBrains Mono,monospace'>"
                 f"{int(max_y * frac)}</text>")

    # Day labels (every other)
    labels = ""
    for i, day in enumerate(days):
        if n_days > 14 and i % 2 != 0:
            continue
        x = pad_l + i * step
        labels += (f"<text x='{x}' y='{height - 5}' text-anchor='middle' "
                   f"font-size='9' fill='{_C_SLATE}' font-family='JetBrains Mono,monospace'>"
                   f"{day.strftime('%m-%d')}</text>")

    chart_svg = (
        f"<div style='background:#FFFFFF;border:1px solid #E2E8F0;border-radius:10px;"
        f"padding:14px 16px;'>"
        f"<div style='display:flex;gap:18px;margin-bottom:8px;font-family:Inter,sans-serif;"
        f"font-size:0.72rem;'>"
        f"<span style='color:{_C_PRIMARY};font-weight:700;'>● Scans/day</span>"
        f"<span style='color:{_C_RED};font-weight:700;'>● Threats/day</span></div>"
        f"<svg viewBox='0 0 {width} {height}' style='width:100%;height:auto;display:block;'>"
        f"{grid}"
        f"{_polyline(scan_series, _C_PRIMARY)}"
        f"{_polyline(threat_series, _C_RED)}"
        f"{labels}"
        f"</svg></div>"
    )
    st.markdown(chart_svg, unsafe_allow_html=True)

    # ── 2. Scans by type (horizontal stacked) ────────────────────────
    _section("Scans by type", "BREAKDOWN",
             icon_svg=_icon(_I_PIE, _C_AMBER))

    type_counts: dict[str, int] = {}
    type_threats: dict[str, int] = {}
    for d in data:
        t = d["scan_type"] or "scan"
        type_counts[t] = type_counts.get(t, 0) + 1
        if d["verdict"] in ("MALICIOUS", "SUSPICIOUS"):
            type_threats[t] = type_threats.get(t, 0) + 1

    type_html = "<div style='background:#FFFFFF;border:1px solid #E2E8F0;border-radius:10px;padding:14px 16px;'>"
    total_for_type = sum(type_counts.values())
    type_palette = {
        "url":         _C_PRIMARY,
        "file":        _C_AMBER,
        "database":    _C_PURPLE,
        "twin_attack": _C_RED,
        "scan":        _C_SLATE,
    }
    for t, n in sorted(type_counts.items(), key=lambda x: -x[1]):
        color = type_palette.get(t, _C_SLATE)
        thr = type_threats.get(t, 0)
        label = f"{t.replace('_', ' ').title()} ({thr} threats)"
        type_html += _bar_row(label, n, total_for_type, color)
    type_html += "</div>"
    st.markdown(type_html, unsafe_allow_html=True)

    # ── 3. Threat severity heatmap by hour-of-day ────────────────────
    _section("Activity heatmap · hour of day", "24H",
             icon_svg=_icon(_I_ZAP, _C_AMBER))

    hourly = [0] * 24
    hourly_threats = [0] * 24
    for d in data:
        h = d["created_at"].hour
        hourly[h] += 1
        if d["verdict"] in ("MALICIOUS", "SUSPICIOUS"):
            hourly_threats[h] += 1

    max_h = max(hourly) or 1
    heat_html = "<div style='background:#FFFFFF;border:1px solid #E2E8F0;border-radius:10px;padding:14px 16px;'>"
    heat_html += "<div style='display:grid;grid-template-columns:repeat(24,1fr);gap:3px;'>"
    for h in range(24):
        intensity = hourly[h] / max_h
        # Blend white → primary based on intensity
        opacity = 0.15 + intensity * 0.85
        has_threat = hourly_threats[h] > 0
        color = _C_RED if has_threat else _C_PRIMARY
        heat_html += (
            f"<div style='display:flex;flex-direction:column;align-items:center;gap:3px;' "
            f"title='Hour {h}: {hourly[h]} scans, {hourly_threats[h]} threats'>"
            f"<div style='background:{color};opacity:{opacity:.2f};width:100%;height:34px;"
            f"border-radius:4px;display:flex;align-items:center;justify-content:center;"
            f"color:#FFFFFF;font-family:JetBrains Mono,monospace;font-size:0.6rem;"
            f"font-weight:700;'>{hourly[h] if hourly[h] else ''}</div>"
            f"<div style='font-family:JetBrains Mono,monospace;font-size:0.55rem;color:{_C_SLATE};'>"
            f"{h:02d}</div>"
            f"</div>"
        )
    heat_html += "</div></div>"
    st.markdown(heat_html, unsafe_allow_html=True)

    # ── 4. Forensic capabilities (expander) ─────────────────────────
    _section("Forensic capabilities", "PHASE 1-4",
             icon_svg=_icon(_I_SHIELD, _C_GREEN))

    cap_col1, cap_col2 = st.columns(2)
    with cap_col1:
        st.markdown(
            f"<div style='background:#F0FDF4;border:1px solid #BBF7D0;border-radius:10px;"
            f"padding:14px;'>"
            f"<div style='font-family:Inter,sans-serif;font-size:0.85rem;font-weight:700;"
            f"color:{_C_GREEN};margin-bottom:8px;'>✅ What we detect</div>"
            f"<div style='font-family:Inter,sans-serif;font-size:0.78rem;color:#166534;line-height:1.7;'>"
            f"• 251 detection signatures (202 regex + 49 YARA)<br/>"
            f"• Phishing URLs (RandomForest, ~94%)<br/>"
            f"• Webshells, RATs, infostealers, cryptominers<br/>"
            f"• Ransomware kill-chain artefacts<br/>"
            f"• Fileless / LOLBin / encoded PowerShell<br/>"
            f"• Hardcoded secrets (AWS, GCP, GitHub, JWT)<br/>"
            f"• 11 threat-intel APIs (CISA/NVD/OTX/VT/…)<br/>"
            f"</div></div>",
            unsafe_allow_html=True,
        )
    with cap_col2:
        st.markdown(
            f"<div style='background:#FFFBEB;border:1px solid #FDE68A;border-radius:10px;"
            f"padding:14px;'>"
            f"<div style='font-family:Inter,sans-serif;font-size:0.85rem;font-weight:700;"
            f"color:#B45309;margin-bottom:8px;'>⚠️ Known limitations</div>"
            f"<div style='font-family:Inter,sans-serif;font-size:0.78rem;color:#854D0E;line-height:1.7;'>"
            f"• Zero-day malware (no signature yet)<br/>"
            f"• Encrypted/packed payloads (run in lab to unpack)<br/>"
            f"• API rate limits (VirusTotal quota, etc.)<br/>"
            f"• Windows WDAC may block pandas/plotly DLLs<br/>"
            f"• Charts rendered as native HTML to bypass this<br/>"
            f"• False-positive risk on benign red-team tools<br/>"
            f"</div></div>",
            unsafe_allow_html=True,
        )

    # ── 5. ML model card ─────────────────────────────────────────────
    _section("ML model · phishing classifier", "v3 · 100K",
             icon_svg=_icon(_I_TARGET, _C_PURPLE))

    metrics = [
        ("Algorithm",     "RandomForest + char-ngram TF-IDF"),
        ("Training set",  "100,000 URLs (PhishTank + Tranco mix)"),
        ("Accuracy",      "89.89% ± 1.67%"),
        ("Precision",     "96.28% ± 1.03%"),
        ("Recall",        "67.98% ± 3.98%"),
        ("F1-score",      "79.62% ± 2.74%"),
        ("CV strategy",   "5-fold stratified"),
        ("Inference",     "~3 ms per URL on CPU"),
    ]
    ml_html = (
        "<div style='background:#FFFFFF;border:1px solid #E2E8F0;border-radius:10px;"
        "padding:14px 16px;'>"
        "<div style='display:grid;grid-template-columns:1fr 1fr;gap:8px 24px;'>"
    )
    for k, v in metrics:
        ml_html += (
            f"<div style='display:flex;justify-content:space-between;"
            f"border-bottom:1px dashed #E2E8F0;padding:5px 0;'>"
            f"<span style='font-family:Inter,sans-serif;font-size:0.74rem;color:{_C_SLATE};'>{k}</span>"
            f"<span style='font-family:JetBrains Mono,monospace;font-size:0.74rem;"
            f"color:{_C_INK};font-weight:600;'>{v}</span></div>"
        )
    ml_html += "</div></div>"
    st.markdown(ml_html, unsafe_allow_html=True)

    # ── 6. Recent activity (top 12, compact) ────────────────────────
    _section("Recent activity feed", "LAST 12",
             icon_svg=_icon(_I_LIST, _C_SLATE))
    recent = sorted(data, key=lambda x: x["created_at"], reverse=True)[:12]
    feed_html = "<div style='background:#FFFFFF;border:1px solid #E2E8F0;border-radius:10px;overflow:hidden;'>"
    for i, d in enumerate(recent):
        icon, color, _ = _VERDICT_META.get(d["verdict"], _VERDICT_META["UNKNOWN"])
        bg = "#FFFFFF" if i % 2 == 0 else "#F8FAFC"
        target = (d["target"] or "—")[:60]
        ts = d["created_at"].strftime("%b %d %H:%M:%S")
        feed_html += (
            f"<div style='display:grid;grid-template-columns:24px 100px 1fr 80px 80px;"
            f"gap:10px;padding:8px 14px;background:{bg};border-bottom:1px solid #F1F5F9;"
            f"align-items:center;'>"
            f"<div>{icon}</div>"
            f"<div style='font-family:Inter,sans-serif;font-size:0.7rem;color:{color};font-weight:700;'>"
            f"{d['verdict']}</div>"
            f"<div style='font-family:JetBrains Mono,monospace;font-size:0.7rem;color:{_C_INK};"
            f"overflow:hidden;text-overflow:ellipsis;white-space:nowrap;' title='{target}'>{target}</div>"
            f"<div style='font-family:JetBrains Mono,monospace;font-size:0.68rem;color:{_C_SLATE};'>{ts}</div>"
            f"<div style='font-family:JetBrains Mono,monospace;font-size:0.7rem;color:{_C_INK};"
            f"text-align:right;font-weight:600;'>{d['score']:.1f}/10</div>"
            f"</div>"
        )
    feed_html += "</div>"
    st.markdown(feed_html, unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════
# TOP-LEVEL RENDER
# ══════════════════════════════════════════════════════════════════════
def render_analytics() -> None:
    # 1. Inject tab CSS (small, professional)
    st.markdown(
        "<style>"
        ".stTabs [data-baseweb='tab-list'] button {"
        "  font-family:Inter,sans-serif; font-weight:600; font-size:0.85rem; color:#64748B;"
        "}"
        ".stTabs [data-baseweb='tab-list'] button[aria-selected='true'] {"
        "  color:#2563EB;"
        "}"
        "</style>",
        unsafe_allow_html=True,
    )

    # 2. Load rows once
    rows = _load_rows()
    if rows is None:
        return

    # 3. TODAY'S ACTIVITY — first, above tabs and selectors
    _render_todays_activity(rows)

    # 4. Top-right date selector (small, doesn't disturb the page)
    date_range = _render_date_selector()

    # 5. Tab switcher between Standard / Advanced — Streamlit-native tabs
    tab_std, tab_adv = st.tabs(["📊  Standard analytics", "🚀  Advanced analytics"])
    with tab_std:
        _render_standard(rows, date_range)
    with tab_adv:
        _render_advanced(rows, date_range)
