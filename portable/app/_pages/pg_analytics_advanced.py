"""
AI-DTCTM | Advanced Analytics Dashboard (Phase 1)
Native Streamlit implementation - NO external DLL dependencies.
Uses built-in st.line_chart, st.bar_chart, st.metric
"""

import streamlit as st
from datetime import datetime, timedelta

from core.scan_history import (
    get_kpi_trending, get_threat_distribution, get_api_health_status,
    get_kpis, get_recent, get_all
)

st.set_page_config(page_title="Advanced Analytics", layout="wide", initial_sidebar_state="expanded")

# ── Page Header ─────────────────────────────────────────────────────────

st.markdown("""
<style>
.analytics-header {
    background: linear-gradient(135deg, #FF6B1A 0%, #FF8C42 100%);
    padding: 24px;
    border-radius: 12px;
    color: white;
    margin-bottom: 24px;
}
.analytics-header h1 {
    margin: 0;
    font-size: 32px;
    font-weight: 700;
}
.analytics-header p {
    margin: 8px 0 0 0;
    opacity: 0.9;
    font-size: 14px;
}
</style>

<div class="analytics-header">
    <h1>Advanced Analytics Dashboard</h1>
    <p>Real-time threat landscape, KPI trending, and security posture metrics</p>
</div>
""", unsafe_allow_html=True)

# ── Auto-refresh control ────────────────────────────────────────────────

col1, col2 = st.columns([10, 2])
with col2:
    if st.button("Refresh", key="refresh_analytics"):
        st.rerun()

st.markdown("---")

# ── Section 1: Live KPI Metrics ─────────────────────────────────────────

st.subheader("Live KPI Metrics (24h)")

kpis = get_kpis()

# Display key metrics in columns
m_col1, m_col2, m_col3, m_col4, m_col5 = st.columns(5)

with m_col1:
    st.metric("Scans Today", kpis["scans_today"],
              delta=f"+{kpis['scans_today']}" if kpis['scans_today'] > 0 else "No scans")

with m_col2:
    st.metric("Threats Detected", kpis["threats_today"],
              delta=f"+{kpis['threats_today']}" if kpis['threats_today'] > 0 else "None")

with m_col3:
    threat_rate = (kpis["threats_today"] / kpis["scans_today"] * 100) if kpis["scans_today"] > 0 else 0
    st.metric("Threat Rate", f"{threat_rate:.1f}%")

with m_col4:
    st.metric("Total Scans", kpis["total_scans"],
              delta=f"+{kpis['scans_today']}")

with m_col5:
    st.metric("Total Threats", kpis["total_threats"],
              delta=f"+{kpis['threats_today']}")

st.markdown("---")

# ── Section 2: KPI Trending Over Time ───────────────────────────────

st.subheader("KPI Trending (7 Days)")

tab1, tab2, tab3 = st.tabs(["Daily Scans", "Daily Threats", "Threat Rate"])

with tab1:
    trending_daily = get_kpi_trending(interval="daily", days=7)
    if trending_daily["data"]:
        buckets = [d["bucket"] for d in trending_daily["data"]]
        scan_counts = [d["scan_count"] for d in trending_daily["data"]]

        chart_data = {}
        for bucket, count in zip(buckets, scan_counts):
            chart_data[bucket] = count

        st.bar_chart(chart_data)
    else:
        st.info("No scan data in last 7 days")

with tab2:
    trending_daily = get_kpi_trending(interval="daily", days=7)
    if trending_daily["data"]:
        buckets = [d["bucket"] for d in trending_daily["data"]]
        threat_counts = [d["threat_count"] for d in trending_daily["data"]]

        chart_data = {}
        for bucket, count in zip(buckets, threat_counts):
            chart_data[bucket] = count

        st.bar_chart(chart_data)
    else:
        st.info("No threat data available")

with tab3:
    trending_daily = get_kpi_trending(interval="daily", days=7)
    if trending_daily["data"]:
        buckets = [d["bucket"] for d in trending_daily["data"]]
        threat_rates = []
        for d in trending_daily["data"]:
            if d["scan_count"] > 0:
                rate = (d["threat_count"] / d["scan_count"]) * 100
            else:
                rate = 0
            threat_rates.append(rate)

        chart_data = {}
        for bucket, rate in zip(buckets, threat_rates):
            chart_data[bucket] = rate

        st.line_chart(chart_data)
    else:
        st.info("No threat rate data available")

st.markdown("---")

# ── Section 3: Threat Landscape ─────────────────────────────────────────

st.subheader("Threat Landscape")

dist_tab1, dist_tab2, dist_tab3 = st.tabs(["24h", "7 Days", "30 Days"])

for dist_tab, timerange in [(dist_tab1, "24h"), (dist_tab2, "7d"), (dist_tab3, "30d")]:
    with dist_tab:
        threat_dist = get_threat_distribution(timerange=timerange)

        col1, col2 = st.columns(2)

        with col1:
            st.write("**Verdict Distribution**")
            if threat_dist["verdicts"]:
                verdict_data = {}
                for v in threat_dist["verdicts"]:
                    verdict_data[v["verdict"]] = v["count"]
                st.bar_chart(verdict_data)
            else:
                st.text("No data")

        with col2:
            st.write("**Severity Distribution**")
            if threat_dist["severity"]:
                severity_data = {}
                for s in threat_dist["severity"]:
                    severity_data[s["severity"]] = s["count"]
                st.bar_chart(severity_data)
            else:
                st.text("No data")

st.markdown("---")

# ── Section 4: Forensic Insights ────────────────────────────────────────

st.subheader("Forensic Insights")

all_scans = get_all(limit=500)
if all_scans:
    insight_col1, insight_col2 = st.columns(2)

    with insight_col1:
        st.write("**Scans by Type**")
        type_counts = {}
        for scan in all_scans:
            scan_type = scan.get("scan_type", "unknown")
            type_counts[scan_type] = type_counts.get(scan_type, 0) + 1

        st.bar_chart(type_counts)

    with insight_col2:
        st.write("**Average Score by Type**")
        type_scores = {}
        type_counts_for_avg = {}
        for scan in all_scans:
            scan_type = scan.get("scan_type", "unknown")
            score = scan.get("score", 0)
            if scan_type not in type_scores:
                type_scores[scan_type] = 0
                type_counts_for_avg[scan_type] = 0
            type_scores[scan_type] += score
            type_counts_for_avg[scan_type] += 1

        avg_scores = {}
        for scan_type in type_scores:
            avg_scores[scan_type] = type_scores[scan_type] / type_counts_for_avg[scan_type]

        st.bar_chart(avg_scores)

st.markdown("---")

# ── Section 5: API Health Status ────────────────────────────────────────

st.subheader("API Health Status")

api_health = get_api_health_status()

health_col1, health_col2, health_col3 = st.columns(3)

with health_col1:
    availability = api_health.get("availability_pct", 0) * 100
    st.metric("API Availability", f"{availability:.1f}%")

with health_col2:
    status = api_health.get("status", "UNKNOWN")
    st.metric("Overall Status", status)

with health_col3:
    scans_sampled = api_health.get("scans_sampled", 0)
    st.metric("Scans Sampled (24h)", scans_sampled)

st.markdown("---")

# ── Section 6: Recent Activity ──────────────────────────────────────────

st.subheader("Recent Activity Feed")

recent = get_recent(limit=15)
if recent:
    st.write("**Last 15 Scans**")
    for idx, row in enumerate(recent):
        verdict = row.get("verdict", "UNKNOWN")
        score = row.get("score", 0)
        target = row.get("target", "")[:80]
        case_id = row.get("case_id", "")
        created = row.get("created_at", "")

        # Color-code by verdict
        if verdict == "MALICIOUS":
            emoji = "🔴"
        elif verdict == "SUSPICIOUS":
            emoji = "🟠"
        elif verdict == "CLEAN":
            emoji = "🟢"
        else:
            emoji = "⚪"

        st.text(f"{emoji} {case_id[:15]} | {verdict:12} | {score:5.1f}/10 | {target}")
else:
    st.info("No scans recorded yet")

st.markdown("---")

# ── Footer ──────────────────────────────────────────────────────────────

st.markdown("""
<div style="text-align: center; color: #888; margin-top: 40px; font-size: 12px;">
    <p>All charts powered by your real scan_history.db. Run more scans to populate charts with richer data.</p>
</div>
""", unsafe_allow_html=True)
