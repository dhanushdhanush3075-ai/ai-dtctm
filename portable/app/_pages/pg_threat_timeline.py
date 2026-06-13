"""
AI-DTCTM | Threat Timeline & Correlation (Phase 1)
Native Streamlit implementation - NO external DLL dependencies.
Reconstruct attack timelines and correlate threats across scans.
"""

import streamlit as st
from datetime import datetime, timedelta
import json

from core.scan_history import get_all, get_case, record_threat_correlation

st.set_page_config(page_title="Threat Timeline", layout="wide", initial_sidebar_state="expanded")

# ── Page Header ─────────────────────────────────────────────────────────

st.markdown("""
<style>
.timeline-header {
    background: linear-gradient(135deg, #FF6B1A 0%, #FF8C42 100%);
    padding: 24px;
    border-radius: 12px;
    color: white;
    margin-bottom: 24px;
}
.timeline-header h1 {
    margin: 0;
    font-size: 32px;
    font-weight: 700;
}
.timeline-header p {
    margin: 8px 0 0 0;
    opacity: 0.9;
    font-size: 14px;
}
.threat-event {
    background: #1a1a1a;
    border-left: 4px solid;
    padding: 16px;
    margin: 8px 0;
    border-radius: 4px;
    font-size: 13px;
}
.threat-event.critical {
    border-left-color: #E63946;
    background: rgba(230, 57, 70, 0.1);
}
.threat-event.high {
    border-left-color: #FF6B1A;
    background: rgba(255, 107, 26, 0.1);
}
.threat-event.medium {
    border-left-color: #FCD34D;
    background: rgba(252, 211, 77, 0.1);
}
.threat-event.low {
    border-left-color: #93C5FD;
    background: rgba(147, 197, 253, 0.1);
}
.threat-event.clean {
    border-left-color: #22C55E;
    background: rgba(34, 197, 85, 0.1);
}
</style>

<div class="timeline-header">
    <h1>Threat Timeline & Correlation</h1>
    <p>Chronological view of detected threats with relationship mapping</p>
</div>
""", unsafe_allow_html=True)

# ── Sidebar Filters ─────────────────────────────────────────────────────

with st.sidebar:
    st.markdown("### Timeline Filters")

    timerange = st.selectbox(
        "Time Range",
        ["24h", "7d", "30d", "All"],
        index=0
    )

    verdict_filter = st.multiselect(
        "Filter by Verdict",
        ["CLEAN", "SUSPICIOUS", "MALICIOUS", "DEAD_DOMAIN"],
        default=["SUSPICIOUS", "MALICIOUS"]
    )

    scan_type_filter = st.multiselect(
        "Filter by Scan Type",
        ["url", "file", "database", "twin_attack"],
        default=None
    )

    min_score = st.slider("Minimum Risk Score", 0.0, 10.0, 0.0)

    show_details = st.checkbox("Show Full Details", value=False)

# ── Get and filter scan data ────────────────────────────────────────────

all_scans = get_all(limit=5000)

if all_scans:
    # Filter by timerange
    now = datetime.utcnow()
    if timerange == "24h":
        filter_time = now - timedelta(hours=24)
    elif timerange == "7d":
        filter_time = now - timedelta(days=7)
    elif timerange == "30d":
        filter_time = now - timedelta(days=30)
    else:
        filter_time = datetime.min

    filtered_scans = []
    for scan in all_scans:
        try:
            scan_time = datetime.fromisoformat(scan["created_at"])
        except:
            scan_time = now

        # Apply all filters
        if scan_time < filter_time:
            continue
        if verdict_filter and scan["verdict"] not in verdict_filter:
            continue
        if scan_type_filter and scan["scan_type"] not in scan_type_filter:
            continue
        if scan["score"] < min_score:
            continue

        filtered_scans.append(scan)

    # Sort by date (newest first)
    filtered_scans.sort(key=lambda x: x["created_at"], reverse=True)

    st.markdown(f"### Timeline: {len(filtered_scans)} Events")

    # ── Display timeline ────────────────────────────────────────────────

    st.markdown("#### Chronological Events")

    for idx, row in enumerate(filtered_scans):
        # Determine severity color class
        if row["score"] >= 9.0:
            severity_class = "critical"
            severity_label = "CRITICAL"
        elif row["score"] >= 7.0:
            severity_class = "high"
            severity_label = "HIGH"
        elif row["score"] >= 5.0:
            severity_class = "medium"
            severity_label = "MEDIUM"
        elif row["score"] >= 3.0:
            severity_class = "low"
            severity_label = "LOW"
        else:
            severity_class = "clean"
            severity_label = "CLEAN (by severity)"

        # Get full case details if available
        case_detail = get_case(row["case_id"])
        detail_json = json.loads(case_detail["detail_json"]) if case_detail and case_detail.get("detail_json") else {}

        # Determine emoji by verdict
        if row["verdict"] == "MALICIOUS":
            emoji = "🔴"
        elif row["verdict"] == "SUSPICIOUS":
            emoji = "🟠"
        elif row["verdict"] == "CLEAN":
            emoji = "🟢"
        else:
            emoji = "⚪"

        # Build event display
        event_html = f"""
<div class="threat-event {severity_class}">
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
        <div>
            <strong>{emoji} {row['case_id']}</strong> | {row['scan_type'].upper()}
        </div>
        <div style="font-weight: 700; color: #FF6B1A;">
            {row['score']:.1f}/10
        </div>
    </div>
    <div style="color: #aaa; margin-bottom: 8px;">
        {row['created_at']} | {row['verdict']}
    </div>
    <div style="color: #ccc; font-family: monospace; word-break: break-all; font-size: 12px;">
        {row['target'][:120]}{'...' if len(str(row['target'])) > 120 else ''}
    </div>
    {f'<div style="color: #888; font-size: 11px; margin-top: 8px;">Duration: {row["duration_ms"]:.0f}ms | IP: {row["target_ip"]}</div>' if row.get('duration_ms') or row.get('target_ip') else ''}
</div>
"""
        st.markdown(event_html, unsafe_allow_html=True)

        # Show details in expander if enabled
        if show_details:
            with st.expander(f"Details: {row['case_id'][:20]}...", expanded=False):
                if case_detail and case_detail.get("detail_json"):
                    try:
                        detail = json.loads(case_detail["detail_json"])
                        st.json(detail)
                    except:
                        st.code(case_detail["detail_json"][:500])
                else:
                    st.text(f"Target: {row['target']}")
                    st.text(f"Verdict: {row['verdict']}")
                    st.text(f"Score: {row['score']:.2f}")
                    st.text(f"Duration: {row['duration_ms']:.0f}ms")

    # ── Section: Correlation Analysis ───────────────────────────────────

    st.markdown("---")
    st.markdown("#### Threat Correlations")

    col1, col2, col3 = st.columns(3)

    with col1:
        st.markdown("**Hash-based Correlations**")
        target_counts = {}
        for scan in filtered_scans:
            target = scan["target"]
            if target:
                target_counts[target] = target_counts.get(target, 0) + 1

        duplicate_targets = {t: c for t, c in target_counts.items() if c > 1}
        if duplicate_targets:
            for target, count in sorted(duplicate_targets.items(), key=lambda x: x[1], reverse=True)[:5]:
                st.info(f"🔴 {target[:50]}... detected {count}x")
        else:
            st.text("No duplicate targets found")

    with col2:
        st.markdown("**Temporal Correlations**")
        temporal_correlations = 0
        for i in range(len(filtered_scans) - 1):
            try:
                time_diff = (
                    datetime.fromisoformat(filtered_scans[i]["created_at"]) -
                    datetime.fromisoformat(filtered_scans[i + 1]["created_at"])
                ).total_seconds()
                if time_diff < 300:  # Within 5 minutes
                    temporal_correlations += 1
            except:
                pass

        st.metric("Events within 5min", temporal_correlations)

    with col3:
        st.markdown("**Timeline Statistics**")
        if filtered_scans:
            malicious = sum(1 for s in filtered_scans if s["verdict"] == "MALICIOUS")
            suspicious = sum(1 for s in filtered_scans if s["verdict"] == "SUSPICIOUS")
            clean = sum(1 for s in filtered_scans if s["verdict"] == "CLEAN")

            st.text(f"Malicious: {malicious}")
            st.text(f"Suspicious: {suspicious}")
            st.text(f"Clean: {clean}")

else:
    st.info("No scan data available. Run some scans first!")

# ── Footer ──────────────────────────────────────────────────────────────

st.markdown("---")
st.markdown("""
<div style="text-align: center; color: #888; margin-top: 40px; font-size: 12px;">
    <p>Timeline reconstructs attack sequence for forensic analysis</p>
</div>
""", unsafe_allow_html=True)
