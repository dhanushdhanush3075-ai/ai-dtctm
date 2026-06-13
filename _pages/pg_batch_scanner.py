"""
Batch Scanner Dashboard
═════════════════════════════════════════════════════════════════════
Streamlit UI for submitting and monitoring batch scanning jobs.

Features:
- Batch submission with URL/file upload
- Real-time progress monitoring
- Results analysis and export
- Job management (cancel, retry, pause)

Author: AI-DTCTM Batch Processing UI
"""

import streamlit as st
from core.batch_scanner import get_queue_manager
from core.shared_css import section_header, readout, kpi_row
from core.logger import get_logger
import json
from datetime import datetime

log = get_logger(__name__)


def render_batch_scanner_page():
    """Main batch scanner page."""
    section_header("Batch Scanner", "SEC-003 · BATCH PROCESSING")

    # Create tabs
    tab1, tab2, tab3 = st.tabs([
        "📤 Submit Batch",
        "📊 Monitor Progress",
        "📋 Results"
    ])

    with tab1:
        _render_submit_tab()

    with tab2:
        _render_monitor_tab()

    with tab3:
        _render_results_tab()


def _render_submit_tab():
    """Batch submission interface."""
    st.markdown(
        '<div style="background:#EFF6FF; padding:14px 18px; border:1px solid #DBEAFE; '
        'border-left:3px solid #2563EB; border-radius:8px; margin-bottom:16px;">'
        '📤 <b>Submit Batch</b> — Scan multiple URLs or files in one batch job.'
        '</div>',
        unsafe_allow_html=True,
    )

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("📋 Input Method")
        input_method = st.radio(
            "How to submit targets?",
            ["Paste URLs", "Upload CSV", "Paste CSV"],
            label_visibility="collapsed"
        )

    with col2:
        st.subheader("⚙️ Settings")
        priority = st.slider("Priority (1-10)", 1, 10, 5,
                           help="Higher priority scans run first")

    # Input based on method
    targets = []
    if input_method == "Paste URLs":
        targets_text = st.text_area(
            "Enter URLs (one per line)",
            placeholder="https://example.com\nhttps://example.org",
            height=150,
            label_visibility="collapsed"
        )
        targets = [t.strip() for t in targets_text.split('\n') if t.strip()]

    elif input_method == "Upload CSV":
        uploaded_file = st.file_uploader("Upload CSV file",
                                        type=['csv'],
                                        label_visibility="collapsed")
        if uploaded_file:
            try:
                import csv
                content = uploaded_file.read().decode('utf-8').split('\n')
                reader = csv.DictReader(content)
                targets = [row.get('target', row.get('url', '')) for row in reader
                          if row.get('target') or row.get('url')]
            except Exception as e:
                st.error(f"Failed to read CSV: {e}")

    else:  # Paste CSV
        csv_text = st.text_area(
            "Paste CSV content",
            placeholder="target\nhttps://example.com\nhttps://example.org",
            height=150,
            label_visibility="collapsed"
        )
        if csv_text:
            try:
                import csv
                import io
                reader = csv.DictReader(io.StringIO(csv_text))
                targets = [row.get('target', row.get('url', '')) for row in reader
                          if row.get('target') or row.get('url')]
            except Exception as e:
                st.error(f"Failed to parse CSV: {e}")

    if targets:
        st.info(f"ℹ️ Ready to scan **{len(targets)}** targets")

        batch_name = st.text_input("Batch name (optional)",
                                  value=f"batch_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                                  label_visibility="collapsed")

        col_submit, col_cancel = st.columns(2)
        with col_submit:
            if st.button("🚀 Submit Batch", type="primary", use_container_width=True):
                qm = get_queue_manager()
                batch_id = qm.enqueue(targets, batch_name, priority=priority)
                st.success(f"✅ Batch submitted! ID: `{batch_id}`")
                st.session_state['last_batch_id'] = batch_id
                log.info(f"Batch submitted: {batch_id} with {len(targets)} targets")

        with col_cancel:
            st.button("❌ Clear", use_container_width=True)


def _render_monitor_tab():
    """Progress monitoring interface."""
    st.markdown(
        '<div style="background:#EFF6FF; padding:14px 18px; border:1px solid #DBEAFE; '
        'border-left:3px solid #2563EB; border-radius:8px; margin-bottom:16px;">'
        '📊 <b>Monitor Progress</b> — Track running and completed batch jobs.'
        '</div>',
        unsafe_allow_html=True,
    )

    # Get batch ID input
    col1, col2 = st.columns([3, 1])
    with col1:
        batch_id = st.text_input(
            "Enter Batch ID to monitor",
            value=st.session_state.get('last_batch_id', ''),
            placeholder="batch_20260603_123abc45",
            label_visibility="collapsed"
        )
    with col2:
        refresh = st.button("🔄 Refresh", use_container_width=True)

    if batch_id and refresh:
        st.session_state['monitor_batch_id'] = batch_id

    # Monitor batch if ID is set
    if 'monitor_batch_id' in st.session_state:
        batch_id = st.session_state['monitor_batch_id']
        qm = get_queue_manager()
        status = qm.get_batch_status(batch_id)

        if status:
            # Show progress metrics
            cols = st.columns(4)
            with cols[0]:
                st.metric("Total Scans", status['total_scans'])
            with cols[1]:
                st.metric("Completed", status['scans_completed'])
            with cols[2]:
                st.metric("Progress", f"{status['progress_pct']:.0f}%")
            with cols[3]:
                st.metric("ETA", f"{status['eta_seconds']}s" if status['eta_seconds'] > 0 else "Done")

            # Progress bar
            st.progress(status['progress_pct'] / 100, text=f"{status['progress_pct']:.1f}% Complete")

            # Current target
            if status['current_target']:
                st.info(f"🔄 Currently scanning: `{status['current_target']}`")

            # Action buttons
            col1, col2, col3 = st.columns(3)
            with col1:
                if st.button("⏸️ Pause", use_container_width=True):
                    st.info("Pause feature coming soon")

            with col2:
                if st.button("⏸️ Cancel", use_container_width=True):
                    if qm.cancel_job(batch_id):
                        st.success("✅ Batch cancelled")
                    else:
                        st.error("❌ Failed to cancel batch")

            with col3:
                if st.button("🔄 Retry Failed", use_container_width=True):
                    count = qm.retry_failed(batch_id)
                    st.info(f"♻️ Requeued {count} failed jobs")

            # Show results so far
            if status['results']:
                st.subheader(f"📋 Results ({len(status['results'])} complete)")

                for result in status['results'][:10]:  # Show first 10
                    verdict_color = {
                        'CLEAN': '#10B981',
                        'SUSPICIOUS': '#F59E0B',
                        'MALICIOUS': '#EF4444'
                    }.get(result.get('verdict', 'UNKNOWN'), '#6B7280')

                    st.markdown(
                        f"<div style='padding:10px; background:#F8FAFC; border-left:4px solid {verdict_color}; "
                        f"margin-bottom:8px; border-radius:4px;'>"
                        f"<strong>{result.get('target')}</strong><br>"
                        f"<small>Verdict: {result.get('verdict')} • Score: {result.get('score'):.1f}</small>"
                        f"</div>",
                        unsafe_allow_html=True,
                    )
        else:
            st.error(f"❌ Batch not found: {batch_id}")


def _render_results_tab():
    """Results analysis and export."""
    st.markdown(
        '<div style="background:#EFF6FF; padding:14px 18px; border:1px solid #DBEAFE; '
        'border-left:3px solid #2563EB; border-radius:8px; margin-bottom:16px;">'
        '📋 <b>Results Analysis</b> — Analyze completed batches and export results.'
        '</div>',
        unsafe_allow_html=True,
    )

    batch_id = st.text_input(
        "Enter completed batch ID",
        placeholder="batch_20260603_123abc45",
        label_visibility="collapsed"
    )

    if batch_id:
        qm = get_queue_manager()
        status = qm.get_batch_status(batch_id)

        if status and status['scans_completed'] > 0:
            results = status['results']

            # Summary statistics
            verdicts = {}
            for r in results:
                verdict = r.get('verdict', 'UNKNOWN')
                verdicts[verdict] = verdicts.get(verdict, 0) + 1

            st.subheader("📊 Summary")
            summary_cols = st.columns(len(verdicts) + 1)

            with summary_cols[0]:
                st.metric("Total", len(results))

            for idx, (verdict, count) in enumerate(sorted(verdicts.items())):
                with summary_cols[idx + 1]:
                    st.metric(verdict, count)

            # Results table
            st.subheader("📋 All Results")

            # Prepare results for table
            table_data = []
            for r in results:
                table_data.append({
                    "Target": r.get('target', 'unknown'),
                    "Verdict": r.get('verdict', 'UNKNOWN'),
                    "Score": f"{r.get('score', 0):.2f}",
                    "Severity": r.get('severity', 'unknown'),
                    "Scan Time": f"{r.get('scan_time_ms', 0):.0f}ms"
                })

            st.dataframe(
                table_data,
                use_container_width=True,
                hide_index=True
            )

            # Export options
            st.subheader("💾 Export")
            col1, col2, col3 = st.columns(3)

            with col1:
                if st.button("📄 Export PDF", use_container_width=True):
                    st.info("PDF export feature coming soon")

            with col2:
                if st.button("📊 Export CSV", use_container_width=True):
                    import csv
                    import io

                    output = io.StringIO()
                    writer = csv.DictWriter(output, fieldnames=table_data[0].keys())
                    writer.writeheader()
                    writer.writerows(table_data)

                    st.download_button(
                        label="Download CSV",
                        data=output.getvalue(),
                        file_name=f"{batch_id}_results.csv",
                        mime="text/csv"
                    )

            with col3:
                if st.button("📋 Export JSON", use_container_width=True):
                    json_data = json.dumps(results, indent=2)
                    st.download_button(
                        label="Download JSON",
                        data=json_data,
                        file_name=f"{batch_id}_results.json",
                        mime="application/json"
                    )

        elif status:
            st.warning("⏳ Batch is still processing. Check back soon!")
        else:
            st.error(f"❌ Batch not found: {batch_id}")


# Render main page
render_batch_scanner_page()
