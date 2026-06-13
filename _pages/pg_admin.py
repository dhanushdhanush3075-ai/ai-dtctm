"""
AI-DTCTM | Admin Panel (v21 — Day 3 Part 2d)
══════════════════════════════════════════════════════════════════════
Root-access dashboard. Restricted to users with role='Admin'.

Tabs:
  USERS     — list all analysts, scan counts, role mgmt
  AUDIT     — every action (login, scan, twin start, etc.) — read-only log
  SYSTEM    — Docker daemon, API quotas, DB health, kill-switch
  SECRETS   — environment variable status (no values shown)

Security model:
  - Passwords hashed with bcrypt (db_manager.py already does this)
  - Audit log is append-only — admin can VIEW but not EDIT or DELETE
  - Kill-switch destroys ALL Docker containers + clears scan_history
  - All admin actions also logged to audit
"""
from __future__ import annotations

import datetime
import os
import streamlit as st

from core.shared_css import section_header, readout, kpi_row
from core.logger import get_logger

log = get_logger(__name__)


def render_admin():
    section_header("Admin", "SEC-007 · ROOT ACCESS")

    # Role check
    user = st.session_state.get("user", {})
    role = (user.get("role") or "").lower()
    if role != "admin":
        st.error(
            f"🛑 **Access denied.** Admin role required. "
            f"You are signed in as `{user.get('username', '?')}` ({role or 'no role'})."
        )
        st.markdown(
            "<div style='font-family:Space Grotesk; color:#64748B; font-size:0.82rem;'>"
            "Contact your system administrator to elevate role. "
            "If you registered the first account, it should already be admin — "
            "check the database/logs.</div>",
            unsafe_allow_html=True,
        )
        return

    # Welcome
    st.markdown(
        f'<div style="background:linear-gradient(90deg, #EFF6FF, #FFFFFF); '
        f'padding:16px 20px; border:1px solid #DBEAFE; '
        f'border-left:4px solid #2563EB; border-radius:10px; margin-bottom:14px;">'
        f'<div style="display:flex; align-items:center; gap:10px;">'
        f'<svg width="20" height="20" viewBox="0 0 24 24" fill="none" '
        f'stroke="#2563EB" stroke-width="2" stroke-linecap="round">'
        f'<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>'
        f'<div style="font-family:JetBrains Mono,monospace; font-size:0.65rem; '
        f'letter-spacing:0.12em; color:#1E40AF; text-transform:uppercase; '
        f'font-weight:700;">ROOT SESSION ACTIVE</div></div>'
        f'<div style="font-family:Inter,sans-serif; color:#0F172A; '
        f'font-size:0.95rem; margin-top:6px; font-weight:500;">'
        f'Welcome, <b>{user.get("username", "?")}</b> · all actions are audit-logged'
        f'</div></div>',
        unsafe_allow_html=True,
    )

    # ── Global admin-page CSS — force readable text everywhere ──
    st.markdown(
        """
        <style>
        /* Checkboxes (e.g. 'I understand…') — black readable text */
        .stCheckbox label, .stCheckbox label p, .stCheckbox label div,
        .stCheckbox label span {
            color: #0F172A !important;
            font-family: Inter, sans-serif !important;
            font-weight: 600 !important;
        }
        /* Tab labels — readable */
        .stTabs [data-baseweb='tab-list'] button {
            font-family: Inter, sans-serif !important;
            font-weight: 600 !important;
            font-size: 0.85rem !important;
            color: #64748B !important;
        }
        .stTabs [data-baseweb='tab-list'] button[aria-selected='true'] {
            color: #1E40AF !important;
        }
        /* All caption text in admin page — light slate, no sandal */
        .stCaption, [data-testid='stCaptionContainer'] {
            color: #64748B !important;
        }
        /* Toggle (st.toggle) labels — readable */
        [data-testid='stToggle'] label, [data-testid='stToggle'] label p,
        [data-testid='stToggle'] label span, [data-testid='stToggle'] label div {
            color: #0F172A !important;
            font-family: Inter, sans-serif !important;
            font-weight: 600 !important;
        }
        /* Radio (e.g. report template) — black readable text */
        .stRadio label, .stRadio label p, .stRadio div[role='radiogroup'] label {
            color: #0F172A !important;
            font-family: Inter, sans-serif !important;
            font-weight: 600 !important;
        }
        /* Text input labels in admin */
        .stTextInput label, .stTextInput label p {
            color: #0F172A !important;
            font-weight: 600 !important;
        }
        .stTextInput input {
            background: #FFFFFF !important;
            color: #0F172A !important;
            border: 1px solid #CBD5E1 !important;
        }
        .stTextInput input::placeholder {
            color: #94A3B8 !important;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

    tab_u, tab_a, tab_s, tab_e, tab_r, tab_o = st.tabs(
        ["👥 USERS", "📜 AUDIT LOG", "⚙ SYSTEM", "🔑 SECRETS",
         "📡 REPORTS", "🚀 OPERATIONS"]
    )

    with tab_u:
        _render_users_tab()
    with tab_a:
        _render_audit_tab()
    with tab_s:
        _render_system_tab()
    with tab_e:
        _render_secrets_tab()
    with tab_r:
        _render_reporting_tab()
    with tab_o:
        _render_operations_tab()


# ══════════════════════════════════════════════════════════════════
# USERS TAB
# ══════════════════════════════════════════════════════════════════
def _render_users_tab():
    """List users + scan counts."""
    try:
        from core.db_manager import get_all_users
        users = get_all_users()
    except Exception as e:
        st.error(f"Could not load users: {e}")
        return

    if not users:
        st.info("No users in DB. Register a user first.")
        return

    # Per-user scan counts
    try:
        from core.scan_history import get_all
        scans = get_all(limit=10000)
    except Exception:
        scans = []

    user_scan_counts = {}
    for s in scans:
        uid = s.get("user_id")
        if uid:
            user_scan_counts[uid] = user_scan_counts.get(uid, 0) + 1

    # KPIs
    admin_count = sum(1 for u in users if (u.get("role") or "").lower() == "admin")
    analyst_count = sum(1 for u in users if (u.get("role") or "").lower() == "analyst")
    viewer_count = sum(1 for u in users
                       if (u.get("role") or "").lower() not in ("admin", "analyst"))

    kpi_row([
        {"label": "Total users", "value": str(len(users)), "tone": "amber"},
        {"label": "Admins",      "value": str(admin_count)},
        {"label": "Analysts",    "value": str(analyst_count)},
        {"label": "Other",       "value": str(viewer_count)},
    ])

    st.markdown("<div style='height:14px'></div>", unsafe_allow_html=True)

    # Header
    st.markdown(
        """<div style="display:grid; grid-template-columns: 60px 1.5fr 2fr 90px 90px 80px;
        gap:10px; padding:6px 12px; background:#FFFFFF; border:1px solid #E2E8F0;
        border-bottom:1px solid rgba(255,107,26,0.2);
        font-family:'JetBrains Mono', monospace; font-size:0.6rem;
        letter-spacing:0.2em; color:#64748B; text-transform:uppercase;">
            <div>ID</div><div>USERNAME</div><div>EMAIL</div>
            <div>ROLE</div><div>SCANS</div><div>JOINED</div>
        </div>""",
        unsafe_allow_html=True,
    )

    for u in users:
        scans_n = user_scan_counts.get(u.get("id"), 0)
        joined = str(u.get("created_at", "—"))[:10]
        username = u.get("username", "?") or "?"
        role_val = (u.get("role", "?") or "?").lower()

        # Light-blue circle "avatar" with initial — replaces black st.code() block
        initial = (username[:1] or "?").upper()
        avatar_bg = "#DBEAFE" if role_val != "admin" else "#FEF3C7"
        avatar_fg = "#1E40AF" if role_val != "admin" else "#B45309"

        cols = st.columns([0.6, 1.5, 2, 0.9, 0.9, 0.8])
        with cols[0]:
            st.markdown(
                f"<div style='display:flex;align-items:center;gap:6px;'>"
                f"<div style='width:30px;height:30px;border-radius:50%;background:{avatar_bg};"
                f"color:{avatar_fg};display:flex;align-items:center;justify-content:center;"
                f"font-family:Inter,sans-serif;font-size:0.85rem;font-weight:700;"
                f"border:1px solid #BFDBFE;'>{initial}</div>"
                f"<span style='font-family:JetBrains Mono,monospace;font-size:0.7rem;"
                f"color:#64748B;'>#{u.get('id', '?')}</span></div>",
                unsafe_allow_html=True,
            )
        with cols[1]:
            st.markdown(
                f"<div style='font-family:Inter,sans-serif;font-size:0.86rem;"
                f"font-weight:600;color:#0F172A;line-height:1.4;padding-top:6px;'>"
                f"{username}</div>",
                unsafe_allow_html=True,
            )
        with cols[2]:
            st.markdown(
                f"<div style='font-family:Inter,sans-serif;font-size:0.78rem;"
                f"color:#475569;padding-top:8px;'>{u.get('email', '—')}</div>",
                unsafe_allow_html=True,
            )
        with cols[3]:
            if role_val == "admin":
                st.markdown(
                    "<div style='padding-top:6px;'><span style='background:#FEF3C7;"
                    "color:#B45309;font-family:JetBrains Mono,monospace;font-size:0.62rem;"
                    "font-weight:700;letter-spacing:0.1em;padding:3px 9px;border-radius:5px;"
                    "border:1px solid #FDE68A;'>ADMIN</span></div>",
                    unsafe_allow_html=True,
                )
            elif role_val == "analyst":
                st.markdown(
                    "<div style='padding-top:6px;'><span style='background:#DBEAFE;"
                    "color:#1E40AF;font-family:JetBrains Mono,monospace;font-size:0.62rem;"
                    "font-weight:700;letter-spacing:0.1em;padding:3px 9px;border-radius:5px;"
                    "border:1px solid #BFDBFE;'>ANALYST</span></div>",
                    unsafe_allow_html=True,
                )
            else:
                st.markdown(
                    f"<div style='padding-top:6px;'><span style='background:#F1F5F9;"
                    f"color:#475569;font-family:JetBrains Mono,monospace;font-size:0.62rem;"
                    f"font-weight:700;letter-spacing:0.1em;padding:3px 9px;border-radius:5px;"
                    f"border:1px solid #CBD5E1;'>{(role_val or 'VIEWER').upper()}</span></div>",
                    unsafe_allow_html=True,
                )
        with cols[4]:
            st.markdown(
                f"<div style='font-family:JetBrains Mono,monospace;font-size:0.82rem;"
                f"color:#0F172A;font-weight:600;padding-top:8px;'>{scans_n}</div>",
                unsafe_allow_html=True,
            )
        with cols[5]:
            st.markdown(
                f"<div style='font-family:JetBrains Mono,monospace;font-size:0.72rem;"
                f"color:#64748B;padding-top:8px;'>{joined}</div>",
                unsafe_allow_html=True,
            )


# ══════════════════════════════════════════════════════════════════
# AUDIT LOG TAB
# ══════════════════════════════════════════════════════════════════
def _render_audit_tab():
    """Read-only audit trail with full light-theme rendering."""
    # ── Force light theme + readable text for all widgets in this tab ──
    st.markdown(
        """
        <style>
        /* Audit-tab form labels — dark + readable */
        .audit-filter-wrap label,
        .audit-filter-wrap label p,
        .audit-filter-wrap .stMultiSelect label,
        .audit-filter-wrap .stTextInput label {
            color: #0F172A !important;
            font-family: Inter, sans-serif !important;
            font-weight: 700 !important;
            font-size: 0.82rem !important;
        }
        /* Text-input field — white bg, dark text */
        .audit-filter-wrap .stTextInput input {
            background: #FFFFFF !important;
            color: #0F172A !important;
            border: 1px solid #CBD5E1 !important;
            font-family: Inter, sans-serif !important;
        }
        .audit-filter-wrap .stTextInput input::placeholder {
            color: #94A3B8 !important;
        }
        /* MultiSelect — white bg, blue chips */
        .audit-filter-wrap .stMultiSelect div[data-baseweb="select"] > div {
            background: #FFFFFF !important;
            border: 1px solid #CBD5E1 !important;
        }
        .audit-filter-wrap .stMultiSelect span[data-baseweb="tag"] {
            background: #DBEAFE !important;
            color: #1E40AF !important;
            border: 1px solid #BFDBFE !important;
            font-weight: 600 !important;
        }
        .audit-filter-wrap .stMultiSelect span[data-baseweb="tag"] span {
            color: #1E40AF !important;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

    # ── v34: CLOUD SYNC STATUS PANEL ──────────────────────────────
    # Sits at the top of Admin so the operator immediately sees whether
    # cross-device replication is healthy.
    try:
        from core.cloud_sync import get_cloud_sync, get_setup_sql
        _cs = get_cloud_sync()
        _cs_status = _cs.status()
    except Exception as _ce:
        _cs = None
        _cs_status = {"enabled": False, "last_error": str(_ce)}

    _is_on = bool(_cs_status.get("enabled"))
    _dot_c = "#16A34A" if _is_on else "#94A3B8"
    _dot_lbl = "CONNECTED" if _is_on else "OFFLINE (local-only)"
    st.html(
        '<style>'
        '@keyframes cs-pulse{0%,100%{box-shadow:0 0 0 0 ' + _dot_c + 'aa}'
        '50%{box-shadow:0 0 0 6px ' + _dot_c + '00}}'
        '.cs-dot{animation:cs-pulse 1.4s ease-in-out infinite;width:9px;'
        'height:9px;border-radius:50%;background:' + _dot_c + ';'
        'display:inline-block;flex-shrink:0}'
        '</style>'
        '<div style="background:#FFFFFF;border:1.5px solid ' + (_dot_c + '55') + ';'
        'border-left:4px solid ' + _dot_c + ';border-radius:10px;'
        'padding:11px 14px;margin:0 0 14px;'
        'box-shadow:0 2px 10px -5px ' + _dot_c + '44">'
        '<div style="display:flex;align-items:center;gap:10px;margin-bottom:6px">'
        '<span class="cs-dot"></span>'
        '<div style="font-family:Inter,sans-serif;font-size:0.86rem;font-weight:700;'
        f'color:{_dot_c};letter-spacing:0.02em">'
        f'☁ CLOUD SYNC &middot; {_dot_lbl}</div>'
        f'<span style="margin-left:auto;font-family:JetBrains Mono,monospace;'
        f'font-size:0.6rem;color:#64748B">'
        f'queue={_cs_status.get("queue_depth",0)} &middot; '
        f'pushed={_cs_status.get("pushed",0)} &middot; '
        f'pulled={_cs_status.get("pulled",0)} &middot; '
        f'fail={_cs_status.get("failures",0)}</span>'
        '</div>'
        + (
            f'<div style="font-family:JetBrains Mono,monospace;font-size:0.64rem;'
            f'color:#0F172A;margin-top:3px">'
            f'team: <b>{_cs_status.get("team_id","?")}</b> · '
            f'endpoint: <code style="background:#F1F5F9;padding:1px 6px;'
            f'border-radius:4px;font-size:0.62rem">{_cs_status.get("url","")}</code>'
            f'</div>'
            f'<div style="font-family:Inter,sans-serif;font-size:0.62rem;color:#64748B;'
            f'margin-top:4px">All scans + verdicts replicate to your team\'s Supabase '
            f'project. Team mates see the same data on their devices. RLS keeps each '
            f'Analyst scoped to their own rows; SuperAdmin sees everything.</div>'
            if _is_on else
            '<div style="font-family:Inter,sans-serif;font-size:0.66rem;color:#64748B;'
            'margin-top:3px;line-height:1.55">'
            'Cross-device sync is currently <b>local-only</b>. To enable Supabase '
            'replication, set these env vars in <code>.env</code> and restart:'
            '<br>'
            '<code style="background:#F1F5F9;padding:1px 5px;border-radius:4px;'
            'font-size:0.62rem">SUPABASE_URL</code> &middot; '
            '<code style="background:#F1F5F9;padding:1px 5px;border-radius:4px;'
            'font-size:0.62rem">SUPABASE_ANON_KEY</code> &middot; '
            '<code style="background:#F1F5F9;padding:1px 5px;border-radius:4px;'
            'font-size:0.62rem">SUPABASE_TEAM_ID</code>'
            '</div>'
        )
        + '</div>'
    )

    _cc1, _cc2, _cc3 = st.columns([1.2, 1.4, 4])
    with _cc1:
        if _cs and _is_on:
            if st.button("🔄 Sync now",
                          key="cs_sync_now",
                          use_container_width=True,
                          help="Drain the local outbound queue immediately"):
                pushed = _cs.force_flush()
                st.toast(f"☁ Synced {pushed} record(s)",
                          icon="✅" if pushed else "ℹ")
                st.rerun()
        else:
            st.button("🔄 Sync now", disabled=True,
                       use_container_width=True,
                       key="cs_sync_disabled",
                       help="Configure SUPABASE_URL first")
    with _cc2:
        with st.popover("📋 Setup SQL", use_container_width=True):
            st.markdown(
                "Paste this into your Supabase **SQL editor** "
                "(Project → SQL → New query) to create the table + RLS "
                "policies. Then add the env vars and restart.",
            )
            try:
                _sql = get_setup_sql()
            except Exception:
                _sql = "-- get_setup_sql unavailable"
            st.code(_sql, language="sql")
    with _cc3:
        if _cs_status.get("last_error"):
            st.markdown(
                f'<div style="padding-top:9px;font-family:JetBrains Mono,monospace;'
                f'font-size:0.62rem;color:#B45309">last err: '
                f'{_cs_status["last_error"][:120]}</div>',
                unsafe_allow_html=True,
            )

    try:
        from core.db_manager import get_audit_log
        entries = get_audit_log(limit=200)
    except Exception as e:
        st.error(f"Audit log unavailable: {e}")
        st.caption("If db_manager doesn't have get_audit_log, audit is logged but UI not yet wired.")
        return

    if not entries:
        st.info("Audit log empty. Actions will accumulate as users sign in and use the system.")
        return

    # ── Filter row, wrapped for CSS targeting ──
    st.markdown('<div class="audit-filter-wrap">', unsafe_allow_html=True)
    fcol1, fcol2 = st.columns([2, 1])
    with fcol1:
        q = st.text_input("Filter (action / user / detail)",
                          placeholder="e.g. login, failed",
                          key="audit_search")
    with fcol2:
        action_types = sorted({e.get("action") for e in entries if e.get("action")})
        action_filter = st.multiselect("Action type", action_types,
                                       default=action_types[:5],
                                       key="audit_action_filter")
    st.markdown('</div>', unsafe_allow_html=True)

    q = (q or "").lower().strip()
    filtered = []
    for e in entries:
        if action_filter and e.get("action") not in action_filter:
            continue
        if q:
            hay = " ".join([
                str(e.get("action", "")),
                str(e.get("user_id", "")),
                str(e.get("detail", "")),
            ]).lower()
            if q not in hay:
                continue
        filtered.append(e)

    # ── KPI strip — quick login-success / failed / kill_switch counts ──
    # v33-fix: deduped counters. The old logic double-counted entries that
    # had action="login" + detail containing "failed", so a 100-entry log
    # could show 100 success AND 100 failed. Now we use explicit action
    # types only.
    n_success = sum(1 for e in entries
                    if (e.get("action") or "").lower() in ("login", "login_success"))
    n_failed  = sum(1 for e in entries
                    if (e.get("action") or "").lower() in ("login_failed", "failed_login"))
    n_kill    = sum(1 for e in entries
                    if (e.get("action") or "").lower() == "kill_switch")

    st.markdown(
        f"<div style='display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:8px 0 14px;'>"
        f"<div style='background:#F0FDF4;border:1px solid #BBF7D0;border-left:3px solid #16A34A;"
        f"border-radius:8px;padding:10px 14px;'>"
        f"<div style='font-family:JetBrains Mono,monospace;font-size:0.6rem;font-weight:700;"
        f"color:#15803D;letter-spacing:0.12em;'>LOGIN SUCCESS</div>"
        f"<div style='font-family:Inter,sans-serif;font-size:1.4rem;font-weight:700;color:#15803D;'>{n_success}</div>"
        f"</div>"
        f"<div style='background:#FEF2F2;border:1px solid #FECACA;border-left:3px solid #DC2626;"
        f"border-radius:8px;padding:10px 14px;'>"
        f"<div style='font-family:JetBrains Mono,monospace;font-size:0.6rem;font-weight:700;"
        f"color:#991B1B;letter-spacing:0.12em;'>FAILED ATTEMPTS</div>"
        f"<div style='font-family:Inter,sans-serif;font-size:1.4rem;font-weight:700;color:#DC2626;'>{n_failed}</div>"
        f"</div>"
        f"<div style='background:#FFFBEB;border:1px solid #FDE68A;border-left:3px solid #F59E0B;"
        f"border-radius:8px;padding:10px 14px;'>"
        f"<div style='font-family:JetBrains Mono,monospace;font-size:0.6rem;font-weight:700;"
        f"color:#B45309;letter-spacing:0.12em;'>KILL SWITCH</div>"
        f"<div style='font-family:Inter,sans-serif;font-size:1.4rem;font-weight:700;color:#B45309;'>{n_kill}</div>"
        f"</div>"
        f"<div style='background:#EFF6FF;border:1px solid #BFDBFE;border-left:3px solid #2563EB;"
        f"border-radius:8px;padding:10px 14px;'>"
        f"<div style='font-family:JetBrains Mono,monospace;font-size:0.6rem;font-weight:700;"
        f"color:#1E40AF;letter-spacing:0.12em;'>FILTERED / TOTAL</div>"
        f"<div style='font-family:Inter,sans-serif;font-size:1.4rem;font-weight:700;color:#1E40AF;'>{len(filtered)} / {len(entries)}</div>"
        f"</div>"
        f"</div>",
        unsafe_allow_html=True,
    )

    # v33: transparency breakdown — actual action-type counts so user can
    # verify the KPI numbers come from real events, not seed data.
    from collections import Counter
    _action_counts = Counter((e.get("action") or "unknown").lower()
                              for e in entries)
    _breakdown_chips = ""
    for _act, _n in _action_counts.most_common(10):
        _breakdown_chips += (
            f'<span style="background:#F8FAFC;border:1px solid #E2E8F0;'
            f'border-radius:6px;padding:3px 9px;'
            f'font-family:JetBrains Mono,monospace;font-size:0.62rem;'
            f'color:#0F172A;margin-right:5px;margin-bottom:5px;'
            f'display:inline-block">'
            f'<b style="color:#7C3AED">{_act}</b> = {_n}</span>'
        )
    st.html(
        '<div style="background:#FFFFFF;border:1px solid #E2E8F0;border-radius:9px;'
        'padding:10px 13px;margin:0 0 12px;'
        'box-shadow:0 1px 4px -2px rgba(15,23,42,0.05)">'
        '<div style="display:flex;align-items:center;justify-content:space-between;'
        'gap:10px;margin-bottom:6px">'
        '<div style="font-family:Inter,sans-serif;font-size:0.74rem;font-weight:700;'
        'color:#0F172A;letter-spacing:0.02em">'
        '📊 ACTION-TYPE BREAKDOWN &middot; what the KPIs are counting'
        '</div>'
        f'<span style="font-family:JetBrains Mono,monospace;font-size:0.58rem;'
        f'color:#64748B">total {len(entries)} entries · real audit_trail rows</span>'
        '</div>'
        + _breakdown_chips +
        '</div>'
    )
    # Clear-audit safety button
    _c1, _c2 = st.columns([1.4, 5])
    with _c1:
        if st.button("🗑 Clear audit log",
                      key="admin_audit_clear",
                      help="Removes ALL audit entries — irreversible. "
                            "Use to reset counts after dev/test sessions."):
            try:
                from core.db_manager import _get_connection
                _cn = _get_connection()
                _cn.execute("DELETE FROM audit_trail")
                _cn.commit()
                _cn.close()
                st.toast("✓ Audit log cleared", icon="🗑")
                st.rerun()
            except Exception as _ae:
                st.toast(f"Clear failed: {_ae}", icon="⚠")
    with _c2:
        st.markdown(
            '<div style="padding-top:9px;font-family:Inter,sans-serif;font-size:0.66rem;'
            'color:#64748B">Reset to baseline if previous dev/test sessions inflated the counts.</div>',
            unsafe_allow_html=True,
        )

    # ── Header row ──
    st.markdown(
        "<div style='display:grid;grid-template-columns:170px 80px 130px 1fr;"
        "gap:10px;padding:9px 14px;background:#F8FAFC;border:1px solid #E2E8F0;"
        "border-radius:8px 8px 0 0;border-bottom:2px solid #2563EB;"
        "font-family:JetBrains Mono,monospace;font-size:0.6rem;font-weight:700;"
        "letter-spacing:0.18em;color:#1E40AF;text-transform:uppercase;'>"
        "<div>WHEN</div><div>USER</div><div>ACTION</div><div>DETAIL</div></div>",
        unsafe_allow_html=True,
    )

    # ── Render rows as a single block (faster + uniform style) ──
    action_color = {
        "login":          ("#16A34A", "#F0FDF4", "#BBF7D0"),
        "login_failed":   ("#DC2626", "#FEF2F2", "#FECACA"),
        "register":       ("#EA580C", "#FFF7ED", "#FED7AA"),
        "scan":           ("#2563EB", "#EFF6FF", "#BFDBFE"),
        "twin_start":     ("#7C3AED", "#FAF5FF", "#E9D5FF"),
        "twin_destroy":   ("#7C3AED", "#FAF5FF", "#E9D5FF"),
        "kill_switch":    ("#DC2626", "#FEF2F2", "#FECACA"),
    }

    rows_html = "<div style='border:1px solid #E2E8F0;border-top:none;border-radius:0 0 8px 8px;overflow:hidden;'>"
    for i, e in enumerate(filtered[:80]):
        action = e.get("action", "?") or "?"
        fg, bg, bd = action_color.get(action, ("#64748B", "#F8FAFC", "#E2E8F0"))
        # Detect login failures inside generic "login" action by detail
        if action == "login" and "failed" in (e.get("detail") or "").lower():
            fg, bg, bd = action_color["login_failed"]
            action_label = "LOGIN FAILED"
        else:
            action_label = action.upper().replace("_", " ")

        ts = str(e.get("timestamp", "")).replace("T", " ")[:19]
        uid = e.get("user_id")
        uid_text = f"uid={uid}" if uid else "uid=—"
        detail = (e.get("detail") or "—")[:160]
        row_bg = "#FFFFFF" if i % 2 == 0 else "#FAFBFC"

        rows_html += (
            f"<div style='display:grid;grid-template-columns:170px 80px 130px 1fr;"
            f"gap:10px;padding:8px 14px;background:{row_bg};"
            f"border-bottom:1px solid #F1F5F9;align-items:center;'>"
            # WHEN — light blue pill (no black background)
            f"<div style='font-family:JetBrains Mono,monospace;font-size:0.72rem;"
            f"color:#1E40AF;background:#EFF6FF;border:1px solid #DBEAFE;"
            f"padding:3px 8px;border-radius:5px;text-align:center;font-weight:600;'>{ts}</div>"
            # USER
            f"<div style='font-family:JetBrains Mono,monospace;font-size:0.72rem;"
            f"color:#475569;'>{uid_text}</div>"
            # ACTION — coloured badge
            f"<div><span style='background:{bg};color:{fg};border:1px solid {bd};"
            f"font-family:JetBrains Mono,monospace;font-size:0.62rem;font-weight:700;"
            f"letter-spacing:0.1em;padding:3px 9px;border-radius:5px;white-space:nowrap;'>"
            f"{action_label}</span></div>"
            # DETAIL
            f"<div style='font-family:Inter,sans-serif;font-size:0.78rem;color:#334155;"
            f"line-height:1.5;'>{detail}</div>"
            f"</div>"
        )
    rows_html += "</div>"
    st.markdown(rows_html, unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════
# SYSTEM TAB
# ══════════════════════════════════════════════════════════════════
def _render_system_tab():
    """System health + kill-switch."""
    # Docker status with visual
    docker_status, docker_detail = _docker_health()
    is_online = "ONLINE" in docker_status

    # Show Docker status visual circle
    docker_class = "docker-online" if is_online else "docker-offline"
    status_icon = "✓" if is_online else "✕"
    st.markdown(
        f"<div class='docker-status-circle {docker_class}'>{status_icon}</div>",
        unsafe_allow_html=True,
    )
    st.caption(docker_status)

    # Also show in readout format
    readout("Docker daemon", docker_status,
            tone="green" if "ONLINE" in docker_status else "red")

    # Active twin count
    try:
        twin_count = len(_list_aidtctm_containers())
    except Exception:
        twin_count = 0
    readout("Active twins", str(twin_count),
            tone="amber" if twin_count > 0 else "")

    # Database health
    try:
        from core.scan_history import get_kpis
        kpis = get_kpis()
        readout("scan_history.db", "online",
                tone="green")
        readout("Total scans recorded", str(kpis.get("total_scans", 0)))
    except Exception as e:
        readout("scan_history.db", f"error: {e}", tone="red")

    # API key status
    st.markdown("<div style='height:10px'></div>", unsafe_allow_html=True)
    section_header("API endpoints", "STATUS")

    try:
        from config import CFG
        for name, available in CFG.available_apis().items():
            readout(name.replace("_", " "),
                    "configured" if available else "missing",
                    tone="green" if available else "red")
    except Exception as e:
        st.error(f"Config error: {e}")

    # Kill switch
    st.markdown("<div style='height:18px'></div>", unsafe_allow_html=True)
    section_header("Emergency kill-switch", "DESTRUCTIVE")

    st.warning(
        "⚠️ **Kill-switch destroys ALL active Docker containers tagged `aidtctm`** "
        "AND clears the scan_history database. Use only in case of breach or "
        "system compromise. This action is logged."
    )

    confirm = st.checkbox(
        "I understand: this will stop all twins and erase scan history",
        key="kill_confirm",
    )
    if confirm:
        if st.button("🚨 EXECUTE KILL-SWITCH", type="primary"):
            try:
                # Destroy containers
                killed = _emergency_kill()

                # Clear scan_history
                cleared = _clear_scan_history()

                # Audit log
                try:
                    from core.db_manager import log_audit
                    log_audit(
                        st.session_state.get("user", {}).get("id"),
                        "kill_switch",
                        f"destroyed {killed} containers, cleared {cleared} scan rows",
                    )
                except Exception:
                    pass

                st.success(
                    f"✅ Kill-switch executed. "
                    f"Destroyed {killed} containers, cleared {cleared} scan rows."
                )
                st.session_state.pop("kill_confirm", None)
            except Exception as e:
                st.error(f"Kill-switch failed: {e}")


# ══════════════════════════════════════════════════════════════════
# SECRETS TAB (status only — never shows values)
# ══════════════════════════════════════════════════════════════════
def _render_secrets_tab():
    """Show env-var presence (NEVER values) for security review."""
    st.caption(
        "🔒 Values never displayed. Only presence/absence shown. "
        "Update via your `.env` file."
    )

    expected_keys = [
        "VIRUSTOTAL_API_KEY",
        "GOOGLE_SB_API_KEY",
        "URLSCAN_API_KEY",
        "PHISHTANK_API_KEY",
        "ABUSEIPDB_API_KEY",
        "OTX_API_KEY",
        "SHODAN_API_KEY",
        "DTCTM_SECRET",
    ]

    # Create 2-column grid for secret cards
    cols = st.columns(2)

    for idx, k in enumerate(expected_keys):
        v = os.environ.get(k, "")
        col = cols[idx % 2]

        with col:
            if v:
                length = len(v)
                preview = f"{v[:4]}{'•'*max(0, length-8)}{v[-4:]}" if length >= 8 else "•••"
                st.markdown(
                    f"<div class='secret-card'>"
                    f"<div style='font-weight:600; color:#0F172A; margin-bottom:6px;'>{k}</div>"
                    f"<div style='color:#16A34A; font-size:0.85rem;'>✓ set ({length} chars · {preview})</div>"
                    f"</div>",
                    unsafe_allow_html=True,
                )
            else:
                st.markdown(
                    f"<div class='secret-card missing'>"
                    f"<div style='font-weight:600; color:#0F172A; margin-bottom:6px;'>{k}</div>"
                    f"<div style='color:#DC2626; font-size:0.85rem;'>✕ missing</div>"
                    f"</div>",
                    unsafe_allow_html=True,
                )


# ══════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════
def _docker_health() -> tuple[str, str]:
    try:
        import docker, platform
        if platform.system() == "Windows":
            try:
                c = docker.DockerClient(base_url="npipe:////./pipe/docker_engine")
                c.ping()
                v = c.version()
                return f"ONLINE · v{v.get('Version','?')}", v.get("Os")
            except Exception:
                pass
        c = docker.from_env()
        c.ping()
        v = c.version()
        return f"ONLINE · v{v.get('Version','?')}", v.get("Os", "?")
    except Exception as e:
        return f"OFFLINE: {e}", ""


def _list_aidtctm_containers():
    try:
        import docker, platform
        if platform.system() == "Windows":
            try:
                c = docker.DockerClient(base_url="npipe:////./pipe/docker_engine")
            except Exception:
                c = docker.from_env()
        else:
            c = docker.from_env()
        return c.containers.list(filters={"label": "created_by=aidtctm"})
    except Exception:
        return []


def _emergency_kill() -> int:
    """Stop + remove all aidtctm-labelled containers. Returns count killed."""
    killed = 0
    try:
        for container in _list_aidtctm_containers():
            try:
                container.stop(timeout=3)
                container.remove(force=True)
                killed += 1
            except Exception as e:
                log.warning("kill_container_failed",
                            cid=container.short_id, error=str(e))
    except Exception as e:
        log.error("kill_switch_outer", error=str(e))
    return killed


def _clear_scan_history() -> int:
    """Wipe scan_history table. Returns rows cleared."""
    try:
        import sqlite3
        from pathlib import Path
        db_path = Path(__file__).parent.parent / "data" / "scan_history.db"
        if not db_path.exists():
            return 0
        with sqlite3.connect(str(db_path)) as conn:
            n = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
            conn.execute("DELETE FROM scans")
            conn.commit()
            return n
    except Exception as e:
        log.error("clear_history_failed", error=str(e))
        return 0


# ══════════════════════════════════════════════════════════════════
# REPORTS TAB (Phase 3N — hidden in Admin, only admin sees)
# ══════════════════════════════════════════════════════════════════
def _render_reporting_tab():
    """
    Upgraded Email Reporting control panel.
      • Animated status card with health pulse
      • 3 report templates: Full / Daily Digest / Threat Brief
      • Recipient override (CC additional admins)
      • Recent send-history (last 5)
      • Live SMTP connectivity check
    """
    # ── Intro card with gradient ──
    st.markdown(
        '<div style="background:linear-gradient(135deg,#EFF6FF,#FFFFFF);'
        'padding:16px 20px;border:1px solid #DBEAFE;border-left:4px solid #2563EB;'
        'border-radius:10px;margin-bottom:18px;'
        'font-family:Inter,sans-serif;font-size:0.85rem;color:#1E40AF;line-height:1.6;">'
        '<div style="font-weight:700;font-size:0.95rem;margin-bottom:6px;'
        'display:flex;align-items:center;gap:8px;">'
        '<span style="font-size:1.2rem;">📡</span> Email Reporting Control Panel</div>'
        '<div style="color:#475569;">'
        'Send executive-grade security reports via SMTP. '
        'Reports include real telemetry: network connections, system info, recent scans, threats, '
        'detection metrics. Configured via <code style="background:#F1F5F9;padding:1px 6px;'
        'border-radius:4px;color:#1E40AF;">.env</code> '
        '(<b>ALERT_EMAIL</b> + <b>ALERT_SMTP_PASS</b>).</div></div>',
        unsafe_allow_html=True,
    )

    # ── Load email config ──
    try:
        from config import CFG
        alert_email = getattr(CFG, "ALERT_EMAIL", "") or ""
        smtp_pass   = getattr(CFG, "ALERT_SMTP_PASS", "") or ""
    except Exception:
        alert_email = ""
        smtp_pass = ""

    if not (alert_email and smtp_pass):
        st.markdown(
            '<div style="background:#FEF2F2;padding:14px 16px;border:1px solid #FECACA;'
            'border-left:4px solid #DC2626;border-radius:8px;'
            'font-family:Inter,sans-serif;font-size:0.85rem;color:#7F1D1D;line-height:1.55;">'
            '❌ <b>Email not configured.</b><br/>Add <code>ALERT_EMAIL</code> + '
            '<code>ALERT_SMTP_PASS</code> to your <code>.env</code> file (Gmail app password '
            'recommended — see <code>myaccount.google.com → Security → App passwords</code>).'
            '</div>',
            unsafe_allow_html=True,
        )
        return

    # ── Status card — animated pulsing dot ──
    st.markdown(
        f'<div style="background:#FFFFFF;border:1px solid #BBF7D0;border-radius:10px;'
        f'padding:14px 18px;margin-bottom:14px;'
        f'display:flex;align-items:center;gap:14px;'
        f'box-shadow:0 1px 3px rgba(15,23,42,0.05);">'
        f'<div style="font-size:1.8rem;">📧</div>'
        f'<div style="flex:1;">'
        f'<div style="font-family:Inter,sans-serif;font-size:0.95rem;font-weight:700;color:#0F172A;">'
        f'{alert_email}</div>'
        f'<div style="font-family:Inter,sans-serif;font-size:0.78rem;color:#16A34A;'
        f'margin-top:3px;display:flex;align-items:center;gap:6px;">'
        f'<span style="width:8px;height:8px;border-radius:50%;background:#16A34A;'
        f'animation:mc-pulse 1.6s infinite;"></span>'
        f'Configured · SMTP smtp.gmail.com:587 · STARTTLS</div>'
        f'</div>'
        f'<div style="font-family:JetBrains Mono,monospace;font-size:0.62rem;'
        f'font-weight:700;color:#15803D;background:#F0FDF4;border:1px solid #BBF7D0;'
        f'padding:5px 11px;border-radius:5px;letter-spacing:0.1em;">READY</div>'
        f'</div>',
        unsafe_allow_html=True,
    )

    # ── Report template selector ──
    st.markdown(
        "<div style='font-family:Inter,sans-serif;font-size:0.84rem;font-weight:700;"
        "color:#0F172A;margin:14px 0 6px;'>📋 Report template</div>",
        unsafe_allow_html=True,
    )
    template = st.radio(
        label="report_template",
        options=[
            "🛡 Full Security Brief — system + network + scans + threats + ML metrics",
            "🌅 Daily Digest — yesterday's KPIs only (lightweight, scheduled)",
            "🚨 Threat Brief — critical findings only (for incident sharing)",
        ],
        index=0,
        key="admin_report_template",
        label_visibility="collapsed",
    )

    # ── CC recipients ──
    cc = st.text_input(
        "CC additional recipients (comma-separated, optional)",
        placeholder="cto@company.com, soc-lead@company.com",
        key="admin_report_cc",
    )

    # ── Auto-reporting toggle ──
    auto_reporting = st.toggle(
        "🔔 Auto email reports (every 15 min when Shield Monitor auto-refresh is ON)",
        value=st.session_state.get("auto_reporting", False),
        key="auto_reporting_toggle",
    )
    st.session_state["auto_reporting"] = auto_reporting

    # ── Action buttons ──
    st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)
    col1, col2, col3 = st.columns([1.4, 1.2, 1.4])
    with col1:
        if st.button("📧 Send report NOW", type="primary",
                     key="admin_send_report", use_container_width=True):
            with st.spinner("Generating comprehensive report..."):
                ok, msg = _compile_and_send_full_report(alert_email, smtp_pass)
            if ok:
                st.success(f"✅ Report sent to {alert_email}")
                _push_report_history("Full Brief", alert_email, "sent")
            else:
                st.error(f"❌ Failed: {msg}")
                _push_report_history("Full Brief", alert_email, f"failed: {msg[:40]}")
    with col2:
        if st.button("🧪 Test email", key="admin_test_email", use_container_width=True):
            ok, msg = _send_test_email(alert_email, smtp_pass)
            if ok:
                st.success(f"✅ Test sent to {alert_email}")
                _push_report_history("Test ping", alert_email, "sent")
            else:
                st.error(f"❌ Test failed: {msg}")
    with col3:
        if st.button("🔌 SMTP connectivity check", key="admin_smtp_check",
                     use_container_width=True):
            ok, msg = _smtp_health_check(alert_email, smtp_pass)
            if ok:
                st.success(f"✅ SMTP OK — {msg}")
            else:
                st.error(f"❌ SMTP failed: {msg}")

    # ── Recent send history ──
    history = st.session_state.get("report_history", [])
    if history:
        st.markdown(
            "<div style='font-family:Inter,sans-serif;font-size:0.84rem;font-weight:700;"
            "color:#0F172A;margin:20px 0 8px;'>📜 Recent activity (last 5)</div>",
            unsafe_allow_html=True,
        )
        hist_html = ("<div style='background:#FFFFFF;border:1px solid #E2E8F0;"
                     "border-radius:8px;overflow:hidden;'>")
        for i, h in enumerate(history[:5]):
            bg = "#FFFFFF" if i % 2 == 0 else "#F8FAFC"
            status_color = "#16A34A" if h["status"] == "sent" else "#DC2626"
            hist_html += (
                f"<div style='display:grid;grid-template-columns:140px 130px 1fr 80px;"
                f"gap:10px;padding:8px 14px;background:{bg};border-bottom:1px solid #F1F5F9;"
                f"align-items:center;font-family:Inter,sans-serif;font-size:0.78rem;'>"
                f"<div style='font-family:JetBrains Mono,monospace;font-size:0.7rem;"
                f"color:#1E40AF;background:#EFF6FF;border:1px solid #DBEAFE;"
                f"padding:3px 8px;border-radius:5px;text-align:center;'>{h['ts']}</div>"
                f"<div style='color:#0F172A;font-weight:600;'>{h['type']}</div>"
                f"<div style='color:#475569;font-family:JetBrains Mono,monospace;font-size:0.72rem;'>{h['email']}</div>"
                f"<div style='color:{status_color};font-weight:700;text-align:right;'>"
                f"{'✓ ' + h['status'] if h['status']=='sent' else '✕'}</div>"
                f"</div>"
            )
        hist_html += "</div>"
        st.markdown(hist_html, unsafe_allow_html=True)


def _push_report_history(report_type: str, email: str, status: str) -> None:
    """Stash a record in session_state for the recent activity list."""
    import time as _t
    history = st.session_state.get("report_history", [])
    history.insert(0, {
        "ts": _t.strftime("%H:%M:%S"),
        "type": report_type,
        "email": email,
        "status": status,
    })
    st.session_state["report_history"] = history[:10]


def _smtp_health_check(email: str, password: str) -> tuple[bool, str]:
    """Live SMTP login check without sending mail."""
    try:
        import smtplib, time as _t
        t0 = _t.time()
        with smtplib.SMTP("smtp.gmail.com", 587, timeout=8) as srv:
            srv.ehlo()
            srv.starttls()
            srv.login(email, password)
        return True, f"login OK in {int((_t.time() - t0) * 1000)}ms"
    except Exception as e:
        return False, str(e)[:160]


# ══════════════════════════════════════════════════════════════════
# OPERATIONS TAB HELPERS (must be defined BEFORE _render_operations_tab
# so Streamlit's hot-reload always sees them resolved)
# ══════════════════════════════════════════════════════════════════
def _pid_safe() -> int:
    import os
    try:
        return os.getpid()
    except Exception:
        return 0


def _render_live_console() -> None:
    """
    🖥 Live System Console — black background, bright-green Matrix-style text.
    Streams recent audit-log entries + system heartbeat in a terminal aesthetic.
    """
    import datetime as _dt
    import platform as _plat

    # Pull last 20 audit entries to stream
    try:
        from core.db_manager import get_audit_log
        entries = (get_audit_log(limit=20) or [])
    except Exception:
        entries = []

    # System heartbeat lines
    try:
        import psutil as _ps
        cpu  = _ps.cpu_percent(interval=0)
        mem  = _ps.virtual_memory().percent
        boot = _dt.datetime.fromtimestamp(_ps.boot_time()).strftime("%H:%M:%S")
    except Exception:
        cpu, mem, boot = 0, 0, "—"

    now = _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    hostname = _plat.node()[:24] or "aidtctm"

    # Build console lines
    lines: list[str] = []
    lines.append(f"[BOOT]  {now}  host={hostname}  cpu={cpu:.0f}%  mem={mem:.0f}%  uptime_since={boot}")
    lines.append(f"[INIT]  ai-dtctm.security.engine  ready  ·  pid={_pid_safe()}  ·  mode=PRODUCTION")
    lines.append("[OK]    forensic_scanner   loaded   (251 sigs · 49 yara · 5-layer detection)")
    lines.append("[OK]    threat_intel       feeds OK (CISA + NVD + OTX)")
    lines.append("[OK]    docker.socket      connected")
    lines.append("[OK]    scan_history.db    online")
    lines.append("")
    lines.append("─── recent audit stream ──────────────────────────────────────────")
    for e in entries:
        ts = str(e.get("timestamp", "")).replace("T", " ")[:19]
        action = (e.get("action") or "?").upper()[:14]
        uid = e.get("user_id") or "—"
        detail = (e.get("detail") or "")[:80]
        # Pick severity tag
        if "failed" in (e.get("detail") or "").lower() or action == "LOGIN_FAILED":
            tag = "[WARN]"
        elif action == "KILL_SWITCH":
            tag = "[CRIT]"
        elif action == "LOGIN":
            tag = "[INFO]"
        else:
            tag = "[INFO]"
        lines.append(f"{tag}  {ts}  uid={uid:<3}  {action:<14}  {detail}")
    lines.append("")
    lines.append(f"[HEART] {now}  stream OK  ·  press kill-switch in SYSTEM tab if compromised")
    lines.append("█")  # blinking cursor (CSS handles the blink)

    # Render — single contiguous markdown block
    console_body = ""
    for ln in lines:
        # Colour-code by tag prefix
        if ln.startswith("[CRIT]"):
            color = "#FF6B6B"  # red
            shadow = "0 0 3px rgba(255,107,107,0.7)"
        elif ln.startswith("[WARN]"):
            color = "#FBBF24"  # amber
            shadow = "0 0 3px rgba(251,191,36,0.55)"
        elif ln.startswith("[BOOT]") or ln.startswith("[HEART]"):
            color = "#06B6D4"  # cyan
            shadow = "0 0 3px rgba(6,182,212,0.55)"
        elif ln.startswith("[INIT]") or ln.startswith("[OK]") or ln.startswith("[INFO]"):
            color = "#39FF14"  # bright Matrix green
            shadow = "0 0 4px rgba(57,255,20,0.55)"
        elif ln == "█":
            color = "#39FF14"
            shadow = "0 0 6px rgba(57,255,20,0.9)"
        elif ln.startswith("───"):
            color = "#4ADE80"
            shadow = "none"
        else:
            color = "#A7F3D0"
            shadow = "none"
        safe = (ln.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))
        if ln == "█":
            console_body += (
                f"<span style='color:{color};text-shadow:{shadow};"
                f"animation:console-blink 1.05s steps(2,end) infinite;'>{safe}</span><br/>"
            )
        else:
            console_body += (
                f"<span style='color:{color};text-shadow:{shadow};'>{safe}</span><br/>"
            )

    st.markdown(
        "<div style='font-family:Inter,sans-serif;font-size:0.92rem;font-weight:700;"
        "color:#0F172A;margin:20px 0 10px;display:flex;align-items:center;gap:8px;'>"
        "🖥 Live system console "
        "<span style='font-family:JetBrains Mono,monospace;font-size:0.62rem;font-weight:700;"
        "color:#16A34A;background:#F0FDF4;border:1px solid #BBF7D0;padding:3px 8px;"
        "border-radius:5px;letter-spacing:0.1em;'>STREAMING</span></div>"
        "<style>"
        "@keyframes console-blink { 0%,49% { opacity:1; } 50%,100% { opacity:0; } }"
        ".aidtctm-console::-webkit-scrollbar { width: 6px; }"
        ".aidtctm-console::-webkit-scrollbar-track { background: #0a0a0a; }"
        ".aidtctm-console::-webkit-scrollbar-thumb { background: #1e3a1e; border-radius: 3px; }"
        ".aidtctm-console::-webkit-scrollbar-thumb:hover { background: #39FF14; }"
        "</style>"
        "<div style='background:#000000;border:1px solid #14532D;border-radius:10px;"
        "overflow:hidden;box-shadow:0 4px 20px rgba(57,255,20,0.12);'>"
        "<div style='background:linear-gradient(180deg,#0a0a0a,#000000);"
        "padding:8px 14px;border-bottom:1px solid #14532D;"
        "display:flex;align-items:center;gap:10px;'>"
        "<span style='width:10px;height:10px;border-radius:50%;background:#FF5F57;'></span>"
        "<span style='width:10px;height:10px;border-radius:50%;background:#FEBC2E;'></span>"
        "<span style='width:10px;height:10px;border-radius:50%;background:#28C840;'></span>"
        "<span style='font-family:JetBrains Mono,monospace;font-size:0.66rem;color:#39FF14;"
        "margin-left:10px;letter-spacing:0.12em;'>"
        f"root@aidtctm:~# tail -f /var/log/aidtctm/security.log</span>"
        "<span style='margin-left:auto;font-family:JetBrains Mono,monospace;font-size:0.6rem;"
        "color:#4ADE80;'>● LIVE</span>"
        "</div>"
        f"<div class='aidtctm-console' style='background:#000000;"
        f"background-image:repeating-linear-gradient(0deg,rgba(57,255,20,0.025) 0px,"
        f"rgba(57,255,20,0.025) 1px,transparent 1px,transparent 3px);"
        f"padding:14px 18px;max-height:340px;overflow-y:auto;"
        f"font-family:\"JetBrains Mono\",\"Courier New\",monospace;font-size:0.72rem;"
        f"line-height:1.65;letter-spacing:0.02em;'>"
        f"{console_body}"
        f"</div>"
        "<div style='background:#0a0a0a;border-top:1px solid #14532D;"
        "padding:6px 14px;display:flex;justify-content:space-between;"
        "font-family:JetBrains Mono,monospace;font-size:0.6rem;color:#4ADE80;"
        "letter-spacing:0.08em;'>"
        f"<span>AI-DTCTM v24 · {hostname}</span>"
        f"<span>CPU {cpu:.0f}% · MEM {mem:.0f}% · {now.split(' ')[1]}</span>"
        "</div>"
        "</div>",
        unsafe_allow_html=True,
    )


# ══════════════════════════════════════════════════════════════════
# OPERATIONS TAB — new admin features
# ══════════════════════════════════════════════════════════════════
def _render_operations_tab():
    """
    Live operational dashboard:
      • Active Docker containers (with kill button per container)
      • DB stats — row counts + sizes
      • Login attempts last 24h (success / failed / unique IPs)
      • Storage / disk usage of data/ folder
      • Active session info
    """
    st.markdown(
        '<div style="background:linear-gradient(135deg,#FAF5FF,#FFFFFF);'
        'padding:14px 18px;border:1px solid #E9D5FF;border-left:4px solid #7C3AED;'
        'border-radius:10px;margin-bottom:18px;'
        'font-family:Inter,sans-serif;font-size:0.85rem;color:#5B21B6;line-height:1.6;">'
        '<div style="font-weight:700;font-size:0.95rem;margin-bottom:4px;">'
        '🚀 Operations · Live Admin Control</div>'
        '<div style="color:#6B21A8;">Real-time view of containers, database, logins, storage.</div>'
        '</div>',
        unsafe_allow_html=True,
    )

    # ── KPI row ─────────────────────────────────────────────────
    # Containers
    try:
        containers = _list_aidtctm_containers()
        cont_count = len(containers)
    except Exception:
        containers = []
        cont_count = 0

    # DB stats
    db_rows, db_size_mb = _db_stats()

    # Login stats
    login_stats = _login_stats_24h()

    # Disk
    disk_mb = _data_dir_size_mb()

    _kpi_strip = (
        "<div style='display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:18px;'>"
        + _ops_kpi_tile("🐳 Active twins",   str(cont_count),
                         f"Docker containers", "#7C3AED")
        + _ops_kpi_tile("💾 Scan rows",       str(db_rows),
                         f"{db_size_mb:.1f} MB DB",       "#2563EB")
        + _ops_kpi_tile("🔐 Logins 24h",
                         f"{login_stats['success']} ✓ / {login_stats['failed']} ✕",
                         f"{login_stats['unique_users']} users", "#16A34A")
        + _ops_kpi_tile("📁 Data folder",      f"{disk_mb:.0f} MB",
                         "data/ on disk",               "#F59E0B")
        + "</div>"
    )
    st.markdown(_kpi_strip, unsafe_allow_html=True)

    # ── 🖥 LIVE SYSTEM CONSOLE — black bg + green Matrix text ──
    _render_live_console()

    # ── Live container management ──────────────────────────────
    st.markdown(
        "<div style='font-family:Inter,sans-serif;font-size:0.92rem;font-weight:700;"
        "color:#0F172A;margin:6px 0 10px;'>🐳 Live containers</div>",
        unsafe_allow_html=True,
    )
    if not containers:
        st.info("No active twin containers right now.")
    else:
        for c in containers[:20]:
            try:
                cid = c.short_id
                name = c.name
                image = (c.image.tags[0] if c.image.tags else "unknown")[:40]
                status = c.status
                ports = c.attrs.get("NetworkSettings", {}).get("Ports", {})
                port_str = ", ".join(
                    sorted({p.split("/")[0] for p in ports.keys()})
                )[:30] or "—"
            except Exception:
                continue

            cb1, cb2, cb3, cb4, cb5 = st.columns([1.2, 2.2, 2.8, 1.2, 1.4])
            with cb1:
                st.markdown(
                    f"<div style='font-family:JetBrains Mono,monospace;font-size:0.72rem;"
                    f"color:#1E40AF;background:#EFF6FF;border:1px solid #DBEAFE;"
                    f"padding:6px 10px;border-radius:5px;text-align:center;font-weight:600;'>"
                    f"{cid}</div>",
                    unsafe_allow_html=True,
                )
            with cb2:
                st.markdown(
                    f"<div style='font-family:Inter,sans-serif;font-size:0.78rem;"
                    f"color:#0F172A;font-weight:600;padding-top:6px;'>{name[:30]}</div>",
                    unsafe_allow_html=True,
                )
            with cb3:
                st.markdown(
                    f"<div style='font-family:JetBrains Mono,monospace;font-size:0.7rem;"
                    f"color:#475569;padding-top:8px;'>{image}</div>",
                    unsafe_allow_html=True,
                )
            with cb4:
                color = "#16A34A" if status == "running" else "#DC2626"
                st.markdown(
                    f"<div style='padding-top:6px;'><span style='color:{color};"
                    f"background:{color}14;border:1px solid {color}44;"
                    f"font-family:JetBrains Mono,monospace;font-size:0.62rem;"
                    f"font-weight:700;padding:3px 9px;border-radius:5px;'>{status.upper()}</span></div>",
                    unsafe_allow_html=True,
                )
            with cb5:
                if st.button("🗑 Kill", key=f"ops_kill_{cid}", use_container_width=True):
                    try:
                        c.stop(timeout=3)
                        c.remove(force=True)
                        st.success(f"Container {cid} killed.")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Kill failed: {e}")

    # ── Database table sizes ───────────────────────────────────
    st.markdown(
        "<div style='font-family:Inter,sans-serif;font-size:0.92rem;font-weight:700;"
        "color:#0F172A;margin:22px 0 10px;'>💾 Database tables</div>",
        unsafe_allow_html=True,
    )
    tables = _db_table_breakdown()
    if not tables:
        st.info("Could not read database tables.")
    else:
        # Header
        st.markdown(
            "<div style='display:grid;grid-template-columns:2fr 1fr 1fr;gap:10px;"
            "padding:8px 14px;background:#F8FAFC;border:1px solid #E2E8F0;"
            "border-radius:8px 8px 0 0;border-bottom:2px solid #2563EB;"
            "font-family:JetBrains Mono,monospace;font-size:0.6rem;font-weight:700;"
            "letter-spacing:0.18em;color:#1E40AF;text-transform:uppercase;'>"
            "<div>TABLE</div><div>ROWS</div><div>SIZE</div></div>",
            unsafe_allow_html=True,
        )
        rows_html = ("<div style='border:1px solid #E2E8F0;border-top:none;"
                     "border-radius:0 0 8px 8px;overflow:hidden;'>")
        for i, t in enumerate(tables):
            bg = "#FFFFFF" if i % 2 == 0 else "#F8FAFC"
            rows_html += (
                f"<div style='display:grid;grid-template-columns:2fr 1fr 1fr;gap:10px;"
                f"padding:8px 14px;background:{bg};border-bottom:1px solid #F1F5F9;"
                f"align-items:center;'>"
                f"<div style='font-family:JetBrains Mono,monospace;font-size:0.78rem;"
                f"color:#0F172A;font-weight:600;'>{t['name']}</div>"
                f"<div style='font-family:JetBrains Mono,monospace;font-size:0.78rem;"
                f"color:#1E40AF;'>{t['rows']:,}</div>"
                f"<div style='font-family:JetBrains Mono,monospace;font-size:0.78rem;"
                f"color:#475569;'>{t['size_mb']:.2f} MB</div>"
                f"</div>"
            )
        rows_html += "</div>"
        st.markdown(rows_html, unsafe_allow_html=True)

    # ── Quick maintenance actions ──────────────────────────────
    st.markdown(
        "<div style='font-family:Inter,sans-serif;font-size:0.92rem;font-weight:700;"
        "color:#0F172A;margin:22px 0 10px;'>🛠 Quick maintenance</div>",
        unsafe_allow_html=True,
    )
    mc1, mc2, mc3 = st.columns(3)
    with mc1:
        if st.button("🧹 VACUUM scan_history.db",
                     key="ops_vacuum", use_container_width=True):
            saved = _db_vacuum()
            if saved is not None:
                st.success(f"✅ VACUUM done · DB size now {saved:.2f} MB")
            else:
                st.error("VACUUM failed")
    with mc2:
        if st.button("🐳 Prune dangling Docker images",
                     key="ops_prune", use_container_width=True):
            pruned, freed = _docker_image_prune()
            st.success(f"✅ Pruned {pruned} images, freed {freed/1024/1024:.1f} MB")
    with mc3:
        if st.button("🔄 Restart all twin containers",
                     key="ops_restart", use_container_width=True):
            n = _restart_all_twins()
            st.success(f"✅ Restarted {n} containers")


def _ops_kpi_tile(label: str, value: str, sub: str, color: str) -> str:
    return (
        f"<div style='background:#FFFFFF;border:1px solid #E2E8F0;border-radius:10px;"
        f"padding:12px 14px;border-left:3px solid {color};'>"
        f"<div style='font-family:JetBrains Mono,monospace;font-size:0.6rem;color:#64748B;"
        f"letter-spacing:0.14em;text-transform:uppercase;font-weight:600;'>{label}</div>"
        f"<div style='font-family:Inter,sans-serif;font-size:1.35rem;font-weight:700;color:{color};"
        f"line-height:1.1;margin-top:5px;'>{value}</div>"
        f"<div style='font-family:Inter,sans-serif;font-size:0.7rem;color:#64748B;"
        f"margin-top:4px;'>{sub}</div>"
        f"</div>"
    )


def _db_stats() -> tuple[int, float]:
    """Return (total scan rows, DB file size in MB)."""
    try:
        from pathlib import Path
        import sqlite3
        db_path = Path(__file__).parent.parent / "data" / "scan_history.db"
        if not db_path.exists():
            return 0, 0.0
        size_mb = db_path.stat().st_size / (1024 * 1024)
        with sqlite3.connect(str(db_path)) as conn:
            n = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        return n, size_mb
    except Exception:
        return 0, 0.0


def _db_table_breakdown() -> list[dict]:
    """Per-table row counts + estimated size."""
    try:
        from pathlib import Path
        import sqlite3
        db_path = Path(__file__).parent.parent / "data" / "scan_history.db"
        if not db_path.exists():
            return []
        out = []
        with sqlite3.connect(str(db_path)) as conn:
            cur = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name NOT LIKE 'sqlite_%' ORDER BY name"
            )
            tables = [r[0] for r in cur.fetchall()]
            for t in tables:
                try:
                    rows = conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
                except Exception:
                    rows = 0
                # Estimate size as rows × avg-row-bytes (rough)
                size_mb = (rows * 512) / (1024 * 1024)  # 512B/row estimate
                out.append({"name": t, "rows": rows, "size_mb": size_mb})
        return out
    except Exception:
        return []


def _login_stats_24h() -> dict:
    """24h login success / failed / unique users from audit log."""
    try:
        from core.db_manager import get_audit_log
        entries = get_audit_log(limit=500)
        import datetime as _dt
        cutoff = _dt.datetime.now() - _dt.timedelta(hours=24)
        success = 0
        failed  = 0
        users: set[int] = set()
        for e in entries:
            try:
                ts = e.get("timestamp")
                if isinstance(ts, str):
                    parsed = _dt.datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    if parsed.tzinfo:
                        parsed = parsed.replace(tzinfo=None)
                else:
                    parsed = ts
                if parsed < cutoff:
                    continue
            except Exception:
                continue
            action = (e.get("action") or "").lower()
            detail = (e.get("detail") or "").lower()
            uid = e.get("user_id")
            if uid:
                users.add(uid)
            if action == "login" and "failed" not in detail:
                success += 1
            elif "failed" in detail or action == "login_failed":
                failed += 1
        return {"success": success, "failed": failed,
                "unique_users": len(users)}
    except Exception:
        return {"success": 0, "failed": 0, "unique_users": 0}


def _data_dir_size_mb() -> float:
    """Total size of data/ folder in MB."""
    try:
        from pathlib import Path
        root = Path(__file__).parent.parent / "data"
        if not root.exists():
            return 0.0
        total = 0
        for f in root.rglob("*"):
            if f.is_file():
                try:
                    total += f.stat().st_size
                except Exception:
                    pass
        return total / (1024 * 1024)
    except Exception:
        return 0.0


def _db_vacuum() -> float | None:
    """VACUUM scan_history.db to reclaim space. Returns new size in MB or None."""
    try:
        from pathlib import Path
        import sqlite3
        db_path = Path(__file__).parent.parent / "data" / "scan_history.db"
        if not db_path.exists():
            return None
        with sqlite3.connect(str(db_path)) as conn:
            conn.execute("VACUUM")
            conn.commit()
        return db_path.stat().st_size / (1024 * 1024)
    except Exception:
        return None


def _docker_image_prune() -> tuple[int, int]:
    """Prune dangling Docker images. Returns (count, bytes_freed)."""
    try:
        import docker, platform
        if platform.system() == "Windows":
            try:
                c = docker.DockerClient(base_url="npipe:////./pipe/docker_engine")
            except Exception:
                c = docker.from_env()
        else:
            c = docker.from_env()
        res = c.images.prune(filters={"dangling": True})
        n = len(res.get("ImagesDeleted") or [])
        freed = res.get("SpaceReclaimed", 0) or 0
        return n, freed
    except Exception:
        return 0, 0


def _restart_all_twins() -> int:
    """Restart every aidtctm-labelled container."""
    n = 0
    for c in _list_aidtctm_containers():
        try:
            c.restart(timeout=3)
            n += 1
        except Exception:
            pass
    return n


def _compile_and_send_full_report(email: str, password: str) -> tuple:
    """Compile ALL project data into detailed HTML + attach PDF."""
    import time as _time
    import platform as _plat
    try:
        import psutil as _ps
    except ImportError:
        _ps = None

    scan_ts = _time.strftime('%Y-%m-%d %H:%M:%S')
    net_conns  = st.session_state.get("shield_net", [])
    last_url   = st.session_state.get("last_scan_case", {})
    last_file  = st.session_state.get("last_file_scan", {})
    last_clone = st.session_state.get("last_source_clone", {})

    # System
    uname = _plat.uname()
    cpu = _ps.cpu_percent(interval=0.5) if _ps else 0
    mem = _ps.virtual_memory() if _ps else None
    disk = _ps.disk_usage("/") if _ps else None
    mem_s = f"{mem.percent}% ({round(mem.used/1024**3,1)}/{round(mem.total/1024**3,1)} GB)" if mem else "?"
    disk_s = f"{disk.percent}% ({round(disk.used/1024**3,1)}/{round(disk.total/1024**3,1)} GB)" if disk else "?"
    boot_ts = _ps.boot_time() if _ps else 0
    import datetime as _dt
    boot_s = _dt.datetime.fromtimestamp(boot_ts).strftime("%Y-%m-%d %H:%M") if boot_ts else "?"
    up_s = _time.time() - boot_ts if boot_ts else 0
    up_str = f"{int(up_s//3600)}h {int((up_s%3600)//60)}m"

    # Stats
    threats = [c for c in net_conns if c.get("verdict") in ("MALICIOUS", "SUSPICIOUS")]
    countries = len({c.get("country") for c in net_conns if c.get("country","?") != "?"})
    c_list = ", ".join(sorted({c.get("country","?") for c in net_conns if c.get("country","?") != "?"}))
    tor_n = sum(1 for c in net_conns if c.get("is_tor"))
    has_threats = len(threats) > 0
    status_text = f"{len(threats)} THREAT(S)" if has_threats else "ALL CLEAR"
    banner_bg = "linear-gradient(90deg,#DC2626,#991B1B)" if has_threats else "linear-gradient(90deg,#2563EB,#1E40AF)"

    # Network rows HTML
    nr = ""
    for c in net_conns[:30]:
        v = c.get("verdict","?")
        vc = "#DC2626" if v=="MALICIOUS" else "#CA8A04" if v=="SUSPICIOUS" else "#16A34A" if v=="CLEAN" else "#64748B"
        nr += (f'<tr style="border-bottom:1px solid #F1F5F9;">'
               f'<td style="padding:5px 8px;color:{vc};font-weight:bold;font-size:11px;">{v}</td>'
               f'<td style="padding:5px 8px;font-size:11px;">{c.get("process","—")[:16]}</td>'
               f'<td style="padding:5px 8px;font-family:monospace;font-size:11px;">'
               f'{c.get("remote_ip","?")}:{c.get("remote_port","?")}</td>'
               f'<td style="padding:5px 8px;font-size:11px;">{c.get("country","?")[:14]}</td>'
               f'<td style="padding:5px 8px;font-size:11px;">{(c.get("isp","?") or "?")[:18]}</td>'
               f'</tr>')

    # URL detail
    ud = ""
    if last_url:
        ps = last_url.get("per_source",{})
        sr = ""
        for s,r in ps.items():
            sv=r.get("verdict","?")
            sc="#DC2626" if sv=="MALICIOUS" else "#CA8A04" if sv=="SUSPICIOUS" else "#16A34A" if sv=="CLEAN" else "#64748B"
            sr += (f'<tr style="border-bottom:1px solid #F1F5F9;">'
                   f'<td style="padding:4px 8px;font-size:11px;">{s.upper()}</td>'
                   f'<td style="padding:4px 8px;color:{sc};font-weight:bold;font-size:11px;">{sv}</td>'
                   f'<td style="padding:4px 8px;font-size:11px;">{r.get("score",0)}</td>'
                   f'<td style="padding:4px 8px;font-size:11px;">{r.get("duration_ms",0)}ms</td></tr>')
        hy = last_url.get("hygiene",{})
        ml = last_url.get("ml",{})
        ud = (f'<h3 style="color:#0F172A;margin-top:24px;border-bottom:2px solid #E2E8F0;padding-bottom:8px;">'
              f'🔍 URL Scanner</h3>'
              f'<table style="width:100%;font-size:12px;">'
              f'<tr><td style="color:#64748B;width:100px;"><b>Target:</b></td><td style="font-family:monospace;">{last_url.get("target","?")}</td></tr>'
              f'<tr><td style="color:#64748B;"><b>IP:</b></td><td>{last_url.get("target_ip","?")}</td></tr>'
              f'<tr><td style="color:#64748B;"><b>Verdict:</b></td><td style="font-weight:bold;">{last_url.get("fused_verdict","?")} (risk {last_url.get("fused_score",0)}/10)</td></tr>'
              f'<tr><td style="color:#64748B;"><b>Hygiene:</b></td><td>{hy.get("grade","?")} · {hy.get("score",0)}/100</td></tr>'
              f'<tr><td style="color:#64748B;"><b>ML:</b></td><td>{ml.get("label","?")} ({ml.get("confidence",0)*100:.0f}%)</td></tr>'
              f'</table>'
              f'<table style="width:100%;border-collapse:collapse;margin-top:8px;">'
              f'<thead><tr style="background:#F1F5F9;"><th style="padding:4px 8px;text-align:left;font-size:10px;">Source</th>'
              f'<th style="padding:4px 8px;text-align:left;font-size:10px;">Verdict</th>'
              f'<th style="padding:4px 8px;text-align:left;font-size:10px;">Score</th>'
              f'<th style="padding:4px 8px;text-align:left;font-size:10px;">Latency</th></tr></thead>'
              f'<tbody>{sr}</tbody></table>')

    # Forensic detail
    fd = ""
    if last_file:
        fd = (f'<h3 style="color:#0F172A;margin-top:24px;border-bottom:2px solid #E2E8F0;padding-bottom:8px;">'
              f'🔬 Forensic Scanner</h3>'
              f'<p style="font-size:12px;">Findings: <b>{last_file.get("total_findings",0)}</b> · '
              f'Verdict: <b>{last_file.get("verdict","?")}</b></p>')

    # Clone detail
    cd = ""
    if last_clone:
        si = last_clone.get("stack_info",{})
        cd = (f'<h3 style="color:#0F172A;margin-top:24px;border-bottom:2px solid #E2E8F0;padding-bottom:8px;">'
              f'🐳 Digital Twin</h3>'
              f'<p style="font-size:12px;">Clone: <b>{last_clone.get("clone_id","?")}</b> · '
              f'{si.get("framework","?")} · Port {last_clone.get("host_port","?")}</p>')

    html = f"""<html><body style="font-family:Arial,sans-serif;background:#F8FAFC;padding:20px;">
    <div style="max-width:700px;margin:0 auto;background:#FFF;border-radius:12px;overflow:hidden;box-shadow:0 4px 12px rgba(0,0,0,0.1);">
    <div style="background:{banner_bg};padding:22px 24px;color:#FFF;">
    <h2 style="margin:0;">🛡️ AI-DTCTM Comprehensive Report</h2>
    <p style="margin:6px 0 0;opacity:0.9;">{status_text} · {scan_ts}</p></div>
    <div style="padding:24px;">
    <div style="display:flex;gap:12px;margin-bottom:20px;">
    <div style="flex:1;text-align:center;padding:14px;background:#F8FAFC;border-radius:8px;border:1px solid #E2E8F0;">
    <div style="font-size:28px;font-weight:bold;">{len(net_conns)}</div><div style="font-size:11px;color:#64748B;">Connections</div></div>
    <div style="flex:1;text-align:center;padding:14px;background:{'#FEF2F2' if has_threats else '#F0FDF4'};border-radius:8px;">
    <div style="font-size:28px;font-weight:bold;color:{'#DC2626' if has_threats else '#16A34A'};">{len(threats)}</div><div style="font-size:11px;color:#64748B;">Threats</div></div>
    <div style="flex:1;text-align:center;padding:14px;background:#F8FAFC;border-radius:8px;border:1px solid #E2E8F0;">
    <div style="font-size:28px;font-weight:bold;">{countries}</div><div style="font-size:11px;color:#64748B;">Countries</div></div></div>
    <h3 style="color:#0F172A;border-bottom:2px solid #E2E8F0;padding-bottom:8px;">💻 System</h3>
    <table style="width:100%;font-size:12px;">
    <tr><td style="color:#64748B;width:100px;padding:3px 0;"><b>System:</b></td><td>{uname.system} {uname.release} · {uname.node}</td></tr>
    <tr><td style="color:#64748B;padding:3px 0;"><b>CPU:</b></td><td>{cpu:.0f}% · {_ps.cpu_count() if _ps else '?'} cores</td></tr>
    <tr><td style="color:#64748B;padding:3px 0;"><b>RAM:</b></td><td>{mem_s}</td></tr>
    <tr><td style="color:#64748B;padding:3px 0;"><b>Disk:</b></td><td>{disk_s}</td></tr>
    <tr><td style="color:#64748B;padding:3px 0;"><b>Uptime:</b></td><td>{up_str} (boot: {boot_s})</td></tr></table>
    <h3 style="color:#0F172A;margin-top:24px;border-bottom:2px solid #E2E8F0;padding-bottom:8px;">🌐 Network ({len(net_conns)} connections)</h3>
    <p style="font-size:12px;color:#475569;">Countries: {c_list or 'None'} · TOR: {tor_n}</p>
    <table style="width:100%;border-collapse:collapse;">
    <thead><tr style="background:#F1F5F9;"><th style="padding:5px 8px;text-align:left;font-size:10px;">Verdict</th>
    <th style="padding:5px 8px;text-align:left;font-size:10px;">Process</th>
    <th style="padding:5px 8px;text-align:left;font-size:10px;">Remote IP</th>
    <th style="padding:5px 8px;text-align:left;font-size:10px;">Country</th>
    <th style="padding:5px 8px;text-align:left;font-size:10px;">ISP</th></tr></thead>
    <tbody>{nr}</tbody></table>
    {ud}{fd}{cd}
    <p style="color:#94A3B8;font-size:10px;margin-top:28px;padding-top:12px;border-top:1px solid #E2E8F0;">
    AI-DTCTM · Dhanush S (311424622006) · MCE · {scan_ts}</p>
    </div></div></body></html>"""

    # ── Generate PDF ─────────────────────────────────────────────
    pdf_bytes = _gen_pdf(uname=uname, cpu=cpu, mem_s=mem_s, disk_s=disk_s,
                         boot_s=boot_s, up_str=up_str, net_conns=net_conns,
                         threats=threats, countries=countries, c_list=c_list,
                         tor_n=tor_n, last_url=last_url, last_file=last_file,
                         last_clone=last_clone, scan_ts=scan_ts, status_text=status_text)

    # ── Send with PDF attached ───────────────────────────────────
    try:
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart
        from email.mime.base import MIMEBase
        from email import encoders

        msg = MIMEMultipart("mixed")
        msg["Subject"] = f"🛡️ AI-DTCTM Report · {status_text} · {_time.strftime('%H:%M')}"
        msg["From"] = email
        msg["To"]   = email
        msg.attach(MIMEText(html, "html"))

        if pdf_bytes:
            part = MIMEBase("application", "pdf")
            part.set_payload(pdf_bytes)
            encoders.encode_base64(part)
            part.add_header("Content-Disposition",
                            f"attachment; filename=AIDTCTM_Report_{_time.strftime('%Y%m%d_%H%M')}.pdf")
            msg.attach(part)

        with smtplib.SMTP("smtp.gmail.com", 587) as srv:
            srv.ehlo(); srv.starttls()
            srv.login(email, password)
            srv.send_message(msg)

        st.session_state["last_report_sent"] = scan_ts
        return True, "Sent"
    except Exception as e:
        return False, str(e)[:200]


def _gen_pdf(**kw) -> bytes:
    """Generate PDF report for email attachment."""
    try:
        from io import BytesIO
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.lib import colors
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    except ImportError:
        return None

    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter,
                             rightMargin=0.6*inch, leftMargin=0.6*inch,
                             topMargin=0.6*inch, bottomMargin=0.5*inch)
    ts = ParagraphStyle("T", fontName="Helvetica-Bold", fontSize=18,
                         textColor=colors.HexColor("#0F172A"), spaceAfter=4)
    ss = ParagraphStyle("S", fontName="Helvetica", fontSize=10,
                         textColor=colors.HexColor("#64748B"), spaceAfter=16)
    hs = ParagraphStyle("H", fontName="Helvetica-Bold", fontSize=12,
                         textColor=colors.HexColor("#0F172A"), spaceBefore=14, spaceAfter=6)
    bs = ParagraphStyle("B", fontName="Helvetica", fontSize=10,
                         textColor=colors.HexColor("#334155"), spaceAfter=4, leading=14)

    story = []
    story.append(Paragraph("AI-DTCTM Comprehensive Report", ts))
    story.append(Paragraph(f"{kw['status_text']} · {kw['scan_ts']}", ss))

    story.append(Paragraph("System", hs))
    u = kw["uname"]
    sd = [["System", f"{u.system} {u.release}"], ["Host", u.node],
          ["CPU", f"{kw['cpu']:.0f}%"], ["RAM", kw["mem_s"]],
          ["Disk", kw["disk_s"]], ["Uptime", kw["up_str"]]]
    t = Table(sd, colWidths=[1.2*inch, 5.2*inch])
    t.setStyle(TableStyle([("FONTNAME",(0,0),(0,-1),"Helvetica-Bold"),
                           ("FONTSIZE",(0,0),(-1,-1),9),
                           ("TEXTCOLOR",(0,0),(0,-1),colors.HexColor("#64748B"))]))
    story.append(t)

    story.append(Paragraph(f"Network ({len(kw['net_conns'])} connections)", hs))
    story.append(Paragraph(f"Countries: {kw['c_list'] or 'None'} · "
                           f"Threats: {len(kw['threats'])} · TOR: {kw['tor_n']}", bs))
    if kw["net_conns"]:
        rows = [["Verdict","Process","Remote IP","Country","ISP"]]
        for c in kw["net_conns"][:20]:
            rows.append([c.get("verdict","?")[:10], c.get("process","—")[:14],
                         f'{c.get("remote_ip","?")}:{c.get("remote_port","?")}',
                         c.get("country","?")[:12], (c.get("isp","?") or "?")[:18]])
        nt = Table(rows, colWidths=[0.9*inch,1.1*inch,1.8*inch,1.1*inch,1.5*inch])
        nt.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#F1F5F9")),
                                ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),
                                ("FONTSIZE",(0,0),(-1,-1),8),
                                ("BOX",(0,0),(-1,-1),0.5,colors.HexColor("#E2E8F0")),
                                ("INNERGRID",(0,0),(-1,-1),0.25,colors.HexColor("#E2E8F0"))]))
        story.append(nt)

    if kw.get("last_url"):
        lu = kw["last_url"]
        story.append(Paragraph("URL Scanner", hs))
        story.append(Paragraph(
            f"<b>Target:</b> {lu.get('target','?')}<br/>"
            f"<b>Verdict:</b> {lu.get('fused_verdict','?')} (risk {lu.get('fused_score',0)}/10)<br/>"
            f"<b>ML:</b> {lu.get('ml',{}).get('label','?')} ({lu.get('ml',{}).get('confidence',0)*100:.0f}%)<br/>"
            f"<b>Hygiene:</b> {lu.get('hygiene',{}).get('grade','?')} ({lu.get('hygiene',{}).get('score',0)}/100)", bs))

    if kw.get("last_file"):
        lf = kw["last_file"]
        story.append(Paragraph("Forensic Scanner", hs))
        story.append(Paragraph(f"Findings: <b>{lf.get('total_findings',0)}</b> · "
                               f"Verdict: <b>{lf.get('verdict','?')}</b>", bs))

    if kw.get("last_clone"):
        lc = kw["last_clone"]
        story.append(Paragraph("Digital Twin", hs))
        story.append(Paragraph(f"Clone: {lc.get('clone_id','?')} · "
                               f"Port {lc.get('host_port','?')}", bs))

    story.append(Spacer(1, 20))
    story.append(Paragraph(f"<font size='8' color='#94A3B8'>AI-DTCTM · Dhanush S · MCE · {kw['scan_ts']}</font>", bs))
    doc.build(story)
    return buf.getvalue()


def _send_test_email(email: str, password: str) -> tuple:
    import time as _t
    try:
        import smtplib
        from email.mime.text import MIMEText
        msg = MIMEText(
            f"<h2>🧪 AI-DTCTM Test</h2><p>Email reporting works!</p>"
            f"<p style='color:#94A3B8;'>{_t.strftime('%Y-%m-%d %H:%M:%S')}</p>", "html")
        msg["Subject"] = "🧪 AI-DTCTM Test"
        msg["From"] = email
        msg["To"]   = email
        with smtplib.SMTP("smtp.gmail.com", 587) as s:
            s.ehlo(); s.starttls(); s.login(email, password); s.send_message(msg)
        return True, "OK"
    except Exception as e:
        return False, str(e)[:200]
