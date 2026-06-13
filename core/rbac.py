"""
AI-DTCTM | Role-Based Access Control Engine
============================================
3 Roles: admin / analyst / viewer
"""
import streamlit as st

# ── Permission Matrix ─────────────────────────────────────────────
PERMISSIONS = {
    "admin": {
        "scan":          True,
        "shield":        True,
        "twin":          True,
        "analytics":     True,
        "intel":         True,
        "geomap":        True,
        "compliance":    True,
        "explainer":     True,
        "compare":       True,
        "heatmap":       True,
        "zerotrust":     True,
        "maturity":      True,
        "darkweb":       True,
        "disclosure":    True,
        "executive":     True,
        "admin_panel":   True,
        "notifications": True,
        "pdf_download":  True,
        "all_users_data":True,
        "demo_mode":     True,
    },
    "analyst": {
        "scan":          True,
        "shield":        True,
        "twin":          True,
        "analytics":     True,
        "intel":         True,
        "geomap":        True,
        "compliance":    True,
        "explainer":     True,
        "compare":       True,
        "heatmap":       True,
        "zerotrust":     True,
        "maturity":      True,
        "darkweb":       True,
        "disclosure":    True,
        "executive":     False,
        "admin_panel":   False,
        "notifications": True,
        "pdf_download":  True,
        "all_users_data":False,
        "demo_mode":     True,
    },
    "viewer": {
        "scan":          False,
        "shield":        True,
        "twin":          False,
        "analytics":     True,
        "intel":         True,
        "geomap":        True,
        "compliance":    False,
        "explainer":     True,
        "compare":       True,
        "heatmap":       True,
        "zerotrust":     True,
        "maturity":      True,
        "darkweb":       False,
        "disclosure":    False,
        "executive":     False,
        "admin_panel":   False,
        "notifications": True,
        "pdf_download":  False,
        "all_users_data":False,
        "demo_mode":     False,
    },
}

ROLE_COLORS = {
    "admin":   "#f472b6",   # pink
    "analyst": "#00d4ff",   # cyan
    "viewer":  "#94a3b8",   # slate
}

ROLE_ICONS = {
    "admin":   "👑",
    "analyst": "🔍",
    "viewer":  "👁️",
}


def can(permission: str) -> bool:
    """Check if current user has a permission."""
    role = st.session_state.get("user", {}).get("role", "viewer")
    return PERMISSIONS.get(role, {}).get(permission, False)


def require(permission: str, message: str = None):
    """Block page if user lacks permission. Call at top of page."""
    if not can(permission):
        role = st.session_state.get("user", {}).get("role", "viewer")
        st.markdown(f"""
        <div style="text-align:center;padding:4rem 2rem;">
          <div style="font-size:4rem;margin-bottom:1rem;">🔒</div>
          <h2 style="font-family:'Syne',sans-serif;color:#f472b6;font-size:1.6rem;">
            Access Restricted
          </h2>
          <p style="font-family:'JetBrains Mono',monospace;color:rgba(0,212,255,0.6);
                    font-size:0.85rem;margin-top:0.5rem;">
            Your role <strong style="color:{ROLE_COLORS.get(role,'#888')}">{ROLE_ICONS.get(role,'')} {role.upper()}</strong>
            does not have access to this feature.
          </p>
          <p style="font-family:'JetBrains Mono',monospace;color:rgba(148,163,184,0.6);
                    font-size:0.75rem;margin-top:1rem;">
            {message or "Contact your administrator to request access."}
          </p>
        </div>
        """, unsafe_allow_html=True)
        st.stop()


def role_badge(role: str) -> str:
    """Return HTML badge for a role."""
    col  = ROLE_COLORS.get(role, "#888")
    icon = ROLE_ICONS.get(role, "")
    return (f'<span style="background:rgba({_hex_to_rgb(col)},0.12);'
            f'border:1px solid rgba({_hex_to_rgb(col)},0.3);'
            f'border-radius:50px;padding:3px 10px;'
            f'font-family:\'JetBrains Mono\',monospace;font-size:0.65rem;'
            f'color:{col};letter-spacing:0.1em;text-transform:uppercase;">'
            f'{icon} {role}</span>')


def _hex_to_rgb(h: str) -> str:
    h = h.lstrip('#')
    r, g, b = int(h[0:2],16), int(h[2:4],16), int(h[4:6],16)
    return f"{r},{g},{b}"
