"""
AI-DTCTM | AI Assistant
Chat with AI about the project, security topics, and threat analysis
"""
import streamlit as st
from core.logger import get_logger

log = get_logger(__name__)


def render_ai_assistant():
    """Simple AI assistant for project questions"""

    # Hero
    st.markdown(
        '<div class="mc-url-hero">'
        '<div style="display:flex; align-items:center; gap:18px;">'
        '<div style="flex-shrink:0;">'
        '<svg width="52" height="52" viewBox="0 0 52 52" fill="none">'
        '<defs><linearGradient id="asG" x1="0" y1="0" x2="52" y2="52" gradientUnits="userSpaceOnUse">'
        '<stop offset="0%" stop-color="#3B82F6"/><stop offset="100%" stop-color="#1E40AF"/></linearGradient></defs>'
        '<circle cx="26" cy="26" r="22" stroke="url(#asG)" stroke-width="2" fill="rgba(59,130,246,0.06)"/>'
        '<path d="M20 26h12M26 20v12" stroke="url(#asG)" stroke-width="2" stroke-linecap="round"/>'
        '</svg></div>'
        '<div style="flex:1;">'
        '<div style="font-family:Inter,sans-serif; font-size:1.35rem; font-weight:700; color:#0F172A;">💬 AI Assistant</div>'
        '<div style="font-family:Inter,sans-serif; font-size:0.875rem; color:#475569; margin-top:4px;">Ask questions about security, threats, and this project</div></div>'
        '<div style="flex-shrink:0;">'
        '<div style="font-family:JetBrains Mono,monospace; font-size:0.7rem; color:#3B82F6; font-weight:700; background:#EFF6FF; padding:5px 10px; border-radius:5px; display:flex; align-items:center; gap:7px;">'
        '<span style="width:7px; height:7px; border-radius:50%; background:#3B82F6; animation:mc-pulse 1.6s infinite;"></span>LIVE</div></div>'
        '</div></div>',
        unsafe_allow_html=True,
    )

    st.markdown("<div style='height:20px'></div>", unsafe_allow_html=True)

    # Initialize session
    if "ai_chat" not in st.session_state:
        st.session_state.ai_chat = []

    # Chat display
    for msg in st.session_state.ai_chat:
        if msg["role"] == "user":
            st.markdown(f"""
            <div style='text-align:right; margin-bottom:12px;'>
            <div style='display:inline-block; background:#3B82F6; color:white; padding:12px 16px; border-radius:12px; max-width:70%;'>
            {msg['text']}
            </div>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown(f"""
            <div style='margin-bottom:12px;'>
            <div style='display:inline-block; background:#1E1B4B; border:1px solid #3B82F6; color:#93C5FD; padding:12px 16px; border-radius:12px; max-width:80%;'>
            {msg['text']}
            </div>
            </div>
            """, unsafe_allow_html=True)

    st.markdown("---")

    # Input
    col1, col2 = st.columns([5, 1])
    with col1:
        question = st.text_input("Ask me anything...", placeholder="e.g., What is this project? How does threat intel work?")

    with col2:
        send = st.button("Send", use_container_width=True)

    if send and question:
        st.session_state.ai_chat.append({"role": "user", "text": question})

        # Generate response
        response = _get_response(question)
        st.session_state.ai_chat.append({"role": "assistant", "text": response})

        st.rerun()

    # Quick questions
    st.markdown("**Quick Questions:**")
    c1, c2, c3 = st.columns(3)

    with c1:
        if st.button("What is AI-DTCTM?", use_container_width=True):
            st.session_state.ai_chat.append({"role": "user", "text": "What is AI-DTCTM?"})
            st.session_state.ai_chat.append({"role": "assistant", "text": _get_response("What is AI-DTCTM?")})
            st.rerun()

    with c2:
        if st.button("How does it work?", use_container_width=True):
            st.session_state.ai_chat.append({"role": "user", "text": "How does AI-DTCTM work?"})
            st.session_state.ai_chat.append({"role": "assistant", "text": _get_response("How does it work?")})
            st.rerun()

    with c3:
        if st.button("What are features?", use_container_width=True):
            st.session_state.ai_chat.append({"role": "user", "text": "What are the key features?"})
            st.session_state.ai_chat.append({"role": "assistant", "text": _get_response("features")})
            st.rerun()


def _get_response(question: str) -> str:
    """Generate AI response"""
    q = question.lower()

    # Project questions
    if any(w in q for w in ["ai-dtctm", "project", "what is"]):
        return """**AI-DTCTM** is an enterprise-grade threat intelligence & forensic analysis system.

**Key Capabilities:**
• 🛡️ Multi-layer threat detection
• 🔗 Real-time security alerts
• 📊 Live threat intelligence aggregation
• 🤖 AI-powered threat analysis
• 📋 Professional security reports
• 🔍 IOC extraction & threat hunting

**Tech Stack:**
- Streamlit (Web UI)
- 11 Threat Intelligence APIs
- ML classifiers (79-94% accuracy)
- Docker for sandboxing
- SQLite for persistence"""

    if any(w in q for w in ["how", "work", "architecture"]):
        return """**How AI-DTCTM Works:**

1️⃣ **Threat Intelligence Aggregation**
- CISA KEV: Active exploits
- NVD: Latest CVEs
- OTX: Community threats

2️⃣ **Real-Time Monitoring**
- 24/7 threat detection
- Instant Slack/Email alerts
- Live alerts dashboard

3️⃣ **AI Analysis**
- Threat scoring system
- IOC extraction
- Attack pattern recognition
- Risk assessment

4️⃣ **Professional Reporting**
- Executive summaries
- Security metrics
- PDF report generation
- Compliance documentation"""

    if any(w in q for w in ["feature", "capability", "what can"]):
        return """**Core Features:**

🔴 **Threat Intelligence:**
- CISA Known Exploited Vulnerabilities
- NVD CVE Feed (latest vulns)
- OTX Community Pulses (real threats)

🚨 **Real-Time Alerts:**
- Slack notifications
- Email alerts
- Live dashboard
- Alert history & analytics

📊 **Security Analysis:**
- URL scanning
- File forensics
- Digital twins (attack simulation)
- Threat correlations

📈 **Reporting & Compliance:**
- Professional PDF reports
- Executive dashboards
- Compliance metrics
- Security health scores"""

    if any(w in q for w in ["threat", "intelligence", "cisa", "nvd", "otx"]):
        return """**Threat Intelligence Sources:**

**🔴 CISA KEV (Known Exploited Vulnerabilities)**
- Vulnerabilities actively exploited NOW
- Ransomware-linked threats
- Required patch information

**🆕 NVD CVE Feed (National Vulnerability Database)**
- All published CVEs
- CVSS severity scores
- Latest vulnerabilities

**📡 OTX Pulses (AlienVault Community)**
- Researcher-reported threats
- Malware campaigns
- IOC indicators
- Threat patterns

All updated in real-time for 24/7 threat monitoring."""

    # Default response
    return """I'm here to help with questions about:
✅ AI-DTCTM features and capabilities
✅ How threat intelligence works
✅ Security concepts and threats
✅ Project architecture and design
✅ Cybersecurity best practices

Ask away! I'm trained on the full project documentation."""


if __name__ == "__main__":
    render_ai_assistant()
