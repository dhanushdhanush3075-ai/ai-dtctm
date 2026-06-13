# ═══════════════════════════════════════════════════════════════════
# AI-DTCTM · Dockerfile
# Multi-stage build for a slim, secure Streamlit image
# ═══════════════════════════════════════════════════════════════════

# ── Stage 1: build ──────────────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build

# System deps for yara-python, pefile, etc.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libyara-dev \
        pkg-config \
        curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt


# ── Stage 2: runtime ────────────────────────────────────────────────
FROM python:3.11-slim

# Non-root user for security
RUN useradd --create-home --shell /bin/bash aidtctm

WORKDIR /app

# Only runtime system libs (slimmer than builder)
RUN apt-get update && apt-get install -y --no-install-recommends \
        libyara10 \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy Python packages from builder
COPY --from=builder /root/.local /home/aidtctm/.local

# Copy application source
COPY --chown=aidtctm:aidtctm . /app/

# Make sure scripts are runnable
RUN chmod +x /app/scripts/*.sh || true

USER aidtctm
ENV PATH="/home/aidtctm/.local/bin:$PATH"
ENV PYTHONUNBUFFERED=1
ENV STREAMLIT_SERVER_HEADLESS=true
ENV STREAMLIT_SERVER_PORT=8501
ENV STREAMLIT_SERVER_ADDRESS=0.0.0.0
ENV STREAMLIT_BROWSER_GATHER_USAGE_STATS=false

EXPOSE 8501

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:8501/_stcore/health || exit 1

CMD ["streamlit", "run", "main_project.py"]
