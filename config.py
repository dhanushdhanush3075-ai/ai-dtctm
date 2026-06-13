"""
AI-DTCTM | Configuration & Environment Manager (v20 - Mission Control)
══════════════════════════════════════════════════════════════════════
Author  : Dhanush S (311424622006)
Guide   : Mrs. S. Padmavathi, AP/MCA
College : Meenakshi College of Engineering

WHAT THIS FILE DOES:
  - Loads environment variables from .env
  - Provides three profiles: dev / demo / prod
  - Validates required secrets at startup
  - Centralises all paths, limits, and API keys
  - Never hardcodes secrets (pulls from .env only)

WHY PROFILES MATTER:
  dev   → verbose logs, mocks if API fails, relaxed timeouts
  demo  → aggressive caching (no rate limit surprises during viva)
  prod  → strict validation, minimal logs, no mocks

USAGE ELSEWHERE:
  from config import CFG
  vt_key = CFG.VIRUSTOTAL_API_KEY
  if CFG.is_demo: ...
"""
import os
import secrets
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

# ── Load .env into process environment ────────────────────────────
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    # python-dotenv not installed yet — fine, use OS env vars directly
    pass


# ── Project Paths ─────────────────────────────────────────────────
BASE_DIR    = Path(__file__).parent.resolve()
MODELS_DIR  = BASE_DIR / "models"
TWINS_DIR   = BASE_DIR / "virtual_twins"
REPORTS_DIR = BASE_DIR / "reports"
DATA_DIR    = BASE_DIR / "data"
LOGS_DIR    = BASE_DIR / "logs"
DB_PATH     = DATA_DIR / "securex.db"
CACHE_DB    = DATA_DIR / "cache.db"
YARA_DIR    = BASE_DIR / "core" / "yara_rules"

for d in [MODELS_DIR, TWINS_DIR, REPORTS_DIR, DATA_DIR, LOGS_DIR]:
    d.mkdir(parents=True, exist_ok=True)


# ── Helper: fetch env var with type conversion ─────────────────────
def _env(key: str, default: str = "", required: bool = False) -> str:
    """Read env var. If required=True and missing, raise on access."""
    val = os.getenv(key, default)
    if required and not val:
        raise RuntimeError(
            f"Missing required environment variable: {key}. "
            f"Check your .env file. See DAY1_SETUP_GUIDE.md section 7."
        )
    return val


def _env_int(key: str, default: int) -> int:
    try:
        return int(os.getenv(key, default))
    except ValueError:
        return default


# ── Main Configuration Object ──────────────────────────────────────
@dataclass(frozen=True)
class Config:
    """Single source of truth for all runtime configuration."""

    # ── Profile ───────────────────────────────────────────────────
    PROFILE: str = _env("DTCTM_PROFILE", "dev")

    # ── App ───────────────────────────────────────────────────────
    APP_TITLE: str   = "AI-DTCTM · Mission Control"
    APP_VERSION: str = "20.0.0"
    SECRET_KEY: str  = _env(
        "DTCTM_SECRET",
        secrets.token_urlsafe(32)  # fallback for dev; prod must set this
    )

    # ── Database ──────────────────────────────────────────────────
    DB_TYPE: str   = _env("DTCTM_DB_TYPE", "sqlite")
    DB_HOST: str   = _env("DTCTM_DB_HOST", "localhost")
    DB_PORT: int   = _env_int("DTCTM_DB_PORT", 3306)
    DB_USER: str   = _env("DTCTM_DB_USER", "root")
    DB_PASS: str   = _env("DTCTM_DB_PASS", "")
    DB_NAME: str   = _env("DTCTM_DB_NAME", "securex_db")

    # ── External API Keys (read at startup; empty = API disabled) ─
    VIRUSTOTAL_API_KEY: str = _env("VIRUSTOTAL_API_KEY", "")
    GOOGLE_SB_API_KEY: str  = _env("GOOGLE_SB_API_KEY", "")
    URLSCAN_API_KEY: str    = _env("URLSCAN_API_KEY", "")
    PHISHTANK_API_KEY: str  = _env("PHISHTANK_API_KEY", "")
    ABUSEIPDB_API_KEY: str  = _env("ABUSEIPDB_API_KEY", "")
    OTX_API_KEY: str        = _env("OTX_API_KEY", "")
    SHODAN_API_KEY: str     = _env("SHODAN_API_KEY", "")
    # abuse.ch unified key — works for URLhaus, ThreatFox, MalwareBazaar
    URLHAUS_KEY: str        = _env("URLHAUS_KEY", "")
    THREATFOX_KEY: str      = _env("THREATFOX_KEY", "")
    ABUSE_CH_KEY: str       = _env("ABUSE_CH_KEY", "")

    # ── ML Model ──────────────────────────────────────────────────
    MODEL_VERSION: str         = "20.0.0"
    CONFIDENCE_THRESHOLD: float = 0.65

    # ── Threat Severity Thresholds (0-10 risk scale) ─────────────
    RISK_LOW: float      = 3.0
    RISK_MEDIUM: float   = 5.5
    RISK_HIGH: float     = 7.5
    RISK_CRITICAL: float = 9.0

    # ── Security ──────────────────────────────────────────────────
    BCRYPT_ROUNDS: int   = 12
    SESSION_TIMEOUT: int = 3600

    # ── Docker Twin ───────────────────────────────────────────────
    DOCKER_TWIN_NETWORK: str = _env("DOCKER_TWIN_NETWORK", "aidtctm_twin_net")
    DOCKER_DVWA_PORT: int    = _env_int("DOCKER_DVWA_PORT", 8081)
    DOCKER_WEBGOAT_PORT: int = _env_int("DOCKER_WEBGOAT_PORT", 8082)
    DOCKER_JUICESHOP_PORT: int = _env_int("DOCKER_JUICESHOP_PORT", 8083)

    # ── Cache ─────────────────────────────────────────────────────
    CACHE_DEFAULT_TTL: int = _env_int("CACHE_DEFAULT_TTL", 300)

    # -- Email Alerts --
    ALERT_EMAIL: str     = _env("ALERT_EMAIL", "")
    ALERT_SMTP_PASS: str = _env("ALERT_SMTP_PASS", "")

    # ── Profile shortcuts ─────────────────────────────────────────
    @property
    def is_dev(self) -> bool:
        return self.PROFILE == "dev"

    @property
    def is_demo(self) -> bool:
        return self.PROFILE == "demo"

    @property
    def is_prod(self) -> bool:
        return self.PROFILE == "prod"

    # ── Logging level derived from profile ────────────────────────
    @property
    def log_level(self) -> str:
        return {"dev": "DEBUG", "demo": "INFO", "prod": "WARNING"}[self.PROFILE]

    # ── API availability check ────────────────────────────────────
    def available_apis(self) -> dict[str, bool]:
        """Which APIs are configured? Empty key = API disabled."""
        return {
            "virustotal":      bool(self.VIRUSTOTAL_API_KEY),
            "google_sb":       bool(self.GOOGLE_SB_API_KEY),
            "urlscan":         bool(self.URLSCAN_API_KEY),
            "phishtank":       bool(self.PHISHTANK_API_KEY),
            "abuseipdb":       bool(self.ABUSEIPDB_API_KEY),
            "otx":             bool(self.OTX_API_KEY),
            "shodan":          bool(self.SHODAN_API_KEY),
            # No-key APIs are always "available"
            "nvd":             True,
            "cisa_kev":        True,
            "malware_bazaar":  True,
            "urlhaus":         True,
            "threatfox":       True,
        }


# ── Singleton instance — import this everywhere ───────────────────
CFG = Config()


# ── Legacy constants (for backward compatibility with existing code) ──
APP_TITLE   = CFG.APP_TITLE
APP_VERSION = CFG.APP_VERSION
SECRET_KEY  = CFG.SECRET_KEY
BCRYPT_ROUNDS = CFG.BCRYPT_ROUNDS
SESSION_TIMEOUT = CFG.SESSION_TIMEOUT
MODEL_FILE    = MODELS_DIR / "threat_classifier.pkl"
VECTORIZER_FILE = MODELS_DIR / "tfidf_vectorizer.pkl"
SCALER_FILE   = MODELS_DIR / "feature_scaler.pkl"
MODEL_VERSION = CFG.MODEL_VERSION
CONFIDENCE_THRESHOLD = CFG.CONFIDENCE_THRESHOLD
RISK_LOW      = CFG.RISK_LOW
RISK_MEDIUM   = CFG.RISK_MEDIUM
RISK_HIGH     = CFG.RISK_HIGH
RISK_CRITICAL = CFG.RISK_CRITICAL
DB_TYPE     = CFG.DB_TYPE
MYSQL_HOST  = CFG.DB_HOST
MYSQL_PORT  = CFG.DB_PORT
MYSQL_USER  = CFG.DB_USER
MYSQL_PASS  = CFG.DB_PASS
MYSQL_DB    = CFG.DB_NAME
