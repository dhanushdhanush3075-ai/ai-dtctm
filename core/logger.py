"""
AI-DTCTM | Structured Logging
════════════════════════════════════════════════════════════════════
Every print() in the codebase is replaced by a structured logger.

WHY STRUCTURED LOGS:
  - Easy to grep: `grep '"severity":"ERROR"' logs/app.log`
  - Easy to parse programmatically (jq, Splunk, ELK)
  - Shows context: timestamp, module, function, extra fields
  - Profile-aware: dev=DEBUG, demo=INFO, prod=WARNING

WHY NOT print():
  - No timestamps
  - No severity levels
  - Can't be turned off
  - Unusable in production

USAGE:
  from core.logger import get_logger
  
  log = get_logger(__name__)
  
  log.info("url_scan_started", url="http://example.com")
  log.warning("api_rate_limited", api="virustotal", retry_in=60)
  log.error("twin_creation_failed", error=str(e), traceback=True)

OUTPUT (dev):
  2026-04-19 14:22:17 [INFO ] core.url_analyzer url_scan_started url=http://example.com
OUTPUT (prod, JSON):
  {"ts":"2026-04-19T14:22:17Z","level":"INFO","module":"core.url_analyzer","event":"url_scan_started","url":"http://example.com"}
"""
from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Any

try:
    import structlog
    _HAS_STRUCTLOG = True
except ImportError:
    _HAS_STRUCTLOG = False

from config import CFG, LOGS_DIR


_configured = False


def _configure_once() -> None:
    """Configure logging on first call. Idempotent."""
    global _configured
    if _configured:
        return

    # ── Standard library logging target for stdout + rotating file ──
    log_level = getattr(logging, CFG.log_level)
    log_file = LOGS_DIR / "app.log"

    # Clear default handlers
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(log_level)

    # File handler — always JSON (for parsing later)
    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setLevel(log_level)

    # Console handler — pretty in dev, JSON in prod
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)

    if _HAS_STRUCTLOG:
        # structlog renders pretty in dev, JSON everywhere else
        shared_processors = [
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
        ]

        if CFG.is_dev:
            console_processor = structlog.dev.ConsoleRenderer(colors=True)
        else:
            console_processor = structlog.processors.JSONRenderer()

        structlog.configure(
            processors=shared_processors + [console_processor],
            wrapper_class=structlog.make_filtering_bound_logger(log_level),
            context_class=dict,
            logger_factory=structlog.PrintLoggerFactory(),
            cache_logger_on_first_use=True,
        )

        # Also wire stdlib logging handlers (for libraries that use it)
        fmt = logging.Formatter('{"ts":"%(asctime)s","level":"%(levelname)s","msg":%(message)r}')
        file_handler.setFormatter(fmt)
        console_fmt = logging.Formatter("%(asctime)s [%(levelname)-5s] %(name)s · %(message)s")
        console_handler.setFormatter(console_fmt)

    else:
        # Fallback: stdlib only
        fmt = logging.Formatter(
            "%(asctime)s [%(levelname)-5s] %(name)s · %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        file_handler.setFormatter(fmt)
        console_handler.setFormatter(fmt)

    root.addHandler(file_handler)
    root.addHandler(console_handler)

    # Quiet noisy third-party loggers
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("docker").setLevel(logging.WARNING)
    logging.getLogger("streamlit").setLevel(logging.WARNING)

    _configured = True


class _StdlibKwargShim:
    """
    Wraps a stdlib logger so callers can pass kwargs as event context
    the same way they would with structlog:

        log.info("user_login", user_id=42, ip="1.2.3.4")

    The shim renders kwargs into a "key=value" trailing string so the
    output is still human-readable without structlog installed.
    """
    __slots__ = ("_lg",)

    def __init__(self, lg: logging.Logger) -> None:
        self._lg = lg

    def _fmt(self, event: str, kwargs: dict) -> str:
        if not kwargs:
            return event
        parts = " ".join(f"{k}={v!r}" for k, v in kwargs.items())
        return f"{event} {parts}"

    def debug(self, event: str, **kw: Any) -> None:
        self._lg.debug(self._fmt(event, kw))

    def info(self, event: str, **kw: Any) -> None:
        self._lg.info(self._fmt(event, kw))

    def warning(self, event: str, **kw: Any) -> None:
        self._lg.warning(self._fmt(event, kw))

    def error(self, event: str, **kw: Any) -> None:
        self._lg.error(self._fmt(event, kw))

    def exception(self, event: str, **kw: Any) -> None:
        self._lg.exception(self._fmt(event, kw))

    def critical(self, event: str, **kw: Any) -> None:
        self._lg.critical(self._fmt(event, kw))


def get_logger(name: str = "aidtctm") -> Any:
    """
    Return a logger that accepts structlog-style kwargs.

    Uses structlog if available; otherwise wraps stdlib logging with
    a shim so the same call sites work in both cases:

        log.info("user_login", user_id=42)
    """
    _configure_once()
    if _HAS_STRUCTLOG:
        return structlog.get_logger(name)
    return _StdlibKwargShim(logging.getLogger(name))
