"""
AI-DTCTM | Local Screenshot Capture (v23 — Phase 3f)
══════════════════════════════════════════════════════════════════════
Selenium-based fallback when URLScan returns no screenshot.

Tries (in order):
  1. selenium with Chrome (headless)
  2. selenium with Edge (headless) — Windows always has Edge
  3. requests-html (limited but pure-Python)

Returns:
  - PIL Image bytes (PNG) → Streamlit can pass to st.image()
  - None on failure (UI shows graceful empty state)

Caching:
  - Each (url, day) cached on disk under data/screenshots/
  - 24h TTL — same URL on same day reuses cache
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import os
from pathlib import Path
from typing import Optional

from core.logger import get_logger

log = get_logger(__name__)

CACHE_DIR = Path(__file__).parent.parent / "data" / "screenshots"
CACHE_DIR.mkdir(parents=True, exist_ok=True)
CACHE_TTL_HOURS = 24


def _cache_key(url: str) -> Path:
    """One file per URL+day. Different days → fresh capture."""
    day = _dt.datetime.utcnow().strftime("%Y%m%d")
    h = hashlib.sha256(f"{day}:{url}".encode()).hexdigest()[:16]
    return CACHE_DIR / f"{h}.png"


def _read_cached(url: str) -> Optional[bytes]:
    p = _cache_key(url)
    if not p.exists():
        return None
    try:
        age_s = (_dt.datetime.utcnow().timestamp() - p.stat().st_mtime)
        if age_s > CACHE_TTL_HOURS * 3600:
            return None
        return p.read_bytes()
    except Exception:
        return None


def _write_cache(url: str, data: bytes) -> None:
    try:
        _cache_key(url).write_bytes(data)
    except Exception as e:
        log.warning("screenshot_cache_write_failed", error=str(e))


def capture_screenshot(url: str, timeout_s: int = 15) -> Optional[bytes]:
    """
    Capture a website screenshot.
    
    Args:
        url:        target URL (must include http:// or https://)
        timeout_s:  page load timeout
    
    Returns:
        PNG bytes, or None if capture fails for any reason.
    """
    if not url or not url.startswith(("http://", "https://")):
        return None

    # Fast cache hit
    cached = _read_cached(url)
    if cached:
        log.info("screenshot_cache_hit", url=url[:60])
        return cached

    # Try Selenium-Chrome
    img = _try_selenium("chrome", url, timeout_s)
    if img:
        _write_cache(url, img)
        return img

    # Try Selenium-Edge (Windows fallback)
    img = _try_selenium("edge", url, timeout_s)
    if img:
        _write_cache(url, img)
        return img

    log.warning("screenshot_capture_failed_all_drivers", url=url[:60])
    return None


def _try_selenium(driver_name: str, url: str, timeout_s: int) -> Optional[bytes]:
    """
    Spin up a headless browser, navigate, capture PNG.
    
    Driver auto-managed: tries `chromedriver` on PATH, falls back to
    selenium-manager if Selenium 4.6+ is installed.
    """
    try:
        from selenium import webdriver  # type: ignore
    except ImportError:
        log.info("selenium_not_installed")
        return None

    drv = None
    try:
        if driver_name == "chrome":
            from selenium.webdriver.chrome.options import Options  # type: ignore
            opts = Options()
            opts.add_argument("--headless=new")
            opts.add_argument("--no-sandbox")
            opts.add_argument("--disable-dev-shm-usage")
            opts.add_argument("--disable-gpu")
            opts.add_argument("--window-size=1280,800")
            opts.add_argument("--ignore-certificate-errors")
            opts.add_argument("--disable-extensions")
            opts.add_argument("--disable-blink-features=AutomationControlled")
            try:
                drv = webdriver.Chrome(options=opts)
            except Exception as e:
                log.info("chrome_driver_unavailable", error=str(e)[:200])
                return None

        elif driver_name == "edge":
            try:
                from selenium.webdriver.edge.options import Options as EdgeOptions  # type: ignore
            except ImportError:
                return None
            opts = EdgeOptions()
            opts.add_argument("--headless=new")
            opts.add_argument("--no-sandbox")
            opts.add_argument("--disable-gpu")
            opts.add_argument("--window-size=1280,800")
            opts.add_argument("--ignore-certificate-errors")
            try:
                drv = webdriver.Edge(options=opts)
            except Exception as e:
                log.info("edge_driver_unavailable", error=str(e)[:200])
                return None
        else:
            return None

        drv.set_page_load_timeout(timeout_s)
        drv.set_script_timeout(timeout_s)

        try:
            drv.get(url)
        except Exception as e:
            log.info("page_load_timeout_or_failed", url=url[:60],
                     error=str(e)[:120])
            # Even on timeout, try to capture whatever loaded
        # Brief settle
        import time as _t
        _t.sleep(1.2)

        png = drv.get_screenshot_as_png()
        log.info("screenshot_captured", url=url[:60], driver=driver_name,
                 bytes=len(png))
        return png

    except Exception as e:
        log.warning("selenium_capture_exception",
                    driver=driver_name, error=str(e)[:200])
        return None
    finally:
        if drv:
            try:
                drv.quit()
            except Exception:
                pass
