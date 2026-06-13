"""
AI-DTCTM — Production Windows Desktop Launcher (v2)
══════════════════════════════════════════════════════════════════════
Native-feeling Windows desktop wrapper around the Streamlit application.

PRODUCTION FEATURES
─────────────────
  • First-run wizard auto-creates .env + SuperAdmin bootstrap code
  • Log rotation — app.log capped at 10 MB, rolled 5 generations
  • Graceful error recovery — Streamlit crash → friendly recovery screen
  • Diagnostic mode — `launcher.py --doctor` checks install integrity
  • Per-monitor DPI awareness (no fuzzy text on 125% / 150% Windows)
  • Windows-11-style splash with smooth Fluent animations
  • Production Streamlit flags — no dev menu, no Deploy button, no telemetry
  • Edge WebView2 backend for hardware-accelerated CSS

CLI FLAGS
─────────────────
  launcher.py            normal launch
  launcher.py --doctor   run diagnostic checks then exit
  launcher.py --reset    wipe local data + .env (asks for confirmation)
"""
from __future__ import annotations

import http.client
import logging
import logging.handlers
import os
import platform
import secrets
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

# ── Configuration ──────────────────────────────────────────────────
APP_NAME      = "AI-DTCTM"
APP_VERSION   = "1.0.0"
WINDOW_TITLE  = f"{APP_NAME} — Forensic Engine"
WINDOW_W      = 1480
WINDOW_H      = 940
STREAMLIT_WAIT_TIMEOUT = 90           # seconds before we give up
LOG_MAX_BYTES = 10 * 1024 * 1024      # 10 MB cap per log
LOG_BACKUPS   = 5                     # keep 5 rotations

IS_FROZEN = getattr(sys, "frozen", False)
BASE_DIR  = Path(sys._MEIPASS) if IS_FROZEN else Path(__file__).resolve().parent
USER_DIR  = Path(os.environ.get("LOCALAPPDATA",
                                  Path.home() / ".local" / "share")) / APP_NAME
DATA_DIR  = USER_DIR / "data"
LOG_DIR   = USER_DIR / "logs"
ENV_FILE  = USER_DIR / ".env"
ENTRY_SCRIPT = BASE_DIR / "main_project.py"
ICON_PATH    = BASE_DIR / "assets" / "app.ico"


# ── Logger setup with rotation ─────────────────────────────────────
def _setup_logger() -> logging.Logger:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    handler = logging.handlers.RotatingFileHandler(
        LOG_DIR / "launcher.log",
        maxBytes=LOG_MAX_BYTES, backupCount=LOG_BACKUPS, encoding="utf-8",
    )
    handler.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    ))
    logger = logging.getLogger("aidtctm.launcher")
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)
    return logger


LOG = _setup_logger()


# ── Windows DPI awareness ──────────────────────────────────────────
def _set_dpi_aware() -> None:
    if platform.system() != "Windows":
        return
    try:
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(2)   # Per-monitor v2
        LOG.info("dpi_awareness set=per_monitor_v2")
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
            LOG.info("dpi_awareness set=system")
        except Exception:
            LOG.warning("dpi_awareness failed")


# ── First-run setup ────────────────────────────────────────────────
def _first_run_setup() -> None:
    """Idempotent: creates user data dirs + .env on first launch."""
    USER_DIR.mkdir(parents=True, exist_ok=True)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    if not ENV_FILE.exists():
        bootstrap_code = secrets.token_urlsafe(24)
        ENV_FILE.write_text(
            f"# AI-DTCTM auto-generated configuration (do NOT commit this file)\n"
            f"# Created by the Windows launcher on first run.\n"
            f"\n"
            f"# Rotate this string after you claim SuperAdmin once.\n"
            f"SUPER_ADMIN_INVITE_CODE={bootstrap_code}\n"
            f"\n"
            f"# Optional: Supabase cloud sync — set these to enable cross-device\n"
            f"# replication. Leave blank for local-only mode.\n"
            f"SUPABASE_URL=\n"
            f"SUPABASE_ANON_KEY=\n"
            f"SUPABASE_TEAM_ID=default\n"
            f"\n"
            f"# Optional: SMTP for OTP-based password reset + alerts\n"
            f"ALERT_EMAIL=\n"
            f"ALERT_SMTP_PASS=\n"
            f"\n"
            f"# Local data directory — keep relative paths inside the user folder\n"
            f"AIDTCTM_DATA_DIR={DATA_DIR}\n",
            encoding="utf-8",
        )
        LOG.info("env_file_created path=%s", ENV_FILE)

    # Expose to Streamlit subprocess
    os.environ["AIDTCTM_USER_DIR"] = str(USER_DIR)
    os.environ["AIDTCTM_DATA_DIR"] = str(DATA_DIR)
    # Load .env contents into current env
    try:
        for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            os.environ.setdefault(k.strip(), v.strip())
    except Exception as e:
        LOG.warning("env_load_failed err=%s", e)


# ── Free port picker ──────────────────────────────────────────────
def _pick_port(preferred: int = 8501) -> int:
    for p in (preferred, 8502, 8503, 8504):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("127.0.0.1", p))
            return p
        except OSError:
            continue
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ── Production Streamlit subprocess ───────────────────────────────
def _spawn_streamlit(port: int) -> subprocess.Popen:
    """Spawn Streamlit with PRODUCTION flags — no dev menu, no telemetry."""
    cmd = [
        sys.executable, "-m", "streamlit", "run",
        str(ENTRY_SCRIPT),
        "--server.address", "127.0.0.1",
        "--server.port",    str(port),
        "--server.headless", "true",
        "--server.runOnSave", "false",
        "--server.fileWatcherType", "none",
        "--server.enableXsrfProtection", "true",
        "--server.enableCORS",          "false",
        "--browser.gatherUsageStats",   "false",
        "--client.toolbarMode",         "minimal",   # hide hamburger menu
        "--client.showSidebarNavigation", "false",   # we render our own
        "--logger.level",               "warning",
        "--theme.base",                 "light",
    ]
    creationflags = 0
    startupinfo = None
    if platform.system() == "Windows":
        creationflags = subprocess.CREATE_NO_WINDOW
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

    LOG.info("streamlit_spawn port=%d entry=%s", port, ENTRY_SCRIPT)
    return subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=creationflags,
        startupinfo=startupinfo,
        cwd=str(BASE_DIR),
    )


# ── Wait until Streamlit HTTP is healthy ──────────────────────────
def _wait_streamlit_ready(port: int, timeout: int = STREAMLIT_WAIT_TIMEOUT,
                          on_progress=None) -> bool:
    deadline = time.time() + timeout
    poll = 0
    while time.time() < deadline:
        poll += 1
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
            conn.request("GET", "/_stcore/health")
            resp = conn.getresponse()
            if resp.status == 200:
                conn.close()
                LOG.info("streamlit_ready after_polls=%d", poll)
                return True
            conn.close()
        except Exception:
            pass
        if on_progress and poll % 4 == 0:
            elapsed = time.time() - (deadline - timeout)
            on_progress(elapsed, timeout)
        time.sleep(0.25)
    LOG.error("streamlit_timeout after=%ds", timeout)
    return False


# ── HTML templates ─────────────────────────────────────────────────
SPLASH_HTML = """\
<!doctype html><html><head><meta charset="utf-8">
<style>
  *,*::before,*::after{margin:0;padding:0;box-sizing:border-box}
  html,body{height:100%;background:#0F172A;
            font-family:'Segoe UI Variable','Segoe UI',sans-serif;
            overflow:hidden;color:#F8FAFC}
  .wrap{height:100%;display:flex;flex-direction:column;align-items:center;
        justify-content:center;gap:18px;
        background:radial-gradient(ellipse at 50% 35%,
            rgba(34,211,238,0.18) 0%,transparent 60%),
          linear-gradient(180deg,#0F172A 0%,#020617 100%);
        animation:fadeIn 220ms cubic-bezier(0.4, 0, 0.2, 1) both}
  @keyframes fadeIn{from{opacity:0;transform:translateY(8px)}
                     to{opacity:1;transform:none}}
  .logo{width:88px;height:88px;border:2px solid #22D3EE;border-radius:18px;
        display:flex;align-items:center;justify-content:center;
        font-size:2.6rem;color:#22D3EE;font-weight:800;
        box-shadow:0 0 32px rgba(34,211,238,0.35),
                   inset 0 0 24px rgba(34,211,238,0.10);
        animation:logoPulse 1.6s ease-in-out infinite}
  @keyframes logoPulse{0%,100%{transform:scale(1);
        box-shadow:0 0 32px rgba(34,211,238,0.35),
                   inset 0 0 24px rgba(34,211,238,0.10)}
    50%{transform:scale(1.04);
        box-shadow:0 0 44px rgba(34,211,238,0.55),
                   inset 0 0 32px rgba(34,211,238,0.18)}}
  .name{font-size:1.4rem;font-weight:800;letter-spacing:0.22em;
        color:#F8FAFC;text-transform:uppercase}
  .tag{font-family:'Cascadia Code','Consolas',monospace;font-size:0.7rem;
       letter-spacing:0.18em;color:#7DD3FC;text-transform:uppercase}
  .bar{width:260px;height:4px;background:rgba(255,255,255,0.08);
       border-radius:2px;overflow:hidden;margin-top:10px;position:relative}
  .fill{position:absolute;top:0;left:0;height:100%;
        background:linear-gradient(90deg,#22D3EE,#0284C7);
        width:0%;border-radius:2px;
        transition:width 0.3s ease-out}
  .stat{font-family:'Cascadia Code','Consolas',monospace;font-size:0.6rem;
        color:rgba(125,211,252,0.7);letter-spacing:0.12em;
        margin-top:4px;text-transform:uppercase;
        max-width:300px;text-align:center;height:14px}
</style></head><body><div class="wrap">
  <div class="logo">⬡</div>
  <div class="name">AI&nbsp;·&nbsp;DTCTM</div>
  <div class="tag">Forensic Engine v__VERSION__</div>
  <div class="bar"><div class="fill" id="fill"></div></div>
  <div class="stat" id="stat">starting secure runtime</div>
</div>
<script>
  window.aidtctmProgress = function(pct, msg) {
    document.getElementById('fill').style.width = (pct * 100).toFixed(0) + '%';
    if (msg) document.getElementById('stat').textContent = msg;
  };
</script></body></html>
""".replace("__VERSION__", APP_VERSION)


ERROR_HTML = """\
<!doctype html><html><head><meta charset="utf-8">
<style>
  *,*::before,*::after{margin:0;padding:0;box-sizing:border-box}
  html,body{height:100%;background:#0F172A;
            font-family:'Segoe UI Variable','Segoe UI',sans-serif;color:#F8FAFC}
  .wrap{height:100%;display:flex;flex-direction:column;
        align-items:center;justify-content:center;padding:36px;gap:14px;
        background:linear-gradient(180deg,#0F172A 0%,#7F1D1D 350%)}
  .icon{width:64px;height:64px;border:2px solid #DC2626;border-radius:50%;
        display:flex;align-items:center;justify-content:center;font-size:2rem;
        color:#FCA5A5;box-shadow:0 0 28px rgba(220,38,38,0.4)}
  h1{font-size:1.3rem;letter-spacing:0.08em;text-transform:uppercase}
  p{max-width:520px;text-align:center;line-height:1.6;
    font-size:0.9rem;color:rgba(255,255,255,0.78)}
  pre{background:rgba(0,0,0,0.4);border:1px solid #1E3A5F;border-radius:6px;
      padding:12px 16px;font-family:'Cascadia Code','Consolas',monospace;
      font-size:0.7rem;color:#A7F3D0;max-width:680px;max-height:160px;
      overflow:auto;white-space:pre-wrap;word-break:break-word}
  .btns{display:flex;gap:10px;margin-top:8px}
  button{background:#0284C7;color:#FFFFFF;border:none;border-radius:6px;
         padding:9px 18px;font-family:inherit;font-size:0.85rem;cursor:pointer;
         box-shadow:0 4px 14px -4px rgba(2,132,199,0.5)}
  button:hover{background:#0369A1}
  button.alt{background:transparent;border:1px solid rgba(255,255,255,0.3)}
</style></head><body><div class="wrap">
  <div class="icon">!</div>
  <h1>Startup interrupted</h1>
  <p>The AI-DTCTM engine could not start. This is usually fixed by
     reopening the app. If it keeps happening, run the diagnostic via the
     Start Menu &rarr; AI-DTCTM &rarr; Doctor.</p>
  <pre id="detail">__DETAIL__</pre>
  <div class="btns">
    <button onclick="pywebview.api.retry()">Try again</button>
    <button class="alt" onclick="pywebview.api.open_logs()">Open log folder</button>
    <button class="alt" onclick="pywebview.api.exit()">Quit</button>
  </div>
</div></body></html>
"""


# ── Diagnostic mode ────────────────────────────────────────────────
def _doctor() -> int:
    print(f"{APP_NAME} Doctor v{APP_VERSION}")
    print("=" * 60)
    rc = 0

    def check(name: str, ok: bool, detail: str = "") -> None:
        nonlocal rc
        # ASCII only — cp1252 console (default Windows) can't encode U+2713/U+2717
        sym = "OK " if ok else "FAIL"
        print(f"  [{sym}] {name:32s} {detail}")
        if not ok:
            rc = 1

    # 1. Python
    check("Python version >= 3.9",
          sys.version_info >= (3, 9),
          f"running {sys.version.split()[0]}")

    # 2. Streamlit
    try:
        import streamlit
        check("Streamlit installed", True, f"v{streamlit.__version__}")
    except Exception as e:
        check("Streamlit installed", False, str(e)[:60])

    # 3. PyWebView
    try:
        import webview
        check("pywebview installed", True, getattr(webview, "__version__", "?"))
    except Exception as e:
        check("pywebview installed", False, str(e)[:60])

    # 4. Docker (optional but recommended)
    docker_ok = False
    try:
        import docker
        client = docker.from_env(timeout=3)
        client.ping()
        docker_ok = True
        check("Docker daemon reachable", True, "twin features enabled")
    except Exception as e:
        check("Docker daemon reachable", False,
              "twin features disabled — install Docker Desktop")

    # 5. App entry exists
    check("Entry script present", ENTRY_SCRIPT.exists(),
          str(ENTRY_SCRIPT))

    # 6. Writable user dir
    try:
        USER_DIR.mkdir(parents=True, exist_ok=True)
        _t = USER_DIR / ".write_test"
        _t.write_text("ok")
        _t.unlink()
        check("User dir writable", True, str(USER_DIR))
    except Exception as e:
        check("User dir writable", False, str(e)[:60])

    # 7. Free port available
    try:
        port = _pick_port()
        check("Port available", True, f"will bind 127.0.0.1:{port}")
    except Exception as e:
        check("Port available", False, str(e)[:60])

    # 8. .env file
    check(".env file exists", ENV_FILE.exists(), str(ENV_FILE))

    print("=" * 60)
    print(f"Doctor finished {'OK' if rc == 0 else 'WITH ISSUES'}.")
    return rc


# ── Main entry ────────────────────────────────────────────────────
def main() -> int:
    if "--doctor" in sys.argv:
        return _doctor()
    if "--version" in sys.argv:
        print(f"{APP_NAME} v{APP_VERSION}")
        return 0
    if "--reset" in sys.argv:
        import shutil
        if input(f"Wipe {USER_DIR}? (yes/no) ").strip().lower() == "yes":
            shutil.rmtree(USER_DIR, ignore_errors=True)
            print("done.")
        return 0

    _set_dpi_aware()
    _first_run_setup()
    LOG.info("launcher_start version=%s base=%s user=%s",
              APP_VERSION, BASE_DIR, USER_DIR)

    try:
        import webview
    except ImportError:
        msg = ("pywebview is not installed.\n"
                "Install via:  pip install pywebview")
        if platform.system() == "Windows":
            import ctypes
            ctypes.windll.user32.MessageBoxW(0, msg, APP_NAME, 0x10)
        else:
            print(msg, file=sys.stderr)
        return 1

    port = _pick_port()
    streamlit_url = f"http://127.0.0.1:{port}"

    # Bridged API exposed to the splash + error windows
    class _API:
        def retry(self) -> None:
            os.execv(sys.executable, [sys.executable] + sys.argv)
        def open_logs(self) -> None:
            if platform.system() == "Windows":
                os.startfile(LOG_DIR)
            else:
                subprocess.Popen(["open" if sys.platform == "darwin" else "xdg-open",
                                   str(LOG_DIR)])
        def exit(self) -> None:
            os._exit(0)

    api = _API()
    splash = webview.create_window(
        title=APP_NAME, html=SPLASH_HTML,
        width=480, height=320,
        resizable=False, frameless=True,
        on_top=True, easy_drag=True,
        js_api=api,
    )

    streamlit_proc = {"p": None}

    def boot() -> None:
        try:
            streamlit_proc["p"] = _spawn_streamlit(port)

            def progress(elapsed: float, total: int) -> None:
                pct = min(0.92, elapsed / total)
                msgs = [
                    "starting secure runtime",
                    "loading detection models",
                    "preparing analysis pipeline",
                    "finalising console",
                ]
                msg = msgs[min(int(pct * len(msgs)), len(msgs) - 1)]
                try:
                    splash.evaluate_js(
                        f"window.aidtctmProgress({pct},'{msg}')"
                    )
                except Exception:
                    pass

            ready = _wait_streamlit_ready(port, on_progress=progress)
            if not ready:
                # Show error window in place of main
                splash.evaluate_js("window.aidtctmProgress(1, 'startup failed')")
                time.sleep(0.6)
                err_win = webview.create_window(
                    title=WINDOW_TITLE,
                    html=ERROR_HTML.replace("__DETAIL__",
                        "Streamlit HTTP health-check timed out after "
                        f"{STREAMLIT_WAIT_TIMEOUT}s. Check log:\n"
                        f"{LOG_DIR / 'launcher.log'}"),
                    width=720, height=500,
                    background_color="#0F172A",
                    js_api=api,
                )
                try: splash.destroy()
                except Exception: pass
                return

            try:
                splash.evaluate_js("window.aidtctmProgress(1, 'ready')")
            except Exception:
                pass
            time.sleep(0.2)

            main_win = webview.create_window(
                title=WINDOW_TITLE,
                url=streamlit_url,
                width=WINDOW_W, height=WINDOW_H,
                min_size=(1024, 640),
                resizable=True, fullscreen=False,
                background_color="#0F172A",
                text_select=True,
                confirm_close=True,
                js_api=api,
            )

            def on_closed() -> None:
                LOG.info("main_window_closed")
                try:
                    if streamlit_proc["p"]:
                        streamlit_proc["p"].terminate()
                        try: streamlit_proc["p"].wait(timeout=3)
                        except Exception:
                            streamlit_proc["p"].kill()
                except Exception:
                    pass
                os._exit(0)
            main_win.events.closed += on_closed

            try: splash.destroy()
            except Exception: pass
        except Exception as e:
            LOG.exception("boot_failed")
            try:
                splash.evaluate_js(
                    f"window.aidtctmProgress(1, 'error: {str(e)[:60]}')"
                )
            except Exception: pass

    threading.Thread(target=boot, daemon=True).start()

    try:
        webview.start(gui="edgechromium", debug=False)
    except Exception as e:
        LOG.warning("edgechromium_failed err=%s falling=back", e)
        webview.start(debug=False)

    if streamlit_proc["p"]:
        try: streamlit_proc["p"].terminate()
        except Exception: pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
