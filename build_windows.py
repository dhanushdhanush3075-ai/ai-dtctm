"""
AI-DTCTM Windows build — one command, full pipeline.

USAGE
─────────
  python build_windows.py
    `-> stage 1: ensure deps (pywebview, pyinstaller)
    `-> stage 2: PyInstaller bundle (dist/AI-DTCTM-Launcher/)
    `-> stage 3: report next-step (Inno Setup compile)
    `-> stage 4 (optional): auto-compile Inno Setup if iscc.exe on PATH

OUTPUT
─────────
  dist/AI-DTCTM-Launcher/
      `->─ AI-DTCTM-Launcher.exe       ← double-clickable
  installer/Output/
      `->─ AI-DTCTM-Setup-1.0.0.exe    ← the installer to share

If `iscc.exe` (Inno Setup 6 compiler) is not on PATH, the script stops
after stage 2 and prints the exact command to run manually.
"""
from __future__ import annotations
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def banner(title: str) -> None:
    print()
    print("=" * 72)
    print(f"  {title}")
    print("=" * 72)


def run(cmd: list[str], cwd: Path | None = None) -> int:
    print(f"  >> {' '.join(cmd)}")
    return subprocess.run(cmd, cwd=cwd or ROOT).returncode


def stage_deps() -> bool:
    banner("Stage 1 — Ensure build dependencies")
    try:
        import pywebview     # noqa: F401
        print("  [OK] pywebview available")
    except ImportError:
        print("  Installing pywebview…")
        if run([sys.executable, "-m", "pip", "install", "pywebview"]) != 0:
            return False
    try:
        import PyInstaller   # noqa: F401
        print("  [OK] PyInstaller available")
    except ImportError:
        print("  Installing pyinstaller…")
        if run([sys.executable, "-m", "pip", "install", "pyinstaller"]) != 0:
            return False
    return True


def stage_clean() -> None:
    banner("Stage 2a — Clean previous build artifacts")
    for d in ("build", "dist"):
        p = ROOT / d
        if p.exists():
            print(f"  removing {p.relative_to(ROOT)}/")
            shutil.rmtree(p, ignore_errors=True)


def stage_pyinstaller() -> bool:
    banner("Stage 2b — PyInstaller bundle")
    icon = ROOT / "assets" / "app.ico"
    icon_arg = ["--icon", str(icon)] if icon.exists() else []
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--clean", "--noconfirm",
        "--onedir", "--windowed",
        "--name", "AI-DTCTM-Launcher",
        *icon_arg,
        # bundled source files
        "--add-data", f"main_project.py{';' if sys.platform == 'win32' else ':'}.",
        "--add-data", f"auth_ui.py{';' if sys.platform == 'win32' else ':'}.",
        "--add-data", f"config.py{';' if sys.platform == 'win32' else ':'}.",
        "--add-data", f"core{';' if sys.platform == 'win32' else ':'}core",
        "--add-data", f"_pages{';' if sys.platform == 'win32' else ':'}_pages",
        "--add-data", f"assets{';' if sys.platform == 'win32' else ':'}assets",
        # Streamlit needs its bundled assets
        "--collect-all", "streamlit",
        # Hidden imports Streamlit pulls dynamically
        "--hidden-import", "streamlit.web.cli",
        "--hidden-import", "streamlit.runtime.scriptrunner.script_runner",
        # Entry script
        "launcher.py",
    ]
    return run(cmd) == 0


def stage_inno_setup() -> bool:
    banner("Stage 3 — Inno Setup installer (optional)")
    iscc = shutil.which("iscc") or shutil.which("iscc.exe")
    if not iscc:
        print("  [WARN] iscc.exe not on PATH — Inno Setup compile skipped.")
        print()
        print("  To build the installer manually:")
        print("    1. Download Inno Setup 6 from https://jrsoftware.org/isdl.php")
        print("    2. Run:  iscc.exe installer/AI-DTCTM.iss")
        print()
        return False
    return run([iscc, "installer/AI-DTCTM.iss"]) == 0


def stage_report() -> None:
    banner("Build complete")
    bundle = ROOT / "dist" / "AI-DTCTM-Launcher"
    if bundle.exists():
        exe = bundle / "AI-DTCTM-Launcher.exe"
        print(f"  [OK] Portable bundle: {bundle}")
        if exe.exists():
            print(f"    `-> {exe.relative_to(ROOT)}  (double-click to run)")
    installer = ROOT / "installer" / "Output"
    if installer.exists():
        for f in installer.glob("*.exe"):
            print(f"  [OK] Installer: {f}")


def main() -> int:
    if sys.platform != "win32":
        print("This script targets Windows. Use a Windows machine or "
              "Wine-based crossbuild (not officially supported).")
        return 1
    if not stage_deps():
        return 1
    stage_clean()
    if not stage_pyinstaller():
        return 1
    stage_inno_setup()
    stage_report()
    return 0


if __name__ == "__main__":
    sys.exit(main())
