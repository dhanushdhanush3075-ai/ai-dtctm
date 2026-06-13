"""
AI-DTCTM — Build Portable WDAC-Friendly Installer

Bundles the app source into portable/app/ + install.bat/uninstall.bat
+ README.txt, then ZIPs the whole portable/ folder for distribution.

Output:
  portable/                          (working dir during build)
  portable/AI-DTCTM-Portable-1.0.0.zip   (the file to share)

This portable version installs WITHOUT any unsigned .exe — so it
works even on Windows machines with strict Application Control
(WDAC / AppLocker), like college and corporate laptops.
"""
from __future__ import annotations

import shutil
import sys
import zipfile
from pathlib import Path

ROOT     = Path(__file__).resolve().parent
PORTABLE = ROOT / "portable"
APP_DIR  = PORTABLE / "app"
OUT_ZIP  = PORTABLE / "AI-DTCTM-Portable-1.0.0.zip"


# Files / folders to bundle as app source
INCLUDE = [
    "core",
    "_pages",
    "assets",
    "sample_databases",
    "main_project.py",
    "auth_ui.py",
    "config.py",
    "requirements.txt",
    "README.md",
    "QUICKSTART.md",
    "TRANSPARENCY_REPORT.md",
]

# Patterns to skip (huge / build / private)
SKIP_PATTERNS = (
    "__pycache__",
    ".venv",
    "build",
    "dist",
    "release",
    "logs",
    "*.pfx",
    "data/source_clones",
    "data/apk_clones",
    "data/apk_workbench",
    "data/screenshots",
    "_archive",
    "installer",
    "_temp",
)


def banner(title: str) -> None:
    print()
    print("=" * 64)
    print(f"  {title}")
    print("=" * 64)


def should_skip(rel_path: str) -> bool:
    """Skip files/folders matching the SKIP_PATTERNS."""
    parts = rel_path.replace("\\", "/").split("/")
    for pat in SKIP_PATTERNS:
        if pat in parts or any(p == pat for p in parts):
            return True
        if pat.startswith("*") and any(p.endswith(pat[1:]) for p in parts):
            return True
    return False


def copy_tree(src: Path, dst: Path) -> int:
    """Recursive copy with skip filter. Returns file count."""
    n = 0
    if src.is_file():
        if should_skip(src.name):
            return 0
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        return 1
    for entry in src.iterdir():
        rel = entry.relative_to(ROOT) if entry.is_relative_to(ROOT) else entry
        if should_skip(str(rel)):
            continue
        target = dst / entry.name
        if entry.is_dir():
            n += copy_tree(entry, target)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(entry, target)
            n += 1
    return n


def main() -> int:
    banner("Stage 1 — Prepare portable directory")
    APP_DIR.mkdir(parents=True, exist_ok=True)
    # Wipe any previous app/ to ensure a clean copy
    if APP_DIR.exists():
        for child in APP_DIR.iterdir():
            if child.is_dir():
                shutil.rmtree(child)
            else:
                child.unlink()
    print(f"  [OK] {APP_DIR}")

    banner("Stage 2 — Copy app source into portable/app/")
    total = 0
    for name in INCLUDE:
        src = ROOT / name
        if not src.exists():
            print(f"  [WARN] {name} not found, skipping")
            continue
        dst = APP_DIR / name
        n = copy_tree(src, dst)
        print(f"  [OK] {name:30s}  {n} files")
        total += n
    print(f"  TOTAL: {total} files copied")

    banner("Stage 3 — Verify install scripts present")
    for fname in ("install.bat", "uninstall.bat", "README.txt"):
        p = PORTABLE / fname
        if not p.exists():
            print(f"  [FAIL] {fname} missing in portable/ — re-run build")
            return 1
        sz = p.stat().st_size
        print(f"  [OK] {fname}  ({sz} bytes)")

    banner("Stage 4 — Create distributable ZIP")
    if OUT_ZIP.exists():
        OUT_ZIP.unlink()
    with zipfile.ZipFile(OUT_ZIP, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        # Top-level files: install.bat, uninstall.bat, README.txt
        for fname in ("install.bat", "uninstall.bat", "README.txt"):
            p = PORTABLE / fname
            zf.write(p, arcname=fname)
        # Bundle the app/ folder
        for path in APP_DIR.rglob("*"):
            if path.is_file():
                rel = path.relative_to(PORTABLE)
                zf.write(path, arcname=str(rel))
    size_mb = OUT_ZIP.stat().st_size / (1024 * 1024)
    print(f"  [OK] {OUT_ZIP.name}  ({size_mb:.1f} MB)")

    banner("DONE")
    print(f"  Portable ZIP:  {OUT_ZIP}")
    print()
    print("  Upload this to GitHub Releases as v1.0.0 asset.")
    print()
    print("  USERS WILL:")
    print("    1. Download AI-DTCTM-Portable-1.0.0.zip from GitHub")
    print("    2. Right-click -> Extract All")
    print("    3. Right-click install.bat -> Run as administrator")
    print("    4. Watch the 5-step install wizard")
    print("    5. Double-click the new 'AI-DTCTM' desktop shortcut")
    print()
    print("  WORKS ON WDAC-LOCKED MACHINES because no unsigned .exe is used.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
