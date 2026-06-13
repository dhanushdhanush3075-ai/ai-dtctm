"""
AI-DTCTM — Final Release Packaging
══════════════════════════════════════════════════════════════════════
Bundles everything users need into ONE distributable folder:

    release/
    ├── AI-DTCTM-Launcher/         (the actual app — 387 MB)
    ├── AI-DTCTM-CodeSign.cer      (public certificate)
    ├── trust_publisher.ps1        (one-time setup for users)
    ├── INSTALL.txt                (5-line user manual)
    └── AI-DTCTM-v1.0.0.zip        (everything zipped for upload)

After this runs, upload AI-DTCTM-v1.0.0.zip to GitHub Releases /
Google Drive / your website. Users download → unzip → run trust
script → double-click launcher.
"""
from __future__ import annotations
import shutil
import sys
import zipfile
from pathlib import Path

ROOT       = Path(__file__).resolve().parent
DIST       = ROOT / "dist" / "AI-DTCTM-Launcher"
CERT_DIR   = ROOT / "installer" / "cert"
RELEASE    = ROOT / "release"
VERSION    = "1.0.0"


def banner(title: str) -> None:
    print()
    print("=" * 72)
    print(f"  {title}")
    print("=" * 72)


def main() -> int:
    if not DIST.exists():
        print(f"ERROR: bundle not found at {DIST}")
        print("       Run `python build_windows.py` first.")
        return 1

    banner("Stage 1 — Prepare release folder")
    if RELEASE.exists():
        shutil.rmtree(RELEASE)
    RELEASE.mkdir(parents=True)
    print(f"  [OK] {RELEASE}")

    banner("Stage 2 — Copy launcher bundle")
    target = RELEASE / "AI-DTCTM-Launcher"
    shutil.copytree(DIST, target)
    size_mb = sum(f.stat().st_size for f in target.rglob("*")) // (1024 * 1024)
    print(f"  [OK] {target}  ({size_mb} MB · {sum(1 for _ in target.rglob('*'))} files)")

    banner("Stage 3 — Copy signing certificate")
    cer = CERT_DIR / "AI-DTCTM-CodeSign.cer"
    if cer.exists():
        shutil.copy(cer, RELEASE / "AI-DTCTM-CodeSign.cer")
        print(f"  [OK] AI-DTCTM-CodeSign.cer")
    else:
        print(f"  [WARN] No certificate at {cer} — users will see SmartScreen warning")

    banner("Stage 4 — Copy trust script")
    trust = ROOT / "installer" / "trust_publisher.ps1"
    if trust.exists():
        shutil.copy(trust, RELEASE / "trust_publisher.ps1")
        print(f"  [OK] trust_publisher.ps1")

    banner("Stage 5 — Write user INSTALL.txt")
    install_txt = RELEASE / "INSTALL.txt"
    install_txt.write_text(
        "AI-DTCTM — User Install Guide\n"
        "=" * 60 + "\n\n"
        "STEP 1 (one time only — removes SmartScreen warnings):\n"
        "  • Right-click PowerShell -> Run as Administrator\n"
        "  • cd into this folder\n"
        "  • Run:\n"
        "      powershell.exe -ExecutionPolicy Bypass -File trust_publisher.ps1\n\n"
        "STEP 2 (start the app):\n"
        "  • Double-click AI-DTCTM-Launcher\\AI-DTCTM-Launcher.exe\n"
        "  • A splash screen appears, then the main window opens\n\n"
        "STEP 3 (first-run inside the app):\n"
        "  • The app generates an invite code in:\n"
        "      %LOCALAPPDATA%\\AI-DTCTM\\.env\n"
        "  • Open that file, copy the SUPER_ADMIN_INVITE_CODE value\n"
        "  • Sign up in the app -> pick role 'SuperAdmin' -> paste code\n"
        "  • You are now the system administrator\n\n"
        "TROUBLESHOOTING:\n"
        "  • App won't start ->\n"
        "      AI-DTCTM-Launcher\\AI-DTCTM-Launcher.exe --doctor\n"
        "  • Docker features missing -> install Docker Desktop first\n"
        "  • Reset everything ->\n"
        "      AI-DTCTM-Launcher\\AI-DTCTM-Launcher.exe --reset\n",
        encoding="utf-8",
    )
    print(f"  [OK] INSTALL.txt")

    banner("Stage 6 — Create the distributable ZIP")
    zip_path = RELEASE / f"AI-DTCTM-v{VERSION}.zip"
    with zipfile.ZipFile(
        zip_path, "w", zipfile.ZIP_DEFLATED, compresslevel=6,
    ) as zf:
        for item in RELEASE.rglob("*"):
            if item.is_file() and item != zip_path:
                arcname = item.relative_to(RELEASE)
                zf.write(item, arcname)
    zip_size_mb = zip_path.stat().st_size // (1024 * 1024)
    print(f"  [OK] {zip_path.name}  ({zip_size_mb} MB)")

    banner("DONE — ready to ship")
    print(f"  Upload this file:")
    print(f"      {zip_path}")
    print()
    print("  Users:")
    print("      1. Download the .zip")
    print("      2. Unzip anywhere")
    print("      3. Follow INSTALL.txt (5 lines)")
    print("      4. Done — they have the app installed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
