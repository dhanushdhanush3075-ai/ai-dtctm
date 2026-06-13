================================================================
  AI-DTCTM v1.0.0 — Portable Install (WDAC-friendly)
================================================================

This version installs WITHOUT requiring any unsigned .exe — so it
works on Windows machines with Application Control / WDAC enabled
(like college- or corporate-managed laptops).

================================================================
INSTALL  (5 minutes)
================================================================

Prerequisite: Python 3.10 or later from python.org
              (most students already have it installed)

Step 1.  Right-click "install.bat" -> Run as administrator
         (admin is only needed to create the Start Menu folder;
          if you don't have admin, just double-click — Desktop
          shortcut still works.)

Step 2.  Watch the 5-step progress messages:
         [1/5] Checking Python...
         [2/5] Installing required Python packages...
         [3/5] Installing app files...
         [4/5] Creating launcher...
         [5/5] Creating shortcuts...

Step 3.  When you see "INSTALLATION COMPLETE", close the window.

================================================================
LAUNCH
================================================================

Double-click the "AI-DTCTM" icon on your Desktop.

A console window opens briefly while Streamlit boots, then your
browser opens automatically at http://localhost:8501 showing the
AI-DTCTM login page.

First time: sign up for an account. The first user to claim the
SuperAdmin invite code (auto-generated in your %LOCALAPPDATA%\
AI-DTCTM\.env file) becomes the system administrator.

================================================================
UNINSTALL
================================================================

Run "uninstall.bat" — removes the app folder, Desktop shortcut,
and Start Menu entry.

================================================================
TROUBLESHOOTING
================================================================

  Q: "Python is not installed or not on PATH"
  A: Install Python 3.10+ from python.org. During install, TICK
     the "Add Python to PATH" checkbox.

  Q: "pip install failed"
  A: Check your internet. Or try: python -m pip install -r
     requirements.txt manually.

  Q: App opens but shows "Connection refused" in browser
  A: Streamlit is still starting. Wait 10-30 seconds, then
     refresh the browser tab.

  Q: Desktop shortcut won't run
  A: Open the install folder at %LOCALAPPDATA%\AI-DTCTM\ and
     double-click "Launch AI-DTCTM.bat" directly.

================================================================
WHY USE THIS INSTEAD OF AI-DTCTM-Setup.exe?
================================================================

The .exe installer uses PyInstaller-bundled code that gets blocked
on systems with strict code-integrity policies (WDAC / AppLocker).
This portable version sidesteps that block by using Python directly
— Python.exe is signed by the Python Software Foundation and is
trusted by virtually all enterprise policies.

For consumer / home Windows machines without WDAC, either install
method works. Use whichever you prefer.

================================================================
Author: DHANUSH S
        Meenakshi College of Engineering (MCE)
        311424622006
================================================================
