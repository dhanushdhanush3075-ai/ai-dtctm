@echo off
REM ════════════════════════════════════════════════════════════════
REM  AI-DTCTM Login Demo — one-click launcher
REM  Just double-click this file. No setup needed.
REM ════════════════════════════════════════════════════════════════

cd /d "%~dp0"

echo.
echo  ╔══════════════════════════════════════════════════════════════╗
echo  ║   AI-DTCTM Login Page Demo v2                                ║
echo  ║   Starting on http://localhost:8599                          ║
echo  ║                                                              ║
echo  ║   Press Ctrl+C to stop the server when done.                 ║
echo  ╚══════════════════════════════════════════════════════════════╝
echo.

REM Use venv Python (so we don't depend on system PATH)
if not exist ".venv\Scripts\python.exe" (
    echo  [ERROR] Virtual environment not found at .venv\Scripts\python.exe
    echo  Please create it first:  python -m venv .venv
    pause
    exit /b 1
)

REM Auto-open browser to the demo URL after a short delay
start "" cmd /c "timeout /t 4 /nobreak >nul && start http://localhost:8599"

REM Run the demo on a non-default port so it doesn't clash with main_project.py
".venv\Scripts\python.exe" -m streamlit run demo_login.py ^
    --server.port 8599 ^
    --server.address 127.0.0.1 ^
    --browser.gatherUsageStats false

pause
