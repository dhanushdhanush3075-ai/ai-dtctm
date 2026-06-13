@echo off
REM ════════════════════════════════════════════════════════════════
REM   AI-DTCTM — Python-Based Installer (WDAC-friendly)
REM ════════════════════════════════════════════════════════════════
REM   Works on Windows machines where unsigned .exe files are blocked
REM   by Application Control / WDAC / AppLocker — because it uses
REM   python.exe (Microsoft-signed) and cmd.exe (Microsoft-signed)
REM   only. No third-party unsigned binaries.
REM
REM   What this does:
REM     1. Verifies Python 3.9+ is installed
REM     2. Installs required Python packages via `python -m pip`
REM     3. Copies the app source to %LOCALAPPDATA%\AI-DTCTM\
REM     4. Creates a Desktop shortcut
REM     5. Creates a Start Menu shortcut
REM     6. Done — user double-clicks shortcut to launch
REM ════════════════════════════════════════════════════════════════

title AI-DTCTM Installer
color 0B
cls

echo.
echo ============================================================
echo   AI-DTCTM Installer v1.0.0
echo ============================================================
echo.

REM -- Step 1: verify Python --
echo [1/5] Checking Python...
python --version >nul 2>&1
if errorlevel 1 (
    echo.
    echo   ERROR: Python is not installed or not on PATH.
    echo   Install Python 3.10+ from https://www.python.org/downloads/
    echo   Make sure to tick "Add Python to PATH" during install.
    echo.
    pause
    exit /b 1
)
for /f "delims=" %%v in ('python --version') do echo   Found: %%v

REM -- Step 2: install dependencies --
echo.
echo [2/5] Installing required Python packages...
echo   This takes 1-3 minutes the first time. Please wait.
echo.
python -m pip install --quiet --user --upgrade pip 2>nul
python -m pip install --quiet --user -r "%~dp0requirements.txt"
if errorlevel 1 (
    echo.
    echo   ERROR: pip install failed. Check your internet connection.
    echo.
    pause
    exit /b 1
)
echo   [OK] All packages installed.

REM -- Step 3: copy app to LocalAppData --
echo.
echo [3/5] Installing app files to %%LOCALAPPDATA%%\AI-DTCTM\...
set "TARGET=%LOCALAPPDATA%\AI-DTCTM"
if exist "%TARGET%" (
    echo   [INFO] Existing install detected — updating in place.
) else (
    mkdir "%TARGET%" 2>nul
)
xcopy /E /I /Y /Q "%~dp0app\*" "%TARGET%\" >nul
if errorlevel 1 (
    echo   ERROR: Could not copy files.
    pause
    exit /b 1
)
echo   [OK] App installed at %TARGET%

REM -- Step 4: create launcher script --
echo.
echo [4/5] Creating launcher...
set "LAUNCHER=%TARGET%\Launch AI-DTCTM.bat"
(
    echo @echo off
    echo title AI-DTCTM
    echo cd /d "%TARGET%"
    echo start "" "http://localhost:8501"
    echo python -m streamlit run main_project.py --server.headless=true --browser.gatherUsageStats=false --client.toolbarMode=minimal
    echo pause
) > "%LAUNCHER%"
echo   [OK] Launcher: "%LAUNCHER%"

REM -- Step 5: create shortcuts via PowerShell --
echo.
echo [5/5] Creating Desktop + Start Menu shortcuts...

powershell -NoProfile -Command ^
    "$WshShell = New-Object -ComObject WScript.Shell;" ^
    "$Shortcut = $WshShell.CreateShortcut([Environment]::GetFolderPath('Desktop') + '\AI-DTCTM.lnk');" ^
    "$Shortcut.TargetPath = '%LAUNCHER%';" ^
    "$Shortcut.WorkingDirectory = '%TARGET%';" ^
    "$Shortcut.IconLocation = '%TARGET%\assets\app.ico';" ^
    "$Shortcut.Description = 'AI-DTCTM Forensic Engine';" ^
    "$Shortcut.Save();" ^
    "$startMenu = [Environment]::GetFolderPath('Programs') + '\AI-DTCTM';" ^
    "New-Item -ItemType Directory -Force -Path $startMenu | Out-Null;" ^
    "$smShortcut = $WshShell.CreateShortcut($startMenu + '\AI-DTCTM.lnk');" ^
    "$smShortcut.TargetPath = '%LAUNCHER%';" ^
    "$smShortcut.WorkingDirectory = '%TARGET%';" ^
    "$smShortcut.IconLocation = '%TARGET%\assets\app.ico';" ^
    "$smShortcut.Description = 'AI-DTCTM Forensic Engine';" ^
    "$smShortcut.Save();"

echo   [OK] Shortcuts created.

echo.
echo ============================================================
echo   INSTALLATION COMPLETE
echo ============================================================
echo.
echo   Desktop shortcut:   AI-DTCTM
echo   Start menu:         AI-DTCTM ^> AI-DTCTM
echo   Manual launch:      %LAUNCHER%
echo.
echo   Double-click the desktop shortcut to launch the app.
echo   The app opens in your browser at http://localhost:8501
echo.
pause
exit /b 0
