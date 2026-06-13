@echo off
REM ════════════════════════════════════════════════════════════════
REM   AI-DTCTM — Uninstaller
REM ════════════════════════════════════════════════════════════════

title AI-DTCTM Uninstaller
color 0C
cls

echo.
echo ============================================================
echo   AI-DTCTM Uninstaller
echo ============================================================
echo.

set "TARGET=%LOCALAPPDATA%\AI-DTCTM"
set "DESKTOP=%USERPROFILE%\Desktop\AI-DTCTM.lnk"
set "STARTMENU=%APPDATA%\Microsoft\Windows\Start Menu\Programs\AI-DTCTM"

echo Removing app files from %TARGET%...
if exist "%TARGET%" (
    rmdir /S /Q "%TARGET%"
    echo   [OK] App folder removed.
) else (
    echo   [INFO] App folder not found.
)

echo.
echo Removing Desktop shortcut...
if exist "%DESKTOP%" (
    del /Q "%DESKTOP%"
    echo   [OK] Desktop shortcut removed.
) else (
    echo   [INFO] Desktop shortcut not found.
)

echo.
echo Removing Start Menu entry...
if exist "%STARTMENU%" (
    rmdir /S /Q "%STARTMENU%"
    echo   [OK] Start Menu entry removed.
) else (
    echo   [INFO] Start Menu entry not found.
)

echo.
echo ============================================================
echo   UNINSTALL COMPLETE
echo ============================================================
echo.
pause
exit /b 0
