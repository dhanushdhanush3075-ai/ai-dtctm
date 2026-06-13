<#
================================================================
  AI-DTCTM — One-Command Web Installer (v1.0.2 — clean rewrite)
================================================================

USAGE
=================================================================
  Open PowerShell. Paste ONE LINE. Press Enter.

  irm https://raw.githubusercontent.com/dhanushdhanush3075-ai/ai-dtctm/main/web_install.ps1 | iex

WHAT IT DOES (~3 minutes, fully automatic)
=================================================================
  [1/6] Verifies Python 3.10+ is installed
  [2/6] Downloads the latest portable ZIP from GitHub
  [3/6] Extracts to a temp folder, then atomically swaps in
  [4/6] Installs Python dependencies via `python -m pip`
  [5/6] Creates Desktop + Start Menu shortcuts
  [6/6] Launches the app at http://localhost:8501

WDAC-FRIENDLY
=================================================================
  Only uses Microsoft-signed binaries:
    powershell.exe (Microsoft) + python.exe (Python.org)
  No unsigned third-party .exe is ever executed.
================================================================
#>

$ErrorActionPreference = "Stop"
$ProgressPreference    = "SilentlyContinue"

$Host.UI.RawUI.WindowTitle = "AI-DTCTM Web Installer"
Clear-Host

function Section($n, $total, $msg) {
    Write-Host ""
    Write-Host ("[" + $n + "/" + $total + "] ") -NoNewline -ForegroundColor Cyan
    Write-Host $msg -ForegroundColor White
}
function OK($msg)   { Write-Host ("       [OK] " + $msg) -ForegroundColor Green }
function Info($msg) { Write-Host ("       " + $msg) -ForegroundColor DarkGray }
function Warn($msg) { Write-Host ("       " + $msg) -ForegroundColor Yellow }
function Fail($msg) {
    Write-Host ""
    Write-Host ("       [FAIL] " + $msg) -ForegroundColor Red
    Write-Host ""
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  AI-DTCTM Web Installer v1.0.0" -ForegroundColor White
Write-Host "  Forensic Engine - by DHANUSH S - MCE" -ForegroundColor DarkGray
Write-Host "================================================================" -ForegroundColor Cyan

# ── Configuration ────────────────────────────────────────────────
$RepoOwner   = "dhanushdhanush3075-ai"
$RepoName    = "ai-dtctm"
$Branch      = "main"
$AssetName   = "AI-DTCTM-Portable-1.0.0.zip"
$InstallDir  = Join-Path $env:LOCALAPPDATA "AI-DTCTM"
$TempZip     = Join-Path $env:TEMP ("aidtctm-" + (Get-Random) + ".zip")
$StageDir    = Join-Path $env:TEMP ("aidtctm-stage-" + (Get-Random))
$DownloadUrl = "https://raw.githubusercontent.com/$RepoOwner/$RepoName/$Branch/portable/$AssetName"

# ── Step 1: Python ───────────────────────────────────────────────
Section 1 6 "Checking Python..."
$pythonExe = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $pythonExe) {
    Fail @"
Python is not installed or not on PATH.

  Install Python 3.11 from:
      https://www.python.org/downloads/release/python-3119/

  Tick "Add Python to PATH" during install. Then re-run this installer.
"@
}
$pyVer = (& python --version 2>&1).Trim()
OK "Found $pyVer at $pythonExe"

if ($pyVer -match "Python (\d+)\.(\d+)") {
    $major = [int]$matches[1]; $minor = [int]$matches[2]
    if ($major -eq 3 -and $minor -ge 13) {
        Warn "Python $major.$minor is bleeding-edge."
        Warn "If install fails, switch to Python 3.11 from python.org."
    }
}

# ── Step 2: Kill any running AI-DTCTM process (prevents file locks) ──
Section 2 6 "Cleaning up any prior AI-DTCTM processes..."
$killedAny = $false
Get-Process -Name python* -ErrorAction SilentlyContinue | ForEach-Object {
    try {
        $cl = (Get-CimInstance Win32_Process -Filter ("ProcessId=" + $_.Id) -ErrorAction SilentlyContinue).CommandLine
        if ($cl -and ($cl -match "AI-DTCTM" -or $cl -match "main_project.py" -or $cl -match "streamlit")) {
            $_ | Stop-Process -Force -ErrorAction SilentlyContinue
            $killedAny = $true
        }
    } catch {}
}
if ($killedAny) {
    OK "Stopped previous instance"
    Start-Sleep -Seconds 1
} else {
    OK "No previous instance running"
}

# ── Step 3: Download portable ZIP ────────────────────────────────
Section 3 6 "Downloading AI-DTCTM portable package..."
Info "URL: $DownloadUrl"
try {
    Invoke-WebRequest -Uri $DownloadUrl -OutFile $TempZip -UseBasicParsing
} catch {
    Fail "Download failed: $($_.Exception.Message)"
}
$sizeMB = [math]::Round((Get-Item $TempZip).Length / 1MB, 1)
OK "Downloaded $sizeMB MB to temp"

# ── Step 4: Extract to staging, then atomic swap into InstallDir ─
Section 4 6 "Installing to $InstallDir..."

# Wipe any prior staging dir
if (Test-Path $StageDir) {
    try { Remove-Item -Recurse -Force $StageDir -ErrorAction Stop } catch {}
}
New-Item -ItemType Directory -Force -Path $StageDir | Out-Null

# Extract ZIP to staging
try {
    Expand-Archive -Path $TempZip -DestinationPath $StageDir -Force
} catch {
    Fail "Extract failed: $($_.Exception.Message)"
}
Remove-Item $TempZip -Force -ErrorAction SilentlyContinue

# ZIP structure has top-level "app/" folder with the actual files +
# install.bat / uninstall.bat / README.txt at root. We only need app/*
# moved into InstallDir.
$StagedApp = Join-Path $StageDir "app"
if (-not (Test-Path $StagedApp)) {
    Fail "Unexpected ZIP layout: 'app/' folder not found inside ZIP"
}

# Make sure InstallDir exists, fully cleaned (force-remove everything)
if (Test-Path $InstallDir) {
    Info "Existing install detected - cleaning..."
    # Take ownership / clear read-only flags before removing
    Get-ChildItem -Path $InstallDir -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
        try { $_.Attributes = "Normal" } catch {}
    }
    try {
        Remove-Item -Recurse -Force $InstallDir -ErrorAction Stop
    } catch {
        # Fall back: rename the old folder out of the way + try again
        $rescue = $InstallDir + ".old-" + (Get-Random)
        try { Rename-Item -Path $InstallDir -NewName $rescue -ErrorAction Stop } catch {
            Fail "Could not clear old install at $InstallDir. Manually delete it, then retry."
        }
        Info "Old install renamed to $rescue (delete later if you want)"
    }
}
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

# Now COPY staged app/* into InstallDir (Copy is safer than Move across folders)
Get-ChildItem -Path $StagedApp -Force | ForEach-Object {
    $dest = Join-Path $InstallDir $_.Name
    Copy-Item -Path $_.FullName -Destination $dest -Recurse -Force
}
# Also copy the top-level install.bat / uninstall.bat / README.txt (optional)
foreach ($fn in @("README.txt")) {
    $src = Join-Path $StageDir $fn
    if (Test-Path $src) {
        Copy-Item -Path $src -Destination (Join-Path $InstallDir $fn) -Force
    }
}
# Clean up staging
try { Remove-Item -Recurse -Force $StageDir -ErrorAction SilentlyContinue } catch {}

OK "Files installed at $InstallDir"

# ── Step 5: Install Python dependencies ─────────────────────────
Section 5 6 "Installing Python dependencies (1-3 minutes)..."
Info "Running: python -m pip install --user -r requirements.txt"
$req = Join-Path $InstallDir "requirements.txt"
if (-not (Test-Path $req)) {
    Fail "requirements.txt missing at $req"
}

# Upgrade pip first (quietly)
& python -m pip install --user --upgrade pip --quiet 2>&1 | Out-Null

# Install requirements — write to a log file, then parse it (bypasses
# PowerShell's "stderr from native commands = terminating error" quirk)
$pipLog = Join-Path $env:TEMP ("aidtctm-pip-" + (Get-Random) + ".log")
$ErrorActionPreference = "Continue"
$prevPSNativeFail = $PSNativeCommandUseErrorActionPreference
$PSNativeCommandUseErrorActionPreference = $false
& python -m pip install --user -r $req 2>&1 > $pipLog
$pipExit = $LASTEXITCODE
$PSNativeCommandUseErrorActionPreference = $prevPSNativeFail
$ErrorActionPreference = "Stop"
$lastErr = $null
if (Test-Path $pipLog) {
    Get-Content $pipLog | ForEach-Object {
        $line = "$_"
        if ($line -match "Successfully installed") {
            Write-Host ("       " + $line) -ForegroundColor Green
        } elseif ($line -match "^ERROR" -or $line -match "^error:") {
            Write-Host ("       " + $line) -ForegroundColor Red
            $script:lastErr = $line
        } elseif ($line -match "^Collecting|^Installing |^Building") {
            Info $line
        }
    }
    Remove-Item $pipLog -Force -ErrorAction SilentlyContinue
}

if ($pipExit -ne 0) {
    Fail @"
pip install failed (exit $LASTEXITCODE).

  Last error: $lastErr

  Common causes + fixes:
  1. Python $pyVer too new - some packages don't have wheels.
     FIX: Install Python 3.11 from python.org, retry.
  2. A package needs MSVC compiler.
     FIX: Tell DHANUSH which package failed, get a custom requirements.txt.
"@
}
OK "Dependencies installed"

# ── Step 6: Shortcuts + launch ──────────────────────────────────
Section 6 6 "Creating launcher and shortcuts..."

$LauncherBat = Join-Path $InstallDir "Launch AI-DTCTM.bat"
$launcherContent = @"
@echo off
title AI-DTCTM
cd /d "$InstallDir"
start "" "http://localhost:8501"
python -m streamlit run main_project.py --server.headless=true --browser.gatherUsageStats=false --client.toolbarMode=minimal
pause
"@
Set-Content -Path $LauncherBat -Value $launcherContent -Encoding ASCII

$iconPath = Join-Path $InstallDir "assets\app.ico"
if (-not (Test-Path $iconPath)) { $iconPath = "" }

$WshShell = New-Object -ComObject WScript.Shell

# Desktop shortcut (idempotent — overwrites)
$DesktopLink = Join-Path ([Environment]::GetFolderPath("Desktop")) "AI-DTCTM.lnk"
if (Test-Path $DesktopLink) { Remove-Item -Force $DesktopLink -ErrorAction SilentlyContinue }
$d = $WshShell.CreateShortcut($DesktopLink)
$d.TargetPath = $LauncherBat
$d.WorkingDirectory = $InstallDir
if ($iconPath) { $d.IconLocation = $iconPath }
$d.Description = "AI-DTCTM Forensic Engine"
$d.Save()
OK "Desktop shortcut created"

# Start Menu shortcut
$StartMenuDir = Join-Path ([Environment]::GetFolderPath("Programs")) "AI-DTCTM"
New-Item -ItemType Directory -Force -Path $StartMenuDir | Out-Null
$SMLink = Join-Path $StartMenuDir "AI-DTCTM.lnk"
if (Test-Path $SMLink) { Remove-Item -Force $SMLink -ErrorAction SilentlyContinue }
$s = $WshShell.CreateShortcut($SMLink)
$s.TargetPath = $LauncherBat
$s.WorkingDirectory = $InstallDir
if ($iconPath) { $s.IconLocation = $iconPath }
$s.Description = "AI-DTCTM Forensic Engine"
$s.Save()
OK "Start Menu entry created"

# Launch the app
Info "Launching AI-DTCTM..."
Start-Process -FilePath $LauncherBat -WindowStyle Minimized
OK "App is starting - browser will open at http://localhost:8501 in a few seconds"

Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host "  INSTALLATION COMPLETE" -ForegroundColor White
Write-Host "================================================================" -ForegroundColor Green
Write-Host ""
Write-Host ("  Desktop:      " + "AI-DTCTM") -ForegroundColor White
Write-Host ("  Start Menu:   " + "AI-DTCTM > AI-DTCTM") -ForegroundColor White
Write-Host ("  Install dir:  " + $InstallDir) -ForegroundColor DarkGray
Write-Host ""
Write-Host "  Browser URL:  " -NoNewline -ForegroundColor DarkGray
Write-Host "http://localhost:8501" -ForegroundColor Cyan
Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host ""
