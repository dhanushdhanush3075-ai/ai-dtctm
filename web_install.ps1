<#
================================================================
  AI-DTCTM — One-Command Web Installer
================================================================

The closest you can get to "tap to install" on Windows.

USAGE
=================================================================
  Open PowerShell on any Windows machine.
  Paste this ONE LINE and press Enter:

  irm https://raw.githubusercontent.com/dhanushdhanush3075-ai/ai-dtctm/main/web_install.ps1 | iex

  That's it. The rest happens automatically.

WHAT IT DOES (~3 minutes, fully automatic)
=================================================================
  [1/6] Verifies Python 3.10+ is installed
  [2/6] Downloads the latest portable ZIP from GitHub Releases
  [3/6] Extracts to %LOCALAPPDATA%\AI-DTCTM\
  [4/6] Installs Python dependencies (streamlit, numpy, etc.)
  [5/6] Creates Desktop + Start Menu shortcuts
  [6/6] Launches the app

WHY THIS IS WDAC-FRIENDLY
=================================================================
  This script only uses:
    - powershell.exe   (signed by Microsoft)
    - python.exe       (signed by Python Software Foundation)
    - .ps1 / .py files (data, not executables)

  NO unsigned .exe is ever executed. So Application Control / WDAC
  policies that block our regular installer DON'T block this one.
================================================================
#>

$ErrorActionPreference = "Stop"
$ProgressPreference    = "SilentlyContinue"

# Visual setup
$Host.UI.RawUI.WindowTitle = "AI-DTCTM Web Installer"
Clear-Host
function Section($n, $total, $msg) {
    Write-Host ""
    Write-Host ("[" + $n + "/" + $total + "] ") -NoNewline -ForegroundColor Cyan
    Write-Host $msg -ForegroundColor White
}
function OK($msg)   { Write-Host ("       [OK] " + $msg) -ForegroundColor Green }
function Info($msg) { Write-Host ("       " + $msg) -ForegroundColor DarkGray }
function Fail($msg) {
    Write-Host ""
    Write-Host ("       [FAIL] " + $msg) -ForegroundColor Red
    Write-Host ""
    Read-Host "Press Enter to exit"
    exit 1
}

# Banner
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
$TempZip     = Join-Path $env:TEMP "$AssetName"
# Download portable ZIP directly from the repo (no release-asset upload needed)
$downloadUrl = "https://raw.githubusercontent.com/$RepoOwner/$RepoName/$Branch/portable/$AssetName"

# ── Step 1: Verify Python ────────────────────────────────────────
Section 1 6 "Checking Python..."
$pythonExe = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $pythonExe) {
    Fail @"
Python is not installed or not on PATH.

  Please install Python 3.10 or later from:
      https://www.python.org/downloads/

  During install, TICK the "Add Python to PATH" checkbox.

  Then re-run this installer:
      irm https://raw.githubusercontent.com/$RepoOwner/$RepoName/main/web_install.ps1 | iex
"@
}
$pyVer = (& python --version 2>&1).Trim()
OK "Found $pyVer at $pythonExe"

# ── Step 2: Download portable ZIP ────────────────────────────────
Section 2 6 "Downloading AI-DTCTM portable package..."
Info "URL: $downloadUrl"
try {
    Invoke-WebRequest -Uri $downloadUrl -OutFile $TempZip -UseBasicParsing
} catch {
    Fail "Download failed: $($_.Exception.Message)"
}
$sizeMB = [math]::Round((Get-Item $TempZip).Length / 1MB, 1)
OK "Downloaded ${sizeMB} MB"

# ── Step 3: Extract to LOCALAPPDATA ─────────────────────────────
Section 3 6 "Installing app files to %LOCALAPPDATA%\AI-DTCTM\..."
if (Test-Path $InstallDir) {
    Info "Existing install detected - removing old version..."
    Remove-Item -Recurse -Force $InstallDir -ErrorAction SilentlyContinue
}
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
try {
    Expand-Archive -Path $TempZip -DestinationPath $InstallDir -Force
} catch {
    Fail "Extract failed: $($_.Exception.Message)"
}
Remove-Item $TempZip -Force -ErrorAction SilentlyContinue
# The ZIP root has a "app/" subfolder + install.bat at top level — move app/* up
$AppSubdir = Join-Path $InstallDir "app"
if (Test-Path $AppSubdir) {
    Get-ChildItem $AppSubdir | ForEach-Object {
        Move-Item -Force $_.FullName (Join-Path $InstallDir $_.Name)
    }
    Remove-Item $AppSubdir -Force -ErrorAction SilentlyContinue
}
OK "Files installed at $InstallDir"

# ── Step 4: Install Python dependencies ─────────────────────────
Section 4 6 "Installing Python dependencies (1-3 minutes)..."
Info "Running: python -m pip install --user -r requirements.txt"
$req = Join-Path $InstallDir "requirements.txt"
if (-not (Test-Path $req)) {
    Fail "requirements.txt not found in $InstallDir"
}
$pipOut = & python -m pip install --quiet --user --upgrade pip 2>&1
$pipOut = & python -m pip install --quiet --user -r $req 2>&1
if ($LASTEXITCODE -ne 0) {
    Fail "pip install returned $LASTEXITCODE. Output:`n$pipOut"
}
OK "Dependencies installed"

# ── Step 5: Create launcher + shortcuts ─────────────────────────
Section 5 6 "Creating launcher and shortcuts..."

# Write the launcher .bat
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

# Desktop shortcut
$WshShell      = New-Object -ComObject WScript.Shell
$DesktopLink   = Join-Path ([Environment]::GetFolderPath("Desktop")) "AI-DTCTM.lnk"
$d             = $WshShell.CreateShortcut($DesktopLink)
$d.TargetPath  = $LauncherBat
$d.WorkingDirectory = $InstallDir
if ($iconPath) { $d.IconLocation = $iconPath }
$d.Description = "AI-DTCTM Forensic Engine"
$d.Save()
OK "Desktop shortcut created"

# Start Menu folder + shortcut
$StartMenuDir = Join-Path ([Environment]::GetFolderPath("Programs")) "AI-DTCTM"
New-Item -ItemType Directory -Force -Path $StartMenuDir | Out-Null
$SMLink        = Join-Path $StartMenuDir "AI-DTCTM.lnk"
$s             = $WshShell.CreateShortcut($SMLink)
$s.TargetPath  = $LauncherBat
$s.WorkingDirectory = $InstallDir
if ($iconPath) { $s.IconLocation = $iconPath }
$s.Description = "AI-DTCTM Forensic Engine"
$s.Save()
OK "Start Menu entry created"

# ── Step 6: Launch the app ───────────────────────────────────────
Section 6 6 "Launching AI-DTCTM..."
Start-Process -FilePath $LauncherBat -WindowStyle Minimized
OK "App is starting - browser will open at http://localhost:8501 in a few seconds"

# ── Done ────────────────────────────────────────────────────────
Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host "  INSTALLATION COMPLETE" -ForegroundColor White
Write-Host "================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Desktop:      " -NoNewline -ForegroundColor DarkGray
Write-Host "AI-DTCTM" -ForegroundColor White
Write-Host "  Start Menu:   " -NoNewline -ForegroundColor DarkGray
Write-Host "AI-DTCTM > AI-DTCTM" -ForegroundColor White
Write-Host "  Install dir:  " -NoNewline -ForegroundColor DarkGray
Write-Host $InstallDir -ForegroundColor White
Write-Host ""
Write-Host "  Browser will open at:  " -NoNewline -ForegroundColor DarkGray
Write-Host "http://localhost:8501" -ForegroundColor Cyan
Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host ""
