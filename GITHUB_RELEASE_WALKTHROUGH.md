# 🚀 GitHub Releases — Your App Live in 15 Minutes

Microsoft Partner Center is currently restricted for new Indian individual
accounts (Microsoft policy, not your fault). **GitHub Releases is the
faster, simpler, equally legitimate alternative** used by every major
open-source security tool — Wireshark, Nmap, Metasploit, OWASP ZAP, etc.

After this walkthrough you will have:
- A public GitHub repo at `https://github.com/<your-username>/ai-dtctm`
- A downloadable installer at
  `https://github.com/<your-username>/ai-dtctm/releases/download/v1.0.0/AI-DTCTM-Setup-1.0.0.exe`
- Version-tagged releases (v1.0.0, v1.0.1, etc.)
- A README that displays automatically on the repo home page

Total time: **15 minutes work + 0 wait time.**

---

## ⏱ Phase 1 — GitHub account (5 min)

### Step 1
Open https://github.com/signup

### Step 2
Sign up with your Gmail address:
- **Email**: `dhanushdhanush3075@gmail.com`
- **Password**: pick a strong one (NOT the same as Microsoft)
- **Username**: pick something like `dhanush-mce` or `dhanushs311424622006`
  - This becomes part of your URL: `github.com/dhanush-mce/...`
  - Pick something professional — examiners will see it

### Step 3
Verify your email by clicking the link GitHub sends.

### Step 4
GitHub asks about your preferences:
- Free tier ✓
- Student / educational
- Skip the team setup

### ✅ At this point: you have a free GitHub account.

---

## ⏱ Phase 2 — Create the repo (3 min)

### Step 5
Click the **green "New"** button (top-right corner, near your avatar)
OR go to https://github.com/new

### Step 6
Fill the form:
- **Repository name**: `ai-dtctm`
- **Description**: `AI Digital Twin Cybersecurity Threat Management — forensic engine for malware detection, vulnerability discovery, and live exploitation testing.`
- **Visibility**: **Public**
- **Initialize with README**: tick this ✓
- Add `.gitignore`: choose **Python** from dropdown
- License: **MIT License** (most common for academic / open-source)

### Step 7
Click **Create repository**.

### ✅ At this point: empty repo created at github.com/<your-username>/ai-dtctm

---

## ⏱ Phase 3 — Upload source code (5 min)

### Step 8
On the repo home page, click **Add file** → **Upload files**.

### Step 9
Open Windows Explorer at `D:\AI_DTCTM\`. **Drag-drop** these into the
GitHub upload area:

**Include (drag these in):**
```
core/                ← all your security modules
_pages/              ← all your Streamlit pages
assets/              ← icons
sample_databases/    ← demo SQLite DBs
installer/           ← Inno Setup script + cert files
main_project.py
auth_ui.py
config.py
launcher.py
build_windows.py
requirements.txt
README.md
QUICKSTART.md
TRANSPARENCY_REPORT.md
package_for_release.py
```

**EXCLUDE (do NOT upload — too big or sensitive):**
```
.venv/                  ← virtual env (huge, regenerated)
dist/                   ← built bundles (huge, regenerated)
build/                  ← PyInstaller intermediate (huge)
release/                ← we'll attach the .exe separately
data/                   ← runtime user data (sensitive)
logs/                   ← log files
__pycache__/            ← Python cache
_archive/               ← quarantined dead code
installer/cert/*.pfx    ← PRIVATE KEY — never publish this
installer/_temp/        ← downloaded installers
```

### Step 10
Below the file list, write a commit message:
```
Initial release v1.0.0 — full source code
```

Click **Commit changes**.

### ✅ At this point: your code is publicly visible on GitHub.

---

## ⏱ Phase 4 — Create the Release (2 min)

This is where the **downloadable .exe** gets attached.

### Step 11
On your repo home page, click **Releases** (right sidebar, under "About").

### Step 12
Click **Create a new release**.

### Step 13
**Choose a tag** → type `v1.0.0` → click "Create new tag: v1.0.0 on publish".

### Step 14
**Release title**: `AI-DTCTM v1.0.0 — Initial release`

### Step 15
**Description** — copy-paste this block:

```markdown
First public release of AI-DTCTM — AI Digital Twin Cybersecurity Threat Management.

## 📦 Downloads

| File | What | Size |
|---|---|---|
| `AI-DTCTM-Setup-1.0.0.exe` | One-click Windows installer | 108 MB |
| `AI-DTCTM-v1.0.0.zip` | Portable bundle (no install needed) | 163 MB |

## ✨ Features

- 19 security modules across 11 dashboards
- Pure-NumPy malware detection (no DLL load requirements)
- Docker-isolated digital twins for source code, databases, and APK files
- 22 SQL injection payloads across 3 categories (tautology, UNION, blind/time)
- 13 real exploitation attacks with NIST 800-53 mapped mitigations
- 3-tier role-based access control with team scoping
- Optional Supabase cloud sync for cross-device replication

## 🛠 System requirements

- Windows 10 version 1809 (build 17763) or later, 64-bit
- 2 GB RAM minimum (4 GB recommended)
- 500 MB free disk space
- Docker Desktop (optional — only for twin features)

## 🔐 File hashes (SHA-256)

```
37C7DA28FA4ACD55AE6F694C8F6FF92EF56F98822F239AB38AEBF9A6D43DB99D  AI-DTCTM-Setup-1.0.0.exe
DBFFB1EFDC93D9202FAE5485B5DCE0A60DAB496DB6641B6AFD05B0D32F21109C  AI-DTCTM-Launcher.exe
F12E6FFB467958CF636E9185F8C3277B7AF9F2AB811B7C9206CC4B10E343EF2E  AI-DTCTM-v1.0.0.zip
```

Verify with:
```powershell
Get-FileHash AI-DTCTM-Setup-1.0.0.exe -Algorithm SHA256
```

## 🚦 First-run

1. Download the installer
2. Right-click → **Properties** → tick **Unblock** → Apply
3. Double-click installer → follow wizard → install
4. Launch from desktop shortcut
5. App auto-generates a SuperAdmin invite code on first run

## 🛡 Security note

This is an academic capstone project. Full transparency report:
[TRANSPARENCY_REPORT.md](https://github.com/<your-username>/ai-dtctm/blob/main/TRANSPARENCY_REPORT.md)

The app deliberately injects the EICAR test string (the official 68-byte
industry-standard antivirus test file) into isolated Docker containers during
the EICAR test. Your antivirus may briefly alert. This is intentional and harmless.

## 📚 Documentation

- [README.md](https://github.com/<your-username>/ai-dtctm/blob/main/README.md) — full feature overview
- [QUICKSTART.md](https://github.com/<your-username>/ai-dtctm/blob/main/QUICKSTART.md) — 5-minute setup guide
- [TRANSPARENCY_REPORT.md](https://github.com/<your-username>/ai-dtctm/blob/main/TRANSPARENCY_REPORT.md) — security audit

---

**Author**: DHANUSH S · Meenakshi College of Engineering (MCE) · 311424622006
```

### Step 16
**Attach binaries** — scroll down to "Attach binaries" section. Drag-drop:

- `D:\AI_DTCTM\installer\Output\AI-DTCTM-Setup-1.0.0.exe` (108 MB)
- `D:\AI_DTCTM\release\AI-DTCTM-v1.0.0.zip` (163 MB, optional)

GitHub uploads them (~2-5 min depending on your network).

### Step 17
Tick **Set as the latest release** ✓

### Step 18
Click **Publish release**.

### ✅ DONE.

---

## 🎉 What you have now

Your downloadable installer is at:
```
https://github.com/<your-username>/ai-dtctm/releases/download/v1.0.0/AI-DTCTM-Setup-1.0.0.exe
```

Share this URL with:
- Your project committee / examiner
- Classmates
- Anyone who wants to try the app
- Add it to your CV / LinkedIn / portfolio

## 📋 What examiners will see

When they visit your repo:
- Professional README at the top of the page
- "Releases" section with v1.0.0 prominently displayed
- Source code browsable
- Star count / fork count visible
- Issues tab for bug reports

When they download:
- Standard browser download
- They'll see "Windows protected your PC" SmartScreen warning the first time
- They click "More info" → "Run anyway"
- Installer wizard opens → install → app runs

This is **identical** to how Wireshark / Nmap / Notepad++ ship. Examiners will recognize it as standard open-source distribution.

## 🆚 GitHub vs Microsoft Store comparison

| Aspect | GitHub Releases | Microsoft Store |
|---|---|---|
| Setup time | 15 min | 2 hours + 2 day wait |
| Cost | ₹0 | ₹0 |
| Public download URL | ✓ | ✓ |
| Version tagging | ✓ | ✓ |
| SmartScreen warning first time | ⚠ Yes | ✓ No (Microsoft-signed) |
| Works on WDAC-locked corp PCs | ⚠ Needs admin override | ✓ Yes |
| Looks professional for viva | ✓ Standard open-source pattern | ✓ Store-listed |
| Microsoft account required | ✗ No | ✓ Yes (currently blocked for you) |
| Auto-updates | ✗ Manual | ✓ Auto via Store |

**For a college viva project, GitHub Releases is the right answer.** Most
open-source security projects use it. It signals "serious developer who
ships on GitHub" not "couldn't get Microsoft Store working."

## 🆘 If you want to also try Microsoft Store later

You can do BOTH — GitHub Releases now (for your viva), and Microsoft Store
later when the account restriction clears. Wait 60-90 days, retry Partner
Center, follow `installer/msix/PARTNER_CENTER_WALKTHROUGH.md`. By then
Microsoft's fraud crackdown may have eased and your account may be eligible.

## ➡️ Right now, do Phase 1 — create GitHub account

Sign up at https://github.com/signup → reply to me with your username when
done → I'll walk you through Phase 2-4 immediately.
