# AI-DTCTM — Day 1 Master Setup Guide

> **Author:** Dhanush S (311424622006)
> **Guide:** Mrs. S. Padmavathi, AP/MCA
> **College:** Meenakshi College of Engineering
> **Version:** 20.0.0 (Mission Control edition)

This is your single source of truth for Day 1. Work top-to-bottom. Don't skip steps. Every install explains **WHY** you need it, **HOW** to install, and **HOW to verify** it's working.

---

## Table of Contents

1. What we're building (vision recap)
2. System requirements
3. Software installations (in order)
4. API registrations (all FREE)
5. Dataset downloads
6. Project folder setup
7. Environment variables (.env)
8. First run & verification
9. Day 2 preview

---

## 1. What we're building — vision recap

**AI-DTCTM = AI-powered Digital Twin Cyber Threat Mitigation**

Racing-car analogy: a Ferrari engineer doesn't crash the real car — they build a digital twin, crash the twin, learn from the damage, and keep the real car safe.

You do the same for web systems:
- Real URL / real file / real network → clone it into an isolated Docker container → attack the clone → capture real vulnerability proof → original system stays untouched.

**What becomes real in this rebuild:**

| Component | Before | After |
|---|---|---|
| ML accuracy | Synthetic data, fake 98.8% | CICIDS2017 real data, honest 95%+ |
| URL scanning | "NOT_CHECKED" placeholders | VirusTotal + GSB + URLScan + PhishTank + AbuseIPDB live |
| Digital Twin | JSON file | Real Docker containers running DVWA / WebGoat / Juice Shop |
| Attack engine | Pre-written fake results | Real HTTP attacks on live containers with real DB dumps |
| Shield Monitor | Random fake packets | Real psutil + AbuseIPDB + IP geolocation |
| File sandbox | Regex only | YARA rules + MalwareBazaar hash lookup (safe, legal) |
| Threat Intel | Hardcoded CVEs | Live NVD + CISA KEV + AlienVault OTX |
| UI | Generic cyan hacker theme | Unique "Mission Control" warm-amber Bloomberg-terminal look |

---

## 2. System requirements

Before you install anything, check that your machine can handle this:

| Item | Minimum | Recommended |
|---|---|---|
| OS | Windows 10 / macOS 11 / Ubuntu 20.04+ | Windows 11 / macOS 13+ / Ubuntu 22.04+ |
| RAM | 8 GB | 16 GB |
| Disk free | 20 GB | 40 GB |
| CPU | Dual-core 2.0 GHz | Quad-core 2.5 GHz+ |
| Internet | Required for API calls | Broadband for Docker image pulls |

Check your specs:
- **Windows:** Press `Win + R` → type `msinfo32` → Enter
- **macOS:** Apple menu → About This Mac
- **Linux:** `free -h` and `df -h` in terminal

If you're short on RAM, skip Docker Desktop's default resource allocation tweak later (we'll allocate only 4 GB to Docker).

---

## 3. Software installations

Install in this exact order. Don't jump ahead.

---

### 3.1 Python 3.11 or newer

**WHY:** The whole project is Python. Streamlit 1.35+ needs Python 3.10 minimum; we use 3.11 features.

**HOW:**
1. Open a terminal.
2. Check current version: `python --version` (or `python3 --version`)
3. If it says 3.11 or higher → skip to 3.2.
4. If older or missing → download from https://www.python.org/downloads/
   - Windows: run installer, **tick "Add Python to PATH"** at the bottom
   - macOS: use the installer, or `brew install python@3.11`
   - Ubuntu: `sudo apt install python3.11 python3.11-venv python3-pip`

**VERIFY:**
```bash
python --version       # Should print Python 3.11.x or newer
pip --version          # Should print pip 23.x or newer
```

**TROUBLESHOOT:**
- `python` command not found on Windows → reinstall and tick "Add to PATH"
- Multiple versions installed → use `py -3.11` on Windows or `python3.11` on macOS/Linux

---

### 3.2 Git

**WHY:** Version control. Also needed to clone DVWA-related repos and for the GitHub Actions CI you'll add.

**HOW:**
- Windows: https://git-scm.com/download/win → run installer, use all defaults
- macOS: `brew install git` or Xcode Command Line Tools (`xcode-select --install`)
- Ubuntu: `sudo apt install git`

**VERIFY:**
```bash
git --version          # Should print git version 2.x
```

---

### 3.3 Docker Desktop

**WHY:** This is the single most important install. Docker gives you real isolated containers — the actual Digital Twins. Without Docker, the twin stays fake.

**HOW:**
1. Download from https://www.docker.com/products/docker-desktop/
2. **Windows:** requires WSL2. The installer will prompt you to enable WSL2 — say yes. Restart when asked.
3. **macOS:** download the Apple Silicon or Intel `.dmg` (check `About This Mac` for chip).
4. **Linux:** follow https://docs.docker.com/engine/install/ubuntu/ for Docker Engine (lighter than Desktop).
5. After install, open Docker Desktop. Wait for the whale icon in your system tray to stop animating (~30 sec).
6. Settings → Resources → set Memory to at least 4 GB, Disk to 20 GB.

**VERIFY:**
```bash
docker --version       # Docker version 25.x or newer
docker run hello-world # Should print "Hello from Docker!"
```

**Pull the vulnerable app images we'll use as Digital Twin targets:**
```bash
docker pull vulnerables/web-dvwa
docker pull webgoat/goat-and-wolf
docker pull bkimminich/juice-shop
```

Each pull is ~500 MB — 1.5 GB total. Do this on decent Wi-Fi.

**VERIFY IMAGES:**
```bash
docker images
# You should see dvwa, webgoat, and juice-shop listed
```

**Quick smoke test of DVWA:**
```bash
docker run --rm -d -p 8081:80 --name dvwa-test vulnerables/web-dvwa
# Wait 5 seconds, then open http://localhost:8081 in your browser
# You should see the DVWA setup page
# When done: docker stop dvwa-test
```

**TROUBLESHOOT:**
- Windows "WSL 2 installation is incomplete" → open PowerShell as Admin, run `wsl --update`, restart
- `docker: Cannot connect to the Docker daemon` → Docker Desktop app not running; open it
- Mac M1/M2 "no matching manifest" → add `--platform linux/amd64` flag to docker run commands

---

### 3.4 VS Code + extensions (optional but strongly recommended)

**WHY:** Not required, but makes your life 10x easier. Good syntax highlighting, Docker integration, debugger.

**HOW:**
1. Download https://code.visualstudio.com/
2. Install these extensions (Ctrl+Shift+X in VS Code):
   - **Python** (Microsoft) — required
   - **Pylance** (Microsoft) — smart type checking
   - **Docker** (Microsoft) — manage containers from sidebar
   - **Ruff** (charliermarsh) — super-fast linter
   - **GitLens** — inline git blame
   - **Better Comments** — color-coded TODO/FIXME

---

### 3.5 Python packages

**WHY:** All the libraries the project depends on — Streamlit, scikit-learn, Docker SDK, YARA, requests, etc.

**HOW:** After you've dropped the starter files into a project folder (section 6 below), run:
```bash
cd AI_DTCTM
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

pip install --upgrade pip
pip install -r requirements.txt
```

Why a virtual environment (`.venv`)? Isolates project dependencies from system Python. Professional practice. Mam will notice.

**VERIFY:**
```bash
pip list | grep streamlit   # should show streamlit 1.35+
pip list | grep docker      # should show docker SDK
pip list | grep yara        # should show yara-python
```

**TROUBLESHOOT:**
- `yara-python` install fails on Windows → install Visual C++ Build Tools: https://visualstudio.microsoft.com/visual-cpp-build-tools/
- `yara-python` install fails on macOS → `brew install yara` first
- `Microsoft Visual C++ 14.0 or greater is required` → same fix as above

---

## 4. API registrations — all FREE

Register in this order. Save every API key into a text file named `api_keys_scratch.txt` on your desktop — we'll move them into `.env` in section 7.

**Rule:** never commit API keys to Git. Ever. The `.gitignore` we'll add blocks `.env` automatically.

---

### 4.1 VirusTotal

**WHY:** 87 antivirus engines check every URL/file you submit. Returns "23/87 engines flagged this as malicious." Industry standard.

**FREE TIER:** 4 requests/minute, 500/day.

**HOW:**
1. Go to https://www.virustotal.com/gui/join-us
2. Sign up (email verification).
3. Log in → click your username top-right → **API Key**.
4. Copy the 64-character hex string.
5. Save as: `VIRUSTOTAL_API_KEY=<your-key>`

**VERIFY (from terminal):**
```bash
curl -H "x-apikey: YOUR_KEY" "https://www.virustotal.com/api/v3/urls/aHR0cHM6Ly9leGFtcGxlLmNvbQ=="
# Should return JSON, not 401 Unauthorized
```

---

### 4.2 Google Safe Browsing

**WHY:** Google's own phishing/malware database. Very accurate on brand-name phishing (bank sites, etc.).

**FREE TIER:** 10,000 requests/day — huge.

**HOW:**
1. Go to https://console.cloud.google.com/
2. Sign in with Google account.
3. Create a new project: top bar "Select a project" → "NEW PROJECT" → name it `AI-DTCTM`.
4. In the search bar, type "Safe Browsing API" → select it → click **Enable**.
5. Left sidebar → APIs & Services → **Credentials** → **Create Credentials** → **API Key**.
6. Copy the key (starts with `AIza...`).
7. **Important:** click "Restrict Key" → under API restrictions select "Safe Browsing API" only. Saves you from abuse.
8. Save as: `GOOGLE_SB_API_KEY=<your-key>`

---

### 4.3 URLScan.io

**WHY:** Actually browses the URL in a sandbox, takes a screenshot, maps all external scripts. Beautiful for phishing forensics.

**FREE TIER:** 100 scans/day, 1000 searches/day.

**HOW:**
1. Go to https://urlscan.io/user/signup
2. Sign up with email.
3. Log in → profile icon → **Settings & API**.
4. Click "Generate API key" → copy.
5. Save as: `URLSCAN_API_KEY=<your-key>`

---

### 4.4 PhishTank

**WHY:** Community-verified phishing URL database. Zero false positives because humans vote on every URL.

**FREE TIER:** Unlimited.

**HOW:**
1. Go to https://www.phishtank.com/
2. Top right → **Register**.
3. After email verification, log in → **My Account** → **Application Keys**.
4. Click "Request API Key" (free, instant).
5. Save as: `PHISHTANK_API_KEY=<your-key>`

---

### 4.5 AbuseIPDB

**WHY:** IP reputation database. For your Shield Monitor — "this IP that's hammering your server has 1,247 past abuse reports, block it."

**FREE TIER:** 1,000 checks/day, 100 reports/day.

**HOW:**
1. Go to https://www.abuseipdb.com/register
2. Register + email verify.
3. Account → **API** tab → **Create Key**.
4. Name it `AI-DTCTM` → copy the 80-char key.
5. Save as: `ABUSEIPDB_API_KEY=<your-key>`

---

### 4.6 AlienVault OTX (Open Threat Exchange)

**WHY:** Community threat intel feed. Real-time indicators of compromise (IoCs) — malicious IPs, domains, file hashes — updated every few minutes.

**FREE TIER:** Unlimited (with fair-use).

**HOW:**
1. Go to https://otx.alienvault.com/
2. Top right → **Sign Up**.
3. Email verify → log in → top right profile icon → **Settings**.
4. Scroll to "OTX Key" → copy.
5. Save as: `OTX_API_KEY=<your-key>`

---

### 4.7 Shodan

**WHY:** "Google for internet-connected devices." Given an IP, returns open ports, running services, known vulnerabilities. Extremely impressive in demos.

**FREE TIER:** 100 queries/month (per account). Use sparingly.

**HOW:**
1. Go to https://account.shodan.io/register
2. Register, email verify.
3. Home page → top right "Account" → copy the "API Key" shown on dashboard.
4. Save as: `SHODAN_API_KEY=<your-key>`

---

### 4.8 No-registration APIs (use directly, no key needed)

These are already free and public — no signup, just use the URL in code:

| API | What it does | Endpoint |
|---|---|---|
| **NVD CVE API** | Every known CVE with CVSS scores | https://services.nvd.nist.gov/rest/json/cves/2.0 |
| **CISA KEV** | Actively exploited CVEs (government feed) | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json |
| **MalwareBazaar** | Hash-based malware lookup (abuse.ch) | https://mb-api.abuse.ch/api/v1/ |
| **URLhaus** | Malicious URL feed (abuse.ch) | https://urlhaus-api.abuse.ch/v1/ |
| **ThreatFox** | IoC feed (abuse.ch) | https://threatfox-api.abuse.ch/api/v1/ |

---

## 5. Dataset downloads

### 5.1 CICIDS2017 — for real ML training (Week 3)

**WHY:** University of New Brunswick's real labeled network attack dataset. ~2.8M rows of real DoS, port scans, web attacks, brute force, infiltration, etc. Replaces your synthetic data.

**HOW:**
1. Go to https://www.unb.ca/cic/datasets/ids-2017.html
2. Scroll down → click the download form link → fill name + email + "student research" as purpose.
3. Download link will be emailed to you (MachineLearningCVE.zip, ~2 GB).
4. Extract into `AI_DTCTM/data/cicids2017/` — you'll get 8 CSV files.
5. **For Day 1, just download.** Training happens in Week 3.

**Sampled version (faster to start):**
For development we only need 200K rows. When we write the training script we'll use `pandas.read_csv(..., nrows=200_000)` and stratified sampling. Saves RAM, same accuracy.

---

## 6. Project folder setup

### 6.1 New folder structure

```
AI_DTCTM/
├── .env                          # Secret keys (never commit)
├── .env.example                  # Template to share
├── .gitignore
├── Dockerfile                    # Containerize the app itself
├── docker-compose.yml            # One-command full-stack spin-up
├── requirements.txt              # Python deps
├── pyproject.toml                # Modern Python config
├── README.md                     # Viva-grade docs
├── DAY1_SETUP_GUIDE.md           # This file
│
├── main_project.py               # Streamlit entrypoint
├── auth_ui.py                    # Login page
├── config.py                     # Config profiles (dev/demo/prod)
│
├── core/
│   ├── __init__.py
│   ├── cache.py                  # SQLite TTL cache (rate-limit safety)
│   ├── logger.py                 # Structured JSON logger
│   ├── shared_css.py             # Mission Control theme (NEW)
│   ├── db_manager.py
│   ├── rbac.py
│   │
│   ├── ml_engine.py              # CICIDS2017 training (Week 3)
│   ├── url_analyzer.py           # URL checks
│   ├── twin_manager.py           # Real Docker twin (Week 2)
│   ├── attack_engine.py          # Real HTTP attacks on DVWA (Week 2)
│   ├── shield_engine.py          # psutil + AbuseIPDB monitor
│   ├── threat_intel_engine.py    # NVD + CISA KEV live
│   ├── compliance_engine.py
│   ├── geo_engine.py
│   ├── notif_engine.py
│   ├── report_gen.py
│   │
│   ├── api_clients/              # All external APIs wrapped (NEW)
│   │   ├── __init__.py
│   │   ├── virustotal.py
│   │   ├── google_safebrowsing.py
│   │   ├── urlscan.py
│   │   ├── phishtank.py
│   │   ├── abuseipdb.py
│   │   ├── otx.py
│   │   ├── shodan_client.py
│   │   ├── nvd.py
│   │   ├── cisa_kev.py
│   │   ├── malware_bazaar.py
│   │   ├── urlhaus.py
│   │   └── threatfox.py
│   │
│   └── yara_rules/               # Malware detection rules (NEW)
│       ├── generic.yar
│       ├── ransomware.yar
│       └── webshells.yar
│
├── _pages/                       # Streamlit multi-page sub-pages
│   ├── pg_admin.py
│   ├── pg_compliance.py
│   ├── pg_darkweb.py
│   ├── pg_explainer.py
│   ├── pg_geomap.py
│   ├── pg_notif.py
│   └── pg_zerotrust.py
│
├── tests/                        # pytest smoke tests (NEW)
│   ├── __init__.py
│   ├── test_cache.py
│   ├── test_api_clients.py
│   └── test_smoke.py
│
├── scripts/                      # One-off utility scripts
│   ├── train_ml_model.py         # CICIDS2017 training runner
│   ├── pull_docker_images.sh
│   └── verify_apis.py
│
├── .github/workflows/
│   └── ci.yml                    # GitHub Actions lint + test
│
├── docs/
│   ├── architecture.md
│   └── demo_script.md
│
├── data/
│   ├── securex.db                # App SQLite
│   ├── cache.db                  # TTL cache SQLite (NEW)
│   └── cicids2017/               # Dataset CSVs
│
├── models/                       # Saved ML models
├── reports/                      # Generated PDF forensic reports
└── virtual_twins/                # Twin session snapshots
```

### 6.2 Setup steps

```bash
# Choose a clean location
mkdir ~/projects && cd ~/projects

# Copy the starter pack here (you'll get AIDTCTM_STARTER.zip from Claude)
unzip AIDTCTM_STARTER.zip
mv aidtctm_starter AI_DTCTM
cd AI_DTCTM

# Create venv + install
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install --upgrade pip
pip install -r requirements.txt

# Copy env template
cp .env.example .env
# Now edit .env and paste your API keys from section 4
```

---

## 7. Environment variables

After registering APIs, fill `.env` (NOT `.env.example` — that stays as a template).

```bash
# ── Profile ───────────────────────────────────────
DTCTM_PROFILE=dev                # dev | demo | prod

# ── Secrets ───────────────────────────────────────
DTCTM_SECRET=change-me-32-char-random-string-here

# ── External APIs ────────────────────────────────
VIRUSTOTAL_API_KEY=paste-here
GOOGLE_SB_API_KEY=paste-here
URLSCAN_API_KEY=paste-here
PHISHTANK_API_KEY=paste-here
ABUSEIPDB_API_KEY=paste-here
OTX_API_KEY=paste-here
SHODAN_API_KEY=paste-here

# ── Database (optional — SQLite works out of box) ─
DTCTM_DB_TYPE=sqlite             # sqlite | mysql
DTCTM_DB_HOST=localhost
DTCTM_DB_PORT=3306
DTCTM_DB_USER=root
DTCTM_DB_PASS=
DTCTM_DB_NAME=securex_db

# ── Docker twin config ───────────────────────────
DOCKER_TWIN_NETWORK=aidtctm_twin_net
DOCKER_DVWA_PORT=8081
DOCKER_WEBGOAT_PORT=8082
DOCKER_JUICESHOP_PORT=8083

# ── Cache ────────────────────────────────────────
CACHE_DEFAULT_TTL=300            # seconds
```

Generate your secret key:
```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

---

## 8. First run & verification

```bash
# 1. Activate venv
source .venv/bin/activate    # Windows: .venv\Scripts\activate

# 2. Verify APIs are reachable (Day 1 smoke test)
python scripts/verify_apis.py

# Expected: ✅ VirusTotal, ✅ GSB, ✅ URLScan, etc.

# 3. Launch the app
streamlit run main_project.py

# App opens at http://localhost:8501
# You should see the NEW Mission Control amber theme
```

---

## 9. Day 2 preview

Tomorrow we wire:
- `core/api_clients/virustotal.py` → real scanning in URL analyzer
- `core/api_clients/google_safebrowsing.py` → real phishing check
- `core/api_clients/urlscan.py` → real sandbox scan
- Caching layer wrapped around all 3 (so you don't burn rate limits)
- Real `core/twin_manager.py` using Docker SDK
- Real `core/attack_engine.py` attacking DVWA container

Then Week 2 Day 3-5: real attacks, Week 3: ML retrain, Week 4: polish.

---

## Status tracker — tick as you complete

```
Software:
[ ] Python 3.11+
[ ] Git
[ ] Docker Desktop
[ ] DVWA / WebGoat / Juice Shop images pulled
[ ] VS Code + extensions

API keys registered & saved to .env:
[ ] VirusTotal
[ ] Google Safe Browsing
[ ] URLScan.io
[ ] PhishTank
[ ] AbuseIPDB
[ ] AlienVault OTX
[ ] Shodan

Project:
[ ] Starter pack unzipped
[ ] venv created
[ ] requirements.txt installed
[ ] .env configured with all keys
[ ] scripts/verify_apis.py all green
[ ] streamlit run main_project.py shows Mission Control theme

Data:
[ ] CICIDS2017 CSVs downloaded to data/cicids2017/
```

When all ticked → message me `"day 1 done"` and we start Day 2.
