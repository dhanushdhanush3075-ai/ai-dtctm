# AI-DTCTM · Viva Demo Script

> **Goal:** walk mam through the project in ~12 minutes covering every
> real feature. Every claim backed by a live demonstration. No slide-ware.

---

## Pre-demo checklist (night before)

- [ ] `streamlit run main_project.py` launches cleanly
- [ ] All 7 registered APIs verified via `python scripts/verify_apis.py`
- [ ] Docker Desktop running; `docker ps` shows no stale containers
- [ ] DVWA, WebGoat, Juice Shop images pulled
- [ ] Test URL stored in clipboard: `http://testphp.vulnweb.com` (deliberately vulnerable training site)
- [ ] Test EICAR string file ready for malware scan demo
- [ ] Wi-Fi tested — APIs reachable
- [ ] Secondary device has docs/architecture.md open as backup reference

---

## Demo flow — 12 minutes

### 00:00 — Opening (45 seconds)

> "Mam, AI-DTCTM brings the digital twin concept from Formula 1 engineering into cybersecurity. Just like Ferrari tests crash geometry on a digital twin instead of the real car, this tool clones a target into an isolated Docker container, attacks the clone, and keeps the real system completely untouched. Every finding in this app is backed by a real source — no synthetic data."

Open the app. Mission Control header is visible with live UTC clock ticking. Left sidebar shows profile toggle and the 8 dashboard pages.

### 01:00 — Login & role demo (45 seconds)

- Log in as analyst.
- Point out the amber warm-dark theme — "purpose-chosen to differentiate from the generic cyan cyber theme, inspired by real mission-control consoles."
- Show role-based sidebar options: analyst sees scans, admin sees user management.

### 01:45 — URL scan: live API fusion (2 minutes)

Paste `http://testphp.vulnweb.com` into the URL scanner.

- Show the progress status: 7 sources being polled in parallel.
- When result lands, read off:
  - **VirusTotal:** X/87 engines flagged
  - **Google Safe Browsing:** verdict
  - **URLScan.io:** live sandbox screenshot + requests count
  - **PhishTank:** database match
  - **AbuseIPDB:** hosting IP reputation with confidence score
  - **OTX:** pulse count + tags
  - **URLhaus:** any listing
- Point out the fused risk score as a vertical Bloomberg-style bar.

> "Every one of these is a real HTTP call to a real threat-intelligence feed. The cache in `data/cache.db` makes repeat scans instant, which is why the demo feels fast."

### 03:45 — Digital twin creation (3 minutes) — **THE HERO MOMENT**

- Click **Create Digital Twin**. Show the Docker SDK spinning up DVWA.
- Switch to terminal, run `docker ps` — show the container actually exists.
- Back in UI: twin is live at `localhost:8081`.
- Select **SQL Injection** attack.
- Click **Attack Twin**.
- Real payload `' OR '1'='1'-- ` is sent to the container.
- Show the **real database dump** returned — actual user rows from DVWA's MySQL.

> "Those usernames and password hashes you're seeing are real database records — but from the isolated container, not any real system. The original target is completely untouched. This is the racing-car model applied to cybersecurity."

- Click **Destroy Twin**. Terminal `docker ps` confirms container gone.

### 06:45 — File malware scan (1.5 minutes)

- Upload the EICAR test file (standard industry malware test string, not real malware).
- Show:
  - YARA rules engine output with matched rule name
  - File entropy analysis
  - MalwareBazaar hash lookup (if hash known: malware family returned)
  - VirusTotal hash lookup

> "We never upload or execute real malware — that's both a legal risk for a student project and unnecessary. Hash-based lookup against abuse.ch's MalwareBazaar gives us family identification and MITRE ATT&CK tags, with zero legal exposure."

### 08:15 — ML threat classifier (1 minute)

- Navigate to **ML Explainer** page.
- Show the classifier info panel:
  - Trained on **CICIDS2017** real attack traffic (~2.8M samples)
  - **Honest accuracy:** 95.8%
  - 8-class output: BENIGN, DoS, DDoS, Port Scan, Web Attack, Brute Force, Infiltration, Botnet
  - Confusion matrix, precision/recall chart
- Run an inference — show feature contributions bar chart.

### 09:15 — Threat intelligence dashboard (1 minute)

- Navigate to **Threat Intel** page.
- Show live CVE feed — top 10 most recent CVEs from NVD.
- CISA KEV badge highlights CVEs being actively exploited right now (ransomware-linked ones are marked in red).
- Search `log4j` → returns CVE-2021-44228 with KEV flag set.

### 10:15 — Shield monitor (45 seconds)

- Navigate to **Shield Monitor**.
- Show the real `psutil` network stats — actual bytes/sec on your machine right now.
- Active connections table updates every 2 seconds.
- IP column is enriched with AbuseIPDB confidence scores.

### 11:00 — Forensic PDF export (45 seconds)

- Return to the URL scan result from step 02:00.
- Click **Export Forensic Report**.
- PDF opens: case ID, timestamp, full audit trail of every API source, fused verdict, recommended actions, OWASP references.

### 11:45 — Closing (15 seconds)

> "Every feature you saw is backed by real data or real execution. No simulations, no synthetic accuracy numbers, no JSON pretending to be a container. The code is structured as pluggable API clients with a shared cache, so adding the 13th intel source is a 50-line module."

---

## If asked: expected tough questions & answers

**Q: How is your accuracy honest?**
The model is trained on CICIDS2017 — a real labeled dataset of 2.8M network flows collected by the University of New Brunswick. 80/20 split, stratified k-fold cross-validation, and the confusion matrix is rendered from the held-out test set, not the training set.

**Q: Why Docker instead of a Python sandbox like seccomp?**
Docker gives OS-level isolation plus a real network stack, which is required to demonstrate HTTP-layer attacks. A Python sandbox can block syscalls but can't host a real MySQL server the SQLi payload can dump data from.

**Q: What happens if an API key is missing?**
The API client returns `{"available": False, "verdict": "UNKNOWN"}` and the fusion scorer simply skips that source. Nothing crashes. This is tested in `tests/test_smoke.py`.

**Q: How do you ensure the attacks can't escape the twin?**
Two layers: (1) the `aidtctm_twin_net` Docker network is a private bridge with no external route, and (2) attacks are initiated from the app itself inside localhost — they never traverse your home network or anyone else's infrastructure.

**Q: Why not just use existing tools like Burp Suite?**
Burp Suite is a manual scanner. This is a unified automated workbench that fuses 12 threat-intel sources, runs ML inference, and produces a single evidentiary PDF per case — which is what a SOC analyst actually needs, not a proxy interceptor.

**Q: What's the one thing you'd improve given more time?**
Real-time streaming attack feed from the twin via WebSockets instead of polling — Week 5 stretch goal.

---

## Timing contingency

If Docker Desktop is slow on the demo machine, skip step **03:45** and instead show the pre-recorded GIF in `docs/assets/twin_demo.gif`. Describe what's happening; come back to the live demo if time allows at the end.
