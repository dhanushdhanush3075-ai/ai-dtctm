# AI-DTCTM — Microsoft Store Listing Copy

Copy-paste these values straight into Partner Center fields when submitting.

═══════════════════════════════════════════════════════════════════
## App name (App identity → Reserve name)
═══════════════════════════════════════════════════════════════════

```
AI-DTCTM Forensic Engine
```

If taken, fallback options:
```
AI-DTCTM by DHANUSH
AI-DTCTM Threat Manager
```

═══════════════════════════════════════════════════════════════════
## Short description (max 200 chars)
═══════════════════════════════════════════════════════════════════

```
AI-powered Digital Twin Cybersecurity Threat Management — pure-NumPy malware
detection, Docker-isolated source/DB/APK twins, 22 SQL injection payloads,
NIST mitigations.
```

(199 characters — fits the limit)

═══════════════════════════════════════════════════════════════════
## Description (max 10,000 chars — paste this block as-is)
═══════════════════════════════════════════════════════════════════

```
AI-DTCTM is a comprehensive forensic engine for malware detection, vulnerability
discovery, and live exploitation testing — designed for security analysts,
academic researchers, and students learning offensive and defensive security.

🛡 19 SECURITY MODULES IN ONE APP

• Real-time URL scanner — browser-warning-grade phishing and malware
  classification using a pure-NumPy machine-learning model (no DLL load
  requirements, works on locked-down corporate machines)

• 6-layer forensic file scanner — YARA-style pattern detection, deep code
  analysis, malware signature matching, base64 obfuscation detection,
  high-entropy packed-payload detection, and behavioural heuristic scoring

• Digital twin sandbox — clone any GitHub repository, SQLite database, or
  Android APK into a disposable Docker container, then run 13 real attacks
  (EICAR test virus, Python pickle RCE, zip-slip CVE-2018-1002101, PHP
  webshell, Local File Inclusion, HTTP header injection, GTUBE email AV
  test, LOLBin pattern detection, Windows PE-header anomaly, macro-enabled
  Office document, custom YARA self-test, malicious PDF, file-upload
  webshell) — with NIST 800-53 mapped mitigation playbook and automated
  verification pass

• Industry-grade SQL injection lab — 22 hand-crafted payloads across 3
  categories (classic tautology, UNION-based exfil, blind / time-based),
  plus a CMD-style terminal for ad-hoc SQL testing, plus a brute-force
  runner that fires up to 1000 payloads with per-category hit-rate stats

• Live threat intelligence — pulls public feeds from URLhaus, OpenPhish,
  and PhishStats for up-to-date IOC enrichment

• Shield Monitor — real-time port scan and active-connection map for the
  local host, with CVE association lookup for risky ports (SMB 445,
  Log4Shell 8080, MongoDB 27017, etc.)

• Analytics dashboard — model drift detection, A/B test logging, threat
  heat-map, geographic origin visualisation, and exportable PDF reports

• 3-tier role-based access — single-SuperAdmin model with team scoping
  (Analyst sees own data, Admin sees managed team, SuperAdmin sees all)
  enforced at every SQL query

• Optional Supabase cloud sync — cross-device data replication with
  row-level security policies matching the local RBAC

🎓 BUILT AS AN ACADEMIC PROJECT

AI-DTCTM is a final-year MCA capstone project by DHANUSH S at Meenakshi
College of Engineering. The full source code is reviewable on GitHub, every
build is reproducible from source, and a complete TRANSPARENCY_REPORT
documents what the app does (and what it does NOT do — no telemetry, no
tracking, no kernel drivers, no data leaves your device unless you
explicitly configure cloud sync).

The app deliberately injects the EICAR antivirus test string into isolated
Docker containers during the EICAR test — this is the official 68-byte
industry-standard AV test file (not real malware). Your antivirus may
briefly alert when the test runs; this is intentional and proves that
the detection pipeline works.

⚙ TECHNICAL REQUIREMENTS

• Windows 10 version 1809 (build 17763) or later
• 64-bit Intel/AMD processor
• 2 GB RAM minimum (4 GB recommended)
• 500 MB disk space
• Docker Desktop (optional — only needed for digital-twin features)
• Internet access (optional — only for threat-intel feeds and cloud sync)

🔒 PRIVACY

All data stays on your device by default. No telemetry, no usage stats,
no cloud upload unless you explicitly configure it.

Full privacy policy: https://github.com/dhanush-mce/ai-dtctm/blob/main/PRIVACY_POLICY.md

📚 ABOUT THE AUTHOR

DHANUSH S — Meenakshi College of Engineering, Tamil Nadu, India.
Submit feedback or report issues:
https://github.com/dhanush-mce/ai-dtctm/issues
```

═══════════════════════════════════════════════════════════════════
## What's new in this version (max 1500 chars)
═══════════════════════════════════════════════════════════════════

```
AI-DTCTM v1.0.0 — Initial public release.

• Native Windows desktop application with PyWebView + Edge WebView2
• Splash screen + smooth Fluent Design animations
• First-run wizard auto-generates SuperAdmin invite code
• Per-monitor DPI awareness for crisp text at 125%/150%/200%
• Production-mode Streamlit (no dev menu, no telemetry)
• 19 security modules across 11 pages (URL scan, forensic, twin, shield,
  threat intel, analytics, admin, batch scanner, AI assistant, threat
  timeline, advanced analytics)
• 22 SQL injection payloads + CMD-style terminal + 1000-attempt brute force
• 13 real exploitation attacks with NIST-mapped mitigations
• Optional Supabase cross-device sync (off by default)
• Diagnostic mode (--doctor) + reset mode (--reset)
• Log rotation (10 MB × 5 backups)
• Friendly error recovery UI on startup failures
```

═══════════════════════════════════════════════════════════════════
## Product features bullets (Partner Center "Features" field)
═══════════════════════════════════════════════════════════════════

```
• Pure-NumPy malware detection (no DLL dependencies)
• Docker-isolated digital twins (source / DB / APK)
• 22 SQL injection payloads + CMD terminal
• NIST 800-53 mapped mitigation playbook
• 3-tier role-based access control
• Optional cross-device cloud sync via Supabase
• 11 dashboards including real-time threat intel
• Full audit trail of privileged actions
• Reproducible builds, full source available
• Native Windows window with Fluent animations
```

═══════════════════════════════════════════════════════════════════
## Search terms / keywords (7 max)
═══════════════════════════════════════════════════════════════════

```
malware detection
vulnerability scanner
SQL injection
digital twin
forensic analysis
security tool
cybersecurity
```

═══════════════════════════════════════════════════════════════════
## Category + Subcategory
═══════════════════════════════════════════════════════════════════

```
Primary:   Developer tools
Secondary: Utilities & tools → Security
```

═══════════════════════════════════════════════════════════════════
## Copyright + Trademark info
═══════════════════════════════════════════════════════════════════

```
Copyright (c) 2026 DHANUSH S — Meenakshi College of Engineering.
Released as a final-year MCA capstone project.
```

═══════════════════════════════════════════════════════════════════
## Privacy policy URL
═══════════════════════════════════════════════════════════════════

Upload `installer/msix/PRIVACY_POLICY.md` to your GitHub repo, then use:

```
https://github.com/dhanush-mce/ai-dtctm/blob/main/installer/msix/PRIVACY_POLICY.md
```

═══════════════════════════════════════════════════════════════════
## Support contact info
═══════════════════════════════════════════════════════════════════

```
Email:       dhanushdhanush3075@gmail.com
Website:     https://github.com/dhanush-mce/ai-dtctm
Issues:      https://github.com/dhanush-mce/ai-dtctm/issues
```
