# AI-DTCTM — AI Digital Twin Cybersecurity Threat Management

Forensic engine for malware detection, vulnerability discovery, and live
exploitation testing — packaged as a native Windows desktop application.

```
┌──────────────────────────────────────────────────────────────────────┐
│  19 modules · 35,000 lines · 11 pages                                │
│  Real ML detection (pure NumPy — no DLL load requirements)           │
│  Docker-isolated digital twins (source code · database · APK)        │
│  22 SQL injection payloads · NIST-mapped mitigations · cloud sync    │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Quick install (Windows 10 / 11, 64-bit)

1. Download `AI-DTCTM-Setup-1.0.0.exe` from the Releases page.
2. Double-click to install. The wizard:
   * Installs to `C:\Program Files\AI-DTCTM\` (or `%LOCALAPPDATA%` if you
     don't want admin rights)
   * Creates desktop + Start menu shortcuts
   * Registers a clean uninstaller
3. Launch from the desktop icon. First-run is automatic:
   * A unique SuperAdmin invite code is generated and saved to
     `%LOCALAPPDATA%\AI-DTCTM\.env`
   * The web UI opens inside a native window — no browser tab required

**Prerequisite for full feature set:** install
[Docker Desktop](https://www.docker.com/products/docker-desktop) first.
Without it the URL scanner, file scanner, and ML detection still work,
but live attack lab features (source clone, database twin, APK twin)
are disabled.

---

## What's inside

| Page              | What it does                                                      |
| ----------------- | ----------------------------------------------------------------- |
| Overview          | Live KPIs from scan history                                       |
| URL Scanner       | Browser-warning-grade phishing/malware classifier (pure-numpy ML) |
| Forensic Scanner  | 6-layer file analysis with deep code scan                         |
| Digital Twin      | Clone a GitHub repo / SQLite DB / APK into an isolated Docker     |
|                   | container; run 13 real attacks (EICAR, pickle RCE, zip-slip,      |
|                   | webshell, LFI, header-injection, GTUBE, LOLBin, PE-anomaly,       |
|                   | macro-doc, YARA self-test + 2 more) with NIST-mapped              |
|                   | mitigation playbook and live verify pass                          |
| Shield Monitor    | Real-time port scan + active connection map                       |
| Threat Intel      | URLhaus, OpenPhish, PhishStats live feeds                         |
| Analytics         | Trend KPIs, threat heat-map, model-drift dashboard                |
| Admin             | User + team management, cloud-sync status, audit trail            |

---

## Build from source (developer mode)

```bash
git clone https://github.com/dhanush-mce/ai-dtctm.git
cd ai-dtctm
pip install -r requirements.txt
python launcher.py            # opens the native window
```

To produce the Windows installer:

```bash
pip install pywebview pyinstaller
python build_windows.py
```

Output:
- `dist/AI-DTCTM-Launcher/` — portable bundle (works on any Windows 10+)
- `installer/Output/AI-DTCTM-Setup-1.0.0.exe` — the installer to share

Requires [Inno Setup 6](https://jrsoftware.org/isdl.php) on PATH to compile
the .exe; without it the build still produces the portable bundle.

---

## Security model

* **3-tier RBAC** — Analyst (default, sees own data) → Admin (manages an
  Analyst team) → SuperAdmin (sees everything, exactly one allowed via
  bootstrap invite code).
* **Per-user data isolation** — `WHERE user_id = ?` enforced on every
  query that returns scan history. SuperAdmin bypasses, all other roles
  hard-scoped.
* **Audit trail** — every privileged action (promote / demote / assign)
  written to `audit_trail` table.
* **Cloud sync** (optional) — Supabase Postgres with Row-Level Security
  policies matching the local RBAC. Local SQLite stays authoritative;
  cloud is best-effort replication for cross-device team scenarios.

---

## Troubleshooting

| Symptom                            | Fix                                      |
| ---------------------------------- | ---------------------------------------- |
| App won't start                    | Run `AI-DTCTM-Launcher.exe --doctor`     |
| Splash never disappears            | Check `%LOCALAPPDATA%\AI-DTCTM\logs\`    |
| "Docker daemon unreachable"        | Start Docker Desktop, wait 60s, retry    |
| Forgot SuperAdmin invite code      | Open `%LOCALAPPDATA%\AI-DTCTM\.env`      |
| Reset everything (factory wipe)    | `AI-DTCTM-Launcher.exe --reset`          |

---

## Author

DHANUSH S · Meenakshi College of Engineering (MCE) · 311424622006
