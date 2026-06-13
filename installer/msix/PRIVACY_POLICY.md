# AI-DTCTM — Privacy Policy

**Effective date:** 2026-06-13
**Version:** 1.0.0
**Last updated:** 2026-06-13

This Privacy Policy describes how AI-DTCTM ("the App") handles your data.
This App is published by **DHANUSH S** as an academic capstone project at
Meenakshi College of Engineering (MCE).

---

## What we collect

**The App stores ALL data locally on your device.** Specifically:

| Data type | Where stored | When deleted |
|---|---|---|
| Your account (username, email, hashed password) | `%LOCALAPPDATA%\AI-DTCTM\data\users.db` | When you uninstall |
| Scan history (URLs, file hashes, verdicts) | `%LOCALAPPDATA%\AI-DTCTM\data\scan_history.db` | When you click "Clear history" or uninstall |
| Audit trail (admin actions) | `%LOCALAPPDATA%\AI-DTCTM\data\audit_trail.db` | When you uninstall |
| Application logs | `%LOCALAPPDATA%\AI-DTCTM\logs\` | Rotates at 10 MB × 5 backups |
| App configuration | `%LOCALAPPDATA%\AI-DTCTM\.env` | When you uninstall |

**We do NOT collect:**
- Personally identifiable information beyond your chosen username + email
- Browsing history, keyboard input, screen contents, or microphone/camera data
- Files outside the ones you explicitly upload to the App

---

## What we send over the network

The App makes network requests only in specific scenarios:

### Public threat-intelligence feeds (optional, on the Threat Intel page)

When you open the Threat Intel page, the App fetches public, anonymous data from:

- **URLhaus** (`urlhaus-api.abuse.ch`) — public malware URL database (Creative Commons license)
- **OpenPhish** (`openphish.com`) — public phishing URL list
- **PhishStats** (`phishstats.info`) — public phishing statistics

No personal data is sent in these requests. The endpoints don't require API keys.

### Optional Supabase cloud sync (DISABLED by default)

If — and ONLY if — you explicitly configure Supabase by editing the `.env`
file and entering your own Supabase URL and anonymous key, then:

- Your scan history rows are sent to YOUR Supabase project
- The connection uses HTTPS only
- The data is stored in YOUR Supabase account, not ours
- We never see this data; we don't have access to your Supabase project

This feature exists for cross-device team scenarios. **It is off by default.**

### Crash telemetry: NONE

We do NOT send crash reports, usage statistics, error traces, or any other
telemetry to any server, ours or third-party. Streamlit's built-in telemetry
is explicitly disabled in our launcher (`--browser.gatherUsageStats false`).

---

## Docker isolation

If you have Docker Desktop installed, the App may spin up disposable Docker
containers to:

- Clone GitHub repositories and run security tests on isolated copies
- Run user-uploaded SQLite databases in a sandboxed web UI for forensic analysis
- Decompile uploaded APK files for static analysis

All containers:

- Run with capped memory (512 MB) and CPU (50 % of one core)
- Run with `no-new-privileges` security flag
- Are destroyed when you close the App or click "Destroy clone"
- Are NEVER pushed to a public registry

We do not collect data about what you analyze in these containers.

---

## Third-party services

The App is built using these open-source libraries (full list in `requirements.txt`):

- Streamlit (Apache 2.0)
- NumPy (BSD)
- Plotly (MIT)
- Requests (Apache 2.0)
- pywebview (BSD)
- Docker SDK for Python (Apache 2.0)

None of these libraries phone home with your data. They are loaded locally
and run inside the App's process.

---

## Children's privacy

The App is rated 3+ but is intended for adult / professional / academic use.
We do not knowingly collect data from anyone under 13. If you believe a child
has used the App, please contact us at the email below — though there is
nothing for us to delete, because we don't collect data centrally.

---

## Your rights

Because all data is stored locally:

- **Right to access** — Open `%LOCALAPPDATA%\AI-DTCTM\` to see every file.
- **Right to delete** — Uninstall the App, or run
  `AI-DTCTM-Launcher.exe --reset`.
- **Right to portability** — The SQLite databases can be opened in any
  SQLite viewer.

If you enable Supabase cloud sync, the data in YOUR Supabase account is
subject to Supabase's privacy policy — see https://supabase.com/privacy.

---

## Changes to this policy

We may update this policy if the App's behavior changes. The "Last updated"
date at the top reflects the latest version.

---

## Contact

**DHANUSH S**
311424622006
Meenakshi College of Engineering (MCE)
Email: dhanushdhanush3075@gmail.com

For security concerns or privacy questions, please email above.
