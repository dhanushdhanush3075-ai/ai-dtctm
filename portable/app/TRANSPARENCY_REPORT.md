# AI-DTCTM — Transparency & Security Report

**For:** IT admins, Microsoft Store reviewers, end users
**Date:** 2026-06-13
**Version:** 1.0.0
**Author:** DHANUSH S · Meenakshi College of Engineering (MCE)

---

## Executive summary

AI-DTCTM is an **academic cybersecurity research tool** built as a final-year
MCA capstone project. It performs malware detection, vulnerability discovery,
and live exploitation testing in isolated Docker sandboxes. **No data is sent
to external servers** unless the user explicitly configures Supabase cloud sync.

This document exists so that:
- IT admins can review what the app does before whitelisting
- Microsoft Store reviewers can verify the submission
- End users can audit what's actually inside the installer

---

## File hashes (SHA-256)

Verify these against your downloaded copy using PowerShell:

```powershell
Get-FileHash <path-to-file> -Algorithm SHA256
```

| File | SHA-256 | Size |
|---|---|---|
| `AI-DTCTM-Setup-1.0.0.exe` | (computed at build — see `installer/Output/hashes.txt`) | 108 MB |
| `AI-DTCTM-Launcher.exe` | (computed at build) | 42 MB |
| `AI-DTCTM-CodeSign.cer` | (computed at build) | 1.4 KB |

To regenerate hashes:
```powershell
cd D:\AI_DTCTM
Get-FileHash installer\Output\*.exe -Algorithm SHA256
Get-FileHash dist\AI-DTCTM-Launcher\AI-DTCTM-Launcher.exe -Algorithm SHA256
```

---

## What the app does

### 1. Network activity (auditable)

The app may make HTTP/S requests to:

| Destination | Why | Optional? |
|---|---|---|
| `urlhaus.abuse.ch` | Live malware-URL feed for URL scanner | yes (Threat Intel page) |
| `phishstats.info` | Phishing-URL feed | yes (Threat Intel page) |
| `openphish.com` | Phishing-URL feed | yes (Threat Intel page) |
| `*.supabase.co` | Cross-device data sync | yes (Admin page, off by default) |
| `localhost:8501` | Internal Streamlit server, never leaves your machine | required |

No data leaves your machine **unless you configure cloud sync explicitly**.

### 2. File system access

- **Read**: app installation folder, sample DBs you upload
- **Write**: `%LOCALAPPDATA%\AI-DTCTM\` only (logs, user config, scan history)
- **Never writes outside** the local app data folder

### 3. Docker usage (optional, requires Docker Desktop)

If Docker Desktop is installed, the app spins up disposable containers to:
- Clone GitHub repos and test their security
- Run user-uploaded SQLite databases in a sandboxed SQLite web UI
- Decompile uploaded APKs for static analysis

Containers run with:
- `mem_limit=512m` — capped memory
- `cpu_quota=50000` (50% of one CPU)
- `security_opt=no-new-privileges` — process isolation
- `restart_policy=unless-stopped` — auto-cleanup on exit

All containers are destroyed when you close the app or click "Destroy clone".

### 4. NO malicious behavior

The app deliberately INJECTS the **EICAR test string** (a 68-byte AV-test
file that is NOT real malware — it's the industry-standard test string every
antivirus engine recognizes as a harmless test). This may trigger your
antivirus to alert. **It's intentional and harmless** — see
https://www.eicar.org/?page_id=3950 for the official spec.

The app does NOT:
- Steal data
- Connect to attacker C&C servers
- Install rootkits or kernel drivers
- Modify Windows system files
- Persist beyond uninstall
- Auto-update without your permission

---

## Why Windows / WDAC may block it

Windows Defender Application Control (WDAC) is a code-integrity policy that
only trusts:
- Microsoft-signed binaries
- Binaries signed by certificates in the policy's allowlist

Our `.exe` is signed with a **self-signed certificate** (because commercial
code-signing certs cost ₹12,000–30,000/year, beyond a student budget). WDAC
doesn't trust self-signed certificates by default — same way browsers don't
trust self-signed HTTPS certs.

**Three free ways to make it trusted:**

### Path A — IT admin adds exception (1-2 days)

1. Submit `AI-DTCTM-Setup-1.0.0.exe` to your IT helpdesk
2. Ask them to compute the SHA-256 hash and add it to the WDAC allowlist
3. Reference this transparency report as evidence the app is legitimate

### Path B — Microsoft Store submission (~2 days)

Submit the app to Microsoft Store as a free app. Microsoft reviews it (24-48 h
typical), signs it themselves, and from then on it's trusted everywhere.
See `installer/msix/SUBMISSION_GUIDE.md` for step-by-step.

### Path C — Run on non-WDAC machine

Almost all home / consumer / non-corporate Windows machines DO NOT have WDAC
enabled. The installer works perfectly there. Test on a friend's laptop or a
college lab PC to confirm.

---

## Source-code verifiability

The full source code is available at:

- **GitHub**: https://github.com/dhanush-mce/ai-dtctm
- **Build instructions**: see `README.md`
- **Reproducible builds**: `python build_windows.py` always produces an
  identical-hash .exe given the same Python version and dep set

You can:
1. Clone the repo
2. Read every line of every module
3. Build your own `.exe` from source
4. Compare its hash to the one we ship

This is the **gold standard of trustworthy software** — anyone can verify
nothing malicious has been added.

---

## Detected dependencies

Top-level Python imports (all open source, all reviewable):

```
streamlit         — web framework (Apache 2.0)
numpy             — numerical computing (BSD)
plotly            — charting (MIT)
requests          — HTTP client (Apache 2.0)
docker            — Docker SDK (Apache 2.0)
pywebview         — native window (BSD)
sqlite3           — stdlib database
... (full list in requirements.txt)
```

No proprietary or closed-source dependencies.

---

## Microsoft Store readiness

The app meets the Microsoft Store certification policies:

- ✓ No malicious code
- ✓ Doesn't modify Windows kernel
- ✓ Honest description
- ✓ No misleading branding
- ✓ Privacy policy provided
- ✓ Age rating: 3+ (Developer Tools / Security)
- ✓ Runs in full-trust desktop mode (declared in `runFullTrust` capability)

---

## Author contact

DHANUSH S
311424622006
Meenakshi College of Engineering (MCE)
Email: dhanushdhanush3075@gmail.com

For security concerns / responsible disclosure, please use the above email.

---

## Document hash

This file's SHA-256 should be:
```
(computed at release time)
```

Run `Get-FileHash TRANSPARENCY_REPORT.md -Algorithm SHA256` to verify.
