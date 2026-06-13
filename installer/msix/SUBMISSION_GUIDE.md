# Microsoft Store Submission Guide — AI-DTCTM

This is the ONLY path to a fully-trusted-by-WDAC Windows install for free.
Once Microsoft signs your `.msix`, it runs on any Windows machine including
the corporate / college laptops with strict code-integrity policies.

## Total time: ~1 hour (plus 24-48 h Microsoft review wait)

---

## Step 1 — Create Microsoft Partner Center account (FREE since 2022)

1. Go to https://partner.microsoft.com/dashboard/registration
2. Sign in with your personal Microsoft account (or create one — use a real
   email that you check regularly, Microsoft will email there)
3. Pick "Individual" account type → enter your real name + address
4. **Fee:** Microsoft removed the $19/₹1,500 individual dev fee in 2022.
   It's free.
5. Wait 1-2 business days for Microsoft to verify your identity (they
   sometimes call to confirm)

## Step 2 — Reserve your app name

1. In Partner Center → Apps and games → Create a new app
2. Enter name: **AI-DTCTM** (or "AI-DTCTM Forensic Engine" if the short
   name is taken)
3. Microsoft holds the name for you for 3 months

## Step 3 — Build the .msix package

You have 2 options:

### Option A — MSIX Packaging Tool (GUI, easiest)

1. Install **MSIX Packaging Tool** from Microsoft Store (it's free)
2. Open it → "Create package from installer"
3. Point it at `D:\AI_DTCTM\installer\Output\AI-DTCTM-Setup-1.0.0.exe`
4. Run through the wizard — it observes the install and captures everything
5. Output: `AI-DTCTM.msix` (~150 MB)

### Option B — Manual via SDK (advanced)

```cmd
cd D:\AI_DTCTM\installer\msix
makeappx pack /d <full-path-to-dist\AI-DTCTM-Launcher> /p AI-DTCTM.msix
signtool sign /fd SHA256 /a /f cert\AI-DTCTM-CodeSign.pfx /p Aidtctm!2026 AI-DTCTM.msix
```

Use the `AppxManifest.xml` already in this folder as your manifest.

## Step 4 — Generate Store assets

You need these PNGs in `Assets\` folder (or use the Partner Center web tool
to auto-generate from a single 1080×1080 source):

- `StoreLogo.png` — 50×50
- `Square44x44Logo.png` — 44×44
- `Square71x71Logo.png` — 71×71
- `Square150x150Logo.png` — 150×150
- `Square310x310Logo.png` — 310×310
- `Wide310x150Logo.png` — 310×150
- `SplashScreen.png` — 620×300

Easy generator: https://www.appicon.co/ (uploads one image, gives all sizes)

## Step 5 — Submit

1. Partner Center → your app → "Packages" → upload `AI-DTCTM.msix`
2. Fill in:
   - **Description** — paste from `Properties/Description` in AppxManifest.xml
   - **Screenshots** — at least 1 (take from running app)
   - **Age rating** — Run the IARC questionnaire (your app: no violence /
     gambling / NSFW → rated 3+)
   - **Categories** — Developer tools → Security
3. Pricing → Free
4. Submit for review

## Step 6 — Wait

- Microsoft review: **24-48 hours typically**
- They check: malware scan, certification requirements, manifest validity
- You get an email when approved

## Step 7 — Distribute

Once approved:
- Public Microsoft Store URL: `https://apps.microsoft.com/store/detail/DhanushS.AIDTCTM`
- Users search "AI-DTCTM" in Windows Store and install
- **Microsoft signs the .msix automatically** → trusted by WDAC by default
- Runs on YOUR laptop too (WDAC trusts Microsoft Store apps)

---

## Why this beats every other path

| Path | Works on WDAC laptop? | Looks professional? | Free? |
|---|---|---|---|
| Self-signed .exe | ❌ blocked by WDAC | ✓ | ✓ |
| EV Code Signing cert ($360/yr) | ✓ if cert pre-trusted | ✓ | ❌ |
| **Microsoft Store .msix** | ✓ | ✓ (Store listing!) | ✓ |
| Setup.exe (no sign) | ❌ blocked by WDAC | ⚠ SmartScreen warning | ✓ |

Microsoft Store is the only path that gives you all 3: ✓ trusted, ✓ professional,
✓ free.

---

## Common rejection reasons (avoid these)

1. **No description / screenshots** — fill them in
2. **Manifest version mismatch** — keep `Version="1.0.0.0"` consistent
3. **App doesn't launch within 5 sec** — our launcher handles this
4. **Crashes on first run** — test in MSIX sandbox first via "App
   Installer"

If rejected, Microsoft gives detailed reasons. Fix → resubmit. Usually
1-2 iterations get you certified.

---

## After certification

Every time you ship a new version:
1. Bump `Version="1.0.1.0"` in AppxManifest.xml
2. Rebuild .msix
3. Upload to Partner Center
4. Submit — usually approved in 4-8 hours for updates (faster than initial)

Users get auto-updates via Microsoft Store. No manual installer to ship.
