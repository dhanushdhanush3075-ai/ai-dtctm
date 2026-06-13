"""
AI-DTCTM — One-Command GitHub Deploy
══════════════════════════════════════════════════════════════════════
Does the entire GitHub upload + release creation in ONE Python script.
No drag-drop. No web UI confusion. Run once → public installer URL live.

WHAT IT DOES (in order)
─────────────────
  1. Asks you for GitHub username + personal access token
  2. Initialises a git repo (if not already)
  3. Writes a hardened .gitignore (excludes huge dirs + secrets)
  4. Stages + commits all source code
  5. Creates a public repo via GitHub API
  6. Pushes the code
  7. Creates a v1.0.0 release
  8. Uploads AI-DTCTM-Setup-1.0.0.exe as a release asset
  9. Prints the public download URL

PREREQUISITES
─────────────
  • Git installed (you have it: git 2.53.0)
  • Internet access
  • Free GitHub account (sign up at github.com/signup)
  • GitHub Personal Access Token (script tells you how)

USAGE
─────
  python deploy_to_github.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT      = Path(__file__).resolve().parent
INSTALLER = ROOT / "installer" / "Output" / "AI-DTCTM-Setup-1.0.0.exe"
README    = ROOT / "README.md"
RELEASE_TAG = "v1.0.0"

# ── ASCII helpers for cp1252 Windows console ────────────────────────
def banner(txt: str) -> None:
    print()
    print("=" * 72)
    print(f"  {txt}")
    print("=" * 72)


def ask(prompt: str, secret: bool = False) -> str:
    if secret:
        import getpass
        return getpass.getpass(prompt).strip()
    return input(prompt).strip()


def run(cmd: list[str], check: bool = True,
         capture: bool = False) -> subprocess.CompletedProcess:
    print(f"  >> {' '.join(cmd)}")
    return subprocess.run(
        cmd, cwd=ROOT, check=check,
        capture_output=capture, text=True,
    )


# ── GitHub API call helper ──────────────────────────────────────────
def gh_api(method: str, path: str, token: str, *,
            data=None, content_type: str = "application/json",
            extra_headers: dict | None = None) -> tuple[int, dict]:
    """Call the GitHub REST API. Returns (status, parsed-json-or-bytes)."""
    url = f"https://api.github.com{path}" if path.startswith("/") else path
    headers = {
        "Authorization":         f"Bearer {token}",
        "Accept":                "application/vnd.github+json",
        "X-GitHub-Api-Version":  "2022-11-28",
        "User-Agent":            "AI-DTCTM-Deploy/1.0",
        "Content-Type":          content_type,
    }
    if extra_headers:
        headers.update(extra_headers)
    body = None
    if data is not None:
        body = json.dumps(data).encode() if isinstance(data, dict) else data
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=90) as resp:
            status = resp.status
            raw = resp.read()
            if content_type == "application/json":
                return status, json.loads(raw) if raw else {}
            return status, raw
    except urllib.error.HTTPError as e:
        err_body = e.read()
        try:
            return e.code, json.loads(err_body) if err_body else {"error": str(e)}
        except Exception:
            return e.code, {"error": err_body.decode("utf-8", "replace")[:300]}


# ── Stage 0 — pre-flight checks ─────────────────────────────────────
def preflight() -> bool:
    banner("Stage 0 — Pre-flight")
    if not INSTALLER.exists():
        print(f"  [FAIL] Installer missing: {INSTALLER}")
        print("         Run `python build_windows.py` first.")
        return False
    print(f"  [OK] Installer present: {INSTALLER.stat().st_size // (1024*1024)} MB")
    try:
        run(["git", "--version"], capture=True)
    except FileNotFoundError:
        print("  [FAIL] git is not installed. Get it from git-scm.com.")
        return False
    print("  [OK] git available")
    return True


# ── Stage 1 — collect credentials ──────────────────────────────────
def collect_creds() -> tuple[str, str, str, str]:
    banner("Stage 1 — GitHub credentials")
    print("""
  You need a Personal Access Token. To create one:
    1. Sign in at github.com
    2. Open https://github.com/settings/tokens/new
    3. Tick scopes:    "repo"  +  "workflow"
    4. Generate token and COPY it (one-time visible)
    5. Paste it below

  Your token stays on your machine — never sent anywhere except GitHub.
""")
    username = ask("  GitHub username     : ")
    if not username:
        print("  username is required")
        sys.exit(1)
    token    = ask("  Personal access token (hidden): ", secret=True)
    if not token or not token.startswith(("ghp_", "github_pat_")):
        print("  Token doesn't look right — should start with ghp_ or github_pat_")
        sys.exit(1)
    repo_name = ask("  Repository name [ai-dtctm]: ") or "ai-dtctm"
    full_name = ask(f"  Full display name  [{username} - MCE]: ") \
                or f"{username} - MCE"
    return username, token, repo_name, full_name


# ── Stage 2 — .gitignore + git init ────────────────────────────────
GITIGNORE = """\
# AI-DTCTM auto-generated .gitignore
# Excludes runtime artifacts, secrets, huge bundles, environments.

# Python
__pycache__/
*.pyc
*.pyo
*.pyd

# Virtual envs
.venv/
venv/
env/

# Build artifacts — too big for git (100 MB push limit), shipped as release assets
build/
dist/
release/
installer/Output/
*.spec

# Editor scratch
*.tmp.*
*.swp
*.swo

# Logs and runtime data
logs/
*.log
data/source_clones/
data/apk_clones/
data/apk_workbench/
data/screenshots/
data/cache.db

# Secrets — NEVER COMMIT THESE
.env
*.pfx
installer/cert/*.pfx
installer/_temp/

# Quarantined dead code (we already archived it)
_archive/

# IDE
.vscode/
.idea/

# OS
.DS_Store
Thumbs.db
"""


def git_init() -> None:
    banner("Stage 2 — git init + .gitignore")
    if not (ROOT / ".git").exists():
        run(["git", "init"])
        print("  [OK] git repo initialised")
    else:
        print("  [OK] git repo already initialised")
    (ROOT / ".gitignore").write_text(GITIGNORE, encoding="utf-8")
    print("  [OK] .gitignore written")
    run(["git", "branch", "-M", "main"], check=False)


# ── Stage 3 — commit ───────────────────────────────────────────────
def git_commit() -> None:
    banner("Stage 3 — Stage + commit")
    run(["git", "add", "."])
    # Set local author identity so the commit doesn't fail
    run(["git", "config", "user.email", "dhanushdhanush3075@gmail.com"], check=False)
    run(["git", "config", "user.name",  "DHANUSH S"], check=False)
    # Allow empty commit failure if nothing changed
    result = subprocess.run(
        ["git", "commit", "-m", "AI-DTCTM v1.0.0 — initial public release"],
        cwd=ROOT, capture_output=True, text=True,
    )
    if result.returncode == 0:
        print("  [OK] commit created")
    elif "nothing to commit" in (result.stdout + result.stderr).lower():
        print("  [OK] nothing new to commit (already committed)")
    else:
        print(f"  [WARN] commit returned {result.returncode}: {result.stderr.strip()}")


# ── Stage 4 — create remote repo via API ──────────────────────────
def create_remote(username: str, token: str, repo: str, display: str) -> str:
    banner("Stage 4 — Create remote repository on GitHub")
    # Check if it already exists
    status, body = gh_api("GET", f"/repos/{username}/{repo}", token)
    if status == 200:
        print(f"  [OK] Repo already exists at https://github.com/{username}/{repo}")
        return f"https://github.com/{username}/{repo}"
    # Create
    status, body = gh_api(
        "POST", "/user/repos", token,
        data={
            "name":          repo,
            "description":   "AI Digital Twin Cybersecurity Threat Management",
            "homepage":      "",
            "private":       False,
            "has_issues":    True,
            "has_wiki":      False,
            "auto_init":     False,
        },
    )
    if status in (201, 202):
        url = body.get("html_url", f"https://github.com/{username}/{repo}")
        print(f"  [OK] Repo created at {url}")
        return url
    print(f"  [FAIL] GitHub API returned {status}: {body}")
    sys.exit(1)


# ── Stage 5 — push ─────────────────────────────────────────────────
def git_push(username: str, token: str, repo: str) -> None:
    banner("Stage 5 — Push to GitHub")
    # Configure the remote URL with embedded credentials (one-shot, not stored)
    remote = f"https://{username}:{token}@github.com/{username}/{repo}.git"
    # Remove any old origin, add fresh
    run(["git", "remote", "remove", "origin"], check=False)
    run(["git", "remote", "add", "origin", remote])
    # Push the branch
    push = subprocess.run(
        ["git", "push", "-u", "origin", "main"],
        cwd=ROOT, capture_output=True, text=True,
    )
    if push.returncode == 0:
        print("  [OK] Source code pushed")
    else:
        # Try force-push (case where remote auto-init created a README)
        print("  Initial push failed — trying force push to overwrite remote default README…")
        force = subprocess.run(
            ["git", "push", "-u", "origin", "main", "--force"],
            cwd=ROOT, capture_output=True, text=True,
        )
        if force.returncode != 0:
            print(f"  [FAIL] push: {force.stderr.strip()}")
            sys.exit(1)
        print("  [OK] Source code pushed (force)")
    # Wipe the embedded-credentials remote so the .git/config doesn't store the token
    safe = f"https://github.com/{username}/{repo}.git"
    run(["git", "remote", "set-url", "origin", safe])


# ── Stage 6 — create release ──────────────────────────────────────
def create_release(username: str, token: str, repo: str) -> dict:
    banner(f"Stage 6 — Create release {RELEASE_TAG}")
    notes = f"""\
First public release of AI-DTCTM.

## Downloads

- **AI-DTCTM-Setup-1.0.0.exe** — single-file Windows installer

## What's inside

- 19 security modules across 11 dashboards
- Pure-NumPy malware ML (no DLL dependencies)
- Docker-isolated digital twins (source code / SQLite DB / APK)
- 22 SQL injection payload library (tautology / UNION / blind-time)
- 13 real exploitation attacks with NIST 800-53 mitigation playbook
- 3-tier RBAC (Analyst / Admin / SuperAdmin) with team scoping
- Optional Supabase cloud sync

## System requirements

- Windows 10 1809 (build 17763) or later, 64-bit
- 2 GB RAM minimum, 4 GB recommended
- 500 MB disk
- Docker Desktop optional (for digital-twin features)

## First-run

1. Download the installer
2. Right-click -> Properties -> tick **Unblock** -> Apply
3. Double-click installer -> follow wizard
4. Launch from desktop shortcut
5. App auto-generates a SuperAdmin invite code on first run

## SHA-256 checksums

```
37C7DA28FA4ACD55AE6F694C8F6FF92EF56F98822F239AB38AEBF9A6D43DB99D  AI-DTCTM-Setup-1.0.0.exe
```

Verify with:
```powershell
Get-FileHash AI-DTCTM-Setup-1.0.0.exe -Algorithm SHA256
```

## Security note

This is a final-year MCA capstone project. The app deliberately injects
the official 68-byte EICAR antivirus test string (https://www.eicar.org/)
into isolated Docker containers as part of the EICAR test. This is the
industry-standard AV test file — not real malware — but your antivirus
may briefly alert during the test. This is intentional.

Full transparency report: TRANSPARENCY_REPORT.md in the source.

---

Author: DHANUSH S - Meenakshi College of Engineering (MCE)
"""
    status, body = gh_api(
        "POST", f"/repos/{username}/{repo}/releases", token,
        data={
            "tag_name":         RELEASE_TAG,
            "target_commitish": "main",
            "name":             f"AI-DTCTM {RELEASE_TAG} - Initial release",
            "body":             notes,
            "draft":            False,
            "prerelease":       False,
            "make_latest":      "true",
        },
    )
    if status in (201, 200):
        print(f"  [OK] Release created: {body.get('html_url','?')}")
        return body
    print(f"  [FAIL] {status}: {body}")
    sys.exit(1)


# ── Stage 7 — upload installer ────────────────────────────────────
def upload_asset(release: dict, token: str) -> str:
    banner("Stage 7 — Upload installer as release asset")
    upload_url_tmpl = release["upload_url"]
    # Template form is "https://uploads.github.com/.../assets{?name,label}"
    upload_url = upload_url_tmpl.split("{")[0] + f"?name={INSTALLER.name}"

    print(f"  Uploading {INSTALLER.name}  "
          f"({INSTALLER.stat().st_size // (1024*1024)} MB) - this may take 2-10 min...")
    with open(INSTALLER, "rb") as f:
        body = f.read()
    status, resp = gh_api(
        "POST", upload_url, token,
        data=body, content_type="application/octet-stream",
    )
    if status in (200, 201):
        url = resp.get("browser_download_url", "?")
        print(f"  [OK] Uploaded: {url}")
        return url
    print(f"  [FAIL] upload returned {status}: {resp}")
    sys.exit(1)


# ── Main ───────────────────────────────────────────────────────────
def main() -> int:
    if not preflight():
        return 1
    username, token, repo, display = collect_creds()
    git_init()
    git_commit()
    repo_url = create_remote(username, token, repo, display)
    git_push(username, token, repo)
    release = create_release(username, token, repo)
    download_url = upload_asset(release, token)

    banner("DONE")
    print(f"  Repository:     {repo_url}")
    print(f"  Release:        {release.get('html_url', '?')}")
    print(f"  Installer URL:  {download_url}")
    print()
    print("  Share that installer URL with your examiner / classmates.")
    print("  Anyone can download + install AI-DTCTM with one click.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
