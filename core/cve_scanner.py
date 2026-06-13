"""
AI-DTCTM | Dependency CVE Scanner
Checks requirements.txt / package.json against the OSV.dev public API
(completely free, no API key needed). Returns structured vuln findings
with severity label + fix version so the UI can render a table.
"""
from __future__ import annotations

import json
import re
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

_OSV_QUERY_URL  = "https://api.osv.dev/v1/query"
_OSV_BATCH_URL  = "https://api.osv.dev/v1/querybatch"   # kept for reference
_TIMEOUT = 20   # seconds per HTTP call
_WORKERS = 8    # parallel package lookups


# ─────────────────────────────────────────────────────────────────────
#  Parsers
# ─────────────────────────────────────────────────────────────────────

def _parse_requirements_txt(path: Path) -> list[tuple[str, str]]:
    """requirements.txt → [(name, version), ...]. Version may be ''."""
    pkgs: list[tuple[str, str]] = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "-", "git+", "http")):
            continue
        m = re.match(r"([A-Za-z0-9_\-\.]+)\s*(?:[>=<!~^]{1,2}\s*([0-9][^\s,;\[]*?))?(?:\s*[,;\[]|$)", line)
        if m:
            pkgs.append((m.group(1), m.group(2) or ""))
    return pkgs


def _parse_package_json(path: Path) -> list[tuple[str, str]]:
    """package.json deps + devDeps → [(name, cleaned_version), ...]."""
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return []
    pkgs: list[tuple[str, str]] = []
    for section in ("dependencies", "devDependencies"):
        for name, ver in (data.get(section) or {}).items():
            ver_clean = re.sub(r"[^0-9\.]", "", ver.lstrip("^~>=< "))
            pkgs.append((name, ver_clean))
    return pkgs


# ─────────────────────────────────────────────────────────────────────
#  OSV API
# ─────────────────────────────────────────────────────────────────────

def _osv_query_one(name: str, version: str, ecosystem: str) -> list[dict]:
    """POST to OSV /query for a single package → returns full vuln objects with severity."""
    payload: dict = {"package": {"name": name, "ecosystem": ecosystem}}
    if version:
        payload["version"] = version
    data_bytes = json.dumps(payload).encode()
    req = urllib.request.Request(
        _OSV_QUERY_URL,
        data=data_bytes,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            data = json.loads(resp.read())
        return data.get("vulns") or []
    except Exception:
        return []


def _osv_parallel_query(pkgs: list[tuple[str, str]], ecosystem: str) -> list[list[dict]]:
    """Run per-package OSV queries in parallel (up to _WORKERS threads)."""
    results: list[list[dict]] = [[] for _ in pkgs]
    with ThreadPoolExecutor(max_workers=_WORKERS) as pool:
        future_map = {
            pool.submit(_osv_query_one, name, ver, ecosystem): i
            for i, (name, ver) in enumerate(pkgs)
        }
        for fut in as_completed(future_map):
            idx = future_map[fut]
            try:
                results[idx] = fut.result()
            except Exception:
                results[idx] = []
    return results


# ─────────────────────────────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────────────────────────────

_SEV_COLOR = {
    "CRITICAL": "#DC2626",
    "HIGH":     "#EA580C",
    "MEDIUM":   "#D97706",
    "LOW":      "#16A34A",
}


def _severity(vuln: dict) -> tuple[str, str]:
    """(label, hex_color) from the vuln object.
    Priority: database_specific.severity string → CVSS_V3 vector score → UNKNOWN.
    """
    # 1. GitHub Advisory / NVD string severity (fastest, most common)
    db_sev = (vuln.get("database_specific") or {}).get("severity", "").upper()
    if db_sev in _SEV_COLOR:
        return db_sev, _SEV_COLOR[db_sev]

    # 2. CVSS_V3 numeric or vector score
    for sev in vuln.get("severity", []):
        raw = sev.get("score", "")
        try:
            score = float(raw)
        except ValueError:
            m = re.search(r"/(\d+\.\d+)$", raw)
            score = float(m.group(1)) if m else None
        if score is not None:
            if score >= 9.0:
                return "CRITICAL", _SEV_COLOR["CRITICAL"]
            if score >= 7.0:
                return "HIGH",     _SEV_COLOR["HIGH"]
            if score >= 4.0:
                return "MEDIUM",   _SEV_COLOR["MEDIUM"]
            return "LOW", _SEV_COLOR["LOW"]

    return "UNKNOWN", "#94A3B8"


def _fix_version(vuln: dict) -> str:
    """First 'fixed' event version found in the affected ranges."""
    for aff in vuln.get("affected", []):
        for rng in aff.get("ranges", []):
            for evt in rng.get("events", []):
                if "fixed" in evt:
                    return evt["fixed"]
    return ""


# ─────────────────────────────────────────────────────────────────────
#  Public API
# ─────────────────────────────────────────────────────────────────────

def scan_source_dir(source_dir: str | Path) -> dict:
    """
    Scan source_dir for requirements.txt or package.json.
    Returns::

        {
          "ecosystem": "PyPI" | "npm" | None,
          "packages_checked": int,
          "vulns": [
            {"pkg", "version", "id", "summary", "severity", "color", "fix"}
          ],
          "error": str | None,
        }
    """
    source_dir = Path(source_dir)
    pkgs:      list[tuple[str, str]] = []
    ecosystem: str | None = None

    req_txt  = source_dir / "requirements.txt"
    pkg_json = source_dir / "package.json"

    if req_txt.exists():
        pkgs      = _parse_requirements_txt(req_txt)
        ecosystem = "PyPI"
    elif pkg_json.exists():
        pkgs      = _parse_package_json(pkg_json)
        ecosystem = "npm"

    if not pkgs:
        return {"ecosystem": ecosystem, "packages_checked": 0, "vulns": [], "error": None}

    pkgs = pkgs[:60]   # cap to avoid too many requests

    try:
        batch = _osv_parallel_query(pkgs, ecosystem)
    except Exception as exc:
        return {"ecosystem": ecosystem, "packages_checked": len(pkgs), "vulns": [], "error": str(exc)}

    _sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    findings: list[dict] = []
    for (name, ver), vulns in zip(pkgs, batch):
        for v in vulns:
            sev, color = _severity(v)
            findings.append({
                "pkg":      name,
                "version":  ver or "?",
                "id":       v.get("id", "?"),
                "summary":  (v.get("summary") or v.get("details") or "")[:140],
                "severity": sev,
                "color":    color,
                "fix":      _fix_version(v),
            })

    findings.sort(key=lambda f: _sev_order.get(f["severity"], 4))

    return {
        "ecosystem":        ecosystem,
        "packages_checked": len(pkgs),
        "vulns":            findings,
        "error":            None,
    }
