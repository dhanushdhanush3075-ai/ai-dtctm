"""
AI-DTCTM | Clone File Profile (v1)
══════════════════════════════════════════════════════════════════════
Scans a live clone container via `docker exec find ...` to count files
by extension, then derives a dominant ecosystem so every attack can
adapt its payload + test set to what the clone actually contains.

Single public function:
    profile_clone(clone_id) -> dict

Result shape:
    {
        "counts":   {"py": 47, "java": 0, "php": 2, "js": 18, "pdf": 0,
                     "zip": 3, "html": 22, "yml": 4, "json": 11, "xml": 2,
                     "go": 0, "rb": 0, "rs": 0},
        "dominant": "py",          # most common code file type
        "ecosystem":"python",      # python|java|php|node|ruby|go|rust|static|mixed
        "has_pdf":  False,
        "has_zip":  True,
        "config_paths": ["/app/.env", "/app/config.yml"],
        "summary":  "Python (47 .py · 18 .js · 3 .zip)",
    }

Used by core.live_malware_lab.run_live_attack to:
  • choose webshell payload (PHP / JSP / Python pickle / Node eval)
  • probe stack-specific config files for path traversal
  • adapt header injection paths
  • decide which file-type attacks (pickle_rce, zip_slip, pdf_js) are relevant

Profile is cached per clone_id for the lifetime of the process — Python
scan, Java scan etc. don't change between attacks on the same clone.
"""
from __future__ import annotations

from core.logger import get_logger

log = get_logger(__name__)

# Extension → bucket key (we only care about a small set of attack-relevant kinds)
_BUCKETS = {
    "py":   ["py", "pyc", "pyo", "pyw"],
    "java": ["java", "jar", "class", "war"],
    "php":  ["php", "phtml", "php3", "php4", "php5", "phps"],
    "js":   ["js", "mjs", "cjs", "ts", "jsx", "tsx"],
    "pdf":  ["pdf"],
    "zip":  ["zip", "tar", "gz", "tgz", "bz2", "xz", "7z", "rar"],
    "html": ["html", "htm"],
    "yml":  ["yml", "yaml"],
    "json": ["json"],
    "xml":  ["xml", "xsd", "xsl"],
    "go":   ["go"],
    "rb":   ["rb", "erb"],
    "rs":   ["rs"],
    "sql":  ["sql", "sqlite", "db"],
}

# Map dominant bucket → ecosystem label (used by attacks to pick payload kind)
_ECOSYSTEM = {
    "py":   "python",
    "java": "java",
    "php":  "php",
    "js":   "node",
    "rb":   "ruby",
    "go":   "go",
    "rs":   "rust",
    "html": "static",
}

# Files we look for to know where credentials live (per stack)
_CONFIG_HINTS = [
    ".env", "config.py", "settings.py", "local_settings.py",
    "application.properties", "application.yml", "application.yaml",
    "wp-config.php", "config.php", ".htaccess",
    "config.json", "package.json", "ecosystem.config.js",
    "database.yml", "secrets.yml", "config/database.yml",
    "config.toml", "Cargo.toml", "go.mod", "appsettings.json",
]

# Where the application probably lives inside the container
_APP_ROOTS = ["/app", "/var/www", "/var/www/html", "/srv", "/srv/http",
              "/usr/share/nginx/html", "/opt/app", "/home/node/app",
              "/usr/src/app", "/workspace"]

_CACHE: dict[str, dict] = {}


def _docker_exec(clone_id: str, cmd: str, timeout: int = 8) -> tuple[int, str]:
    """Light wrapper around the docker SDK — duplicated from live_malware_lab
    to keep this module standalone (no circular import)."""
    try:
        import docker
        client = docker.from_env(timeout=timeout)
    except Exception:
        return 127, ""
    for name in (f"aidtctm_{clone_id}", f"aidtctm_clone_{clone_id}", clone_id):
        try:
            c = client.containers.get(name)
            res = c.exec_run(["sh", "-c", cmd], demux=False)
            out = (res.output or b"").decode("utf-8", errors="replace").strip()
            return res.exit_code or 0, out
        except Exception:
            continue
    return 127, ""


def profile_clone(clone_id: str, *, force: bool = False) -> dict:
    """Public entry. Profiles the clone's filesystem; result is cached."""
    if not force and clone_id in _CACHE:
        return _CACHE[clone_id]

    counts: dict[str, int] = {k: 0 for k in _BUCKETS}

    # Build one big find command that counts all extensions in one shot —
    # cheaper than N separate exec calls.
    ext_set = []
    for bucket, exts in _BUCKETS.items():
        for ext in exts:
            ext_set.append(ext)

    find_paths = " ".join(_APP_ROOTS)
    # `find <roots> -type f -name '*.ext'` over the union, then count by ext via awk.
    name_expr = " -o ".join([f"-name '*.{e}'" for e in ext_set])
    cmd = (
        f"sh -c \"find {find_paths} -type f \\( {name_expr} \\) "
        f"2>/dev/null | awk -F. '{{print tolower($NF)}}' | sort | uniq -c\""
    )
    code, out = _docker_exec(clone_id, cmd)

    # Parse "   N ext" lines
    if code == 0 and out:
        for line in out.splitlines():
            parts = line.strip().split(None, 1)
            if len(parts) == 2 and parts[0].isdigit():
                n = int(parts[0])
                ext = parts[1].strip().lower()
                for bucket, exts in _BUCKETS.items():
                    if ext in exts:
                        counts[bucket] += n
                        break

    # Pick dominant bucket (only count *code* buckets — skip pdf/zip/json)
    code_buckets = ["py", "java", "php", "js", "rb", "go", "rs"]
    dominant = max(code_buckets, key=lambda k: counts.get(k, 0))
    if counts.get(dominant, 0) == 0:
        # No code files — fall back to static HTML
        dominant = "html" if counts["html"] else ""

    ecosystem = _ECOSYSTEM.get(dominant, "mixed")

    # Locate concrete config files (so traversal can probe the real paths)
    cfg_cmd = (
        f"sh -c \"find {find_paths} -maxdepth 5 -type f \\( "
        + " -o ".join([f"-name '{n}'" for n in _CONFIG_HINTS])
        + "\\) 2>/dev/null | head -15\""
    )
    _, cfg_out = _docker_exec(clone_id, cfg_cmd)
    config_paths = [l.strip() for l in cfg_out.splitlines() if l.strip()][:15]

    # Build short human summary
    top = sorted(counts.items(), key=lambda kv: -kv[1])
    bits = [f"{n} .{ext}" for ext, n in top if n > 0][:4]
    if bits:
        summary = f"{ecosystem.title()} ({' · '.join(bits)})"
    else:
        summary = f"{ecosystem.title()} (no recognised files)"

    result = {
        "counts":      counts,
        "dominant":    dominant,
        "ecosystem":   ecosystem,
        "has_pdf":     counts.get("pdf", 0) > 0,
        "has_zip":     counts.get("zip", 0) > 0,
        "has_java":    counts.get("java", 0) > 0,
        "has_php":     counts.get("php", 0) > 0,
        "has_python":  counts.get("py", 0) > 0,
        "has_node":    counts.get("js", 0) > 0,
        "config_paths": config_paths,
        "summary":     summary,
    }
    _CACHE[clone_id] = result
    log.info("clone_file_profile %s → %s", clone_id, summary)
    return result


def clear_cache(clone_id: str | None = None) -> None:
    """Clear cached profile (call when clone is destroyed/rebuilt)."""
    if clone_id is None:
        _CACHE.clear()
    else:
        _CACHE.pop(clone_id, None)
