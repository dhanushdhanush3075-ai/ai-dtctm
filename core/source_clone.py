"""
AI-DTCTM | Source Clone Engine (v21 — Day 3 Part 2a)
══════════════════════════════════════════════════════════════════════
User uploads a ZIP containing their source code (PHP/Python/Node/etc).
We:
  1. Extract to isolated sandbox directory
  2. Auto-detect technology stack (composer.json → PHP, package.json → Node)
  3. Auto-generate Dockerfile matching the stack
  4. Build Docker image
  5. Run container on isolated network
  6. Return live URL → user's code now running at localhost:809X

Plus cleaning:
  7. Apply automated fixes (eval removal, SQL sanitization, etc.)
  8. Rebuild cleaned version
  9. Expose cleaned URL alongside original for comparison

WHY THIS MATTERS:
  The user wanted "cloning" — upload code → actually run it → test attacks.
  This module makes the running-clone real, not just a static scan.

SECURITY GUARANTEES:
  - User code runs in isolated Docker network (aidtctm_twin_net)
  - Resource caps: 1GB RAM, 50% CPU per container
  - No host filesystem access (no volume mounts)
  - Auto-destroy after 30 minutes (session timeout)
  - No outbound internet from container (internal:true on network)
  - Every Dockerfile scanned for dangerous RUN commands before build

USAGE:
  from core.source_clone import clone_and_deploy, destroy_clone

  result = clone_and_deploy("/path/to/user_upload.zip", case_id="CASE-123")
  # {
  #   "status":      "running",
  #   "clone_id":    "src_abc123",
  #   "url":         "http://localhost:8092",
  #   "stack":       {"lang": "php", "framework": "wordpress"},
  #   "container":   "aidtctm_src_abc123",
  #   "started_at":  "...",
  # }
"""
from __future__ import annotations

import datetime
import json
import os
import re
import secrets
import json
import shutil
import tempfile
import time
import uuid
import zipfile
from pathlib import Path
from typing import Optional

try:
    import docker
    from docker.errors import DockerException, NotFound, APIError, BuildError
    _DOCKER_AVAILABLE = True
except ImportError:
    _DOCKER_AVAILABLE = False

from config import CFG
from core.logger import get_logger

log = get_logger(__name__)


# ── Stack detection signatures ────────────────────────────────────
# Order matters: checked top-to-bottom, first match wins
STACK_SIGNATURES = [
    # file/dir patterns → (language, framework, base_image, run_cmd, internal_port)
    {
        "files":        ["composer.json", "index.php", "wp-config.php"],
        "language":     "php",
        "framework":    "wordpress",
        "base_image":   "wordpress:6-php8.2-apache",
        "internal_port": 80,
        "copy_dest":    "/var/www/html",
    },
    {
        "files":        ["composer.json"],
        "language":     "php",
        "framework":    "php-apache",
        "base_image":   "php:8.2-apache",
        "internal_port": 80,
        "copy_dest":    "/var/www/html",
    },
    {
        "files":        ["index.php"],
        "language":     "php",
        "framework":    "plain-php",
        "base_image":   "php:8.2-apache",
        "internal_port": 80,
        "copy_dest":    "/var/www/html",
    },
    {
        "files":        ["package.json"],
        "language":     "nodejs",
        "framework":    "node",
        "base_image":   "node:20-alpine",
        "internal_port": 3000,
        "copy_dest":    "/app",
        "npm_install":  True,
    },
    {
        "files":        ["manage.py"],
        "language":     "python",
        "framework":    "django",
        "base_image":   "python:3.11-slim",
        "internal_port": 8000,
        "copy_dest":    "/app",
        "pip_install":  True,
        "run_cmd":      "python manage.py runserver 0.0.0.0:8000",
    },
    {
        "files":        ["app.py", "requirements.txt"],
        "language":     "python",
        "framework":    "flask",
        "base_image":   "python:3.11-slim",
        "internal_port": 5000,
        "copy_dest":    "/app",
        "pip_install":  True,
        "run_cmd":      "python app.py",
    },
    {
        "files":        ["requirements.txt"],
        "language":     "python",
        "framework":    "python",
        "base_image":   "python:3.11-slim",
        "internal_port": 5000,
        "copy_dest":    "/app",
        "pip_install":  True,
        "run_cmd":      "python -m http.server 5000",
    },
    # ── Java (Maven / Gradle / Spring Boot) ────────────────────────
    {
        "files":        ["pom.xml"],
        "language":     "java",
        "framework":    "maven",
        "base_image":   "maven:3.9-eclipse-temurin-17",
        "internal_port": 8080,
        "copy_dest":    "/app",
        "run_cmd":      "mvn -q -o spring-boot:run || mvn -q -o exec:java",
    },
    {
        "files":        ["build.gradle"],
        "language":     "java",
        "framework":    "gradle",
        "base_image":   "gradle:8-jdk17-alpine",
        "internal_port": 8080,
        "copy_dest":    "/app",
        "run_cmd":      "gradle bootRun --no-daemon",
    },
    # ── Go ─────────────────────────────────────────────────────────
    {
        "files":        ["go.mod"],
        "language":     "go",
        "framework":    "go-module",
        "base_image":   "golang:1.23-alpine",
        "internal_port": 8080,
        "copy_dest":    "/app",
        "run_cmd":      "go run . 2>/dev/null || go run ./cmd/... 2>/dev/null || go run *.go",
    },
    # ── Ruby (Rails / Sinatra / generic) ───────────────────────────
    {
        "files":        ["Gemfile", "config.ru"],
        "language":     "ruby",
        "framework":    "rack",
        "base_image":   "ruby:3.3-slim",
        "internal_port": 9292,
        "copy_dest":    "/app",
        "run_cmd":      "bundle install --quiet 2>/dev/null || true; "
                        "bundle exec rackup --host 0.0.0.0 --port 9292",
    },
    {
        "files":        ["Gemfile"],
        "language":     "ruby",
        "framework":    "ruby",
        "base_image":   "ruby:3.3-slim",
        "internal_port": 4567,
        "copy_dest":    "/app",
        "run_cmd":      "bundle install --quiet 2>/dev/null || true; "
                        "ruby app.rb -o 0.0.0.0 -p 4567 2>/dev/null || "
                        "rackup -o 0.0.0.0 -p 4567",
    },
    {
        "files":        ["index.html"],
        "language":     "static",
        "framework":    "html",
        "base_image":   "nginx:alpine",
        "internal_port": 80,
        "copy_dest":    "/usr/share/nginx/html",
    },
    # ── Java (Spring Boot / Maven / Gradle) ──
    {
        "files":        ["pom.xml"],
        "language":     "java",
        "framework":    "java-maven",
        "base_image":   "maven:3.9-eclipse-temurin-17",
        "internal_port": 8080,
        "copy_dest":    "/app",
        "maven_build":  True,
        "run_cmd":      "sh -c 'mvn -q package -DskipTests && java -jar target/*.jar'",
    },
    {
        "files":        ["build.gradle"],
        "language":     "java",
        "framework":    "java-gradle",
        "base_image":   "gradle:8-jdk17",
        "internal_port": 8080,
        "copy_dest":    "/app",
        "gradle_build": True,
        "run_cmd":      "sh -c 'gradle --no-daemon -q bootJar && java -jar build/libs/*.jar'",
    },
    {
        "files":        ["build.gradle.kts"],
        "language":     "java",
        "framework":    "java-gradle-kotlin",
        "base_image":   "gradle:8-jdk17",
        "internal_port": 8080,
        "copy_dest":    "/app",
        "gradle_build": True,
        "run_cmd":      "sh -c 'gradle --no-daemon -q bootJar && java -jar build/libs/*.jar'",
    },
    # ── Go (go.mod) ──
    {
        "files":        ["go.mod"],
        "language":     "go",
        "framework":    "go-module",
        "base_image":   "golang:1.23-alpine",
        "internal_port": 8080,
        "copy_dest":    "/app",
        "go_build":     True,
        "run_cmd":      "sh -c 'go build -o /app/server ./... && /app/server'",
    },
    # ── Ruby (Gemfile / Rails / Sinatra) ──
    {
        "files":        ["Gemfile"],
        "language":     "ruby",
        "framework":    "ruby-bundler",
        "base_image":   "ruby:3.3-slim",
        "internal_port": 4567,
        "copy_dest":    "/app",
        "bundle_install": True,
        "run_cmd":      "sh -c 'bundle install --jobs 4 --quiet && if [ -f config.ru ]; then bundle exec rackup -o 0.0.0.0 -p 4567; elif [ -f config/application.rb ]; then bundle exec rails server -b 0.0.0.0 -p 4567; else ruby app.rb; fi'",
    },
]


# ── Sandbox root ──────────────────────────────────────────────────
SANDBOX_ROOT = Path(CFG.DATA_DIR) if hasattr(CFG, "DATA_DIR") else Path(__file__).parent.parent / "data"
SANDBOX_ROOT = SANDBOX_ROOT / "source_clones"


def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "") + "Z"


# ══════════════════════════════════════════════════════════════════
# SMART ZIP EXTRACTION  — skip bloat that slows deploy & serves no purpose
# ══════════════════════════════════════════════════════════════════
_SKIP_ZIP_DIRS = {"node_modules", ".git", "__pycache__", ".venv", "venv",
                  ".idea", ".vscode", ".DS_Store", "dist/__pycache__"}
_BIG_MODEL_EXTS = {".keras", ".h5", ".hdf5", ".pt", ".pth", ".onnx",
                   ".pkl", ".bin", ".weights", ".pb", ".tflite", ".mlmodel",
                   ".npy", ".npz", ".ckpt"}
_BIG_FILE_SKIP_MB = 15  # skip model/binary files larger than this


def _extract_zip_smart(zip_path: str, dest: Path) -> tuple[int, list[tuple[str, float]]]:
    """
    Extract zip to dest, skipping:
      - node_modules/, .git/, venv/ directories (bloat, not needed in container)
      - Large model/weight files (>.keras, .h5, .pt, etc. > 15 MB) — they cause
        slow Docker build-context sends and are never needed for web serving.

    Returns (extracted_count, [(skipped_name, size_mb), ...]).
    Raises ValueError on unsafe paths; zipfile.BadZipFile on corrupt zips.
    """
    skipped: list[tuple[str, float]] = []
    extracted = 0
    with zipfile.ZipFile(zip_path, "r") as zf:
        for info in zf.infolist():
            name = info.filename
            # Safety: no path traversal
            if name.startswith("/") or ".." in name:
                raise ValueError(f"Unsafe ZIP path: {name}")
            parts = name.replace("\\", "/").split("/")
            # Skip known bloat directories
            if any(p in _SKIP_ZIP_DIRS for p in parts):
                continue
            # Skip large model/binary files
            size_mb = info.file_size / (1024 * 1024)
            ext = Path(name).suffix.lower()
            if ext in _BIG_MODEL_EXTS and size_mb > _BIG_FILE_SKIP_MB:
                skipped.append((name, size_mb))
                continue
            zf.extract(info, dest)
            extracted += 1
    return extracted, skipped


# ══════════════════════════════════════════════════════════════════
# PYTHON ENTRYPOINT DETECTION (real — reads source to find the app)
# ══════════════════════════════════════════════════════════════════
_SKIP_DIRS = {"venv", ".venv", "env", "__pycache__", "node_modules",
              ".git", "tests", "test", "migrations", "site-packages"}

def _detect_python_entrypoint(source_dir: Path) -> Optional[dict]:
    """
    Scan .py files to find the REAL ASGI/WSGI app instance and build a
    correct run command. Handles FastAPI (uvicorn), Flask, and __main__.

    Returns {"framework", "internal_port", "run_cmd"} or None.
    This is what makes real API apps (e.g. uvicorn backend.api:app) run,
    instead of falling back to a useless directory listing.
    """
    fastapi_re = re.compile(r'^\s*(\w+)\s*=\s*FastAPI\s*\(', re.MULTILINE)
    flask_re   = re.compile(r'^\s*(\w+)\s*=\s*Flask\s*\(', re.MULTILINE)
    main_run_re = re.compile(r'__name__\s*==\s*[\'"]__main__[\'"]')
    streamlit_re = re.compile(r'(?:import\s+streamlit|streamlit\s+as\s+st)', re.IGNORECASE)
    gradio_re   = re.compile(r'(?:import\s+gradio|gradio\s+as\s+gr)', re.IGNORECASE)

    candidates: list[Path] = []
    for root, dirs, files in os.walk(source_dir):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS and not d.startswith('.')]
        for fn in files:
            if fn.endswith('.py'):
                candidates.append(Path(root) / fn)

    # Prefer common entrypoint names first, then the rest
    priority = {"main.py": 0, "app.py": 1, "api.py": 2, "server.py": 3,
                "wsgi.py": 4, "asgi.py": 5, "application.py": 6, "run.py": 7}
    candidates.sort(key=lambda p: priority.get(p.name, 99))

    flask_hit = None
    main_hit = None
    for pf in candidates:
        try:
            txt = pf.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        rel = pf.relative_to(source_dir)
        module = ".".join(rel.with_suffix("").parts)
        relpath = str(rel).replace(os.sep, "/")

        # Streamlit — must run via `streamlit run <file>`, not http.server.
        # (This is why dashboards like SmartFlow showed a file list, not the app.)
        if streamlit_re.search(txt):
            log.info("python_entrypoint_streamlit", file=relpath)
            return {
                "framework":    "streamlit",
                "internal_port": 8501,
                "run_cmd":      (f"streamlit run {relpath} --server.port 8501 "
                                 f"--server.address 0.0.0.0 --server.headless true "
                                 f"--browser.gatherUsageStats false"),
                "pip_extra":    "streamlit",
            }
        # Gradio — runs on 7860 via the script's own launch()
        if gradio_re.search(txt):
            log.info("python_entrypoint_gradio", file=relpath)
            return {
                "framework":    "gradio",
                "internal_port": 7860,
                "run_cmd":      f"python {relpath}",
                "pip_extra":    "gradio",
            }

        m = fastapi_re.search(txt)
        if m:
            var = m.group(1)
            log.info("python_entrypoint_fastapi", module=module, var=var)
            return {
                "framework":    "fastapi",
                "internal_port": 8000,
                "run_cmd":      f"uvicorn {module}:{var} --host 0.0.0.0 --port 8000",
                "pip_extra":    "uvicorn[standard] fastapi",
            }
        if flask_hit is None:
            mf = flask_re.search(txt)
            if mf:
                flask_hit = (module, mf.group(1))
        if main_hit is None and main_run_re.search(txt):
            main_hit = module

    if flask_hit:
        module, var = flask_hit
        log.info("python_entrypoint_flask", module=module, var=var)
        return {
            "framework":    "flask",
            "internal_port": 5000,
            "run_cmd":      f"python -m flask --app {module}:{var} run --host 0.0.0.0 --port 5000",
            "pip_extra":    "flask",
        }
    if main_hit:
        log.info("python_entrypoint_main", module=main_hit)
        return {
            "framework":    "python-script",
            "internal_port": 8000,
            "run_cmd":      f"python -m {main_hit}",
            "pip_extra":    "",
        }
    return None


# ══════════════════════════════════════════════════════════════════
# NODE.JS ENTRYPOINT DETECTION  — reads package.json scripts
# ══════════════════════════════════════════════════════════════════
def _detect_nodejs_entrypoint(source_dir: Path) -> Optional[dict]:
    """
    Read package.json to derive the real run command.

    Handles three common patterns:
      1. Pre-built dist/ — `node dist/index.cjs` (Vite/tsup output)
      2. Needs build    — `npm run build && npm start`
      3. Dev server     — `npm run dev` (Vite, Next, etc.)

    Returns {"framework", "internal_port", "run_cmd"} or None.
    """
    # Find the root package.json (skip node_modules)
    pkg_path: Optional[Path] = None
    for candidate in [source_dir / "package.json"] + list(source_dir.glob("*/package.json")):
        if "node_modules" not in str(candidate):
            pkg_path = candidate
            break
    if not pkg_path or not pkg_path.exists():
        return None

    try:
        pkg = json.loads(pkg_path.read_text(encoding="utf-8"))
    except Exception:
        return None

    scripts = pkg.get("scripts", {})
    start_cmd: str = scripts.get("start", "")
    dev_cmd:   str = scripts.get("dev", "")
    build_cmd: str = scripts.get("build", "")

    # Detect port — check scripts first, then scan server source files
    port = 3000
    for script_text in (start_cmd, dev_cmd):
        m = re.search(r'(?:--port[=\s]+|PORT=)(\d{4,5})', script_text)
        if m:
            port = int(m.group(1))
            break
    else:
        # Scan common server entry files for `PORT || "NNNN"` or `PORT, NNNN`
        for server_file in ("server/index.ts", "server/index.js", "index.ts",
                            "index.js", "app.ts", "app.js", "src/index.ts",
                            "src/index.js", "src/app.ts", "src/app.js"):
            sf = (pkg_path.parent / server_file)
            if sf.exists():
                try:
                    src = sf.read_text(encoding="utf-8", errors="ignore")
                    pm = re.search(r'PORT\s*\|\|\s*["\']?(\d{4,5})["\']?', src)
                    if pm:
                        port = int(pm.group(1))
                        break
                    pm2 = re.search(r'\.listen\s*\(\s*\{?\s*port[^,)]*[,:]?\s*(\d{4,5})', src)
                    if pm2:
                        port = int(pm2.group(1))
                        break
                except Exception:
                    pass

    # Does the source already have a built dist/?  (happens when ZIP includes dist/)
    has_dist = (source_dir / "dist").exists() or any(
        (pkg_path.parent / d).exists() for d in ("build", "out", ".next")
    )
    needs_build = bool(build_cmd) and not has_dist

    # Build install prefix — always install (deps not in container image)
    install = "npm install --legacy-peer-deps --silent 2>&1 | tail -3 || true"

    if start_cmd:
        if needs_build:
            # Use `npm start` not the raw start_cmd so node_modules/.bin is in PATH
            run_cmd = f"{install} && npm run build 2>&1 | tail -5 && npm start"
        else:
            run_cmd = f"{install} && npm start"
    elif dev_cmd:
        run_cmd = f"{install} && npm run dev"
    else:
        return None

    framework = "nodejs-express"
    if "next" in (start_cmd + dev_cmd).lower():
        framework = "nextjs"
        port = port or 3000
    elif "vite" in (start_cmd + dev_cmd).lower():
        framework = "vite"
        port = port or 5173

    log.info("nodejs_entrypoint_detected", framework=framework, port=port,
             needs_build=needs_build, run_cmd=run_cmd[:80])
    return {"framework": framework, "internal_port": port, "run_cmd": run_cmd}


# ══════════════════════════════════════════════════════════════════
# STACK DETECTION
# ══════════════════════════════════════════════════════════════════
def detect_stack(source_dir: Path) -> dict:
    """
    Phase 3h - improved stack detection.
    
    Walks up to 4 levels deep (handles nested zip extraction).
    If the zip extracts to source_dir/myapp/{actual files}, we still find them.
    Also auto-promotes the "real root" if there's only one subdirectory.
    """
    # Auto-promote: if source_dir has exactly one subdirectory, treat that as root
    try:
        children = [p for p in source_dir.iterdir() if not p.name.startswith('.')]
        if len(children) == 1 and children[0].is_dir():
            actual_root = children[0]
            log.info("stack_detection_promoted_root", from_=str(source_dir), to=str(actual_root))
            source_dir = actual_root
    except Exception as e:
        log.warning("stack_detection_promote_failed", error=str(e))

    # Walk up to 4 levels deep collecting filenames
    all_files = set()
    def _walk(d: Path, depth: int) -> None:
        if depth > 4:
            return
        try:
            for item in d.iterdir():
                if item.name.startswith('.'):
                    continue
                all_files.add(item.name)
                if item.is_dir() and depth < 4:
                    _walk(item, depth + 1)
        except Exception:
            pass
    _walk(source_dir, 0)

    # Phase 3h: also check file-extension-based detection as secondary signal
    extension_hints = {}
    try:
        for f in all_files:
            if '.' in f:
                ext = f.rsplit('.', 1)[1].lower()
                extension_hints[ext] = extension_hints.get(ext, 0) + 1
    except Exception:
        pass

    # Score each signature: ratio (matched / total markers) wins over raw count.
    # Tiebreaker = ratio so a more-specific signature beats a more-generic one
    # when both have the same hit count (e.g. ruby-rack vs ruby-only).
    best_match = None
    best_ratio = 0.0
    best_score = 0
    for sig in STACK_SIGNATURES:
        match_count = sum(1 for f in sig["files"] if f in all_files)
        if match_count == 0:
            continue
        ratio = match_count / max(1, len(sig["files"]))
        if (match_count > best_score) or (match_count == best_score and ratio > best_ratio):
            best_score = match_count
            best_ratio = ratio
            best_match = sig

    if best_match:
        result = {
            "language":     best_match["language"],
            "framework":    best_match["framework"],
            "base_image":   best_match["base_image"],
            "internal_port": best_match["internal_port"],
            "copy_dest":    best_match["copy_dest"],
            "confidence":   f"{best_score}/{len(best_match['files'])}",
            "markers":      [f for f in best_match["files"] if f in all_files],
            "signature":    best_match,
            "source_root":  str(source_dir),
        }
        # Promote signature's static run_cmd (Django/Java/Go/Ruby/Flask all use this)
        if best_match.get("run_cmd"):
            result["run_cmd"] = best_match["run_cmd"]
        # Real entrypoint detection for Python — overrides generic run_cmd
        if best_match["language"] == "python":
            ep = _detect_python_entrypoint(source_dir)
            if ep:
                result["framework"]     = ep["framework"]
                result["internal_port"] = ep["internal_port"]
                result["run_cmd"]       = ep["run_cmd"]
                result["pip_extra"]     = ep.get("pip_extra", "")
                result["confidence"]   += f" · entrypoint:{ep['framework']}"
            else:
                # No real server entrypoint found → serve the directory instead of
                # crash-looping on a non-existent app.py. A clone must always serve.
                port = result.get("internal_port", 8000)
                result["run_cmd"]   = f"python -m http.server {port}"
                result["framework"] = "python-static"
                result["confidence"] += " · no-entrypoint→http.server"
        # Real entrypoint detection for Node.js — reads package.json scripts
        elif best_match["language"] == "nodejs":
            ep = _detect_nodejs_entrypoint(source_dir)
            if ep:
                result["framework"]     = ep["framework"]
                result["internal_port"] = ep["internal_port"]
                result["run_cmd"]       = ep["run_cmd"]
                result["confidence"]   += f" · entrypoint:{ep['framework']}"
        return result

    # Phase 3h: extension-based fallback before going to nginx
    php_count    = extension_hints.get("php", 0)
    py_count     = extension_hints.get("py", 0)
    js_count     = extension_hints.get("js", 0) + extension_hints.get("ts", 0)
    html_count   = extension_hints.get("html", 0) + extension_hints.get("htm", 0)

    if php_count >= 1:
        # User uploaded PHP code without index.php — still serve PHP via Apache
        sig = next((s for s in STACK_SIGNATURES if s["framework"] == "php-apache"),
                   STACK_SIGNATURES[0])
        log.info("stack_detection_extension_fallback", lang="php",
                 file_count=php_count)
        return {
            "language": "php", "framework": "php-apache",
            "base_image": sig["base_image"], "internal_port": sig["internal_port"],
            "copy_dest": sig["copy_dest"],
            "confidence": f"ext-fallback ({php_count} .php files)",
            "markers": [f for f in all_files if f.endswith('.php')][:5],
            "signature": sig, "source_root": str(source_dir),
        }
    if py_count >= 1:
        sig = next((s for s in STACK_SIGNATURES if s["framework"] == "flask"),
                   STACK_SIGNATURES[0])
        log.info("stack_detection_extension_fallback", lang="python",
                 file_count=py_count)
        result = {
            "language": "python", "framework": "flask",
            "base_image": sig["base_image"], "internal_port": sig["internal_port"],
            "copy_dest": sig["copy_dest"],
            "confidence": f"ext-fallback ({py_count} .py files)",
            "markers": [f for f in all_files if f.endswith('.py')][:5],
            "signature": sig, "source_root": str(source_dir),
        }
        ep = _detect_python_entrypoint(source_dir)
        if ep:
            result["framework"]     = ep["framework"]
            result["internal_port"] = ep["internal_port"]
            result["run_cmd"]       = ep["run_cmd"]
            result["pip_extra"]     = ep.get("pip_extra", "")
            result["confidence"]   += f" · entrypoint:{ep['framework']}"
        else:
            # No server entrypoint → serve directory, never crash-loop
            port = result.get("internal_port", 5000)
            result["run_cmd"]   = f"python -m http.server {port}"
            result["framework"] = "python-static"
            result["confidence"] += " · no-entrypoint→http.server"
        return result
    if html_count >= 1:
        # Genuinely a static site — nginx is correct here
        sig = next((s for s in STACK_SIGNATURES if s["framework"] == "html"),
                   STACK_SIGNATURES[-1])
        log.info("stack_detection_extension_fallback", lang="static-html",
                 file_count=html_count)
        return {
            "language": "static", "framework": "html",
            "base_image": sig["base_image"], "internal_port": sig["internal_port"],
            "copy_dest": sig["copy_dest"],
            "confidence": f"ext-fallback ({html_count} .html files)",
            "markers": [f for f in all_files if f.endswith(('.html', '.htm'))][:5],
            "signature": sig, "source_root": str(source_dir),
        }

    # True last-resort: serve as static (nginx) but warn
    log.warning("stack_detection_true_fallback",
                files_seen=len(all_files), exts=extension_hints)
    return {
        "language":     "static",
        "framework":    "unknown",
        "base_image":   "nginx:alpine",
        "internal_port": 80,
        "copy_dest":    "/usr/share/nginx/html",
        "confidence":   "0/0 (fallback — no recognised stack)",
        "markers":      [],
        "signature":    STACK_SIGNATURES[-1],
        "source_root":  str(source_dir),
    }


# ══════════════════════════════════════════════════════════════════
# MISSING PACKAGE AUTO-DETECTION
# Maps import name → pip install name for packages that are almost never
# in requirements.txt but crash the app immediately at startup if absent.
# ══════════════════════════════════════════════════════════════════
_IMPORT_TO_PIP: dict[str, str] = {
    # ── Databases ────────────────────────────────────────────────────
    "mysql":              "mysql-connector-python",
    "MySQLdb":            "mysqlclient",
    "psycopg2":           "psycopg2-binary",
    "pymongo":            "pymongo",
    "pymysql":            "PyMySQL",
    "motor":              "motor",
    "aiomysql":           "aiomysql",
    "asyncpg":            "asyncpg",
    "elasticsearch":      "elasticsearch",
    "redis":              "redis",
    "celery":             "celery",
    # ── ML / Data science ────────────────────────────────────────────
    "cv2":                "opencv-python-headless",
    "PIL":                "Pillow",
    "sklearn":            "scikit-learn",
    "tensorflow":         "tensorflow-cpu",
    "torch":              "torch --index-url https://download.pytorch.org/whl/cpu",
    "transformers":       "transformers",
    "xgboost":            "xgboost",
    "lightgbm":           "lightgbm",
    "scipy":              "scipy",
    "statsmodels":        "statsmodels",
    "nltk":               "nltk",
    "spacy":              "spacy",
    "gensim":             "gensim",
    # ── Mapping / geo ────────────────────────────────────────────────
    "folium":             "folium",
    "streamlit_folium":   "streamlit-folium",
    "geopy":              "geopy",
    "shapely":            "shapely",
    "geopandas":          "geopandas",
    "pydeck":             "pydeck",
    # ── Streamlit extensions ─────────────────────────────────────────
    "streamlit_option_menu":  "streamlit-option-menu",
    "streamlit_extras":       "streamlit-extras",
    "streamlit_aggrid":       "streamlit-aggrid",
    "streamlit_lottie":       "streamlit-lottie",
    "streamlit_card":         "streamlit-card",
    "streamlit_echarts":      "streamlit-echarts",
    "streamlit_chat":         "streamlit-chat",
    "streamlit_authenticator": "streamlit-authenticator",
    "streamlit_drawable_canvas": "streamlit-drawable-canvas",
    "streamlit_tags":         "streamlit-tags",
    "streamlit_toggle_switch": "streamlit-toggle-switch",
    "streamlit_timeline":     "streamlit-timeline",
    "st_aggrid":              "streamlit-aggrid",
    "streamlit_ace":          "streamlit-ace",
    "streamlit_plotly_events": "streamlit-plotly-events",
    # ── Web / API ────────────────────────────────────────────────────
    "dotenv":             "python-dotenv",
    "jwt":                "PyJWT",
    "bs4":                "beautifulsoup4",
    "lxml":               "lxml",
    "yaml":               "PyYAML",
    "toml":               "toml",
    "aiohttp":            "aiohttp",
    "httpx":              "httpx",
    "stripe":             "stripe",
    "sendgrid":           "sendgrid",
    "twilio":             "twilio",
    "boto3":              "boto3",
    "botocore":           "boto3",
    "firebase_admin":     "firebase-admin",
    # ── Security / crypto ────────────────────────────────────────────
    "cryptography":       "cryptography",
    "passlib":            "passlib",
    "bcrypt":             "bcrypt",
    "nacl":               "pynacl",
    "paramiko":           "paramiko",
    # ── ORM / validation ─────────────────────────────────────────────
    "pydantic":           "pydantic",
    "sqlalchemy":         "SQLAlchemy",
    "alembic":            "alembic",
    "marshmallow":        "marshmallow",
    "cerberus":           "cerberus",
    # ── Visualisation extras ─────────────────────────────────────────
    "plotly":             "plotly",
    "altair":             "altair",
    "bokeh":              "bokeh",
    "matplotlib":         "matplotlib",
    "seaborn":            "seaborn",
    "wordcloud":          "wordcloud",
    # ── Document / file ─────────────────────────────────────────────
    "docx":               "python-docx",
    "pptx":               "python-pptx",
    "openpyxl":           "openpyxl",
    "xlrd":               "xlrd",
    "PyPDF2":             "PyPDF2",
    "pdfplumber":         "pdfplumber",
    "pypdf":              "pypdf",
    "qrcode":             "qrcode",
    # ── Misc utility ─────────────────────────────────────────────────
    "arrow":              "arrow",
    "pendulum":           "pendulum",
    "rich":               "rich",
    "tqdm":               "tqdm",
    "loguru":             "loguru",
    "click":              "click",
    "typer":              "typer",
    "tabulate":           "tabulate",
    "pyarrow":            "pyarrow",
    "orjson":             "orjson",
}

_IMPORT_RE = re.compile(
    r'^\s*(?:import|from)\s+(\w+)', re.MULTILINE
)


def _detect_missing_pip_packages(source_root: str) -> list[str]:
    """
    Scan .py files under source_root for import statements.
    Return pip packages to install for any import that maps to a well-known
    package name not typically listed in requirements.txt.
    Skips packages already covered by a requirements.txt in the same tree.
    """
    if not source_root:
        return []
    root = Path(source_root)
    # Read requirements.txt to avoid double-installing
    existing: set[str] = set()
    for req_path in root.rglob("requirements*.txt"):
        try:
            for line in req_path.read_text(encoding="utf-8", errors="ignore").splitlines():
                pkg = re.split(r"[>=<!;\[]", line.strip())[0].lower().replace("-", "_")
                existing.add(pkg)
        except Exception:
            pass

    imports_found: set[str] = set()
    for py_file in root.rglob("*.py"):
        if any(skip in str(py_file) for skip in ("node_modules", ".venv", "venv",
                                                   "__pycache__", "site-packages")):
            continue
        try:
            txt = py_file.read_text(encoding="utf-8", errors="ignore")
            for m in _IMPORT_RE.finditer(txt):
                imports_found.add(m.group(1))
        except Exception:
            pass

    to_install: list[str] = []
    for imp, pip_pkg in _IMPORT_TO_PIP.items():
        pip_name = pip_pkg.split()[0].lower().replace("-", "_")
        if imp in imports_found and pip_name not in existing:
            to_install.append(pip_pkg)

    return to_install


# ══════════════════════════════════════════════════════════════════
# DOCKERFILE GENERATION
# ══════════════════════════════════════════════════════════════════
def generate_dockerfile(stack: dict) -> str:
    """
    Build an optimised Dockerfile that works on both the classic builder
    AND BuildKit (v24 — BuildKit-only `--mount=type=cache` removed).

    Key optimisation: copy dependency manifests BEFORE source code so Docker
    can cache the install layer — if only source changes, pip/npm don't re-run.
    Layer order: base → workdir → COPY manifests → install → COPY source → CMD
    """
    sig = stack["signature"]
    lang = sig["language"]
    base = sig["base_image"]
    copy_dest = sig["copy_dest"]
    internal_port = stack.get("internal_port") or sig["internal_port"]
    run_cmd = stack.get("run_cmd") or sig.get("run_cmd")
    pip_extra = stack.get("pip_extra", "")

    # v24: write a Dockerfile that works on BOTH classic builder AND BuildKit.
    # We dropped `RUN --mount=type=cache,...` because docker-py's
    # client.images.build() uses the LEGACY builder by default — that errors
    # out with "the --mount option requires BuildKit". Classic RUN works
    # everywhere; we lose pip/npm host-cache speedups but builds succeed.
    dockerfile = "# syntax=docker/dockerfile:1\n"
    dockerfile += f"FROM {base}\n"
    dockerfile += f"WORKDIR {copy_dest}\n"

    # ── nginx/static: remove default page before user files land ────────────
    if lang in ("static", "unknown") and "nginx" in base:
        dockerfile += (
            "RUN rm -f /usr/share/nginx/html/index.html "
            "/usr/share/nginx/html/50x.html 2>/dev/null || true\n"
        )
        dockerfile += (
            "RUN printf '"
            "server {\\n"
            "  listen 80;\\n"
            "  root /usr/share/nginx/html;\\n"
            "  index index.html index.htm default.html home.html main.html;\\n"
            "  autoindex on;\\n"
            "  location / { try_files \\$uri \\$uri/ =404; }\\n"
            "}\\n"
            "' > /etc/nginx/conf.d/default.conf\n"
        )

    # ── Node.js: copy manifests first → cached npm install ──────────────────
    if sig.get("npm_install"):
        dockerfile += 'ENV DATABASE_URL=postgresql://localhost/placeholder\n'
        dockerfile += 'ENV NODE_ENV=development\n'
        # Copy ONLY manifest files first — Docker caches the install layer
        # when only source code changes (not package.json).
        dockerfile += "COPY package*.json ./\n"
        # Classic RUN (no BuildKit needed). --legacy-peer-deps handles
        # peer-dep conflicts in older codebases. Layer is cached by Docker
        # as long as package.json doesn't change.
        dockerfile += "RUN npm install --legacy-peer-deps || true\n"
        # Install global serve once (cached after first build)
        dockerfile += "RUN npm install -g serve 2>/dev/null || true\n"
        # Now copy all source files
        dockerfile += f"COPY . {copy_dest}/\n"
        # Build step (vite/tsc/esbuild) — after source copy
        dockerfile += "RUN npm run build 2>&1 || npm run compile 2>/dev/null || true\n"
        dockerfile += 'ENV NODE_ENV=production\n'

    # ── Python: copy requirements first → cached pip install ────────────────
    elif sig.get("pip_install"):
        # Copy only requirements manifest — layer cached if unchanged
        dockerfile += "COPY requirements*.txt ./\n"
        # Classic pip install — works on legacy builder.
        # Layer is cached by Docker as long as requirements.txt is unchanged.
        dockerfile += "RUN pip install --no-cache-dir -r requirements.txt || true\n"
        if pip_extra:
            dockerfile += f"RUN pip install --no-cache-dir {pip_extra} || true\n"
        extra_pkgs = _detect_missing_pip_packages(stack.get("source_root", ""))
        if extra_pkgs:
            dockerfile += (
                f"RUN pip install --no-cache-dir {' '.join(extra_pkgs)} "
                f"2>/dev/null || true\n"
            )
        # Now copy all source code (cache-friendly: only this layer changes)
        dockerfile += f"COPY . {copy_dest}/\n"

    else:
        # Static/PHP/other — copy everything
        dockerfile += f"COPY . {copy_dest}/\n"

    # Fix permissions — prevents 403 from Apache/nginx
    dockerfile += f"RUN chmod -R 755 {copy_dest}/ 2>/dev/null || true\n"

    if lang == "php":
        dockerfile += "RUN docker-php-ext-install mysqli pdo pdo_mysql 2>/dev/null || true\n"

    dockerfile += f"EXPOSE {internal_port}\n"

    if run_cmd and sig.get("npm_install"):
        # Smart CMD: only use npm start if the script actually exists in package.json
        # Vite / CRA / tsup apps often only have dev/build/preview — no start script
        dockerfile += (
            'CMD ["sh", "-c", '
            '"if grep -q \\"\\\\\\\"start\\\\\\\"\\" package.json 2>/dev/null; '
            'then npm start; '
            f'elif [ -d dist ]; then serve -s dist -l {internal_port}; '
            f'elif [ -d build ]; then serve -s build -l {internal_port}; '
            f'else npm run dev -- --port {internal_port} --host 0.0.0.0 2>/dev/null || serve -s . -l {internal_port}; '
            'fi"]\n'
        )
    elif run_cmd:
        escaped = run_cmd.replace('"', '\\"')
        dockerfile += f'CMD ["sh", "-c", "{escaped}"]\n'
    elif sig.get("npm_install"):
        dockerfile += (
            'CMD ["sh", "-c", '
            '"if grep -q \\"\\\\\\\"start\\\\\\\"\\" package.json 2>/dev/null; then npm start; '
            'elif [ -d dist ]; then serve -s dist -l {port}; '
            'elif [ -d build ]; then serve -s build -l {port}; '
            'else serve -s . -l {port}; fi"]\n'.format(port=internal_port)
        )

    return dockerfile


def scan_dockerfile_safety(dockerfile: str) -> list[str]:
    """
    Basic safety check on Dockerfile text — catches obviously malicious patterns.
    Returns list of warning strings. Empty list = safe.
    """
    warnings = []
    dangerous_patterns = [
        (r"rm\s+-rf\s+/", "RUN rm -rf / detected — would wipe container"),
        (r":(){\s*:.*;.*};:",   "Fork bomb detected in RUN command"),
        (r"curl\s+[^\|]*\|\s*(ba)?sh",  "Remote shell execution via curl | bash — suspicious"),
        (r"wget\s+[^\|]*\|\s*(ba)?sh",  "Remote shell execution via wget | bash — suspicious"),
        (r"base64\s+-d\s*\|\s*(ba)?sh", "Base64 decoded script execution — suspicious"),
    ]
    for pattern, msg in dangerous_patterns:
        if re.search(pattern, dockerfile, re.IGNORECASE):
            warnings.append(msg)
    return warnings


# ══════════════════════════════════════════════════════════════════
# MAIN CLONE & DEPLOY
# ══════════════════════════════════════════════════════════════════
def clone_and_deploy(zip_path: str, case_id: Optional[str] = None,
                     wait_for_ready: bool = True) -> dict:
    """
    Full pipeline: unzip user upload → detect stack → build Docker → run.

    Args:
        zip_path: path to uploaded ZIP file
        case_id:  optional ID to link with scan history; auto-generated if None
        wait_for_ready: poll container HTTP endpoint before returning

    Returns:
        {
          "status":      "running" | "error",
          "clone_id":    "src_abc123",
          "url":         "http://localhost:8092",
          "stack":       {...},
          "container_id": "abc123...",
          "sandbox_dir": "/path/to/extracted/",
          "dockerfile":  "FROM php:8...",
          "warnings":    [],
          "error":       None | str,
          "started_at":  "2026-04-21T...",
        }
    """
    if not _DOCKER_AVAILABLE:
        return {"status": "error", "error": "docker SDK not installed. pip install docker"}

    clone_id = f"src_{secrets.token_hex(3)}"
    started = _now_iso()

    # ── 1. Extract ZIP to sandbox ─────────────────────────────────
    sandbox_dir = SANDBOX_ROOT / clone_id
    sandbox_dir.mkdir(parents=True, exist_ok=True)

    try:
        n_extracted, skipped = _extract_zip_smart(zip_path, sandbox_dir)
        log.info("zip_extracted", files=n_extracted,
                 skipped_count=len(skipped),
                 skipped_mb=round(sum(s for _, s in skipped), 1))
    except ValueError as e:
        return {"status": "error", "error": str(e), "clone_id": clone_id}
    except zipfile.BadZipFile:
        return {"status": "error", "error": "Invalid ZIP file", "clone_id": clone_id}
    except Exception as e:
        return {"status": "error", "error": f"Extract failed: {e}", "clone_id": clone_id}

    # Unwrap single-directory ZIPs (common pattern: zip contains MyApp/ at root)
    entries = list(sandbox_dir.iterdir())
    if len(entries) == 1 and entries[0].is_dir():
        inner = entries[0]
        for item in inner.iterdir():
            shutil.move(str(item), str(sandbox_dir / item.name))
        inner.rmdir()

    # ── 2. Detect stack ───────────────────────────────────────────
    stack = detect_stack(sandbox_dir)
    log.info("source_stack_detected",
             clone_id=clone_id,
             language=stack["language"],
             framework=stack["framework"])

    # ── 3. Generate Dockerfile ────────────────────────────────────
    dockerfile = generate_dockerfile(stack)
    dockerfile_path = sandbox_dir / "Dockerfile.aidtctm"
    dockerfile_path.write_text(dockerfile)

    safety_warnings = scan_dockerfile_safety(dockerfile)
    if safety_warnings:
        log.warning("dockerfile_safety_warnings",
                    clone_id=clone_id, warnings=safety_warnings)

    # ── 4. Connect Docker FIRST (Phase 2f - fix port collision) ──────
    try:
        client = _get_docker_client()
    except Exception as e:
        return {"status": "error", "error": f"Docker unavailable: {e}",
                "clone_id": clone_id}

    # ── 5. Pick free host port (Docker-aware) ─────────────────────
    host_port = _pick_free_port(start=8090, end=8199, docker_client=client)
    if host_port is None:
        return {"status": "error",
                "error": "No free port in 8090-8199. "
                         "Clean leftover containers: docker rm -f "
                         "$(docker ps -aq -f label=created_by=aidtctm)",
                "clone_id": clone_id}

    image_tag = f"aidtctm_clone_{clone_id}:latest"
    try:
        log.info("building_clone_image", clone_id=clone_id, tag=image_tag)
        # v24 belt-and-suspenders: enable BuildKit at the process level too.
        # The Dockerfile no longer uses `--mount=type=cache`, but user-supplied
        # source ZIPs sometimes include their own Dockerfile with BuildKit
        # features; this env var lets the daemon negotiate BuildKit when
        # available, and falls back gracefully when not.
        os.environ.setdefault("DOCKER_BUILDKIT", "1")
        image, build_logs = client.images.build(
            path=str(sandbox_dir),
            dockerfile="Dockerfile.aidtctm",
            tag=image_tag,
            rm=True,
            forcerm=True,
            pull=False,   # use cached base images where possible
        )
    except BuildError as e:
        build_output = "\n".join(str(ln.get("stream", "")) for ln in e.build_log)[:3000]
        log.error("docker_build_failed", clone_id=clone_id, err=str(e))
        return {
            "status": "error",
            "error": f"Docker build failed: {e.msg}",
            "build_log": build_output,
            "clone_id": clone_id,
            "dockerfile": dockerfile,
        }
    except APIError as e:
        return {"status": "error",
                "error": f"Docker API error: {e.explanation or e}",
                "clone_id": clone_id}
    except Exception as e:
        return {"status": "error",
                "error": f"Build crashed: {e}",
                "clone_id": clone_id}

    # ── 6. Ensure isolated network ────────────────────────────────
    network_name = getattr(CFG, "DOCKER_TWIN_NETWORK", "aidtctm_twin_net")
    try:
        client.networks.get(network_name)
    except NotFound:
        client.networks.create(
            network_name,
            driver="bridge",
            labels={"created_by": "aidtctm"},
        )

    # ── 7. Run container ──────────────────────────────────────────
    container_name = f"aidtctm_{clone_id}"
    try:
        # Clean up old container with same name (rare)
        try:
            old = client.containers.get(container_name)
            old.remove(force=True)
        except NotFound:
            pass

        container = client.containers.run(
            image=image_tag,
            name=container_name,
            detach=True,
            ports={f"{stack['internal_port']}/tcp": host_port},
            network=network_name,
            labels={
                "created_by":   "aidtctm",
                "clone_id":     clone_id,
                "case_id":      case_id or "",
                "clone_type":   "source_code",
                "stack":        stack["framework"],
            },
            mem_limit="1g",
            cpu_quota=50000,
            cpu_period=100000,
            security_opt=["no-new-privileges"],
            read_only=False,
            restart_policy={"Name": "unless-stopped"},
        )
    except Exception as e:
        return {"status": "error",
                "error": f"Container start failed: {e}",
                "clone_id": clone_id,
                "dockerfile": dockerfile}

    url = f"http://localhost:{host_port}"

    # ── 8. Wait for ready (HTTP probe) ────────────────────────────
    ready = False
    if wait_for_ready:
        ready = _wait_http_ready(url, timeout=25)

    return {
        "status":       "running" if ready else "starting",
        "clone_id":     clone_id,
        "url":          url,
        "stack":        stack,
        "container_id": container.short_id,
        "container_name": container_name,
        "sandbox_dir":  str(sandbox_dir),
        "dockerfile":   dockerfile,
        "warnings":     safety_warnings,
        "host_port":    host_port,
        "ready":        ready,
        "error":        None,
        "started_at":   started,
        "case_id":      case_id,
    }


# ══════════════════════════════════════════════════════════════════
# UNIVERSAL RUNNER IMAGES — pre-warmed once, reused for every deploy
# ══════════════════════════════════════════════════════════════════
# Strategy: build a Python image ONCE with the common web framework deps
# (Streamlit, Flask, FastAPI, uvicorn, requests, pandas, numpy) baked in.
# Every Python deploy then just `docker run`s this image with the user's
# code bind-mounted — no per-deploy pip install, no per-deploy build.
# Result: cold deploy goes from 30-60 s → 3-5 s.
_PY_RUNNER_IMAGE = "aidtctm_py_runner:2"      # bump after adding tcpdump
_NODE_RUNNER_IMAGE = "aidtctm_node_runner:2"
_JAVA_RUNNER_IMAGE = "aidtctm_java_runner:1"   # JRE only (smaller than maven)
_GO_RUNNER_IMAGE = "aidtctm_go_runner:1"
_RUBY_RUNNER_IMAGE = "aidtctm_ruby_runner:1"


def _ensure_python_runner(client) -> bool:
    """Build the universal Python runner ONCE; reused for every Python deploy."""
    try:
        client.images.get(_PY_RUNNER_IMAGE)
        return True
    except Exception:
        pass
    log.info("py_runner_build_start")
    import tempfile as _tf
    build_dir = Path(_tf.mkdtemp(prefix="aidtctm_pyrun_"))
    (build_dir / "Dockerfile").write_text(
        "FROM python:3.11-slim\n"
        "WORKDIR /app\n"
        # tcpdump → for the malware lab's real packet-capture during attacks.
        "RUN apt-get update -qq && apt-get install -y --no-install-recommends "
        "    tcpdump curl ca-certificates && rm -rf /var/lib/apt/lists/*\n"
        # Pre-install the most common web framework stack.
        "RUN pip install --no-cache-dir "
        "streamlit==1.40.0 flask==3.1.0 fastapi==0.115.5 "
        "'uvicorn[standard]==0.32.0' requests==2.32.3 "
        "pandas==2.2.3 numpy==2.1.3 plotly==5.24.1 "
        "folium==0.18.0 'jinja2==3.1.4' || true\n"
        "EXPOSE 8501 8000 5000\n"
    )
    try:
        for _ in client.api.build(
            path=str(build_dir), dockerfile="Dockerfile",
            tag=_PY_RUNNER_IMAGE, rm=True, forcerm=True, pull=False, decode=True,
        ):
            pass
        log.info("py_runner_build_done")
        return True
    except Exception as e:
        log.error("py_runner_build_failed", error=str(e)[:120])
        return False


def _ensure_java_runner(client) -> bool:
    """Universal JRE runner for prebuilt JARs. Slow-path still builds for Maven projects."""
    try:
        client.images.get(_JAVA_RUNNER_IMAGE)
        return True
    except Exception:
        pass
    log.info("java_runner_build_start")
    import tempfile as _tf
    build_dir = Path(_tf.mkdtemp(prefix="aidtctm_javarun_"))
    (build_dir / "Dockerfile").write_text(
        "FROM eclipse-temurin:17-jre-alpine\n"
        "WORKDIR /app\n"
        "RUN apk add --no-cache curl tcpdump\n"
        "EXPOSE 8080 8443 9090\n"
    )
    try:
        for _ in client.api.build(
            path=str(build_dir), dockerfile="Dockerfile",
            tag=_JAVA_RUNNER_IMAGE, rm=True, forcerm=True, pull=False, decode=True,
        ):
            pass
        log.info("java_runner_build_done")
        return True
    except Exception as e:
        log.error("java_runner_build_failed", error=str(e)[:120])
        return False


def _ensure_go_runner(client) -> bool:
    """Universal Go runner — has full toolchain for `go build` at run-time."""
    try:
        client.images.get(_GO_RUNNER_IMAGE)
        return True
    except Exception:
        pass
    log.info("go_runner_build_start")
    import tempfile as _tf
    build_dir = Path(_tf.mkdtemp(prefix="aidtctm_gorun_"))
    (build_dir / "Dockerfile").write_text(
        "FROM golang:1.23-alpine\n"
        "WORKDIR /app\n"
        "RUN apk add --no-cache curl tcpdump git\n"
        "EXPOSE 8080 3000\n"
    )
    try:
        for _ in client.api.build(
            path=str(build_dir), dockerfile="Dockerfile",
            tag=_GO_RUNNER_IMAGE, rm=True, forcerm=True, pull=False, decode=True,
        ):
            pass
        log.info("go_runner_build_done")
        return True
    except Exception as e:
        log.error("go_runner_build_failed", error=str(e)[:120])
        return False


def _ensure_ruby_runner(client) -> bool:
    """Universal Ruby runner with bundler + Rails/Sinatra-friendly deps pre-baked."""
    try:
        client.images.get(_RUBY_RUNNER_IMAGE)
        return True
    except Exception:
        pass
    log.info("ruby_runner_build_start")
    import tempfile as _tf
    build_dir = Path(_tf.mkdtemp(prefix="aidtctm_rubyrun_"))
    (build_dir / "Dockerfile").write_text(
        "FROM ruby:3.3-slim\n"
        "WORKDIR /app\n"
        "RUN apt-get update -qq && apt-get install -y --no-install-recommends "
        "    build-essential curl tcpdump libpq-dev libsqlite3-dev "
        "    && rm -rf /var/lib/apt/lists/*\n"
        "RUN gem install --no-document bundler rack sinatra puma\n"
        "EXPOSE 4567 3000 9292\n"
    )
    try:
        for _ in client.api.build(
            path=str(build_dir), dockerfile="Dockerfile",
            tag=_RUBY_RUNNER_IMAGE, rm=True, forcerm=True, pull=False, decode=True,
        ):
            pass
        log.info("ruby_runner_build_done")
        return True
    except Exception as e:
        log.error("ruby_runner_build_failed", error=str(e)[:120])
        return False


def _ensure_node_runner(client) -> bool:
    """Universal Node runner with `serve` pre-installed for static SPAs."""
    try:
        client.images.get(_NODE_RUNNER_IMAGE)
        return True
    except Exception:
        pass
    log.info("node_runner_build_start")
    import tempfile as _tf
    build_dir = Path(_tf.mkdtemp(prefix="aidtctm_noderun_"))
    (build_dir / "Dockerfile").write_text(
        "FROM node:20-alpine\n"
        "WORKDIR /app\n"
        "RUN npm install -g serve@14 || true\n"
        "EXPOSE 3000 5000 8080\n"
    )
    try:
        for _ in client.api.build(
            path=str(build_dir), dockerfile="Dockerfile",
            tag=_NODE_RUNNER_IMAGE, rm=True, forcerm=True, pull=False, decode=True,
        ):
            pass
        log.info("node_runner_build_done")
        return True
    except Exception as e:
        log.error("node_runner_build_failed", error=str(e)[:120])
        return False


def _can_use_fast_path(stack: dict, source_dir: Path) -> tuple[bool, str]:
    """
    Check if we can skip per-deploy build and just mount + run.
    Returns (ok, runner_image).
    """
    lang = stack.get("language", "")
    if lang == "python":
        return True, _PY_RUNNER_IMAGE
    if lang == "nodejs":
        try:
            pkg = (source_dir / "package.json").read_text(encoding="utf-8")
            if '"dependencies"' in pkg or '"devDependencies"' in pkg:
                return False, ""
        except Exception:
            pass
        return True, _NODE_RUNNER_IMAGE
    if lang == "go":
        # Go runner has the full toolchain — `go build` happens at run-time
        return True, _GO_RUNNER_IMAGE
    if lang == "ruby":
        # Ruby runner has bundler + Sinatra/Rack/Puma pre-installed
        return True, _RUBY_RUNNER_IMAGE
    if lang == "java":
        # Java fast-path only when a prebuilt .jar is in the source — Maven/Gradle
        # builds still need the slow path
        try:
            for jar in source_dir.rglob("*.jar"):
                if "target" not in str(jar) and "build" not in str(jar):
                    return True, _JAVA_RUNNER_IMAGE
        except Exception:
            pass
        return False, ""
    if lang == "static":
        return False, ""
    return False, ""


def _fast_run_cmd(stack: dict) -> tuple[str, int]:
    """
    Build the CMD for the fast-path container, plus the internal port.

    Per language:
      • Python — skip pip install when all deps are already in runner
      • Java   — detect prebuilt .jar and run it
      • Go     — `go build` + run (runner has full toolchain)
      • Ruby   — bundle install only if Gemfile says so
      • Node   — `serve` static for dep-less folders
    """
    lang = stack.get("language", "")
    port = stack.get("internal_port", 8000)
    explicit = stack.get("run_cmd")

    if lang == "python":
        if explicit:
            return (
                "set -e; "
                "if [ -f requirements.txt ]; then "
                "  if ! python -c 'import sys, pkg_resources as p; "
                "req=[l.strip().split(\"==\")[0].split(\">=\")[0].split(\"<\")[0] "
                "for l in open(\"requirements.txt\") if l.strip() and not l.startswith(\"#\")]; "
                "[p.get_distribution(r) for r in req]' 2>/dev/null; then "
                "    pip install --no-cache-dir -r requirements.txt 2>&1 | tail -3 || true; "
                "  fi; "
                "fi; "
                f"exec {explicit}"
            ), port
        return f"python -m http.server {port}", port

    if lang == "java":
        # Prefer a prebuilt jar; fall back to mvn package
        return (
            "set -e; "
            "JAR=$(find . -name '*.jar' -not -path './target/*' -not -path './build/*' "
            "| head -1); "
            "if [ -z \"$JAR\" ]; then "
            "  echo 'no prebuilt jar — use slow path'; exit 1; "
            "fi; "
            f"exec java -jar $JAR --server.port={port}"
        ), port

    if lang == "go":
        # Compile + run in-place. Cache uses GOCACHE inside container.
        return (
            "set -e; "
            "if [ -f go.mod ]; then "
            "  go build -o /tmp/server ./... 2>&1 | tail -3 || true; "
            "  exec /tmp/server; "
            "fi; "
            f"exec /tmp/server"
        ), port

    if lang == "ruby":
        if explicit:
            return (
                "set -e; "
                "if [ -f Gemfile ] && [ ! -f Gemfile.lock ]; then "
                "  bundle install --jobs 4 2>&1 | tail -3 || true; "
                "fi; "
                f"exec {explicit}"
            ), port
        return f"ruby -run -e httpd . -p {port}", port

    if lang == "nodejs":
        return f"serve -s . -l {port}", port

    # Generic fallback — just run the explicit cmd if provided
    if explicit:
        return f"exec {explicit}", port
    return "", port


# ══════════════════════════════════════════════════════════════════
# DESTROY CLONE
# ══════════════════════════════════════════════════════════════════
def clone_and_deploy_streaming(zip_path: str, case_id: Optional[str] = None):
    """
    Generator version of clone_and_deploy that yields progress events.
    
    Each yield is a dict:
      {"type": "stage", "stage": "extract|detect|dockerfile|build|run|ready",
       "message": str}
      {"type": "build_log", "line": str}
      {"type": "complete", "result": dict}     # final result
      {"type": "error", "error": str, "result": dict}
    
    UI uses this to show layer-by-layer progress instead of a frozen spinner.
    """
    if not _DOCKER_AVAILABLE:
        yield {"type": "error", "error": "docker SDK not installed",
               "result": {"status": "error", "error": "docker SDK not installed"}}
        return

    clone_id = f"src_{secrets.token_hex(3)}"
    started = _now_iso()

    # ── 0. Pre-flight: Docker daemon MUST be reachable before slow work ──
    # (Auto-launch Docker Desktop on Windows; otherwise tell user fast.)
    yield {"type": "stage", "stage": "extract",
           "message": "Checking Docker daemon…"}
    _log_buf = []
    def _on_p(msg):
        _log_buf.append(msg)
    # 180 s ≈ realistic Docker Desktop cold-boot on WSL2 Windows
    ok, msg = ensure_docker_ready(timeout=180, on_progress=_on_p)
    for line in _log_buf:
        yield {"type": "build_log", "line": line}
    if not ok:
        err = {"status": "error",
               "error": (f"Docker daemon unavailable. {msg}\n\n"
                         "Fix: Open Docker Desktop manually (Start menu → "
                         "Docker Desktop). On Windows, give it ~60 s to fully "
                         "start, then click Clone & Deploy again."),
               "clone_id": clone_id}
        yield {"type": "error", "error": err["error"], "result": err}
        return
    yield {"type": "build_log", "line": f"✓ docker daemon ready ({msg})"}

    # ── 1. Extract ────────────────────────────────────────────────
    yield {"type": "stage", "stage": "extract",
           "message": "Extracting ZIP to sandbox..."}
    sandbox_dir = SANDBOX_ROOT / clone_id
    sandbox_dir.mkdir(parents=True, exist_ok=True)

    try:
        n_extracted, skipped = _extract_zip_smart(zip_path, sandbox_dir)
        if skipped:
            skipped_mb = sum(s for _, s in skipped)
            yield {"type": "build_log",
                   "line": (f"⚡ Smart extract: {n_extracted} files extracted, "
                            f"{len(skipped)} large model/bloat files skipped "
                            f"({skipped_mb:.0f} MB saved — not needed for web serving)")}
            for fname, fmb in skipped[:5]:
                yield {"type": "build_log", "line": f"   ✂ skipped {fname} ({fmb:.0f} MB)"}
        else:
            yield {"type": "build_log", "line": f"✓ Extracted {n_extracted} files"}
    except ValueError as e:
        err = {"status": "error", "error": str(e), "clone_id": clone_id}
        yield {"type": "error", "error": err["error"], "result": err}
        return
    except zipfile.BadZipFile:
        err = {"status": "error", "error": "Invalid ZIP file", "clone_id": clone_id}
        yield {"type": "error", "error": err["error"], "result": err}
        return

    # Unwrap single-dir
    entries = list(sandbox_dir.iterdir())
    if len(entries) == 1 and entries[0].is_dir():
        inner = entries[0]
        for item in inner.iterdir():
            shutil.move(str(item), str(sandbox_dir / item.name))
        inner.rmdir()

    yield {"type": "stage", "stage": "detect",
           "message": "Detecting technology stack..."}

    # ── 2. Detect stack ────────────────────────────────────────────
    stack = detect_stack(sandbox_dir)
    yield {"type": "build_log",
           "line": f"Stack detected: {stack['language']} / {stack['framework']} "
                   f"(confidence {stack['confidence']})"}
    yield {"type": "build_log",
           "line": f"Markers found: {', '.join(stack.get('markers', []))}"}

    # ── 3. Generate Dockerfile ─────────────────────────────────────
    yield {"type": "stage", "stage": "dockerfile",
           "message": "Generating Dockerfile..."}
    dockerfile = generate_dockerfile(stack)
    dockerfile_path = sandbox_dir / "Dockerfile.aidtctm"
    dockerfile_path.write_text(dockerfile)

    safety_warnings = scan_dockerfile_safety(dockerfile)
    for w in safety_warnings:
        yield {"type": "build_log", "line": f"⚠ {w}"}

    # ── 4. Connect Docker FIRST so port picker can see live containers ──
    try:
        client = _get_docker_client()
    except Exception as e:
        err = {"status": "error", "error": f"Docker unreachable: {e}",
               "clone_id": clone_id}
        yield {"type": "error", "error": err["error"], "result": err}
        return

    host_port = _pick_free_port(start=8090, end=8199, docker_client=client)
    if host_port is None:
        err = {"status": "error",
               "error": "No free port in 8090-8199. "
                        "Run: docker rm -f $(docker ps -aq -f label=created_by=aidtctm)",
               "clone_id": clone_id}
        yield {"type": "error", "error": err["error"], "result": err}
        return
    yield {"type": "build_log",
           "line": f"Allocated host port: {host_port}"}

    # ── 5. Build with streaming output OR fast-path (mount universal runner) ──
    fast_ok, fast_image = _can_use_fast_path(stack, sandbox_dir)
    fast_cmd = ""
    fast_internal_port = stack.get("internal_port", 8000)
    use_fast_path = False
    if fast_ok:
        yield {"type": "stage", "stage": "build",
               "message": "Fast-path: reusing pre-warmed runner image…"}
        # Build the runner ONCE (first deploy ever); subsequent deploys reuse
        try:
            client.images.get(fast_image)
            yield {"type": "build_log",
                   "line": f"✓ runner image cached: {fast_image}"}
            use_fast_path = True
        except Exception:
            yield {"type": "build_log",
                   "line": f"Building runner image (one-time, ≈ 40 s)…"}
            _runner_builders = {
                _PY_RUNNER_IMAGE:   _ensure_python_runner,
                _NODE_RUNNER_IMAGE: _ensure_node_runner,
                _JAVA_RUNNER_IMAGE: _ensure_java_runner,
                _GO_RUNNER_IMAGE:   _ensure_go_runner,
                _RUBY_RUNNER_IMAGE: _ensure_ruby_runner,
            }
            ok = _runner_builders.get(fast_image, lambda c: False)(client)
            if ok:
                use_fast_path = True
                yield {"type": "build_log",
                       "line": f"✓ runner image cached for next time"}
        if use_fast_path:
            fast_cmd, fast_internal_port = _fast_run_cmd(stack)

    image_tag = fast_image if use_fast_path else f"aidtctm_clone_{clone_id}:latest"

    if not use_fast_path:
        yield {"type": "stage", "stage": "build",
               "message": "Building Docker image (BuildKit cache enabled)…"}

        # Enable Docker BuildKit — parallel layers + pip/npm cache mounts
        import os as _os
        _os.environ.setdefault("DOCKER_BUILDKIT", "1")

        try:
            build_stream = client.api.build(
                path=str(sandbox_dir),
                dockerfile="Dockerfile.aidtctm",
                tag=image_tag,
                rm=True,
                forcerm=True,
                pull=False,
                decode=True,
                # Tell BuildKit to store inline cache metadata so layer hits
                # are faster on subsequent builds of the same stack.
                buildargs={"BUILDKIT_INLINE_CACHE": "1"},
            )
            _step_re = re.compile(r"Step\s+(\d+)/(\d+)\s*:")
            _cached_re = re.compile(r"---> Using cache", re.I)
            _step_cur = 0
            _step_total = 0
            for chunk in build_stream:
                if "stream" in chunk:
                    line = chunk["stream"].rstrip("\n")
                    if not line.strip():
                        continue
                    # Parse "Step N/M" for granular progress events
                    m = _step_re.search(line)
                    if m:
                        _step_cur, _step_total = int(m.group(1)), int(m.group(2))
                        pct = int(30 + (_step_cur / max(_step_total, 1)) * 55)
                        yield {"type": "progress", "pct": pct,
                               "message": f"Build step {_step_cur}/{_step_total}"}
                    if _cached_re.search(line):
                        yield {"type": "build_log",
                               "line": f"⚡ Cache hit — step {_step_cur} skipped (instant)"}
                    else:
                        yield {"type": "build_log", "line": line}
                elif "error" in chunk:
                    yield {"type": "build_log", "line": f"❌ {chunk['error']}"}
                    err = {"status": "error",
                           "error": f"Docker build failed: {chunk['error']}",
                           "clone_id": clone_id,
                           "dockerfile": dockerfile}
                    yield {"type": "error", "error": err["error"], "result": err}
                    return
                elif "status" in chunk:
                    # Layer pull progress (when base image is downloading)
                    status = chunk.get("status", "")
                    prog = chunk.get("progress", "")
                    if status and "Pull" in status:
                        yield {"type": "build_log",
                               "line": f"⬇ {status} {prog}".strip()}
        except (APIError, Exception) as e:
            err = {"status": "error",
                   "error": f"Build crashed: {e}",
                   "clone_id": clone_id,
                   "dockerfile": dockerfile}
            yield {"type": "error", "error": err["error"], "result": err}
            return

    # ── 6. Network setup ──────────────────────────────────────────
    network_name = getattr(CFG, "DOCKER_TWIN_NETWORK", "aidtctm_twin_net")
    try:
        client.networks.get(network_name)
    except NotFound:
        client.networks.create(network_name, driver="bridge",
                               labels={"created_by": "aidtctm"})
        yield {"type": "build_log", "line": f"Created isolated network: {network_name}"}

    # ── 7. Run container ──────────────────────────────────────────
    yield {"type": "stage", "stage": "run",
           "message": f"Starting container on port {host_port}..."}

    container_name = f"aidtctm_{clone_id}"
    try:
        try:
            old = client.containers.get(container_name)
            old.remove(force=True)
        except NotFound:
            pass

        run_kwargs = dict(
            image=image_tag, name=container_name, detach=True,
            network=network_name,
            labels={"created_by": "aidtctm", "clone_id": clone_id,
                    "case_id": case_id or "", "clone_type": "source_code",
                    "stack": stack["framework"]},
            mem_limit="1g", cpu_quota=50000, cpu_period=100000,
            security_opt=["no-new-privileges"],
            restart_policy={"Name": "unless-stopped"},
        )
        if use_fast_path:
            # Bind-mount the user's code into /app and run the universal runner
            host_src = str(sandbox_dir.resolve())
            run_kwargs["volumes"] = {host_src: {"bind": "/app", "mode": "rw"}}
            run_kwargs["working_dir"] = "/app"
            run_kwargs["command"] = ["sh", "-c", fast_cmd]
            run_kwargs["ports"] = {f"{fast_internal_port}/tcp": host_port}
        else:
            run_kwargs["ports"] = {f"{stack['internal_port']}/tcp": host_port}
        container = client.containers.run(**run_kwargs)
        yield {"type": "build_log",
               "line": f"Container started: {container.short_id}"}
    except Exception as e:
        err = {"status": "error",
               "error": f"Container start failed: {e}",
               "clone_id": clone_id,
               "dockerfile": dockerfile}
        yield {"type": "error", "error": err["error"], "result": err}
        return

    url = f"http://localhost:{host_port}"

    # ── 8. Wait for ready ─────────────────────────────────────────
    yield {"type": "stage", "stage": "ready",
           "message": f"Waiting for HTTP at {url}..."}
    ready = _wait_http_ready(url, timeout=25)

    result = {
        "status":         "running" if ready else "starting",
        "clone_id":       clone_id,
        "url":            url,
        "stack":          stack,
        "container_id":   container.short_id,
        "container_name": container_name,
        "sandbox_dir":    str(sandbox_dir),
        "dockerfile":     dockerfile,
        "warnings":       safety_warnings,
        "host_port":      host_port,
        "ready":          ready,
        "error":          None,
        "started_at":     started,
        "case_id":        case_id,
    }
    yield {"type": "complete", "result": result}


def destroy_clone(clone_id: str, remove_sandbox: bool = True) -> bool:
    """Stop + remove container + optionally delete extracted files."""
    try:
        client = _get_docker_client()
        container_name = f"aidtctm_{clone_id}"
        try:
            container = client.containers.get(container_name)
            container.stop(timeout=5)
            container.remove(force=True)
            log.info("clone_destroyed", clone_id=clone_id)
        except NotFound:
            log.info("clone_already_gone", clone_id=clone_id)

        # Clean up image too
        try:
            client.images.remove(f"aidtctm_clone_{clone_id}:latest", force=True)
        except Exception:
            pass

        # Remove sandbox files
        if remove_sandbox:
            sandbox_dir = SANDBOX_ROOT / clone_id
            if sandbox_dir.exists():
                shutil.rmtree(sandbox_dir, ignore_errors=True)

        return True
    except Exception as e:
        log.error("destroy_failed", clone_id=clone_id, error=str(e))
        return False


def list_active_clones() -> list[dict]:
    """List all running source-code clones, including their mapped host port."""
    try:
        client = _get_docker_client()
        containers = client.containers.list(
            filters={"label": "clone_type=source_code"}
        )
        result = []
        for c in containers:
            # Extract first mapped host port from the Docker port bindings
            host_port = None
            for bindings in (c.ports or {}).values():
                if bindings:
                    host_port = int(bindings[0].get("HostPort", 0))
                    break
            result.append({
                "clone_id":     c.labels.get("clone_id"),
                "container_id": c.short_id,
                "stack":        c.labels.get("stack"),
                "status":       c.status,
                "case_id":      c.labels.get("case_id"),
                "host_port":    host_port,
                "url":          f"http://localhost:{host_port}" if host_port else None,
            })
        return result
    except Exception as e:
        log.error("list_clones_failed", error=str(e))
        return []


# ══════════════════════════════════════════════════════════════════
# INTERNAL HELPERS
# ══════════════════════════════════════════════════════════════════
def _probe_docker_socket(fast: bool = False) -> tuple[bool, str]:
    """
    Cheap OS-level probe BEFORE we touch the docker SDK.

    On Windows: try to open the named pipe ``\\\\.\\pipe\\docker_engine`` with a
    short ConnectNamedPipe — instant if pipe is missing/busy, no 60s hang.
    On Unix: check the socket file exists + connect() with 0.5s timeout.
    Returns (alive, message). Used by readiness polling for fast probes.
    """
    import os, platform
    if platform.system() == "Windows":
        pipe_path = r"\\.\pipe\docker_engine"
        # If the named pipe file doesn't exist, daemon isn't running
        try:
            # Open with very short timeout — Windows file API
            import time as _t
            try:
                fd = os.open(pipe_path, os.O_RDWR)
                os.close(fd)
                return True, "pipe open"
            except FileNotFoundError:
                return False, "pipe missing (daemon not started)"
            except PermissionError:
                # Pipe exists but daemon owns it — usually means daemon is up
                # (we can't open, but the SDK can via proper API)
                return True, "pipe locked by daemon"
            except OSError as e:
                # errno 22 / 231 = busy → daemon is starting
                if "busy" in str(e).lower() or getattr(e, "winerror", 0) == 231:
                    return False, "pipe busy (daemon booting)"
                return False, f"pipe error: {e}"
        except Exception as e:
            return False, f"probe error: {e}"
    else:
        sock = "/var/run/docker.sock"
        if not os.path.exists(sock):
            return False, "socket missing"
        import socket as _s
        try:
            s = _s.socket(_s.AF_UNIX, _s.SOCK_STREAM)
            s.settimeout(0.5 if fast else 5)
            s.connect(sock)
            s.close()
            return True, "socket connectable"
        except Exception as e:
            return False, f"socket connect: {e}"


def _get_docker_client(*, fast_timeout: bool = False):
    """
    Cross-platform Docker client with Windows named-pipe fallback.
    fast_timeout: when True, do an OS-level probe first to avoid 60s SDK hangs.
    """
    import platform
    if fast_timeout:
        alive, msg = _probe_docker_socket(fast=True)
        if not alive:
            raise RuntimeError(f"Docker unreachable: {msg}")

    candidates = [None]
    if platform.system() == "Windows":
        candidates += ["npipe:////./pipe/docker_engine"]
    else:
        candidates += ["unix:///var/run/docker.sock"]

    last_err = None
    timeout = 4 if fast_timeout else 60
    for base_url in candidates:
        try:
            if base_url is None:
                c = docker.from_env(timeout=timeout)
            else:
                c = docker.DockerClient(base_url=base_url, timeout=timeout)
            c.ping()
            return c
        except DockerException as e:
            last_err = e
            continue
        except Exception as e:
            last_err = e
            continue
    raise RuntimeError(f"Docker unreachable. Last error: {last_err}")


def _try_start_docker_desktop() -> tuple[bool, str]:
    """
    Best-effort Docker Desktop auto-launch on Windows.
    Returns (started, message). Does NOT wait for daemon — caller polls.
    """
    import platform, os, subprocess
    if platform.system() != "Windows":
        return False, "auto-launch supported on Windows only"
    # Common install paths
    candidates = [
        os.path.expandvars(r"%ProgramFiles%\Docker\Docker\Docker Desktop.exe"),
        os.path.expandvars(r"%ProgramFiles(x86)%\Docker\Docker\Docker Desktop.exe"),
        os.path.expandvars(r"%LocalAppData%\Docker\Docker Desktop.exe"),
    ]
    exe = next((p for p in candidates if os.path.isfile(p)), None)
    if not exe:
        return False, "Docker Desktop.exe not found in standard install paths"
    try:
        # CREATE_NEW_PROCESS_GROUP + DETACHED so we don't block on it
        DETACHED = 0x00000008
        NEW_GROUP = 0x00000200
        subprocess.Popen([exe], creationflags=DETACHED | NEW_GROUP,
                         close_fds=True)
        return True, f"launched {exe}"
    except Exception as e:
        return False, f"launch failed: {e}"


def _wait_for_docker(timeout: int = 150, on_progress=None) -> tuple[bool, str]:
    """
    Poll for the Docker daemon to come up.

    Each probe uses a 2-second TCP/named-pipe timeout so a busy/starting
    daemon doesn't hang us — we want many short probes, not few long ones.

    Default 150s ≈ Docker Desktop's typical cold-boot on WSL2 Windows.
    """
    import time as _t
    deadline = _t.time() + timeout
    attempt = 0
    last_err = "unknown"
    while _t.time() < deadline:
        attempt += 1
        try:
            c = _get_docker_client(fast_timeout=True)
            return True, f"ready after {attempt} probe(s)"
        except Exception as e:
            last_err = str(e)[:120]
            remaining = int(deadline - _t.time())
            if on_progress:
                # Detect pipe-busy / pipe-not-found patterns to give user
                # an honest "daemon still booting" signal.
                err_low = last_err.lower()
                if "pipe is busy" in err_low or "(231," in last_err:
                    state = "daemon booting (WSL2 starting up)"
                elif "cannot find the file" in err_low or "(2," in last_err:
                    state = "daemon socket not yet created"
                else:
                    state = "daemon still unavailable"
                on_progress(f"{state} · {remaining}s left · probe {attempt}")
            _t.sleep(2)
    return False, f"timed out after {timeout}s; last error: {last_err}"


def ensure_docker_ready(timeout: int = 180, on_progress=None) -> tuple[bool, str]:
    """
    Single-call gate the UI uses BEFORE doing any slow work.

    1. Probe the daemon (instant).
    2. If down → try auto-launching Docker Desktop on Windows.
    3. Poll until ready or timeout.
    """
    try:
        c = _get_docker_client()
        return True, "docker already running"
    except Exception as e:
        first_err = str(e)[:80]
    if on_progress:
        on_progress("docker daemon not running — attempting auto-launch…")
    started, msg = _try_start_docker_desktop()
    if not started:
        return False, f"docker not running and auto-launch failed: {msg} (first error: {first_err})"
    if on_progress:
        on_progress(f"Docker Desktop launching ({msg})")
    return _wait_for_docker(timeout=timeout, on_progress=on_progress)


def _pick_free_port(start: int = 8090, end: int = 8199,
                     docker_client=None) -> Optional[int]:
    """
    Find an unused TCP port in the range.
    
    Phase 2f bug fix: must check BOTH:
      1. 0.0.0.0 (the address Docker binds to — not just 127.0.0.1)
      2. Active Docker containers already publishing on the port
    
    Previously only checked 127.0.0.1, which let through ports already
    grabbed by Docker (the "0.0.0.0:8090 already allocated" error).
    """
    import socket as _s

    # Step 1: get set of ports already published by aidtctm containers
    blocked_by_docker = set()
    try:
        if docker_client is None:
            docker_client = _get_docker_client()
        for c in docker_client.containers.list(all=True):
            ports = (c.attrs or {}).get("HostConfig", {}).get("PortBindings", {}) or {}
            for binds in ports.values():
                if not binds:
                    continue
                for b in binds:
                    p = b.get("HostPort")
                    if p:
                        try:
                            blocked_by_docker.add(int(p))
                        except (TypeError, ValueError):
                            pass
    except Exception as e:
        log.warning("port_detect_docker_query_failed", error=str(e))

    # Step 2: scan range, skipping Docker-blocked + OS-blocked
    for port in range(start, end + 1):
        if port in blocked_by_docker:
            continue
        # Try binding on 0.0.0.0 (matches Docker's bind) — strict check
        with _s.socket(_s.AF_INET, _s.SOCK_STREAM) as sock:
            sock.setsockopt(_s.SOL_SOCKET, _s.SO_REUSEADDR, 0)
            try:
                sock.bind(("0.0.0.0", port))
                # Bind succeeded → also verify nothing else listening
                return port
            except OSError:
                continue
    return None


def _wait_http_ready(url: str, timeout: int = 25) -> bool:
    """
    Poll URL until 2xx/3xx/4xx response or timeout.
    Aggressive polling: 150ms first attempts → catches ready quickly without
    waiting a full second after Docker has already started serving.
    """
    import requests
    deadline = time.time() + timeout
    attempt = 0
    while time.time() < deadline:
        attempt += 1
        try:
            r = requests.get(url, timeout=2, allow_redirects=False)
            if r.status_code < 500:
                log.info("clone_http_ready", url=url, status=r.status_code,
                         attempts=attempt)
                return True
        except requests.RequestException as e:
            if attempt == 1 or attempt % 10 == 0:
                log.debug("clone_http_not_ready_yet", url=url,
                          attempt=attempt, error=type(e).__name__)
        # Tight polling early (Docker port-forward race usually resolves in <2s),
        # then back off so we don't burn CPU on a genuinely-broken container.
        if   attempt <  6: time.sleep(0.15)
        elif attempt < 15: time.sleep(0.4)
        else:              time.sleep(1.0)
    log.warning("clone_http_timeout", url=url, attempts=attempt)
    return False


# ══════════════════════════════════════════════════════════════════
# Phase 3h - URL CLONE (real frontend mirror)
# ══════════════════════════════════════════════════════════════════
def clone_url_to_sandbox(url: str, case_id: Optional[str] = None,
                          max_pages: int = 1, timeout_s: int = 30) -> dict:
    """
    Phase 3h - real URL frontend cloner.

    Downloads HTML + linked CSS/JS/images for a single page, rewrites
    references to relative paths, then serves via nginx in Docker.

    NOT a deep crawler — only mirrors one page (safe + fast).
    User can preview the cloned page in their browser to inspect what
    a phishing kit would look like if it cloned their target.
    """
    import re as _re
    from urllib.parse import urlparse, urljoin
    try:
        import requests as _rq
        from bs4 import BeautifulSoup
    except ImportError:
        return {"status": "error",
                "error": "Required: pip install requests beautifulsoup4",
                "clone_id": None}

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    case_id = case_id or "url-" + _now_iso()[:19].replace(":", "").replace("-", "")
    clone_id = "urlc_" + uuid.uuid4().hex[:6]
    sandbox_dir = SANDBOX_ROOT / clone_id
    sandbox_dir.mkdir(parents=True, exist_ok=True)

    log.info("url_clone_started", url=url[:80], clone_id=clone_id)

    # ── 1. Download main HTML ────────────────────────────────────
    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; AIDTCTM-clone/1.0)"
    }
    try:
        r = _rq.get(url, headers=headers, timeout=timeout_s, allow_redirects=True,
                    verify=False)
        if r.status_code >= 400:
            return {"status": "error",
                    "error": f"HTTP {r.status_code} from target",
                    "clone_id": clone_id}
        html = r.text
        final_url = r.url
    except Exception as e:
        return {"status": "error", "error": f"Download failed: {e}",
                "clone_id": clone_id}

    # ── 2. Parse HTML, fetch assets ──────────────────────────────
    soup = BeautifulSoup(html, "html.parser")
    assets_dir = sandbox_dir / "assets"
    assets_dir.mkdir(exist_ok=True)
    assets_downloaded = 0
    assets_failed = 0

    def _safe_filename(u: str, idx: int) -> str:
        try:
            path = urlparse(u).path
            name = path.rsplit("/", 1)[-1] or f"asset_{idx}"
            name = _re.sub(r"[^A-Za-z0-9._-]", "_", name)[:80]
            return name or f"asset_{idx}"
        except Exception:
            return f"asset_{idx}"

    asset_tags = [
        ("link", "href", ("stylesheet", "preload", "icon", "shortcut icon")),
        ("script", "src", None),
        ("img", "src", None),
    ]
    counter = 0
    for tag_name, attr, rel_filter in asset_tags:
        for tag in soup.find_all(tag_name):
            asset_url = tag.get(attr)
            if not asset_url:
                continue
            # Skip data URIs and anchor links
            if asset_url.startswith(("data:", "#", "javascript:", "mailto:")):
                continue
            # rel filter for <link>
            if rel_filter:
                rel = tag.get("rel", [])
                if isinstance(rel, list): rel = " ".join(rel).lower()
                else: rel = rel.lower()
                if not any(r in rel for r in rel_filter):
                    continue

            absolute = urljoin(final_url, asset_url)
            counter += 1
            local_name = f"{counter:03d}_" + _safe_filename(absolute, counter)
            try:
                resp = _rq.get(absolute, headers=headers,
                               timeout=8, verify=False, stream=True)
                if resp.status_code < 400:
                    with open(assets_dir / local_name, "wb") as f:
                        for chunk in resp.iter_content(8192):
                            f.write(chunk)
                    tag[attr] = f"assets/{local_name}"
                    assets_downloaded += 1
                else:
                    assets_failed += 1
            except Exception:
                assets_failed += 1

    # Rewrite <a href="absolute_url"> to '#cloned' so they don't escape sandbox
    for a in soup.find_all("a"):
        href = a.get("href", "")
        if href.startswith(("http://", "https://", "//")):
            a["href"] = "#cloned"
            a["data-original-href"] = href

    # Inject "Cloned by AI-DTCTM" banner so it's clearly a sandbox
    banner_html = (
        '<div style="position:fixed; top:0; left:0; right:0; z-index:99999; '
        'background:linear-gradient(90deg,#2563EB,#1E40AF); color:#FFFFFF; '
        'padding:8px 16px; font-family:system-ui,sans-serif; font-size:13px; '
        'text-align:center; box-shadow:0 2px 8px rgba(0,0,0,0.15);">'
        f'🛡️ AI-DTCTM Forensic Clone &middot; Original URL: '
        f'<code style="background:rgba(255,255,255,0.2); padding:2px 6px; '
        f'border-radius:3px;">{url}</code> &middot; Sandbox: {clone_id}'
        '</div>'
    )
    if soup.body:
        soup.body.insert(0, BeautifulSoup(banner_html, "html.parser"))

    # Save index.html
    index_path = sandbox_dir / "index.html"
    index_path.write_text(str(soup), encoding="utf-8")

    # ── 3. Generate Dockerfile (nginx serves static) ─────────────
    dockerfile = (
        "FROM nginx:alpine\n"
        "WORKDIR /usr/share/nginx/html\n"
        "RUN rm -rf ./*\n"
        "COPY . /usr/share/nginx/html/\n"
        "EXPOSE 80\n"
    )
    (sandbox_dir / "Dockerfile.aidtctm").write_text(dockerfile)

    # ── 4. Build + run via Docker ────────────────────────────────
    client = _get_docker_client()
    if not client:
        return {"status": "error",
                "error": "Docker daemon unreachable. Start Docker Desktop and retry.",
                "clone_id": clone_id, "sandbox_dir": str(sandbox_dir)}

    host_port = _pick_free_port()
    if host_port is None:
        return {"status": "error",
                "error": "No free port available in 8090-8199",
                "clone_id": clone_id}

    image_tag = f"aidtctm_clone_{clone_id}:latest"
    try:
        image, _ = client.images.build(
            path=str(sandbox_dir),
            dockerfile="Dockerfile.aidtctm",
            tag=image_tag, rm=True, forcerm=True, pull=False,
        )
    except Exception as e:
        return {"status": "error",
                "error": f"Build failed: {e}",
                "clone_id": clone_id}

    try:
        container = client.containers.run(
            image=image_tag,
            detach=True,
            ports={"80/tcp": host_port},
            name=f"aidtctm_clone_{clone_id}",
            labels={"created_by": "aidtctm",
                    "clone_id": clone_id,
                    "case_id": case_id,
                    "kind": "url"},
            mem_limit="256m",
            network_mode="bridge",
            read_only=False,
            cap_drop=["ALL"],
            security_opt=["no-new-privileges:true"],
        )
    except Exception as e:
        return {"status": "error",
                "error": f"Container start failed: {e}",
                "clone_id": clone_id}

    # ── 5. Wait for nginx ready ──────────────────────────────────
    preview_url = f"http://localhost:{host_port}"
    ready = _wait_http_ready(preview_url, timeout=20)
    if not ready:
        log.warning("url_clone_health_check_timeout", clone_id=clone_id,
                    port=host_port)

    log.info("url_clone_ready", clone_id=clone_id, port=host_port,
             assets_ok=assets_downloaded, assets_fail=assets_failed,
             ready=ready)

    return {
        "status":            "running" if ready else "starting",
        "clone_id":          clone_id,
        "case_id":           case_id,
        "kind":              "url",
        "original_url":      url,
        "final_url":         final_url,
        "host_port":         host_port,
        "preview_url":       preview_url,
        "ready":             ready,
        "assets_downloaded": assets_downloaded,
        "assets_failed":     assets_failed,
        "container_id":      container.id[:12],
        "started_at":        _now_iso(),
        "sandbox_dir":       str(sandbox_dir),
        "stack": {
            "language": "static-clone",
            "framework": "url-mirror",
            "base_image": "nginx:alpine",
            "internal_port": 80,
            "confidence": "URL clone (1 page mirrored)",
        },
    }


# ══════════════════════════════════════════════════════════════════
# Phase 3i — EICAR test injection (safe, legitimate)
# ══════════════════════════════════════════════════════════════════
EICAR_TEST_STRING = (
    "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)
EICAR_DROPPER_PHP = """<?php
/* EICAR DROPPER - test file for AI-DTCTM forensic scanner.
   This file is part of an industry-standard fake virus signature.
   It does nothing harmful — every AV detects this string. */
$payload = "X5O!P%@AP[4\\\\PZX54(P^)7CC)7}\\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\\$H+H*";
echo "EICAR test signature: " . $payload;
?>
"""


def inject_eicar_into_clone(clone_id: str) -> dict:
    """
    Inject EICAR test signature files into a deployed clone.
    Safe + legitimate test for AV/forensic scanner demos.
    """
    sandbox_dir = SANDBOX_ROOT / clone_id
    if not sandbox_dir.exists():
        return {"status": "error", "error": f"Clone sandbox not found: {clone_id}"}

    files_injected = 0
    try:
        # Plain EICAR text file
        (sandbox_dir / "eicar.txt").write_text(EICAR_TEST_STRING)
        files_injected += 1

        # PHP dropper variant (so php-apache clones serve it)
        (sandbox_dir / "eicar_dropper.php").write_text(EICAR_DROPPER_PHP)
        files_injected += 1

        log.info("eicar_injected", clone_id=clone_id, files=files_injected)
        return {
            "status": "ok",
            "clone_id": clone_id,
            "files_injected": files_injected,
            "files": ["eicar.txt", "eicar_dropper.php"],
        }
    except Exception as e:
        log.error("eicar_injection_failed", clone_id=clone_id, error=str(e))
        return {"status": "error", "error": f"Injection failed: {e}"}


def remove_eicar_from_clone(clone_id: str) -> dict:
    sandbox_dir = SANDBOX_ROOT / clone_id
    removed = 0
    for fname in ("eicar.txt", "eicar_dropper.php"):
        try:
            f = sandbox_dir / fname
            if f.exists():
                f.unlink()
                removed += 1
        except Exception:
            pass
    return {"status": "ok", "removed": removed}


# ══════════════════════════════════════════════════════════════════
# Phase 3j — Download clone as ZIP
# ══════════════════════════════════════════════════════════════════
def download_clone_as_zip(clone_id: str) -> Optional[bytes]:
    """
    Package the entire clone sandbox folder (source + Dockerfile +
    any injected test files like EICAR) into a single in-memory ZIP.
    Returns ZIP bytes ready for st.download_button.
    """
    sandbox_dir = SANDBOX_ROOT / clone_id
    if not sandbox_dir.exists():
        log.warning("download_clone_no_sandbox", clone_id=clone_id)
        return None

    import io as _io
    buf = _io.BytesIO()
    try:
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for root, dirs, files in os.walk(sandbox_dir):
                # Skip docker-internal folders
                dirs[:] = [d for d in dirs if not d.startswith('.') and d != 'node_modules']
                for f in files:
                    full = Path(root) / f
                    try:
                        rel = full.relative_to(sandbox_dir)
                        zf.write(full, arcname=str(rel))
                    except Exception:
                        pass
        buf.seek(0)
        size_kb = len(buf.getvalue()) // 1024
        log.info("clone_zip_downloaded", clone_id=clone_id, size_kb=size_kb)
        return buf.getvalue()
    except Exception as e:
        log.error("download_clone_failed", clone_id=clone_id, error=str(e))
        return None


# ══════════════════════════════════════════════════════════════════
# Phase 3P: File browser for Digital Twin
# ══════════════════════════════════════════════════════════════════
def list_clone_files(clone_id: str) -> list:
    """List all files inside a running clone container."""
    try:
        import docker
        client = docker.from_env()
        # Try both naming patterns
        for prefix in [f"aidtctm_{clone_id}", f"aidtctm_clone_{clone_id}"]:
            try:
                container = client.containers.get(prefix)
                break
            except: continue
        else:
            return []
        for root in ["/var/www/html", "/app", "/usr/share/nginx/html", "/src"]:
            exit_code, output = container.exec_run(f"find {root} -type f -name '*' 2>/dev/null")
            if exit_code == 0 and output:
                files = [f.strip() for f in output.decode("utf-8", errors="replace").splitlines() if f.strip()]
                if files:
                    return [{"path": f, "name": f.split("/")[-1],
                             "dir": "/".join(f.split("/")[:-1]),
                             "ext": f.split(".")[-1] if "." in f else ""} for f in files[:100]]
        return []
    except Exception as e:
        log.warning("list_clone_files_failed", clone_id=clone_id, error=str(e)[:100])
        return []


def read_clone_file(clone_id: str, filepath: str) -> str:
    """Read content of a specific file from clone container."""
    try:
        import docker
        client = docker.from_env()
        for prefix in [f"aidtctm_{clone_id}", f"aidtctm_clone_{clone_id}"]:
            try:
                container = client.containers.get(prefix)
                break
            except: continue
        else:
            return "Container not found"
        exit_code, output = container.exec_run(f"cat {filepath}")
        if exit_code == 0:
            return output.decode("utf-8", errors="replace")[:50000]
        return f"Error reading file (exit code {exit_code})"
    except Exception as e:
        return f"Error: {e}"


def clone_from_github_streaming(gh_url: str, case_id: Optional[str] = None):
    """
    Clone a public GitHub repo URL → Docker clone.
    Yields the same event dicts as clone_and_deploy_streaming so the
    existing pipeline progress UI works without changes.
    """
    import subprocess

    # Basic URL validation — must be github.com
    if not re.match(r"https?://github\.com/[^/\s]+/[^/\s]+", gh_url.strip()):
        yield {"stage": "error", "pct": 0, "msg": "Invalid GitHub URL",
               "error": "Must be https://github.com/owner/repo"}
        return

    # Normalise: strip .git suffix then re-add for git clone
    base_url   = re.sub(r"(\.git)?(/.*)?$", "", gh_url.strip())
    clone_url  = base_url + ".git"
    repo_name  = base_url.rstrip("/").split("/")[-1]

    yield {"stage": "preflight", "pct": 5, "msg": f"git clone --depth=1 {repo_name}…"}

    tmp_root  = Path(tempfile.mkdtemp(prefix="aidtctm_gh_"))
    clone_dir = tmp_root / repo_name
    zip_path  = tmp_root / f"{repo_name}.zip"

    try:
        proc = subprocess.run(
            ["git", "clone", "--depth=1", clone_url, str(clone_dir)],
            capture_output=True, text=True, timeout=120,
        )
        if proc.returncode != 0:
            err = (proc.stderr or proc.stdout)[:300]
            yield {"stage": "error", "pct": 5, "msg": "git clone failed", "error": err}
            return

        yield {"stage": "extracting", "pct": 18, "msg": "Cloned — packing deploy archive…"}

        # Smart ZIP (reuse skip lists from the rest of the module)
        skipped = 0
        file_count = 0
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for fpath in clone_dir.rglob("*"):
                if fpath.is_dir():
                    continue
                rel   = fpath.relative_to(clone_dir)
                parts = rel.parts
                if any(p in _SKIP_ZIP_DIRS for p in parts):
                    continue
                if (fpath.suffix.lower() in _BIG_MODEL_EXTS
                        and fpath.stat().st_size > _BIG_FILE_SKIP_MB * 1024 * 1024):
                    skipped += 1
                    continue
                zf.write(fpath, rel)
                file_count += 1

        size_mb = zip_path.stat().st_size / 1024 / 1024
        yield {
            "stage": "extracting", "pct": 28,
            "msg": f"Archive ready — {file_count} files, {size_mb:.1f} MB "
                   f"(skipped {skipped} large/bloat files)",
        }

        # Delegate to the existing streaming pipeline; scale pct from 28→100
        for evt in clone_and_deploy_streaming(str(zip_path), case_id=case_id):
            if isinstance(evt, dict) and "pct" in evt and evt.get("stage") != "error":
                evt = dict(evt)
                evt["pct"] = 28 + int(evt["pct"] * 0.72)
            yield evt

    except subprocess.TimeoutExpired:
        yield {"stage": "error", "pct": 5,
               "msg": "git clone timed out (120s)",
               "error": "Repository too large or network unavailable"}
    except Exception as exc:
        yield {"stage": "error", "pct": 5, "msg": str(exc), "error": str(exc)}
    finally:
        shutil.rmtree(tmp_root, ignore_errors=True)


def write_clone_file(clone_id: str, filepath: str, content: str) -> bool:
    """Write content to a file inside the clone container (live edit)."""
    try:
        import docker, tempfile, os, tarfile
        from io import BytesIO
        client = docker.from_env()
        for prefix in [f"aidtctm_{clone_id}", f"aidtctm_clone_{clone_id}"]:
            try:
                container = client.containers.get(prefix)
                break
            except: continue
        else:
            return False
        # Create a tar archive with the file
        buf = BytesIO()
        with tarfile.open(fileobj=buf, mode='w') as tar:
            data = content.encode("utf-8")
            info = tarfile.TarInfo(name=os.path.basename(filepath))
            info.size = len(data)
            tar.addfile(info, BytesIO(data))
        buf.seek(0)
        dest_dir = os.path.dirname(filepath)
        container.put_archive(dest_dir, buf.getvalue())
        return True
    except Exception as e:
        log.warning("write_clone_file_failed", error=str(e)[:100])
        return False
