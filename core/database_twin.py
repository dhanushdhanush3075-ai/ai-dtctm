"""
AI-DTCTM | Database Twin Engine (v22)
══════════════════════════════════════════════════════════════════════
Upload a SQLite database (.db / .sqlite / .sqlite3) → we spin up a REAL
Docker container running `sqlite-web`, which serves a live, browsable,
queryable web UI of the actual database. Shown live in the preview iframe.

This is a genuine "database twin": the real data, running in an isolated
container, explorable in the browser — not a static scan.

WHY SQLite-first:
  Student / college projects ship SQLite files. sqlite-web gives a full
  web UI (tables, rows, SQL query console) with zero config. Runs in the
  already-cached python:3.11-slim image, so it's fast and reliable.

SECURITY:
  - Container runs read-only sqlite-web (-r) → evidence cannot be mutated
  - Isolated Docker network, 512MB RAM cap, no-new-privileges
  - restart_policy=unless-stopped → survives reboot like the source clone

USAGE:
  from core.database_twin import deploy_sqlite_twin_streaming
  for ev in deploy_sqlite_twin_streaming("/path/college.db", case_id="DB-1"):
      ...
"""
from __future__ import annotations

import datetime
import os
import secrets
import shutil
import socket
import sqlite3
from pathlib import Path
from typing import Optional

# v29: force legacy builder — BuildKit incompatibility with docker-py used
# to surface as cryptic build failures on Windows. Same defence we shipped
# for the source clone module.
os.environ.setdefault("DOCKER_BUILDKIT", "0")

from config import CFG
from core.logger import get_logger
# Reuse the battle-tested Docker helpers from the source-clone engine
from core.source_clone import (
    _DOCKER_AVAILABLE,
    _get_docker_client,
    _pick_free_port,
    _wait_http_ready,
    SANDBOX_ROOT,
)

try:
    from docker.errors import NotFound
except Exception:                       # pragma: no cover
    class NotFound(Exception):
        pass

log = get_logger(__name__)


# ── File-type detection ───────────────────────────────────────────
_SQLITE_MAGIC = b"SQLite format 3\x00"

def detect_db_type(path: str) -> str:
    """Return 'sqlite' | 'sql_dump' | 'unknown' by inspecting the file."""
    p = Path(path)
    if not p.exists():
        return "unknown"
    try:
        with open(p, "rb") as f:
            head = f.read(16)
        if head == _SQLITE_MAGIC:
            return "sqlite"
    except Exception:
        pass
    # Text .sql dump?
    if p.suffix.lower() == ".sql":
        return "sql_dump"
    try:
        with open(p, "r", encoding="utf-8", errors="ignore") as f:
            sample = f.read(2000).upper()
        if "CREATE TABLE" in sample or "INSERT INTO" in sample:
            return "sql_dump"
    except Exception:
        pass
    return "unknown"


def get_sqlite_schema(db_path: str, max_tables: int = 50) -> list[dict]:
    """
    Read the schema for the explorer view: tables, column count, row count.
    Pure read — never writes. Returns [] on any failure.
    """
    out: list[dict] = []
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        cur = conn.cursor()
        tables = cur.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name NOT LIKE 'sqlite_%' ORDER BY name"
        ).fetchall()
        for (tname,) in tables[:max_tables]:
            try:
                cols = cur.execute(f'PRAGMA table_info("{tname}")').fetchall()
                rows = cur.execute(f'SELECT COUNT(*) FROM "{tname}"').fetchone()[0]
                out.append({
                    "name":        tname,
                    "columns":     [c[1] for c in cols],
                    "column_count": len(cols),
                    "row_count":   rows,
                })
            except Exception:
                out.append({"name": tname, "columns": [],
                            "column_count": 0, "row_count": 0})
        conn.close()
    except Exception as e:
        log.warning("sqlite_schema_failed", error=str(e))
    return out


def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(
        timespec="milliseconds").replace("+00:00", "") + "Z"


_TWIN_BASE_IMAGE = "aidtctm_dbtwin_base:1"
_FALLBACK_IMAGE  = "coleifer/sqlite-web:latest"


def _ensure_base_image(client, on_log=None) -> tuple[bool, str, str]:
    """
    Ensure a usable sqlite-web image exists locally. Returns
        (ok, image_tag_to_use, message)

    Strategy (in order):
      1. If our cached AI-DTCTM image exists → use it (fastest)
      2. Try building from python:3.11-slim + pip install sqlite-web
         (streams every Docker build event to on_log so the user sees
         pip output / errors in real time)
      3. If build fails → pull the community coleifer/sqlite-web image
         as a fallback so the user still gets a working twin even when
         pip / PyPI is unreachable

    v34: total rewrite — every failure mode now surfaces a real reason
    instead of returning a bare False that left the user with "Could not
    build base image" and no idea why.
    """
    def _log(msg: str) -> None:
        if on_log:
            try: on_log(msg)
            except Exception: pass
        log.info("dbtwin_base_image_progress msg=%s", msg[:200])

    # ── 1. Already cached? Use it.
    try:
        client.images.get(_TWIN_BASE_IMAGE)
        _log(f"✓ cached image present: {_TWIN_BASE_IMAGE}")
        return True, _TWIN_BASE_IMAGE, "cached"
    except Exception:
        pass

    # ── 2. Build from python:3.11-slim with pip install
    import tempfile as _tf
    build_dir = Path(_tf.mkdtemp(prefix="aidtctm_dbtwin_base_"))
    (build_dir / "Dockerfile").write_text(
        "FROM python:3.11-slim\n"
        "RUN pip install --no-cache-dir sqlite-web==0.6.4\n"
        "WORKDIR /data\n"
        "EXPOSE 8080\n"
    )
    _log("▶ Building base image (python:3.11-slim + sqlite-web)…")
    build_err = ""
    try:
        for chunk in client.api.build(
            path=str(build_dir), dockerfile="Dockerfile",
            tag=_TWIN_BASE_IMAGE, rm=True, forcerm=True, pull=False, decode=True,
        ):
            # Surface real-time output
            if "stream" in chunk:
                line = (chunk["stream"] or "").rstrip()
                if line:
                    _log(line)
            elif "error" in chunk:
                build_err = chunk.get("error") or "unknown"
                err_detail = chunk.get("errorDetail") or {}
                _log(f"  ✗ build error: {build_err}")
                if err_detail.get("message"):
                    _log(f"  ↳ {err_detail['message']}")
        # Final check — image present?
        try:
            client.images.get(_TWIN_BASE_IMAGE)
            _log("✓ base image built successfully")
            return True, _TWIN_BASE_IMAGE, "built"
        except Exception:
            pass  # build silently failed, fall through to fallback
    except Exception as e:
        build_err = str(e)
        _log(f"✗ build raised: {build_err[:200]}")

    # ── 3. Fallback to community image
    _log(f"▶ Falling back to {_FALLBACK_IMAGE} (community image, ~30 MB)…")
    try:
        for chunk in client.api.pull(_FALLBACK_IMAGE, stream=True, decode=True):
            status = chunk.get("status") or ""
            if status and "progress" not in chunk:
                _log(f"  pull: {status}")
        # Verify it's actually present
        try:
            client.images.get(_FALLBACK_IMAGE)
            _log(f"✓ fallback image ready: {_FALLBACK_IMAGE}")
            return True, _FALLBACK_IMAGE, "fallback"
        except Exception:
            pass
    except Exception as e:
        _log(f"✗ fallback pull failed: {e}")

    return False, "", (
        f"Could not get any sqlite-web image. Build err: '{build_err[:200]}'. "
        f"Check (1) Docker Desktop is running, (2) Internet access to PyPI "
        f"and Docker Hub, (3) corporate proxy / firewall isn't blocking. "
        f"You can also run manually: docker pull {_FALLBACK_IMAGE}"
    )


# ══════════════════════════════════════════════════════════════════
# MAIN — streaming deploy (same event shape as source-clone for UI reuse)
# ══════════════════════════════════════════════════════════════════
def deploy_sqlite_twin_streaming(db_path: str, case_id: Optional[str] = None):
    """
    Generator. Yields:
      {"type":"stage","stage":"...","message":"..."}
      {"type":"build_log","line":"..."}
      {"type":"complete","result":{...}}
      {"type":"error","error":"...","result":{...}}
    """
    if not _DOCKER_AVAILABLE:
        yield {"type": "error", "error": "docker SDK not installed",
               "result": {"status": "error", "error": "docker SDK not installed"}}
        return

    twin_id = f"db_{secrets.token_hex(3)}"
    started = _now_iso()

    # 1. Stage the db file into an isolated build dir
    yield {"type": "stage", "stage": "extract",
           "message": "Staging database file…"}
    build_dir = SANDBOX_ROOT / twin_id
    build_dir.mkdir(parents=True, exist_ok=True)
    db_filename = "input.sqlite"
    try:
        shutil.copy(db_path, build_dir / db_filename)
    except Exception as e:
        err = {"status": "error", "error": f"Could not stage DB: {e}",
               "twin_id": twin_id}
        yield {"type": "error", "error": err["error"], "result": err}
        return

    # 2. Read schema (for the explorer)
    yield {"type": "stage", "stage": "detect",
           "message": "Reading schema…"}
    schema = get_sqlite_schema(str(build_dir / db_filename))
    total_rows = sum(t["row_count"] for t in schema)
    yield {"type": "build_log",
           "line": f"Schema: {len(schema)} tables · {total_rows:,} rows"}

    # 3. Docker client + port (with auto-launch + wait on Windows)
    yield {"type": "stage", "stage": "dockerfile",
           "message": "Checking Docker daemon…"}
    from core.source_clone import ensure_docker_ready
    _log_buf = []
    # 180 s ≈ realistic Docker Desktop cold-boot on WSL2 Windows
    ok, msg = ensure_docker_ready(timeout=180,
                                   on_progress=lambda m: _log_buf.append(m))
    for line in _log_buf:
        yield {"type": "build_log", "line": line}
    if not ok:
        err = {"status": "error",
               "error": (f"Docker daemon unavailable. {msg}\n\n"
                         "Fix: Open Docker Desktop manually (Start menu → "
                         "Docker Desktop), wait ~60 s, then click Deploy again."),
               "twin_id": twin_id}
        yield {"type": "error", "error": err["error"], "result": err}
        return
    yield {"type": "build_log", "line": f"✓ docker daemon ready ({msg})"}
    try:
        client = _get_docker_client()
    except Exception as e:
        err = {"status": "error", "error": f"Docker unreachable: {e}",
               "twin_id": twin_id}
        yield {"type": "error", "error": err["error"], "result": err}
        return

    host_port = _pick_free_port(start=8090, end=8199, docker_client=client)
    if host_port is None:
        err = {"status": "error",
               "error": "No free port in 8090-8199.", "twin_id": twin_id}
        yield {"type": "error", "error": err["error"], "result": err}
        return
    yield {"type": "build_log", "line": f"Allocated host port: {host_port}"}

    # 4. Resolve a usable sqlite-web image — uses cache, then builds,
    #    then falls back to community image. All progress streamed.
    yield {"type": "stage", "stage": "build",
           "message": "Resolving sqlite-web image…"}
    _build_lines: list[str] = []
    ok, image_tag, msg = _ensure_base_image(
        client, on_log=lambda m: _build_lines.append(m)
    )
    # Drain captured lines to UI so user sees pip output / pull progress
    for line in _build_lines:
        yield {"type": "build_log", "line": line}
    if not ok:
        err = {"status": "error",
               "error": msg or "Could not get any sqlite-web image",
               "twin_id": twin_id}
        yield {"type": "error", "error": err["error"], "result": err}
        return
    yield {"type": "build_log", "line": f"✓ image source: {msg} ({image_tag})"}

    # 5. Network
    network_name = getattr(CFG, "DOCKER_TWIN_NETWORK", "aidtctm_twin_net")
    try:
        client.networks.get(network_name)
    except NotFound:
        client.networks.create(network_name, driver="bridge",
                               labels={"created_by": "aidtctm"})

    # 6. Run — bind-mount the .db so we don't bake-and-rebuild per twin
    yield {"type": "stage", "stage": "run",
           "message": f"Starting sqlite-web on port {host_port}…"}
    container_name = f"aidtctm_{twin_id}"
    db_host_path = str((build_dir / db_filename).resolve())

    # Image-specific command/listen port — community coleifer image
    # expects "sqlite_web /data/db.sqlite" on port 8080 by default.
    if image_tag == _FALLBACK_IMAGE:
        # The community image's entry point auto-invokes sqlite_web on 8080.
        run_command = ["/data/db.sqlite", "-H", "0.0.0.0", "-p", "8080",
                        "-x", "-r"]
    else:
        run_command = ["sqlite_web", "-H", "0.0.0.0", "-p", "8080",
                        "-x", "-r", "/data/db.sqlite"]

    # v29: port-conflict retry — pick a fresh port up to 3 times if Docker
    # reports the bind is occupied (race condition under fast re-deploys).
    container = None
    last_err = None
    for _attempt in range(3):
        try:
            try:
                old = client.containers.get(container_name)
                old.remove(force=True)
            except NotFound:
                pass
            container = client.containers.run(
                image=image_tag,
                name=container_name,
                detach=True,
                command=run_command,
                ports={"8080/tcp": host_port},
                network=network_name,
                volumes={db_host_path: {"bind": "/data/db.sqlite", "mode": "ro"}},
                labels={"created_by": "aidtctm", "twin_id": twin_id,
                        "case_id": case_id or "", "clone_type": "database",
                        "stack": "sqlite-web"},
                mem_limit="512m", cpu_quota=50000, cpu_period=100000,
                security_opt=["no-new-privileges"],
                restart_policy={"Name": "unless-stopped"},
            )
            yield {"type": "build_log",
                   "line": f"Container started: {container.short_id}"}
            break
        except Exception as e:
            last_err = e
            msg = str(e).lower()
            if "address already in use" in msg or "port is already" in msg:
                yield {"type": "build_log",
                       "line": f"⚠ port {host_port} busy → retrying…"}
                host_port = _pick_free_port(start=host_port + 1, end=8199,
                                             docker_client=client) or host_port
                continue
            # Non-port errors — surface immediately
            err = {"status": "error",
                   "error": f"Container start failed: {e}", "twin_id": twin_id}
            yield {"type": "error", "error": err["error"], "result": err}
            return
    if container is None:
        err = {"status": "error",
               "error": f"All retries failed: {last_err}", "twin_id": twin_id}
        yield {"type": "error", "error": err["error"], "result": err}
        return

    # 8. Wait for ready
    url = f"http://localhost:{host_port}"
    yield {"type": "stage", "stage": "ready",
           "message": f"Waiting for HTTP at {url}…"}
    # v34: longer timeout (60s) — sqlite-web on first run can take
    # extra seconds on slow disks / WSL2 mounts.
    ready = _wait_http_ready(url, timeout=60)
    if not ready:
        # Surface container logs so the user sees the REAL crash reason
        try:
            log_tail = container.logs(tail=40).decode("utf-8", "replace")
            for ln in log_tail.splitlines()[-20:]:
                yield {"type": "build_log",
                       "line": f"  container[{container.short_id}]: {ln}"}
        except Exception as _le:
            yield {"type": "build_log",
                   "line": f"  (could not read container logs: {_le})"}
        # Inspect status — exited / running / paused
        try:
            container.reload()
            yield {"type": "build_log",
                   "line": f"  container status: {container.status}"}
        except Exception:
            pass

    result = {
        "status":         "running" if ready else "starting",
        "twin_id":        twin_id,
        "clone_id":       twin_id,          # alias so shared UI helpers work
        "url":            url,
        "schema":         schema,
        "total_rows":     total_rows,
        "stack":          {"language": "database", "framework": "sqlite-web",
                           "internal_port": 8080},
        "container_id":   container.short_id,
        "container_name": container_name,
        "sandbox_dir":    str(build_dir),
        "dockerfile":     f"# uses shared base image {_TWIN_BASE_IMAGE}",
        "host_port":      host_port,
        "ready":          ready,
        "error":          None,
        "started_at":     started,
        "case_id":        case_id,
    }
    yield {"type": "complete", "result": result}


def destroy_database_twin(twin_id: str, remove_sandbox: bool = True) -> bool:
    """Stop + remove the db-twin container, image, and staged files."""
    try:
        client = _get_docker_client()
        cname = f"aidtctm_{twin_id}"
        try:
            c = client.containers.get(cname)
            c.stop(timeout=5)
            c.remove(force=True)
        except NotFound:
            pass
        # Don't remove the shared base image — other twins reuse it.
        if remove_sandbox:
            d = SANDBOX_ROOT / twin_id
            if d.exists():
                shutil.rmtree(d, ignore_errors=True)
        return True
    except Exception as e:
        log.error("db_twin_destroy_failed", twin_id=twin_id, error=str(e))
        return False
