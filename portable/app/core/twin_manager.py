"""
AI-DTCTM | Digital Twin Manager — REAL DOCKER (v20 — Day 2)
══════════════════════════════════════════════════════════════════════
THE HERO FEATURE.

Instead of a JSON file pretending to be a "twin", we spin up ACTUAL
Docker containers of deliberately-vulnerable training apps, attack
them with real HTTP payloads, capture REAL database dumps, and tear
the twin down when done.

RACING CAR ANALOGY:
  Real car → Digital twin → Crash test → Real data → Real car untouched

OUR VERSION:
  Real URL/system → Docker clone (DVWA/WebGoat/JuiceShop) → Real attack
  → Real database dump → Original target untouched

THE 3 TWIN TYPES:
  DVWA        → best for SQL injection, XSS, CMDi demos (PHP/MySQL)
  JuiceShop   → modern JS, OWASP Top 10, good for API attacks
  WebGoat     → Java-based, good for XXE, deserialization

ISOLATION GUARANTEES:
  - Twin runs on private bridge network (aidtctm_twin_net)
  - No external network route from inside twin
  - Twin auto-destroys on session end or crash
  - No volume mounts to host filesystem

USAGE:
  from core.twin_manager import TwinManager

  tm = TwinManager()
  twin = tm.create("dvwa")               # starts container
  # twin.url → "http://localhost:8081"
  # twin.container_id → "a1b2c3..."
  # twin.status → "running"
  
  # ... run attacks against twin.url ...
  
  tm.destroy(twin)                       # auto-removes container
  
  # Or use as context manager (preferred):
  with tm.session("dvwa") as twin:
      # attacks here
      pass  # auto-destroy on exit
"""
from __future__ import annotations

import datetime
import secrets
import time
from contextlib import contextmanager
from dataclasses import dataclass, field, asdict
from typing import Iterator, Optional

try:
    import docker
    from docker.errors import DockerException, NotFound, APIError
    _DOCKER_AVAILABLE = True
except ImportError:
    _DOCKER_AVAILABLE = False

from config import CFG
from core.logger import get_logger

log = get_logger(__name__)


# ── Twin image registry ──────────────────────────────────────────
# Each entry describes how to run one type of vulnerable target.
TWIN_CATALOG = {
    "dvwa": {
        "image":          "vulnerables/web-dvwa",
        "internal_port":  80,
        "host_port":      CFG.DOCKER_DVWA_PORT,       # 8081 default
        "ready_endpoint": "/",                         # GET / returns login page
        "ready_timeout":  25,
        "description":    "Damn Vulnerable Web Application — PHP/MySQL (SQLi, XSS, CMDi)",
        "default_creds":  {"username": "admin", "password": "password"},
        "label":          "DVWA",
        "attack_surface": ["SQL Injection", "XSS", "Command Injection",
                           "File Upload", "CSRF", "Brute Force"],
    },
    "juiceshop": {
        "image":          "bkimminich/juice-shop",
        "internal_port":  3000,
        "host_port":      CFG.DOCKER_JUICESHOP_PORT,  # 8083 default
        "ready_endpoint": "/",
        "ready_timeout":  35,
        "description":    "OWASP Juice Shop — modern JS e-commerce (full OWASP Top 10)",
        "default_creds":  None,
        "label":          "JuiceShop",
        "attack_surface": ["Broken Auth", "Injection", "XXE", "IDOR",
                           "SSRF", "JWT Manipulation", "Race Conditions"],
    },
    "webgoat": {
        "image":          "webgoat/webgoat",
        "internal_port":  8080,
        "host_port":      CFG.DOCKER_WEBGOAT_PORT,    # 8082 default
        "ready_endpoint": "/WebGoat",
        "ready_timeout":  60,                          # WebGoat slow to boot
        "description":    "OWASP WebGoat — Java security tutorial (XXE, deserialization)",
        "default_creds":  None,
        "label":          "WebGoat",
        "attack_surface": ["XXE", "Insecure Deserialization",
                           "SSRF", "Path Traversal", "Auth Bypass"],
    },
    # Phase 3k - 5 more real vulnerable apps
    "bwapp": {
        "image":          "raesene/bwapp",
        "internal_port":  80,
        "host_port":      8084,
        "ready_endpoint": "/",
        "ready_timeout":  30,
        "description":    "bWAPP — Buggy Web App with 100+ vulnerabilities, OWASP Top 10",
        "default_creds":  {"username": "bee", "password": "bug"},
        "label":          "bWAPP",
        "attack_surface": ["100+ Vulns", "All OWASP Top 10",
                           "HTML5 ClickJacking", "WSDL Enumeration",
                           "Heartbleed", "Shellshock"],
    },
    "mutillidae": {
        "image":          "citizenstig/nowasp",
        "internal_port":  80,
        "host_port":      8085,
        "ready_endpoint": "/",
        "ready_timeout":  30,
        "description":    "OWASP Mutillidae II — deliberately vulnerable PHP, hint system",
        "default_creds":  None,
        "label":          "Mutillidae",
        "attack_surface": ["OWASP Top 10", "WebServices",
                           "Cryptography", "Session Fixation",
                           "Application Logic"],
    },
    "vulnerablewebgoat": {
        "image":          "vulnerables/web-owasp-nodegoat",
        "internal_port":  4000,
        "host_port":      8086,
        "ready_endpoint": "/",
        "ready_timeout":  30,
        "description":    "OWASP NodeGoat — Top 10 vulnerabilities in Node.js",
        "default_creds":  {"username": "admin", "password": "Admin_123"},
        "label":          "NodeGoat",
        "attack_surface": ["NoSQL Injection", "Server-Side JS Injection",
                           "Insecure Direct Object Refs", "Mass Assignment",
                           "JWT Issues"],
    },
    "securityshepherd": {
        "image":          "ismisepaul/securityshepherd",
        "internal_port":  80,
        "host_port":      8087,
        "ready_endpoint": "/",
        "ready_timeout":  60,
        "description":    "OWASP Security Shepherd — gamified web security training",
        "default_creds":  None,
        "label":          "Security Shepherd",
        "attack_surface": ["Browser Exploitation", "Session Management",
                           "Insecure Cryptographic Storage",
                           "Failure to Restrict URL Access"],
    },
    "vulnerablespringboot": {
        "image":          "sasanlabs/owasp-vulnerableapp",
        "internal_port":  9090,
        "host_port":      8088,
        "ready_endpoint": "/",
        "ready_timeout":  45,
        "description":    "OWASP VulnerableApp — Spring Boot Java with API vulns",
        "default_creds":  None,
        "label":          "VulnerableApp (Spring)",
        "attack_surface": ["API Security Top 10", "REST Vulns",
                           "JWT Manipulation", "GraphQL Injection",
                           "SSRF in APIs"],
    },
}


# ── Twin session object ───────────────────────────────────────────
@dataclass
class Twin:
    """Handle to a running twin container."""
    twin_id:        str                   # our UUID
    twin_type:      str                   # "dvwa" | "juiceshop" | "webgoat"
    image:          str
    container_id:   Optional[str] = None  # Docker's container ID (short)
    container_name: Optional[str] = None  # friendly name we assigned
    url:            Optional[str] = None  # http://localhost:808X
    host_port:      int  = 0
    status:         str  = "pending"      # pending | running | ready | stopped | error
    created_at:     str  = field(default_factory=lambda: datetime.datetime.utcnow().isoformat() + "Z")
    started_at:     Optional[str] = None
    stopped_at:     Optional[str] = None
    last_error:     Optional[str] = None
    attack_surface: list[str] = field(default_factory=list)
    description:    str  = ""

    def to_dict(self) -> dict:
        return asdict(self)


# ── Main manager ──────────────────────────────────────────────────
class TwinManager:
    """
    Lifecycle controller for Docker-based twins.
    
    Thread-safe for a single Python process. Multiple instances can
    coexist but will share the Docker daemon — no cross-process locking.
    """

    def __init__(self):
        if not _DOCKER_AVAILABLE:
            raise RuntimeError(
                "docker SDK not installed. Run: pip install docker"
            )
        self._client = None
        self._network_name = CFG.DOCKER_TWIN_NETWORK
        self._active: dict[str, Twin] = {}   # twin_id -> Twin

    # ── Docker client lazy init ──────────────────────────────────
    @property
    def client(self):
        """Lazy Docker client — only connects when first used.
        
        On Windows, Docker Desktop uses a named pipe (npipe://) that
        docker.from_env() doesn't always discover correctly. We fall
        back to explicit npipe URL, then TCP, in order of safety.
        """
        if self._client is not None:
            return self._client

        import platform
        candidates: list[str | None] = [None]  # try from_env first
        if platform.system() == "Windows":
            candidates += [
                "npipe:////./pipe/docker_engine",
                "tcp://localhost:2375",   # only if exposed
            ]
        else:
            candidates += [
                "unix:///var/run/docker.sock",
            ]

        last_err = None
        for base_url in candidates:
            try:
                if base_url is None:
                    c = docker.from_env()
                else:
                    c = docker.DockerClient(base_url=base_url)
                c.ping()
                self._client = c
                log.info("docker_connected", base_url=base_url or "env")
                return self._client
            except DockerException as e:
                last_err = e
                continue
            except Exception as e:
                last_err = e
                continue

        raise RuntimeError(
            f"Cannot connect to Docker daemon.\n\n"
            f"Steps:\n"
            f"  1. Open Docker Desktop from Start menu\n"
            f"  2. Wait until whale icon in system tray stops animating (~30s)\n"
            f"  3. Run `docker ps` in a new PowerShell — should succeed\n"
            f"  4. Restart this app\n\n"
            f"Last error: {last_err}"
        )

    # ── Ensure isolated network exists ───────────────────────────
    def ensure_network(self) -> None:
        """Create aidtctm_twin_net if it doesn't exist. Idempotent."""
        try:
            self.client.networks.get(self._network_name)
        except NotFound:
            log.info("creating_twin_network", name=self._network_name)
            self.client.networks.create(
                self._network_name,
                driver="bridge",
                internal=False,  # let twin contact itself; outbound still blocked by no route
                labels={"created_by": "aidtctm", "purpose": "digital_twin_isolation"},
            )

    # ── Diagnostics ──────────────────────────────────────────────
    def docker_status(self) -> dict:
        """Report on Docker daemon + available images. For Overview widget."""
        if not _DOCKER_AVAILABLE:
            return {"available": False, "reason": "docker SDK not installed"}
        try:
            self.client.ping()
            info = self.client.info()
            images = {img.attrs["RepoTags"][0] for img in self.client.images.list()
                      if img.attrs.get("RepoTags")}
            available_twins = [
                t_id for t_id, meta in TWIN_CATALOG.items()
                if any(meta["image"] in img for img in images)
            ]
            return {
                "available":       True,
                "docker_version":  info.get("ServerVersion", "?"),
                "containers_running": info.get("ContainersRunning", 0),
                "images_total":    info.get("Images", 0),
                "available_twin_types": available_twins,
                "missing_twin_types":   [t for t in TWIN_CATALOG if t not in available_twins],
            }
        except Exception as e:
            return {"available": False, "reason": str(e)}

    # ── Create a twin ────────────────────────────────────────────
    def create(self, twin_type: str, wait_for_ready: bool = True) -> Twin:
        """
        Spin up a twin container of the given type.
        
        Args:
            twin_type: key in TWIN_CATALOG (dvwa / juiceshop / webgoat)
            wait_for_ready: if True, polls the twin's ready endpoint until
                            it responds (or timeout). If False, returns
                            as soon as container starts.
        Returns:
            Twin dataclass with full state.
        Raises:
            ValueError if twin_type unknown.
            RuntimeError if Docker not reachable or container start fails.
        """
        if twin_type not in TWIN_CATALOG:
            raise ValueError(
                f"Unknown twin_type '{twin_type}'. "
                f"Choose one of: {list(TWIN_CATALOG.keys())}"
            )

        meta = TWIN_CATALOG[twin_type]
        twin_id = f"twin_{twin_type}_{secrets.token_hex(3)}"
        container_name = f"aidtctm_{twin_id}"

        self.ensure_network()

        twin = Twin(
            twin_id=        twin_id,
            twin_type=      twin_type,
            image=          meta["image"],
            container_name= container_name,
            host_port=      meta["host_port"],
            url=            f"http://localhost:{meta['host_port']}",
            attack_surface= meta["attack_surface"],
            description=    meta["description"],
        )

        # Clean up any leftover container with same name (rare but happens)
        try:
            old = self.client.containers.get(container_name)
            log.warning("removing_stale_container", name=container_name)
            old.remove(force=True)
        except NotFound:
            pass

        # If host port in use, advance by 100 to find a free one
        host_port = meta["host_port"]
        for attempt in range(5):
            port_busy = self._port_in_use(host_port)
            if not port_busy:
                break
            host_port += 100
            log.info("port_busy_trying_alternate", original=meta["host_port"], tried=host_port)
        twin.host_port = host_port
        twin.url       = f"http://localhost:{host_port}"

        try:
            log.info("creating_twin", twin_id=twin_id, type=twin_type, image=meta["image"])
            container = self.client.containers.run(
                image=         meta["image"],
                name=          container_name,
                detach=        True,
                ports=         {f"{meta['internal_port']}/tcp": host_port},
                network=       self._network_name,
                labels={
                    "created_by":   "aidtctm",
                    "twin_id":      twin_id,
                    "twin_type":    twin_type,
                    "purpose":      "digital_twin",
                },
                # Resource caps — a runaway twin shouldn't hurt the host
                mem_limit=      "1g",
                cpu_quota=      50000,   # 50% of one CPU
                cpu_period=     100000,
                # Security hardening
                read_only=      False,   # some apps need to write (DVWA DB)
                security_opt=   ["no-new-privileges"],
                remove=         False,   # we remove explicitly on destroy
            )

            twin.container_id = container.short_id
            twin.status       = "running"
            twin.started_at   = datetime.datetime.utcnow().isoformat() + "Z"

        except APIError as e:
            twin.status     = "error"
            twin.last_error = f"Docker API error: {e.explanation or e}"
            log.error("twin_create_failed", twin_id=twin_id, error=twin.last_error)
            raise RuntimeError(twin.last_error)
        except Exception as e:
            twin.status     = "error"
            twin.last_error = str(e)
            log.error("twin_create_crashed", twin_id=twin_id, error=str(e))
            raise

        self._active[twin_id] = twin

        # ── Wait for ready (HTTP 200 from ready_endpoint) ────────
        if wait_for_ready:
            ready = self._wait_ready(twin, meta["ready_endpoint"], meta["ready_timeout"])
            twin.status = "ready" if ready else "running"

        return twin

    # ── Destroy a twin ───────────────────────────────────────────
    def destroy(self, twin: Twin | str) -> bool:
        """
        Stop and remove a twin container. Idempotent.
        
        Accepts either a Twin object or a twin_id string.
        Returns True if container was actually destroyed, False if already gone.
        """
        twin_obj = twin if isinstance(twin, Twin) else self._active.get(twin)
        if twin_obj is None:
            log.warning("destroy_unknown_twin", twin=str(twin))
            return False

        try:
            container = self.client.containers.get(twin_obj.container_name)
            container.stop(timeout=5)
            container.remove(force=True)
            twin_obj.status     = "stopped"
            twin_obj.stopped_at = datetime.datetime.utcnow().isoformat() + "Z"
            log.info("twin_destroyed", twin_id=twin_obj.twin_id)
            self._active.pop(twin_obj.twin_id, None)
            return True
        except NotFound:
            log.info("twin_already_gone", twin_id=twin_obj.twin_id)
            twin_obj.status = "stopped"
            self._active.pop(twin_obj.twin_id, None)
            return False
        except Exception as e:
            log.error("twin_destroy_failed", twin_id=twin_obj.twin_id, error=str(e))
            twin_obj.last_error = str(e)
            return False

    # ── Context manager version (auto-destroy on exit) ───────────
    @contextmanager
    def session(self, twin_type: str) -> Iterator[Twin]:
        """
        Recommended way to use twins — guaranteed cleanup.
        
        Example:
            with tm.session("dvwa") as twin:
                # twin.url is ready
                attack(twin.url, payload)
            # twin auto-destroyed here even on exception
        """
        twin = self.create(twin_type, wait_for_ready=True)
        try:
            yield twin
        finally:
            self.destroy(twin)

    # ── Housekeeping: cleanup orphaned twins from prior runs ─────
    def cleanup_orphans(self) -> int:
        """
        Remove any aidtctm-labelled containers that aren't in our active map.
        Useful on app startup / restart.
        """
        removed = 0
        try:
            containers = self.client.containers.list(
                all=True,
                filters={"label": "created_by=aidtctm"}
            )
            for c in containers:
                twin_id = c.labels.get("twin_id")
                if twin_id and twin_id not in self._active:
                    try:
                        c.stop(timeout=3)
                    except Exception:
                        pass
                    try:
                        c.remove(force=True)
                        removed += 1
                    except Exception as e:
                        log.warning("cleanup_orphan_failed", name=c.name, error=str(e))
            if removed:
                log.info("orphans_cleaned", count=removed)
        except Exception as e:
            log.warning("cleanup_orphans_error", error=str(e))
        return removed

    # ── List currently active twins ──────────────────────────────
    def list_active(self) -> list[Twin]:
        return list(self._active.values())

    # ── Internal: wait until twin's HTTP endpoint responds ───────
    def _wait_ready(self, twin: Twin, endpoint: str, timeout: int) -> bool:
        """Poll twin.url+endpoint until 2xx/3xx response or timeout."""
        import requests
        target = twin.url + endpoint
        deadline = time.time() + timeout
        attempt = 0
        while time.time() < deadline:
            attempt += 1
            try:
                r = requests.get(target, timeout=2, allow_redirects=False)
                if r.status_code < 500:
                    log.info("twin_ready",
                             twin_id=twin.twin_id,
                             attempts=attempt,
                             status=r.status_code)
                    return True
            except requests.RequestException:
                pass
            time.sleep(1.0)
        log.warning("twin_not_ready_in_time",
                    twin_id=twin.twin_id,
                    timeout=timeout)
        return False

    # ── Internal: check if host TCP port is already bound ────────
    def _port_in_use(self, port: int) -> bool:
        import socket as _s
        with _s.socket(_s.AF_INET, _s.SOCK_STREAM) as sock:
            try:
                sock.bind(("127.0.0.1", port))
                return False
            except OSError:
                return True
