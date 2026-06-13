"""
AI-DTCTM | APK Source Workbench
══════════════════════════════════════════════════════════════════════
"Clone" an APK into a real file explorer + readable views, the same way
the ZIP code clone works. No emulator needed — this is what every real
APK security analyst actually wants.

What it does:
  1. Unpack the APK (it's a zip) into a persistent sandbox dir
  2. Decode binary AndroidManifest.xml into readable XML (via apkInspector)
  3. Extract printable strings from every classes*.dex (Java strings + methods)
  4. Index every file (path, size, ext, viewability)
  5. Build the "attack surface": URLs, IPs, hardcoded secrets, suspicious tokens
  6. Tag files that contain critical/high forensic findings

The sandbox is what the UI walks as a file tree. read_apk_file() returns
the appropriate readable view per file type.
"""
from __future__ import annotations

import io
import os
import re
import secrets
import shutil
import struct
import zipfile
from pathlib import Path

from core.logger import get_logger

log = get_logger(__name__)

# Same sandbox layout as the source clones live under
try:
    from core.source_clone import SANDBOX_ROOT as _SRC_SANDBOX
    APK_SANDBOX = _SRC_SANDBOX.parent / "apk_workbench"
except Exception:
    APK_SANDBOX = Path("data") / "apk_workbench"


# ── File-type config ──────────────────────────────────────────────
_TEXT_EXTS = {
    "xml", "json", "txt", "properties", "html", "htm", "css", "js",
    "java", "kt", "smali", "yml", "yaml", "md", "csv", "ini",
}
_ICONS = {
    "xml": "📄", "json": "📋", "txt": "📝", "properties": "⚙️",
    "html": "🌐", "css": "🎨", "js": "📜", "java": "☕", "kt": "🇰",
    "smali": "🪄", "dex": "📦", "so": "🔧", "arsc": "🗂️",
    "rsa": "🔐", "dsa": "🔐", "ec": "🔐", "sf": "📜",
    "png": "🖼️", "jpg": "🖼️", "jpeg": "🖼️", "webp": "🖼️",
    "gif": "🖼️", "ttf": "🔤", "otf": "🔤", "woff": "🔤",
    "mp3": "🎵", "mp4": "🎬", "ogg": "🎵",
}

# ── Attack-surface signatures (run against extracted strings) ─────
_URL_RE   = re.compile(rb"https?://[A-Za-z0-9.\-/_:%?=&#~+]+")
_IP_RE    = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_AWS_RE   = re.compile(rb"AKIA[0-9A-Z]{16}")
_GOOG_RE  = re.compile(rb"AIza[0-9A-Za-z\-_]{35}")
_GH_RE    = re.compile(rb"ghp_[A-Za-z0-9]{36}")
_FB_RE    = re.compile(rb"[a-z0-9]{20,40}firebaseio\.com")
_JWT_RE   = re.compile(rb"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")
_BEARER_RE= re.compile(rb"(?:Bearer|bearer)\s+[A-Za-z0-9._\-]{20,}")
_SECRET_RE= re.compile(rb"(?:secret|api[_-]?key|token|password)['\"]?\s*[:=]\s*['\"][A-Za-z0-9+/=_\-]{8,}['\"]", re.IGNORECASE)

# Hosts that are noise (Google/Android boilerplate)
_NOISE_HOSTS = {
    "schemas.android.com", "schemas.openxmlformats.org",
    "www.w3.org", "ns.adobe.com", "java.sun.com",
    "purl.org", "www.apache.org", "xml.apache.org",
}


def _now_id() -> str:
    return "apkwb_" + secrets.token_hex(3)


# ══════════════════════════════════════════════════════════════════
# DEX STRING EXTRACTION (pure Python, no JVM)
# ══════════════════════════════════════════════════════════════════
def extract_dex_strings(dex_bytes: bytes, max_strings: int = 4000) -> list[str]:
    """
    Parse the DEX header and walk string_ids → string_data_off to extract
    every Java/Kotlin/native string the code references.
    """
    out: list[str] = []
    try:
        if len(dex_bytes) < 0x70 or dex_bytes[:4] != b"dex\n":
            return out
        # header.string_ids_size (offset 0x38), string_ids_off (0x3C)
        sids_count = struct.unpack_from("<I", dex_bytes, 0x38)[0]
        sids_off   = struct.unpack_from("<I", dex_bytes, 0x3C)[0]
        if sids_count == 0 or sids_off + 4 * sids_count > len(dex_bytes):
            return out
        cap = min(sids_count, max_strings)
        for i in range(cap):
            data_off = struct.unpack_from("<I", dex_bytes, sids_off + 4 * i)[0]
            if data_off >= len(dex_bytes):
                continue
            # ULEB128 length prefix, then MUTF-8 bytes terminated by 0x00
            length, p = _read_uleb(dex_bytes, data_off)
            if length is None or p is None or p >= len(dex_bytes):
                continue
            end = dex_bytes.find(b"\x00", p)
            if end < 0:
                continue
            s = dex_bytes[p:end]
            try:
                txt = s.decode("utf-8", errors="replace")
            except Exception:
                continue
            if len(txt) >= 3:
                out.append(txt)
    except Exception as e:
        log.debug("dex_string_parse_failed", error=str(e)[:80])
    return out


def _read_uleb(buf: bytes, off: int) -> tuple[int, int] | tuple[None, None]:
    """Read an unsigned LEB128 starting at off. Returns (value, new_offset)."""
    try:
        v = 0; shift = 0
        for _ in range(5):
            if off >= len(buf):
                return None, None
            b = buf[off]; off += 1
            v |= (b & 0x7F) << shift
            if not (b & 0x80):
                return v, off
            shift += 7
        return v, off
    except Exception:
        return None, None


# ══════════════════════════════════════════════════════════════════
# ELF (.so) — exported symbols + readable strings
# ══════════════════════════════════════════════════════════════════
def parse_native_lib(blob: bytes) -> dict:
    """Quick ELF inspection — arch + symbol-table strings (best-effort)."""
    out: dict = {"arch": "?", "symbols": [], "strings": []}
    if not blob.startswith(b"\x7fELF"):
        return out
    try:
        cls = blob[4]  # 1=32, 2=64
        machine = struct.unpack_from("<H", blob, 0x12)[0]
        m = {0x28: "ARM", 0xb7: "ARM64", 0x3e: "x86_64",
             0x03: "x86", 0xf3: "RISC-V"}.get(machine, f"machine 0x{machine:x}")
        out["arch"] = f"ELF {'64' if cls==2 else '32'}-bit · {m}"
        # Extract any printable ASCII strings ≥4 chars from the entire file
        printable = re.findall(rb"[\x20-\x7e]{4,}", blob)[:200]
        out["strings"] = [s.decode("ascii", "ignore") for s in printable]
    except Exception:
        pass
    return out


# ══════════════════════════════════════════════════════════════════
# ATTACK SURFACE — every URL, IP, secret across the whole APK
# ══════════════════════════════════════════════════════════════════
def extract_attack_surface(blob_iter) -> dict:
    """
    blob_iter yields (path, bytes). Returns dedup'd attack surface.
    """
    urls: dict[str, list[str]] = {}     # url -> [paths where seen]
    ips: dict[str, list[str]] = {}
    aws: list[tuple[str, str]] = []     # (path, match)
    google: list[tuple[str, str]] = []
    github: list[tuple[str, str]] = []
    jwt: list[tuple[str, str]] = []
    bearer: list[tuple[str, str]] = []
    secrets_hits: list[tuple[str, str]] = []

    for path, raw in blob_iter:
        for u in _URL_RE.findall(raw):
            s = u.decode("ascii", "ignore")
            host = re.sub(r"^https?://", "", s).split("/", 1)[0].lower()
            if host in _NOISE_HOSTS:
                continue
            urls.setdefault(s, []).append(path)
        for ip in _IP_RE.findall(raw):
            s = ip.decode("ascii", "ignore")
            # Skip well-known noise IPs (0.0.0.0, 127.0.0.1, broadcasts)
            if s in ("0.0.0.0", "127.0.0.1", "255.255.255.255"):
                continue
            ips.setdefault(s, []).append(path)
        for m in _AWS_RE.findall(raw):
            aws.append((path, m.decode("ascii", "ignore")))
        for m in _GOOG_RE.findall(raw):
            google.append((path, m.decode("ascii", "ignore")))
        for m in _GH_RE.findall(raw):
            github.append((path, m.decode("ascii", "ignore")))
        for m in _JWT_RE.findall(raw)[:5]:
            jwt.append((path, m.decode("ascii", "ignore")[:90] + "…"))
        for m in _BEARER_RE.findall(raw)[:5]:
            bearer.append((path, m.decode("ascii", "ignore")[:90]))
        for m in _SECRET_RE.findall(raw)[:5]:
            secrets_hits.append((path, m.decode("ascii", "ignore")[:90]))

    return {
        "urls":    sorted(urls.items(), key=lambda kv: -len(kv[1]))[:80],
        "ips":     sorted(ips.items(),  key=lambda kv: -len(kv[1]))[:30],
        "aws":     aws[:10],
        "google":  google[:10],
        "github":  github[:10],
        "jwt":     jwt[:10],
        "bearer":  bearer[:10],
        "secrets": secrets_hits[:20],
    }


# ══════════════════════════════════════════════════════════════════
# MAIN — unpack APK into workbench sandbox
# ══════════════════════════════════════════════════════════════════
def build_apk_workbench(apk_path: str, *,
                        max_files: int = 1500,
                        max_dex_strings: int = 4000) -> dict:
    """
    Unpacks an APK into APK_SANDBOX/<id>/, decodes the manifest,
    indexes every file, and computes the attack surface.

    Returns a dict the UI consumes:
      {
        "apk_id":   str,
        "sandbox":  str  (path),
        "files":    [ {path, rel, name, dir, ext, size, kind, viewable, icon, threat} ],
        "manifest": str  (decoded XML),
        "manifest_error": str|None,
        "dex_strings":   {dex_filename: [strings]},
        "attack_surface": {urls, ips, aws, google, github, jwt, bearer, secrets},
        "stats":  {file_count, dex_count, native_count, total_size},
      }
    """
    apk_path = str(apk_path)
    if not zipfile.is_zipfile(apk_path):
        return {"error": "Not a valid APK (zip) file"}

    apk_id = _now_id()
    APK_SANDBOX.mkdir(parents=True, exist_ok=True)
    sandbox = APK_SANDBOX / apk_id
    sandbox.mkdir(parents=True, exist_ok=True)

    files: list[dict] = []
    dex_strings: dict[str, list[str]] = {}
    blobs_for_surface: list[tuple[str, bytes]] = []
    manifest_text = ""
    manifest_err = None
    total_size = 0
    dex_count = 0
    native_count = 0

    try:
        with zipfile.ZipFile(apk_path, "r") as z:
            members = [m for m in z.infolist() if not m.is_dir()]
            members.sort(key=lambda m: m.filename.lower())

            for m in members[:max_files]:
                rel = m.filename.replace("\\", "/")
                ext = rel.rsplit(".", 1)[-1].lower() if "." in rel else ""
                size = m.file_size
                total_size += size

                # Extract to sandbox (skip absolute / parent-traversal)
                if rel.startswith("/") or ".." in rel.split("/"):
                    continue
                out_path = sandbox / rel
                out_path.parent.mkdir(parents=True, exist_ok=True)
                try:
                    with z.open(m) as src, open(out_path, "wb") as dst:
                        shutil.copyfileobj(src, dst)
                except Exception:
                    continue

                # Kind classification → "viewable" feeds the UI explorer
                if rel == "AndroidManifest.xml":
                    kind = "manifest"
                    viewable = True
                elif ext == "dex":
                    kind = "dex"; viewable = True; dex_count += 1
                elif ext == "so":
                    kind = "native"; viewable = True; native_count += 1
                elif rel.startswith("META-INF/") and ext in ("rsa", "dsa", "ec"):
                    kind = "cert"; viewable = True
                elif ext == "arsc":
                    kind = "resources"; viewable = True
                elif ext in _TEXT_EXTS:
                    kind = "text"; viewable = True
                elif ext in ("png", "jpg", "jpeg", "webp", "gif"):
                    kind = "image"; viewable = True
                else:
                    kind = "binary"; viewable = False

                # Pull bytes for the attack-surface scan (text files + DEX + so + assets)
                if viewable and size > 0 and size < 4_000_000:
                    try:
                        b = out_path.read_bytes()
                        if kind in ("text", "manifest", "resources",
                                    "dex", "native") or rel.startswith("assets/"):
                            blobs_for_surface.append((rel, b))
                        if kind == "dex":
                            dex_strings[rel] = extract_dex_strings(
                                b, max_strings=max_dex_strings)
                    except Exception:
                        pass

                files.append({
                    "path":     str(out_path),
                    "rel":      rel,
                    "name":     rel.rsplit("/", 1)[-1],
                    "dir":      rel.rsplit("/", 1)[0] if "/" in rel else ".",
                    "ext":      ext,
                    "size":     size,
                    "kind":     kind,
                    "viewable": viewable,
                    "icon":     _ICONS.get(ext, "📄"),
                    "threat":   False,   # filled in by the caller from forensic results
                })

            # Decode AndroidManifest if present
            try:
                from apkInspector.axml import get_manifest
                blob = z.read("AndroidManifest.xml")
                manifest_text = get_manifest(io.BytesIO(blob))
            except KeyError:
                manifest_err = "AndroidManifest.xml missing from APK"
            except Exception as e:
                manifest_err = f"AXML decode failed: {e}"
    except Exception as e:
        log.error("apk_workbench_unpack_failed", error=str(e))
        return {"error": f"unpack failed: {e}"}

    attack_surface = extract_attack_surface(iter(blobs_for_surface))

    return {
        "apk_id":         apk_id,
        "sandbox":        str(sandbox),
        "files":          files,
        "manifest":       manifest_text,
        "manifest_error": manifest_err,
        "dex_strings":    dex_strings,
        "attack_surface": attack_surface,
        "stats": {
            "file_count":   len(files),
            "dex_count":    dex_count,
            "native_count": native_count,
            "total_size":   total_size,
        },
    }


def read_apk_file(file_meta: dict, dex_strings_map: dict | None = None,
                  attack_surface_per_path: dict | None = None) -> dict:
    """
    Render a single file from the workbench into something displayable.
    Returns: {"view": "text"|"binary"|"image"|"strings"|"native"|"cert",
              "content": str, "language": str, "extra": dict}
    """
    path = file_meta["path"]
    kind = file_meta["kind"]
    rel = file_meta["rel"]
    ext = file_meta["ext"]
    size = file_meta["size"]

    try:
        raw = Path(path).read_bytes() if size <= 4_000_000 else b""
    except Exception:
        raw = b""

    if kind == "manifest":
        # Caller already has decoded XML on workbench["manifest"] —
        # but if they ask for the file directly, just show its raw bytes hex.
        return {"view": "binary", "language": "text",
                "content": f"# Binary AndroidManifest.xml ({size} bytes)\n"
                           "# Decoded readable XML is shown in the dedicated\n"
                           "# 'Decoded manifest' tab.",
                "extra": {}}

    if kind == "dex":
        strs = (dex_strings_map or {}).get(rel, [])
        head = (f"# {rel} — {size:,} bytes\n"
                f"# Extracted {len(strs)} strings from string_ids table\n"
                f"# (showing first 800; full list in workbench data)\n\n")
        body = "\n".join(strs[:800])
        return {"view": "strings", "language": "text",
                "content": head + body, "extra": {"total_strings": len(strs)}}

    if kind == "native":
        info = parse_native_lib(raw)
        head = (f"# {rel} — {size:,} bytes\n"
                f"# {info['arch']}\n"
                f"# Extracted {len(info['strings'])} printable strings\n\n")
        body = "\n".join(info["strings"][:500])
        return {"view": "native", "language": "text",
                "content": head + body, "extra": info}

    if kind == "resources":
        # We don't fully parse the arsc tree — strings are the useful part.
        printable = re.findall(rb"[\x20-\x7e]{4,}", raw)[:600]
        return {"view": "strings", "language": "text",
                "content": (f"# {rel} — {size:,} bytes (binary resource table)\n"
                            "# Printable strings extracted from the arsc:\n\n"
                            + "\n".join(s.decode("ascii", "ignore")
                                        for s in printable)),
                "extra": {}}

    if kind == "cert":
        head = f"# {rel} — {size:,} bytes (PKCS#7 signature block)\n"
        printable = re.findall(rb"[\x20-\x7e]{5,}", raw)[:80]
        identity = [s for s in printable
                    if any(t in s for t in (b"CN=", b"O=", b"L=", b"OU="))]
        body = "\n".join(s.decode("ascii", "ignore") for s in (identity or printable))
        return {"view": "cert", "language": "text",
                "content": head + body, "extra": {}}

    if kind == "image":
        # Streamlit can render images from raw bytes via st.image
        return {"view": "image", "language": "", "content": "",
                "extra": {"image_bytes": raw}}

    if kind == "text":
        try:
            txt = raw.decode("utf-8", errors="replace")
        except Exception:
            txt = raw.decode("latin-1", errors="replace")
        lang = {"xml": "xml", "json": "json", "txt": "text",
                "html": "html", "css": "css", "js": "javascript",
                "java": "java", "kt": "kotlin", "smali": "text",
                "yml": "yaml", "yaml": "yaml", "properties": "properties",
                "md": "markdown"}.get(ext, "text")
        return {"view": "text", "language": lang, "content": txt, "extra": {}}

    # binary fallback — hex preview
    return {"view": "binary", "language": "text",
            "content": _hex_preview(raw[:512]),
            "extra": {"truncated": True}}


def _hex_preview(b: bytes) -> str:
    """Classic xxd-style preview of binary content."""
    rows = []
    for off in range(0, len(b), 16):
        chunk = b[off:off + 16]
        hexstr = " ".join(f"{x:02x}" for x in chunk).ljust(48)
        ascii_ = "".join(chr(x) if 32 <= x < 127 else "." for x in chunk)
        rows.append(f"{off:08x}  {hexstr}  |{ascii_}|")
    return "\n".join(rows)


def destroy_apk_workbench(apk_id: str) -> bool:
    """Wipe the unpacked sandbox for an APK."""
    try:
        d = APK_SANDBOX / apk_id
        if d.exists():
            shutil.rmtree(d, ignore_errors=True)
        return True
    except Exception:
        return False
