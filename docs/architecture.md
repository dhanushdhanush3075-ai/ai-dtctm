# AI-DTCTM · Architecture

## Design philosophy

AI-DTCTM is built on three hard rules, each of which rejects a common student-project shortcut:

1. **No synthetic data where real is available.** Every threat score, every accuracy number, every report field is traceable to a real source — a live API response, a real CVE record, or a container's real filesystem. The ML model is trained on CICIDS2017 real attack traffic, not a noise generator that "looks like" attacks.

2. **No simulated attacks where real ones are safe.** Attacks are executed inside isolated Docker containers (DVWA, WebGoat, Juice Shop) that ship pre-vulnerable by design. The SQL-injection proof is a real database dump from a real MySQL instance inside a real container — not a pre-written string.

3. **No vendor lock-in on external intel.** Every external API has a defined `APIResult` schema, a cache wrapper, and a "disabled but non-crashing" fallback. If VirusTotal is down or the key is missing, the rest of the pipeline continues and the report simply marks that source as `unavailable`.

## Layered architecture

```
╔═══════════════════════════════════════════════════════════════╗
║                       Presentation Layer                      ║
║  Streamlit UI · Mission Control theme · multi-page navigation ║
╠═══════════════════════════════════════════════════════════════╣
║                     Orchestration Layer                       ║
║  url_analyzer · file_scanner · twin_manager · shield_engine   ║
╠═══════════════════════════════════════════════════════════════╣
║                       Intelligence Layer                      ║
║          ML ensemble  ·  YARA rules  ·  12 API clients        ║
╠═══════════════════════════════════════════════════════════════╣
║                       Foundation Layer                        ║
║     config  ·  cache (TTL)  ·  logger  ·  db_manager          ║
╚═══════════════════════════════════════════════════════════════╝
```

Each layer depends only on the layer below it. The foundation layer has zero inter-module imports; it's the bedrock.

## Data flow — URL scan example

```
User submits URL via UI
         │
         ▼
  url_analyzer.full_scan(url)
         │
         ├──▶ api_clients.virustotal.scan_url(url)
         ├──▶ api_clients.google_safebrowsing.scan_url(url)
         ├──▶ api_clients.urlscan.scan_url(url)
         ├──▶ api_clients.phishtank.check_url(url)
         ├──▶ api_clients.otx.lookup_indicator(url, "url")
         ├──▶ api_clients.urlhaus.lookup(url)
         ├──▶ Local heuristics: DNS, SSL, redirect chain, body scan
         ├──▶ ML classifier (url_features → prediction)
         │
         ▼
  Fusion scorer merges all APIResults into one risk score 0-10
         │
         ▼
  If score ≥ RISK_HIGH → offer twin creation (Docker)
         │
         ▼
  report_gen writes case-file JSON + optional PDF
```

## Cache layer — why it's load-bearing

Without the cache, a demo that scans 5 URLs burns 5 × 6 = 30 API requests. VirusTotal's 4-req/minute limit would rate-limit you within seconds during a live viva.

With `@cached(ttl=600)` wrapping every client function:
- Second scan of the same URL within 10 min returns in ~2ms from SQLite
- `CFG.is_demo` tripling the TTL makes viva runs effectively rate-limit-free
- Empty / error responses are not cached → transient network failures self-heal

Cache storage: single `data/cache.db` SQLite file, one `cache` table, indexed on `expires_at`.

## Twin lifecycle — the Docker contract

```
      start              attack             teardown
        │                  │                   │
create_twin(url) ──▶ run_attack(payload) ──▶ destroy_twin()
        │                  │                   │
        ▼                  ▼                   ▼
 docker run -d        HTTP request to     docker stop + rm
 --network=isolated   localhost:808X       remove volume
 --name=twin_XXXX     capture response     log forensic artefact
```

The isolated network (`aidtctm_twin_net`) is a Docker bridge with no external route. Container sees only other containers on the same network, never the host or the internet. Any malicious behaviour is fully contained.

Every twin lives at most a few minutes. Teardown is guaranteed via `contextlib.contextmanager`, so even on exception the container and volume are cleaned up.

## Security boundaries

| Boundary | Enforcement |
|---|---|
| User sessions | PBKDF2 password hashing, 1-hour session timeout, role-based access |
| External API calls | `requests` with `timeout=10s`, SSL verification on |
| Docker twin | Isolated bridge network, `--network=none` option for file-sandbox containers, auto-teardown |
| File uploads | Size limit, extension whitelist, YARA-scanned before storage, never executed |
| Report generation | PDF uses fpdf2 which escapes LaTeX-style injection attempts |
| SQL layer | Parameterised queries everywhere (no string concatenation) |

## Profile differences

| Setting | `dev` | `demo` | `prod` |
|---|---|---|---|
| Log level | DEBUG | INFO | WARNING |
| Cache TTL | 300s (from env) | 900s (3×) | from env |
| Mock fallbacks | On when API fails | On | Off (strict) |
| Error detail shown to UI | Full traceback | Friendly message | Generic "contact admin" |

The profile is a single environment variable `DTCTM_PROFILE` — swap it for different runtime behaviour without code changes.
