# AI-DTCTM — AI-powered Digital Twin Cyber Threat Mitigation

> **Final-year MCA capstone project**
> **Author:** Dhanush S · 311424622006
> **Guide:** Mrs. S. Padmavathi, AP/MCA
> **Institute:** Meenakshi College of Engineering
> **Version:** 20.0.0 · *Mission Control edition*

---

## What this project does

AI-DTCTM is a cybersecurity analysis platform that applies the **Digital Twin** concept — borrowed from automotive and aerospace engineering — to web security.

A Ferrari engineer doesn't crash the real car to test its safety. They build a digital twin, crash the twin, measure the damage, and keep the real car untouched. AI-DTCTM does the same for web systems: given a suspicious URL, file, or service, it clones the target into an isolated Docker container, attacks the clone, and produces a forensic vulnerability report — all while the original system stays safe.

## Why this is different

Most student cybersecurity projects stop at signature-based detection and synthetic data. AI-DTCTM wires in ten real-world external security feeds, trains its ML model on the CICIDS2017 real-attack dataset, and actually runs attacks inside live Docker containers — not pre-scripted fake results.

| Capability | Implementation |
|---|---|
| Real threat intel | VirusTotal · Google Safe Browsing · URLScan · PhishTank · AbuseIPDB · OTX · Shodan · NVD · CISA KEV · MalwareBazaar · URLhaus · ThreatFox |
| Real Digital Twin | Docker SDK orchestrating isolated DVWA / WebGoat / Juice Shop containers on an internal network |
| Real ML accuracy | Trained on CICIDS2017 (2.8M real labelled flows) — honest 95%+ accuracy, no synthetic inflation |
| Real file analysis | YARA rule engine + SHA-256 hash lookup — no malware transmission, fully offline-capable |
| Real network monitor | psutil + AbuseIPDB IP reputation + geolocation — not random fake packet counters |

---

## Architecture

```
                 ┌──────────────────────┐
                 │    Streamlit UI      │  ← "Mission Control" theme
                 │    (Auth gated)      │
                 └──────────┬───────────┘
                            │
        ┌───────────────────┼───────────────────┐
        │                   │                   │
   ┌────▼────┐       ┌──────▼──────┐      ┌─────▼──────┐
   │  ML     │       │  URL / IP   │      │  Digital    │
   │ engine  │       │  scanner    │      │  twin       │
   │         │       │             │      │  manager    │
   │ CICIDS  │       │  10+ APIs   │      │  Docker     │
   │ trained │       │  aggregated │      │  SDK        │
   └────┬────┘       └──────┬──────┘      └─────┬──────┘
        │                   │                   │
        └───────────────────┼───────────────────┘
                            │
                 ┌──────────▼───────────┐
                 │  SQLite TTL cache    │  ← rate-limit safety net
                 └──────────┬───────────┘
                            │
                 ┌──────────▼───────────┐
                 │  Structured logger   │  ← JSON output, grep-able
                 └──────────────────────┘
```

---

## Quick start

**Prerequisites:** Python 3.11+, Docker Desktop, Git.

```bash
# Clone
git clone <your-repo-url> AI_DTCTM
cd AI_DTCTM

# Virtual environment
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Environment
cp .env.example .env
# Edit .env and paste your free API keys (see DAY1_SETUP_GUIDE.md)

# Pull Digital Twin target images
./scripts/pull_docker_images.sh

# Verify all configured APIs respond
python scripts/verify_apis.py

# Launch
streamlit run main_project.py
# Opens at http://localhost:8501
```

**Full setup (step-by-step, every install, every API):** see [`DAY1_SETUP_GUIDE.md`](./DAY1_SETUP_GUIDE.md).

---

## Docker Compose — one-command full stack

For demos, spin up the app AND all three Digital Twin targets on an isolated network with one command:

```bash
docker compose up -d
```

This brings up:
- `aidtctm` — the main app at `http://localhost:8501`
- `dvwa` — DVWA target at `http://localhost:8081` (internal)
- `webgoat` — WebGoat target at `http://localhost:8082` (internal)
- `juiceshop` — Juice Shop target at `http://localhost:8083` (internal)

The twin targets are on an **internal** network — they cannot reach the internet, which is the key safety property of the racing-car concept. The original systems being studied can never be affected by anything happening inside the twin.

---

## Project structure

```
AI_DTCTM/
├── main_project.py              ← Streamlit entrypoint
├── auth_ui.py                   ← Login/register page
├── config.py                    ← Profiles + env loading
├── requirements.txt
├── pyproject.toml               ← Ruff / mypy / pytest config
├── Dockerfile                   ← App containerization
├── docker-compose.yml           ← Full stack orchestration
│
├── core/
│   ├── cache.py                 ← SQLite TTL cache (rate-limit safety)
│   ├── logger.py                ← Structured JSON logger
│   ├── shared_css.py            ← Mission Control theme
│   ├── yara_scanner.py          ← Local malware pattern detection
│   ├── api_clients/             ← 12 external API integrations
│   └── yara_rules/              ← *.yar files
│
├── scripts/
│   ├── verify_apis.py           ← Day 1 smoke test
│   └── pull_docker_images.sh
│
├── tests/                       ← pytest suite
├── .github/workflows/ci.yml     ← Lint + test on every push
├── DAY1_SETUP_GUIDE.md          ← Full install & registration walkthrough
└── docs/                        ← Architecture + demo scripts
```

---

## Development

```bash
# Lint (fast — under 1 sec)
ruff check .
ruff format --check .

# Type check
mypy core/

# Run tests
pytest

# Coverage report
pytest --cov-report=html && open htmlcov/index.html
```

---

## Configuration profiles

| Profile | Purpose | Logging | Caching |
|---|---|---|---|
| `dev` | Local development | DEBUG | Default TTL |
| `demo` | Live presentations | INFO | 3× TTL (no rate-limit surprises) |
| `prod` | Hardened deployment | WARNING | Default TTL |

Set via `DTCTM_PROFILE` in `.env`.

---

## Design system — "Mission Control"

The UI is intentionally unlike generic student cybersecurity dashboards. Instead of the cyan-on-navy "hacker terminal" aesthetic, AI-DTCTM uses a warm-amber Bloomberg-terminal palette with IBM Plex Sans + Plex Mono, flat surfaces, and Bloomberg-style data readouts.

| Token | Value | Role |
|---|---|---|
| Background | `#0F0D10` | Warm near-black |
| Surface | `#1A1618` | Raised panels |
| Primary accent | `#FF6B1A` | Signal amber |
| Success | `#9ACD32` | Sodium green |
| Critical | `#E63946` | Alert red |
| Text | `#F5E8D8` | Warm ivory |

---

## References

- **CICIDS2017 dataset** — Sharafaldin, Lashkari, Ghorbani; UNB CIC
- **Docker** — official Python SDK docs
- **YARA** — Victor Alvarez; yara.readthedocs.io
- **OWASP Top 10** — 2021 edition
- **MITRE ATT&CK** — framework for adversary tactics
- **NVD CVE** — NIST National Vulnerability Database

---

## License

MIT License — see LICENSE file.

This project is submitted as partial fulfillment of the Master of Computer Applications (MCA) degree at Meenakshi College of Engineering.
