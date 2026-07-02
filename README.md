# EMET — Defensive Vulnerability Intelligence Platform

EMET orchestrates open-source and commercial vulnerability scanners, normalizes
their output into a single schema, enriches findings with **real** threat
intelligence, and layers AI-assisted analysis on top — with transparent
provenance for every value it reports.

It is a defensive tool. It does not generate or run exploit code.

## What EMET actually does

**Scanning & normalization (core, works out of the box for installed tools)**
- Runs scanners as real subprocesses: Nmap, Rustscan, Nuclei, Nikto, Trivy,
  Semgrep, Gitleaks, ZAP, plus adapters for Nessus/OpenVAS reports. Each runner
  checks tool availability and degrades gracefully when a tool is missing.
- Normalizes every result into one `UnifiedFinding` schema (CVSS, CWE, ports,
  evidence, references), deduplicates, and records per-scanner run status so
  partial failures are visible rather than hidden.

**Threat-intelligence enrichment (real data, no fabrication)**
- **NVD** — CVSS base score and references pulled from the NVD CVE API 2.0.
- **EPSS** — exploitation probability from the FIRST.org EPSS API.
- **CISA KEV** — known-exploited status from the official CISA KEV feed (cached
  locally; refresh with `python scripts/download_cisa_kev.py`).
- A `dynamic_risk_score` combines CVSS + EPSS + KEV. When a feed is unreachable,
  the corresponding value stays at its default — EMET never invents a score.

**AI analysis (optional, honest fallback)**
- Google Gemini summarizes findings grounded on retrieved context. Without a
  valid `GEMINI_API_KEY`, EMET returns an explicit "AI analysis unavailable"
  response instead of fabricating one.
- RAG chat retrieves from ingested CVE knowledge and your own scan findings.

**Access control**
- Cookie-based JWT auth with scopes (`read`/`write`) and roles, plus tenant
  isolation endpoints (global-admin gated).

**Compliance mapping**
- Maps findings to SOC2 / PCI-DSS / HIPAA controls using a documented
  severity- and KEV-based heuristic (not a certified control-mapping engine).

## Integrations that require configuration

These talk to real external systems. Without credentials they report their state
honestly and take no action — they never fake success:

| Integration | Configured with | Behavior when unconfigured |
|---|---|---|
| Jira ticketing | `JIRA_BASE_URL`, `JIRA_EMAIL`, `JIRA_API_TOKEN`, `JIRA_PROJECT_KEY` | Ticket tracked locally, reported `synced: false` |
| Patch automation | `EMET_PATCH_PLAYBOOK` + `ansible-playbook` on PATH | Job status `not_configured`, no patch applied |
| CSPM connectors | AWS/GCP/Azure provider credentials | Status `not_configured` |

## Architecture

- `frontend/` — Next.js (App Router) console with a light neobrutalist UI.
- `backend/` — FastAPI orchestration layer; Redis for queues/pub-sub; SQLAlchemy
  over SQLite (dev) or PostgreSQL (prod).
- `agent/` — lightweight monitoring agent client.
- `scripts/` — dataset/feed download and index-build utilities.

## Quick start (Docker)

```bash
cp .env.example .env      # fill in SECRET_KEY etc.
docker compose up --build
```

- Dashboard: http://localhost:3000
- API docs: http://localhost:8000/docs

**Demo credentials:** `admin` / `emet`, `analyst@emet.local` / `emet`, or guest
(read-only). Change these before any real deployment.

## Manual run

```bash
# Backend (needs Redis; SQLite works for local dev)
cd backend
python3.12 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload
python worker.py          # background scan worker

# Frontend
cd frontend && npm install && npm run dev
```

## Tests

```bash
cd backend && pytest      # 76 tests
```

Enrichment tests exercise the live EPSS/KEV feeds and degrade gracefully offline.

## Security

Defensive use only. Target validation blocks SSRF and argument-injection vectors;
data-at-rest encryption and signed audit logging are configurable. Validate that
you are authorized to scan any target before running EMET against it.
