# EMET - Defensive Vulnerability Intelligence Platform (Phase 1)

EMET is a defensive-first vulnerability orchestration platform focused on evidence, provenance, and analyst workflows.

## What is implemented in Phase 1

- Auth with httpOnly JWT cookies and refresh rotation
- Scan job orchestration with queue-backed worker
- SSE scan progress streaming (`/api/scan/{scan_id}/events`)
- Scanner interfaces for Nmap, Rustscan, Nuclei (Nmap wired end-to-end)
- Unified finding schema with verification and confidence fields
- Reports page and CVE Explorer foundation
- Defensive attack-path page foundation
- RAG chat fallback mode without managed model key
- Evaluation run history foundation
- Audit log API and viewer page

## Repo structure

- `frontend/` - Next.js App Router UI
- `backend/` - FastAPI APIs, scanner orchestration, worker
- `docs/` - setup and operational docs

## Quick start (Docker)

1. Copy environment file

```bash
cp .env.example .env
```

2. Start stack

```bash
docker compose up --build
```

3. Open app and API health

- Frontend: `http://localhost:3000`
- Backend health: `http://localhost:8000/api/health`
- Backend readiness: `http://localhost:8000/api/readiness`

4. Demo credentials

- Analyst: `analyst@emet.local` / `emet`
- Guest (read-only): `guest` / `emet`

## Optional graph mode

Start Neo4j only when needed:

```bash
docker compose --profile graph up -d neo4j
```

## Manual run (without Docker)

Frontend:

```bash
cd frontend
npm install
npm run dev
```

Backend:

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

Worker:

```bash
cd backend
source .venv/bin/activate
python worker.py
```

## Notes

- EMET is defensive-only and does not generate exploit code.
- Private/internal targets are blocked unless `ALLOW_INTERNAL_SCANNING=true`.
- If model keys are missing, RAG and evaluation still run in explicit fallback mode.
