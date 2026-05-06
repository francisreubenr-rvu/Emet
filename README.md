# EMET - Enterprise Defensive Vulnerability Intelligence Platform

EMET (Enterprise Managed Evolutionary Tooling) is a production-ready, defensive-first vulnerability orchestration platform. It combines automated scanning, AI-driven intelligence, and remediation workflows into a unified enterprise suite.

The platform features a distinctive **Professional Neobrutalism 2.0** visual identity, designed for high-performance defensive intelligence operations.

## Key Features (Phase 4 Ready)

- **Agent-Based Architecture**: Deploy lightweight agents for internal network visibility and continuous monitoring.
- **Remediation Orchestration**: Full synchronization with Jira and ServiceNow for end-to-end vulnerability lifecycle management.
- **Automated Patch Deployment**: Orchestrate security patches via Ansible and Terraform directly from the console.
- **Dynamic Risk Scoring**: Advanced prioritization using EPSS, CISA KEV, and internal business context.
- **Compliance Mapping Engine**: Real-time mapping of findings to SOC2, ISO27001, HIPAA, and GDPR controls.
- **Multi-Tenancy & Enterprise RBAC**: Robust access control with tenant isolation and granular permission sets.
- **Scanner Ecosystem**: Support for Nmap, Rustscan, Nuclei, Nikto, Trivy, Zap, and more (all fully normalized).
- **Hardened Security**: Built-in SSRF protection, command injection prevention, and encrypted data at rest.

## Visual Identity

EMET utilizes **Professional Neobrutalism 2.0**:
- **Rugged Tactile UX**: Mechanical button states and industrial control surfaces.
- **High-Contrast Design**: Bold typography and technical blueprint aesthetics.
- **LED Status Indicators**: Real-time visual telemetry for backend system health.

## Documentation

For a comprehensive introduction, please refer to the **[Quick Start PDF](startup_guide.pdf)** located in the root directory.

## Repo Structure

- `frontend/` - Next.js (App Router) + Tailwind + Professional Neobrutalist components.
- `backend/` - FastAPI (Python) orchestration layer with Redis/Celery background workers.
- `agent/` - Lightweight monitoring agents.
- `docs/` - Technical documentation and setup guides.

## Quick Start (Docker)

1. **Environment Setup**:
   ```bash
   cp .env.example .env
   ```

2. **Launch Stack**:
   ```bash
   docker compose up --build
   ```

3. **Access Platform**:
   - Dashboard: `http://localhost:3000`
   - API Docs: `http://localhost:8000/docs`

4. **Default Credentials**:
   - Administrator: `admin@emet.local` / `emet`
   - Analyst: `analyst@emet.local` / `emet`

## Manual Execution

If running without Docker, ensure you have **Redis** and **PostgreSQL** active.

### Frontend
```bash
cd frontend
npm install
npm run dev
```

### Backend
```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload
```

### Worker
```bash
cd backend
python worker.py
```

## Security & Ethics

EMET is designed strictly for **defensive security operations**. It does not generate or execute exploit code. All target validations must comply with organizational security policies.
