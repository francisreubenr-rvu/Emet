# EMET Master Implementation Checklist

This checklist is derived directly from `EMET_Build_Prompt.md` and is the source-of-truth build tracker.

## Phase 0 - Foundation Reset

- [x] Create monorepo-style structure: `frontend/`, `backend/`, `docs/`
- [x] Add project-wide environment template in `.env.example`
- [x] Add Docker Compose baseline (`frontend`, `backend`, `postgres`, `redis`)
- [x] Add scanner setup guide (`docs/scanner-setup.md`)
- [x] Remove or migrate legacy Vite prototype once Next.js app is fully validated

## Phase 1 - Core (Must-Have)

### 1) Login + Auth
- [x] Build Next.js App Router auth route at `frontend/app/(auth)/login/page.tsx`
- [x] Implement backend JWT issuance endpoint (`/api/auth/login`)
- [x] Store JWT in httpOnly cookie (server-set)
- [x] Add guest/demo read-only path
- [x] Add token refresh rotation flow

### 2) Sidebar + Routing
- [x] Build persistent dashboard layout with fixed left sidebar
- [x] Add nav destinations: Dashboard, Scan Console, Scan Reports, Exploit Console, News, Settings
- [x] Add backend live-status indicator region in sidebar
- [ ] Connect live-status indicator to backend health endpoint + WebSocket state

### 3) Scan Console (UI-first)
- [x] Build split-pane layout (input/config + output tabs)
- [x] Add target input with inline valid/invalid indicator
- [x] Add scanner selection grid with time/metadata
- [x] Add scan profile controls (Quick/Standard/Deep)
- [x] Add progress, unified report, detailed findings tab shells
- [x] Wire tab content to real backend scan lifecycle

### 4) Nmap + Normalization
- [x] Create scanner abstraction (`scanner_base.py`)
- [x] Add `nmap_runner.py` stub with normalized output
- [x] Add unified finding schema in `unified_schema.py`
- [x] Execute real nmap command, parse XML, and map to CVE correlations
- [x] Deduplicate findings by CVE+component signature

### 5) Report Storage
- [x] Implement IndexedDB storage layer in frontend
- [x] Implement backend persistence (SQLite dev / PostgreSQL prod)
- [x] Build report history fetch endpoints and pagination

## Phase 2 - Intelligence

### 6) Gemini Integration
- [x] Add backend Gemini client skeleton and strict system prompt
- [ ] Implement robust API retries, timeout, and structured parsing

### 7) RAG Pipeline + Datasets
- [x] Add RAG module scaffold
- [x] Add dataset download instructions (`backend/datasets/README.md`)
- [ ] Implement embedding + FAISS index builder
- [x] Add dataset status telemetry endpoint for Settings page

### 8) Unified + Detailed Report Generation
- [ ] Generate executive summary from findings + RAG context
- [ ] Generate detailed findings with references, confidence, verification state
- [ ] Support export: JSON / CSV / PDF

### 9) Scan Reports + OSINT
- [x] Build scan reports page shell
- [x] Add report cards + detail drawer + timeline chart
- [x] Add OSINT fetch pipeline (Shodan, WHOIS, SSL, breach, CVE)

## Phase 3 - Advanced

### 10) Exploit Console
- [x] Build five-panel exploit console UI shell
- [ ] Integrate NVD, Exploit-DB, GitHub, Packet Storm data adapters
- [ ] Build attack surface graph visualization (D3/Cytoscape)

### 11) Zero-Day Detection
- [x] Add zero-day detector scaffold
- [ ] Implement residual anomaly extraction and scoring
- [ ] Add baseline-calibrated false-positive suppression

### 12) Self-Audit
- [x] Add self-audit module scaffold
- [ ] Implement 20% sampling + NVD cross-check
- [ ] Publish weekly performance report task

### 13) WebSockets
- [x] Add backend websocket endpoints placeholders
- [x] Add frontend `useWebSocket` hook with backoff reconnect
- [x] Drive real-time progress and logs from running jobs

### 14) Settings + Server Logs
- [x] Build settings page sections UI shell
- [ ] Persist scanner toggles + API keys (securely on backend)
- [ ] Implement streamed backend logs with filters

## Phase 4 - Polish + Hardening

### 15) Theme System
- [x] Build neobrutalist design tokens and base primitives
- [ ] Add robust light/dark + accent runtime switcher

### 16) Exports
- [ ] Add single-report and all-report export flows (JSON/CSV/PDF)

### 17) Cross-Verification
- [x] Add verification fields in unified schema
- [ ] Implement clean-target baseline scans (`google.com`, `cloudflare.com`, `1.1.1.1`)
- [ ] Quarantine findings below confidence threshold

### 18) Performance
- [x] Add backend background queue (Redis worker)
- [ ] Optimize frontend render with suspense/streaming where useful

### 19) Security Hardening
- [x] Add CORS config shell + frontend/backend split
- [x] Encrypt scan results at rest (AES-256)
- [x] Add rate limiting for scan endpoints
- [x] Validate targets against SSRF + IANA reserved range policies
- [ ] Add full audit log trail for user actions

## Quality Gate

- [x] `frontend`: typecheck + lint + build passes
- [x] `backend`: lint + type checks + startup health endpoint passes
- [ ] End-to-end happy path: login -> scan -> report -> exploit console -> settings
