# EMET — Cybersecurity Vulnerability Detection Platform
## Master Build Prompt (Complete)

---

```
PROJECT: EMET — Centralized Vulnerability Detection & Zero-Day Intelligence Platform
AESTHETIC: Neobrutalism — hard borders, raw contrast, expressive typography, intentional roughness
STACK: React + Next.js (frontend), FastAPI (backend), PostgreSQL + local SQLite (scan storage),
       Google Gemini API (AI layer), LangChain (RAG pipeline), Ollama (optional local LLM fallback)
DEPLOYMENT: Vercel (frontend), Render (backend free tier)
```

---

## 🎨 DESIGN SYSTEM — NEOBRUTALISM

```
FONTS:
  Display: "Space Mono" or "Courier Prime" (monospaced, raw, technical)
  Body: "IBM Plex Mono" or "JetBrains Mono"
  Accent headers: "Bebas Neue" or "Anton" (blocky, loud)

COLORS (CSS Variables):
  --bg-primary: #F5F0E8        (off-white, paper-like)
  --bg-dark: #0D0D0D           (near-black)
  --accent-yellow: #FFE500     (hard yellow)
  --accent-red: #FF2D2D        (alert red)
  --accent-green: #00FF6A      (terminal green)
  --accent-blue: #0057FF       (electric blue)
  --border: #000000            (always solid black, 2-3px)
  --shadow: 4px 4px 0px #000   (hard drop shadow, no blur)
  --text-primary: #000000
  --text-inverse: #F5F0E8

NEOBRUTALISM RULES:
  - All cards/panels: solid 2-3px black border, hard box-shadow (4px 4px 0 #000)
  - No border-radius > 0px (or max 2px)
  - Hover states: translate(-2px, -2px), shadow becomes (6px 6px 0 #000)
  - Active/click: translate(2px, 2px), shadow collapses to (2px 2px 0 #000)
  - Background textures: subtle noise grain overlay (SVG filter or CSS)
  - Buttons: filled background + black border + hard shadow, no gradients
  - Status indicators: solid colored squares, not rounded badges
  - Typography: heavy weights (700-900), uppercase labels, tight letter-spacing
```

---

## 🗂️ APPLICATION STRUCTURE

```
emet/
├── frontend/                    # Next.js 14 App Router
│   ├── app/
│   │   ├── (auth)/login/        # Login page
│   │   ├── (dashboard)/
│   │   │   ├── layout.tsx       # Sidebar layout wrapper
│   │   │   ├── page.tsx         # Dashboard homepage
│   │   │   ├── scan-console/
│   │   │   ├── scan-reports/
│   │   │   ├── exploit-console/
│   │   │   ├── news/
│   │   │   └── settings/
│   ├── components/
│   │   ├── Sidebar.tsx
│   │   ├── ScanForm.tsx
│   │   ├── ProgressPanel.tsx
│   │   ├── ReportViewer.tsx
│   │   └── ui/ (neobrutalist primitives)
│   └── lib/
│       ├── api.ts               # FastAPI client
│       ├── storage.ts           # Local scan history (localStorage + IndexedDB)
│       └── gemini.ts            # Gemini API direct calls

├── backend/                     # FastAPI
│   ├── main.py
│   ├── routers/
│   │   ├── scan.py
│   │   ├── reports.py
│   │   ├── exploit.py
│   │   └── settings.py
│   ├── scanners/
│   │   ├── nmap_runner.py
│   │   ├── nessus_runner.py
│   │   ├── openvas_runner.py
│   │   ├── nuclei_runner.py
│   │   ├── nikto_runner.py
│   │   ├── wapiti_runner.py
│   │   └── scanner_base.py      # Abstract base class
│   ├── normalizer/
│   │   ├── cvss_normalizer.py   # Convert all outputs → CVSS 3.1 schema
│   │   └── unified_schema.py    # Pydantic models
│   ├── ai/
│   │   ├── rag_pipeline.py      # LangChain RAG
│   │   ├── gemini_client.py     # Gemini Flash/Pro API
│   │   ├── zero_day_detector.py
│   │   ├── self_audit.py        # AI self-assessment of Emet's own output
│   │   └── embeddings/          # FAISS vector store
│   ├── datasets/
│   │   └── README.md            # Dataset download instructions (see below)
│   └── db/
│       ├── models.py
│       └── database.py          # SQLite (dev) / PostgreSQL (prod)
```

---

## 📄 PAGE SPECIFICATIONS

### 1. LOGIN PAGE

```
Layout: Full-screen split — left 40% solid black with EMET logo + tagline,
        right 60% off-white with login form

Logo: "EMET" in Bebas Neue, 96px, with a hard yellow underline bar
Tagline: "THREAT INTELLIGENCE. ZERO COMPROMISE." in monospace, uppercase

Form fields:
  - Username / Email (monospace input, black border, hard shadow)
  - Password (same style)
  - [LOGIN] button: full-width, black bg, yellow text, 3px border, hard shadow

Auth: JWT-based, stored in httpOnly cookie
Demo mode: "ENTER AS GUEST" text link (read-only mode, no real scans)
```

---

### 2. SIDEBAR (Persistent across all dashboard pages)

```
Width: 240px, fixed left
Background: #0D0D0D (black)
Right border: 3px solid #FFE500 (yellow)

Logo at top: "EMET" in Bebas Neue, yellow
Subtitle: "v1.0 // INTEL PLATFORM" in tiny monospace, grey

Nav items (each):
  Icon (lucide-react, 20px) + Label
  Default: dark bg, grey text
  Active: yellow left border (4px), yellow text, slightly lighter bg
  Hover: translate effect, bg #1A1A1A

Nav items in order:
  🏠 DASHBOARD
  🔍 SCAN CONSOLE
  📋 SCAN REPORTS
  💀 EXPLOIT CONSOLE
  📰 RECENT NEWS        ← live cybersec news via RSS/API
  ⚙️  SETTINGS

Bottom of sidebar:
  - Small system status indicator (backend: online/offline dot)
  - Current user avatar/name
  - Logout button
```

---

### 3. DASHBOARD (Homepage)

```
Layout: Minimalist, 3-column grid at top, full-width panels below

TOP STATS ROW (4 cards, neobrutalist style):
  [TOTAL SCANS RUN] [CRITICAL VULNS FOUND] [ZERO-DAY ALERTS] [LAST SCAN TIME]
  Each: white card, black border, hard shadow, large number in Bebas Neue

MIDDLE ROW:
  Left (60%): "RECENT SCANS" — last 5 scans with target, date, severity badge
  Right (40%): "SEVERITY DISTRIBUTION" — simple bar chart (Recharts or pure CSS bars)

BOTTOM ROW:
  Left (50%): "TOP VULNERABILITIES ACROSS ALL SCANS" — ranked list
  Right (50%): "EMET SYSTEM STATUS" — live backend health, scanner availability,
               RAG pipeline status, dataset freshness indicator
```

---

### 4. SCAN CONSOLE

```
Layout: Left 55% (input/config) | Right 45% (results panel)

─── LEFT PANEL ───

Header: "NEW SCAN" in Bebas Neue, 48px

Target Input:
  Label: "TARGET URL / IP ADDRESS"
  Input: large monospace field, black border 3px, hard shadow
  Validation: real-time format check, show ✓ or ✗ indicator

Scanner Selection:
  Label: "SELECT SCANNER TOOLS"
  Grid of checkboxes (neobrutalist — square checkboxes, yellow fill when checked):
    ☐ Nmap           ☐ Nessus
    ☐ OpenVAS        ☐ Nuclei
    ☐ Nikto          ☐ Wapiti
    ☐ Shodan API     ☐ VirusTotal API
    ☐ SSL Labs API   ☐ SecurityHeaders.io
  Each tool shows: tool icon, name, estimated scan time, last updated

Scan Profile:
  Radio buttons: QUICK (2min) | STANDARD (10min) | DEEP (30min)

[START SCAN] button:
  Default: black bg, yellow text, "▶ START SCAN"
  On click: animate to "⟳ RUNNING..." with pulsing yellow border
  Transforms to: "■ ABORT SCAN" (red) when running
  On complete: "✓ SCAN COMPLETE" (green) for 3 seconds, then resets

─── RIGHT PANEL ───

Three tabs (neobrutalist tab style — selected tab has hard bottom border cut):

TAB 1: CURRENT PROGRESS
  For each selected tool, a progress row:
    [TOOL NAME] [████████░░] 80% [STATUS TEXT]
  Status texts: "INITIALIZING" / "PORT SCANNING" / "CVE MATCHING" / "COMPLETE" / "FAILED"
  Live log stream at bottom (scrollable terminal-style, dark bg, green text)
  WebSocket connection to backend for real-time updates

TAB 2: UNIFIED REPORT
  After scan: plain-English summary generated by Gemini
  Sections:
    EXECUTIVE SUMMARY (2-3 sentences, severity overall)
    KEY FINDINGS (bullet list, human-readable)
    ZERO-DAY RISK ASSESSMENT (Gemini RAG output)
    RECOMMENDED ACTIONS (prioritized, plain English)
  Tone: Clear, non-technical language for executives
  Export: [COPY] [DOWNLOAD PDF] buttons

TAB 3: DETAILED FINDINGS
  Table: CVE ID | Severity (CVSS) | Tool Found By | Description | Affected Component
  Each row expandable to show:
    - Full CVSS vector string
    - Technical description
    - Proof of concept (if available from NVD)
    - 📄 Referenced Research Papers (fetched via Semantic Scholar / arXiv API)
    - Remediation steps
    - Cross-verification status (verified against known-clean sites ✓/✗)
  Sort/filter by severity, tool, CVE date
  Export: [JSON] [CSV]
```

---

### 5. SCAN REPORTS

```
Layout: Full-width list view

Header: "SCAN HISTORY" + search bar + filter dropdown (by severity, date, target)

Report cards (each):
  [Target URL/IP] [Scan Date] [Duration] [Tools Used] [Severity Badge] [▼ EXPAND] [🗑 DELETE]
  Severity badge: CRITICAL (red) / HIGH (orange) / MEDIUM (yellow) / LOW (green) / INFO (blue)

On clicking a report card — opens detail drawer/modal:
  TABS:
    1. ALL PREVIOUS SCANS FOR THIS TARGET
       Timeline view showing all historical scans, trend of vulnerabilities over time
       Chart: "Vulnerability count over time" for this target

    2. FULL SCAN DETAILS
       All sections from Scan Console TAB 2 + TAB 3

    3. OSINT INTELLIGENCE
       Automatically fetched from internet when report is opened:
       - Shodan data for the IP
       - WHOIS information
       - SSL certificate details
       - Known breach history (via HaveIBeenPwned API if applicable)
       - CVE database entries for detected software versions
       - Recent news mentioning the domain
       [NOTE: Show "FETCHING LIVE INTEL..." spinner during load]

Storage:
  Primary: IndexedDB (browser) for offline-capable local storage
  Secondary: Backend SQLite/PostgreSQL for persistence across devices
  Export ALL reports: [DOWNLOAD ALL AS JSON] [DOWNLOAD ALL AS CSV]
  Danger zone: [DELETE ALL SCANS] with confirmation modal
```

---

### 6. EXPLOIT CONSOLE ← SIGNATURE FEATURE

```
CONCEPT: A structured, ethical exploit research workbench.
WARNING BANNER: "FOR AUTHORIZED SECURITY RESEARCH ONLY. EMET LOGS ALL ACTIVITIES."

Layout: Terminal-inspired, dark bg, but still neobrutalist borders

─── PANEL A: EXPLOIT INTELLIGENCE ───
  Input: CVE ID or target + CVE
  Fetches from:
    - Exploit-DB (via API or scraped)
    - NVD (National Vulnerability Database)
    - GitHub (public PoC repos via GitHub API)
    - Packet Storm Security
  Displays:
    - CVE details + CVSS score breakdown (visual vector diagram)
    - Known public exploits + their status (weaponized / PoC only / theoretical)
    - Affected versions + patch status
    - Exploitability score + Attack Vector visualization

─── PANEL B: ATTACK SURFACE MAPPER ───
  After a scan, auto-generates an interactive attack surface map:
  Visual graph (D3.js or Cytoscape.js) showing:
    - Open ports → services → known CVEs → exploit paths
    - Color-coded by exploitability (red = actively exploited in wild)
  "ATTACK PATH ANALYSIS" — AI narrates most likely attacker path

─── PANEL C: AI EXPLOIT ADVISOR ───
  Gemini-powered chat interface
  Context: Loaded with current scan's findings
  User can ask: "What's the most critical vector here?" /
               "How would an attacker chain these vulnerabilities?" /
               "What's the blast radius if CVE-XXXX is exploited?"
  Hard guardrails: Does NOT generate actual exploit code.
                   Redirects to defensive posture recommendations.
  All queries logged for audit.

─── PANEL D: REMEDIATION PLANNER ───
  Ordered list of fixes (by exploitability × impact score)
  Each fix: Description + patch links + config change snippets
  "GENERATE REMEDIATION REPORT" → PDF export
  Tickboxes to mark items as fixed → updates dashboard stats

─── PANEL E: CVE WATCHLIST ───
  User adds CVEs to monitor
  Daily check: Has exploit status changed? New PoC published?
  Push notification / badge if watched CVE becomes weaponized
```

---

### 7. RECENT NEWS

```
Layout: Card grid, 3 columns

Live cybersecurity news feed from:
  - Krebs on Security RSS
  - The Hacker News RSS
  - CISA Alerts feed
  - CVE Trending (GitHub API: recent CVEs with high activity)

Each card:
  [SOURCE BADGE] [HEADLINE] [DATE] [READ →]
  Tags: zero-day / ransomware / patch / data-breach / etc.
  Filter by tag

Auto-refreshes every 15 minutes
"BREAKING" badge for items < 2 hours old
```

---

### 8. SETTINGS

```
Sections:

APPEARANCE
  Theme toggle: LIGHT / DARK (neobrutalist toggle switch)
  Color accent: Yellow (default) / Red / Green / Blue — changes --accent color

SCANNER CONFIGURATION
  Toggle each scanner tool ON/OFF globally
  API key inputs: Shodan, VirusTotal, Nessus, HaveIBeenPwned, Gemini
  Test connection button for each API

RAG PIPELINE
  Dataset status table:
    Dataset Name | Source | Last Updated | Size | Status
    NVD CVE Feed | NIST | [date] | [size] | ● LOADED
    Exploit-DB   | Offensive Security | ... | ... | ● LOADED
    MITRE ATT&CK | MITRE | ... | ... | ● LOADED
    Kaggle CVE   | Kaggle | ... | ... | ⚠ NOT DOWNLOADED
  [UPDATE DATASETS] button (triggers background job)
  RAG hallucination rate indicator (target: <4%)

AI SELF-AUDIT LOG
  Live display of Emet's self-assessment runs
  Shows: "AUDIT #47: Checked 12 CVE matches. 0 false positives detected.
          Suggested improvement: Add CVE-2024-XXXX to watchlist."
  Auto-runs after every scan

SERVER BACKEND LOG
  Live-streamed log panel (WebSocket, dark terminal style)
  Filters: INFO / WARNING / ERROR / CRITICAL
  Auto-scrolls, max 1000 lines retained

DATA MANAGEMENT
  Storage usage bar (IndexedDB + server)
  [EXPORT ALL DATA] [DELETE ALL STORED DATA]
  Confirmation modal with typed confirmation: "DELETE EMET DATA"
```

---

## ⚙️ BACKEND ARCHITECTURE

### Scanner Normalization Pipeline

```python
# unified_schema.py — All scanners output this
class UnifiedFinding(BaseModel):
    scan_id: str
    target: str
    scanner_source: str           # "nmap" | "nessus" | "openvas" | etc.
    timestamp: datetime
    cve_id: Optional[str]         # e.g. "CVE-2024-1234"
    cvss_score: float             # 0.0 - 10.0
    cvss_vector: str              # CVSS:3.1/AV:N/AC:L/...
    severity: str                 # CRITICAL/HIGH/MEDIUM/LOW/INFO
    title: str
    description: str
    affected_component: str
    port: Optional[int]
    service: Optional[str]
    remediation: Optional[str]
    references: List[str]         # URLs
    verified: bool                # Cross-verified with clean-site baseline
    false_positive_probability: float  # 0.0-1.0, from AI assessment
```

---

### RAG Pipeline

```python
# rag_pipeline.py
"""
Pipeline:
1. Scanner raw output → normalize to UnifiedFinding schema
2. Embed findings using sentence-transformers (all-MiniLM-L6-v2)
3. Query FAISS vector store (built from CVE/exploit datasets)
4. Retrieve top-k similar known CVEs + exploits
5. Pass to Gemini with context: finding + retrieved docs + scan history
6. Gemini outputs: zero-day risk, remediation, confidence score
7. Self-audit: Re-run subset through second Gemini call to verify output
8. Hallucination check: Compare against NVD API ground truth
Target hallucination rate: <4%
"""

VECTOR_STORE_DATASETS = [
    "NVD CVE JSON feed (full history)",
    "Exploit-DB CSV export",
    "MITRE ATT&CK STIX bundles",
    "CISA KEV (Known Exploited Vulnerabilities)",
    "Custom Kaggle dataset: CVE severity prediction",
]
```

---

### Self-Audit Module

```python
# self_audit.py
"""
After every scan, Emet runs a self-audit:
1. Sample 20% of findings
2. Cross-reference each against NVD API
3. Check: Is CVSS score accurate? Is remediation correct?
4. Flag any discrepancies → log to audit trail → adjust confidence
5. Every 10 scans: Gemini audits the overall system prompt and
   suggests improvements to scanner normalization logic
6. Weekly: Generate "EMET PERFORMANCE REPORT" — false positive rate,
   coverage gaps, missed CVE categories
"""
```

---

### Zero-Day Detection

```python
# zero_day_detector.py
"""
Strategy:
1. Scan produces all known CVE matches first
2. Residual anomalies (open ports, unusual behaviors, unknown service banners)
   that DON'T match known CVEs are flagged as "UNCLASSIFIED FINDINGS"
3. These are embedded + queried against:
   - Recent CVE feeds (last 30 days, NVD)
   - Full-disclosure mailing list archives
   - GitHub security advisories
4. Gemini assesses: "Does this pattern match any emerging threat intelligence?"
5. Output: Zero-Day Risk Score (0-100) + narrative + recommended monitoring
6. Cross-verification: Run same check against a known-clean baseline target
   to calibrate false positive rate
"""
```

---

## 📦 DATASETS TO DOWNLOAD (Developer Instructions)

```
Add to backend/datasets/README.md:

REQUIRED DATASETS — Download before first run:

1. NVD CVE Feed (NIST)
   URL: https://nvd.nist.gov/vuln/data-feeds
   Files: nvdcve-1.1-{year}.json.gz (download all years)
   Script: python scripts/download_nvd.py

2. Exploit-DB
   URL: https://gitlab.com/exploit-database/exploitdb
   git clone https://gitlab.com/exploit-database/exploitdb.git datasets/exploitdb

3. MITRE ATT&CK
   URL: https://github.com/mitre/cti
   git clone https://github.com/mitre/cti datasets/mitre-attack

4. CISA KEV (Known Exploited Vulnerabilities)
   URL: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
   Script: python scripts/download_cisa_kev.py

5. Kaggle: CVE Severity Prediction Dataset
   URL: https://www.kaggle.com/datasets/andrewkronser/cve-common-vulnerabilities-and-exposures
   kaggle datasets download andrewkronser/cve-common-vulnerabilities-and-exposures

6. OSV (Open Source Vulnerabilities)
   URL: https://osv.dev/docs/
   Script: python scripts/download_osv.py

Total estimated size: ~15-25 GB
Run: python scripts/build_faiss_index.py  ← builds the vector store from all datasets
```

---

## 🔌 API INTEGRATIONS

```
REQUIRED (free tier available):
  - Google Gemini API (gemini-1.5-flash for speed, gemini-1.5-pro for deep analysis)
  - NVD API (free, rate limited — get API key for higher limits)
  - Shodan API (free tier: 1 query/sec)
  - VirusTotal API (free tier: 4 req/min)

OPTIONAL:
  - HaveIBeenPwned API (breach data)
  - Semantic Scholar API (research paper cross-referencing)
  - SecurityHeaders.io API
  - SSL Labs API (ssllabs.com/ssltest/)
  - GitHub API (PoC lookup in repos)
```

---

## 🧪 CROSS-VERIFICATION (Authenticity System)

```
To ensure Emet ONLY produces authentic data:

BASELINE CALIBRATION TARGETS (known clean):
  - google.com
  - cloudflare.com
  - 1.1.1.1 (Cloudflare DNS)
These are scanned in the background when Emet first starts.
Any CVE that appears on these targets is flagged as likely false positive.

VERIFICATION PIPELINE:
1. Every finding gets a "VERIFIED" flag only if:
   a. CVE exists in NVD database
   b. CVSS score matches NVD within ±0.5
   c. Affected software version confirmed by scanner
   d. Does NOT appear in clean baseline scan

2. Unverified findings shown with ⚠ "UNVERIFIED — MANUAL REVIEW RECOMMENDED"

3. Confidence score displayed per finding: 0-100%

4. "FALSE POSITIVE GUARD" — if AI confidence < 40%, finding is quarantined
   and shown in separate "REVIEW QUEUE" section
```

---

## ⚡ REAL-TIME FEATURES

```
WebSocket endpoints (FastAPI):
  /ws/scan/{scan_id}/progress    ← live scanner progress updates
  /ws/logs                       ← live server log stream (Settings page)
  /ws/alerts                     ← zero-day alert notifications

Frontend:
  useWebSocket hook for all real-time connections
  Reconnect logic with exponential backoff
  Visual indicator in sidebar: "● LIVE" when connected
```

---

## 🔐 SECURITY OF EMET ITSELF

```
Since Emet handles sensitive security data, the tool must itself be secure:

- All scan results encrypted at rest (AES-256)
- API keys stored in environment variables ONLY, never in code
- JWT tokens with 1-hour expiry + refresh token rotation
- Rate limiting on all scan endpoints (prevent abuse)
- Input sanitization on URL/IP fields (prevent SSRF)
- Scan targets validated against IANA reserved ranges
  (block 192.168.x.x etc. unless user explicitly enables local network scanning)
- Full audit log of all user actions
- CORS restricted to known frontend origin
- All external API calls proxied through backend (no direct frontend calls to Shodan etc.)
```

---

## 🚀 DEPLOYMENT

```
Frontend (Vercel):
  - next.config.js: proxy /api/* to Render backend URL
  - Environment: NEXT_PUBLIC_API_URL, NEXT_PUBLIC_GEMINI_KEY (if direct calls needed)

Backend (Render free tier):
  - Dockerfile provided
  - Note: Render free tier spins down after inactivity — add /health ping from frontend
  - Nmap requires: apt-get install nmap in Dockerfile
  - Datasets: Mount persistent disk (Render paid) OR use external storage (Cloudflare R2)

Local Development:
  docker-compose.yml provided:
    services: frontend, backend, postgres, redis (for job queue)
  .env.example with all required variables listed

IMPORTANT FOR DEVELOPER:
  Nessus and OpenVAS require local installation and credentials.
  Provide setup guide in /docs/scanner-setup.md
  For environments without Nessus: graceful degradation with clear UI message
```

---

## 📋 COMPONENT DEVELOPMENT ORDER

```
Phase 1 — Core:
  1. Login page + JWT auth
  2. Sidebar + routing
  3. Scan Console UI (static, no backend)
  4. Nmap integration + normalization
  5. Basic report storage (IndexedDB)

Phase 2 — Intelligence:
  6. Gemini API integration
  7. RAG pipeline + dataset indexing
  8. Unified + Detailed report generation
  9. Scan Reports page with OSINT

Phase 3 — Advanced:
  10. Exploit Console (all 5 panels)
  11. Zero-day detection pipeline
  12. Self-audit module
  13. Real-time WebSockets
  14. Settings page + server logs

Phase 4 — Polish:
  15. Dark/light theme toggle
  16. Export (JSON/CSV/PDF)
  17. Cross-verification system
  18. Performance optimization
  19. Security hardening
```

---

## 🌐 ENVIRONMENT VARIABLES (.env.example)

```bash
# Backend (FastAPI)
DATABASE_URL=sqlite:///./emet.db
SECRET_KEY=your-jwt-secret-key-here
GEMINI_API_KEY=your-gemini-api-key
NVD_API_KEY=your-nvd-api-key
SHODAN_API_KEY=your-shodan-api-key
VIRUSTOTAL_API_KEY=your-virustotal-api-key
HIBP_API_KEY=your-haveibeenpwned-api-key
GITHUB_TOKEN=your-github-personal-access-token
NESSUS_URL=https://localhost:8834
NESSUS_ACCESS_KEY=your-nessus-access-key
NESSUS_SECRET_KEY=your-nessus-secret-key
OPENVAS_HOST=localhost
OPENVAS_PORT=9390
OPENVAS_USERNAME=admin
OPENVAS_PASSWORD=your-openvas-password
CORS_ORIGINS=http://localhost:3000,https://your-vercel-app.vercel.app
DATASET_PATH=./datasets
FAISS_INDEX_PATH=./embeddings/faiss_index

# Frontend (Next.js)
NEXT_PUBLIC_API_URL=http://localhost:8000
NEXT_PUBLIC_APP_NAME=EMET
```

---

## 🐳 DOCKER COMPOSE (docker-compose.yml)

```yaml
version: "3.9"
services:
  frontend:
    build: ./frontend
    ports:
      - "3000:3000"
    environment:
      - NEXT_PUBLIC_API_URL=http://backend:8000
    depends_on:
      - backend

  backend:
    build: ./backend
    ports:
      - "8000:8000"
    env_file: .env
    volumes:
      - ./datasets:/app/datasets
      - ./embeddings:/app/embeddings
    depends_on:
      - postgres
      - redis

  postgres:
    image: postgres:15
    environment:
      POSTGRES_DB: emet
      POSTGRES_USER: emet
      POSTGRES_PASSWORD: emet_password
    volumes:
      - pgdata:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine

volumes:
  pgdata:
```

---

## 📁 KEY FILE TEMPLATES

### backend/scanners/scanner_base.py

```python
from abc import ABC, abstractmethod
from typing import List
from normalizer.unified_schema import UnifiedFinding

class ScannerBase(ABC):
    name: str
    version: str

    @abstractmethod
    async def scan(self, target: str, profile: str) -> List[UnifiedFinding]:
        """Run scan and return normalized findings."""
        pass

    @abstractmethod
    async def is_available(self) -> bool:
        """Check if this scanner tool is installed/accessible."""
        pass

    def normalize(self, raw_output: dict) -> List[UnifiedFinding]:
        """Convert tool-specific output to UnifiedFinding schema."""
        raise NotImplementedError
```

### backend/ai/gemini_client.py

```python
import google.generativeai as genai
from typing import List
from normalizer.unified_schema import UnifiedFinding

genai.configure(api_key=os.environ["GEMINI_API_KEY"])

SYSTEM_PROMPT = """
You are EMET's threat intelligence AI. You analyze vulnerability scan results
and produce clear, accurate security assessments. You ONLY report findings
that are supported by the provided context and verified data sources.
Never hallucinate CVE IDs, CVSS scores, or remediation steps.
If uncertain, say so explicitly with confidence percentage.
Always cross-reference against the provided RAG context before responding.
"""

async def analyze_findings(
    findings: List[UnifiedFinding],
    rag_context: str,
    mode: str = "unified"  # "unified" | "detailed" | "zero_day"
) -> dict:
    model = genai.GenerativeModel("gemini-1.5-flash")
    # ...implementation
```

---

## 🔍 SCAN FLOW (End-to-End)

```
USER INPUT → URL / IP address
      ↓
VALIDATION → Format check, IANA reserved range check
      ↓
SCANNER DISPATCH → Parallel execution of selected tools
      ↓
RAW OUTPUT → Nmap XML / Nessus .nessus / OpenVAS XML / Nuclei JSON / etc.
      ↓
NORMALIZATION → All outputs → UnifiedFinding (CVSS 3.1 schema)
      ↓
DEDUPLICATION → Merge findings for same CVE from multiple tools
      ↓
EMBEDDING → sentence-transformers → vector representations
      ↓
RAG RETRIEVAL → FAISS query → top-k similar known CVEs + exploits
      ↓
GEMINI ANALYSIS → Unified report + detailed findings + zero-day risk
      ↓
SELF-AUDIT → 20% sample re-verified against NVD API
      ↓
FALSE POSITIVE FILTER → Quarantine low-confidence findings
      ↓
CROSS-VERIFICATION → Check against known-clean baseline targets
      ↓
STORAGE → IndexedDB (local) + PostgreSQL (server)
      ↓
REPORT OUTPUT → Unified Report + Detailed Findings + Research Papers
```

---

*EMET — Built for security professionals. Authentic data only.*
*"THREAT INTELLIGENCE. ZERO COMPROMISE."*
