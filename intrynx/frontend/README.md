# ADVERSA — Network VAPT Platform

> AI-powered network penetration testing operations platform.  
> Scan → Discover → Analyze → Report → Remediate — all in one place.

---

## What It Is

ADVERSA is a full-lifecycle VAPT operations platform built for security engineers running network penetration tests. It combines real scanning tools (nmap, nuclei, naabu, testssl), an AI reasoning engine (Claude), a distributed agent network, and compliance-mapped reporting — all accessible through a web dashboard and a CLI.

**The core idea:** instead of running tools in separate terminals, copy-pasting output into Excel, and writing reports manually — ADVERSA runs the entire pentest pipeline, correlates findings across tools, maps every finding to MITRE ATT&CK and compliance frameworks, and drafts the executive report automatically.

> For authorized security testing, internal use, and controlled lab environments only.

---

## Architecture

ADVERSA has three ways to run a scan. All three share the same `lib/engine/` core — the output path is what changes.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│  ① CLI (local terminal)                                                     │
│     adversa scan 10.0.0.1 --profile deep --save                             │
│     cli/commands/scan.ts                                                    │
│            │                                                                │
│            │ ScanCallbacks → cli/ui/output.ts (ANSI terminal)               │
│            │                                                                │
│  ② Web Dashboard (Next.js, port 3000)                                       │
│     POST /api/scans/start  →  job-store  →  SSE /api/scan/stream/[scanId]   │
│            │                                                                │
│            │ ScanCallbacks → scan-events bus → SSE → browser               │
│            │                                                                │
│  ③ Python Field Agent (remote box / container)                              │
│     agent/poll_loop.py  →  GET /api/agents/jobs/next  (long-poll)           │
│     agent/scan_executor.py  →  POST /api/findings/ingest                   │
│            │                                                                │
│            └──────────────┬─────────────────────────────────────────────── │
│                           │                                                 │
│               ┌───────────▼──────────────────┐                             │
│               │     lib/engine/scanner.ts     │                             │
│               │        runScan(opts, cb)       │                             │
│               │                               │                             │
│               │  naabu → nmap → nuclei+testssl│                             │
│               │  (nuclei & testssl parallel)   │                             │
│               │  → AI triage (Claude)          │                             │
│               │  → saveFindings()              │                             │
│               └───────────┬──────────────────┘                             │
│                           │                                                 │
│               ┌───────────▼──────────────────┐                             │
│               │  lib/findings-store.ts        │                             │
│               │  data/findings.json           │                             │
│               │  (flat file, deduped)         │                             │
│               └──────────────────────────────┘                             │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## How a Scan Works — Step by Step

### The 6-Stage Pipeline (`lib/engine/scanner.ts`)

Every scan — CLI or web — runs through `runScan(opts, callbacks)`:

| Stage | Tool | What It Does | Output |
|---|---|---|---|
| 1 | **naabu** | TCP connect-scan with stealth-rate control; streams JSONL | `DiscoveredHost[]` with open port list |
| 2 | **nmap** | Service fingerprinting on discovered ports; `-sT -sV` + NSE scripts | enriches hosts with service name, version, OS, hostnames |
| 3 | **nuclei** | CVE/template scan against all web ports (80, 443, 8080…); streams JSONL | `LiveFinding[]` per match — fires **live** |
| 4 | **testssl** | TLS config audit on ports 443/8443; `--fast --jsonfile` | `LiveFinding[]` per TLS issue |
| 5 | **AI triage** | Claude enriches findings with exploitability context | enriched `LiveFinding[]` |
| 6 | **persist** | `saveFindings()` writes to `data/findings.json` | deduped by host+CVE or normalized title |

Stages 3 and 4 run **in parallel** via `Promise.all`. Stages 1 and 2 are sequential because nmap needs naabu's port list.

### Raw Tool Output → Finding

Each tool has a dedicated parser that converts tool-native output to `LiveFinding`:

```
naabu stdout (JSONL line)   → lib/naabu-parser.ts   → NaabuResult → DiscoveredHost
nmap  stdout (XML)          → lib/nmap-parser.ts    → NmapHost    → enriches DiscoveredHost
nuclei stdout (JSONL line)  → lib/nuclei-parser.ts  → NucleiMatch → LiveFinding
testssl output file (JSON)  → lib/testssl-parser.ts → TestsslIssue → LiveFinding
```

naabu and nuclei are **streamed live** — `onLine()` fires per stdout line, findings reach the UI/terminal in real time. nmap and testssl are **batch-collected** and parsed when the process exits.

### ScanCallbacks — The Decoupling Layer

`ScanCallbacks` is the interface that decouples the scan engine from its output destination:

```typescript
interface ScanCallbacks {
  onStageStart(stage: string): void
  onStageComplete(stage: string, summary: string): void
  onHostDiscovered(host: DiscoveredHost): void
  onFinding(finding: LiveFinding): void
  onProgress(pct: number, msg: string): void
  onError(stage: string, err: string): void
  onComplete(summary: ScanSummary): void
}
```

The CLI wires callbacks to `cli/ui/output.ts` (colored ANSI output).  
The web API wires callbacks to `lib/scan-events.ts` (SSE broadcast bus).  
The Python agent runs the tools directly and POSTs findings to `/api/findings/ingest`.

---

## CLI Architecture

```
bin/adversa
    └─ cli/index.ts  (Commander entry point)
           ├─ scan       →  cli/commands/scan.ts
           │                  ├─ resolveTargets()     validate + dedup + file read
           │                  ├─ builds ScanOptions   (targets, profile, stealth, tools, scanId)
           │                  ├─ builds ScanCallbacks → cli/ui/output.ts
           │                  └─ runScan(opts, callbacks)  ← lib/engine/scanner.ts
           │
           └─ findings   →  cli/commands/findings.ts
                              └─ getAllFindings()  →  data/findings.json
```

**Scan profiles map to tool sets:**

| Profile | Tools | Use Case |
|---|---|---|
| `fast` | naabu + nuclei | Quick CVE sweep, no service fingerprint |
| `standard` | naabu + nmap + nuclei | Default — full service + CVE scan |
| `deep` | naabu + nmap + nuclei + testssl | Full scan including TLS audit |

**Stealth level → tool rate:**

| Level | naabu Rate | nmap Timing | Use Case |
|---|---|---|---|
| 1–2 | 50 pkt/s | T1 | Evade IDS, long-running stealth tests |
| 3–4 | 300 pkt/s | T2 | Stealth-conscious external tests |
| 5 | 1 000 pkt/s | T3 | Balanced default |
| 6–7 | 3 000 pkt/s | T4 | Fast internal network scans |
| 8–9 | 5 000 pkt/s | T5 | Maximum speed, lab / internal only |

---

## Web Dashboard Architecture

```
Browser
  │
  ├─ POST /api/scans/start
  │      ├─ parseTargets()  validate targets
  │      ├─ sign JWT scope token (SCOPE_SECRET, 24h)
  │      ├─ createJob()  →  lib/job-store.ts  (in-memory)
  │      └─ returns { scanId, jobId, scopeToken }
  │
  ├─ GET /api/scan/stream/[scanId]   (Server-Sent Events)
  │      └─ ReadableStream subscribes to lib/scan-events.ts bus
  │         receives: { type: "finding"|"host"|"stage"|"progress"|"complete" }
  │
  └─ GET /api/scans/[scanId]/status
         └─ getJobByScanId() + getAllFindings() filtered by scanId
```

**Scan events bus (`lib/scan-events.ts`):**

```
subscribeScan(scanId, callback)  →  adds listener
broadcastToScan(scanId, event, data)  →  fires all listeners for that scanId
  formats: "event: finding\ndata: {...}\n\n"
```

The SSE stream keeps the connection open with a 15-second heartbeat comment. When the browser closes the tab, `cancel()` unregisters the listener.

---

## Python Field Agent Architecture

The Python agent runs on a remote box (or container) inside the target network segment. It polls the manager for jobs, executes scans locally, and ships findings back.

```
agent/main.py  →  AdversaAgent.start()
      │
      ├─ agent/poll_loop.py
      │      ├─ register()   POST /api/agents/register
      │      │                   { sessionId, hostname, os, capabilities, … }
      │      │                   ← { agentId }
      │      │
      │      └─ poll_once()  GET /api/agents/jobs/next?agentId=…
      │                         long-poll: waits up to 28s, returns 204 if empty
      │                         ← Job { type, payload, scopeToken }
      │
      ├─ agent/scope_verifier.py
      │      └─ verify JWT scope token (PyJWT)
      │         check target CIDR containment (ipaddress module)
      │         reject out-of-scope targets before any tool runs
      │
      ├─ agent/scan_executor.py
      │      └─ full pipeline: scope check → naabu → nmap → nuclei+testssl
      │         writes results to /tmp/adversa/<scanId>.jsonl
      │
      ├─ agent/result_buffer.py
      │      └─ buffers findings to disk first (survives disconnects)
      │         ships batches to POST /api/findings/ingest
      │         flush_pending() retries on reconnect
      │
      └─ agent/tool_adapter.py
             └─ cross-platform binary resolution
                CREATE_NO_WINDOW flag on Windows
                threading.Timer for per-tool timeouts
```

**Findings ingest path:**

```
POST /api/findings/ingest
    ├─ validate agentId
    ├─ saveFindings(findings)   →  data/findings.json
    └─ broadcastToScan(scanId, "finding", f)  →  SSE stream → browser
```

---

## Data Storage

Everything lands in `data/findings.json` — a flat JSON file, no database.

```
saveFindings(findings[], engagementId?)
    ├─ dedup: same host + overlapping CVE IDs  → merge evidence
    ├─ dedup: same host + same normalized title → merge evidence
    ├─ attach SLA deadline per severity
    │      CRITICAL: +24h  ·  HIGH: +72h  ·  MEDIUM: +7d  ·  LOW: +30d
    └─ atomic write to DATA_PATH (overrideable via env for tests)
```

**Read functions:**

| Function | Returns |
|---|---|
| `getAllFindings()` | All findings |
| `getFindingById(id)` | Single finding |
| `getFindingsByEngagement(engId)` | Findings for one engagement |
| `getFindingStats()` | `{ total, bySeverity, byStatus }` |
| `updateFindingStatus(id, status)` | Patch status + timestamp |

---

## AI Integration

Three Claude-powered features, all using `claude-sonnet-4-6`:

| Feature | Route | What Claude Does |
|---|---|---|
| **AI Triage** | called from scanner.ts | Enriches findings with CVSS context, deduplicates noise, adds exploitability notes |
| **AI Brain** | `POST /api/brain` | Pentest strategy chat, streaming SSE, knows current finding set |
| **AI Report** | `POST /api/engagements/[id]/ai-report` | Generates full executive report with risk scorecard and remediation roadmap |
| **Exploit Builder** | `POST /api/exploit/build` | Builds safe verify-first exploit commands, forces human approval on HIGH/DESTRUCTIVE |

All prompts live in `lib/prompts/` — triage, report, and exploit-builder each have their own system prompt with strict safety constraints.

---

## Modules

### 1. Dashboard  `/`
Operational overview: active engagements, open critical findings, SLA breach count, attack surface trend charts, recent agent activity.

### 2. Scan  `/scan`
Live scanning interface with SSE real-time streaming:
- **Profiles:** fast · standard · deep
- **Stealth levels:** 1–9
- **Host map:** discovered hosts appear live as ports open
- **Finding feed:** each CVE/NSE match appears immediately, not at the end

### 3. Findings  `/findings`
Full finding lifecycle management:
- CVSS score + vector, evidence terminal blocks, attack path
- Status workflow: OPEN → IN\_REVIEW → IN\_REMEDIATION → VERIFIED → CLOSED
- SLA countdown per severity
- MITRE ATT&CK technique tags, compliance framework references
- Deduplication: same CVE on same host → merge evidence, not duplicate

### 4. Engagements  `/engagements`
Client engagement management:
- Scope CIDRs, excluded CIDRs, credentials vault references
- **Attack paths** and **blast radius** analysis per asset
- **Chokepoint detection** — most-traversed assets in attack chains
- **AI report generation** — draft → human review → approve workflow

### 5. AI Brain  `/aibrain`
Claude-powered offensive reasoning chat:
- Pentest strategy, exploitation paths, credential attacks, lateral movement advice
- Streaming responses (SSE), persistent conversation per session
- Context-aware: injects top 20 findings from current engagement into system prompt

### 6. Attack Graph  `/attack-graph`
SVG attack path visualisation:
- Nodes: assets, credentials, privilege levels
- Edges: exploitation steps, lateral movement vectors
- Chokepoint detection (most-traversed nodes)

### 7. Cases  `/cases`
Investigation case management — group related findings into a single investigation case with comment threads, status tracking, assignee, and timeline.

### 8. Agents  `/agents`
Distributed scanning agent fleet:
- Agent self-registration with TLS cert
- Heartbeat monitoring (ONLINE / OFFLINE / BUSY / ERROR)
- Job dispatch: discovery · vuln\_scan · ad\_enum · lateral\_movement
- Per-job progress streaming and result ingestion

### 9. AI Report  `/ai-report`
Per-engagement AI-generated reports:
- Executive summary + technical findings index
- Compliance gap analysis (5 frameworks, 35+ controls)
- Draft → human review → approve/reject workflow

### 10. Reports  `/reports`
Compliance-mapped report viewer:
- NIST SP 800-115 · NIST SP 800-53 Rev 5 · ISO/IEC 27001:2022 · PCI DSS v4.0 · CIS Controls v8
- Per-control pass / fail / partial status linked to actual findings

### 11. Active Directory  `/active-directory`
AD attack surface analysis: Kerberoastable accounts, delegation exposure, dangerous group memberships, BloodHound JSON ingestion.

### 12. Segmentation  `/segmentation`
Network zone validation: VLAN/zone inventory, ACL audit, inter-zone traffic policies.

### 13. Exploit  `/exploit`
Controlled exploit execution with approval gate — Propose → review → approve/reject before any execution.

### 14. Settings  `/settings`
Platform configuration: integrations, API keys, notification preferences.

---

## Quick Start

### Local dev (hot reload, no Docker)
```bash
cp .env.example .env.local
# Set ANTHROPIC_API_KEY in .env.local

npm install
npm run dev
# → http://localhost:3000
```

### Docker — production
```bash
make up
# → http://localhost:3000

make down         # stop
make logs         # tail logs
make shell        # shell into container
```

### Docker — dev with hot reload + scanning tools
```bash
make dev-up
# → http://localhost:3001  (source mounted, hot reload active)
```

### Python agent (run on target-network box)
```bash
pip install -r agent/requirements.txt

ADVERSA_MANAGER_URL=http://your-adversa-host:3000 \
ADVERSA_AGENT_TOKEN=adversa-agent-secret-change-me \
python -m agent.main
```

---

## CLI

Run scans directly from the terminal — no web server, no browser needed.

```bash
# Scan
npm run cli -- scan 10.0.0.1
npm run cli -- scan 192.168.1.0/24 --profile deep --stealth 3
npm run cli -- scan -f targets.txt --save
npm run cli -- scan 10.0.0.1 --tools naabu,nmap --save

# Findings
npm run cli -- findings
npm run cli -- findings --severity critical
npm run cli -- findings --target 10.0.0.1
npm run cli -- findings show VAPT-CRIT-001
npm run cli -- findings stats
npm run cli -- findings list --json | jq '.[] | .title'
```

**Output (example):**
```
   ▄▄▄  ██▄  ▄  ██▄ ▄  ██▄ ██▄  ▄▄   ▄▄
  Network VAPT Platform  v0.2.0  |  Intrynx
  ────────────────────────────────────────────────────────────────
  Target    10.0.0.1
  Profile   standard   Stealth  5/9
  Modules   Port Scanner  ·  SVC Probe  ·  CVE Engine  ·  TLS Analyzer
  ────────────────────────────────────────────────────────────────

  [PORT SCANNER]  starting…
  [HOST]  10.0.0.1   ports: 22, 80, 443, 3306   services: 3306/mysql 8.0.35
  [PORT SCANNER]  ✓  1 host · 4 ports

  [SVC PROBE]  fingerprinting services…
  [SVC PROBE]  ✓  1 host fingerprinted

  [CVE ENGINE]  initialising…
  [CRITICAL]  10.0.0.1:3306    mysql-unauthenticated-access  → VAPT-CRIT-007
  [HIGH    ]  10.0.0.1:443     ssl-tls-1-0-deprecated
  [CVE ENGINE]  ✓  2 matches

  ────────────────────────────────────────────────────────────────
  COMPLETE  1 host   2 findings   2 saved   14.2s
  ────────────────────────────────────────────────────────────────
```

**Scan flags:**

| Flag | Default | Description |
|---|---|---|
| `-p, --profile` | `standard` | `fast` · `standard` · `deep` |
| `-s, --stealth` | `5` | 1 (slow, quiet) → 9 (fast, loud) |
| `--save` | off | Persist findings to `data/findings.json` |
| `-f, --file` | — | Read targets from file (one per line) |
| `--tools` | profile default | Comma-separated: `naabu,nmap,nuclei,testssl` |

---

## Project Structure

```
adversa/
│
├── app/                           Next.js App Router (pages + API)
│   ├── page.tsx                   Dashboard
│   ├── scan/page.tsx              Live scan UI (SSE streaming)
│   ├── findings/page.tsx          Finding management
│   ├── engagements/page.tsx       Engagement tracker
│   ├── engagements/[id]/page.tsx  Per-engagement: AI report, attack paths
│   ├── aibrain/page.tsx           Claude chat
│   ├── attack-graph/page.tsx      SVG attack visualisation
│   ├── cases/page.tsx             Case management
│   ├── agents/page.tsx            Agent fleet
│   ├── exploit/page.tsx           Exploit approval workflow
│   ├── ai-report/page.tsx         AI report viewer
│   ├── reports/page.tsx           Compliance report viewer
│   ├── active-directory/page.tsx  AD analysis
│   ├── segmentation/page.tsx      Network zone validation
│   ├── settings/page.tsx          Platform settings
│   │
│   └── api/
│       ├── scans/
│       │   ├── start/             Validate targets · sign scope JWT · createJob
│       │   └── [scanId]/status/   Job status + findings for scan
│       ├── scan/
│       │   ├── stream/[scanId]/   SSE stream (ReadableStream + scan-events bus)
│       │   ├── pipeline/          Legacy SSE scan orchestrator
│       │   ├── naabu/             Port scanner endpoint
│       │   ├── nmap/              Service probe + XML parser
│       │   ├── nuclei/            CVE engine endpoint
│       │   ├── testssl/           TLS analyser endpoint
│       │   ├── openvas/           OpenVAS OMP integration
│       │   ├── netexec/           NetExec SMB/WinRM/LDAP
│       │   └── eyewitness/        Web screenshots
│       ├── findings/
│       │   ├── route.ts           List + create findings
│       │   ├── [id]/route.ts      Get · update · delete finding
│       │   └── ingest/route.ts    Agent ingest endpoint (→ broadcastToScan)
│       ├── agents/
│       │   ├── register/          Agent self-registration
│       │   └── jobs/next/         Long-poll job dispatch (500ms, 28s timeout)
│       ├── engagements/[id]/
│       │   ├── attack-paths/
│       │   ├── blast-radius/[assetId]/
│       │   ├── chokepoints/
│       │   ├── vuln-prioritizer/
│       │   ├── detection-validation/
│       │   └── ai-report/         Generate · draft · approve · reject
│       ├── brain/                 Claude AI chat (streaming SSE)
│       ├── cases/                 Case CRUD + comments
│       ├── exploit/
│       │   ├── build/             AI-generated exploit plan (JWT-gated)
│       │   └── approvals/         Approval workflow
│       ├── ad/                    AD analysis + BloodHound ingest
│       ├── mitre/                 MITRE ATT&CK data
│       └── integrations/          Slack · Jira · Email
│
├── cli/                           CLI tool
│   ├── index.ts                   Commander entry point
│   ├── commands/
│   │   ├── scan.ts                adversa scan [targets] [flags]
│   │   └── findings.ts            adversa findings [list|show|stats]
│   └── ui/
│       └── output.ts              ANSI renderer — banner, stages, tables
│
├── lib/                           Shared business logic
│   ├── engine/
│   │   ├── types.ts               ScanCallbacks · LiveFinding · DiscoveredHost · ScanOptions
│   │   ├── scanner.ts             Core 6-stage scan engine (callback-based)
│   │   └── tool-runners.ts        runNaabu · runNmap · runNuclei · runTestssl
│   ├── findings-store.ts          Finding CRUD · dedup · SLA calculation
│   ├── job-store.ts               Job queue for agent dispatch
│   ├── scan-events.ts             SSE broadcast bus (subscribeScan / broadcastToScan)
│   ├── agents-store.ts            Agent registry (in-memory dashboard + file-based field agents)
│   ├── engagements-store.ts       Engagement management
│   ├── cases-store.ts             Case management
│   ├── graph-store.ts             Attack graph nodes/edges
│   ├── ai-engine.ts               Anthropic Claude SDK — triageFindings · generateReport · chat
│   ├── nmap-parser.ts             XML → NmapHost[]
│   ├── nuclei-parser.ts           JSONL → NucleiMatch → LiveFinding
│   ├── testssl-parser.ts          JSON → TestsslIssue → LiveFinding
│   ├── naabu-parser.ts            JSONL → NaabuResult → DiscoveredHost
│   ├── nmap-parser.ts             XML → NmapHost[]
│   ├── openvas-client.ts          OpenVAS OMP XML-RPC client
│   ├── scan-pipeline.ts           Legacy pipeline state + SSE event queue
│   ├── target-parser.ts           IP / CIDR / hostname validation + UI ParseResult
│   ├── finding-id.ts              VAPT-CRIT-001 ID generator
│   └── prompts/
│       ├── triage.ts              AI triage system prompt
│       ├── report.ts              AI report generation prompt
│       └── exploit-builder.ts     Exploit builder system prompt (safety-constrained)
│
├── agent/                         Python field agent
│   ├── main.py                    Entry point — AdversaAgent.start()
│   ├── poll_loop.py               Register + long-poll job queue
│   ├── scan_executor.py           Full pipeline executor
│   ├── scope_verifier.py          JWT decode + CIDR containment check
│   ├── result_buffer.py           Disk-buffered findings shipper
│   ├── tool_adapter.py            Cross-platform binary resolver
│   ├── config.py                  Config dataclass + env validation
│   └── requirements.txt           requests · PyJWT · click
│
├── components/                    Shared React components
│   ├── Sidebar.tsx                Navigation (all routes, dark mode toggle)
│   ├── ThemeProvider.tsx          Dark/light theme context + localStorage
│   ├── PageShell.tsx              Page layout wrapper
│   ├── DashboardCharts.tsx        Recharts visualisations
│   ├── QueryProvider.tsx          TanStack Query provider
│   └── ToastProvider.tsx          Toast notifications
│
├── hooks/
│   ├── useCountUp.ts              Animated number counter
│   ├── useMouseGradient.ts        Mouse-tracking gradient effect
│   └── useToast.ts                Toast hook
│
├── bin/
│   └── adversa                    CLI shim (dist/cli → tsx fallback)
│
├── data/                          Persistent JSON stores (gitignored in prod)
│   ├── findings.json              All VAPT findings
│   └── agents.json                Registered field agents
│
├── infrastructure/
│   ├── docker-compose.full.yml    Full production stack (Kafka, Neo4j, Vault…)
│   ├── agent/                     Scanning agent Docker image
│   ├── helm/                      Kubernetes Helm charts
│   └── terraform/                 AWS EKS infrastructure
│
├── Dockerfile                     Multi-stage: deps → builder → runner
├── docker-compose.yml             Local dev/prod profiles
├── Makefile                       up · down · dev-up · shell · logs · ci
├── tsconfig.json                  Next.js TypeScript config
└── tsconfig.cli.json              CLI TypeScript config (CommonJS, Node)
```

---

## Data Models

### LiveFinding
```typescript
{
  id:           "VAPT-CRIT-001"          // generated by lib/finding-id.ts
  title:        string
  severity:     "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"
  host:         string                   // IP or hostname
  port?:        number
  source:       "nmap" | "nuclei" | "testssl" | "openvas" | "manual" | "agent"
  status:       "OPEN" | "IN_REVIEW" | "IN_REMEDIATION" | "VERIFIED" | "CLOSED"
  evidence:     [{ label: string; content: string; timestamp: string }]
  cveIds?:      string[]
  engagementId?: string
  slaDeadline?: string                   // computed on save
  timestamp:    string                   // ISO 8601
}
```

### DiscoveredHost
```typescript
{
  ip:        string
  ports:     number[]
  services:  [{ port, proto, name?, version? }]
  os?:       string
  hostnames?: string[]
}
```

### Engagement
```typescript
{
  id:            "ENG-001"
  name:          "ACME Corp — Q2 VAPT"
  client:        string
  status:        "PLANNING" | "ACTIVE" | "PAUSED" | "COMPLETED" | "ARCHIVED"
  scopeCidrs:    ["192.168.1.0/24"]
  findingsBySeverity: { CRITICAL: 2, HIGH: 5, MEDIUM: 12, LOW: 8 }
}
```

### FieldAgent
```typescript
{
  id:               "AGT-A1B2"
  sessionId:        string
  hostname:         string
  os:               string
  status:           "ONLINE" | "OFFLINE" | "BUSY" | "ERROR"
  capabilities:     string[]
  networkInterfaces: [{ name, ip, cidr }]
  registeredAt:     string
  lastSeen:         string
}
```

---

## Compliance Coverage

Every finding is automatically mapped against:

| Framework | Scope |
|---|---|
| NIST SP 800-115 | §4.1 Planning · §5.1 Discovery · §5.2 Vuln Scanning · §5.4 Validation · §6.1 Reporting |
| NIST SP 800-53 Rev 5 | RA-5 · CA-8 · SI-2 · AC-6 · IA-5 · SC-7 · SC-8 · AU-12 · AC-17 · IR-4 |
| ISO/IEC 27001:2022 | A.8.8 · A.8.9 · A.5.17 · A.8.20 · A.8.22 · A.8.15 · A.5.36 |
| PCI DSS v4.0 | Req 11.3.1/2 · 7.2.1 · 8.3.1 · 8.6.1 · 1.3.1 · 1.3.2 · 6.3.3 · 12.10.1 |
| CIS Controls v8 | 5.4 · 7.1 · 7.5 · 12.2 · 13.3 · 18.1 |

---

## Scanning Tools

| Tool | Purpose | Version |
|---|---|---|
| naabu | Fast port discovery (connect scan, no root needed) | 2.3.1 |
| nmap | Service fingerprinting + NSE vuln scripts | 7.x |
| nuclei | CVE / misconfiguration scanner | 3.3.2 |
| testssl.sh | TLS cipher / certificate analysis | 3.2 |
| OpenVAS | Deep authenticated vulnerability scan | via OMP |
| NetExec (nxc) | SMB / WinRM / LDAP credential auditing | — |
| Impacket | Kerberos / AD protocol attacks | — |
| EyeWitness | Web application screenshot capture | — |

Templates are pre-fetched at Docker build time to `/opt/nuclei-templates`.

---

## Make Commands

```bash
make up              # build + start production stack (port 3000)
make down            # stop all services
make dev-up          # hot-reload dev server (port 3001)
make restart         # down + up
make logs            # tail all container logs
make shell           # shell into production container
make typecheck       # TypeScript type check (no emit)
make lint            # ESLint
make ci              # full CI: install → typecheck → lint → build
make docker-build    # build Docker image only
make prune           # remove all unused Docker resources
```

---

## Environment Variables

```bash
# .env.local

ANTHROPIC_API_KEY=sk-ant-...          # required for AI Brain, AI Report, AI triage

# Agent authentication
AGENT_SECRET=adversa-agent-secret-change-me   # Bearer token agents send on register
SCOPE_SECRET=adversa-scope-secret-change-me   # JWT signing key for scan scope tokens

# OpenVAS
OPENVAS_HOST=openvas
OPENVAS_PORT=9390
OPENVAS_USER=admin
OPENVAS_PASSWORD=

# Scan engine limits
SCAN_MAX_RATE=1000
SCAN_NUCLEI_CONCURRENCY=25
SCAN_NUCLEI_RATE_LIMIT=50
SCAN_PIPELINE_TIMEOUT=7200

PORT=3000
NEXT_TELEMETRY_DISABLED=1
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| Frontend | Next.js (App Router) · TypeScript · Tailwind CSS v4 |
| Charts | Recharts |
| Data fetching | TanStack Query v5 |
| Icons | Lucide React |
| AI | Anthropic Claude (`claude-sonnet-4-6`) via `@anthropic-ai/sdk` |
| Scanning tools | naabu · nmap · nuclei · testssl.sh |
| CLI | Commander.js · tsx |
| Python agent | Click · PyJWT · requests |
| Runtime | Node.js 22 · Alpine Linux |
| Container | Docker multi-stage · Docker Compose |
| Auth | JWT scope tokens (SCOPE_SECRET) · Bearer agent tokens (AGENT_SECRET) |
| Prod infra | EKS · Kafka MSK · RDS PostgreSQL · Neo4j · Redis · MinIO · HashiCorp Vault |

---

## Notes

- Findings persist to `data/findings.json` — both the CLI and web dashboard read/write the same file
- The scan pipeline uses SSE for real-time web streaming; the CLI uses direct callbacks — same engine, different output wiring
- Python agents ship findings via `/api/findings/ingest`, which writes to `findings.json` and broadcasts to any open SSE streams simultaneously
- Exploit commands require human approval before execution — HIGH/DESTRUCTIVE risk levels cannot bypass this gate
- No authentication layer on the web dashboard — designed for operator workstations inside an engagement network
- Dark mode is fully implemented via CSS custom properties and `data-theme="dark"` on `<html>`
