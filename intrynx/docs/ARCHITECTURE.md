# ADVERSA — Architecture

> **This copy.** `intrynx/` (this directory — sibling to `scanner_module/` in
> the `Agentic VA Scanner` workspace) is a clean, deduplicated copy of the
> separate `Security-projects/Intrynx copy/` project's `backend/`, `probe/`,
> and `frontend/` (build artifacts and dependency dirs excluded — reinstall
> fresh, see the workspace root `README.md`). Three things were *not* carried
> over, all consistent with `INTEGRATION.md`'s own already-documented
> direction, not a new decision made here:
> `frontend_new/` (an abandoned, unwired v2 frontend scaffold);
> `original/autoresearch` (an unrelated LLM-training experiment, accidentally
> present); and the dead Next.js-side probe/agent system —
> `frontend/probe/`, `frontend/agent/`, `frontend/lib/probe/`, and the
> `app/api/agents/*` + `app/api/probe/*` route handlers that backed it with an
> in-memory store. That last one is exactly the duplication
> `INTEGRATION.md`'s pending-migration table already flags: *"both sides have
> a full probe system; pick FastAPI's `register/heartbeat/{id}/jobs/result`
> and retire the Next one."* Excluding it here executes that decision rather
> than overriding it.
>
> **Consequence to fix next**: `frontend/app/agents/page.tsx` and the agent
> count on `frontend/app/page.tsx` fetch `/api/agents/register` (the now-
> removed mock route) to list probes. Re-point them at the real backend via
> the standard BFF pattern already in use elsewhere
> (`withBackend`/`adapters.ts`/`backend.ts` — see `INTEGRATION.md` §"The
> pattern"), calling FastAPI's `GET /agents` instead. This was already a
> listed pending migration; it isn't a new regression from this consolidation.

ADVERSA is an automated **Network VAPT** (Vulnerability Assessment & Penetration
Testing) platform. It is split into two cooperating planes:

| Plane | What it is | Where it runs |
|---|---|---|
| **Platform (manager)** | A FastAPI control plane + Postgres/Redis (+ optional Neo4j) and a built-in operator console. It stores state, orchestrates work, runs all analysis engines, and serves the dashboard. | Central server / your hosting machine (Docker Compose). |
| **Probe(s)** | Lightweight remote scanners that sit **inside** the target networks. They dial out to the platform, pull scan jobs, run them (today: `nmap` discovery), and ship results back. | One per network segment, behind NAT/firewall. |

```
        OPERATORS (browser / API)                         TARGET NETWORKS
                 │ HTTPS                              ┌──────────┬──────────┐
                 ▼                                    │  DMZ     │ internal │
   ┌──────────────────────── PLATFORM (manager) ─────│──────────│──────────│──┐
   │  ┌──────────── api (FastAPI :18080) ───────────┐│          │          │  │
   │  │ TenantIsolationMiddleware (JWT→tenant scope) ││         ▼          ▼  │
   │  │ dashboard (static console at /dashboard)     ││   ┌──────────┐ ┌──────────┐
   │  │ auth · engagements · assets · findings       ││   │ probe #1 │ │ probe #2 │
   │  │ agents · vuln · exploit · ad · graph         ││◀──│ nmap     │ │ nmap     │
   │  │ detection · ai                                ││   └──────────┘ └──────────┘
   │  └───────┬───────────────┬──────────────┬───────┘│   outbound HTTPS only
   │     ┌────▼───┐      ┌─────▼─────┐   ┌────▼─────┐  │   (register/heartbeat/
   │     │postgres│      │   redis   │   │  neo4j   │  │    poll-jobs/submit)
   │     │(state) │      │(queue/hb) │   │(graph,opt)│ │
   │     └────────┘      └───────────┘   └──────────┘  │
   │        ▲ migrate (one-shot: alembic upgrade + seed admin)                 │
   └────────┼──────────────────────────────────────────────────────────────────┘
```

---

## 1. Deployment topology

Everything on the platform side is one `docker-compose.yml` (see `RUNBOOK.md`):

| Service | Image | Role | Host port |
|---|---|---|---|
| `postgres` | postgres:16 | System of record | internal only |
| `redis` | redis:7 | Job queue + liveness | internal only |
| `neo4j` | neo4j:5 (profile `graph`) | Attack-path graph store (optional) | 7474/7687 |
| `migrate` | adversa-backend (one-shot) | `alembic upgrade head` + seed admin, then exits | — |
| `api` | adversa-backend | FastAPI app + static dashboard | **18080** |
| `probe` | adversa-probe (profile `probe`) | Local test probe (real ones deploy remotely) | none (outbound only) |

`migrate` runs once and `api` only starts after it succeeds, so migrations never
race across workers. The base image is **lean**; heavy integrations (AI/AD/Neo4j
Python libs) install only with `INSTALL_EXTRAS=1` and are imported defensively —
absent libraries degrade to `503`/fallback rather than crashing.

---

## 2. Backend architecture

### 2.1 Request lifecycle
```
HTTP request
  → CORSMiddleware
  → TenantIsolationMiddleware   # decodes JWT, pins request.state.tenant_id + role
  → Router (FastAPI)            # RBAC via require_role([...]) dependency
  → DB session (async SQLAlchemy, auto commit/rollback)
  → Response
```
- **Auth** is JWT (HS256): `access` (15m) + `refresh` (7d). The middleware rejects any non-public path without a valid access token; public paths are `/health`, `/auth/*`, `/docs`, `/dashboard`, `/`.
- **Multi-tenancy**: every JWT carries `tenant_id`; every DB query is scoped to it, so tenants never see each other's data.
- **RBAC** roles: `admin`, `manager`, `tester`, `analyst`, `auditor`. Mutating endpoints gate with `require_role([...])`.

### 2.2 Module map (`backend/app/`)
| Package | Responsibility | Key endpoints |
|---|---|---|
| `auth/` | JWT issue/verify, tenant middleware, RBAC | `POST /auth/login`, `/auth/refresh` |
| `routers/engagements.py` | Operations (SOW), assets, attack surface | `POST/GET /engagements`, `GET /engagements/{id}`, `POST/GET /engagements/{id}/assets`, `GET /engagements/{id}/jobs` |
| `routers/findings.py` | Finding triage | `GET /findings`, `PATCH /findings/{id}` |
| `routers/agents.py` | Probe lifecycle + job queue | `GET/POST /agents`, `/agents/heartbeat`, `/agents/{id}/jobs`, `.../result`, `POST /agents/jobs` |
| `discovery/` | nmap XML parsing, service identification, server-side worker | (consumed by worker / probe results) |
| `vuln/` | Nessus + Nuclei scanners, NVD/EPSS/KEV enrichment, risk score | `POST /engagements/{id}/scans/{nessus,nuclei,import}`, `/{job}/status`, `/{job}/enrich` |
| `exploit/` | Metasploit RPC, **safety allowlist**, approval gate, audit log | `POST /exploits/run`, `GET /exploits`, `/exploit-approvals/*`, `/audit-logs` |
| `ad/` | LDAP enum, Kerberoast/AS-REP (evidence-only), NTLM-relay, ADCS ESC1/4/8, BloodHound | `POST /engagements/{id}/ad/assess`, `/{job}/status` |
| `graph/` | NetworkX/Neo4j attack-path engine | `GET /engagements/{id}/attack-paths`, `/chokepoints`, `/blast-radius/{asset}`, `/attack-graph` |
| `detection/` | SIEM (Splunk/Sentinel/Elastic) + EDR (CrowdStrike/Defender/SentinelOne) correlation, Sigma gaps | `POST .../detection-validation/run`, `GET .../coverage`, `/gaps`, `POST /siem-config` |
| `ai/` | XGBoost prioritizer (+SHAP), Claude report generator, hallucination guard | `POST .../ai-report/generate`, `GET /draft`, `/status/{job}`, `POST /approve`, `/reject` |
| `models/` · `schemas/` · `utils/` | SQLAlchemy models, Pydantic schemas, helpers | — |
| `static/index.html` | The operator console | served at `/dashboard` |

### 2.3 Background work
Long-running tasks (vuln scan, AD assess, detection correlation, AI report) run as
FastAPI **BackgroundTasks** that write progress to a `scan_jobs` row; clients poll
`…/status`. Network scanning is **delegated to probes** via the `agents` queue
(see §4).

### 2.4 Data model (Postgres, 16 tables)
```
tenants ─┬─ users
         └─ engagements ─┬─ assets ── services
                         ├─ findings ── detection_results
                         ├─ scan_jobs              (job queue + probe results)
                         ├─ attack_paths
                         ├─ attack_timeline        (red-team actions, for detection)
                         ├─ detection_configs      (SIEM/EDR creds)
                         ├─ exploit_results / exploit_approvals
                         ├─ llm_outputs            (AI drafts, review_status)
                         └─ audit_logs (append-only)        agents (probes)
```
Migrations are versioned with Alembic (`0001`→`0006`).

---

## 3. Where the SOW / scope is defined

The **Statement of Work / Rules of Engagement** lives on the **engagement** object
(the dashboard calls it an "Operation"). It is the contract that bounds every
action in that engagement.

`engagements` columns:
| Field | Meaning |
|---|---|
| `name` | Operation name |
| `scope_cidrs` (required) | In-scope networks/hosts — what *may* be scanned/attacked |
| `excluded_cidrs` | Carve-outs that override scope (never touch) |
| `start_time` / `end_time` | Authorized testing window |
| `rules_of_engagement` (JSONB) | Free-form RoE: business hours, allowed techniques, contacts, blast-radius limits, etc. |
| `status` | draft / active / paused / completed |

How the SOW is **enforced**, not just stored:
- **Probe targets** come from the operation's `scope_cidrs` (the dashboard's "Discover hosts" uses them automatically).
- **Exploit engine** (`app/exploit/safety.py`) calls `validate_scope(target_ip, scope_cidrs, excluded_cidrs)` before any module runs — out-of-scope IPs raise `OutOfScopeError`. `excluded_cidrs` always wins.
- **Blast-radius limits** and **approval gates** (DC/Exchange/ADCS/critical hosts) read RoE + asset criticality before exploitation.
- **Rate limiting** (`app/discovery/rate_limiter.py`) can honor a business-hours window from the RoE.

So: define scope/RoE once on the engagement → it constrains discovery, exploitation, and reporting downstream.

---

## 4. Probe architecture

### 4.1 What a probe is
A small, self-contained agent (`probe/agent.py`, ~250 LOC + `nmap`) packaged as a
Docker image or a systemd service. It is **stateless to the network** (nothing
listens inbound) and **identity-stable** (its `agent_id`/token are cached in a
state file/volume so restarts reuse the same identity).

### 4.2 Capabilities — what scanning the probe does
The probe is a **registry of scanners** (`probe/scanners/`), each a tool + parser.
It auto-detects which it can run from the installed tools and advertises them on
register; the operator selects one per job via `params.scan_type`.

**White-labeling**: the real tool behind each scanner is an internal detail —
`ENGINE_LABELS` in `probe/scanners/base.py` maps it to a branded `ix-*` codename,
and `sanitize()` redacts raw tool names from any error/log text leaving the
probe. Operators and stored results only ever see the engine codename, never
`nmap`/`masscan`/etc.

| `scan_type` | Engine | What it gathers |
|---|---|---|
| `host_discovery` | `ix-netscan` (nmap `-sn`) | fast liveness sweep — live hosts, MAC + NIC vendor |
| `discovery` | `ix-netscan` (nmap `-sV`) | live hosts, open ports, service + version |
| `port_scan` | `ix-netscan` (nmap, fast) | open TCP ports (no version) — quick sweep |
| `mass_scan` | `ix-fastsweep` (masscan) | internet-speed port sweep of large ranges |
| `service_fingerprint` | `ix-netscan` (nmap `--version-all`) | installed-server inventory — product, version, CPE, category |
| `udp_scan` | `ix-netscan` (nmap `-sU`) | UDP services — SNMP/DNS/NTP/NetBIOS/SIP/IKE |
| `vuln_scan` | `ix-vulnscan` (nuclei) | CVEs, misconfigs, exposures, default logins (severity-tagged) |
| `tls_scan`  | `ix-tlsscan` (sslscan) | weak/deprecated protocols, weak ciphers, certificate issues |
| `web_scan`  | `ix-webscan` (httpx) | HTTP status, title, web server, detected technologies |
| `smb_enum`  | `ix-smbscan` (netexec) | SMB signing, SMBv1, null sessions, (with creds) shares |
| `mcp_discovery` | `ix-aiscan` (builtin) | MCP servers — JSON-RPC handshake + exposed tool/resource enumeration |
| `ai_service_discovery` | `ix-aiscan` (builtin) | AI/LLM/ML servers — Ollama, vLLM, Jupyter, Ray, Triton, ComfyUI, … |
| `passive_discovery` | `ix-passivescan` (builtin) | **OT/ICS-safe** — listens only (mDNS/SSDP/LLMNR/BACnet/EtherNet-IP), transmits nothing |
| `db_fingerprint` | `ix-dbscan` (builtin) | databases — MySQL/Postgres/MSSQL/Redis/MongoDB/Oracle via real protocol handshakes |
| `ssh_inventory` | `ix-sshaudit` (builtin, optional `paramiko`) | credentialed Linux inventory — OS, packages, listeners, processes |
| `windows_inventory` | `ix-winaudit` (builtin, optional `pywinrm`/`impacket`) | credentialed Windows inventory — OS build, hotfixes, software, services (WinRM, SMB fallback) |

The last 4 were added to close gaps the original 12 left: no OT-safe discovery
(every other scan_type is active), no credentialed collection at all, and no
database protocol fingerprinting. `ssh_inventory`/`windows_inventory` only
advertise when their optional Python dependency is importable — same
"missing engine → not advertised" rule as a missing `nmap` binary, via a new
`available_check` override on `Scanner` (`base.py`) for capabilities gated on
a Python import rather than a binary on PATH.

Coarse `job_type` (the bucket the manager hands to probes) maps to a default
`scan_type`: `discovery`→`discovery`, `lateral`→`smb_enum`, `cloud_scan`→`vuln_scan`.
An explicit `params.scan_type` overrides the default and can select any
registered scan_type regardless of `job_type` — see §4.6 for how the OT
profile constrains this. Every scanner returns a normalized
`{scan_type, engine, ok, error, hosts|findings|…}` result; a missing
engine/dependency is reported cleanly and never crashes the probe.

**Discovery output** (submitted as the job result):
```json
{ "host_count": 2,
  "hosts": [
    { "ip": "45.33.32.156", "hostname": "scanme.nmap.org",
      "ports": [ { "port": 22, "protocol": "tcp", "service": "ssh",
                   "product": "OpenSSH", "version": "6.6.1p1" } ] } ] }
```
Job **parameters** the operator/dashboard can set: `targets` (list/CIDR/host),
`ports` (e.g. `1-1024`), `args` (nmap flags, default `-sV -T4 -Pn`), `timeout`.

> Probes only run **network-side** jobs. Server-side analysis (vuln enrichment,
> AD, detection correlation, AI) never leaves the platform — the queue refuses to
> hand those job types to a probe, so a probe can't steal/break them.

### 4.3 Probe ↔ platform protocol
All probe traffic is **outbound HTTPS** to the platform; the agent's bearer token
is required on every call (the `register` step needs an operator token).

```
sequence:
  probe ──POST /auth/login (operator)──────────────▶ platform   # one-time, to register
  probe ──POST /agents/register ───────────────────▶ platform   # → {agent_id, token}
  loop every cycle:
     probe ──POST /agents/heartbeat ───────────────▶ platform   # status: online/busy
     probe ──GET  /agents/{id}/jobs?limit=N ────────▶ platform   # claims pending jobs (discovery/lateral/cloud)
     probe ── run nmap (params.targets) ───┐
     probe ──POST /agents/{id}/jobs/{job}/result ───▶ platform   # parsed hosts/ports
```
The platform assigns a polled job to the claiming agent and marks it `running`;
on result submit it becomes `completed`/`failed` and the result JSON is stored on
the `scan_jobs` row. Operators read it via `GET /engagements/{id}/scans/{job}/status`
or the dashboard.

### 4.4 Managing probes
| Task | How |
|---|---|
| **Deploy** | Copy `probe/`, set `probe.env` (`PLATFORM_URL`, operator creds, `PROBE_NETWORK_SEGMENTS`), run `./install.sh` (Docker) or `./install.sh --native` (systemd). |
| **Register** | Automatic on first start (operator login → `POST /agents/register`), or pin a pre-provisioned `AGENT_ID`/`AGENT_TOKEN`. |
| **List / monitor** | `GET /agents` (tenant-scoped: name, status, capabilities, `last_heartbeat`, `online` flag) — surfaced in the dashboard "Probes" panel. A probe is "online" if it heartbeat within 90s. |
| **Assign work** | `POST /agents/jobs` (operator) enqueues a `discovery`/`lateral`/`cloud_scan` job with `params`; any matching online probe claims it on its next poll. |
| **Scope / segments** | A probe advertises `network_segments` (CIDRs it can reach) at registration. |
| **Identity persistence** | State file (`/var/lib/adversa-probe/state.json`); the Docker/native installers mount a volume so restarts don't re-register. |
| **Stop / retire** | `docker rm -f adversa-probe` or `systemctl disable --now adversa-probe`. Stale agents go `offline` (no heartbeat). |
| **Scale** | Run one probe per segment; each registers independently. |

### 4.5 Security posture
- **Outbound-only** — no inbound listener, safe behind NAT/firewall.
- **Least authority** — the agent token is scoped to agent endpoints; only an operator token can register new probes.
- **Authorized targets only** — discovery targets come from the engagement scope; never point a probe at networks you aren't permitted to test.
- **Raw-socket capability** — SYN scans need `CAP_NET_RAW` (granted in the systemd unit / container).

### 4.6 Environment profiles (IT / IoT / OT) and the OT hard gate

Not every network tolerates the same scanning. An unsolicited active probe
that's routine on a corporate LAN can hang or reboot a PLC/RTU/safety
controller on an OT/ICS segment. An engagement records its profile in
`rules_of_engagement.scan_profile` (`it` | `iot` | `ot`; default `it` when
unset — reuses the existing JSONB field, no schema migration needed):

| Profile | Policy |
|---|---|
| `it` | Active, full scan_type catalog, normal rate/concurrency. |
| `iot` | Active but gentle — intended for embedded/IoT devices (lower rate, curated ports, skip SMB/DB scan types). Not yet a separate enforced policy at the manager level (see below); today this is operator discipline when setting job `params`. |
| `ot` | **Passive only.** Every scan_type except `passive_discovery` is structurally blocked — not a default an operator can quietly override per job. |

**The gate**: `enqueue_agent_job` (`routers/agents.py`) resolves the scan_type
the job would *actually* run (mirroring the probe's own
`resolve_scan_type(job_type, params)` — an explicit `params.scan_type`
override is checked too, not just the coarse `job_type`) and rejects with
`400` if the engagement is `ot`-profiled and that resolved scan_type isn't
`passive_discovery`. This enforces the policy centrally, once, auditably —
**not** by trusting the probe to police itself. A compromised or buggy probe
on a customer's OT network is exactly the wrong place for a safety-critical
"am I allowed to do this" decision to live.

**Deliberately not yet built**: a staged-funnel orchestrator (discovery →
narrow to live hosts → port scan → narrow to open ports → deep inspection,
profile-appropriate port sets and pacing per stage) — that belongs on the
manager too, as a sequence of ordinary jobs it creates one at a time as each
prior stage's result comes in. The probe stays a "dumb" single-scan_type
executor on purpose; giving it its own sequencing logic would put that same
safety-critical decision back on the untrusted edge. This is a larger,
separate piece of work, not implied by the gate above.

> **Current data-flow note:** probe results are stored on the `scan_jobs` row,
> and `submit_job_result()` promotes discovered hosts/ports into the
> `assets`/`services` tables directly (`_promote_assets()` in
> `routers/agents.py`) — not deferred to a separate worker path.
>
> A second gap existed and is now closed: `tls_scan`/`smb_enum`/
> `mcp_discovery`/`ai_service_discovery` already self-compute severity-tagged
> `findings` in their result envelope (e.g. "SMBv1 enabled", "unauthenticated
> MCP server exposed"), but nothing converted those into `Finding` rows —
> they landed on `scan_jobs.result` and were never visible on the dashboard's
> Findings view. `backend/app/discovery/finding_translator.py` bridges this,
> called alongside `_promote_assets()`. It intentionally does **not**
> suppress a finding that reopens after being marked remediated/fp — that is
> a regression signal, not noise to dedupe away.

---

## 5. Frontend architecture

The console is a **single, zero-build, vanilla-JS page** (`app/static/index.html`)
served **same-origin** by the API at `/dashboard` (so there is no CORS and no
separate web server). It is intentionally lightweight — one HTML file, no
framework, no bundler.

### 5.1 Cross-cutting concerns
- **Auth/token (automatic):** sign in once → access+refresh tokens kept in `localStorage`. A small `api()` wrapper attaches the bearer to every call and, on a `401`, transparently calls `/auth/refresh` and retries. The operator never sees a token.
- **Polling:** KPIs, findings, attack surface, and probes auto-refresh every ~6s.
- **Operation context:** an engagement (operation) selector at the top scopes the whole page.

### 5.2 Frontend modules (sections) and their endpoints
| Module (UI section) | What it shows / does | Backend calls |
|---|---|---|
| **Login** | email/password → tokens | `POST /auth/login`, `POST /auth/refresh` |
| **Operation selector + New** | pick/create an engagement (SOW) | `GET /engagements`, `POST /engagements` |
| **KPI bar** | hosts, Critical/High, total findings, coverage, probes online | `GET /engagements/{id}`, `GET /agents`, detection coverage |
| **Step ① Find what's out there** | host/service discovery over scope | `POST /agents/jobs` (discovery) |
| **Step ② Look for weaknesses** | vulnerability scan | `POST /engagements/{id}/scans/nuclei` |
| **Step ③ Map routes to crown jewels** | attack paths + chokepoints | `GET /engagements/{id}/attack-paths`, `/chokepoints` |
| **Step ④ Did defenders notice?** | detection coverage % + caught/blocked/missed | `GET /engagements/{id}/detection-validation/coverage` |
| **Findings** | severity-ranked loot, click for detail | `GET /findings?engagement_id=` |
| **Attack surface** | hosts + open services | `GET /engagements/{id}/assets` |
| **Probes** | sensor status (online dot, caps, last seen) | `GET /agents` |
| **Report** | generate AI draft → approve | `POST .../ai-report/generate`, `GET /draft`, `POST /approve` |

Technical knobs (ports, nmap flags) are hidden behind an "Advanced" disclosure so
the default flow stays plain-language.

> The full React/TypeScript dashboard (Recharts + D3 attack-graph) described in the
> product spec as "Prompt 9" is a future, richer frontend; the served console is
> the operational MVP that ships with the platform.

---

## 6. End-to-end engagement flow

```
1. Operator creates an Operation (SOW: scope_cidrs, RoE, window).
2. Probe(s) deployed on the in-scope network(s), auto-register.
3. ① Discovery  → operator queues discovery → probe runs nmap → hosts/ports/services.
4. ② Vuln scan  → Nuclei/Nessus → findings → enrichment (NVD/EPSS/KEV) → risk score.
5.    (optional) Exploit validation — safety-checked, scope-bounded, approval-gated.
6.    (optional) AD assessment — LDAP/Kerberoast/ADCS/BloodHound (evidence-only).
7. ③ Attack paths → graph engine → routes to crown jewels + chokepoints.
8. ④ Detection validation → correlate red-team timeline vs SIEM/EDR → coverage + Sigma gaps.
9.    AI report → prioritized findings + narrative → human review → approve.
```
Each numbered step maps to a card in the dashboard and to the endpoints in §5.2.

---

## 7. Security model (summary)
- **Tenant isolation** at the middleware layer; all queries scoped by `tenant_id`.
- **RBAC** per endpoint; append-only `audit_logs` for exploit actions.
- **Exploit safety**: exhaustive payload allowlist, blocked module prefixes, scope + blast-radius + approval gates (no override flag).
- **AD/roasting**: capture hashes as *evidence only* — never crack.
- **AI**: strict system prompt + `HallucinationGuard` (flags invented CVEs/CVSS, destructive commands) + mandatory human approval before anything is "final".
- **Probes**: outbound-only, scope-bounded targets, least-privilege tokens.

---

## 8. Extending the system
- **New probe capability** (e.g. remote Nuclei): add a handler in `probe/agent.py` `execute_job()`, advertise the capability, and (if needed) allow the job type in `AGENT_EXECUTABLE_TYPES`.
- **New analysis engine**: add an `app/<module>/` package + a router; guard heavy deps; persist long work via `scan_jobs`.
- **New dashboard module**: add a card/section in `app/static/index.html` calling the relevant endpoint — no build step.

See `RUNBOOK.md` for the exact commands (hosting machine vs probe machine) and
`CHANGELOG.md` for the per-prompt build log.

---

## 9. Target deployment — multi-tenant SaaS, probe-per-client

The platform is operated as a **central manager** (the "mothership") in the cloud
(AWS or similar), with **one probe per client**, deployed inside that client's
network. From a single dashboard the operator manages every client and every probe.

```
                         ┌──────────────── MANAGER (cloud / AWS) ─────────────────┐
                         │  Next.js dashboard ──BFF──▶ FastAPI ──▶ Postgres        │
  Operator (1 browser) ─▶│  multi-tenant: each CLIENT = a tenant                   │
                         │  detection · prioritization · cases · remediation · AI  │
                         └───────▲───────────────▲────────────────▲────────────────┘
                                 │ outbound HTTPS │                │
              ┌──────────────────┘     ┌──────────┘      ┌─────────┘
   ┌──────────┴─────────┐   ┌──────────┴─────────┐   ┌───┴───────────────┐
   │ Client A network    │   │ Client B network    │   │ Client C network   │
   │  probe A (nmap)      │   │  probe B (nmap)      │   │  probe C (nmap)    │
   └─────────────────────┘   └─────────────────────┘   └───────────────────┘
```

### Tenancy model
- **Client = tenant.** Each client maps to a `tenants` row. All data (engagements, assets, findings, scan jobs, agents) is scoped by `tenant_id`, enforced at the middleware layer — clients are fully isolated.
- **Probe = the client's sensor.** You provision a probe with that tenant's operator credentials; on register it becomes a tenant-scoped `agents` row. Everything it submits lands under that tenant.
- **One dashboard, many clients.** An operator/admin logs in once and switches between client tenants; data from each client's probe(s) flows into the same manager and is kept separate by tenant.

### Data flow (probe → manager → value)
```
probe (in client net)        manager (cloud)
─────────────────────        ──────────────────────────────────────────────
nmap discovery  ───────────▶ scan_jobs (raw hosts/ports/services, tenant-scoped)
                              │
                              ▼  (server-side engines, no agent involvement)
                              ├─ vuln scan + enrichment  → findings (CVSS/EPSS/KEV → risk_score)
                              ├─ prioritization (XGBoost + SHAP) → ranked findings
                              ├─ attack-path analysis (graph) → routes + chokepoints
                              ├─ detection validation (SIEM/EDR) → coverage + Sigma gaps
                              ├─ case management → triage/ownership/workflow
                              └─ AI report (Claude, human-approved) → remediation guidance
                              ▼
                       Dashboard renders all of the above, per client.
```
The **probe stays thin** — it only does network-side scanning inside the client
network (today: `nmap` discovery; `lateral`/`cloud_scan` reserved). All the
heavy analysis (detection, prioritization, cases, remediation, reporting) runs on
the manager, which never needs to reach into the client network.

### Why this shape
- **Security:** probes are outbound-only — no inbound exposure inside client networks; the manager holds no implant access, only receives results.
- **Operability:** the manager scales independently in the cloud; onboarding a new client = create a tenant + ship them one probe.
- **Separation of duties:** scanning (edge) vs analysis/decisioning (core) are cleanly split, so a compromised probe leaks only scan output for one tenant, never the platform.

> **Gaps to close for full SaaS** (tracked): self-service **tenant/client provisioning** endpoints, an operator **tenant switcher**, and per-tenant probe-enrollment tokens. The data model already supports tenancy; these are management-surface additions.

---

## 10. Frontend integration (single project)

The `adversa/` Next.js app (now `frontend/` in this monorepo) is the dashboard.
It is integrated with the FastAPI backend using a **BFF (backend-for-frontend)**
pattern so there is one source of truth and no CORS:

```
browser ──▶ Next.js /api/* (BFF route handlers) ──server-side──▶ FastAPI ──▶ Postgres
            (forwards the FastAPI JWT)            (BACKEND_INTERNAL_URL)
```
- The UI keeps calling its own `/api/*` routes; those handlers now **proxy FastAPI** instead of in-memory stores. Contract translation (snake_case↔camelCase, enum maps) lives in `frontend/lib/adapters.ts`; the server client is `frontend/lib/backend.ts`; the proxy wrapper is `frontend/lib/with-backend.ts`.
- **Auth** is unified on the backend's email+password JWT (`/auth/login`, `/auth/refresh`, `/auth/me`); the FastAPI token is the single session token.
- **Packaging:** one monorepo; `docker-compose.yml` adds a `frontend` service (`make full`) wired to the API over the compose network.

Integration is **phased** — see `INTEGRATION.md` for what's wired vs. pending and
the route-by-route migration checklist.
