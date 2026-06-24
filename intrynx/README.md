# Intrynx — Automated Network VAPT Platform

One project, two deployables:

| Part | What it is | Where it runs |
|---|---|---|
| **Manager** (`backend/` + `frontend/`) | The cloud platform — API, database, analysis engines (detection, prioritization, attack paths, AI reporting), and the operator dashboard. Multi-tenant: one tenant per client. | Central server / cloud (AWS, etc.) |
| **Probe** (`probe/`) | A standalone scanning agent. You install **one probe per client**, inside that client's network. It dials out to the manager, runs scans (nmap discovery), and ships results back. | Inside each client's network |

The probe is intentionally **separate and self-contained** (`probe/`) because it is
installed on a different machine than the manager.

```
        Operator (browser)                              Client networks
              │                                    ┌──────────┬──────────┐
              ▼                                     │ client A │ client B │
   ┌──────── MANAGER (cloud) ────────┐             ▼          ▼
   │  frontend (Next.js dashboard)    │       ┌──────────┐ ┌──────────┐
   │      │ BFF                        │◀──────│ probe A  │ │ probe B  │
   │  backend (FastAPI) ── postgres    │  HTTPS│ (nmap)   │ │ (nmap)   │
   │      └── redis (+ neo4j optional) │ (out) └──────────┘ └──────────┘
   └──────────────────────────────────┘
```

## Repository structure
```
intrynx/
├── README.md                  ← you are here
├── Makefile                   ← one-command operations
├── docker-compose.yml         ← the manager stack (+ optional local probe / dashboard)
├── .env.docker.example        ← copy to .env
├── docs/
│   ├── ARCHITECTURE.md        ← system design (multi-tenant, probe-per-client, BFF)
│   ├── RUNBOOK.md             ← exact commands (manager machine vs probe machine)
│   ├── INTEGRATION.md         ← frontend↔backend integration status + migration guide
│   └── CHANGELOG.md           ← per-module build log
├── backend/                   ← MANAGER API (Python / FastAPI + Postgres)
│   ├── app/                   ← auth, engagements, findings, agents, vuln, exploit,
│   │                            ad, graph, detection, ai  (+ static fallback console)
│   ├── alembic/               ← DB migrations
│   ├── scripts/seed_admin.py  ← first-run admin seeder
│   └── tests/                 ← 222 unit tests
├── frontend/                  ← MANAGER dashboard (Next.js 16, BFF → backend)
│   ├── app/                   ← UI pages + /api BFF route handlers
│   └── lib/                   ← backend client, adapters, auth
└── probe/                     ← STANDALONE agent (deploys on client networks)
    ├── agent.py               ← register → heartbeat → poll jobs → nmap → submit
    ├── Dockerfile · install.sh ← Docker or systemd install
    └── probe.env.example
```

## Quickstart

### Manager (this machine / cloud)
```bash
cp .env.docker.example .env      # set JWT_SECRET + SEED_ADMIN_PASSWORD
make run                         # API + a local test probe        → http://localhost:18080
make full                        # API + probe + Next.js dashboard → http://localhost:3000
```
Sign in with `SEED_ADMIN_EMAIL` / `SEED_ADMIN_PASSWORD`.

### Probe (a client's network — a different machine)
```bash
cd probe
cp probe.env.example probe.env   # set PLATFORM_URL + operator creds + network segments
./install.sh                     # Docker   (or ./install.sh --native for systemd)
```

Full step-by-step (manager machine vs probe machine) is in **`docs/RUNBOOK.md`**;
the system design is in **`docs/ARCHITECTURE.md`**.

## Make targets
```
make run     # manager API + local probe (fast)
make full    # everything incl. Next.js dashboard
make up      # manager API only
make down    # stop      |   make clean  # stop + wipe DB
make logs    # tail API  |   make test   # backend test suite
```

## Notes
- **Tenancy:** each client is a tenant; all data is isolated by `tenant_id`. Onboard a client = create a tenant + ship them one probe.
- **Probe capability today:** `nmap` host/service discovery (`lateral`/`cloud_scan` reserved). The probe stays thin; all analysis runs on the manager.
- **Auth:** email + password → JWT (single token across UI and API).
- The `frontend/` still contains some legacy embedded probe/scan code from its prototype origins; the canonical, deployable probe is `probe/`. Migration status is tracked in `docs/INTEGRATION.md`.
