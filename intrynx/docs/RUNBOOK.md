# ADVERSA — Operations Runbook

Two machine roles. Run the right commands on the right box.

| Machine | Role | What runs there |
|---|---|---|
| **Hosting machine** | The platform server | Docker stack: `api` + `postgres` + `redis` (+ optional `neo4j`). You also run operator API calls from here (or anywhere that can reach it). |
| **Probe machine(s)** | Remote scanners inside target networks | One small `probe` container/service with `nmap`. It only dials **out** to the platform — nothing listens inbound. One per network segment you want to assess. |

```
   HOSTING MACHINE                                   PROBE MACHINE (per segment)
 ┌───────────────────────┐    outbound HTTPS only   ┌────────────────────────┐
 │ api :18080             │◀─────────────────────────│ probe (nmap + agent.py)│
 │ postgres / redis      │   register/heartbeat/    │ gathers host+port+svc  │
 │ (+ neo4j optional)    │   poll-jobs/submit       │ ships results back     │
 └───────────────────────┘                          └────────────────────────┘
```

---

# PART A — HOSTING MACHINE

The server that runs the platform.

## A0. Prerequisites
- Docker + Docker Compose v2 (`docker compose version`).
- Ports: only **18080** is published to the host (Postgres/Redis stay on the internal Docker network).

## A1. Install & start (one command)
```bash
cd <repo root>                     # the folder containing docker-compose.yml
cp .env.docker.example .env        # then edit .env (see A2)
make up                            # == docker compose up -d --build
```
What `make up` does, in order:
1. starts **postgres** + **redis** and waits until they're healthy,
2. runs the one-shot **migrate** service → `alembic upgrade head` + seeds the admin user, then exits,
3. starts **api** (only after migrate succeeds), published on `:18080`.

## A2. Configure (`.env`) — change before production
```ini
JWT_SECRET=...                     # >= 32 chars. Generate: openssl rand -base64 48
SEED_ADMIN_EMAIL=admin@adversa.io  # must be a real TLD (NOT .local — email validation rejects it)
SEED_ADMIN_PASSWORD=ChangeMe123!
INSTALL_EXTRAS=0                   # 1 = build image with AI/AD/ML libs (heavy, slow)
ANTHROPIC_API_KEY=                 # set to enable AI reports
```

## A3. Verify it's up — easiest is the dashboard (handles auth/token for you)
```bash
open http://localhost:18080/dashboard/             # sign in: admin@adversa.io / ChangeMe123!
```
The dashboard logs in once, stores + auto-refreshes the token, and gives you buttons to
queue scans, watch probe status, and view re
sults. The curl flow below is optional.

```bash
curl -s localhost:18080/health                     # {"status":"healthy","checks":{"postgres":"ok","redis":"ok"}}
open http://localhost:18080/docs                    # Swagger UI

# get an operator token (you'll reuse $TOKEN below)
TOKEN=$(curl -s -X POST localhost:18080/auth/login -H 'Content-Type: application/json' \
  -d '{"email":"admin@adversa.io","password":"ChangeMe123!"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
echo "$TOKEN"
```

## A4. Day-2 operations
```bash
make logs        # tail API logs            (docker compose logs -f api)
make ps          # service status
make migrate     # re-run DB migrations
make seed        # re-run admin seeder (idempotent)
make down        # stop, keep data
make clean       # stop + DELETE volumes (wipes the database)
make test        # run the backend test suite locally (needs backend/.venv)

docker compose exec api sh                                  # shell inside the API
docker compose exec postgres psql -U vapt -d vapt_db -c '\dt'   # inspect tables
docker compose exec api alembic current                    # current migration revision
```

## A5. Optional add-ons (hosting machine)
```bash
make up-graph    # also start Neo4j (attack-path graph store)
make up-ai       # rebuild image WITH AI/AD/ML extras (impacket, xgboost, anthropic, ...)
```
The base image is **lean**; AD/AI/Neo4j features degrade gracefully (503 / fallback) until you enable them.

## A6. Operator workflow (drive an assessment — runs against the API)
```bash
export URL=http://localhost:18080                  # or https://<your-platform-host>

# 1. create an engagement (scope_cidrs is required)
ENG=$(curl -s -X POST $URL/engagements -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"Acme Q3","scope_cidrs":["10.0.1.0/24"]}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["id"])')

# 2. queue a DISCOVERY job for a probe to execute (job_type: discovery|lateral|cloud_scan)
JOB=$(curl -s -X POST $URL/agents/jobs -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"engagement_id\":\"$ENG\",\"job_type\":\"discovery\",
       \"params\":{\"targets\":[\"10.0.1.0/24\"],\"ports\":\"1-1024\",\"args\":\"-sV -T4 -Pn\"}}" \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["job_id"])')

# 3. (a probe must be running on that network — see PART B) read the result
curl -s "$URL/engagements/$ENG/scans/$JOB/status" -H "Authorization: Bearer $TOKEN"
```
Other engagement workflow endpoints (all `-H "Authorization: Bearer $TOKEN"`):
| Stage | Call |
|---|---|
| import assets | `POST /engagements/$ENG/assets` (JSON array) |
| vuln scan (Nuclei) | `POST /engagements/$ENG/scans/nuclei` |
| enrich + triage | `POST /engagements/$ENG/scans/$JOB/enrich` · `GET /findings?engagement_id=$ENG` |
| exploit-validate (safe) | `POST /exploits/run` · `GET /exploit-approvals` |
| AD assess (needs `make up-ai`) | `POST /engagements/$ENG/ad/assess` |
| attack paths | `GET /engagements/$ENG/attack-paths` · `/chokepoints` · `/attack-graph` |
| detection validation | `POST /engagements/$ENG/detection-validation/run` · `GET .../coverage` |
| AI report (needs key) | `POST /engagements/$ENG/ai-report/generate` · `GET .../draft` · `POST .../approve` |

A local test probe can be started **on the hosting machine** for a smoke test:
```bash
make probe-run          # docker compose --profile probe up -d --build probe
docker compose logs -f probe
```

---

# PART B — PROBE MACHINE

A box **inside the network you want to scan**. It gathers host/port/service info with `nmap` and ships it to the platform. Repeat per segment.

## B0. Prerequisites
- The probe machine must reach the platform over **outbound HTTPS** (e.g. `https://adversa.example.com`). It does **not** need any inbound ports open.
- Docker **or** Linux+systemd (the installer supports both). `nmap` is bundled (Docker) or installed for you (native).
- Operator credentials (or a pre-provisioned agent token) so the probe can register.

## B1. Get the probe files onto the machine
Copy the `probe/` directory to the probe machine (scp/git/usb):
```bash
scp -r probe/ user@probe-host:/opt/    # example
ssh user@probe-host
cd /opt/probe
```

## B2. Configure
```bash
cp probe.env.example probe.env
$EDITOR probe.env
```
Minimum to set:
```ini
PLATFORM_URL=https://adversa.example.com      # the hosting machine's URL (required)
OPERATOR_EMAIL=admin@adversa.io               # probe logs in once and self-registers
OPERATOR_PASSWORD=ChangeMe123!
PROBE_NAME=dmz-probe-01
PROBE_NETWORK_SEGMENTS=10.0.1.0/24,10.0.2.0/24
# VERIFY_TLS=false                            # ONLY for a self-signed lab platform
```
(Alternative to operator creds: register once via the API and pin `AGENT_ID`/`AGENT_TOKEN`.)

## B3. Install & run — pick ONE
```bash
./install.sh             # Docker: builds image (python+nmap), runs container, --restart unless-stopped
# or
./install.sh --native    # Linux+systemd: venv + nmap + a service with CAP_NET_RAW (for SYN scans)
```

## B4. Verify the probe is gathering info
```bash
# Docker:
docker logs -f adversa-probe
# native (systemd):
journalctl -u adversa-probe -f
```
Healthy log sequence:
```
registered with platform   agent_id=...
probe online               caps=discovery
executing job              type=discovery
running nmap               targets=10.0.1.0/24
job done                   success=True
```

## B5. What the probe does each cycle
1. **register** (once) → `POST /agents/register` → gets its agent token (cached so restarts reuse it).
2. **heartbeat** every 30s → `POST /agents/heartbeat`.
3. **poll** → `GET /agents/{id}/jobs` (only `discovery`/`lateral`/`cloud_scan` are handed to probes).
4. **execute** → runs `nmap` against the job's `params.targets`, parses open ports + service/version.
5. **submit** → `POST /agents/{id}/jobs/{job_id}/result`. The operator reads it via `GET /engagements/{eng}/scans/{job}/status`.

## B6. Probe config reference (`probe.env`)
| Var | Meaning |
|---|---|
| `PLATFORM_URL` | platform base URL (required) |
| `OPERATOR_EMAIL`/`OPERATOR_PASSWORD` | login → self-register (one auth option) |
| `AGENT_ID`/`AGENT_TOKEN` | pre-provisioned identity (other auth option) |
| `PROBE_NAME` / `PROBE_LOCATION` | display identity |
| `PROBE_NETWORK_SEGMENTS` | CIDRs this probe can reach (advertised on register) |
| `NMAP_DEFAULT_ARGS` | default nmap flags (default `-sV -T4 -Pn`) |
| `PROBE_DEFAULT_TARGETS` | fallback targets if a job carries none |
| `HEARTBEAT_INTERVAL`/`POLL_INTERVAL`/`JOB_LIMIT` | timing/throughput |
| `VERIFY_TLS` | `false` only for self-signed lab platforms |

## B7. Job parameters (set by the operator in `POST /agents/jobs`)
```json
{ "targets": ["10.0.1.0/24"], "ports": "1-1024", "args": "-sV -T4 -Pn", "timeout": 1800 }
```

## B8. Stop / remove the probe
```bash
docker rm -f adversa-probe                       # Docker
sudo systemctl disable --now adversa-probe       # native
```

---

# Who runs what — quick reference

| Action | Hosting machine | Probe machine |
|---|---|---|
| Start the platform (`make up`) | ✅ | |
| `curl /health`, `/auth/login` | ✅ (or any client) | |
| Create engagement, queue jobs, read results | ✅ (operator) | |
| Run the scanner (`nmap`) | | ✅ |
| `./install.sh` (probe) | only for a local smoke test (`make probe-run`) | ✅ |

> ⚠️ Only scan networks you are authorized to assess. Set a strong `JWT_SECRET`, change `SEED_ADMIN_PASSWORD`, and in production put the API behind TLS and don't publish Postgres/Redis ports. Engineering changelog lives in `CHANGELOG.md`.
