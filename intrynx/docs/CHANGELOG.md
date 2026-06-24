# Intrynx — Change Log

---

## Probe security — host-locked licensing + plain-English UX  ✅ Complete

**Made the probe copy-resistant and simple to run.** A copied probe folder is
useless on another machine, the operator experience is plain English, and the
existing scan flow is unchanged. **+13 security tests (43 total pass).**

- **Host-locked deployment license** (`security/license.py`): Ed25519-signed token;
  the probe embeds only the **public** key (can verify, never mint). Binds to a
  machine **Host ID** + **expiry**; failures raise plain-English `LicenseError`s
  (missing / invalid / expired / wrong-machine). Enforced at startup; a wrong-host
  or absent license exits with a friendly message and the machine's Host ID.
- **Machine fingerprint** (`security/hostid.py`): stable id from `/etc/machine-id`
  / macOS `IOPlatformUUID` / Windows BIOS UUID, with a `PROBE_HOST_ID` override for
  containers.
- **Host-bound state** (`security/state.py`): the cached identity is Fernet-encrypted
  with a key derived from the Host ID — a lifted `state.json` won't decrypt elsewhere.
- **Vendor mint tool** (`tools/mint_license.py`): `keygen` (creates the private key +
  embeds the public key), `hostid`, and `mint`. `keys/` and `license.key` are git-ignored.
- **Plain-English flow + one-command run**: `./probe run|check|setup|hostid|version`;
  friendly lifecycle messages ("Registered as 'dmz-01'. Ready. Waiting for scan jobs…
  Running host discovery on 10.0.1.0/24 … done — 12 hosts"). `agent.py` now loads
  `probe.env` itself (handles values with spaces), and `check` reports license, Host
  ID, ready/missing scans, and manager reachability.
- Dependency: `cryptography`. Dockerfile/installer ship the `security/` package; the
  private key is never copied into the image.

---

## Probe capability expansion — network VA + MCP/AI discovery  ✅ Complete

**Doubled the probe's capability registry from 6 → 12 scanners** for full network
vulnerability-assessment coverage, including first-class **host discovery**,
**installed-server fingerprinting**, and novel **MCP / AI-server discovery**.
**27 parser/registry/detection tests pass**; new scanners verified end-to-end
against live nmap and a mock MCP/AI server (Streamable-HTTP + legacy SSE).

New `scan_type`s:

| `scan_type` | tool | output |
|---|---|---|
| `host_discovery` | nmap `-sn` | fast liveness sweep — live hosts, MAC, NIC vendor |
| `mass_scan` | masscan | internet-speed port sweep of large ranges |
| `service_fingerprint` | nmap `-sV --version-all` | installed-server inventory — product, version, **CPE**, server **category** |
| `udp_scan` | nmap `-sU` | UDP services (SNMP/DNS/NTP/NetBIOS/SIP/IKE) |
| `mcp_discovery` | builtin (httpx) | **MCP servers** — JSON-RPC `initialize` handshake, enumerates exposed `tools`/`resources`; unauthenticated server with code/data tools → `critical` |
| `ai_service_discovery` | builtin (httpx) | **AI/LLM/ML servers** — Ollama, vLLM/LM-Studio/LocalAI/llama.cpp, Jupyter, Ray, Triton, TorchServe, ComfyUI, Gradio/SD-WebUI, Open WebUI, MLflow → exposure findings |

- `scanners/base.py`: added a `BUILTIN` tool marker (pure-Python scanners are always available), plus `split_host_port()` and CIDR-expanding `expand_hosts()` (capped) helpers.
- `scanners/discovery.py`: `parse_nmap_xml` now extracts **CPE**, **MAC/vendor**, OS-match accuracy, and TLS `tunnel` info, and accepts an `include_states` filter (used by the UDP scanner for `open|filtered`). Benefits `discovery`/`port_scan` too.
- `scanners/fingerprint.py`: server taxonomy (`categorize`) + `build_inventory` (servers, `by_category`, `software` rollups).
- `scanners/mcp_ai.py`: detection logic in pure, offline-testable functions (`parse_jsonrpc` JSON+SSE, `extract_mcp_server_info`, `classify_mcp_tools`, per-product AI matchers); thin concurrent `httpx` I/O layer (lazy import) with `ThreadPoolExecutor`, bounded bodies, and per-task exception isolation.
- No new external tools required — nmap/masscan already bundled; MCP/AI run on the probe's existing `httpx`. No backend changes (selection via `params.scan_type`).

---

## Probe scanning module  ✅ Complete

**Refactored the probe into a capability registry** (`probe/scanners/`) — 6 scanners,
each a tool + parser, auto-detected and advertised on register; dispatched by
`params.scan_type` (no backend changes needed). **11 parser/registry tests pass.**

| `scan_type` | tool | output |
|---|---|---|
| `discovery` / `port_scan` | nmap | hosts + open ports (+ service/version on discovery) |
| `vuln_scan` | nuclei | CVE/misconfig findings (severity, CVEs) |
| `tls_scan`  | sslscan | weak protocols/ciphers, cert issues |
| `web_scan`  | httpx | status, title, web server, tech |
| `smb_enum`  | netexec | SMB signing / SMBv1 / null session |

- `scanners/base.py` registry + normalized result envelope + tool detection; `__init__.py` dispatch + `available_capabilities()`.
- `agent.py` now dispatches `scan_type` (default mapped from `job_type`), advertises installed capabilities, logs the capability catalog, and degrades gracefully when a tool is absent.
- `Dockerfile` bundles nmap, sslscan, masscan, nuclei, httpx, netexec; `install.sh` (Docker / systemd) installs the same and ships `scanners/`.
- Tests: `probe/tests/test_scanners.py` — nmap/nuclei/sslscan/httpx/netexec parsers + dispatch/registry.

---

## ADVERSA Platform — Backend Change Log

---

## Prompt 1 — Backend Foundation  ✅ Complete

**Files created:** 40

### Models (SQLAlchemy 2.0 async)
| File | Table | Notes |
|---|---|---|
| `app/models/tenant.py` | `tenants` | Multi-tenant root — id, name, plan, created_at |
| `app/models/user.py` | `users` | RBAC roles enum, bcrypt password, MFA flag, UniqueConstraint(tenant+email) |
| `app/models/engagement.py` | `engagements` | PostgreSQL ARRAY for scope_cidrs, JSONB for rules_of_engagement |
| `app/models/asset.py` | `assets` | IP validation, asset_type + criticality enums, JSONB tags |
| `app/models/finding.py` | `findings` | CVSS/EPSS/risk_score decimals, ARRAY mitre_techniques, JSONB evidence |
| `app/models/attack_path.py` | `attack_paths` | UUID[] path_nodes, JSONB[] path_edges, UUID[] chokepoints |
| `app/models/detection.py` | `detection_results` | SIEM+EDR alert tracking, latency, Sigma recommendation |
| `app/models/scan_job.py` | `scan_jobs` | Job type + status enums, agent_id, JSONB result |

### Auth
| File | Purpose |
|---|---|
| `app/auth/jwt.py` | HS256 JWT — access (15m) + refresh (7d) + jti for revocation |
| `app/auth/middleware.py` | `TenantIsolationMiddleware` — validates JWT, injects tenant_id into request.state |
| `app/auth/rbac.py` | `require_role(["admin","manager"])` — FastAPI Depends decorator |
| `app/auth/router.py` | POST /auth/login, POST /auth/refresh |

### API Routers
| Route | Method | Auth | Notes |
|---|---|---|---|
| `/health` | GET | public | PostgreSQL + Redis liveness check |
| `/auth/login` | POST | public | bcrypt verify, returns access+refresh |
| `/auth/refresh` | POST | public | rotates both tokens |
| `/engagements` | POST | admin,manager | creates engagement scoped to tenant |
| `/engagements` | GET | any | paginated list with status+date filters |
| `/engagements/{id}` | GET | any | detail with asset count + finding summary |
| `/engagements/{id}/assets` | POST | admin,manager,tester | bulk import JSON array or CSV |
| `/findings` | GET | any | paginated, filters: severity,status,asset_id,mitre_technique |
| `/findings/{id}` | PATCH | admin,manager,tester,analyst | status, owner, notes, enrichment fields |

### Infrastructure
| File | Purpose |
|---|---|
| `app/config.py` | pydantic-settings, `.env` loading, `is_production` flag |
| `app/database.py` | `create_async_engine` + `async_sessionmaker`, auto-commit/rollback |
| `app/dependencies.py` | `DB`, `AuthUser`, `RedisConn` type aliases for FastAPI DI |
| `app/utils/pagination.py` | `paginate_query()` — count + OFFSET/LIMIT in one helper |
| `app/utils/csv_parser.py` | CSV→AssetIn parser with column aliasing and enum coercion |
| `app/schemas/common.py` | `PaginatedResponse[T]` generic, `paginate()` helper |
| `alembic/versions/0001_initial.py` | Full migration: 9 enum types + 8 tables + all indexes |
| `Dockerfile` | python:3.12-slim, 4 uvicorn workers |

---

## Prompt 2 — Network Discovery Engine  ✅ Complete

**Files created:** 11

### New Models
| File | Table | Notes |
|---|---|---|
| `app/models/service.py` | `services` | port, protocol, service_name, version, banner per asset |
| `app/models/agent.py` | `agents` | agent registration, capabilities[], heartbeat tracking |

### Discovery Engine
| File | Class | Purpose |
|---|---|---|
| `app/discovery/xml_parser.py` | `NmapXMLParser` | Parses nmap -oX XML → list[ParsedHost] with ports+services |
| `app/discovery/service_id.py` | `ServiceIdentifier` | Banner + port → {service, version, product, cpe, confidence_score} |
| `app/discovery/rate_limiter.py` | `RateLimiter` | Token-bucket PPS enforcement + business-hours window from RoE |
| `app/discovery/worker.py` | `DiscoveryWorker` | Full async pipeline: Redis queue → nmap → banner grab → PostgreSQL |

### Agent API
| Route | Method | Notes |
|---|---|---|
| `/agents/register` | POST | Self-registration, returns agent JWT |
| `/agents/heartbeat` | POST | Updates last_heartbeat + status |
| `/agents/{id}/jobs` | GET | Returns pending ScanJobs for this agent |
| `/agents/{id}/jobs/{job_id}/result` | POST | Submits job result, triggers asset/service save |

### Tests
| File | Covers |
|---|---|
| `tests/test_xml_parser.py` | XML parsing, empty scan, partial output, malformed XML |
| `tests/test_service_identifier.py` | All 13 service types, unknown banner, confidence scoring |

### Alembic
| File | Change |
|---|---|
| `alembic/versions/0002_services_agents.py` | Creates `services` + `agents` tables |

---

---

## Prompt 3 — Vulnerability Scanner Integration  ✅ Complete

**Files created:** 9

### Vuln Engine
| File | Class | Purpose |
|---|---|---|
| `app/vuln/nessus.py` | `NessusScanner` | Full async Nessus v6 API client — auth (API key + session), create/launch/poll/results/export |
| `app/vuln/nuclei.py` | `NucleiScanner` | Nuclei CLI subprocess wrapper — async run, JSONL parser, template_selector(services→tags) |
| `app/vuln/enrichment.py` | `VulnEnrichmentService` | NVD 2.0 + EPSS + CISA KEV + MITRE; in-memory cache; composite risk 0-1000 |
| `app/vuln/tasks.py` | `run_post_scan_enrichment` | Background task: dedup by SHA-256 hash, batch enrich, fire webhook on critical findings |

### NessusScanner key methods
| Method | Returns |
|---|---|
| `authenticate(url, access_key, secret_key)` | Stores API key or session token |
| `create_scan(engagement_id, target_ips, policy_id, creds)` | nessus scan_id |
| `launch_scan(scan_id)` | scan_uuid |
| `poll_status(scan_id)` | `{status, progress_percent, host_count}` |
| `get_results(scan_id)` | list of raw plugin finding dicts |
| `map_finding(raw)` | Finding-compatible dict (severity, CVEs, CVSS, exploitable, evidence) |
| `export_nessus_file(scan_id)` | `.nessus` XML bytes for evidence storage |

### VulnEnrichmentService formula
```
risk_score (0-1000) = (
  cvss_norm   * 0.25 +   # CVSS/10
  epss        * 0.20 +   # FIRST EPSS score
  kev_bonus   * 0.20 +   # 1.0 if on CISA KEV catalog
  exploit_val * 0.15 +   # 1.0 if exploit_validated=True
  asset_crit  * 0.10 +   # 1.0=critical .. 0.25=low
  path_depth  * 0.05 +   # 1.0=1 hop, 0.0=10+ hops
  lateral     * 0.05     # reachable hosts / 50
) * 1000
```

### API Routes added
| Route | Method | Auth | Notes |
|---|---|---|---|
| `/engagements/{id}/scans/nessus` | POST | admin,manager,tester | Create+launch Nessus scan, auto-creates ScanJob |
| `/engagements/{id}/scans/nuclei` | POST | admin,manager,tester | Launch Nuclei async, saves findings+triggers enrichment |
| `/engagements/{id}/scans/{job_id}/status` | GET | any | Poll ScanJob status+result |
| `/engagements/{id}/scans/{job_id}/enrich` | POST | admin,manager,analyst | Manual enrichment trigger |
| `/engagements/{id}/scans/import` | POST | admin,manager,tester | Bulk finding import from any scanner |

### Alembic
| Migration | Change |
|---|---|
| `0003_vuln_scan_fields.py` | GIN indexes on mitre_techniques[] and cve_ids[], risk_score B-tree, partial index on un-enriched findings |

### Tests
| File | Covers |
|---|---|
| `tests/test_nessus_scanner.py` | authenticate, create_scan with creds, launch, poll_status, map_finding (critical/info/no-CVSS) |
| `tests/test_vuln_enrichment.py` | NVD fetch+cache, EPSS, CISA KEV (present/absent/case), MITRE hints, composite risk formula bounds, full enrich() integration, dedup_hash |

---

## Prompt 4 — Exploitation Engine (Safe)  ✅ Complete

**Files created:** 12  |  **Total Python files:** 68  |  **All syntax-clean**

### Safety system (`app/exploit/safety.py`)
- Exhaustive payload **allowlist**: `cmd/unix/generic`, `windows/x64/exec` (whoami/hostname/id only), `generic/none`, pingback probes
- 13 **blocked payload patterns**: meterpreter, reverse_tcp, bind_shell, encrypt, ransomware, staged, vncinject…
- **Module blocklist prefixes**: `auxiliary/dos/`, `auxiliary/fuzzer/`, `post/*/credentials`, `encoder/`, `evasion/`
- `validate_scope()` — CIDR membership; excluded_cidrs override; `OutOfScopeError`
- `requires_approval()` — triggers on criticality=critical OR DC/Exchange/ADCS hostname patterns
- `CVE_MODULE_MAP` — 10 CVEs → safe `{module, payload, safe_check}`

### `MetasploitRPCClient` — msgpack-over-HTTPS
`connect` · `list_modules` · `run_module` → job_id · `get_job_status` · `kill_job` · `wait_for_job`

### `ExploitOrchestrator` — full pipeline in `execute()`
Safety → Scope → Blast radius (5/15min) → Approval gate → MSF run → `ExploitResult` persist → `AuditLog`

### `NucleiExploitRunner`
`safe_template_check` (YAML parse + 14 unsafe patterns + blocked tags) · `run_cve_poc` → `{vulnerable, evidence}`

### DB models: `ExploitResult`, `ExploitApprovalRequest`, `AuditLog` (FK=RESTRICT, append-only)

### API routes
`POST /exploits/run` · `GET /exploits` · `GET /exploits/{id}` · `GET /exploit-approvals` ·
`POST /exploit-approvals/{id}/approve` (auto-queues BackgroundTask) ·
`POST /exploit-approvals/{id}/reject` · `GET /audit-logs`

### Alembic `0004` — 3 tables + 8 indexes

### Tests — 40 unit tests across 8 test classes; integration tests skip unless `--msf-host` provided

---

## Prompt 5 — Active Directory Assessment Module  ✅ Complete

**Files created:** 8 (`app/ad/` package + router + tests)  |  **All syntax-clean, 36 unit tests passing**

Read-only AD assessment. Every offensive dependency (ldap3 / impacket / neo4j /
bloodhound-python) is **optional** — modules import cleanly and degrade to a typed
error or empty result when a dependency is missing, so the API never 500s on an
ImportError. Roasting checks **capture hashes as evidence only — never crack them**.

### Shared (`app/ad/findings.py`)
- `build_ad_finding(...)` — emits Finding-compatible dicts (same shape as the Nuclei/Nessus scanners). Every finding carries MITRE technique, CWE, step-by-step reproduction, detection opportunity, and remediation. Fields without a Finding column (CWE, reproduction, detection, attack_narrative) live in `evidence` JSONB.
- Exceptions: `ADError`, `ADConnectionError`, `DependencyMissingError`. UAC-flag / privileged-group / ADCS-flag / low-priv-SID constant tables.

### `LDAPEnumerator` (`app/ad/ldap_enum.py`)
`connect` (NTLM or Kerberos SASL) · `get_users` → `ADUser` (SPN, no_preauth, admin_count via UAC parsing) · `get_computers` → `ADComputer` (is_dc via UAC/primaryGroupID) · `get_groups` → `ADGroup` (privileged flag) · `check_anonymous_bind` · `get_aces` (nTSecurityDescriptor → `ACE[]` via impacket ldaptypes, best-effort).

### `KerberoastChecker` (`app/ad/kerberoast.py`)
`get_spn_accounts` (excludes krbtgt) · `request_tgs` → `$krb5tgs$` hash (evidence) · `generate_finding` (Critical if adminCount accounts, else High; MITRE T1558.003).

### `ASREPRoastChecker` (`app/ad/asreproast.py`)
`get_no_preauth_accounts` · `request_asrep` → `$krb5asrep$` hash (evidence, credential-less AS-REQ) · `generate_finding` (MITRE T1558.004).

### `NTLMRelayChecker` (`app/ad/ntlm_relay.py`)
`check_smb_signing` (per-host signing_enabled/required/reachable via impacket SMB) · `check_ldap_signing` (unsigned bind probe → enforced bool) · `generate_finding` with `attack_narrative` + ready-to-run `ntlmrelayx.py` command (MITRE T1557.001).

### `ADCSChecker` (`app/ad/adcs.py`)
`enumerate_templates` → `CertTemplate[]` (Configuration NC) · `check_esc1` (enrollee-supplied subject + client-auth EKU + low-priv enrolment, no manager approval) · `check_esc4` (low-priv dangerous write on template) · `check_esc8` (web enrollment + NTLM without EPA/HTTPS) · `generate_findings` (MITRE T1649).

### `BloodHoundCollector` (`app/ad/bloodhound.py`)
`run_collection` (async `bloodhound-python` subprocess → JSON) · `import_to_neo4j` (nodes + MemberOf edges, idempotent MERGE) · `query_da_paths` (Cypher shortestPath to Domain Admins) · `generate_finding` (MITRE T1482/T1078.002).

### `ADAssessmentRunner` (`app/ad/orchestrator.py`)
Full pipeline (LDAP enum → anon bind → kerberoast → AS-REP → NTLM relay → ADCS → optional BloodHound). Per-stage isolation: a stage failure or missing dep is recorded in `errors[]` without aborting the rest.

### API routes (`app/routers/ad.py`)
`POST /engagements/{id}/ad/assess` (admin,manager,tester — queues BackgroundTask, creates `ScanJob(ad_enum)`) · `GET /engagements/{id}/ad/{job_id}/status`. Findings persist into the shared `findings` table (no new migration needed — reuses existing schema and the `ScanJobType.ad_enum` enum value).

### Deps added — `ldap3`, `impacket`, `neo4j`, `bloodhound`

### Tests — `tests/test_ad_assessment.py`: 36 unit tests (UAC parsing, ESC1/4/8 logic, signing posture, finding contract, BloodHound paths) — all external access mocked, no live domain required.

---

## Prompt 6 — Attack Path Analysis Engine  ✅ Complete

**Files created:** 7 (`app/graph/` package + router + tests)  |  **27 unit tests passing**

In-memory **NetworkX** is the canonical engine (deterministic, fully testable
with no DB and no Neo4j). **Neo4j is optional** — the same graph is mirrored via
batched `UNWIND` writes when enabled, and equivalent Cypher shortest-path queries
are provided for >10k-node graphs. The graph is a `MultiDiGraph` so an asset pair
can carry several relationship types at once (e.g. `SAME_SEGMENT` *and*
`CREDENTIAL_REUSE`).

### `Neo4jClient` (`app/graph/neo4j_client.py`)
Guarded driver wrapper: `connect` (verify connectivity) · `ensure_schema` (UNIQUE constraints on Asset/Finding/Service id + range indexes on engagement_id, criticality, internet_exposed, cvss) · `run` / `run_write` (UNWIND batching) · `close`. No-ops cleanly when the driver is absent.

### `GraphBuilder` (`app/graph/builder.py`)
`build_asset_graph(engagement_id, assets, services, findings, credentials, network_topology)` — node types **Asset / Service / Finding / Credential / NetworkSegment**; relationships **HAS_SERVICE, HAS_FINDING, EXPLOITS, CONNECTS_TO, SAME_SEGMENT, CREDENTIAL_REUSE**. `add_exploit_edges` (EXPLOITS Finding→Asset, weight = `exploit_complexity` from CVSS AC / severity) · `add_network_edges` (CONNECTS_TO + SAME_SEGMENT from segmentation) · `build_from_db` (loads from PostgreSQL) · `sync_to_neo4j` (mirror).

### `PathAnalyzer` (`app/graph/analyzer.py`)
Operates on an Asset→Asset **movement projection** (collapses parallel edges by rel priority; edge cost = hop cost + destination's easiest exploit). `find_paths_to_target` (NetworkX simple paths from internet-exposed sources) · `score_path` (0–100: sum exploit CVSS, hop penalty, credential-reuse bonus) · `identify_chokepoints` (interior assets on >50% of paths, with remediation priority) · `find_blast_radius` (reachable assets by distance). Includes `CYPHER_SHORTEST_PATH` / `CYPHER_BLAST_RADIUS` / `CYPHER_CHOKEPOINTS` examples.

### `GraphVisualizer` (`app/graph/visualizer.py`)
`to_d3` → `{nodes:[{id,label,type,criticality,compromised,x,y}], edges:[{source,target,technique,weight,exploited}], paths:[{id,hops,risk_score,highlighted}]}`. Deterministic numpy-free ring layout (frontend re-runs its own force sim).

### `demo.py`
`generate_demo_dataset()` — 4-asset DMZ→app→data topology with exploitable findings, segmentation, and a reused credential. Drives tests and docs.

### API routes (`app/routers/attack_paths.py`)
`GET /engagements/{id}/attack-paths` (recompute + paginated, risk-sorted; persists to `attack_paths`) · `GET .../attack-paths/{path_id}` (hop-by-hop explanation) · `GET .../chokepoints` · `GET .../blast-radius/{asset_id}` · `GET .../attack-graph` (D3 JSON).

### Config / deps
Neo4j settings added to `config.py` + `.env.example` (`NEO4J_ENABLED=false` default). `networkx==3.4.2` added. **No migration** — reuses the existing `attack_paths` table.

### Tests — `tests/test_attack_paths.py`: 27 tests (builder node/edge types, exploit-complexity, path discovery + scoring, chokepoints, blast radius, D3 export determinism, guarded Neo4j) — all in-memory, no DB/Neo4j required.

---

## Prompt 7 — Detection Validation Engine  ✅ Complete

**Files created:** 8 (`app/detection/` package + router + tests + migration)  |  **26 unit tests passing**

Grades the blue team: correlates each red-team attack action against SIEM alerts
and EDR detections to mark it **detected / prevented / missed**, rolls up ATT&CK
coverage, and auto-generates Sigma rules for the gaps. All SIEM/EDR HTTP is async
(httpx) and fails soft — an unreachable provider degrades to "no alerts" rather
than crashing the run.

### New tables (migration `0005`)
- `attack_timeline` — append-only ledger of every attack action (engagement, finding, MITRE technique, target, timestamp, detail). Heavily indexed for ±window correlation.
- `detection_configs` — per-engagement SIEM/EDR connection settings (provider + JSONB secrets; one row per engagement).
- `detection_results` extended — added `engagement_id`, `attack_action_id`, `host_ip`, `detection_status` enum; `finding_id` made nullable. Added `detection` value to `scanjobtype`.

### `AttackLogger` (`app/detection/logger.py`)
`log_action(...)` — called by all attack modules to record the exact timestamp of each action into `attack_timeline`.

### `SIEMQueryEngine` (`app/detection/siem.py`)
Abstract `query_alerts(time_start, time_end, host_filter) → list[SIEMAlert]` with **SplunkSIEM** (REST export + SPL), **SentinelSIEM** (Azure Monitor Logs + KQL), **ElasticSIEM** (`_search` bool query). Provider factory `build_siem_engine`.

### `EDRQueryEngine` (`app/detection/edr.py`)
Abstract `query_detections(...) → list[EDRDetection]` with **CrowdStrikeFalcon** (`/detects` query+summaries), **MicrosoftDefender** (Graph `/security/alerts_v2`), **SentinelOne** (`/threats`). `EDRDetection.is_prevented` distinguishes blocked vs. alerted. Factory `build_edr_engine`.

### `DetectionCorrelator` (`app/detection/correlator.py`)
`correlate(timeline, siem_alerts, edr_detections)` — ±5min same-host matching → prevented (EDR blocked) / detected (alert fired) / missed. `compute_coverage` → `{total_techniques, detected, prevented, missed, coverage_pct, by_technique}`. `generate_gap_report` → `DetectionGap[]` with Sigma rules. Timezone-safe (naive timestamps normalised to UTC).

### `SigmaRuleGenerator` (`app/detection/sigma.py`)
Template library of base Sigma rules per technique (T1190/T1059/T1558.003/T1558.004/T1110/T1003/T1021/T1557.001/T1649/T1046), sub-technique → parent fallback, customised with observed evidence (host, process, SPN…). Emits valid YAML with deterministic rule ids.

### API routes (`app/routers/detection.py`)
`POST /engagements/{id}/detection-validation/run` (queues correlation BackgroundTask, `ScanJob(detection)`) · `GET .../results` · `GET .../coverage` (ATT&CK matrix) · `GET .../gaps` (missed + Sigma) · `POST .../siem-config` (upsert; never echoes secrets).

### Tests — `tests/test_detection_validation.py`: 26 tests (detected/prevented/missed grading, window + host matching, coverage, Sigma generation/customisation, all 6 SIEM/EDR parsers, factories). Splunk integration test skips unless `--splunk-url` given.

---

## Prompt 8 — AI Engine (LLM Reporting + Risk Scoring)  ✅ Complete

**Files created:** 8 (`app/ai/` package + router + tests + migration)  |  **21 unit tests passing**

ML-based prioritisation + Claude-backed report generation with a mandatory
human-in-the-loop review gate and a hallucination guard. All heavy deps
(`anthropic`, `xgboost`, `shap`, `scikit-learn`) are optional — modules import
cleanly and degrade (fallback formula / 503) when they're absent.

> **Model note:** the spec named `claude-sonnet-4-20250514`, which is deprecated and retires 2026-06-15. Used the current equivalent **`claude-sonnet-4-6`** (configurable via `LLM_MODEL`) — it still honours the spec's `temperature=0.3` (Opus 4.8 would reject sampling params).

### New table (migration `0006`)
- `llm_outputs` — every generation persisted with `prompt_hash`, `model`, `output`, `generated_at`, `reviewed_by`, `review_status` enum `[pending, approved, rejected]`, plus the hallucination-guard `validation` verdict. Added `ai_report` to the `scanjobtype` enum.

### `VulnPrioritizer` (`app/ai/prioritizer.py`)
`train(df)` (XGBoost regressor on the 7-feature vector — cvss, epss, kev, exploit_validated, asset_criticality, lateral_reachable_count, days_since_last_patch) · `predict_priority` → 0–1000 · `explain_prediction` (SHAP values when available) · **weighted-formula fallback** matching the Prompt-3 composite when no model is trained or ML libs are missing.

### `LLMReportGenerator` (`app/ai/llm_report.py`)
`AsyncAnthropic` client; strict `SYSTEM_PROMPT` (only use provided data, never invent CVE/CVSS, no destructive commands); `temperature=0.3`; explicit exponential-backoff retry. Methods: `generate_executive_summary` (400–600 word CISO/board summary), `generate_technical_finding`, `generate_remediation_steps`, `generate_detection_rule_explanation`. Each output is guard-validated and saved to `llm_outputs` as `pending`. Raises `LLMUnavailableError` (→ 503) without a key.

### `HallucinationGuard` (`app/ai/hallucination.py`)
`validate_cve_claims` (flags CVE IDs not in the finding set) · `validate_cvss_scores` (flags scores not matching any finding ±0.1) · `validate_remediation_commands` (12 destructive patterns: rm -rf, DROP TABLE, mkfs, fork bomb…) · `validate` → `{valid, issues, confidence}`.

### API routes (`app/routers/ai_report.py`)
`POST /engagements/{id}/ai-report/generate` (queues BackgroundTask, `ScanJob(ai_report)`, builds engagement summary from findings/paths/detection coverage) · `GET .../status/{job_id}` · `GET .../draft` (pending sections) · `POST .../approve` (marks final) · `POST .../reject` (feedback + auto-regeneration).

### Config / deps
Added `ANTHROPIC_API_KEY`, `LLM_MODEL`, `LLM_MAX_TOKENS`, `LLM_TEMPERATURE`, `LLM_MAX_RETRIES` to config + `.env.example`. Added `anthropic`, `scikit-learn`, `xgboost`, `shap`, `pandas`, `numpy`.

### Tests — `tests/test_ai_engine.py`: 21 tests (prioritiser feature extraction + fallback scoring + monotonicity, all 3 hallucination checks + aggregate, LLM generation with mocked `AsyncAnthropic`, guard integration on invented CVEs, retry/backoff, `LLMUnavailableError`).

---

## Deployment & Probe  ✅ Complete

**Single-command platform install + a deployable scanning probe.** (+7 tests)

### Platform (Docker Compose — repo root)
- `docker-compose.yml` — `postgres` + `redis` (healthchecked) → one-shot **`migrate`** service (`alembic upgrade head` + admin seed) → **`api`** (starts only after migrate succeeds). Optional `neo4j` (`--profile graph`) and in-stack `probe` (`--profile probe`).
- `.env.docker.example`, `Makefile` (`up`/`up-graph`/`up-ai`/`down`/`logs`/`migrate`/`seed`/`probe-run`…), `RUNBOOK.md` (ops reference split by machine: hosting vs probe).
- **Lean by default**: `Dockerfile` installs `requirements-core.txt`; heavy AI/AD/Neo4j deps (`requirements-extras.txt`) only with `--build-arg INSTALL_EXTRAS=1`. Added `email-validator` to core (fixes the clean-env import gotcha).
- `scripts/seed_admin.py` — idempotent tenant+admin seeder (env-driven; there's no public signup).

### Agent/probe protocol hardening (`app/routers/agents.py`)
- Polling restricted to `AGENT_EXECUTABLE_TYPES` (`discovery`/`lateral`/`cloud_scan`) so a probe can't steal server-side background jobs (vuln/AD/detection/AI).
- Jobs response now carries `params` so probes know what to scan.
- New `POST /agents/jobs` — operators enqueue agent-executable jobs with params.

### Offensive-ops console (`app/static/index.html`, served at `/dashboard`)
- Single-page, zero-build vanilla-JS console served same-origin by the API (no CORS). Sign in once → JWT stored in localStorage and **auto-attached + auto-refreshed** (transparent token handling); `/` redirects to `/dashboard/`.
- **Operator-framed, not API-framed**: an "Operation" (engagement) selector, a KPI bar (hosts / Critical / High / total findings / detection coverage / probes online), and a plain-language 4-step flow — **① Find what's out there** (discovery), **② Look for weaknesses** (vuln scan), **③ Map routes to crown jewels** (attack paths + chokepoints), **④ Did defenders notice?** (detection coverage) — plus severity-ranked Findings, an Attack-surface table, Probe status, and an AI report draft/approve panel. Technical inputs (ports/nmap args) are tucked behind an "Advanced" toggle.
- Supporting read endpoints: `GET /agents` (probes + online flag), `GET /engagements/{id}/jobs` (jobs + results), `GET /engagements/{id}/assets` (hosts + services). Middleware allows `/dashboard` + `/` unauthenticated (the page handles its own login).

### Probe (`probe/`)
- `agent.py` — standalone client: operator-login→register (or pre-provisioned `AGENT_ID`/`AGENT_TOKEN`, cached in a state file) → heartbeat → poll → run **nmap** for `discovery` (XML parsed to hosts/ports/services) → submit. Outbound-HTTPS only.
- `Dockerfile` (python + nmap), `install.sh` (Docker **or** `--native` systemd unit with `CAP_NET_RAW`), `probe.env.example`, `README.md`.

## Upcoming

| # | Prompt | Status |
|---|---|---|
| 9 | Frontend dashboard (React 18, white/red-blue 2030 theme) | ⏳ Pending |
| 10 | Infrastructure (Kubernetes + Kafka + Terraform) | ⏳ Pending |
