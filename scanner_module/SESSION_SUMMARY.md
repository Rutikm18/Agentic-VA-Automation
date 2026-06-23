# Session Summary — 2026-06-23

Scope: hardened `scanner_module` (Agentic VA Scanner), designed an agentic-AI
integration architecture, then integrated `scanner_module`'s validated
capabilities into the separate **Intrynx** VAPT platform
(`Security-projects/Intrynx copy/`) without creating a duplicate scanning
engine. Two projects touched; this doc lives in `scanner_module` since that's
the home base, but covers both.

---

## 1. Architecture research: where does agentic AI actually belong?

Question going in: should scanning be agent-driven ("give an AI a scope list
and let it decide"), or stay deterministic/code-driven with AI layered on
top?

**Conclusion: keep scanning fully deterministic; put AI strictly at the
analysis/correlation/communication layer, never in the network-I/O loop.**
Three reasons, not style preference:

1. **Compliance defensibility.** Audits (PCI DSS 11.3, NIST 800-115) expect a
   reproducible, explainable methodology. "The AI decided to skip that port"
   is a liability, not a feature.
2. **Indirect prompt injection is real here, not hypothetical.** Every
   banner/HTTP body/TLS CN field a scanner touches is attacker-controlled
   text if the target is hostile. Feeding that raw into an LLM's instruction
   context is an injection channel. The fix: the AI layer must only ever
   consume structured, already-parsed fields — never raw `evidence`/banner
   bytes.
3. **Cost/latency.** An LLM call per scan decision is slow and expensive at
   the scale `pipeline.py` already operates at. Reserve LLM calls for the
   much lower-volume "turn a batch of findings into a narrative/remediation"
   step.

Five-layer architecture landed on: **Scan Engine → Ingestion/Storage →
Detection Engine (deterministic) → Attack Graph Engine (deterministic
traversal, AI narrates) → AI Brain (Claude; remediation, compliance mapping,
triage chat) → Dashboard.**

### Memory correction
The existing memory for "ADVERSA" was 26 days stale — described a static
Next.js demo. Reality: a full two-plane platform (FastAPI/Postgres manager +
Python probe agent), already production-shaped. Memory rewritten; a new
`project-agentic-va-scanner` memory and a `feedback-ground-truth-testing`
memory were also added (see `~/.claude/.../memory/MEMORY.md`).

---

## 2. `scanner_module`: the `mcp_ai_scanner.py` false-positive fix

**Bug found via manual ground-truth testing** (see `MANUAL_TESTING.md`):
macOS's AirPlay receiver (port 5000, `Server: AirTunes`) was flagged as a
possible Ollama/MCP server — **4 separate fake findings from one service** —
because the confirmation logic treated a bare HTTP 401/403 as "exists, auth
enforced," with no check on whether the response carried any real auth
semantics.

**Fix — evidence-tiered confirmation**, grounded in actual specs:
1. Known false-positive denylist (Server/body fingerprint, e.g. AirPlay) —
   suppresses outright.
2. `WWW-Authenticate` referencing RFC 9728 OAuth Protected Resource Metadata
   (required by the MCP Authorization spec, 2025-03+) → confidence 95.
3. Any `WWW-Authenticate` header (RFC 7235) → confidence 85, trusted
   standalone (global auth gates legitimately 401 every path, including
   nonexistent ones).
4. JSON-typed body naming auth/tokens/keys → confidence 70.
5. Bare status code, none of the above → suppressed (debug-logged, not
   silently dropped).

**A near-miss worth recording**: the first draft required JSON-body evidence
to *also* differ from a control probe against a bogus path, to rule out
generic catch-all pages. Building a dedicated fixture for that exact case —
a global FastAPI auth dependency that legitimately 401s every path including
bogus ones — showed this would have produced a **false negative** on a very
common real-world pattern. Fixed by trusting `WWW-Authenticate`/JSON-body
evidence on its own merits, not gated on a differential. This is the
session's clearest example of "build the adversarial fixture before shipping
a fix," not just reason about it.

Validated against 4 fixtures: real AirPlay (4→0 false positives), real
Ollama (still confirms, 95), the global-auth-gate trap case (now correctly
confirms, 70), real MCP OAuth signal (confirms, 95).

---

## 3. `scanner_module` testing & validation

Full pass through `MANUAL_TESTING.md`'s ground-truth methodology against
real fixtures (planted HTML title, real TLS 1.3 server, fake banner, real
MySQL):

| Scanner | Result |
|---|---|
| `host_discovery` | PASS — caught a Docker listener my own manual `lsof` check missed |
| `port_scanner` | PASS — exact match, correct negative on closed port |
| `service_banner` | PASS — exact banner match |
| `tls_scanner` | PASS on a clean fixture; **found a real, separate bug**: `ConnectionResetError` against Docker Desktop's internal TLS proxy specifically (Python's bundled OpenSSL vs. system `openssl` CLI ClientHello difference) — not yet fixed, documented in `CURRENT_STATE.md` |
| `web_scanner` | PASS — exact planted-title match |
| `db_scanner` | PASS — exact MySQL version match |
| `udp/smb/snmp_scanner` | PASS — correct negatives, cross-checked against `dig` |
| `mcp_ai_scanner` | bug found + fixed (see §2) |
| `nmap_wrapper` / `mass_scan` | PASS — zero contradictions across 3 independent engines |
| `pipeline.py` (it/ot) | PASS — IT funnel reproduces individual results; OT profile proven to send zero packets (grep + live test), hard-refuses active scanning |

**Re-verified today, fresh**: ran `./test_all.sh 127.0.0.1` — 13/13 clean,
zero errors. Cross-checked every result against live `lsof`/`nc` ground
truth (MySQL 9.6.0 real, Docker's Postgres real, port 5000 = Control
Center/AirPlay again) — `mcp_ai_scan` correctly returned 0 findings,
confirming the §2 fix holds on a fresh independent check, not just the
original test run.

---

## 4. Intrynx integration — what already existed there

Discovered (not assumed) via direct code reading: Intrynx already has a
**real backend** (FastAPI + Postgres, 16-table schema, CVSS/EPSS/KEV
enrichment, attack-path graph engine, AD assessment, AI reporting) and a
**real, deployed probe** (`probe/`) with its own scanner registry,
white-labeling (`nmap`→`ix-netscan` etc.), host-locked licensing, and tests.
It also has **4 separate duplicate agent/probe implementations** from past
iteration, which the project's own docs already flag for cleanup.

Explicit instruction followed throughout: **do not add a 5th duplicate** —
port validated logic into the existing `probe/scanners/` `@scanner` registry,
never copy-paste standalone files into a new folder.

### Task 1 — `scan_job.result → Finding` pipeline (verified broken, then fixed)

Found, by reading the actual router code: a probe's `tls_scan`/`smb_enum`/
`mcp_discovery`/`ai_service_discovery` results — which already self-compute
severity-tagged `findings` — were being silently dropped. `submit_job_result()`
only promoted hosts/services into inventory tables, never created `Finding`
rows. New module `backend/app/discovery/finding_translator.py` bridges this,
with dedup that intentionally does **not** suppress a finding reopening after
remediation (a real regression signal, not noise).

### Task 2 — ported `passive_collector.py` → `probe/scanners/passive.py`

New `passive_discovery` scan_type. Zero packets sent (grep-verified: no
`send`/`connect` of any kind). Real 3-second live test found a real host via
mDNS. Required extending `base.py`'s `Scanner` class with distinct builtin
sentinels per capability (`BUILTIN_PASSIVE` → `ix-passivescan`) so it isn't
mislabeled as the AI scanner.

### Task 3 — ported `db_scanner.py` → `probe/scanners/db.py`

New `db_fingerprint` scan_type (MySQL/Postgres/MSSQL/Redis/MongoDB/Oracle).
Validated live against real MySQL (`9.6.0`, exact match) and real Postgres.
Deliberately scoped to **one** finding rule — unauthenticated Redis — because
it's the only fact these lightweight handshakes genuinely prove (MongoDB's
`isMaster` succeeding doesn't prove data access is unauthenticated; claiming
otherwise would repeat the §2 class of bug). Validated both directions with
real Redis fixtures (no-auth → critical finding; auth-required → detected,
no false finding).

### Task 4 — credentialed collection → `probe/scanners/ssh.py` + `windows.py`

`ssh_inventory` and `windows_inventory`, faithfully ported. `ssh_inventory`
validated against a **real paramiko SSH server fixture** (full connect →
auth → exec → capture cycle, plus wrong-password and missing-credential
negative cases). `windows_inventory`'s WinRM→SMB fallback control flow
validated live (no real Windows host available — flagged honestly rather
than claimed as fully tested). Both use optional Python deps
(`paramiko`/`pywinrm`/`impacket`) via a new `available_check` mechanism on
`Scanner`, so a probe without them simply doesn't advertise the capability —
same rule as a missing `nmap` binary.

**Flagged, not fixed**: credentials travel via `params.credentials`,
matching the *existing* `smb_enum` convention — but that means they land in
`scan_jobs.result` (Postgres JSONB) in cleartext at job-creation time, before
the probe ever picks the job up. Followed the established pattern rather
than inventing a divergent one; this is a real, separate decision (encrypt
at rest? redact after consumption?) that deserves explicit discussion.

### Task 5 — hardened `probe/scanners/mcp_ai.py`

Found a real, demonstrable bug distinct from §2: the legacy MCP HTTP+SSE
fallback trusted a bare "200 + `text/event-stream` content-type" as proof of
an MCP server — and used a non-streaming HTTP helper that would have
**blocked until timeout on every genuinely long-lived SSE connection**,
making the check non-functional against exactly the servers it was meant to
detect. Fixed with a proper streaming read requiring real evidence (an
`event: endpoint` frame per the legacy MCP spec, or JSON-RPC-shaped data).
Validated against a real generic-SSE fixture (continuous heartbeats, never
closes — correctly rejected, and didn't hang) and `httpx.MockTransport` unit
tests for fast regression coverage.

### Task 6 — designed the it/iot/ot profile concept; implemented the safety-critical piece

Design: the staged funnel (discovery → narrow to live hosts → port scan →
narrow to open ports → deep inspection) belongs on the **manager**, not the
probe. The probe stays a "dumb" single-scan_type executor by design — giving
it autonomous sequencing logic would put a safety-critical decision (may I
escalate to active scanning?) on a remote, less-trusted, customer-network
machine instead of one central, auditable gate.

**Implemented now**: a hard OT gate in `enqueue_agent_job` — when an
engagement's `rules_of_engagement.scan_profile == "ot"`, any job whose
*resolved* scan_type (not just the coarse `job_type` label) isn't
`passive_discovery` is rejected with HTTP 400. Mirrors `pipeline.py`'s
structural (non-flag) OT block. Tested: blocks the default active resolution,
blocks an explicit `params.scan_type` override attempt, allows
`passive_discovery`, and confirms `it`/`iot` engagements are unaffected.

**Deferred deliberately**: the full staged-funnel orchestrator (new
endpoint, a small state machine, IT/IoT port-and-rate policy mirroring
`pipeline.py`'s `PROFILES` dict) — meaningfully larger, separate
infrastructure work, not rushed in as the last of several tasks.

---

## 5. Other findings flagged, not unilaterally fixed

- **Nessus/Nuclei bypass the probe entirely** — `vuln_scans.py` runs nuclei
  directly from the backend server (or talks to an external Nessus API),
  which quietly defeats the probe's whole design point (manager never needs
  direct network reach into the client's network).
- **`scope_check()` was defined but never called anywhere** — no probe
  scanner enforced it, and the backend never validated job targets against
  `engagement.scope_cidrs` at job-creation time. The new `passive_discovery`
  scanner is the first to actually wire it in for real.

---

## 6. Final verification state

- `scanner_module`: `./test_all.sh 127.0.0.1` — 13/13 clean, every result
  cross-checked against live ground truth.
- Intrynx backend: 233 tests passed, 3 skipped, 0 failed.
- Intrynx probe: 55 tests passed, 0 failed.
- Zero regressions introduced across either project during this session.
