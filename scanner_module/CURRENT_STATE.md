# VA Scanner Module — Current State & Capabilities

This document is a complete, accurate snapshot of what exists in this codebase
**right now**, verified by reading every source file (not from memory). It
covers what each module does, how the pieces fit together, what is and is not
built, and the known limitations.

Total: **19 Python files, ~3,800 lines**, pure standard library except the two
optional credentialed collectors.

---

## 1. Project philosophy

This is a **collection-only** vulnerability-assessment scanner. Three hard
rules run through every module:

1. **Scope is mandatory.** Every scanner requires `-s scope.txt`. A target not
   in the allowlist is refused before any packet is sent. There is no flag to
   bypass this.
2. **Read-only.** No exploitation, no brute-forcing, no credential spraying, no
   modification of any target. Where a protocol offers an unauthenticated
   read (Redis `INFO`, MySQL's server greeting, SNMP `GET`), the scanner reads
   it; it never authenticates with guessed credentials or writes anything.
3. **Observe, don't judge.** Each scanner reports raw facts ("server accepted
   TLSv1.0", "SMBv1 negotiate succeeded"). None of them decide "vulnerable" —
   that is an explicitly separate, not-yet-built detection/correlation layer.

Because every scanner emits the same schema (`ScanResult`, below), you can
diff any scanner's output against a hand-verified ground truth and compute
precision/recall/false-positive rate per module in isolation — this is what
`MANUAL_TESTING.md` walks through.

---

## 2. Foundation: `scanner/scanner_base.py`

Every scanner inherits from `BaseScanner` and gets, for free:

| Component | What it does |
|---|---|
| `ScopeGuard` | Loads an allowlist (CIDR / single IP / exact hostname, `#` comments). `in_scope()` checks before any operation; `from_file()` raises `ScopeError` (wrapped, not a raw traceback) if the file is missing/empty/unreadable. |
| `RateLimiter` | Async token-paced limiter — at most `--rate` operations/sec, shared across all concurrent tasks. |
| `asyncio.Semaphore` (`self.sem`) | Bounds **concurrent operations**, not targets. Every scanner acquires it around each individual socket call (`async with self.sem:`), so `-p 1-65535` against one host can't silently spawn 65,535 unbounded sockets — this was an actual bug, fixed by moving acquisition from per-target to per-operation scope across 9 scanner files. |
| `ScanResult` | The unified output dataclass (see §3). |
| `ResultWriter` | Streams JSONL to a file and/or stdout; auto-creates parent directories. |
| `expand_targets()` | CIDR / range (`a-b`) / single host / hostname → de-duplicated host list. Caps at 200,000 hosts (`ValueError` past that) to stop a typo'd `/8` from spawning millions of asyncio tasks — push genuinely large ranges through `mass_scan.py`, which scans CIDRs directly without pre-expanding. |
| `parse_ports()` | `"22,80,443,8000-8100"` → sorted unique int list. Rejects garbage, reversed ranges, and out-of-range ports (must be 1–65535). |
| `main_entrypoint()` | Wraps every CLI's async body. Catches `ScopeError` / `OSError` / `ValueError` → one-line error + `exit(1)`. Catches `KeyboardInterrupt` → "interrupted by user" + `exit(130)`. No scanner leaks a raw Python traceback for a routine operator mistake (bad scope file, bad `-p` spec, Ctrl+C mid-scan). |
| `base_argparser()` | Shared CLI flags every scanner gets identically: `-t/--targets`, `-s/--scope` (required), `-o/--output`, `--rate`, `--concurrency`, `--timeout`, `-v`. |

### 2.1 `ScanResult` — the unified schema

```json
{
  "scanner": "port_scan",
  "target": "10.0.0.5",
  "timestamp": "2026-...Z",
  "port": 445,
  "proto": "tcp",
  "status": "open",
  "data": { /* scanner-specific parsed facts */ },
  "evidence": "tcp connect succeeded",
  "error": null
}
```

`status` is one of `observed | open | closed | filtered | error`. Identical
across all 13 scanner modules — this is what makes cross-engine A/B testing
(your pure-Python scanner vs nmap vs masscan) and per-scanner FP measurement
possible.

---

## 3. The 13 unauthenticated network scanners

Each is independently runnable as `python3 -m scanner.<name> -t <targets> -s scope.txt`.

| Module | Method | Default ports | Key output facts |
|---|---|---|---|
| **`host_discovery.py`** | TCP connect to 8 common ports (`80,443,445,22,3389,53,135,139`). Any response — open **or** RST/refused — proves liveness. Unprivileged (no raw ICMP). | fixed 8-port probe set | `alive: bool`, `responding_ports: [{port, state}]` |
| **`port_scanner.py`** | Full TCP `connect()` per port via OS stack. 3-state model: open (SYN/ACK) / closed (RST) / filtered (timeout). No SYN/stealth scanning (needs root — use `nmap_wrapper.py` for that). | `TOP_TCP_PORTS` (34 ports) or `-p` | `status` per port; `--report-closed` to also emit closed/filtered (off by default to reduce noise) |
| **`service_banner.py`** | Connects, waits briefly for a service to greet first (SSH/SMTP/FTP), else sends a minimal benign probe (`GET / HTTP/1.0` for known web ports, else `\r\n`) and reads the reply verbatim. | caller-specified (`-p` required) | `banner` (first 1000 chars), `first_line`, `byte_len` |
| **`tls_scanner.py`** | Per protocol version (TLS 1.0/1.1/1.2/1.3) attempts a pinned handshake to learn exactly which versions the server accepts; fetches the peer certificate (no chain validation — just reads it). Runs in a thread executor (pure `ssl`+`socket`, no event-loop blocking). Suppresses the stdlib's `DeprecationWarning` for intentional TLS1.0/1.1 probing. | `443,8443,993,995,465,636,989,990,5986` | `accepted_versions`, `cipher_by_version`, certificate `subject/issuer/not_before/not_after/san/expired` |
| **`udp_scanner.py`** | UDP has no handshake, so it sends a small valid **protocol-specific** read request per service (DNS A-query, NTP mode-3 client packet, SNMPv1 GET sysDescr, NetBIOS node-status) and looks for a real reply. | `53` (dns), `123` (ntp), `161` (snmp), `137` (netbios-ns) | `service`, `reply_bytes`, `reply_hex_head`; no-reply → `status: filtered` (ambiguous open\|filtered, UDP's fundamental limitation) |
| **`smb_scanner.py`** | Hand-rolled SMB protocol **negotiation only** — sends an SMBv1 `SMB_COM_NEGOTIATE` (dialect list incl. legacy `NT LM 0.12`) and a separate SMB2 `NEGOTIATE`. Reads the negotiate response only; no auth, no share access, no MS17-010 trigger. | `445` | `smbv1_enabled: bool`, `smb2_supported: bool` |
| **`snmp_scanner.py`** | SNMPv1 `GET` for `sysDescr.0` (`1.3.6.1.2.1.1.1.0`) tried against 5 common community strings (`public, private, community, manager, snmp`). Read-only GET, never SET. Includes a small hand-rolled BER walker to extract the OCTET STRING value. | `161` | `community` (which one worked), `sysdescr` |
| **`web_scanner.py`** | One benign GET per port via `urllib`. Parses `<title>`, `Server`/`X-Powered-By` headers, presence/absence of 5 security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy), and a small signature table for tech fingerprinting (WordPress, Drupal, Joomla, Django, Laravel, React, Grafana, Kibana, Jenkins). No fuzzing, no path brute-forcing. | `80,443,8080,8443,8000,8888,9000,9200` | `status`, `title`, `server`, `tech_hints[]`, `security_headers_present/missing` |
| **`mcp_ai_scanner.py`** | Discovers exposed AI inference servers / MCP endpoints via known discovery paths only: Ollama (`/api/tags`, `/api/version`), OpenAI-compatible (`/v1/models`), MCP (`/sse`, `/mcp`). Confirms a hit only on a signature-matched 2xx body, or a 401/403 on one of those specific paths (treated as "exists but auth-enforced"). Never calls a tool or sends an action-triggering prompt. | `11434,8000,8080,5000,3000,1234,8001,7860,11435` | `kind` (ollama/openai_compat/mcp), `auth_enforced`, `unauthenticated_access`, `model_count` (when present) |
| **`db_scanner.py`** | Real **protocol handshakes**, not banner guessing — most DBs speak binary. MySQL: reads the server's own greeting packet (version is embedded, server speaks first). PostgreSQL: sends `SSLRequest`, reads the single `S`/`N` reply byte. MSSQL: sends a minimal TDS pre-login packet, checks for a TDS response type. Redis: sends `INFO server` (unauthenticated info is public on most installs; `NOAUTH` reply still confirms Redis). MongoDB: sends an `isMaster` OP_QUERY, checks reply opcode + extracts version via regex. Oracle: minimal TNS connect packet, checks TNS response type (accept/refuse/resend all confirm a listener). | `3306,5432,1433,6379,27017,1521` | `engine`, `server_version` (where the protocol volunteers it), engine-specific facts (`ssl_supported`, `auth_required`, etc.) |
| **`mass_scan.py`** | Wraps the `masscan` binary (stateless, scans CIDRs directly without host-expansion) when installed; **falls back to a pure-Python async connect sweep** (no root, no external binary) when it isn't. Designed as stage 1 of a two-stage pattern: mass-find-opens → deep-inspect only those. | `1-1000` (`-p` to override) | Same schema; `--fallback` forces the pure-Python path |
| **`nmap_wrapper.py`** | Shells out to `nmap -oX -` and parses the XML into the same `ScanResult` schema, so you can A/B nmap's findings against the pure-Python scanners. 5 profiles: `discovery` (`-sn` ping sweep), `version` (`-sT -sV`), `os` (`-sT -O`, needs root), `smb` (NSE `smb-protocols,smb2-security-mode`), `fast` (`-sT -F`). Only `-sT`/`-sV` based profiles run without root; SYN/OS detection need it. | profile-dependent | `service/product/version/cpe`, OS matches, NSE script output |
| **`passive_collector.py`** | **The only scanner that sends zero packets.** Joins multicast discovery groups (mDNS `224.0.0.251:5353`, SSDP `239.255.255.250:1900`, LLMNR `224.0.0.252:5355`) and binds broadcast/industrial ports (NetBIOS `137`, BACnet/IP `47808`, EtherNet/IP `2222`) in recv-only mode, then records whichever in-scope hosts voluntarily announce themselves within a listen window. Built specifically for OT/ICS, where an unsolicited active probe can disrupt a live physical process. Out-of-scope chatter is observed but never recorded. Gracefully skips any source port that's already bound (logs a warning, doesn't fall back to anything active). | n/a — listens, never connects | `announced_via[]`, `device_hints[]` (parsed mDNS service names / SSDP `SERVER:`/`USN:` headers), `packets_observed` |

### 3.1 `mcp_ai_scanner.py` false-positive fix (evidence-tiered confirmation)

`mcp_ai_scanner.py` originally flagged macOS's **AirPlay receiver on port
5000** as a possible Ollama/MCP server (4 separate false findings from one
service), because it treated a bare HTTP 401/403 on an AI-shaped path as
"exists, auth-enforced" — without checking whether the 401/403 carried any
actual auth semantics. **Fixed** with an evidence-tiered confirmation model:

1. **Known false-positive denylist** — Server-header/body fingerprint match
   (e.g. `AirTunes`/`AirPlay`) suppresses a candidate outright.
2. **Real auth evidence required**, not just a status code — in order of
   strength: an MCP-spec `WWW-Authenticate` header referencing OAuth 2.0
   Protected Resource Metadata (RFC 9728 / the MCP Authorization spec,
   confidence 95) → any `WWW-Authenticate` header (RFC 7235, confidence 85) →
   a JSON-typed error body that actually names auth/tokens/keys (confidence
   70). A control probe against a deliberately nonexistent path is also sent
   per port for audit transparency (recorded in `data.checks`), but is **not**
   used to gate the JSON-body tier — an earlier version did, and that
   incorrectly produced a false *negative* on real, properly-secured APIs
   that apply auth middleware globally before routing (so they 401 a bogus
   path too — normal, correct behavior for e.g. a global FastAPI auth
   dependency, not evidence of a problem).

Validated against 4 fixtures: the real AirPlay false positive (4→0), a real
Ollama server (still confirms, confidence 95), a simulated global-auth-gate
API with no `WWW-Authenticate` header (confirms at 70 — this is the case the
control-diff-gated version would have missed), and a simulated MCP server
sending the RFC 9728 signal (confirms at 95). Every `ScanResult` now carries
`confidence`, `evidence_reason`, and a `checks` dict so the reasoning is
auditable, not just a binary verdict.

---

## 4. Credentialed collectors (2 modules)

These are a structurally different category: they need real, authorized
credentials and answer a different question — not "what's reachable from
outside" but "what does this host actually have installed." Run separately
from the unauthenticated scanners (own CLI, own invocation model); not part
of `run_scan.py`'s registry or `pipeline.py`'s funnel.

| Module | Transport | Commands run (all read-only, fixed allowlist) | Dependency |
|---|---|---|---|
| **`ssh_collector.py`** | SSH (paramiko) | `os-release`, `uname -a`, `hostname`, `uptime`, `dpkg`/`rpm` package list (capped 5000 lines), listening TCP/UDP (`ss`/`netstat`), process names | `paramiko` |
| **`windows_collector.py`** | **WinRM first** (5985/5986, read-only PowerShell), **SMB+RemoteRegistry fallback** (445, via impacket) when WinRM is unreachable/disabled | WinRM: OS build, installed hotfixes/KBs, installed software (both registry hives), services, local admin group membership, SMBv1 registry state, RDP NLA state, Defender status. SMB fallback: OS build + installed software from the registry only (narrower, but works on hardened/legacy hosts with WinRM off). | `pywinrm` and/or `impacket` (either alone enables that one transport) |

Both: credentials passed by the operator (CLI flag or, preferably, an
environment variable — `WIN_SCAN_PASSWORD` for Windows); never logged; no
config changes, no lateral movement, no privilege escalation.

---

## 5. Two orchestration layers (different jobs, both real)

### 5.1 `run_scan.py` — flat batch orchestrator

Runs **any chosen subset** of the 10 registered scanners (`host_discovery,
port_scan, service_banner, tls_scan, udp_scan, smb_scan, snmp_scan, web_scan,
mcp_ai_scan, db_scan`) against **every** target independently, with one
combined JSONL and/or `--split-output DIR` (one `<scanner>.jsonl` file per
scanner). `--mass-scan` runs masscan/fallback first as an additional fast
sweep. This is the right tool for **measuring a single scanner's
accuracy/FP-rate in isolation** — it intentionally does not narrow scope
between scanners. `passive_collector.py` is **not** in its registry.

### 5.2 `pipeline.py` — staged, profile-aware funnel

Built specifically to chain the scanners by use case: discovery → port scan
(live hosts only) → service banner (open ports only) → deep inspection
(tls/web/smb/db, routed only to the ports that match each protocol's typical
port set). Each stage narrows the next, so packet count and noise scale with
what's actually there, not with the size of the target range. Produces a
clean per-host summary by default; full raw JSONL only with `-o`/`--raw`.

**Three environment profiles** — the core design decision of this layer:

| Profile | Mode | Ports | Rate / Concurrency / Timeout | Deep stage | Why |
|---|---|---|---|---|---|
| `it` | active, full | 34-port IT/server set | 200/sec, 100 concurrent, 3.0s (discovery: 1.5s) | tls, web, smb, db | Corporate/server LANs tolerate normal-speed scanning. |
| `iot` | active, **gentle** | 17-port curated embedded set (RTSP, MQTT, CoAP, printer ports, no Windows-domain/DB ports) | 20/sec, 20 concurrent, 5.0s (discovery: 2.0s) | tls, web only | Embedded stacks are fragile; tiny budgets get knocked over by IT-grade speed. No SMB/DB probing of a camera. |
| `ot` | **passive only** | n/a | n/a | n/a | An unsolicited probe to a PLC/RTU/safety controller can disrupt a live physical process. Runs only `passive_collector.py`. |

**The OT gate is structural, not a flag**: `pipeline.py --profile ot
--scanners tls web` exits with an error (code 2) and refuses to run — there is
no override. Verified live: a 10-second passive run on a real home network
correctly identified two real devices (a Xiaomi device via `_mi-connect` mDNS,
a Google Cast device) purely by listening, with `grep` confirming the module
contains **no `sendto`/`send`/`connect`/`write` of any kind** to a target —
only `bind`, `IP_ADD_MEMBERSHIP`, and `recvfrom`.

**Validated discovery-timeout tradeoff** (measured against a real `/24`, not
assumed): a 1.5s discovery timeout cuts total runtime roughly in half versus
reusing the 3s service timeout, while still reliably catching the hosts that
matter; 1.0s was measured to be too aggressive and missed real hosts (likely
wifi power-save devices needing >1s to answer a RST). Override with
`--disc-timeout` for slow/remote targets.

**Known non-determinism, documented not hidden**: repeated discovery runs on
the same real LAN returned different live-host counts (7, then 2, then 5, then
6) across consecutive runs — genuine wifi/LAN churn (phones joining/leaving),
not a bug. Unauthenticated discovery on a wireless segment is inherently
non-deterministic; this is stated plainly rather than smoothed over.

---

## 6. Testing infrastructure

| File | Purpose |
|---|---|
| **`test_all.sh`** | Single-command smoke test. Runs all 10 registered scanners standalone + `nmap_wrapper` (if `nmap` is on PATH) + `mass_scan --fallback` + the `run_scan.py --all --split-output` orchestrator against one target, auto-creating a scope file scoped to just that target if none is given. Prints a pass/fail count and per-scanner row counts. Credentialed collectors are opt-in via `SSH_TEST_USER`/`SSH_TEST_KEY` or `WIN_TEST_USER`/`WIN_SCAN_PASSWORD` env vars — skipped (not failed) otherwise. Verified: 13/13 steps passed cleanly against real local fixtures (HTTP, TLS, fake banner, MySQL). |
| **`MANUAL_TESTING.md`** | 12-step ground-truth verification guide: stand up known local fixtures (HTTP server with a planted `<title>`, a real TLS 1.3 server, a fake banner service), independently snapshot the truth with `curl`/`openssl`/`nc`/`lsof`, then run each scanner and check true-positive / false-positive / fidelity against that snapshot. Includes the documented AirPlay false-positive lesson (Step 8) and a 3-engine cross-validation (pure-Python vs nmap vs masscan, Step 9) and an OT-passive `tcpdump` verification (Step 11). |

---

## 7. Dependencies — verified, not assumed

Confirmed by grepping every import in the codebase: **zero third-party
imports** in the entire pipeline and all 13 network scanners. Pure stdlib
(`asyncio`, `socket`, `ssl`, `struct`, `urllib`, `xml.etree`, `subprocess`,
`ipaddress`, `argparse`, `dataclasses`...).

`pip install -r requirements.txt` is needed **only** for:
- `paramiko>=3.4.0` — `ssh_collector.py`
- `pywinrm>=0.4.3` — `windows_collector.py` WinRM transport
- `impacket>=0.11.0` — `windows_collector.py` SMB/registry fallback transport

Verified: `windows_collector.py` imports cleanly with `pywinrm` absent
(`_HAVE_WINRM=False`, degrades to the SMB path) — the graceful-degradation
guards actually work, not just documented to.

Two scanners shell out to **system binaries** (not pip-installable, OS package
manager only), both optional with documented fallback:
- `nmap_wrapper.py` → `nmap` (no fallback; the module just reports it's
  missing and points at the pure-Python alternatives)
- `mass_scan.py` → `masscan` (falls back to the pure-Python connect sweep
  automatically)

Licensing notes carried in both `requirements.txt` and the source comments:
masscan is AGPL-3.0, nmap is NPSL/GPLv2-derived — fine to invoke an installed
binary, review before bundling either inside a shipped product.

Requires **Python 3.10+** (the codebase uses PEP 604 `X | None` union syntax
throughout).

---

## 8. Known limitations (stated plainly, not fixed yet)

These are real, current gaps — not hidden behind confident language:

- **`mcp_ai_scanner.py`'s evidence-tiered confirmation is per-scanner, not a
  general framework.** The AirPlay false positive is fixed (see §3.1), but the
  confidence-scoring/evidence-chain approach lives only inside that one
  module. There is still no shared `verifier.py` or codebase-wide
  confidence-scoring layer — if other scanners need similar anti-FP treatment,
  it has to be built per-module; don't assume it's generically available.
- **A real TLS false-negative exists, found during manual testing.**
  `tls_scanner.py` got `ConnectionResetError` against a real, confirmed-live
  TLS 1.3 endpoint (Docker Desktop's internal proxy), while the `openssl` CLI
  handshakes successfully against the identical target. Root cause is a
  ClientHello-level difference between Python's bundled OpenSSL and the
  system `openssl` binary — not a logic bug in the scanner's code, but a real
  accuracy gap against at least one real-world TLS implementation. Not yet
  fixed.
- **IPv4 only.** `udp_scanner.py`, `smb_scanner.py`, `snmp_scanner.py`,
  `db_scanner.py` hardcode `socket.AF_INET`. An IPv6 target will fail outright
  on these modules.
- **UDP results are fundamentally ambiguous.** No reply on a UDP port reports
  `status: filtered`, which conflates "actually closed," "actually filtered by
  a firewall," and "service didn't reply to that particular probe shape." This
  is a property of UDP itself (no handshake), not a bug, but it limits how
  much weight a "no reply" result can carry on its own.
- **No CVE correlation / risk scoring exists anywhere in this codebase.**
  Every module is explicit that this is the collection layer only; matching
  observed banners/versions against known vulnerabilities is a deliberately
  separate, not-yet-built layer.
- **`pipeline.py`'s deep-inspection port routing is a fixed table**
  (`TLS_PORTS`, `WEB_PORTS`, `SMB_PORTS`, `DB_PORTS` module-level sets). A
  service running on a genuinely non-standard port (e.g. HTTPS on 9443) won't
  get routed to `TLSScanner`/`WebScanner` unless that port is added to the set.
- **No large-scope time warning.** `expand_targets()` hard-caps at 200,000
  hosts (raises `ValueError` above that), but a 65,000-host `/16` is allowed
  through and would simply take a long time — there's no advance warning
  about expected runtime before the cap is hit.
- **`passive_collector.py` needs the right vantage point to be useful.** It
  only sees multicast/broadcast traffic on its own local segment. Real OT use
  requires connecting the collection host to a SPAN/mirror port or a network
  TAP — on an ordinary switch port it will only hear what's broadcast to it,
  which is a real but narrow slice of a network's actual traffic.

---

## 9. Quick reference — what to run for what

```bash
# Single scanner, manually inspect output
python3 -m scanner.port_scanner -t 10.0.0.5 -s scope.txt -p 1-1024

# Run a chosen subset across one target range, split for FP measurement
python3 run_scan.py -t 10.0.0.0/24 -s scope.txt \
    --scanners host_discovery port_scan service_banner tls_scan web_scan \
    --split-output ./runs/

# Everything, one combined file
python3 run_scan.py -t 10.0.0.0/24 -s scope.txt --all -o results.jsonl

# The staged funnel — clean summary, minimum packets, IT-grade LAN
python3 pipeline.py -t 192.168.1.0/24 -s scope.txt --profile it

# Same funnel, gentle pacing + curated ports for embedded/IoT
python3 pipeline.py -t 192.168.1.0/24 -s scope.txt --profile iot

# OT/ICS — listen only, zero packets sent, ever
python3 pipeline.py -t 192.168.1.0/24 -s scope.txt --profile ot --listen-seconds 120

# Credentialed Linux inventory
python3 -m scanner.ssh_collector -t 10.0.0.5 -s scope.txt --user audit --key ~/.ssh/audit_key

# Credentialed Windows inventory (WinRM, falls back to SMB automatically)
export WIN_SCAN_PASSWORD='...'
python3 -m scanner.windows_collector -t 10.0.0.0/24 -s scope.txt --user audit --domain CORP

# One-command smoke test of everything against a target
./test_all.sh 10.0.0.5 scope.txt

# Manual ground-truth accuracy verification, step by step
# -> see MANUAL_TESTING.md
```
