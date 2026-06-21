# VA Scanner Module — pure collection layer

A modular network scanner for an **authorized** internal vulnerability-assessment
tool. This is the **scanning / collection layer only**:

- It **observes and records** — open ports, banners, TLS config, SMB dialects,
  SNMP info, web fingerprints, MCP/AI endpoints, credentialed inventory.
- It does **not** correlate, match CVEs, score risk, or decide what's
  "vulnerable" — that is a separate detection layer.
- It performs **no exploitation**: no brute-force, no credential spraying, no
  exploit payloads, no modification of any target.

Every scanner is an **independent file** with one **unified output schema**, so
you can run each in isolation and measure its accuracy and false-positive rate.

---

## Safety model (read this first)

1. **Scope allowlist is mandatory.** Every scanner requires `-s scope.txt`. A
   target not inside the allowlist is refused. Only list assets you are
   explicitly authorized to scan.
2. **Read-only.** No scanner mutates a target. SMB does protocol negotiation
   only; SNMP does GET (read) only; web does a single benign GET; MCP/AI only
   reads discovery endpoints.
3. **Rate-limited.** Global pacing (`--rate`) prevents flooding production.

---

## Layout

```
scanner_module/
  run_scan.py            orchestrator — run any subset in one pass
  scope.example.txt      example allowlist
  requirements.txt
  scanner/
    scanner_base.py      shared: ScopeGuard, RateLimiter, ScanResult, output
    host_discovery.py    liveness via TCP probes (alive-via-RST)
    port_scanner.py      TCP connect scan (open/closed/filtered)
    service_banner.py    banner / version-string grabbing
    tls_scanner.py       TLS versions, ciphers, certificate facts
    udp_scanner.py       DNS/NTP/SNMP/NetBIOS UDP detection
    smb_scanner.py       SMB dialect detection (is SMBv1 enabled?)
    snmp_scanner.py      SNMP read-only enumeration (sysDescr)
    web_scanner.py       passive HTTP(S) fingerprinting
    mcp_ai_scanner.py    MCP / AI inference endpoint discovery
    nmap_wrapper.py      orchestrate nmap, normalize XML to same schema
    ssh_collector.py     credentialed Linux inventory (authorized creds)
```

---

## Install

Core scanners need **nothing** (stdlib only). Optional:

```bash
pip install -r requirements.txt          # paramiko, for ssh_collector
# nmap_wrapper additionally needs the nmap binary: apt install nmap
```

---

## Unified output schema (every scanner)

Each result is one JSON line:

```json
{
  "scanner": "port_scan",
  "target": "10.0.0.5",
  "timestamp": "2026-...Z",
  "port": 445,
  "proto": "tcp",
  "status": "open",          // observed | open | closed | filtered | error
  "data": { ... },           // parsed facts, scanner-specific
  "evidence": "tcp connect succeeded",
  "error": null
}
```

Because the schema is identical across scanners, you can diff any scanner's
output against a ground-truth file and compute precision / recall / FP rate.

---

## Running individual scanners

Each file is runnable as a module. Common flags: `-t` targets, `-s` scope,
`-o` output, `--rate`, `--concurrency`, `--timeout`, `-v`.

```bash
# liveness
python -m scanner.host_discovery -t 10.0.0.0/24 -s scope.txt -o live.jsonl

# TCP ports (default top ports, or -p)
python -m scanner.port_scanner -t 10.0.0.0/24 -s scope.txt -p 1-1024 -o ports.jsonl

# banners on known-open ports
python -m scanner.service_banner -t 10.0.0.5 -s scope.txt -p 22,80,443,3306

# TLS facts
python -m scanner.tls_scanner -t 10.0.0.5 -s scope.txt -p 443,8443

# UDP services
python -m scanner.udp_scanner -t 10.0.0.0/24 -s scope.txt

# SMB dialects (is SMBv1 on?)
python -m scanner.smb_scanner -t 10.0.0.0/24 -s scope.txt

# SNMP read-only enumeration
python -m scanner.snmp_scanner -t 10.0.0.0/24 -s scope.txt

# passive web fingerprint
python -m scanner.web_scanner -t 10.0.0.5 -s scope.txt -p 80,443,8080

# MCP / AI endpoint discovery
python -m scanner.mcp_ai_scanner -t 10.0.0.0/24 -s scope.txt

# nmap orchestration (needs nmap installed)
python -m scanner.nmap_wrapper -t 10.0.0.0/24 -s scope.txt --profile version

# credentialed Linux inventory (needs paramiko + authorized creds)
python -m scanner.ssh_collector -t 10.0.0.5 -s scope.txt --user audit --key ~/.ssh/audit_key
```

---

## Orchestrator

```bash
# run a chosen subset, per-scanner output files for FP measurement
python run_scan.py -t 10.0.0.0/24 -s scope.txt \
   --scanners host_discovery port_scan service_banner tls_scan web_scan \
   --split-output ./runs/

# or everything, combined into one file
python run_scan.py -t 10.0.0.0/24 -s scope.txt --all -o results.jsonl
```

`--split-output DIR` writes `DIR/<scanner>.jsonl` per scanner — the intended way
to measure each scanner's accuracy/FP independently.

---

## Measuring false-positive rate per scanner

1. Build a **ground-truth** file for a known lab range (what is *actually* there).
2. Run a scanner to its own JSONL via `--split-output` or `-o`.
3. Compare: each `status:"open"` / positive observation is a true positive only
   if it matches ground truth; otherwise it's a false positive. Compute:

   ```
   precision = TP / (TP + FP)
   recall    = TP / (TP + FN)
   fp_rate   = FP / (TP + FP)
   ```

Because the modules are independent and emit raw facts (no interpretation),
each scanner's FP behavior is isolated and tunable on its own.

---

## Design notes / extension

- `scanner_base.BaseScanner` is the contract: subclass it, implement
  `scan_target()`, get scope enforcement + rate limiting + concurrency for free.
- Add a new scanner by dropping a file in `scanner/` and registering it in
  `run_scan.py`'s `SCANNERS` map. This is the plugin seam.
- The pure-Python scanners and `nmap_wrapper` emit the same schema on purpose,
  so you can A/B their accuracy (e.g. your `smb_scan` vs nmap's `smb-protocols`).
- `nmap` is GPLv2-derived — review licensing before bundling it in a commercial
  product; here it is invoked, not redistributed.

---

## Credentialed Windows collector (windows_collector.py)

The Windows counterpart to `ssh_collector.py` — closes the biggest enterprise gap,
since most high-impact findings (missing patches/KBs, installed-software versions,
insecure local config) are only visible with authenticated access.

**Access strategy (graceful degradation):**
1. **WinRM (5985/5986)** — primary. Modern, HTTP(S), firewall-friendly. Runs
   read-only PowerShell to enumerate OS build, hotfixes, installed software,
   services, local admins, SMBv1 state, RDP NLA state, and Defender status.
2. **SMB + RemoteRegistry (445)** — fallback when WinRM is disabled (common on
   hardened/legacy hosts). Reads installed-software + OS build from the registry.

If WinRM is unreachable, it automatically falls through to SMB. Collection only:
read-only commands and registry reads — no config changes, no lateral movement.

```bash
pip install pywinrm impacket    # either alone enables that transport

# auto (WinRM then SMB), password via env (preferred over CLI)
export WIN_SCAN_PASSWORD='...'
python -m scanner.windows_collector -t 10.0.0.0/24 -s scope.txt \
    --user audit --domain CORP

# WinRM over HTTPS (keeps creds encrypted), explicit
python -m scanner.windows_collector -t 10.0.0.50 -s scope.txt \
    --user CORP\\audit --password '...' --https --prefer winrm

# force the SMB/registry fallback (for hosts with WinRM disabled)
python -m scanner.windows_collector -t 10.0.0.50 -s scope.txt \
    --user audit --password '...' --prefer smb
```

Credential best practice: pass the password via `WIN_SCAN_PASSWORD` (or a secrets
manager), use a dedicated least-privilege audit account, and prefer `--https`.
Credentials are never logged.

---

## Database service fingerprint (db_scanner.py)

Identifies databases via real protocol handshakes (not banner guessing, since most
DBs speak binary protocols): MySQL/MariaDB, PostgreSQL, MSSQL, Redis, MongoDB,
Oracle. Collection only — reads server greetings / public version pings, never
authenticates or queries data.

```bash
python -m scanner.db_scanner -t 10.0.0.0/24 -s scope.txt                 # standard ports
python -m scanner.db_scanner -t 10.0.0.5 -s scope.txt -p 13306 --try-all # custom port
```

## Mass scan (mass_scan.py)

Fast large-scale port discovery. Wraps `masscan` (install: `apt install masscan`)
and falls back to a pure-Python connect sweep if absent. Front of the two-stage
pattern: mass_scan finds open ports fast -> other scanners deep-inspect only opens.

```bash
# via orchestrator
python run_scan.py -t 10.0.0.0/16 -s scope.txt --mass-scan --mass-ports 1-1000 \
    --scanners service_banner db_scan --split-output ./runs/
# standalone
python -m scanner.mass_scan -t 10.0.0.0/16 -s scope.txt -p 1-1000
```
