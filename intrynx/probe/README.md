# Intrynx Probe

A standalone scanning agent. Deploy it **inside the network you want to assess**
(one probe per client). It dials **out** to the Intrynx manager over HTTPS —
nothing listens inbound — registers itself, then pulls and runs scan jobs and
ships results back.

This folder is self-contained: copy just `probe/` to the target machine.

## Scanning capabilities
Each capability is a self-registering scanner in `scanners/` backed by an Intrynx
**scan engine**. The probe **auto-detects** which engines are available on the host
and advertises them on registration. Pick one per job via `params.scan_type`.

| `scan_type` | Engine | What it gathers |
|---|---|---|
| `host_discovery` | `ix-netscan` | fast liveness sweep — live hosts, MAC + NIC vendor (ARP/ICMP) |
| `discovery` | `ix-netscan` | live hosts, open ports, service + version |
| `port_scan` | `ix-netscan` | open TCP ports (no version) — quick sweep |
| `mass_scan` | `ix-fastsweep` | internet-speed port sweep of large ranges |
| `service_fingerprint` | `ix-netscan` | installed-server inventory — product, version, **CPE**, category |
| `udp_scan` | `ix-netscan` | UDP services — SNMP/DNS/NTP/NetBIOS/SIP/IKE |
| `vuln_scan` | `ix-vulnscan` | CVEs, misconfigs, exposures, default logins (severity-tagged) |
| `tls_scan`  | `ix-tlsscan` | weak/deprecated protocols, weak ciphers, cert issues |
| `web_scan`  | `ix-webscan` | HTTP status, title, web server, detected technologies |
| `smb_enum`  | `ix-smbscan` | SMB signing, SMBv1, null sessions, (with creds) shares |
| `mcp_discovery` | `ix-aiscan` | **MCP servers** — JSON-RPC handshake, enumerates exposed tools/resources |
| `ai_service_discovery` | `ix-aiscan` | **AI/LLM/ML servers** — Ollama, vLLM, Jupyter, Ray, Triton, ComfyUI, … |
| `passive_discovery` | `ix-passivescan` | **OT/ICS-safe** — listens only (mDNS/SSDP/LLMNR/BACnet/EtherNet-IP), sends nothing |
| `db_fingerprint` | `ix-dbscan` | **databases** — MySQL/Postgres/MSSQL/Redis/MongoDB/Oracle via real protocol handshakes |
| `ssh_inventory` | `ix-sshaudit` | **credentialed Linux inventory** — OS, packages, listeners, processes (needs `credentials`) |
| `windows_inventory` | `ix-winaudit` | **credentialed Windows inventory** — OS build, hotfixes, software, services (WinRM, SMB fallback) |

> `ix-aiscan` (`mcp_discovery` / `ai_service_discovery`) is **built in** — it needs
> no external engine and is always available. It reports each open, unauthenticated
> MCP/AI endpoint as a severity-tagged finding (an unauthenticated MCP server
> exposing `exec`/file/SQL tools → `critical`).

> `ix-passivescan` (`passive_discovery`) is the **only** scan_type safe for OT/ICS
> segments (PLCs, RTUs, safety controllers) — every other scan_type is active and
> an unsolicited probe can hang or reboot fragile control hardware. It transmits
> nothing; connect the probe to a SPAN/mirror port or a passive TAP to see real
> traffic on a switched network. `params.listen_seconds` controls the listen
> window (default 60).

> `ix-dbscan` (`db_fingerprint`) speaks each database's own wire protocol
> (never guesses credentials, never queries data) and only raises a finding
> for the one case the handshake genuinely proves: an unauthenticated Redis
> instance answering `INFO` with real server data instead of `-NOAUTH`.
> Other engines (MySQL/MSSQL/Postgres/MongoDB/Oracle) are inventory-only —
> their handshakes don't reveal whether data access requires auth.

> `ix-sshaudit` (`ssh_inventory`) needs **operator-supplied, authorized
> credentials** in `params.credentials` (`{username, password}` or
> `{username, key}`) — never logged, never echoed back in the result. Runs a
> fixed allowlist of read-only commands only (OS/kernel/packages/listening
> ports/process names); never escalates privilege or changes anything.
> Optional dependency: `pip install paramiko` — a probe without it simply
> doesn't advertise this capability.

> `ix-winaudit` (`windows_inventory`) needs the same kind of operator-supplied
> `credentials` (`{username, password, domain?}`). Tries WinRM first
> (`params.prefer`: `auto`/`winrm`/`smb`), falls back to SMB+RemoteRegistry
> when WinRM is unreachable/disabled. Read-only PowerShell / registry reads
> only — never writes config, creates services, or moves laterally. Optional
> deps: `pip install pywinrm impacket` (either alone enables that one
> transport).

All scanners return a normalized result `{scan_type, engine, ok, error, hosts|findings|…}`.
A missing engine → that capability is simply not advertised (the job reports it
cleanly, never crashes the probe). Results, logs, and errors reference only the
branded engine label — the underlying utilities are an internal detail.

### Queue a specific scan (operator side)
```bash
curl -X POST $PLATFORM_URL/agents/jobs -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{
    "engagement_id":"<uuid>", "job_type":"discovery",
    "params":{ "scan_type":"vuln_scan", "targets":["10.0.1.0/24"],
               "tags":["cve","misconfiguration"], "severity":"critical,high" } }'
```
`job_type` is the coarse bucket the manager hands to probes (`discovery`/`lateral`/
`cloud_scan`); `params.scan_type` selects the exact scanner. Omit `scan_type` and it
defaults from `job_type` (discovery→discovery, lateral→smb_enum, cloud_scan→vuln_scan).

```
  client network                          manager (cloud)
 ┌───────────────┐   outbound HTTPS      ┌────────────────────┐
 │ probe (engines)│ ───────────────────▶ │  /agents/* + jobs   │
 └───────────────┘  register/heartbeat   │  detection, AI, ... │
                    poll-jobs / submit    └────────────────────┘
```

## Install
```bash
cp probe.env.example probe.env
$EDITOR probe.env          # PLATFORM_URL + OPERATOR_EMAIL/PASSWORD + PROBE_NETWORK_SEGMENTS

./install.sh               # Docker (bundles all scan engines)
# or
./install.sh --native      # Linux + systemd (installs engines, CAP_NET_RAW)
```
Logs: `docker logs -f intrynx-probe`  ·  `journalctl -u intrynx-probe -f`

## Configure (`probe.env`)
| Var | Meaning |
|---|---|
| `PLATFORM_URL` | manager URL, e.g. `https://intrynx.example.com` (required) |
| `OPERATOR_EMAIL` / `OPERATOR_PASSWORD` | logs in once and self-registers |
| `AGENT_ID` / `AGENT_TOKEN` | alternative: pre-provisioned identity |
| `PROBE_NAME` / `PROBE_LOCATION` | display identity |
| `PROBE_NETWORK_SEGMENTS` | CIDRs this probe can reach |
| `SCAN_DEFAULT_ARGS` | default discovery-engine flags (`-sV -T4 -Pn`) |
| `VERIFY_TLS` | `false` only for self-signed lab managers |

## What it does each cycle
1. **register** (once) → cached identity (state volume), so restarts reuse it.
2. **heartbeat** every 30s.
3. **poll** for `discovery` / `lateral` / `cloud_scan` jobs (server-side jobs stay on the manager).
4. **run the selected engine** against the job's targets → parse hosts / ports / findings.
5. **submit** the result; operators read it in the dashboard.

## Commands (plain English)
```bash
./probe check      # health check: license, host, which scans are ready, manager reachable
./probe hostid     # print this machine's Host ID (give it to your admin to get a license)
./probe setup      # guided first-time setup — writes probe.env
./probe run        # start the probe (default)
```

## Security & licensing (host-locked)
The probe will not run without a valid **deployment license** issued for the
machine it runs on. This makes a copied probe folder useless on any other host.

- The license is **signed with a private key only the vendor holds**; the probe
  embeds only the public key, so it can verify a license but never forge one.
- It is **bound to the machine's Host ID** and has an **expiry date**.
- The cached identity file is **encrypted to the host**, so a lifted state file
  can't be reused elsewhere — the probe just re-registers.

**Issue a license (vendor side):**
```bash
python3 tools/mint_license.py keygen                      # one-time: create the signing key
# ask the operator to run "./probe hostid" on the target machine, then:
python3 tools/mint_license.py mint --customer "ACME Corp" \
    --host <host-id-from-target> --days 365 --name dmz-01  # prints PROBE_LICENSE=...
```
Paste the `PROBE_LICENSE=...` line into the client's `probe.env`. In containers,
set a fixed `PROBE_HOST_ID` and mint against it (the OS machine-id isn't stable
across rebuilds). `keys/` and `license.key` are git-ignored — never ship the
private key.

## Operating notes
- Outbound-only; safe behind NAT/firewall.
- SYN / UDP scans need raw-socket capability (Docker container / systemd `CAP_NET_RAW` provide it).
- **Only scan networks you are authorized to assess.**

Manager-side commands (queueing jobs, reading results) are in `../docs/RUNBOOK.md`.
