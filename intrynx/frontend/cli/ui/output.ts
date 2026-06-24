/* Terminal renderer — raw ANSI, zero extra dependencies */
import type { DiscoveredHost, LiveFinding, ScanSummary } from "../../lib/engine/types";

// ── ANSI codes ──────────────────────────────────────────────────
const A = {
  reset:   "\x1b[0m",
  bold:    "\x1b[1m",
  dim:     "\x1b[2m",
  red:     "\x1b[31m",
  green:   "\x1b[32m",
  yellow:  "\x1b[33m",
  blue:    "\x1b[34m",
  magenta: "\x1b[35m",
  cyan:    "\x1b[36m",
  white:   "\x1b[97m",
  gray:    "\x1b[90m",
  bRed:    "\x1b[1;31m",
  bGreen:  "\x1b[1;32m",
  bYellow: "\x1b[1;33m",
  bBlue:   "\x1b[1;34m",
  bCyan:   "\x1b[1;36m",
};

const USE_COLOR = process.stdout.isTTY && process.env.NO_COLOR !== "1";
const c = USE_COLOR
  ? A
  : Object.fromEntries(Object.keys(A).map((k) => [k, ""])) as typeof A;

const w = (s: string) => process.stdout.write(s);
const ln = (s = "") => process.stdout.write(s + "\n");

// ── Severity helpers ────────────────────────────────────────────
const SEV_COLOR: Record<string, string> = {
  CRITICAL: c.bRed,
  HIGH:     c.red,
  MEDIUM:   c.yellow,
  LOW:      c.cyan,
  INFO:     c.gray,
};

const SEV_PAD = 8;

export function sevBadge(sev: string): string {
  const col = SEV_COLOR[sev.toUpperCase()] ?? c.gray;
  return `${col}${c.bold}[${sev.toUpperCase().padEnd(SEV_PAD)}]${c.reset}`;
}

// ── Separator ───────────────────────────────────────────────────
const LINE = "─".repeat(68);
export function rule() { ln(`${c.gray}  ${LINE}${c.reset}`); }

// ── Banner ──────────────────────────────────────────────────────
export function banner(version = "0.2.0") {
  ln();
  ln(`${c.bBlue}   ▄▄▄  ██▄  ▄  ██▄ ▄  ██▄ ██▄  ▄▄   ▄▄${c.reset}`);
  ln(`${c.bBlue}  ▀▀▀█  █ █  █  █   ██ █ █  █ █ █   ▀▀▀█${c.reset}`);
  ln(`${c.bBlue}  ▀▀▀▀  ▀▀▀  ▀  ▀▀▀ ▀  ▀▀▀  ▀▀▀  ▀▀  ▀▀▀▀${c.reset}`);
  ln(`${c.gray}  Network VAPT Platform  ${c.white}v${version}${c.gray}  |  Intrynx${c.reset}`);
  ln();
}

// ── Scan header ─────────────────────────────────────────────────
export function scanHeader(targets: string[], profile: string, stealth: number, tools: string[]) {
  const LABELS: Record<string, string> = {
    naabu: "Port Scanner", nmap: "SVC Probe",
    nuclei: "CVE Engine", testssl: "TLS Analyzer",
  };
  rule();
  ln(`  ${c.gray}Target   ${c.reset}${c.white}${targets.join(", ")}${c.reset}`);
  ln(`  ${c.gray}Profile  ${c.reset}${profile}   ${c.gray}Stealth${c.reset}  ${stealth}/9`);
  ln(`  ${c.gray}Modules  ${c.reset}${tools.map((t) => LABELS[t] ?? t).join("  ·  ")}`);
  ln(`  ${c.gray}Started  ${c.reset}${new Date().toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC")}`);
  rule();
  ln();
}

// ── Stage lines ─────────────────────────────────────────────────
const STAGE_LABEL: Record<string, string> = {
  subfinder:         "Subdomain Enum",
  'dns-recon':       "DNS Recon",
  'host-discovery':  "Host Discovery",
  naabu:             "Port Scanner",
  'udp-scan':        "UDP Scan",
  nmap:              "SVC Probe",
  'os-detect':       "OS Fingerprint",
  'smb-enum':        "SMB Enum",
  'netbios-enum':    "NetBIOS Enum",
  'snmp-enum':       "SNMP Enum",
  'ldap-enum':       "LDAP Enum",
  'rpc-enum':        "RPC Enum",
  'nfs-enum':        "NFS Enum",
  'rdp-fingerprint': "RDP Fingerprint",
  'db-enum':         "DB Service Enum",
  httpx:             "HTTP Probe",
  whatweb:           "Tech Fingerprint",
  ffuf:              "Dir Buster",
  nuclei:            "CVE Engine",
  testssl:           "TLS Analyzer",
  'ssh-audit':       "SSH Audit",
  pipeline:          "Pipeline",
};

const STAGE_COL: Record<string, string> = {
  subfinder:        c.gray,
  'host-discovery': c.blue,
  naabu:            c.bBlue,
  nmap:             c.bCyan,
  httpx:            c.green,
  whatweb:          c.bGreen,
  ffuf:             c.bYellow,
  nuclei:           c.magenta,
  testssl:          c.yellow,
  'ssh-audit':      c.cyan,
};

export function stageStart(stage: string) {
  const label = STAGE_LABEL[stage] ?? stage;
  const col   = STAGE_COL[stage]   ?? c.blue;
  ln(`  ${col}[${label}]${c.reset}  starting…`);
}

export function stageProgress(pct: number, message: string) {
  w(`\r  ${c.gray}  ↳ [${String(pct).padStart(3)}%] ${message.slice(0, 55).padEnd(57)}${c.reset}`);
}

export function stageComplete(stage: string, message: string) {
  ln(); // end the \r line
  const label = STAGE_LABEL[stage] ?? stage;
  const col   = STAGE_COL[stage]   ?? c.blue;
  ln(`  ${col}[${label}]${c.reset}  ${c.bGreen}✓${c.reset}  ${message}`);
}

export function stageError(stage: string, error: string) {
  // Wipe any in-flight \r progress line, then push a blank line so the error
  // can't be overwritten by the next stage's progress write.
  w('\r' + ' '.repeat(78) + '\r');
  const label = STAGE_LABEL[stage] ?? stage;
  const col   = STAGE_COL[stage]   ?? c.blue;
  ln();
  ln(`  ${col}[${label}]${c.reset}  ${c.red}✗${c.reset}  ${error.split('\n')[0]}`);
  // Render the rest of multi-line error on subsequent rows (indented)
  for (const extra of error.split('\n').slice(1)) {
    if (extra.trim()) ln(`           ${extra}`);
  }
  ln();
}

// ── Host discovered ─────────────────────────────────────────────
export function hostLine(host: DiscoveredHost) {
  ln(); // end progress \r line if active

  const ip = `${c.bCyan}${host.ip}${c.reset}`;
  const hn = host.hostnames?.[0] ? `  ${c.gray}(${host.hostnames[0]})${c.reset}` : "";

  // First line: IP + port list, or "(live)" when ports haven't been scanned yet
  if (host.ports.length > 0) {
    const portList = host.ports.slice(0, 12).join(", ") +
      (host.ports.length > 12 ? ` …+${host.ports.length - 12}` : "");
    ln(`  ${c.gray}[HOST]${c.reset}  ${ip}${hn}   ${c.gray}ports:${c.reset} ${c.white}${portList}${c.reset}`);
  } else {
    ln(`  ${c.gray}[HOST]${c.reset}  ${ip}${hn}   ${c.dim}(live)${c.reset}`);
  }

  // Per-service lines — three tiers:
  //   version known  → "22/ssh  dropbear_2020.80"
  //   protocol only  → "22/ssh?  (banner only — no version)"
  //   port open only → "22/tcp  (open)"  — naabu gave us a port but no service info yet
  const sorted = [...host.services].sort((a, b) => a.port - b.port);
  for (const s of sorted) {
    const name = s.name ?? s.proto;
    let tag: string;
    if (s.version) {
      tag = `${c.white}${s.port}/${name}${c.reset}  ${c.gray}${s.version}${c.reset}`;
    } else if (s.name) {
      tag = `${c.white}${s.port}/${name}${c.reset}${c.yellow}?${c.reset}  ${c.gray}(banner only — no version)${c.reset}`;
    } else {
      tag = `${c.white}${s.port}/tcp${c.reset}  ${c.dim}(open)${c.reset}`;
    }
    ln(`          ${tag}`);
  }
}

// ── Finding ─────────────────────────────────────────────────────
export function findingLine(f: LiveFinding) {
  ln();
  const badge = sevBadge(f.severity);
  const host  = f.port ? `${f.host}:${f.port}` : f.host;
  const title = f.title.slice(0, 55);
  const cve   = f.cveIds?.[0] ? `  ${c.gray}${f.cveIds[0]}${c.reset}` : "";
  ln(`  ${badge}  ${c.white}${host.padEnd(22)}${c.reset}  ${title}${cve}`);
}

// ── Summary ─────────────────────────────────────────────────────
export function summary(s: ScanSummary) {
  const dur = s.duration < 60_000
    ? `${(s.duration / 1000).toFixed(1)}s`
    : `${Math.floor(s.duration / 60000)}m ${Math.floor((s.duration % 60000) / 1000)}s`;

  ln();
  rule();
  ln(`  ${c.bGreen}COMPLETE${c.reset}  ${c.white}${s.hostsScanned} host${s.hostsScanned !== 1 ? "s" : ""}${c.reset}` +
     `   ${c.white}${s.totalFindings} finding${s.totalFindings !== 1 ? "s" : ""}${c.reset}` +
     `${s.savedCount > 0 ? `   ${c.green}${s.savedCount} saved${c.reset}` : ""}` +
     `   ${c.gray}${dur}${c.reset}`);
  rule();
  ln();
}

// ── Findings table ───────────────────────────────────────────────
export function findingsTable(findings: LiveFinding[]) {
  if (findings.length === 0) {
    ln(`  ${c.gray}No findings.${c.reset}`);
    return;
  }

  const hdr = [
    "ID".padEnd(16),
    "SEV".padEnd(10),
    "HOST".padEnd(24),
    "FINDING",
  ].join("  ");
  ln(`  ${c.bold}${c.gray}${hdr}${c.reset}`);
  ln(`  ${c.gray}${"─".repeat(16)}  ${"─".repeat(10)}  ${"─".repeat(24)}  ${"─".repeat(38)}${c.reset}`);

  for (const f of findings) {
    const sev   = SEV_COLOR[f.severity] ?? c.gray;
    const id    = f.id.padEnd(16);
    const s     = `${sev}${f.severity.padEnd(10)}${c.reset}`;
    const host  = f.host.slice(0, 24).padEnd(24);
    const title = f.title.slice(0, 38);
    ln(`  ${c.cyan}${id}${c.reset}  ${s}  ${c.gray}${host}${c.reset}  ${title}`);
  }

  ln();
}

// ── Finding detail ───────────────────────────────────────────────
export function findingDetail(f: LiveFinding) {
  rule();
  ln(`  ${c.bold}${SEV_COLOR[f.severity] ?? ""}[${f.severity}]${c.reset}  ${c.bold}${f.title}${c.reset}`);
  ln(`  ${c.gray}ID:${c.reset}       ${f.id}`);
  ln(`  ${c.gray}Host:${c.reset}     ${f.host}${f.port ? `:${f.port}` : ""}`);
  ln(`  ${c.gray}CVSS:${c.reset}     ${f.cvss || "—"}   ${c.gray}Status:${c.reset}  ${f.status}`);
  ln(`  ${c.gray}Source:${c.reset}   ${f.source}${f.cveIds?.length ? `   ${c.gray}CVEs:${c.reset} ${f.cveIds.join(", ")}` : ""}`);
  ln(`  ${c.gray}Found:${c.reset}    ${f.timestamp.replace("T", " ").replace(/\.\d+Z$/, " UTC")}`);
  if (f.slaDeadline) {
    ln(`  ${c.gray}SLA:${c.reset}      ${f.slaDeadline.replace("T", " ").replace(/\.\d+Z$/, " UTC")}`);
  }
  ln();
  if (f.remediation) {
    ln(`  ${c.bold}Remediation${c.reset}`);
    ln(`  ${f.remediation}`);
    ln();
  }
  if (f.evidence?.length) {
    ln(`  ${c.bold}Evidence${c.reset}`);
    for (const ev of f.evidence) {
      ln(`  ${c.gray}[${ev.label}]${c.reset}`);
      for (const line of ev.content.split("\n").slice(0, 15)) {
        ln(`  ${c.gray}  ${line}${c.reset}`);
      }
    }
    ln();
  }
  rule();
}

// ── Error / info ────────────────────────────────────────────────
export function error(msg: string) {
  process.stderr.write(`${c.bRed}[ERR]${c.reset} ${msg}\n`);
}

export function info(msg: string) {
  ln(`  ${c.gray}[INF]${c.reset}  ${msg}`);
}
