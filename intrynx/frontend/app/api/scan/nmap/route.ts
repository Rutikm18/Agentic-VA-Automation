import { NextRequest, NextResponse } from "next/server";
import { spawn } from "child_process";
import os from "os";
import path from "path";
import fs from "fs";

/* ─── Types ─── */
export interface NseScript {
  id: string;
  output: string;
}

export interface VulnRef {
  id: string;
  state: string;
  description: string;
  refs: string[];
}

export interface ScanPort {
  port: number;
  protocol: string;
  state: string;
  service: string;
  product: string;
  version: string;
  extrainfo: string;
  cpe: string[];
  scripts: NseScript[];
  banner?: string;
  vulnerabilities?: VulnRef[];
}

export interface ScanHost {
  ip: string;
  hostname: string;
  state: string;
  os: string;
  osAccuracy: number;
  ports: ScanPort[];
  openCount: number;
  macAddress?: string;
  macVendor?: string;
}

export interface ScanResult {
  target: string;
  scanType: string;
  command: string;
  startTime: string;
  endTime: string;
  hosts: ScanHost[];
  totalHosts: number;
  upHosts: number;
  elapsed: string;
  rawXml?: string;
}

/* ─── Validation ─── */
const SAFE_TARGET = /^[a-zA-Z0-9.\-_/: ,]+$/;

function validateTarget(target: string): boolean {
  return SAFE_TARGET.test(target) && target.length < 200;
}

const SCAN_PROFILES: Record<string, (ports?: string) => string[]> = {
  quick:    () => ["-sV", "-F", "--version-intensity", "3"],
  service:  () => ["-sV", "-sC", "-p", "21,22,23,25,53,80,110,139,143,443,445,1433,1521,3306,3389,5432,5900,6379,8080,8443,27017"],
  full:     () => ["-sV", "-sC", "-p-"],
  os:       () => ["-sV", "-O", "--osscan-guess"],
  vuln:     () => ["-sV", "--script", "vuln", "-F"],
  stealth:  () => ["-sS", "-T2", "-F"],
  targeted: (ports) => ["-sV", "-sC", "-A", "--version-intensity", "7", "-p", ports ?? "top-1000"],
};

/* NSE vuln script → finding metadata */
const NSE_VULN_MAP: Record<string, { category: string; severity: string }> = {
  "http-shellshock":        { category: "RCE",             severity: "CRITICAL" },
  "ms17-010":               { category: "RCE (EternalBlue)", severity: "CRITICAL" },
  "ssl-heartbleed":         { category: "Cryptographic",   severity: "CRITICAL" },
  "smb-vuln-ms08-067":      { category: "RCE",             severity: "CRITICAL" },
  "http-slowloris-check":   { category: "DoS",              severity: "HIGH" },
  "mysql-empty-password":   { category: "Authentication",  severity: "HIGH" },
  "ftp-anon":               { category: "Authentication",  severity: "MEDIUM" },
  "smtp-open-relay":        { category: "Misconfiguration", severity: "MEDIUM" },
};

/* ─── Parse nmap XML ─── */
export function parseNmapXml(xml: string): ScanHost[] {
  const hosts: ScanHost[] = [];
  const hostMatches = xml.match(/<host[\s\S]*?<\/host>/g) ?? [];

  for (const hostXml of hostMatches) {
    const stateMatch = hostXml.match(/<status state="([^"]+)"/);
    const state = stateMatch?.[1] ?? "unknown";

    const ipMatch    = hostXml.match(/<address addr="([^"]+)" addrtype="ipv4"/);
    const macMatch   = hostXml.match(/<address addr="([^"]+)" addrtype="mac"(?:[^>]*vendor="([^"]*)")?/);
    const hostMatch  = hostXml.match(/<hostname name="([^"]+)"/);
    const osMatch    = hostXml.match(/<osmatch name="([^"]+)"[^>]*accuracy="(\d+)"/);

    const ip        = ipMatch?.[1] ?? "unknown";
    const hostname  = hostMatch?.[1] ?? ip;
    const osName    = osMatch?.[1] ?? "";
    const osAcc     = Number(osMatch?.[2] ?? 0);
    const mac       = macMatch?.[1];
    const macVendor = macMatch?.[2];

    const ports: ScanPort[] = [];
    const portMatches = hostXml.match(/<port[\s\S]*?<\/port>/g) ?? [];

    for (const portXml of portMatches) {
      const portId    = portXml.match(/portid="(\d+)"/)?.[1] ?? "0";
      const proto     = portXml.match(/protocol="([^"]+)"/)?.[1] ?? "tcp";
      const portState = portXml.match(/<state state="([^"]+)"/)?.[1] ?? "unknown";
      const svcName   = portXml.match(/<service name="([^"]+)"/)?.[1] ?? "";
      const product   = portXml.match(/product="([^"]+)"/)?.[1] ?? "";
      const version   = portXml.match(/version="([^"]+)"/)?.[1] ?? "";
      const extra     = portXml.match(/extrainfo="([^"]+)"/)?.[1] ?? "";
      const cpeList   = portXml.match(/<cpe>([^<]+)<\/cpe>/g)?.map((c) => c.replace(/<\/?cpe>/g, "")) ?? [];

      /* NSE scripts */
      const scripts: NseScript[] = [];
      const scriptMatches = portXml.match(/<script[^>]*id="([^"]+)"[^>]*output="([^"]*)"[^/]*/g) ?? [];
      for (const sm of scriptMatches) {
        const sid = sm.match(/id="([^"]+)"/)?.[1] ?? "";
        const sout = sm.match(/output="([^"]*)"/)?.[1] ?? "";
        if (sid) scripts.push({ id: sid, output: sout.replace(/\\n/g, "\n") });
      }

      /* Extract banner from service element */
      const banner = portXml.match(/banner="([^"]+)"/)?.[1];

      /* Parse vuln script results */
      const vulnerabilities: VulnRef[] = [];
      for (const sc of scripts) {
        if (sc.output.includes("VULNERABLE") || sc.output.includes("LIKELY VULNERABLE")) {
          const cveMatch = sc.output.match(/CVE-\d{4}-\d+/g);
          vulnerabilities.push({
            id: cveMatch?.[0] ?? sc.id,
            state: sc.output.includes("LIKELY") ? "LIKELY_VULNERABLE" : "VULNERABLE",
            description: sc.output.slice(0, 300),
            refs: cveMatch ?? [],
          });
        }
      }

      ports.push({
        port: Number(portId), protocol: proto, state: portState,
        service: svcName, product, version, extrainfo: extra, cpe: cpeList,
        scripts, banner, vulnerabilities: vulnerabilities.length ? vulnerabilities : undefined,
      });
    }

    hosts.push({
      ip, hostname, state, os: osName, osAccuracy: osAcc,
      ports, openCount: ports.filter((p) => p.state === "open").length,
      macAddress: mac, macVendor,
    });
  }

  return hosts;
}

/* ─── Auto-create findings from vuln scan ─── */
async function createVulnFindings(hosts: ScanHost[], origin: string): Promise<string[]> {
  const createdIds: string[] = [];
  const baseUrl = process.env.NEXTAUTH_URL ?? `http://localhost:${process.env.PORT ?? 3000}`;

  for (const host of hosts) {
    for (const port of host.ports.filter((p) => p.state === "open")) {
      for (const sc of port.scripts) {
        const meta = NSE_VULN_MAP[sc.id];
        const isVuln = sc.output.includes("VULNERABLE") || sc.output.includes("LIKELY VULNERABLE");
        if (!isVuln && !meta) continue;

        const severity = meta?.severity ?? (sc.output.includes("CRITICAL") ? "CRITICAL" : "HIGH");
        const category = meta?.category ?? "Network Service";

        try {
          const resp = await fetch(`${baseUrl}/api/findings`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              title: `${sc.id.replace(/-/g, " ").toUpperCase()} — ${host.ip}:${port.port}`,
              severity,
              cvss: severity === "CRITICAL" ? "9.8" : severity === "HIGH" ? "7.5" : "5.0",
              cvssVector: "",
              category,
              status: "OPEN",
              affectedHost: host.ip,
              description: sc.output.slice(0, 500),
              technicalDetails: `NSE Script: ${sc.id}\nPort: ${port.port}/${port.protocol}\nService: ${port.service} ${port.product} ${port.version}`,
              attackPath: `External → ${host.ip}:${port.port} → ${sc.id}`,
              evidence: [{ label: "NSE Script Output", content: sc.output }],
              impact: `Vulnerability confirmed on ${host.ip}:${port.port}`,
              remediation: [],
              compliance: [],
              mitre: [],
              source: "nmap",
            }),
          });
          if (resp.ok) {
            const f = await resp.json() as { id: string };
            createdIds.push(f.id);
          }
        } catch { /* non-fatal */ }
      }
    }
  }
  return createdIds;
}

/* ─── Route Handler ─── */
export async function POST(req: NextRequest) {
  const body = await req.json() as {
    target: string;
    scanType?: string;
    ports?: string;
    scripts?: string[];
    createFindings?: boolean;
  };

  const { target, scanType = "quick", ports, scripts, createFindings = false } = body;

  if (!target || !validateTarget(target)) {
    return NextResponse.json({ error: "Invalid target. Use IP, hostname, or CIDR notation." }, { status: 400 });
  }

  const profileFn = SCAN_PROFILES[scanType] ?? SCAN_PROFILES.quick;
  let profileArgs = profileFn(ports);

  /* Inject extra NSE scripts if requested */
  if (scripts && scripts.length > 0) {
    profileArgs = [...profileArgs, "--script", scripts.join(",")];
  }

  const xmlFile = path.join(os.tmpdir(), `adversa-scan-${Date.now()}.xml`);
  const args = [...profileArgs, "-oX", xmlFile, ...target.split(",").map((t) => t.trim())];
  const command = `nmap ${args.join(" ")}`;

  return new Promise<NextResponse>((resolve) => {
    let stdout = "";
    let stderr = "";
    const startTime = new Date().toISOString();
    const t0 = Date.now();

    const proc = spawn("nmap", args, { timeout: 300_000 });

    proc.stdout.on("data", (chunk: Buffer) => { stdout += chunk.toString(); });
    proc.stderr.on("data", (chunk: Buffer) => { stderr += chunk.toString(); });

    proc.on("error", (err) => {
      resolve(NextResponse.json({ error: `nmap not found or failed to start: ${err.message}` }, { status: 503 }));
    });

    proc.on("close", async (code) => {
      const endTime = new Date().toISOString();
      const elapsed = `${((Date.now() - t0) / 1000).toFixed(1)}s`;

      let xml = "";
      try {
        xml = fs.readFileSync(xmlFile, "utf-8");
        fs.unlinkSync(xmlFile);
      } catch { /* file may not exist if nmap errored */ }

      if (code !== 0 && !xml) {
        resolve(NextResponse.json({
          error: `nmap exited with code ${code}. ${stderr.slice(0, 500)}`,
          stdout, stderr,
        }, { status: 400 }));
        return;
      }

      const hosts = parseNmapXml(xml);

      let findingsCreated: string[] = [];
      if (createFindings && (scanType === "vuln" || scanType === "targeted")) {
        findingsCreated = await createVulnFindings(hosts, target);
      }

      const result: ScanResult & { findingsCreated?: string[] } = {
        target, scanType, command, startTime, endTime, elapsed,
        hosts,
        totalHosts: hosts.length,
        upHosts: hosts.filter((h) => h.state === "up").length,
        ...(findingsCreated.length ? { findingsCreated } : {}),
      };

      resolve(NextResponse.json(result));
    });
  });
}
