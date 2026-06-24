import { NextRequest, NextResponse } from "next/server";
import { spawn } from "child_process";
import os from "os";
import path from "path";
import fs from "fs";
import { createFinding } from "../../../../lib/findings-store";

const SAFE_TARGET = /^[a-zA-Z0-9.\-_/:,]+$/;

interface NxcHost {
  host: string;
  hostname?: string;
  domain?: string;
  os?: string;
  smbv1: boolean;
  signing: boolean;
  shares?: { name: string; access: "READ" | "WRITE" | "NO ACCESS" }[];
  passwordPolicy?: { minLength: number; lockoutThreshold: number; complexityEnabled: boolean };
  nullSession: boolean;
}

function parseNxcOutput(filePath: string): NxcHost[] {
  if (!fs.existsSync(filePath)) return [];
  try {
    const content = fs.readFileSync(filePath, "utf-8").trim();
    if (!content) return [];
    // nxc outputs one JSON object per line or a JSON array
    if (content.startsWith("[")) return JSON.parse(content) as NxcHost[];
    return content.split("\n").filter(Boolean).map((l) => JSON.parse(l) as NxcHost);
  } catch { return []; }
}

async function runNxc(args: string[], outputFile: string): Promise<void> {
  return new Promise((resolve) => {
    const proc = spawn("nxc", args, { timeout: 120_000 });
    proc.on("error", () => resolve());
    proc.on("close", () => resolve());
  });
}

export async function POST(req: NextRequest) {
  const body = await req.json() as {
    targets: string[];
    domain?: string;
    username?: string;
    password?: string;
    checks?: string[];
    createFindings?: boolean;
  };

  const {
    targets,
    domain = "",
    username = "",
    password = "",
    checks = ["smb", "null-session", "shares"],
    createFindings = false,
  } = body;

  if (!targets || targets.length === 0 || !targets.every((t) => SAFE_TARGET.test(t) && t.length < 200)) {
    return NextResponse.json({ error: "Invalid targets." }, { status: 400 });
  }

  const scanId    = `netexec-${Date.now()}`;
  const startTime = new Date().toISOString();
  const t0        = Date.now();
  const allHosts: NxcHost[] = [];
  const allFindings = [];
  const findingsCreated: string[] = [];

  for (const cidr of targets) {
    const baseFile = path.join(os.tmpdir(), `adversa-nxc-base-${Date.now()}.json`);
    const nullFile = path.join(os.tmpdir(), `adversa-nxc-null-${Date.now()}.json`);
    const authFile = path.join(os.tmpdir(), `adversa-nxc-auth-${Date.now()}.json`);

    if (checks.includes("smb")) {
      await runNxc(["smb", cidr, "--json", "-o", baseFile], baseFile);
      const baseHosts = parseNxcOutput(baseFile);
      fs.unlink(baseFile, () => {});

      for (const host of baseHosts) {
        allHosts.push(host);
        if (host.smbv1) {
          allFindings.push({
            title: `SMBv1 Enabled — ${host.host}`,
            severity: "CRITICAL" as const,
            cvss: "9.8",
            cvssVector: "",
            category: "Network Service",
            status: "OPEN" as const,
            affectedHost: host.host,
            description: "SMBv1 is enabled. Vulnerable to EternalBlue (MS17-010) and other SMBv1 exploits.",
            technicalDetails: `Host: ${host.host}\nHostname: ${host.hostname ?? ""}\nOS: ${host.os ?? ""}`,
            attackPath: `External → ${host.host}:445 → SMBv1 Exploit (EternalBlue)`,
            evidence: [{ label: "NetExec Result", content: JSON.stringify(host, null, 2) }],
            impact: "Full remote code execution without authentication on unpatched systems.",
            remediation: [
              { step: 1, title: "Disable SMBv1", command: "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force", description: "Disable SMBv1 protocol immediately.", estimatedHours: 0.5, completed: false },
            ],
            compliance: [],
            mitre: [{ id: "T1210", name: "Exploitation of Remote Services" }],
            source: "netexec" as const,
          });
        }
        if (!host.signing) {
          allFindings.push({
            title: `SMB Signing Disabled — ${host.host}`,
            severity: "HIGH" as const,
            cvss: "7.5",
            cvssVector: "",
            category: "Network Service",
            status: "OPEN" as const,
            affectedHost: host.host,
            description: "SMB signing is not enforced. Vulnerable to NTLM relay attacks.",
            technicalDetails: `Host: ${host.host}\nSigning: false`,
            attackPath: `CORP VLAN → LLMNR/NBNS Poison → NTLMv2 Capture → Relay to ${host.host}`,
            evidence: [{ label: "NetExec Result", content: JSON.stringify(host, null, 2) }],
            impact: "NTLM relay attack possible — lateral movement without cracking credentials.",
            remediation: [
              { step: 1, title: "Enforce SMB signing", command: "Set-SmbServerConfiguration -RequireSecuritySignature $true -Force", description: "Require SMB signing on all hosts.", estimatedHours: 1, completed: false },
            ],
            compliance: [],
            mitre: [{ id: "T1557.001", name: "LLMNR/NBT-NS Poisoning and SMB Relay" }],
            source: "netexec" as const,
          });
        }
      }
    }

    if (checks.includes("null-session")) {
      await runNxc(["smb", cidr, "-u", "", "-p", "", "--shares", "--json", "-o", nullFile], nullFile);
      const nullHosts = parseNxcOutput(nullFile);
      fs.unlink(nullFile, () => {});

      for (const host of nullHosts) {
        if (host.nullSession) {
          const existing = allHosts.find((h) => h.host === host.host);
          if (existing) existing.nullSession = true;
          allFindings.push({
            title: `SMB Null Session Enabled — ${host.host}`,
            severity: "HIGH" as const,
            cvss: "7.5",
            cvssVector: "",
            category: "Authentication",
            status: "OPEN" as const,
            affectedHost: host.host,
            description: "SMB null session is enabled. Unauthenticated enumeration of shares and user information is possible.",
            technicalDetails: `Host: ${host.host}\nNull session authentication succeeded.`,
            attackPath: `External → ${host.host}:445 → Anonymous SMB Authentication`,
            evidence: [{ label: "NetExec Null Session", content: JSON.stringify(host, null, 2) }],
            impact: "Unauthenticated access to SMB shares and user enumeration.",
            remediation: [
              { step: 1, title: "Restrict anonymous SMB access", description: "Set RestrictAnonymous=2 in registry.", estimatedHours: 0.5, completed: false },
            ],
            compliance: [],
            mitre: [{ id: "T1135", name: "Network Share Discovery" }],
            source: "netexec" as const,
          });
        }
      }
    }

    if (checks.includes("shares") && username && password) {
      await runNxc(["smb", cidr, "-u", username, "-p", password, "-d", domain, "--shares", "--pass-pol", "--json", "-o", authFile], authFile);
      fs.unlink(authFile, () => {});
    }
  }

  if (createFindings) {
    for (const f of allFindings) {
      try {
        const created = createFinding(f);
        findingsCreated.push(created.id);
      } catch { /* non-fatal */ }
    }
  }

  return NextResponse.json({
    scanId,
    startTime,
    endTime: new Date().toISOString(),
    elapsed: `${((Date.now() - t0) / 1000).toFixed(1)}s`,
    hosts: allHosts,
    findings: allFindings,
    findingsCreated,
  });
}
