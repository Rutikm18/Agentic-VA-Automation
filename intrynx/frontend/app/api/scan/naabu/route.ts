import { NextRequest, NextResponse } from "next/server";
import { spawn } from "child_process";
import os from "os";
import path from "path";
import fs from "fs";

const SAFE_TARGET = /^[a-zA-Z0-9.\-_/: ,]+$/;

function validateTargets(targets: string[]): boolean {
  return targets.length > 0 && targets.every((t) => SAFE_TARGET.test(t) && t.length < 200);
}

function parseNaabuOutput(outputFile: string): { ip: string; openPorts: number[]; portCount: number }[] {
  if (!fs.existsSync(outputFile)) return [];

  const hostMap = new Map<string, number[]>();
  const lines = fs.readFileSync(outputFile, "utf-8").split("\n").filter(Boolean);

  for (const line of lines) {
    try {
      const obj = JSON.parse(line) as { ip: string; port: number; protocol?: string };
      if (!obj.ip || !obj.port) continue;
      const ports = hostMap.get(obj.ip) ?? [];
      if (!ports.includes(obj.port)) ports.push(obj.port);
      hostMap.set(obj.ip, ports);
    } catch {
      // Skip non-JSON lines
    }
  }

  return Array.from(hostMap.entries()).map(([ip, ports]) => ({
    ip,
    openPorts: ports.sort((a, b) => a - b),
    portCount: ports.length,
  }));
}

export async function POST(req: NextRequest) {
  const body = await req.json() as {
    targets: string[];
    ports?: string;
    rate?: number;
    excludePorts?: string;
    timeout?: number;
  };

  const { targets, ports = "top-1000", rate = 1000, excludePorts, timeout = 5000 } = body;

  if (!targets || !validateTargets(targets)) {
    return NextResponse.json({ error: "Invalid targets. Provide valid IPs, CIDRs, or hostnames." }, { status: 400 });
  }

  const safeRate = Math.min(Math.max(rate, 100), 5000);

  const targetsFile = path.join(os.tmpdir(), `adversa-naabu-targets-${Date.now()}.txt`);
  const outputFile  = path.join(os.tmpdir(), `adversa-naabu-out-${Date.now()}.json`);

  fs.writeFileSync(targetsFile, targets.join("\n"));

  const portSpec = ports === "top-1000" ? "top-1000"
    : ports === "top-100" ? "top-100"
    : ports;

  const args: string[] = [
    "-list", targetsFile,
    "-rate", String(safeRate),
    "-json",
    "-o", outputFile,
    "-silent",
    "-timeout", String(timeout),
  ];

  if (portSpec === "1-65535") {
    args.push("-p", "1-65535");
  } else if (portSpec.startsWith("top-")) {
    args.push("-top-ports", portSpec.replace("top-", ""));
  } else {
    args.push("-p", portSpec);
  }

  if (excludePorts) {
    args.push("-exclude-ports", excludePorts);
  }

  const command = `naabu ${args.join(" ")}`;

  return new Promise<NextResponse>((resolve) => {
    const startTime = new Date().toISOString();
    const t0 = Date.now();

    const proc = spawn("naabu", args, { timeout: 300_000 });

    proc.on("error", (err) => {
      fs.unlink(targetsFile, () => {});
      resolve(NextResponse.json({ error: `naabu not found or failed to start: ${err.message}` }, { status: 503 }));
    });

    proc.on("close", (code) => {
      const endTime = new Date().toISOString();
      const elapsed = `${((Date.now() - t0) / 1000).toFixed(1)}s`;

      fs.unlink(targetsFile, () => {});

      const hosts = parseNaabuOutput(outputFile);
      try { fs.unlinkSync(outputFile); } catch { /* ignore */ }

      if (code !== 0 && hosts.length === 0) {
        resolve(NextResponse.json({ error: `naabu exited with code ${code}` }, { status: 400 }));
        return;
      }

      resolve(NextResponse.json({
        scanId: `naabu-${Date.now()}`,
        startTime,
        endTime,
        elapsed,
        hosts,
        totalHosts: hosts.length,
        totalOpenPorts: hosts.reduce((sum, h) => sum + h.portCount, 0),
        command,
      }));
    });
  });
}
