import { NextRequest } from "next/server";
import {
  createInitialPipelineState,
  computeOverallProgress,
  getPipeline,
  setPipeline,
  pushScanEvent,
  drainScanEvents,
  PROFILE_TOOLS,
  type ScanTool,
  type ScanProfile,
  type PipelineState,
  type StageState,
} from "../../../../lib/scan-pipeline";
import { parseNucleiLine, nucleiMatchToFinding, countBySeverity, type NucleiRawLine } from "../../../../lib/nuclei-parser";
import { parseTestsslOutput, type TestsslOutput } from "../../../../lib/testssl-parser";
import { parseNmapXml } from "../../scan/nmap/route";
import { createFinding } from "../../../../lib/findings-store";
import { spawn } from "child_process";
import { writeFileSync, readFileSync, existsSync, unlinkSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";

const SAFE_TARGET = /^[a-zA-Z0-9.\-_/:,]+$/;

/* Templates pre-fetched in Docker image; writable config dir for nuclei state */
const NUCLEI_TEMPLATES = "/opt/nuclei-templates";
const NUCLEI_HOME      = "/opt";

/* Stealth level (1–9) → naabu rate + nmap timing template */
function stealthToScanParams(level: number): { naabuRate: number; nmapTiming: string } {
  if (level <= 1) return { naabuRate: 50,   nmapTiming: "T1" };
  if (level <= 3) return { naabuRate: 300,  nmapTiming: "T2" };
  if (level <= 5) return { naabuRate: 1000, nmapTiming: "T3" };
  if (level <= 7) return { naabuRate: 3000, nmapTiming: "T4" };
  return              { naabuRate: 5000, nmapTiming: "T5" };
}

/* ── STAGE: naabu — real-time port discovery ─────────────────────── */
async function runNaabuStage(
  scanId: string,
  targets: string[],
  stealthLevel: number,
  update: (s: Partial<StageState>) => void,
): Promise<Record<string, number[]>> {
  update({ status: "running", progress: 5, message: "Starting port discovery…" });

  const { naabuRate } = stealthToScanParams(stealthLevel);
  const targetsFile   = join(tmpdir(), `naabu-targets-${Date.now()}.txt`);
  writeFileSync(targetsFile, targets.join("\n"));

  return new Promise((resolve) => {
    const portMap: Record<string, number[]> = {};
    const WEB_PORTS = new Set([80, 443, 8080, 8443, 8000, 8888, 3000, 5000]);
    let lineBuffer = "";

    const proc = spawn("naabu", [
      "-list", targetsFile,
      "-rate", String(naabuRate),
      "-json",          // JSONL to stdout
      "-silent",        // suppress banner; JSON still flows to stdout
      "-top-ports", "1000",
      "-s", "c",        // connect scan — no CAP_NET_RAW needed
      "-timeout", "5",
    ], { timeout: 300_000 });

    proc.stdout?.on("data", (chunk: Buffer) => {
      lineBuffer += chunk.toString();
      const lines = lineBuffer.split("\n");
      lineBuffer = lines.pop() ?? "";

      for (const raw of lines) {
        if (!raw.trim()) continue;
        try {
          const obj = JSON.parse(raw) as { ip?: string; host?: string; port: number };
          const ip = obj.ip ?? obj.host;
          if (!ip || !obj.port) continue;

          portMap[ip] = [...(portMap[ip] ?? []), obj.port];
          const ports = portMap[ip];

          // Push live host update — the host dot appears instantly in the UI
          pushScanEvent(scanId, {
            type: "host_discovered",
            host: {
              ip,
              ports: ports.length,
              hasWeb: ports.some((p) => WEB_PORTS.has(p)),
              hasAD:  false,
              risk:   "none",
            },
          });

          const total = Object.values(portMap).reduce((s, p) => s + p.length, 0);
          update({ progress: 50, message: `${Object.keys(portMap).length} hosts · ${total} open ports` });
        } catch { /* skip non-JSON lines */ }
      }
    });

    proc.on("error", (e) => {
      update({ status: "error", progress: 0, message: `Port Scanner not found: ${e.message.slice(0, 120)}` });
      try { unlinkSync(targetsFile); } catch { /* ignore */ }
      resolve({});
    });

    proc.on("close", (code) => {
      try { unlinkSync(targetsFile); } catch { /* ignore */ }
      const hostCount = Object.keys(portMap).length;
      const portCount = Object.values(portMap).reduce((s, p) => s + p.length, 0);

      if (code !== 0 && hostCount === 0) {
        update({ status: "error", progress: 0, message: "Port scan failed or no hosts reachable" });
      } else {
        update({ status: "done", progress: 100, message: `${hostCount} hosts · ${portCount} open ports` });
      }
      resolve(portMap);
    });
  });
}

/* ── STAGE: nmap — service fingerprinting ────────────────────────── */
async function runNmapStage(
  scanId: string,
  targets: string[],
  naabuPorts: Record<string, number[]>,
  stealthLevel: number,
  update: (s: Partial<StageState>) => void,
): Promise<unknown[]> {
  update({ status: "running", progress: 10, message: "Fingerprinting services…" });

  const { nmapTiming } = stealthToScanParams(stealthLevel);

  // Use specific IPs naabu discovered; fall back to original targets
  const scanTargets = Object.keys(naabuPorts).length > 0
    ? Object.keys(naabuPorts)
    : targets;

  const allPorts = [...new Set(Object.values(naabuPorts).flat())].sort((a, b) => a - b);
  const portArg  = allPorts.length > 0 ? allPorts.join(",") : "top-1000";
  const xmlFile  = join(tmpdir(), `nmap-out-${Date.now()}.xml`);

  return new Promise((resolve) => {
    // -sT: TCP connect (no raw socket, works as non-root)
    // -sV: version detection  -${nmapTiming}: timing from stealth level
    const proc = spawn("nmap", [
      "-sT", "-sV", `--version-intensity`, "5",
      `-${nmapTiming}`,
      "-p", portArg,
      "-oX", xmlFile,
      ...scanTargets,
    ], { timeout: 600_000 });

    // nmap writes progress to stderr — forward it to the UI log
    proc.stderr?.on("data", (d: Buffer) => {
      const line = d.toString().trim();
      if (line) update({ message: line.slice(0, 80) });
    });

    proc.on("error", (e) => {
      update({ status: "error", progress: 0, message: `Service Probe not found: ${e.message.slice(0, 120)}` });
      resolve([]);
    });

    proc.on("close", (code) => {
      update({ status: "running", progress: 85, message: "Parsing service data…" });

      let hosts: ReturnType<typeof parseNmapXml> = [];
      if (existsSync(xmlFile)) {
        try {
          hosts = parseNmapXml(readFileSync(xmlFile, "utf-8"));
        } catch { /* ignore parse errors */ }
        try { unlinkSync(xmlFile); } catch { /* ignore */ }
      }

      const WEB_PORTS = new Set([80, 443, 8080, 8443, 8000, 8888, 3000, 5000]);
      const AD_PORTS  = new Set([88, 389, 445, 636, 3268, 3269]);

      for (const h of hosts) {
        const open = h.ports.filter((p) => p.state === "open").map((p) => p.port);
        const hasWeb = open.some((p) => WEB_PORTS.has(p));
        const hasAD  = open.some((p) => AD_PORTS.has(p));

        // Update host with richer data from nmap (overrides naabu's coarse entry)
        pushScanEvent(scanId, {
          type: "host_discovered",
          host: {
            ip:       h.ip,
            hostname: h.hostname !== h.ip ? h.hostname : undefined,
            ports:    open.length,
            hasWeb,
            hasAD,
            risk:     hasAD ? "high" : hasWeb ? "medium" : "low",
          },
        });

        // Push NSE vuln findings immediately
        for (const port of h.ports.filter((p) => p.state === "open")) {
          for (const sc of port.scripts ?? []) {
            if (sc.output.includes("VULNERABLE") || sc.output.includes("LIKELY VULNERABLE")) {
              const cveMatch = sc.output.match(/CVE-\d{4}-\d+/);
              pushScanEvent(scanId, {
                type: "finding",
                finding: {
                  id:        `nmap-${Date.now()}-${h.ip}-${port.port}`,
                  title:     `${sc.id.toUpperCase().replace(/-/g, " ")} — ${h.ip}:${port.port}`,
                  severity:  sc.output.includes("LIKELY") ? "HIGH" : "CRITICAL",
                  host:      h.ip,
                  source:    "Service Probe",
                  timestamp: new Date().toISOString(),
                },
              });

              if (cveMatch) {
                try {
                  createFinding({
                    title:          `${sc.id.toUpperCase()} — ${h.ip}:${port.port}`,
                    severity:       "CRITICAL",
                    cvss:           "9.8",
                    cvssVector:     "",
                    category:       "Network Service",
                    status:         "OPEN",
                    affectedHost:   h.ip,
                    description:    sc.output.slice(0, 500),
                    technicalDetails: `Script: ${sc.id}\nPort: ${port.port}/${port.protocol}`,
                    attackPath:     `External → ${h.ip}:${port.port} → ${sc.id}`,
                    evidence:       [{ label: "NSE Output", content: sc.output }],
                    impact:         `Confirmed vulnerability on ${h.ip}`,
                    remediation:    [],
                    compliance:     [],
                    mitre:          [],
                    source:         "nmap",
                  });
                } catch { /* non-fatal */ }
              }
            }
          }
        }
      }

      update({ status: code !== 0 && hosts.length === 0 ? "error" : "done", progress: 100, message: `${hosts.length} hosts fingerprinted` });
      resolve(hosts);
    });
  });
}

/* ── STAGE: nuclei — real-time CVE scanning ──────────────────────── */
async function runNucleiStage(
  scanId: string,
  targets: string[],
  createFindings: boolean,
  update: (s: Partial<StageState>) => void,
): Promise<{ matches: ReturnType<typeof parseNucleiLine>[]; findingIds: string[] }> {
  update({ status: "running", progress: 5, message: "Initialising CVE engine…" });

  const targetsFile = join(tmpdir(), `nuclei-targets-${Date.now()}.txt`);
  writeFileSync(targetsFile, targets.join("\n"));

  const args = [
    "-l", targetsFile,
    "-tags", "cves,misconfigs,default-logins,exposed-panels,ssl,network",
    "-severity", "critical,high,medium",
    "-j",             // JSONL output to stdout (NOT -silent: that would suppress stdout)
    "-no-color",      // clean output for parsing
    "-rate-limit", "50",
    "-c", "25",
    "-retries", "1",
    "-timeout", "5",
    "-duc",           // disable update check on each run
  ];

  if (existsSync(NUCLEI_TEMPLATES)) {
    args.push("-t", NUCLEI_TEMPLATES);
  }

  return new Promise((resolve) => {
    const matches: ReturnType<typeof parseNucleiLine>[] = [];
    const findingIds: string[] = [];
    let lineBuffer = "";

    const proc = spawn("nuclei", args, {
      timeout: 600_000,
      env: { ...process.env, HOME: NUCLEI_HOME },
    });

    proc.stdout?.on("data", (chunk: Buffer) => {
      lineBuffer += chunk.toString();
      const lines = lineBuffer.split("\n");
      lineBuffer = lines.pop() ?? "";

      for (const raw of lines) {
        if (!raw.trim()) continue;
        try {
          const match   = parseNucleiLine(raw);
          if (!match) continue;
          matches.push(match);

          const sev = match.severity.toUpperCase() as "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

          // Live finding — appears in the UI immediately
          pushScanEvent(scanId, {
            type: "finding",
            finding: {
              id:        `nuclei-${Date.now()}-${matches.length}`,
              title:     match.name ?? match.templateId,
              severity:  sev,
              host:      match.ip,
              source:    "CVE Engine",
              timestamp: new Date().toISOString(),
            },
          });

          if (createFindings && match.severity !== "info") {
            try {
              const f = createFinding({ ...nucleiMatchToFinding(match) });
              findingIds.push(f.id);
            } catch { /* non-fatal */ }
          }

          update({
            progress: Math.min(90, 5 + matches.length * 5),
            message:  `${matches.length} match${matches.length !== 1 ? "es" : ""} found…`,
          });
        } catch { /* not a JSON result line — nuclei also prints status lines */ }
      }
    });

    proc.on("error", (e) => {
      update({ status: "error", progress: 0, message: `CVE Engine not found: ${e.message.slice(0, 120)}` });
      try { unlinkSync(targetsFile); } catch { /* ignore */ }
      resolve({ matches, findingIds });
    });

    proc.on("close", (code) => {
      try { unlinkSync(targetsFile); } catch { /* ignore */ }
      const stats = countBySeverity(matches);
      update({
        status:   code === -1 ? "error" : "done",
        progress: 100,
        message:  code === -1
          ? "CVE scan failed"
          : `${matches.length} matches · ${stats.critical} critical · ${stats.high} high`,
      });
      resolve({ matches, findingIds });
    });
  });
}

/* ── STAGE: testssl.sh — TLS analysis ───────────────────────────── */
async function runTestsslStage(
  scanId: string,
  nmapHosts: unknown[],
  createFindings: boolean,
  update: (s: Partial<StageState>) => void,
): Promise<unknown[]> {
  update({ status: "running", progress: 10, message: "Analysing TLS configuration…" });

  const TLS_PORTS = [443, 8443, 4443];
  const tlsTargets = (nmapHosts as Array<{ ip: string; ports: Array<{ port: number; state: string }> }>)
    .filter((h) => h.ports?.some((p) => TLS_PORTS.includes(p.port) && p.state === "open"))
    .map((h) => h.ip);

  if (tlsTargets.length === 0) {
    update({ status: "done", progress: 100, message: "No TLS services found" });
    return [];
  }

  const allFindings: ReturnType<typeof parseTestsslOutput> = [];

  for (const target of tlsTargets.slice(0, 10)) {
    const outFile = join(tmpdir(), `testssl-${Date.now()}.json`);

    const { code } = await new Promise<{ code: number | null }>((res) => {
      const proc = spawn("testssl.sh", [
        "--jsonfile", outFile,
        "--severity", "LOW",
        "--color", "0",
        "--fast",
        "--quiet",
        target,
      ], { timeout: 300_000 });

      proc.on("error",  ()        => res({ code: -1 }));
      proc.on("close",  (c)       => res({ code: c }));
    });

    if (code === -1) {
      update({ status: "error", progress: 0, message: "TLS Analyser not found (optional)" });
      return allFindings;
    }

    if (existsSync(outFile)) {
      try {
        const data     = JSON.parse(readFileSync(outFile, "utf-8")) as TestsslOutput;
        const findings = parseTestsslOutput(data, target);
        allFindings.push(...findings);

        for (const f of findings) {
          pushScanEvent(scanId, {
            type: "finding",
            finding: {
              id:        `testssl-${Date.now()}`,
              title:     f.title,
              severity:  f.severity,
              host:      target,
              source:    "TLS Analyser",
              timestamp: new Date().toISOString(),
            },
          });
        }

        if (createFindings) {
          for (const f of findings) {
            try { createFinding(f as Parameters<typeof createFinding>[0]); } catch { /* non-fatal */ }
          }
        }
        unlinkSync(outFile);
      } catch { /* ignore parse errors for this target */ }
    }
  }

  update({ status: "done", progress: 100, message: `${allFindings.length} TLS issues` });
  return allFindings;
}

/* ── STAGE: eyewitness — web screenshots ────────────────────────── */
async function runEyewitnessStage(
  nmapHosts: unknown[],
  update: (s: Partial<StageState>) => void,
): Promise<unknown[]> {
  update({ status: "running", progress: 10, message: "Capturing web screenshots…" });

  const WEB_PORTS: Record<number, string> = {
    80: "http", 443: "https", 8080: "http", 8443: "https",
    8000: "http", 8888: "http", 3000: "http", 5000: "http",
  };

  const urls = (nmapHosts as Array<{ ip: string; ports: Array<{ port: number; state: string }> }>)
    .flatMap((h) =>
      (h.ports ?? [])
        .filter((p) => p.state === "open" && WEB_PORTS[p.port])
        .map((p) => `${WEB_PORTS[p.port]}://${h.ip}:${p.port}`),
    );

  if (urls.length === 0) {
    update({ status: "done", progress: 100, message: "No web services found" });
    return [];
  }

  const urlFile   = join(tmpdir(), `ew-urls-${Date.now()}.txt`);
  const outputDir = join(tmpdir(), `ew-out-${Date.now()}`);
  writeFileSync(urlFile, urls.join("\n"));

  const { code } = await new Promise<{ code: number | null }>((res) => {
    const proc = spawn("eyewitness", [
      "-f", urlFile, "-d", outputDir,
      "--no-prompt", "--timeout", "15", "--threads", "5", "--web", "--compress",
    ], { timeout: 600_000 });

    proc.on("error",  () => res({ code: -1 }));
    proc.on("close",  (c) => res({ code: c }));
  });

  try { unlinkSync(urlFile); } catch { /* ignore */ }

  if (code === -1) {
    update({ status: "error", progress: 0, message: "Web Capture not installed (optional)" });
    return [];
  }

  update({ status: "done", progress: 100, message: `${urls.length} URLs captured` });
  return urls;
}

/* ── Background pipeline orchestrator ───────────────────────────── */
async function runPipelineBackground(
  state: PipelineState,
  tools: ScanTool[],
  createFindings: boolean,
  stealthLevel: number,
): Promise<void> {
  const { scanId, context } = state;

  function updateStage(tool: ScanTool, partial: Partial<StageState>) {
    const cur = getPipeline(scanId);
    if (!cur) return;
    const next = { ...cur, stages: { ...cur.stages, [tool]: { ...cur.stages[tool], ...partial } } };
    next.overallProgress = computeOverallProgress(next.stages, tools);
    setPipeline(scanId, next);
  }

  function update(partial: Partial<PipelineState>) {
    const cur = getPipeline(scanId);
    if (!cur) return;
    setPipeline(scanId, { ...cur, ...partial });
  }

  update({ status: "running" });
  const allFindingIds: string[] = [];

  try {
    // ── 1. Port discovery
    let naabuPorts: Record<string, number[]> = {};
    if (tools.includes("naabu")) {
      naabuPorts = await runNaabuStage(scanId, context.targets, stealthLevel, (s) => updateStage("naabu", s));
    }

    // ── 2. Service fingerprinting (chains off naabu port list)
    let nmapHosts: unknown[] = [];
    if (tools.includes("nmap")) {
      nmapHosts = await runNmapStage(scanId, context.targets, naabuPorts, stealthLevel, (s) => updateStage("nmap", s));
    }

    // ── 3. CVE scan + TLS in parallel
    const [nucleiResult] = await Promise.all([
      tools.includes("nuclei")
        ? runNucleiStage(scanId, context.targets, createFindings, (s) => updateStage("nuclei", s))
        : Promise.resolve({ matches: [], findingIds: [] as string[] }),
      tools.includes("testssl")
        ? runTestsslStage(scanId, nmapHosts, createFindings, (s) => updateStage("testssl", s))
        : Promise.resolve([]),
    ]);
    allFindingIds.push(...nucleiResult.findingIds);

    // ── 4. Screenshots (optional)
    if (tools.includes("eyewitness")) {
      await runEyewitnessStage(nmapHosts, (s) => updateStage("eyewitness", s));
    }

    // ── 5. AD modules — require out-of-band agent with credentials
    if (tools.includes("netexec")) {
      updateStage("netexec",  { status: "skipped", progress: 100, message: "Requires domain credentials via agent" });
    }
    if (tools.includes("impacket")) {
      updateStage("impacket", { status: "skipped", progress: 100, message: "Requires domain credentials via agent" });
    }
    if (tools.includes("openvas")) {
      updateStage("openvas",  { status: "skipped", progress: 100, message: "Start via /api/scan/openvas (long-running)" });
    }

    update({ status: "complete", completedAt: new Date().toISOString(), totalFindings: allFindingIds.length, findingIds: allFindingIds, overallProgress: 100 });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    update({ status: "error", completedAt: new Date().toISOString() });
    pushScanEvent(scanId, { type: "error", error: msg });
  }
}

/* ── POST /api/scan/pipeline ─────────────────────────────────────── */
export async function POST(req: NextRequest) {
  const body = await req.json() as {
    targets:      string[];
    profile?:     ScanProfile;
    tools?:       ScanTool[];
    credentials?: { domain?: string; username?: string; password?: string; dcIp?: string };
    createFindings?: boolean;
    stealthLevel?:   number;
  };

  const {
    targets,
    profile       = "standard",
    tools         = PROFILE_TOOLS[profile],
    credentials   = {},
    createFindings = false,
    stealthLevel   = 5,
  } = body;

  if (!targets?.length || !targets.every((t) => SAFE_TARGET.test(t) && t.length < 200)) {
    return new Response(
      `data: ${JSON.stringify({ type: "error", error: "Invalid or missing targets." })}\n\n`,
      { headers: { "Content-Type": "text/event-stream" } },
    );
  }

  const scanId = `pipeline-${Date.now()}`;
  const state  = createInitialPipelineState(scanId, targets, profile, credentials, tools);
  setPipeline(scanId, state);

  // Fire and forget — runs concurrently with the SSE polling loop
  runPipelineBackground(state, tools, createFindings, stealthLevel);

  const encoder = new TextEncoder();

  const stream = new ReadableStream({
    async start(controller) {
      const send = (data: unknown) => {
        try { controller.enqueue(encoder.encode(`data: ${JSON.stringify(data)}\n\n`)); }
        catch { /* client disconnected */ }
      };

      send({ type: "pipeline_started", scanId, profile, tools, targets });

      let lastProgress = -1;
      let waited = 0;

      while (waited < 7_200_000) {
        await new Promise((r) => setTimeout(r, 400)); // 400ms poll
        waited += 400;

        const cur = getPipeline(scanId);
        if (!cur) break;

        // Drain live events (findings, hosts) — send immediately
        for (const ev of drainScanEvents(scanId)) send(ev);

        // Progress snapshot — send only when it changed
        if (cur.overallProgress !== lastProgress) {
          lastProgress = cur.overallProgress;
          send({ type: "progress", scanId, overallProgress: cur.overallProgress, stages: cur.stages });
        }

        if (cur.status === "complete" || cur.status === "error") {
          send({ type: "pipeline_complete", scanId, status: cur.status, totalFindings: cur.totalFindings, findingIds: cur.findingIds, stages: cur.stages });
          break;
        }
      }

      controller.close();
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      "Connection":    "keep-alive",
    },
  });
}
