import { NextRequest, NextResponse } from "next/server";
import { spawn } from "child_process";
import os from "os";
import path from "path";
import fs from "fs";
import { parseNucleiLine, nucleiMatchToFinding, countBySeverity, type NucleiRawLine } from "../../../../lib/nuclei-parser";
import { createFinding } from "../../../../lib/findings-store";

const SAFE_TARGET = /^[a-zA-Z0-9.\-_/:,]+$/;

export async function POST(req: NextRequest) {
  const body = await req.json() as {
    targets: string[];
    templates?: string[];
    tags?: string[];
    severity?: string[];
    rateLimit?: number;
    concurrency?: number;
    retries?: number;
    timeout?: number;
    createFindings?: boolean;
  };

  const {
    targets,
    templates,
    tags = ["cves", "misconfigs", "default-logins", "exposed-panels", "ssl", "network"],
    severity = ["critical", "high", "medium"],
    rateLimit = 50,
    concurrency = 25,
    retries = 1,
    timeout = 5,
    createFindings = false,
  } = body;

  if (!targets || targets.length === 0 || !targets.every((t) => SAFE_TARGET.test(t) && t.length < 300)) {
    return NextResponse.json({ error: "Invalid targets." }, { status: 400 });
  }

  const scanId       = `nuclei-${Date.now()}`;
  const targetsFile  = path.join(os.tmpdir(), `adversa-nuclei-targets-${Date.now()}.txt`);
  const outputFile   = path.join(os.tmpdir(), `adversa-nuclei-out-${Date.now()}.jsonl`);

  fs.writeFileSync(targetsFile, targets.join("\n"));

  const args: string[] = [
    "-l", targetsFile,
    "-severity", severity.join(","),
    "-json-export", outputFile,
    "-rate-limit", String(Math.min(rateLimit, 150)),
    "-c", String(Math.min(concurrency, 50)),
    "-retries", String(retries),
    "-timeout", String(timeout),
    "-silent",
  ];

  if (templates && templates.length > 0) {
    for (const tmpl of templates) {
      args.push("-t", tmpl);
    }
  } else {
    args.push("-tags", tags.join(","));
  }

  const startTime = new Date().toISOString();
  const t0 = Date.now();

  await new Promise<void>((resolve) => {
    const proc = spawn("nuclei", args, { timeout: 600_000 });
    proc.on("error", () => resolve());
    proc.on("close", () => resolve());
  });

  fs.unlink(targetsFile, () => {});

  const matches = [];
  if (fs.existsSync(outputFile)) {
    const lines = fs.readFileSync(outputFile, "utf-8").split("\n").filter(Boolean);
    for (const line of lines) {
      try {
        const m = parseNucleiLine(line);
        if (m) matches.push(m);
      } catch { /* skip malformed lines */ }
    }
    fs.unlinkSync(outputFile);
  }

  const findingsCreated: string[] = [];
  if (createFindings) {
    for (const match of matches.filter((m) => m.severity !== "info")) {
      try {
        const finding = createFinding(nucleiMatchToFinding(match));
        findingsCreated.push(finding.id);
      } catch { /* non-fatal */ }
    }
  }

  return NextResponse.json({
    scanId,
    startTime,
    endTime: new Date().toISOString(),
    elapsed: `${((Date.now() - t0) / 1000).toFixed(1)}s`,
    totalTemplates: matches.length,
    matches,
    findingsCreated,
    stats: countBySeverity(matches),
  });
}
