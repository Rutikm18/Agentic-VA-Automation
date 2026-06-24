import { NextRequest, NextResponse } from "next/server";
import { spawn } from "child_process";
import os from "os";
import path from "path";
import fs from "fs";
import { parseTestsslOutput, type TestsslOutput } from "../../../../lib/testssl-parser";
import { createFinding } from "../../../../lib/findings-store";

const SAFE_HOST = /^[a-zA-Z0-9.\-_:]+$/;

export async function POST(req: NextRequest) {
  const body = await req.json() as {
    targets: string[];
    checks?: string[];
    createFindings?: boolean;
  };

  const { targets, createFindings = false } = body;

  if (!targets || targets.length === 0 || !targets.every((t) => SAFE_HOST.test(t) && t.length < 200)) {
    return NextResponse.json({ error: "Invalid targets." }, { status: 400 });
  }

  const allFindings: ReturnType<typeof parseTestsslOutput> = [];
  const findingsCreated: string[] = [];
  const hostResults: Record<string, unknown>[] = [];
  const scanId = `testssl-${Date.now()}`;
  const startTime = new Date().toISOString();
  const t0 = Date.now();

  for (const target of targets) {
    const outputFile = path.join(os.tmpdir(), `adversa-testssl-${Date.now()}-${Math.random().toString(36).slice(2)}.json`);

    await new Promise<void>((resolve) => {
      const args = [
        "--jsonfile", outputFile,
        "--severity", "LOW",
        "--color", "0",
        "--fast",
        "--quiet",
        target,
      ];

      const proc = spawn("testssl.sh", args, { timeout: 300_000 });

      proc.on("error", () => resolve());
      proc.on("close", () => resolve());
    });

    let parsed: TestsslOutput = { findings: [] };
    if (fs.existsSync(outputFile)) {
      try {
        parsed = JSON.parse(fs.readFileSync(outputFile, "utf-8")) as TestsslOutput;
        fs.unlinkSync(outputFile);
      } catch { /* ignore */ }
    }

    const hostFindings = parseTestsslOutput(parsed, target);
    allFindings.push(...hostFindings);
    hostResults.push({ target, findingCount: hostFindings.length });

    if (createFindings) {
      for (const f of hostFindings) {
        try {
          const created = createFinding(f);
          findingsCreated.push(created.id);
        } catch { /* non-fatal */ }
      }
    }
  }

  const elapsed = `${((Date.now() - t0) / 1000).toFixed(1)}s`;

  return NextResponse.json({
    scanId,
    startTime,
    endTime: new Date().toISOString(),
    elapsed,
    targets: hostResults,
    totalFindings: allFindings.length,
    findings: allFindings,
    findingsCreated,
    stats: {
      critical: allFindings.filter((f) => f.severity === "CRITICAL").length,
      high:     allFindings.filter((f) => f.severity === "HIGH").length,
      medium:   allFindings.filter((f) => f.severity === "MEDIUM").length,
      low:      allFindings.filter((f) => f.severity === "LOW").length,
      info:     allFindings.filter((f) => f.severity === "INFO").length,
    },
  });
}
