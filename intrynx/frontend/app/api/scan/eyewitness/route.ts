import { NextRequest, NextResponse } from "next/server";
import { spawn } from "child_process";
import os from "os";
import path from "path";
import fs from "fs";
import { createFinding } from "../../../../lib/findings-store";

const SAFE_URL = /^[a-zA-Z0-9.\-_/:]+$/;

export async function POST(req: NextRequest) {
  const body = await req.json() as {
    urls: string[];
    threads?: number;
    timeout?: number;
    createFindings?: boolean;
  };

  const {
    urls,
    threads = parseInt(process.env.EYEWITNESS_THREADS ?? "5"),
    timeout = parseInt(process.env.EYEWITNESS_TIMEOUT ?? "15"),
    createFindings = false,
  } = body;

  if (!urls || urls.length === 0 || !urls.every((u) => SAFE_URL.test(u) && u.length < 500)) {
    return NextResponse.json({ error: "Invalid URLs." }, { status: 400 });
  }

  const scanId     = `eyewitness-${Date.now()}`;
  const urlFile    = path.join(os.tmpdir(), `adversa-ew-urls-${Date.now()}.txt`);
  const outputDir  = process.env.EYEWITNESS_OUTPUT_DIR
    ? path.join(process.env.EYEWITNESS_OUTPUT_DIR, scanId)
    : path.join(os.tmpdir(), `adversa-ew-${scanId}`);

  fs.writeFileSync(urlFile, urls.join("\n"));

  const args = [
    "-f", urlFile,
    "-d", outputDir,
    "--no-prompt",
    "--timeout", String(timeout),
    "--threads", String(threads),
    "--web",
    "--prepend-https",
    "--compress",
  ];

  const startTime = new Date().toISOString();
  const t0 = Date.now();

  await new Promise<void>((resolve) => {
    const proc = spawn("eyewitness", args, { timeout: 600_000 });
    proc.on("error", () => resolve());
    proc.on("close", () => resolve());
  });

  fs.unlink(urlFile, () => {});

  type Category = "login" | "admin" | "default" | "error" | "other";
  const screenshots: { url: string; file: string; category: Category; fileSize: number }[] = [];
  const categories: Record<Category, string[]> = { login: [], admin: [], default: [], error: [], other: [] };

  if (fs.existsSync(outputDir)) {
    const files = fs.readdirSync(outputDir).filter((f) => f.endsWith(".png"));
    for (const file of files) {
      const filePath = path.join(outputDir, file);
      const nameLower = file.toLowerCase();
      const category: Category =
        nameLower.includes("login") || nameLower.includes("signin") ? "login"
        : nameLower.includes("admin") || nameLower.includes("manage") || nameLower.includes("dashboard") ? "admin"
        : nameLower.includes("default") || nameLower.includes("welcome") ? "default"
        : nameLower.includes("error") || nameLower.includes("403") || nameLower.includes("404") ? "error"
        : "other";

      const url = file.replace(/_([\d]+)\.png$/, "").replace(/_/g, "://", ).replace(/__/g, "/");
      screenshots.push({ url, file: filePath, category, fileSize: fs.statSync(filePath).size });
      categories[category].push(url);
    }
  }

  const adminFindings = [];
  const findingsCreated: string[] = [];

  for (const url of [...categories.admin, ...categories.login]) {
    const finding = {
      title: `Exposed Admin/Login Interface — ${url}`,
      severity: "MEDIUM" as const,
      cvss: "5.3",
      cvssVector: "",
      category: "Exposed Panel",
      status: "OPEN" as const,
      affectedHost: url.replace(/https?:\/\//, "").split("/")[0],
      description: `Web interface accessible at ${url}. Verify authentication requirements and restrict access.`,
      technicalDetails: `EyeWitness discovered accessible web interface.\nURL: ${url}\nOutput directory: ${outputDir}`,
      attackPath: `External → ${url} → Unauthenticated Access`,
      evidence: [{ label: "Screenshot", content: `EyeWitness output directory: ${outputDir}` }],
      impact: "Administrative or login interface exposed. Risk of brute force or credential stuffing.",
      remediation: [
        { step: 1, title: "Restrict access by IP", description: "Limit access to admin interfaces to known management IPs.", estimatedHours: 1, completed: false },
        { step: 2, title: "Enforce MFA", description: "Require multi-factor authentication on login pages.", estimatedHours: 2, completed: false },
      ],
      compliance: [],
      mitre: [{ id: "T1133", name: "External Remote Services" }],
      source: "eyewitness" as const,
    };
    adminFindings.push(finding);
    if (createFindings) {
      try {
        const created = createFinding(finding);
        findingsCreated.push(created.id);
      } catch { /* non-fatal */ }
    }
  }

  return NextResponse.json({
    scanId,
    startTime,
    endTime: new Date().toISOString(),
    elapsed: `${((Date.now() - t0) / 1000).toFixed(1)}s`,
    screenshots,
    categories,
    outputDir,
    adminFindings,
    findingsCreated,
    totalScreenshots: screenshots.length,
  });
}
