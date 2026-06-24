import { NextRequest, NextResponse } from "next/server";
import { startOpenVASScan } from "../../../../lib/openvas-client";
import { createFinding } from "../../../../lib/findings-store";

const SAFE_TARGET = /^[a-zA-Z0-9.\-_/:,]+$/;

export async function POST(req: NextRequest) {
  const body = await req.json() as {
    targets: string[];
    scanConfig?: string;
    gvmHost?: string;
    gvmPort?: number;
    gvmUser?: string;
    createFindings?: boolean;
  };

  const {
    targets,
    scanConfig = "full-fast",
    gvmHost    = process.env.OPENVAS_HOST ?? "openvas",
    gvmPort    = parseInt(process.env.OPENVAS_PORT ?? "9390"),
    gvmUser    = process.env.OPENVAS_USER ?? "admin",
    createFindings = false,
  } = body;

  if (!targets || targets.length === 0 || !targets.every((t) => SAFE_TARGET.test(t) && t.length < 200)) {
    return NextResponse.json({ error: "Invalid targets." }, { status: 400 });
  }

  const gvmPassword = process.env.OPENVAS_PASSWORD ?? "";
  if (!gvmPassword) {
    return NextResponse.json({ error: "OPENVAS_PASSWORD environment variable not set." }, { status: 503 });
  }

  const { taskId } = await startOpenVASScan({
    targets,
    gvmHost,
    gvmPort,
    gvmUser,
    gvmPassword,
    scanConfig,
  });

  return NextResponse.json({
    taskId,
    status: "queued",
    progress: 0,
    message: `OpenVAS scan queued. Poll GET /api/scan/openvas/${taskId} for status.`,
    createFindings,
  });
}
