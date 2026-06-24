import { NextRequest, NextResponse } from "next/server";
import { getPipeline } from "../../../../../lib/scan-pipeline";

export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ scanId: string }> },
) {
  const { scanId } = await params;
  const state = getPipeline(scanId);

  if (!state) {
    return NextResponse.json({ error: "Pipeline scan not found." }, { status: 404 });
  }

  return NextResponse.json(state);
}
