import { NextResponse } from "next/server";
import { aiReportStore } from "../../../../../../lib/ai-engine";

// POST /engagements/{id}/ai-report/approve  body: { outputId, reviewedBy }
export async function POST(request: Request) {
  const body = await request.json().catch(() => ({}));
  const { outputId, reviewedBy = "manager@adversa.io" } = body;
  if (!outputId) return NextResponse.json({ error: "outputId required" }, { status: 400 });
  const updated = aiReportStore.approve(outputId, reviewedBy);
  if (!updated) return NextResponse.json({ error: "Output not found" }, { status: 404 });
  return NextResponse.json({ output: updated });
}
