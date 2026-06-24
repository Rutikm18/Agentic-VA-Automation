import { NextResponse } from "next/server";
import { aiReportStore } from "../../../../../../lib/ai-engine";

// POST /engagements/{id}/ai-report/reject  body: { outputId, reviewedBy, feedback }
export async function POST(request: Request) {
  const body = await request.json().catch(() => ({}));
  const { outputId, reviewedBy = "manager@adversa.io", feedback } = body;
  if (!outputId || !feedback?.trim()) {
    return NextResponse.json({ error: "outputId and feedback are required" }, { status: 400 });
  }
  const updated = aiReportStore.reject(outputId, reviewedBy, feedback.trim());
  if (!updated) return NextResponse.json({ error: "Output not found" }, { status: 404 });
  return NextResponse.json({ output: updated });
}
