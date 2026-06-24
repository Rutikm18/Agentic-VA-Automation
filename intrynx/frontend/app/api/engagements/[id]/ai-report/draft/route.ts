import { NextResponse } from "next/server";
import { aiReportStore } from "../../../../../../lib/ai-engine";

// GET /engagements/{id}/ai-report/draft
export async function GET(
  _req: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  const drafts = aiReportStore.getDraft(id);
  const all    = aiReportStore.listOutputs(id);
  return NextResponse.json({ drafts, all, total: all.length, pendingReview: drafts.length });
}
