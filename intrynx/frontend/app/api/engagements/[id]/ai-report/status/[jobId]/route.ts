import { NextResponse } from "next/server";
import { aiReportStore } from "../../../../../../../lib/ai-engine";

// GET /engagements/{id}/ai-report/status/{jobId}
export async function GET(
  _req: Request,
  { params }: { params: Promise<{ id: string; jobId: string }> }
) {
  const { jobId } = await params;
  const job = aiReportStore.getJob(jobId);
  if (!job) return NextResponse.json({ error: "Job not found" }, { status: 404 });
  return NextResponse.json({ status: job.status, progress: job.progress, completedSections: job.completedSections, completedAt: job.completedAt });
}
