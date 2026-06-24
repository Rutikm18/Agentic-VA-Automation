import { NextResponse } from "next/server";
import { detectionStore } from "../../../../../../lib/detection-store";

// POST /engagements/{id}/detection-validation/run
export async function POST(
  _req: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  const jobId = detectionStore.runCorrelation(id);
  const run = detectionStore.getRunStatus(jobId);
  return NextResponse.json({ jobId, status: run?.status, completedAt: run?.completedAt }, { status: 202 });
}
