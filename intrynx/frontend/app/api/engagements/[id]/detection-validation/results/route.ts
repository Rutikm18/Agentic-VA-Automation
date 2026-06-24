import { NextResponse } from "next/server";
import { detectionStore } from "../../../../../../lib/detection-store";

// GET /engagements/{id}/detection-validation/results
export async function GET(
  _req: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  const results  = detectionStore.getLatestResults(id);
  const timeline = detectionStore.getTimeline(id);
  const siem     = detectionStore.getSiemAlerts();
  const edr      = detectionStore.getEdrDetections();
  return NextResponse.json({ results, timeline, siemAlerts: siem, edrDetections: edr });
}
