import { NextResponse } from "next/server";
import { detectionStore } from "../../../../../../lib/detection-store";

// GET /engagements/{id}/detection-validation/gaps
export async function GET(
  _req: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  const gaps = detectionStore.getGaps(id);
  return NextResponse.json({ gaps, total: gaps.length });
}
