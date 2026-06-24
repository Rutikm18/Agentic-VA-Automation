import { NextResponse } from "next/server";
import { detectionStore } from "../../../../../../lib/detection-store";

// GET /engagements/{id}/detection-validation/coverage
export async function GET(
  _req: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  const coverage = detectionStore.getCoverage(id);
  const results  = detectionStore.getLatestResults(id);

  // ATT&CK coverage matrix breakdown by tactic
  const byTactic: Record<string, { detected: number; prevented: number; missed: number }> = {};
  for (const r of results) {
    if (!byTactic[r.tactic]) byTactic[r.tactic] = { detected: 0, prevented: 0, missed: 0 };
    byTactic[r.tactic][r.outcome]++;
  }

  return NextResponse.json({ coverage, byTactic, results });
}
