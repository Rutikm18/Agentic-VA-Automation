import { NextRequest, NextResponse }  from "next/server";
import { getJobByScanId }            from "../../../../../lib/job-store";
import { getAllFindings }             from "../../../../../lib/findings-store";
import { verifyToken }               from "../../../../../lib/auth-store";
import type { Severity }             from "../../../../../lib/engine/types";

// GET /api/scans/[scanId]/status
export async function GET(
  _request: NextRequest,
  { params }: { params: Promise<{ scanId: string }> },
) {
  const auth  = _request.headers.get('authorization') ?? '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token || !verifyToken(token)) {
    return NextResponse.json({ error: 'Not authenticated' }, { status: 401 });
  }

  const { scanId } = await params;

  const job = getJobByScanId(scanId);
  if (!job) {
    return NextResponse.json({ error: "Scan not found" }, { status: 404 });
  }

  // Findings are stored with engagementId = engagementId ?? scanId (see scanner.ts)
  const engId    = (job.payload as Record<string, unknown>).engagementId as string | undefined;
  const findings = getAllFindings().filter(
    (f) => f.engagementId === scanId || (engId && f.engagementId === engId),
  );
  const bySeverity: Record<Severity, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  for (const f of findings) bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;

  return NextResponse.json({
    scanId,
    status:       job.status,
    findingCount: findings.length,
    bySeverity,
    agentId:      job.agentId,
    startedAt:    job.dispatchedAt,
  });
}
