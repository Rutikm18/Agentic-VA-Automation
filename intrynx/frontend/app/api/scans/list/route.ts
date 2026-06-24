import { NextRequest, NextResponse } from "next/server";
import { withAuth }                  from "../../../../lib/auth-middleware";
import { getAllJobs }                from "../../../../lib/job-store";
import { isAdmin }                  from "../../../../lib/permissions-store";

// GET /api/scans/list  →  returns scan jobs visible to the caller
export const GET = withAuth((req: NextRequest, ctx) => {
  const all = getAllJobs();
  const jobs = isAdmin(ctx.email)
    ? all
    : all.filter((j) => (j.payload as Record<string, unknown>).operatorEmail === ctx.email);

  return NextResponse.json(
    jobs
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
      .slice(0, 50)
      .map((j) => ({
        scanId:    (j.payload as Record<string, unknown>).scanId,
        jobId:     j.id,
        status:    j.status,
        targets:   (j.payload as Record<string, unknown>).targets,
        profile:   (j.payload as Record<string, unknown>).profile,
        createdAt: j.createdAt,
        operator:  (j.payload as Record<string, unknown>).operatorEmail,
      })),
  );
});
