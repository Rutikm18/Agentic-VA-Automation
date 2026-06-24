import { NextResponse }              from "next/server";
import { withAuth }                  from "../../../../../lib/auth-middleware";
import { engagementsStore }          from "../../../../../lib/engagements-store";
import { getFindingsByEngagement }   from "../../../../../lib/findings-store";
import { generateReport }            from "../../../../../lib/ai-engine";

// POST /api/engagements/[id]/ai-report — generate AI pentest report for engagement
export const POST = withAuth<{ id: string }>(async (_req, _ctx, params) => {
  const id = params?.id;
  if (!id) {
    return NextResponse.json({ error: "Engagement id required" }, { status: 400 });
  }

  const engagement = engagementsStore.get(id);
  if (!engagement) {
    return NextResponse.json({ error: "Engagement not found" }, { status: 404 });
  }

  const findings = getFindingsByEngagement(id);

  const session = {
    clientName:     engagement.client,
    scope:          engagement.scopeCidrs ?? [],
    findings,
    exploitResults: [],
    engagementType: "Black-box network VAPT",
  };

  try {
    const report = await generateReport(session);
    engagementsStore.update(id, { aiReport: report } as never);
    return NextResponse.json(report);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return NextResponse.json({ error: msg }, { status: 500 });
  }
});
