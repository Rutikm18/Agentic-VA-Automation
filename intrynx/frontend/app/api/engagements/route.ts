/**
 * Engagements — BFF proxy to the FastAPI backend (single source of truth).
 *
 * Replaces the old in-memory `engagementsStore`. The UI shape is unchanged
 * ({ engagements, stats, activity, timeline }); contract translation lives in
 * `lib/adapters.ts`.
 */
import { NextResponse } from "next/server";
import { backend } from "../../../lib/backend";
import { withBackend } from "../../../lib/with-backend";
import { toUiEngagement, toApiEngagementCreate } from "../../../lib/adapters";

export const GET = withBackend(async (_req, { token }) => {
  const list = await backend<{ items: any[] }>("/engagements", {
    token,
    query: { page: 1, page_size: 100 },
  });
  const ids = (list.items ?? []).map((e) => e.id);

  // The list endpoint omits counts; fetch detail (asset_count + finding_summary)
  // for each in parallel so the cards render fully.
  const details = await Promise.all(
    ids.map((id) =>
      backend<any>(`/engagements/${id}`, { token }).catch(() => null),
    ),
  );
  const engagements = details
    .filter(Boolean)
    .map(toUiEngagement);

  const stats = {
    totalFindings: engagements.reduce((s, e) => s + (e.findingCount || 0), 0),
    activeEngagements: engagements.filter((e) => e.status === "ACTIVE").length,
    totalAssets: engagements.reduce((s, e) => s + (e.assetCount || 0), 0),
  };

  // FastAPI has no activity/timeline feed yet — return empty so the UI degrades gracefully.
  return NextResponse.json({ engagements, activity: [], timeline: [], stats });
});

export const POST = withBackend(async (req, { token }) => {
  const body = await req.json();
  if (!body?.name || !(body.scopeCidrs?.length || typeof body.scopeCidrs === "string")) {
    return NextResponse.json({ error: "name and scopeCidrs are required" }, { status: 400 });
  }
  const created = await backend<any>("/engagements", {
    token,
    method: "POST",
    body: toApiEngagementCreate(body),
  });
  return NextResponse.json({ engagement: toUiEngagement({ ...created, finding_summary: {}, asset_count: 0 }) }, { status: 201 });
});
