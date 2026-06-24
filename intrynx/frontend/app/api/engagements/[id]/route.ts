/**
 * Engagement detail — BFF proxy to FastAPI.
 *   GET  → /engagements/{id}        (detail + counts)
 *   PUT  → PATCH /engagements/{id}  (update fields)
 *
 * Native route-handler signature (Next 16 validates dynamic-segment context).
 */
import { NextResponse } from "next/server";
import { backend, bearerFrom, BackendError } from "../../../../lib/backend";
import { toUiEngagement, toApiEngagementPatch } from "../../../../lib/adapters";

function fail(e: unknown) {
  const status = e instanceof BackendError ? e.status : 500;
  return NextResponse.json({ error: (e as Error)?.message ?? "backend error" }, { status });
}

export async function GET(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const token = bearerFrom(req);
  if (!token) return NextResponse.json({ error: "Not authenticated" }, { status: 401 });
  const { id } = await params;
  try {
    const detail = await backend<any>(`/engagements/${id}`, { token });
    return NextResponse.json({ engagement: toUiEngagement(detail), activity: [] });
  } catch (e) {
    return fail(e);
  }
}

export async function PUT(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const token = bearerFrom(req);
  if (!token) return NextResponse.json({ error: "Not authenticated" }, { status: 401 });
  const { id } = await params;
  try {
    const body = await req.json();
    await backend<any>(`/engagements/${id}`, { token, method: "PATCH", body: toApiEngagementPatch(body) });
    const detail = await backend<any>(`/engagements/${id}`, { token });
    return NextResponse.json({ engagement: toUiEngagement(detail) });
  } catch (e) {
    return fail(e);
  }
}
