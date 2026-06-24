/**
 * Findings — BFF proxy to the FastAPI backend (single source of truth).
 * Replaces the in-memory `findings-store`. Returns an array of UI-shaped findings.
 */
import { NextResponse } from "next/server";
import { backend } from "../../../lib/backend";
import { withBackend } from "../../../lib/with-backend";
import { toUiFinding } from "../../../lib/adapters";

export const GET = withBackend(async (req, { token }) => {
  const url = new URL(req.url);
  const engagementId =
    url.searchParams.get("engagement_id") ??
    url.searchParams.get("engagementId") ??
    undefined;
  const severity = url.searchParams.get("severity") ?? undefined;

  const data = await backend<{ items?: any[] } | any[]>("/findings", {
    token,
    query: { engagement_id: engagementId, severity, page: 1, page_size: 200 },
  });
  const items = Array.isArray(data) ? data : data.items ?? [];
  return NextResponse.json(items.map(toUiFinding));
});

// Manual finding creation is done through the scan/import path on the backend.
export async function POST() {
  return NextResponse.json(
    { error: "Create findings via a scan or POST /engagements/{id}/scans/import on the backend." },
    { status: 501 },
  );
}
