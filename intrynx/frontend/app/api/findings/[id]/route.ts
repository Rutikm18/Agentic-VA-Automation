/**
 * Finding detail + triage — BFF proxy to FastAPI.
 *   GET → /findings/{id}
 *   PUT → PATCH /findings/{id}   (status / notes / remediation)
 *   DELETE → not supported (findings are an immutable assessment record).
 *
 * Native route-handler signature (Next 16 validates dynamic-segment context).
 */
import { NextResponse } from "next/server";
import { backend, bearerFrom, BackendError } from "../../../../lib/backend";
import { toUiFinding, toApiFindingPatch } from "../../../../lib/adapters";

function fail(e: unknown) {
  const status = e instanceof BackendError ? e.status : 500;
  return NextResponse.json({ error: (e as Error)?.message ?? "backend error" }, { status });
}

export async function GET(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const token = bearerFrom(req);
  if (!token) return NextResponse.json({ error: "Not authenticated" }, { status: 401 });
  const { id } = await params;
  try {
    const finding = await backend<any>(`/findings/${id}`, { token });
    return NextResponse.json(toUiFinding(finding));
  } catch (e) {
    return fail(e);
  }
}

export async function PUT(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const token = bearerFrom(req);
  if (!token) return NextResponse.json({ error: "Not authenticated" }, { status: 401 });
  const { id } = await params;
  try {
    const patch = await req.json();
    const updated = await backend<any>(`/findings/${id}`, { token, method: "PATCH", body: toApiFindingPatch(patch) });
    return NextResponse.json(toUiFinding(updated));
  } catch (e) {
    return fail(e);
  }
}

export async function DELETE() {
  return NextResponse.json(
    { error: "Findings are an immutable record of the assessment and cannot be deleted." },
    { status: 405 },
  );
}
