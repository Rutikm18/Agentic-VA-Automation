/**
 * Attack surface (assets + services) — BFF proxy to FastAPI.
 *   GET → /engagements/{id}/assets   (hosts discovered by probes, with services)
 */
import { NextResponse } from "next/server";
import { backend, bearerFrom, BackendError } from "../../../../../lib/backend";

export async function GET(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const token = bearerFrom(req);
  if (!token) return NextResponse.json({ error: "Not authenticated" }, { status: 401 });
  const { id } = await params;
  try {
    const assets = await backend<unknown[]>(`/engagements/${id}/assets`, { token });
    return NextResponse.json(assets);
  } catch (e) {
    const status = e instanceof BackendError ? e.status : 500;
    return NextResponse.json({ error: (e as Error)?.message ?? "backend error" }, { status });
  }
}
