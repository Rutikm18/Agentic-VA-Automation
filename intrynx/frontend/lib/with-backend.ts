/**
 * Wrapper for BFF route handlers that proxy to the FastAPI backend.
 *
 * Replaces the old `withAuth` (which verified a local OTP JWT + checked an
 * in-memory allowlist) for any route that now delegates to FastAPI. It just
 * extracts the bearer token and hands it to the handler — FastAPI itself
 * enforces auth, tenant isolation, and RBAC, so there's no second auth system.
 */
import { NextRequest, NextResponse } from "next/server";
import { bearerFrom, BackendError } from "./backend";

export interface BackendCtx {
  token: string;
}

type Handler<P = Record<string, string>> = (
  req: NextRequest,
  ctx: BackendCtx,
  params?: P,
) => Promise<NextResponse> | NextResponse;

export function withBackend<P = Record<string, string>>(
  handler: Handler<P>,
): (req: NextRequest, extra?: { params?: Promise<P> }) => Promise<NextResponse> {
  return async (req, extra) => {
    const token = bearerFrom(req);
    if (!token) {
      return NextResponse.json({ error: "Not authenticated" }, { status: 401 });
    }
    try {
      const params = extra?.params ? await extra.params : undefined;
      return await handler(req, { token }, params as P);
    } catch (e) {
      if (e instanceof BackendError) {
        return NextResponse.json({ error: e.message }, { status: e.status });
      }
      return NextResponse.json({ error: (e as Error)?.message ?? "backend error" }, { status: 500 });
    }
  };
}
