/**
 * Current user — proxies to the FastAPI backend's /auth/me, validating the
 * forwarded token. The UI shell calls this to decide "am I logged in" and to
 * show the operator's identity/role.
 */
import { NextResponse } from "next/server";
import { backend } from "../../../../lib/backend";
import { withBackend } from "../../../../lib/with-backend";

export const GET = withBackend(async (_req, { token }) => {
  const me = await backend<{ email: string; role: string; tenant_id: string }>("/auth/me", { token });
  return NextResponse.json({
    email: me.email,
    role: me.role,
    tenantId: me.tenant_id,
    allowedScopes: [],
  });
});
