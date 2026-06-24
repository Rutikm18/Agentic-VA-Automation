import { NextResponse } from "next/server";
import { clientFromRequest } from "../../../../lib/tenant-server";

// GET /api/portal/context — resolved tenant for this request (portal bootstrap + C2 test).
// Returns only safe client fields (never integration secrets).
export async function GET(request: Request) {
  const client = clientFromRequest(request);
  if (!client) return NextResponse.json({ tenant: null });
  return NextResponse.json({
    tenant: client.subdomain,
    client: {
      id: client.id,
      name: client.name,
      status: client.status,
      branding: client.settings.branding ?? null,
    },
  });
}
