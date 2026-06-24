import { NextRequest, NextResponse } from "next/server";
import { resolveTenantSubdomain, TENANT_HEADER } from "./lib/tenant";

/**
 * Subdomain → tenant routing (C2). Edge-safe: resolves the tenant *subdomain string* only
 * (no clients-store / fs here) and injects it as a request header for Node route handlers and
 * server components to consume. Maps subdomain → Client happens server-side (lib/tenant-server).
 *
 * Dev override: ?tenant=acme (persisted to a cookie), X-Tenant header, or acme.localhost.
 */
export function middleware(req: NextRequest) {
  const url = req.nextUrl;
  const queryTenant = url.searchParams.get("tenant");

  const sub = resolveTenantSubdomain({
    host: req.headers.get("host"),
    headerTenant: req.headers.get("x-tenant"),
    queryTenant,
    cookieTenant: req.cookies.get("tenant")?.value,
  });

  const reqHeaders = new Headers(req.headers);
  if (sub) reqHeaders.set(TENANT_HEADER, sub);
  else reqHeaders.delete(TENANT_HEADER);

  const res = NextResponse.next({ request: { headers: reqHeaders } });
  if (queryTenant) {
    res.cookies.set("tenant", queryTenant.toLowerCase(), { sameSite: "lax", path: "/" });
  }
  return res;
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
