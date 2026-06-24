import "server-only";
import { headers } from "next/headers";
import { getClientBySubdomain, type Client } from "./clients-store";
import { TENANT_HEADER } from "./tenant";

/**
 * Server-side tenant access (C2). Reads the subdomain the middleware injected and maps it to a
 * Client via clients-store (Node runtime only). Two entry points: from a route handler's Request,
 * or from a server component via next/headers.
 */

export function readTenantSubdomain(req: Request): string | null {
  return req.headers.get(TENANT_HEADER);
}

export function clientFromRequest(req: Request): Client | null {
  const sub = readTenantSubdomain(req);
  return sub ? getClientBySubdomain(sub) ?? null : null;
}

export async function tenantSubdomain(): Promise<string | null> {
  const h = await headers();
  return h.get(TENANT_HEADER);
}

export async function currentClient(): Promise<Client | null> {
  const sub = await tenantSubdomain();
  return sub ? getClientBySubdomain(sub) ?? null : null;
}
