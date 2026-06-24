/**
 * Tenant resolution (C1): map an incoming request to a client subdomain.
 *
 * Production: <subdomain>.<root> → subdomain (e.g. acme.dash.example.com → "acme").
 * The root domain itself, and the reserved "app"/"www" hosts, resolve to null = internal console.
 *
 * Dev (no wildcard DNS): override via the X-Tenant header, ?tenant= query, or a `tenant` cookie,
 * so localhost:3000?tenant=acme behaves like acme.<root>.
 *
 * This module only extracts the subdomain *string* (pure, edge-safe). Mapping subdomain → Client
 * happens via clients-store in route/middleware code (Node runtime), so this stays import-light.
 */

// Hosts that are the bare app, never a tenant. Configure root via PORTAL_ROOT_DOMAIN.
const RESERVED = new Set(["app", "www", "dashboard", "admin", "api"]);

function rootDomain(): string {
  return (process.env.PORTAL_ROOT_DOMAIN || "").toLowerCase();
}

/** Extract a subdomain label from a Host header, or null for the bare app / localhost. */
export function subdomainFromHost(host: string | null | undefined): string | null {
  if (!host) return null;
  const h = host.split(":")[0].toLowerCase().trim();          // strip port
  if (!h || h === "localhost" || /^\d{1,3}(\.\d{1,3}){3}$/.test(h)) return null;  // localhost / raw IP

  const root = rootDomain();
  let label: string | null = null;
  if (h.endsWith(".localhost")) {
    label = h.split(".")[0];                                   // acme.localhost → acme (dev)
  } else if (root && h.endsWith(`.${root}`)) {
    label = h.slice(0, -(root.length + 1)).split(".")[0];      // first label before the root
  } else {
    const parts = h.split(".");
    if (parts.length >= 3) label = parts[0];                   // foo.example.com → foo (no root configured)
  }
  if (!label || RESERVED.has(label)) return null;
  return label;
}

/**
 * Resolve the tenant subdomain for a request, honoring dev overrides.
 * Pass the values the caller can read (header/cookie/query) — works in both middleware and routes.
 */
export function resolveTenantSubdomain(opts: {
  host?: string | null;
  headerTenant?: string | null;     // X-Tenant
  queryTenant?: string | null;      // ?tenant=
  cookieTenant?: string | null;     // tenant cookie
}): string | null {
  const override = (opts.headerTenant || opts.queryTenant || opts.cookieTenant || "").toLowerCase().trim();
  if (override) return RESERVED.has(override) ? null : override;
  return subdomainFromHost(opts.host);
}

/** Header the middleware injects so server components / route handlers know the tenant. */
export const TENANT_HEADER = "x-tenant-subdomain";
