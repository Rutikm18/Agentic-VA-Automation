/**
 * Server-side client for the ADVERSA Python backend (FastAPI).
 *
 * This is the integration seam: the Next.js `app/api/*` route handlers act as a
 * BFF (backend-for-frontend) and call FastAPI through this module, forwarding the
 * caller's JWT. The browser never talks to FastAPI directly (no CORS), and the
 * FastAPI JWT is the single source of auth.
 *
 * Configure with BACKEND_INTERNAL_URL (e.g. http://api:8000 inside compose).
 */
const BASE = (process.env.BACKEND_INTERNAL_URL ?? "http://localhost:18080").replace(/\/$/, "");

export class BackendError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

export interface BackendOpts {
  method?: string;
  token?: string | null;
  body?: unknown;
  query?: Record<string, string | number | boolean | undefined>;
}

/** Call a FastAPI endpoint, forwarding the operator's bearer token. */
export async function backend<T = unknown>(path: string, opts: BackendOpts = {}): Promise<T> {
  const url = new URL(BASE + path);
  if (opts.query) {
    for (const [k, v] of Object.entries(opts.query)) {
      if (v !== undefined) url.searchParams.set(k, String(v));
    }
  }
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (opts.token) headers.Authorization = `Bearer ${opts.token}`;

  const res = await fetch(url.toString(), {
    method: opts.method ?? "GET",
    headers,
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
    cache: "no-store",
  });

  const text = await res.text();
  const data = text ? safeJson(text) : null;
  if (!res.ok) {
    const detail = (data && (data.detail ?? data.error)) || res.statusText;
    throw new BackendError(res.status, typeof detail === "string" ? detail : JSON.stringify(detail));
  }
  return data as T;
}

function safeJson(t: string): any {
  try {
    return JSON.parse(t);
  } catch {
    return { raw: t };
  }
}

/** Extract the Bearer token from an incoming request's Authorization header. */
export function bearerFrom(req: Request): string | null {
  const h = req.headers.get("authorization") ?? "";
  return h.startsWith("Bearer ") ? h.slice(7) : null;
}
