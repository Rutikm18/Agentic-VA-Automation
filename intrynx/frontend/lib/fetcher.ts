/**
 * Typed fetch for React Query queryFns.
 *
 * Unlike `fetch().then(r => r.json())`, this *throws* on non-2xx with the HTTP
 * status attached, so the UI can distinguish a normal error from an expired
 * session (401/403). Pair with <DataState/> for consistent edge-state handling.
 */
export class ApiError extends Error {
  status: number;
  detail?: string;
  constructor(message: string, status: number, detail?: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.detail = detail;
  }
}

export async function fetchJson<T = unknown>(url: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(url, init);
  } catch {
    // Network/offline — the manager is unreachable.
    throw new ApiError("Can't reach the server. Check your connection and try again.", 0);
  }
  if (!res.ok) {
    let detail: string | undefined;
    try {
      const body = await res.json();
      detail = body?.detail || body?.error || body?.message;
    } catch {
      /* non-JSON error body */
    }
    const msg =
      res.status === 401 || res.status === 403
        ? "Your session has expired. Please sign in again."
        : detail || `Request failed (${res.status}).`;
    throw new ApiError(msg, res.status, detail);
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

/** True when the error means the user must re-authenticate. */
export function isUnauthorized(error: unknown): boolean {
  return error instanceof ApiError && (error.status === 401 || error.status === 403);
}

/** A safe, human-readable message for any thrown error. */
export function errorMessage(error: unknown): string {
  if (error instanceof ApiError) return error.message;
  if (error instanceof Error) return error.message;
  return "Something went wrong.";
}
