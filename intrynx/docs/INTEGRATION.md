# Frontend ↔ Backend Integration

The `frontend/` (Next.js) and `backend/` (FastAPI) are now **one monorepo**. The
frontend talks to the backend through a **BFF proxy**: its `app/api/*` route
handlers call FastAPI server-side (no CORS), forwarding the operator's JWT.

```
browser ──▶ Next /api/* (BFF) ──server-side──▶ FastAPI ──▶ Postgres
            forwards FastAPI JWT     BACKEND_INTERNAL_URL
```

## The pattern (how every route is migrated)
Old route (in-memory store):
```ts
import { withAuth } from ".../lib/auth-middleware";
import { fooStore } from ".../lib/foo-store";
export const GET = withAuth(async () => NextResponse.json(fooStore.list()));
```
New route (BFF → FastAPI):
```ts
import { backend } from ".../lib/backend";
import { withBackend } from ".../lib/with-backend";
import { toUiFoo } from ".../lib/adapters";
export const GET = withBackend(async (_req, { token }) => {
  const data = await backend("/foo", { token });
  return NextResponse.json((data.items ?? []).map(toUiFoo));
});
```
Three helpers do the work:
- `frontend/lib/backend.ts` — server-side FastAPI client (`backend(path,{token,method,body,query})`).
- `frontend/lib/with-backend.ts` — `withBackend(handler)`: extracts the bearer, lets FastAPI enforce auth/tenant/RBAC.
- `frontend/lib/adapters.ts` — contract translation (snake↔camel, enum maps). Add a `toUi*` / `toApi*` per resource.

## Status

### ✅ Done — frontend `next build` is GREEN with these wired
| Area | Frontend route | → Backend |
|---|---|---|
| Login (email+password) | `app/api/auth/login` | `POST /auth/login`, `PUT`→`/auth/refresh` |
| Current user / auth gate | `app/api/auth/me` | `GET /auth/me` |
| Engagements list + create | `app/api/engagements` | `GET/POST /engagements`, detail fan-out |
| **Engagement detail + update** | `app/api/engagements/[id]` | `GET /engagements/{id}`, `PUT`→`PATCH /engagements/{id}` |
| Findings list | `app/api/findings` | `GET /findings` |
| **Finding detail + triage** | `app/api/findings/[id]` | `GET /findings/{id}`, `PUT`→`PATCH /findings/{id}` |

Backend endpoints added for the integration: `GET /auth/me`, `GET /findings/{id}`,
`PATCH /engagements/{id}`, plus the earlier `GET /agents`,
`GET /engagements/{id}/jobs`, `GET /engagements/{id}/assets`.

> Note: dynamic `[id]` routes use the **native** Next 16 handler signature
> (`export async function GET(req, { params })`) rather than the `withBackend`
> wrapper, because Next 16 type-checks the dynamic-segment context. Flat routes
> use `withBackend`.

### ⏳ Pending (same pattern, not yet migrated)
These still hit in-memory stores and will need converting to `withBackend` /
native + adapters (or a backend endpoint if none exists yet):

| Frontend area | Target backend | Note |
|---|---|---|
| `app/api/agents/*` (enroll/heartbeat/jobs) | `/agents/*` (FastAPI) | **unify the probe protocol** — both sides have a full probe system; pick FastAPI's `register/heartbeat/{id}/jobs/result` and retire the Next one |
| `app/api/scans/*`, `scan/*` | `/engagements/{id}/scans/*` | nuclei/nessus/import |
| `app/api/exploit*`, `exploit-approvals` | `/exploits/*`, `/exploit-approvals/*` | |
| `app/api/ad` | `/engagements/{id}/ad/assess` | |
| `app/api/ai-report`, `brain` | `/engagements/{id}/ai-report/*` | |
| attack-graph page | `/engagements/{id}/attack-graph` | |
| detection | `/engagements/{id}/detection-validation/*` | |

### 🚫 Frontend features with **no backend equivalent yet**
The Next app has modules the FastAPI backend doesn't implement. Each needs a
backend module (model + router) before it can be wired — until then, leave them
on their stores or stub them:
`cases`, `segmentation`, `clients`, `portal`, `kafka`, `mitre` browser, `aibrain`.

> **Login UI:** the page still uses the old OTP/magic-link flow. Point it at the
> new `POST /api/auth/login` with `{ email, password }`, store the returned
> `token`, and send it as `Authorization: Bearer` on every `/api/*` call. The
> built-in console at the backend's `/dashboard` already does exactly this and is
> a working reference.

## Run it
```bash
make full          # API + probe + Next.js dashboard (first Next build is slow)
# dashboard:  http://localhost:3000   (login: SEED_ADMIN_EMAIL / SEED_ADMIN_PASSWORD)
# api:        http://localhost:18080
```
`BACKEND_INTERNAL_URL=http://api:8000` wires the BFF to the API over the compose
network. For local frontend dev outside Docker: `cd frontend && BACKEND_INTERNAL_URL=http://localhost:18080 npm run dev`.

## Notes / caveats
- This is a **large** integration (the Next app had ~18 self-contained API route groups backed by in-memory stores). Phase 1 establishes the seam + auth + the engagements/findings read path. The rest follows the checklist above, one route at a time.
- During cutover, pages whose routes aren't migrated yet will error against the FastAPI token (expected) — migrate them with the pattern above.
- The frontend runs **Next.js 16**; follow `frontend/AGENTS.md` (read `node_modules/next/dist/docs/`) and mirror the repo's existing route conventions.
