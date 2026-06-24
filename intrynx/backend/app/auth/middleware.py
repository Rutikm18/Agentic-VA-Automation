import structlog
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from app.auth.jwt import decode_token

logger = structlog.get_logger()

_PUBLIC_PATHS = {"/", "/health", "/auth/login", "/auth/refresh", "/docs", "/openapi.json", "/redoc"}
# Static prefixes served without auth (the dashboard page handles its own login).
_PUBLIC_PREFIXES = ("/docs", "/redoc", "/dashboard")


class TenantIsolationMiddleware(BaseHTTPMiddleware):
    """
    Extracts JWT from Authorization header and injects tenant_id + user
    claims into request.state.  All DB queries downstream use
    request.state.tenant_id to scope results.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        path = request.url.path
        if path in _PUBLIC_PATHS or path.startswith(_PUBLIC_PREFIXES):
            return await call_next(request)

        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return Response(
                content='{"detail":"Missing or invalid Authorization header"}',
                status_code=401,
                media_type="application/json",
            )

        token = auth.removeprefix("Bearer ").strip()
        try:
            payload = decode_token(token)
            if payload.get("type") != "access":
                raise ValueError("not an access token")
        except Exception as exc:
            logger.warning("auth.middleware.rejected", path=path, reason=str(exc))
            return Response(
                content=f'{{"detail":"{exc}"}}',
                status_code=401,
                media_type="application/json",
            )

        request.state.user_id = payload["sub"]
        request.state.tenant_id = payload["tenant_id"]
        request.state.role = payload["role"]

        structlog.contextvars.bind_contextvars(
            tenant_id=payload["tenant_id"],
            user_id=payload["sub"],
        )

        response = await call_next(request)
        structlog.contextvars.clear_contextvars()
        return response
