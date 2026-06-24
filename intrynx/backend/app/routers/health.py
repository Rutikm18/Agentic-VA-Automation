import time

import structlog
from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import get_redis

router = APIRouter(tags=["system"])
logger = structlog.get_logger()


@router.get("/health", summary="Health check — DB + Redis liveness")
async def health(
    db: AsyncSession = Depends(get_db),
    redis=Depends(get_redis),
):
    t0 = time.monotonic()
    checks: dict = {}

    # PostgreSQL
    try:
        await db.execute(text("SELECT 1"))
        checks["postgres"] = "ok"
    except Exception as exc:
        checks["postgres"] = f"error: {exc}"

    # Redis
    try:
        await redis.ping()
        checks["redis"] = "ok"
    except Exception as exc:
        checks["redis"] = f"error: {exc}"

    ok = all(v == "ok" for v in checks.values())
    return {
        "status": "healthy" if ok else "degraded",
        "checks": checks,
        "latency_ms": round((time.monotonic() - t0) * 1000, 2),
    }
