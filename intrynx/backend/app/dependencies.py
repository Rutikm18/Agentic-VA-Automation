import uuid
from typing import Annotated

import redis.asyncio as aioredis
import structlog
from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import get_db
from app.schemas.auth import CurrentUser

logger = structlog.get_logger()
settings = get_settings()

_redis_pool: aioredis.Redis | None = None


async def get_redis() -> aioredis.Redis:
    global _redis_pool
    if _redis_pool is None:
        _redis_pool = aioredis.from_url(settings.redis_url, decode_responses=True)
    return _redis_pool


async def close_redis() -> None:
    """Close the global Redis connection pool. Call during app shutdown."""
    global _redis_pool
    if _redis_pool is not None:
        await _redis_pool.close()
        _redis_pool = None
        logger.info("redis.pool.closed")


def get_current_user(request: Request) -> CurrentUser:
    """
    Reads user claims injected by TenantIsolationMiddleware.
    Raises 401 if middleware did not run (shouldn't happen for protected routes).
    """
    user_id = getattr(request.state, "user_id", None)
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )
    return CurrentUser(
        user_id=uuid.UUID(request.state.user_id),
        tenant_id=uuid.UUID(request.state.tenant_id),
        role=request.state.role,
    )


# Convenience type aliases used in route signatures
DB = Annotated[AsyncSession, Depends(get_db)]
RedisConn = Annotated[aioredis.Redis, Depends(get_redis)]
AuthUser = Annotated[CurrentUser, Depends(get_current_user)]
