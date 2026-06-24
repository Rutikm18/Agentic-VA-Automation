"""
Shared database helpers — single source of truth for patterns duplicated across routers.
"""
from __future__ import annotations

import uuid
from typing import TypeVar

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import DeclarativeBase

T = TypeVar("T", bound=DeclarativeBase)


async def get_or_404(
    db: AsyncSession,
    model: type[T],
    id: uuid.UUID,
    tenant_id: uuid.UUID | None = None,
    tenant_field: str = "tenant_id",
) -> T:
    """
    Fetch a row by primary key, optionally scoped to a tenant.
    Raises 404 if missing.

    Usage:
        eng = await get_or_404(db, Engagement, engagement_id, tenant_id)
    """
    q = select(model).where(model.id == id)
    if tenant_id is not None:
        q = q.where(getattr(model, tenant_field) == tenant_id)
    result = await db.execute(q)
    obj = result.scalar_one_or_none()
    if not obj:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"{model.__name__} not found",
        )
    return obj
