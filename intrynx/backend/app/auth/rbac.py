from typing import Annotated

from fastapi import Depends, HTTPException, status

from app.dependencies import get_current_user
from app.schemas.auth import CurrentUser


def require_role(allowed_roles: list[str]):
    """
    FastAPI dependency that enforces role-based access.

    Usage:
        @router.post("/")
        async def create(..., _: Annotated[CurrentUser, require_role(["admin","manager"])]):
    """
    async def _check(
        current_user: Annotated[CurrentUser, Depends(get_current_user)],
    ) -> CurrentUser:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{current_user.role}' is not permitted. Required: {allowed_roles}",
            )
        return current_user

    return Depends(_check)
