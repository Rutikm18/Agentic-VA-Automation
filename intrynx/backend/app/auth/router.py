import uuid

import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.jwt import create_access_token, create_refresh_token, decode_token
from app.database import get_db
from app.dependencies import AuthUser
from app.models.user import User
from app.schemas.auth import LoginRequest, TokenResponse

router = APIRouter(prefix="/auth", tags=["auth"])
logger = structlog.get_logger()
_pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")


@router.get("/me", summary="Current user from the access token (for the dashboard)")
async def me(current_user: AuthUser, db: AsyncSession = Depends(get_db)):
    user = (await db.execute(select(User).where(User.id == current_user.user_id))).scalar_one_or_none()
    return {
        "user_id": str(current_user.user_id),
        "tenant_id": str(current_user.tenant_id),
        "role": current_user.role,
        "email": user.email if user else None,
    }


@router.post("/login", response_model=TokenResponse, summary="Obtain JWT access + refresh tokens")
async def login(body: LoginRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.email == body.email))
    user = result.scalar_one_or_none()

    if not user or not _pwd.verify(body.password, user.hashed_password):
        logger.warning("auth.login.failed", email=body.email)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    access = create_access_token(
        subject=str(user.id),
        tenant_id=str(user.tenant_id),
        role=user.role.value,
    )
    refresh, _ = create_refresh_token(
        subject=str(user.id),
        tenant_id=str(user.tenant_id),
    )
    logger.info("auth.login.success", user_id=str(user.id))
    return TokenResponse(access_token=access, refresh_token=refresh)


@router.post("/refresh", response_model=TokenResponse, summary="Rotate access token using refresh token")
async def refresh(refresh_token: str, db: AsyncSession = Depends(get_db)):
    payload = decode_token(refresh_token)
    if payload.get("type") != "refresh":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not a refresh token")

    user_id = uuid.UUID(payload["sub"])
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    access = create_access_token(
        subject=str(user.id),
        tenant_id=str(user.tenant_id),
        role=user.role.value,
    )
    new_refresh, _ = create_refresh_token(
        subject=str(user.id),
        tenant_id=str(user.tenant_id),
    )
    return TokenResponse(access_token=access, refresh_token=new_refresh)
