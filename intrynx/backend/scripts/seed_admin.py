"""
Idempotent admin seeder.

Creates a tenant + admin user so you can log in (there is no public signup
endpoint). Safe to run repeatedly — it no-ops if the user already exists.

Driven by environment variables (set in compose / .env):
  SEED_ADMIN_EMAIL     — if empty, seeding is skipped entirely
  SEED_ADMIN_PASSWORD  — default "ChangeMe123!"
  SEED_TENANT_NAME     — default "Default Tenant"

Run:  python scripts/seed_admin.py
"""
from __future__ import annotations

import asyncio
import os
import sys

# Make the repo root importable whether this is run as `python scripts/seed_admin.py`
# (Python puts scripts/ on the path) or `python -m scripts.seed_admin`.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from passlib.context import CryptContext
from sqlalchemy import select

from app.database import AsyncSessionLocal
from app.models.enums import UserRole
from app.models.tenant import Tenant
from app.models.user import User

_pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")


async def seed() -> None:
    email = os.getenv("SEED_ADMIN_EMAIL", "").strip()
    if not email:
        print("[seed] SEED_ADMIN_EMAIL not set — skipping admin seed.")
        return

    password = os.getenv("SEED_ADMIN_PASSWORD", "ChangeMe123!")
    tenant_name = os.getenv("SEED_TENANT_NAME", "Default Tenant")

    async with AsyncSessionLocal() as db:
        existing = (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()
        if existing:
            print(f"[seed] user {email} already exists (id={existing.id}) — nothing to do.")
            return

        tenant = (await db.execute(select(Tenant).where(Tenant.name == tenant_name))).scalar_one_or_none()
        if tenant is None:
            tenant = Tenant(name=tenant_name)
            db.add(tenant)
            await db.flush()

        db.add(User(
            tenant_id=tenant.id,
            email=email,
            hashed_password=_pwd.hash(password),
            role=UserRole.admin,
        ))
        await db.commit()
        print(f"[seed] created tenant '{tenant_name}' ({tenant.id}) and admin {email}.")


if __name__ == "__main__":
    asyncio.run(seed())
