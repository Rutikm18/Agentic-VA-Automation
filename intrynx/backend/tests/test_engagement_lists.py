"""Unit tests for the dashboard list endpoints (jobs + assets)."""
from __future__ import annotations

import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.routers import engagements as eng


def _user():
    return SimpleNamespace(tenant_id=uuid.uuid4(), user_id=uuid.uuid4(), role="admin")


def _scalars(items):
    return MagicMock(scalars=lambda: MagicMock(all=lambda: items))


@pytest.mark.asyncio
async def test_list_jobs_returns_results():
    job = SimpleNamespace(
        id=uuid.uuid4(), job_type=SimpleNamespace(value="discovery"),
        status=SimpleNamespace(value="completed"), agent_id="ag-1",
        result={"host_count": 3}, created_at=None, started_at=None, completed_at=None,
    )
    db = MagicMock()
    db.execute = AsyncMock(side_effect=[
        MagicMock(scalar_one_or_none=lambda: SimpleNamespace(id=uuid.uuid4())),  # _get_or_404
        _scalars([job]),
    ])
    out = await eng.list_engagement_jobs(uuid.uuid4(), db, _user())
    assert out[0]["job_type"] == "discovery"
    assert out[0]["result"] == {"host_count": 3}


@pytest.mark.asyncio
async def test_list_assets_groups_services():
    aid = uuid.uuid4()
    asset = SimpleNamespace(
        id=aid, ip_address="10.0.0.5", hostname="web01", os="Linux",
        asset_type=SimpleNamespace(value="server"), criticality=SimpleNamespace(value="high"),
    )
    svc = SimpleNamespace(asset_id=aid, port=443, protocol="tcp", service_name="https",
                          product="nginx", version="1.25")
    db = MagicMock()
    db.execute = AsyncMock(side_effect=[
        MagicMock(scalar_one_or_none=lambda: SimpleNamespace(id=uuid.uuid4())),  # _get_or_404
        _scalars([asset]),    # assets
        _scalars([svc]),      # services
    ])
    out = await eng.list_engagement_assets(uuid.uuid4(), db, _user())
    assert out[0]["hostname"] == "web01"
    assert out[0]["services"][0]["service"] == "https"
    assert out[0]["services"][0]["port"] == 443
