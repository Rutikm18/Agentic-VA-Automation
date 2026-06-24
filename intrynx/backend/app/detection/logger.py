"""
AttackLogger — records every attack action to the ``attack_timeline`` table.

All attack modules (discovery, exploit, AD, lateral movement) call this so the
detection correlator has an authoritative, timestamped record of what the red
side actually did and when — the anchor for ±window correlation against blue-team
SIEM/EDR telemetry.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.attack_timeline import AttackTimeline

logger = structlog.get_logger()


class AttackLogger:
    def __init__(self, db: AsyncSession):
        self._db = db

    async def log_action(
        self,
        engagement_id: uuid.UUID | str,
        mitre_technique: str | None,
        target_ip: str | None,
        action: str,
        *,
        finding_id: uuid.UUID | str | None = None,
        target_hostname: str | None = None,
        timestamp: datetime | None = None,
        action_detail: dict[str, Any] | None = None,
        flush: bool = True,
    ) -> AttackTimeline:
        """
        Persist a single attack action. Returns the AttackTimeline row.

        ``timestamp`` defaults to now (UTC). The caller may pass the precise
        moment the action hit the wire for tighter correlation.
        """
        entry = AttackTimeline(
            engagement_id=_as_uuid(engagement_id),
            finding_id=_as_uuid(finding_id) if finding_id else None,
            mitre_technique=mitre_technique,
            target_ip=target_ip,
            target_hostname=target_hostname,
            action=action,
            action_detail=action_detail,
            timestamp=timestamp or datetime.now(timezone.utc),
        )
        self._db.add(entry)
        if flush:
            await self._db.flush()
        logger.info(
            "attack.logged",
            engagement=str(engagement_id),
            technique=mitre_technique,
            target=target_ip,
            action=action,
        )
        return entry


def _as_uuid(value: uuid.UUID | str | None) -> uuid.UUID | None:
    if value is None or isinstance(value, uuid.UUID):
        return value
    return uuid.UUID(str(value))
