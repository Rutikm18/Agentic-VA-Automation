"""
Convert a probe's self-assessed `findings` into persisted Finding rows.

WHY THIS EXISTS: submit_job_result() in routers/agents.py already promotes a
probe's discovered hosts/services into Asset/Service rows via
_promote_assets(), but nothing converted the probe's own severity-tagged
`findings` (tls_scan/smb_enum/mcp_discovery/ai_service_discovery already embed
these directly in their result envelope — see probe/scanners/{tls,smb,mcp_ai}.py)
into dashboard-visible Finding rows. They were silently dropped on arrival,
even though the scanners themselves already computed them. This is the
missing translation step — not a new detection engine, just a bridge.

Deliberately excludes vuln_scan: that scan_type is never agent-dispatched in
practice (see AGENT_EXECUTABLE_TYPES in routers/agents.py) and its nuclei
findings use a different shape (template_id/matched_at/cves) handled by the
existing nessus/nuclei -> run_post_scan_enrichment path instead.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.asset import Asset
from app.models.enums import AssetType, FindingSeverity, FindingStatus
from app.models.finding import Finding

logger = structlog.get_logger()

# Only these scan_types embed pre-assessed `findings` in their result envelope
# today. The rest (host_discovery, discovery, port_scan, mass_scan,
# service_fingerprint, udp_scan, web_scan) are pure inventory — nothing for
# this translator to do until/unless they grow their own findings list too.
FINDING_PRODUCING_SCAN_TYPES = {"tls_scan", "smb_enum", "mcp_discovery", "ai_service_discovery"}

# A Finding the operator already resolved (remediated/fp) is NOT deduped if the
# same issue reappears on a later scan — that is a real regression signal, not
# noise, and should surface as a fresh finding. Only still-relevant statuses
# suppress a duplicate.
_DEDUP_SUPPRESSING_STATUSES = (FindingStatus.open, FindingStatus.confirmed, FindingStatus.accepted)


def _map_severity(raw: str | None) -> FindingSeverity:
    try:
        return FindingSeverity((raw or "info").lower())
    except ValueError:
        return FindingSeverity.info


async def _resolve_asset(db: AsyncSession, engagement_id: uuid.UUID, target: str | None) -> Asset | None:
    """Find the Asset for a probe-reported target IP, creating a minimal one if needed.

    A probe's tls_scan/smb_enum/etc. can run standalone (no prior discovery job
    promoted this host yet), so the asset may not exist — create a bare-bones
    row rather than dropping the finding for lack of somewhere to attach it.
    """
    if not target:
        return None
    host = target.split(":", 1)[0] if target.count(":") == 1 else target
    existing = (await db.execute(
        select(Asset).where(Asset.engagement_id == engagement_id, Asset.ip_address == host)
    )).scalar_one_or_none()
    if existing:
        return existing
    asset = Asset(engagement_id=engagement_id, ip_address=host,
                  asset_type=AssetType.server, last_seen=datetime.now(timezone.utc))
    db.add(asset)
    await db.flush()
    return asset


async def _find_open_duplicate(
    db: AsyncSession, engagement_id: uuid.UUID, asset_id: uuid.UUID | None, title: str,
) -> Finding | None:
    """A still-relevant Finding with the same (engagement, asset, title), if any.

    Re-running the same probe scan weekly must not pile up duplicate rows for
    an unchanged issue — but a finding the operator already remediated/marked
    fp is intentionally NOT matched here (see _DEDUP_SUPPRESSING_STATUSES):
    if it reappears on a later scan that's a regression worth a fresh row,
    not noise to suppress.
    """
    q = select(Finding).where(
        Finding.engagement_id == engagement_id,
        Finding.title == title,
        Finding.status.in_(_DEDUP_SUPPRESSING_STATUSES),
    )
    q = q.where(Finding.asset_id == asset_id) if asset_id else q.where(Finding.asset_id.is_(None))
    return (await db.execute(q.limit(1))).scalar_one_or_none()


async def create_findings_from_probe_result(
    db: AsyncSession, engagement_id: uuid.UUID, result: dict,
) -> int:
    """Convert a probe's self-assessed `findings` list into persisted Finding rows.

    Best-effort per finding: one bad/malformed entry must never abort the rest
    or fail the probe's result submission (mirrors _promote_assets' philosophy
    in routers/agents.py). Returns the number of NEW Finding rows created
    (re-touching an existing open duplicate does not count).
    """
    scan_type = result.get("scan_type")
    if scan_type not in FINDING_PRODUCING_SCAN_TYPES:
        return 0
    raw_findings = result.get("findings") or []
    if not raw_findings:
        return 0

    created = 0
    for f in raw_findings:
        if not isinstance(f, dict):
            continue
        try:
            asset = await _resolve_asset(db, engagement_id, f.get("target"))
            title = (f.get("title") or f"{scan_type} finding")[:500]
            asset_id = asset.id if asset else None

            dup = await _find_open_duplicate(db, engagement_id, asset_id, title)
            if dup is not None:
                # Still relevant and still present — touch evidence (bumps
                # updated_at) rather than creating a literal duplicate row.
                dup.evidence = {**f, "scan_type": scan_type, "engine": result.get("engine")}
                continue

            db.add(Finding(
                engagement_id=engagement_id,
                asset_id=asset_id,
                title=title,
                description=f.get("detail"),
                severity=_map_severity(f.get("severity")),
                status=FindingStatus.open,
                evidence={**f, "scan_type": scan_type, "engine": result.get("engine")},
            ))
            created += 1
        except Exception as exc:  # noqa: BLE001 — one bad finding must not sink the batch
            logger.warning("probe_finding.create_failed", scan_type=scan_type, error=str(exc))

    if created or raw_findings:
        await db.flush()
    return created
