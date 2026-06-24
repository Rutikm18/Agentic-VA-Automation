"""
Background tasks triggered after a vuln scan completes.

Pipeline:
  1. Load all new findings for the engagement
  2. Deduplicate by (asset_id, primary_cve_id, plugin_id)
  3. Run VulnEnrichmentService on each unique finding
  4. Persist enriched data back to PostgreSQL
  5. Fire webhook if any critical findings found
"""
from __future__ import annotations

import asyncio
import json
import uuid
from decimal import Decimal
from typing import Any

import httpx
import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import AsyncSessionLocal
from app.models.asset import Asset
from app.models.engagement import Engagement
from app.models.enums import FindingSeverity, FindingStatus
from app.models.finding import Finding
from app.utils.hash import dedup_hash
from app.vuln.enrichment import VulnEnrichmentService

logger = structlog.get_logger()


# ── Entry point ────────────────────────────────────────────────────────────────

async def run_post_scan_enrichment(engagement_id: str, scan_job_id: str) -> None:
    """
    Triggered by the vuln scan API after a scan completes.
    Safe to run as a FastAPI BackgroundTask or asyncio.create_task().
    """
    log = logger.bind(engagement=engagement_id, scan_job=scan_job_id)
    log.info("enrichment.task.start")

    async with AsyncSessionLocal() as db:
        eng_uuid = uuid.UUID(engagement_id)

        # Load un-enriched open findings for this engagement
        result = await db.execute(
            select(Finding).where(
                Finding.engagement_id == eng_uuid,
                Finding.status == FindingStatus.open,
                Finding.epss_score.is_(None),          # not yet enriched
            )
        )
        findings: list[Finding] = list(result.scalars().all())
        log.info("enrichment.task.findings_loaded", count=len(findings))

        if not findings:
            return

        # Load asset criticality lookup
        asset_ids = {f.asset_id for f in findings if f.asset_id}
        assets_result = await db.execute(select(Asset).where(Asset.id.in_(asset_ids)))
        asset_crit_map: dict[uuid.UUID, str] = {
            a.id: a.criticality.value for a in assets_result.scalars().all()
        }

        # Dedup tracking (within this batch)
        seen_hashes: set[str] = set()

        enricher = VulnEnrichmentService()
        critical_titles: list[str] = []
        enriched_count = 0
        skipped_count = 0

        for finding in findings:
            primary_cve = (finding.cve_ids or [None])[0]
            plugin_id = (finding.evidence or {}).get("plugin_id") if finding.evidence else None
            dedup = dedup_hash(str(finding.asset_id), primary_cve, plugin_id)

            if dedup in seen_hashes:
                skipped_count += 1
                continue
            seen_hashes.add(dedup)

            if not primary_cve:
                continue  # no CVE to enrich against

            try:
                crit = asset_crit_map.get(finding.asset_id, "medium")
                finding_dict = {
                    "cve_ids":          finding.cve_ids,
                    "cvss_score":       finding.cvss_score,
                    "cvss_vector":      finding.cvss_vector,
                    "epss_score":       finding.epss_score,
                    "description":      finding.description,
                    "mitre_techniques": finding.mitre_techniques,
                    "exploit_validated":finding.exploit_validated,
                    "evidence":         finding.evidence or {},
                }

                enriched = await enricher.enrich(finding_dict, asset_criticality=crit)

                # Write enriched fields back
                finding.epss_score       = enriched.get("epss_score")
                finding.risk_score       = enriched.get("risk_score")
                finding.mitre_techniques = enriched.get("mitre_techniques")
                finding.evidence         = enriched.get("evidence")
                if enriched.get("cvss_score") and not finding.cvss_score:
                    finding.cvss_score   = enriched["cvss_score"]
                if enriched.get("description") and not finding.description:
                    finding.description  = enriched["description"]

                enriched_count += 1

                if finding.severity == FindingSeverity.critical:
                    critical_titles.append(finding.title)

            except Exception as exc:
                log.warning("enrichment.finding.failed", finding_id=str(finding.id), error=str(exc))

        await db.commit()
        log.info(
            "enrichment.task.done",
            enriched=enriched_count,
            skipped=skipped_count,
            critical=len(critical_titles),
        )

        # Fire webhook for critical findings
        if critical_titles:
            await _fire_critical_webhook(engagement_id, critical_titles, db)


# ── Webhook ────────────────────────────────────────────────────────────────────

async def _fire_critical_webhook(
    engagement_id: str,
    critical_titles: list[str],
    db: AsyncSession,
) -> None:
    eng = (
        await db.execute(select(Engagement).where(Engagement.id == uuid.UUID(engagement_id)))
    ).scalar_one_or_none()

    if not eng:
        return

    roe = eng.rules_of_engagement or {}
    webhook_url: str | None = roe.get("critical_webhook_url")
    if not webhook_url:
        logger.debug("enrichment.webhook.skip", reason="no webhook URL in RoE")
        return

    payload = {
        "event": "critical_findings_found",
        "engagement_id": engagement_id,
        "count": len(critical_titles),
        "findings": critical_titles[:10],
    }
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(webhook_url, json=payload)
            logger.info("enrichment.webhook.sent", status=resp.status_code, url=webhook_url)
    except Exception as exc:
        logger.warning("enrichment.webhook.failed", error=str(exc))


def _dedup_hash(asset_id: str | None, cve_id: str | None, plugin_id: Any) -> str:
    """Deprecated — use app.utils.hash.dedup_hash instead."""
    return dedup_hash(asset_id, cve_id, plugin_id)
