"""
DiscoveryWorker — full async pipeline:
  Redis queue → nmap subprocess → banner grab → PostgreSQL
"""
from __future__ import annotations

import asyncio
import json
import os
import subprocess
import tempfile
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import structlog
from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import AsyncSessionLocal
from app.discovery.rate_limiter import RateLimiter
from app.discovery.service_id import ServiceIdentifier
from app.discovery.xml_parser import NmapXMLParser, ParsedHost, ParsedPort
from app.models.asset import Asset
from app.models.enums import AssetType, ScanJobStatus
from app.models.scan_job import ScanJob
from app.models.service import Service

logger = structlog.get_logger()

SCAN_PROFILES: dict[str, list[str]] = {
    "fast":     ["-sn", "-T4", "--max-retries", "1"],
    "standard": ["-sV", "-sC", "-T3", "--top-ports", "1000"],
    "deep":     ["-sV", "-sC", "-A", "-T3", "-p-", "--osscan-guess"],
}

BANNER_TIMEOUT = 3.0  # seconds per banner grab
BANNER_READ_BYTES = 1024


@dataclass
class DiscoveryJobPayload:
    job_id: str
    engagement_id: str
    target_cidrs: list[str]
    excluded_cidrs: list[str]
    scan_profile: str = "standard"
    roe: dict = None

    def __post_init__(self):
        if self.roe is None:
            self.roe = {}


class DiscoveryWorker:
    """
    Pulled from Redis list `discovery:queue:{tenant_id}`.
    One worker instance processes one job at a time.
    """

    def __init__(self):
        self._parser = NmapXMLParser()
        self._svc_id = ServiceIdentifier()
        self._cancelled = False

    # ── Entry point ────────────────────────────────────────────────────────────

    async def run(self, payload: DiscoveryJobPayload) -> None:
        log = logger.bind(job_id=payload.job_id, engagement=payload.engagement_id)
        log.info("discovery.worker.start")

        async with AsyncSessionLocal() as db:
            await self._set_status(db, payload.job_id, ScanJobStatus.running, progress=0)

            try:
                rate_limiter = RateLimiter(payload.roe)
                if not rate_limiter.is_within_window():
                    raise RuntimeError("Outside scan window defined in Rules of Engagement")

                # Run nmap
                xml_output = await self._run_nmap(payload, log)
                hosts = self._parser.parse(xml_output)
                log.info("discovery.nmap.done", hosts_found=len(hosts))

                await self._set_status(db, payload.job_id, ScanJobStatus.running, progress=40)

                # Banner grab
                hosts = await self._banner_grab_all(hosts, rate_limiter, log)

                await self._set_status(db, payload.job_id, ScanJobStatus.running, progress=70)

                # Save to PostgreSQL
                saved = await self._save_assets(db, payload.engagement_id, hosts, log)

                result = {
                    "hosts_found": len(hosts),
                    "assets_saved": saved,
                    "open_ports": sum(len(h.open_ports) for h in hosts),
                }
                await self._set_status(
                    db, payload.job_id, ScanJobStatus.completed, progress=100, result=result
                )
                log.info("discovery.worker.done", **result)

            except asyncio.CancelledError:
                log.warning("discovery.worker.cancelled")
                await self._set_status(db, payload.job_id, ScanJobStatus.failed, result={"error": "cancelled"})
                raise
            except Exception as exc:
                log.error("discovery.worker.failed", error=str(exc), exc_info=exc)
                await self._set_status(
                    db, payload.job_id, ScanJobStatus.failed, result={"error": str(exc)}
                )

    # ── Nmap execution ─────────────────────────────────────────────────────────

    async def _run_nmap(self, payload: DiscoveryJobPayload, log) -> str:
        profile_args = SCAN_PROFILES.get(payload.scan_profile, SCAN_PROFILES["standard"])
        targets = [t for t in payload.target_cidrs if t not in payload.excluded_cidrs]

        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tf:
            xml_path = tf.name

        exclude_args: list[str] = []
        if payload.excluded_cidrs:
            exclude_args = ["--exclude", ",".join(payload.excluded_cidrs)]

        cmd = ["nmap", *profile_args, *exclude_args, "-oX", xml_path, *targets]
        log.info("discovery.nmap.launch", cmd=" ".join(cmd))

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await proc.communicate()

        if proc.returncode not in (0, None) and not os.path.exists(xml_path):
            raise RuntimeError(f"nmap failed (code {proc.returncode}): {stderr.decode()[:500]}")

        try:
            with open(xml_path) as f:
                return f.read()
        finally:
            os.unlink(xml_path)

    # ── Banner grabbing ────────────────────────────────────────────────────────

    async def _banner_grab_all(
        self, hosts: list[ParsedHost], rate_limiter: RateLimiter, log
    ) -> list[ParsedHost]:
        tasks = []
        for host in hosts:
            for port in host.open_ports:
                tasks.append(self._grab_one(host, port, rate_limiter))
        await asyncio.gather(*tasks, return_exceptions=True)
        return hosts

    async def _grab_one(
        self, host: ParsedHost, port: ParsedPort, rate_limiter: RateLimiter
    ) -> None:
        try:
            await rate_limiter.acquire(host.ip)
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host.ip, port.port),
                timeout=BANNER_TIMEOUT,
            )
            # Some services send banner on connect; for others, send a probe
            await asyncio.sleep(0.3)
            banner_bytes = b""
            try:
                banner_bytes = await asyncio.wait_for(
                    reader.read(BANNER_READ_BYTES), timeout=BANNER_TIMEOUT
                )
            except (asyncio.TimeoutError, ConnectionResetError):
                pass
            finally:
                writer.close()

            banner = banner_bytes.decode("utf-8", errors="replace").strip()
            if banner:
                fp = self._svc_id.identify(banner, port.port)
                port.service = fp.service or port.service
                port.product = fp.product or port.product
                port.version = fp.version or port.version
                port.extra_info = json.dumps({"banner_snippet": banner[:200], "confidence": fp.confidence_score})
        except Exception:
            pass  # Banner grab failures are non-fatal

    # ── PostgreSQL persistence ─────────────────────────────────────────────────

    async def _save_assets(
        self, db: AsyncSession, engagement_id: str, hosts: list[ParsedHost], log
    ) -> int:
        saved = 0
        eng_uuid = uuid.UUID(engagement_id)

        for host in hosts:
            if not host.ip:
                continue

            # Deduplication: upsert by (engagement_id, ip_address)
            existing = (
                await db.execute(
                    select(Asset).where(
                        Asset.engagement_id == eng_uuid,
                        Asset.ip_address == host.ip,
                    )
                )
            ).scalar_one_or_none()

            if existing:
                existing.hostname = host.hostname or existing.hostname
                existing.fqdn = host.fqdn or existing.fqdn
                existing.os = host.os or existing.os
                existing.last_seen = datetime.now(timezone.utc)
                asset = existing
            else:
                asset = Asset(
                    engagement_id=eng_uuid,
                    ip_address=host.ip,
                    hostname=host.hostname,
                    fqdn=host.fqdn,
                    os=host.os,
                    asset_type=AssetType.server,
                    last_seen=datetime.now(timezone.utc),
                )
                db.add(asset)
                await db.flush()
                saved += 1

            await db.flush()

            # Upsert services
            for port in host.open_ports:
                svc_result = await db.execute(
                    select(Service).where(
                        Service.asset_id == asset.id,
                        Service.port == port.port,
                        Service.protocol == port.protocol,
                    )
                )
                existing_svc = svc_result.scalar_one_or_none()
                if existing_svc:
                    existing_svc.service_name = port.service or existing_svc.service_name
                    existing_svc.product = port.product or existing_svc.product
                    existing_svc.version = port.version or existing_svc.version
                    existing_svc.cpe = port.cpe or existing_svc.cpe
                else:
                    db.add(Service(
                        asset_id=asset.id,
                        port=port.port,
                        protocol=port.protocol,
                        service_name=port.service,
                        product=port.product,
                        version=port.version,
                        cpe=port.cpe,
                    ))

            await db.flush()

        await db.commit()
        return saved

    # ── Helpers ────────────────────────────────────────────────────────────────

    @staticmethod
    async def _set_status(
        db: AsyncSession,
        job_id: str,
        status: ScanJobStatus,
        progress: int = 0,
        result: dict | None = None,
    ) -> None:
        values: dict[str, Any] = {"status": status}
        if result is not None:
            values["result"] = {**(result or {}), "progress": progress}
        if status == ScanJobStatus.running:
            values["started_at"] = datetime.now(timezone.utc)
        elif status in (ScanJobStatus.completed, ScanJobStatus.failed):
            values["completed_at"] = datetime.now(timezone.utc)

        await db.execute(
            update(ScanJob).where(ScanJob.id == uuid.UUID(job_id)).values(**values)
        )
        await db.commit()
