"""
NessusScanner — wraps the Tenable Nessus REST API v6.

Endpoints used:
  POST /session                               → auth token
  POST /scans                                 → create scan
  POST /scans/{id}/launch                     → start scan
  GET  /scans/{id}                            → status / host list / vuln list
  GET  /scans/{id}/hosts/{host_id}            → host detail
  GET  /scans/{id}/plugins/{plugin_id}        → plugin detail
  POST /scans/{id}/export                     → request .nessus export
  GET  /scans/{id}/export/{file_id}/download  → download .nessus file
"""
from __future__ import annotations

import asyncio
import ssl
from decimal import Decimal
from typing import Any

import httpx
import structlog

from app.models.enums import FindingSeverity, FindingStatus

logger = structlog.get_logger()

# Nessus severity int → our enum
_NESSUS_SEV: dict[int, FindingSeverity] = {
    4: FindingSeverity.critical,
    3: FindingSeverity.high,
    2: FindingSeverity.medium,
    1: FindingSeverity.low,
    0: FindingSeverity.info,
}


class NessusScanner:
    """Async Nessus API client. One instance per engagement scan session."""

    def __init__(self, verify_ssl: bool = False):
        self._base_url: str = ""
        self._token: str = ""
        self._api_keys: dict[str, str] = {}
        self._verify_ssl = verify_ssl
        self._client: httpx.AsyncClient | None = None

    # ── Lifecycle ──────────────────────────────────────────────────────────────

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self._base_url,
                verify=self._verify_ssl,
                timeout=httpx.Timeout(30.0, read=120.0),
                headers=self._auth_headers(),
            )
        return self._client

    def _auth_headers(self) -> dict[str, str]:
        if self._api_keys:
            return {"X-ApiKeys": f"accessKey={self._api_keys['access_key']};secretKey={self._api_keys['secret_key']}"}
        if self._token:
            return {"X-Cookie": f"token={self._token}"}
        return {}

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    # ── authenticate ──────────────────────────────────────────────────────────

    async def authenticate(self, url: str, access_key: str, secret_key: str) -> None:
        """
        Prefer API key auth (stateless, no session expiry).
        Falls back to username/password session token if keys are empty.
        """
        self._base_url = url.rstrip("/")

        if access_key and secret_key:
            self._api_keys = {"access_key": access_key, "secret_key": secret_key}
            logger.info("nessus.auth.api_key", url=self._base_url)
            return

        # username/password session flow
        client = httpx.AsyncClient(base_url=self._base_url, verify=self._verify_ssl, timeout=30.0)
        resp = await client.post("/session", json={"username": access_key, "password": secret_key})
        resp.raise_for_status()
        self._token = resp.json()["token"]
        await client.aclose()
        logger.info("nessus.auth.session_token", url=self._base_url)

    # ── create_scan ───────────────────────────────────────────────────────────

    async def create_scan(
        self,
        engagement_id: str,
        target_ips: list[str],
        policy_id: int,
        credentials: dict[str, Any] | None = None,
    ) -> str:
        """Returns nessus scan_id as string."""
        client = await self._get_client()
        targets = "\n".join(target_ips)
        body: dict[str, Any] = {
            "uuid": await self._get_template_uuid(client, policy_id),
            "settings": {
                "name": f"ADVERSA-{engagement_id[:8]}",
                "description": f"Automated VAPT scan — engagement {engagement_id}",
                "scanner_id": 1,
                "policy_id": policy_id,
                "text_targets": targets,
                "launch": "ONDEMAND",
            },
        }
        if credentials:
            body["credentials"] = {"add": credentials}

        resp = await client.post("/scans", json=body)
        resp.raise_for_status()
        scan_id = str(resp.json()["scan"]["id"])
        logger.info("nessus.scan.created", scan_id=scan_id, engagement=engagement_id)
        return scan_id

    async def _get_template_uuid(self, client: httpx.AsyncClient, policy_id: int) -> str:
        resp = await client.get("/editor/scan/templates")
        resp.raise_for_status()
        templates = resp.json().get("templates", [])
        for t in templates:
            if t.get("policy_id") == policy_id:
                return t["uuid"]
        # fall back to basic network scan template
        for t in templates:
            if "basic" in t.get("name", "").lower():
                return t["uuid"]
        return templates[0]["uuid"] if templates else "ab4bacd2-05f6-425c-9d79-3ba3940ad1c0"

    # ── launch_scan ───────────────────────────────────────────────────────────

    async def launch_scan(self, scan_id: str) -> str:
        """Returns scan_uuid (token for tracking)."""
        client = await self._get_client()
        resp = await client.post(f"/scans/{scan_id}/launch")
        resp.raise_for_status()
        scan_uuid = resp.json().get("scan_uuid", "")
        logger.info("nessus.scan.launched", scan_id=scan_id)
        return scan_uuid

    # ── poll_status ───────────────────────────────────────────────────────────

    async def poll_status(self, scan_id: str) -> dict[str, Any]:
        """Returns {status, progress_percent, host_count}."""
        client = await self._get_client()
        resp = await client.get(f"/scans/{scan_id}")
        resp.raise_for_status()
        info = resp.json().get("info", {})
        return {
            "status": info.get("status", "unknown"),
            "progress_percent": info.get("hm_total", 0) and int(
                100 * info.get("hm_scanned", 0) / max(info.get("hm_total", 1), 1)
            ),
            "host_count": info.get("hostcount", 0),
        }

    # ── get_results ───────────────────────────────────────────────────────────

    async def get_results(self, scan_id: str) -> list[dict[str, Any]]:
        """Returns list of raw finding dicts from all hosts."""
        client = await self._get_client()
        resp = await client.get(f"/scans/{scan_id}")
        resp.raise_for_status()
        data = resp.json()

        hosts: list[dict] = data.get("hosts", [])
        vulns: list[dict] = data.get("vulnerabilities", [])

        # Build host_id → hostname lookup
        host_map = {h["host_id"]: h.get("hostname", "") for h in hosts}

        raw_findings = []
        for vuln in vulns:
            host_id = vuln.get("host_id")
            # Fetch full plugin detail for each unique vuln
            detail = await self._get_plugin_detail(client, scan_id, host_id, vuln["plugin_id"])
            raw_findings.append({
                **vuln,
                "hostname": host_map.get(host_id, ""),
                "plugin_detail": detail,
            })

        logger.info("nessus.results.fetched", scan_id=scan_id, count=len(raw_findings))
        return raw_findings

    async def _get_plugin_detail(
        self, client: httpx.AsyncClient, scan_id: str, host_id: int, plugin_id: int
    ) -> dict:
        try:
            resp = await client.get(f"/scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}")
            resp.raise_for_status()
            return resp.json().get("info", {}).get("plugindescription", {})
        except Exception:
            return {}

    # ── map_finding ───────────────────────────────────────────────────────────

    def map_finding(self, raw: dict[str, Any]) -> dict[str, Any]:
        """
        Map a raw Nessus vulnerability dict → Finding-compatible dict.
        Returns a dict matching the Finding model fields (not yet persisted).
        """
        detail = raw.get("plugin_detail", {})
        plugin_attrs = detail.get("pluginattributes", {})
        risk_info = plugin_attrs.get("risk_information", {})
        vuln_info = plugin_attrs.get("vuln_information", {})
        description = plugin_attrs.get("description", "")
        solution = plugin_attrs.get("solution", "")
        synopsis = plugin_attrs.get("synopsis", raw.get("plugin_name", ""))

        # CVE extraction
        cve_list: list[str] = []
        ref_info = plugin_attrs.get("ref_information", {})
        for ref in ref_info.get("ref", []):
            if ref.get("@name", "").upper() == "CVE":
                val = ref.get("#text", "")
                if val:
                    cve_list.extend(val.split(","))

        # CVSS
        cvss_raw = risk_info.get("cvss3_base_score") or risk_info.get("cvss_base_score")
        cvss_score = Decimal(str(cvss_raw)) if cvss_raw else None
        cvss_vector = risk_info.get("cvss3_vector") or risk_info.get("cvss_vector") or None

        severity_int = int(raw.get("severity", 0))
        severity = _NESSUS_SEV.get(severity_int, FindingSeverity.info)

        return {
            "title": synopsis or f"Plugin {raw.get('plugin_id')}",
            "description": description,
            "remediation": solution,
            "severity": severity,
            "status": FindingStatus.open,
            "cve_ids": [c.strip() for c in cve_list if c.strip()],
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
            "exploitable": bool(vuln_info.get("exploit_available")),
            "exploit_validated": False,
            "evidence": {
                "plugin_id": raw.get("plugin_id"),
                "plugin_name": raw.get("plugin_name"),
                "hostname": raw.get("hostname"),
                "plugin_family": plugin_attrs.get("plugin_information", {}).get("plugin_family", ""),
            },
        }

    # ── export_nessus_file ────────────────────────────────────────────────────

    async def export_nessus_file(self, scan_id: str) -> bytes:
        """Request + poll + download .nessus XML for evidence storage."""
        client = await self._get_client()

        # Request export
        resp = await client.post(f"/scans/{scan_id}/export", json={"format": "nessus"})
        resp.raise_for_status()
        file_id = resp.json()["file"]

        # Poll until ready (max 60s)
        for _ in range(30):
            status_resp = await client.get(f"/scans/{scan_id}/export/{file_id}/status")
            if status_resp.json().get("status") == "ready":
                break
            await asyncio.sleep(2)

        # Download
        dl_resp = await client.get(f"/scans/{scan_id}/export/{file_id}/download")
        dl_resp.raise_for_status()
        logger.info("nessus.export.done", scan_id=scan_id, bytes=len(dl_resp.content))
        return dl_resp.content
