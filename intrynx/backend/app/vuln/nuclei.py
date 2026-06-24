"""
NucleiScanner — async subprocess wrapper around the Nuclei CLI.

Nuclei outputs JSONL: one JSON object per finding on stdout.
Each line shape:
  {
    "template-id": "CVE-2021-44228",
    "info": {"name": "...", "severity": "critical", "tags": ["cve"]},
    "matched-at": "http://10.0.0.5:8080/path",
    "host": "http://10.0.0.5:8080",
    "type": "http",
    "timestamp": "2026-05-19T10:00:00Z",
    "matcher-name": "matcher-1",
    "extracted-results": [],
    "curl-command": "curl ..."
  }
"""
from __future__ import annotations

import asyncio
import json
import re
import shutil
from decimal import Decimal
from typing import Any

import structlog

from app.models.enums import FindingSeverity, FindingStatus
from app.discovery.service_id import ServiceFingerprint

logger = structlog.get_logger()

_NUCLEI_SEV: dict[str, FindingSeverity] = {
    "critical": FindingSeverity.critical,
    "high":     FindingSeverity.high,
    "medium":   FindingSeverity.medium,
    "low":      FindingSeverity.low,
    "info":     FindingSeverity.info,
    "unknown":  FindingSeverity.info,
}

# Service type → relevant template tags
_SERVICE_TEMPLATE_MAP: dict[str, list[str]] = {
    "http":      ["cves", "misconfigs", "ssl", "default-logins", "exposures", "technologies"],
    "https":     ["cves", "misconfigs", "ssl", "default-logins", "exposures", "technologies"],
    "ssh":       ["cves", "default-logins", "misconfigs"],
    "ftp":       ["cves", "default-logins", "misconfigs"],
    "smb":       ["cves", "misconfigs", "network"],
    "rdp":       ["cves", "misconfigs", "default-logins"],
    "smtp":      ["cves", "misconfigs"],
    "mssql":     ["cves", "default-logins", "misconfigs"],
    "mysql":     ["cves", "default-logins", "misconfigs"],
    "postgres":  ["cves", "default-logins", "misconfigs"],
    "redis":     ["cves", "misconfigs", "default-logins"],
    "mongodb":   ["cves", "misconfigs", "default-logins"],
    "ldap":      ["misconfigs", "network"],
    "kerberos":  ["misconfigs", "network"],
    "snmp":      ["misconfigs", "network", "default-logins"],
    "netbios":   ["misconfigs", "network"],
    "default":   ["cves", "misconfigs"],
}

_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.I)


class NucleiScanner:
    """Run Nuclei against targets and parse JSONL output into Finding dicts."""

    NUCLEI_BIN = "nuclei"

    # ── run_scan ──────────────────────────────────────────────────────────────

    async def run_scan(
        self,
        targets: list[str],
        templates: list[str],
        rate_limit: int = 150,
        timeout_sec: int = 300,
    ) -> list[dict[str, Any]]:
        """
        Runs nuclei as an async subprocess.
        Returns a list of parsed finding dicts.
        """
        if not shutil.which(self.NUCLEI_BIN):
            logger.warning("nuclei.not_found", hint="Install nuclei: https://github.com/projectdiscovery/nuclei")
            return []

        target_args = []
        for t in targets:
            target_args += ["-target", t]

        tag_args = []
        if templates:
            tag_args = ["-tags", ",".join(set(templates))]

        cmd = [
            self.NUCLEI_BIN,
            *target_args,
            *tag_args,
            "-rate-limit", str(rate_limit),
            "-json-export", "/dev/stdout",
            "-silent",
            "-no-color",
            "-timeout", str(timeout_sec),
        ]
        logger.info("nuclei.scan.start", targets=len(targets), tags=templates)

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=float(timeout_sec + 30)
            )
        except asyncio.TimeoutError:
            proc.kill()
            logger.error("nuclei.scan.timeout")
            return []

        output = stdout.decode("utf-8", errors="replace")
        findings = self.parse_output(output)
        logger.info("nuclei.scan.done", findings=len(findings))
        return findings

    # ── parse_output ──────────────────────────────────────────────────────────

    def parse_output(self, jsonl_output: str) -> list[dict[str, Any]]:
        """Parse nuclei JSONL output → list of Finding-compatible dicts."""
        findings = []
        for line in jsonl_output.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                raw = json.loads(line)
                findings.append(self._map_finding(raw))
            except (json.JSONDecodeError, KeyError):
                continue
        return findings

    def _map_finding(self, raw: dict[str, Any]) -> dict[str, Any]:
        info = raw.get("info", {})
        severity_str = info.get("severity", "info").lower()
        severity = _NUCLEI_SEV.get(severity_str, FindingSeverity.info)

        # Extract CVE IDs from template-id and description
        template_id = raw.get("template-id", "")
        description = info.get("description", "")
        cve_ids = list({m.upper() for m in _CVE_RE.findall(f"{template_id} {description}")})

        # CVSS from metadata if present
        metadata = info.get("metadata", {})
        cvss_score = None
        cvss_val = metadata.get("cvss-score") or metadata.get("cvss3-score")
        if cvss_val:
            try:
                cvss_score = Decimal(str(cvss_val))
            except Exception:
                pass

        # MITRE techniques
        mitre = [t for t in metadata.get("attack-vector", []) if t.startswith("T")]

        matched_at = raw.get("matched-at", raw.get("host", ""))

        return {
            "title": info.get("name", template_id),
            "description": description,
            "severity": severity,
            "status": FindingStatus.open,
            "cve_ids": cve_ids,
            "cvss_score": cvss_score,
            "mitre_techniques": mitre or None,
            "exploitable": severity in (FindingSeverity.critical, FindingSeverity.high),
            "exploit_validated": False,
            "evidence": {
                "template_id": template_id,
                "matched_at": matched_at,
                "matcher_name": raw.get("matcher-name", ""),
                "extracted_results": raw.get("extracted-results", []),
                "curl_command": raw.get("curl-command", ""),
                "type": raw.get("type", ""),
                "timestamp": raw.get("timestamp", ""),
                "tags": info.get("tags", []),
            },
        }

    # ── template_selector ─────────────────────────────────────────────────────

    def template_selector(self, asset_services: list[str]) -> list[str]:
        """
        Given a list of service names on an asset, return the union
        of relevant Nuclei template tags.

        Args:
            asset_services: e.g. ["http", "ssh", "smb"]

        Returns:
            Deduplicated list of template tags: ["cves", "misconfigs", "ssl", ...]
        """
        tags: set[str] = set()
        for svc in asset_services:
            svc_lower = svc.lower()
            mapped = _SERVICE_TEMPLATE_MAP.get(svc_lower, _SERVICE_TEMPLATE_MAP["default"])
            tags.update(mapped)
        return sorted(tags)
