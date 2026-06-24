"""
EDR query engines — abstract interface + CrowdStrike Falcon / Microsoft Defender
/ SentinelOne implementations.

Each engine queries its platform for endpoint detections in a time window
(optionally host-filtered) and normalises them into ``EDRDetection``. The
``action`` field is the key signal for the correlator: a value of "prevented" /
"blocked" / "quarantined" means the EDR actively stopped the action (→ result
``prevented``), versus merely "detected"/"alert" (→ ``detected``).
"""
from __future__ import annotations

import abc
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import httpx
import structlog

logger = structlog.get_logger()

# EDR action strings that indicate the attack was actively blocked.
PREVENTED_ACTIONS: frozenset[str] = frozenset({
    "prevented", "blocked", "quarantined", "kill", "killed", "remediated",
    "prevention", "block", "mitigated",
})


@dataclass
class EDRDetection:
    id: str
    title: str
    host: str | None
    timestamp: datetime | None
    technique: str | None = None
    severity: str | None = None
    action: str | None = None          # detected | prevented | blocked | ...
    source: str = "edr"
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def is_prevented(self) -> bool:
        return (self.action or "").lower() in PREVENTED_ACTIONS


def _parse_dt(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    text = str(value).replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        try:
            return datetime.fromtimestamp(float(value))
        except (ValueError, OSError):
            return None


class EDRQueryEngine(abc.ABC):
    provider: str = "abstract"

    def __init__(self, config: dict[str, Any], http_timeout: float = 30.0):
        self._config = config
        self._timeout = http_timeout

    @abc.abstractmethod
    async def query_detections(
        self,
        time_start: datetime,
        time_end: datetime,
        host_filter: str | None = None,
    ) -> list[EDRDetection]:
        ...

    async def _request(self, method: str, url: str, **kwargs: Any) -> httpx.Response | None:
        try:
            async with httpx.AsyncClient(timeout=self._timeout, verify=self._config.get("verify_ssl", True)) as client:
                resp = await client.request(method, url, **kwargs)
                resp.raise_for_status()
                return resp
        except Exception as exc:
            logger.warning("edr.request_failed", provider=self.provider, url=url, error=str(exc))
            return None


# ── CrowdStrike Falcon ────────────────────────────────────────────────────────

class CrowdStrikeFalcon(EDRQueryEngine):
    """
    Falcon: query detection IDs then fetch their summaries.
    config: {base_url, token (OAuth2 bearer), verify_ssl?}.
    """
    provider = "crowdstrike"

    async def query_detections(self, time_start, time_end, host_filter=None) -> list[EDRDetection]:
        base = self._config.get("base_url", "https://api.crowdstrike.com").rstrip("/")
        headers = {"Authorization": f"Bearer {self._config.get('token', '')}"}
        fql = (f"created_timestamp:>'{time_start.isoformat()}'"
               f"+created_timestamp:<'{time_end.isoformat()}'")
        if host_filter:
            fql += f"+device.hostname:'{host_filter}'"
        q = await self._request("GET", f"{base}/detects/queries/detects/v1",
                                headers=headers, params={"filter": fql, "limit": 500})
        if q is None:
            return []
        ids = q.json().get("resources", [])
        if not ids:
            return []
        s = await self._request("POST", f"{base}/detects/entities/summaries/GET/v1",
                                headers=headers, json={"ids": ids})
        if s is None:
            return []
        return self.parse_response(s.json())

    def parse_response(self, data: dict[str, Any]) -> list[EDRDetection]:
        detections: list[EDRDetection] = []
        for res in data.get("resources", []):
            behaviors = res.get("behaviors", [{}])
            beh = behaviors[0] if behaviors else {}
            device = res.get("device", {})
            detections.append(EDRDetection(
                id=str(res.get("detection_id") or res.get("composite_id", "")),
                title=beh.get("display_name") or res.get("detection_name") or "Falcon detection",
                host=device.get("hostname"),
                timestamp=_parse_dt(res.get("created_timestamp")),
                technique=beh.get("technique_id") or beh.get("technique"),
                severity=res.get("max_severity_displayname") or beh.get("severity"),
                action=beh.get("pattern_disposition_description") or res.get("status"),
                source="crowdstrike",
                raw=res,
            ))
        return detections


# ── Microsoft Defender ────────────────────────────────────────────────────────

class MicrosoftDefender(EDRQueryEngine):
    """
    Microsoft Defender via the Graph Security API ``/security/alerts_v2``.
    config: {token (Graph bearer), verify_ssl?}.
    """
    provider = "defender"

    async def query_detections(self, time_start, time_end, host_filter=None) -> list[EDRDetection]:
        url = "https://graph.microsoft.com/v1.0/security/alerts_v2"
        headers = {"Authorization": f"Bearer {self._config.get('token', '')}"}
        flt = (f"createdDateTime ge {time_start.isoformat()} and "
               f"createdDateTime le {time_end.isoformat()}")
        resp = await self._request("GET", url, headers=headers,
                                   params={"$filter": flt, "$top": 500})
        if resp is None:
            return []
        return self.parse_response(resp.json(), host_filter)

    def parse_response(self, data: dict[str, Any], host_filter: str | None = None) -> list[EDRDetection]:
        detections: list[EDRDetection] = []
        for alert in data.get("value", []):
            devices = alert.get("evidence", []) or []
            host = None
            for ev in devices:
                if ev.get("@odata.type", "").endswith("deviceEvidence"):
                    host = ev.get("deviceDnsName") or ev.get("hostName")
                    break
            if host_filter and host and host_filter.lower() not in host.lower():
                continue
            techniques = alert.get("mitreTechniques", [])
            detections.append(EDRDetection(
                id=str(alert.get("id", "")),
                title=alert.get("title") or "Defender alert",
                host=host,
                timestamp=_parse_dt(alert.get("createdDateTime")),
                technique=",".join(techniques) if techniques else None,
                severity=alert.get("severity"),
                action=alert.get("determination") or alert.get("status"),
                source="defender",
                raw=alert,
            ))
        return detections


# ── SentinelOne ───────────────────────────────────────────────────────────────

class SentinelOne(EDRQueryEngine):
    """
    SentinelOne via the REST ``/web/api/v2.1/threats`` endpoint.
    config: {base_url, token (ApiToken), verify_ssl?}.
    """
    provider = "sentinelone"

    async def query_detections(self, time_start, time_end, host_filter=None) -> list[EDRDetection]:
        base = self._config.get("base_url", "").rstrip("/")
        url = f"{base}/web/api/v2.1/threats"
        headers = {"Authorization": f"ApiToken {self._config.get('token', '')}"}
        params = {
            "createdAt__gte": time_start.isoformat(),
            "createdAt__lte": time_end.isoformat(),
            "limit": 500,
        }
        if host_filter:
            params["computerName__contains"] = host_filter
        resp = await self._request("GET", url, headers=headers, params=params)
        if resp is None:
            return []
        return self.parse_response(resp.json())

    def parse_response(self, data: dict[str, Any]) -> list[EDRDetection]:
        detections: list[EDRDetection] = []
        for threat in data.get("data", []):
            info = threat.get("threatInfo", threat)
            agent = threat.get("agentRealtimeInfo", {})
            detections.append(EDRDetection(
                id=str(threat.get("id") or info.get("threatId", "")),
                title=info.get("threatName") or "SentinelOne threat",
                host=agent.get("agentComputerName") or info.get("computerName"),
                timestamp=_parse_dt(info.get("createdAt") or threat.get("createdAt")),
                technique=(info.get("mitreTactic") or [{}])[0].get("techniques") if isinstance(info.get("mitreTactic"), list) else None,
                severity=info.get("confidenceLevel") or info.get("severity"),
                action=info.get("mitigationStatus") or info.get("incidentStatus"),
                source="sentinelone",
                raw=threat,
            ))
        return detections


EDR_PROVIDERS: dict[str, type[EDRQueryEngine]] = {
    "crowdstrike": CrowdStrikeFalcon,
    "defender": MicrosoftDefender,
    "sentinelone": SentinelOne,
}


def build_edr_engine(provider: str, config: dict[str, Any]) -> EDRQueryEngine | None:
    cls = EDR_PROVIDERS.get((provider or "").lower())
    return cls(config) if cls else None
