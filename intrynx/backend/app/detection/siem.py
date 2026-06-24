"""
SIEM query engines — abstract interface + Splunk / Microsoft Sentinel / Elastic
implementations.

Each engine queries its platform for alerts in a time window optionally filtered
by host, and normalises the platform-specific response into ``SIEMAlert``. All
HTTP is async (httpx). Network/credential errors are caught and logged so a
correlation run degrades to "no alerts from this source" rather than crashing.
"""
from __future__ import annotations

import abc
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import httpx
import structlog

logger = structlog.get_logger()


@dataclass
class SIEMAlert:
    id: str
    title: str
    host: str | None
    timestamp: datetime | None
    severity: str | None = None
    technique: str | None = None
    source: str = "siem"
    raw: dict[str, Any] = field(default_factory=dict)


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


class SIEMQueryEngine(abc.ABC):
    """Abstract SIEM connector."""

    provider: str = "abstract"

    def __init__(self, config: dict[str, Any], http_timeout: float = 30.0):
        self._config = config
        self._timeout = http_timeout

    @abc.abstractmethod
    async def query_alerts(
        self,
        time_start: datetime,
        time_end: datetime,
        host_filter: str | None = None,
    ) -> list[SIEMAlert]:
        ...

    async def _request(self, method: str, url: str, **kwargs: Any) -> httpx.Response | None:
        try:
            async with httpx.AsyncClient(timeout=self._timeout, verify=self._config.get("verify_ssl", True)) as client:
                resp = await client.request(method, url, **kwargs)
                resp.raise_for_status()
                return resp
        except Exception as exc:
            logger.warning("siem.request_failed", provider=self.provider, url=url, error=str(exc))
            return None


# ── Splunk ────────────────────────────────────────────────────────────────────

class SplunkSIEM(SIEMQueryEngine):
    """
    Splunk via the REST search endpoint (``/services/search/jobs/export``) with an
    SPL query. config: {base_url, token, index?, verify_ssl?}.
    """
    provider = "splunk"

    def build_spl(self, time_start: datetime, time_end: datetime, host_filter: str | None) -> str:
        index = self._config.get("index", "main")
        spl = f'search index={index} (tag=alert OR sourcetype=*notable*)'
        if host_filter:
            spl += f' (host="{host_filter}" OR dest="{host_filter}" OR dest_ip="{host_filter}")'
        spl += f' earliest={int(time_start.timestamp())} latest={int(time_end.timestamp())}'
        return spl

    async def query_alerts(self, time_start, time_end, host_filter=None) -> list[SIEMAlert]:
        base = self._config.get("base_url", "").rstrip("/")
        url = f"{base}/services/search/jobs/export"
        headers = {"Authorization": f"Bearer {self._config.get('token', '')}"}
        params = {"search": self.build_spl(time_start, time_end, host_filter),
                  "output_mode": "json", "exec_mode": "oneshot"}
        resp = await self._request("POST", url, headers=headers, data=params)
        if resp is None:
            return []
        return self.parse_response(resp.text)

    def parse_response(self, body: str) -> list[SIEMAlert]:
        import json
        alerts: list[SIEMAlert] = []
        for line in body.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            result = row.get("result", row)
            alerts.append(SIEMAlert(
                id=str(result.get("event_id") or result.get("_cd") or result.get("_serial", "")),
                title=result.get("search_name") or result.get("source") or "Splunk notable",
                host=result.get("host") or result.get("dest") or result.get("dest_ip"),
                timestamp=_parse_dt(result.get("_time")),
                severity=result.get("severity") or result.get("urgency"),
                technique=result.get("annotations.mitre_attack") or result.get("mitre_technique"),
                source="splunk",
                raw=result,
            ))
        return alerts


# ── Microsoft Sentinel ────────────────────────────────────────────────────────

class SentinelSIEM(SIEMQueryEngine):
    """
    Microsoft Sentinel via the Azure Monitor Logs query REST API with KQL.
    config: {workspace_id, token (bearer), table?, verify_ssl?}.
    """
    provider = "sentinel"

    def build_kql(self, time_start: datetime, time_end: datetime, host_filter: str | None) -> str:
        table = self._config.get("table", "SecurityAlert")
        kql = (
            f"{table} "
            f"| where TimeGenerated between (datetime({time_start.isoformat()}) .. "
            f"datetime({time_end.isoformat()}))"
        )
        if host_filter:
            kql += f' | where CompromisedEntity == "{host_filter}" or Computer == "{host_filter}"'
        return kql

    async def query_alerts(self, time_start, time_end, host_filter=None) -> list[SIEMAlert]:
        workspace = self._config.get("workspace_id", "")
        url = f"https://api.loganalytics.io/v1/workspaces/{workspace}/query"
        headers = {"Authorization": f"Bearer {self._config.get('token', '')}",
                   "Content-Type": "application/json"}
        payload = {"query": self.build_kql(time_start, time_end, host_filter)}
        resp = await self._request("POST", url, headers=headers, json=payload)
        if resp is None:
            return []
        return self.parse_response(resp.json())

    def parse_response(self, data: dict[str, Any]) -> list[SIEMAlert]:
        alerts: list[SIEMAlert] = []
        for table in data.get("tables", []):
            cols = [c["name"] for c in table.get("columns", [])]
            for row in table.get("rows", []):
                rec = dict(zip(cols, row))
                alerts.append(SIEMAlert(
                    id=str(rec.get("SystemAlertId") or rec.get("TimeGenerated", "")),
                    title=rec.get("AlertName") or rec.get("DisplayName") or "Sentinel alert",
                    host=rec.get("CompromisedEntity") or rec.get("Computer"),
                    timestamp=_parse_dt(rec.get("TimeGenerated")),
                    severity=rec.get("AlertSeverity"),
                    technique=rec.get("Techniques") or rec.get("AttackTechniques"),
                    source="sentinel",
                    raw=rec,
                ))
        return alerts


# ── Elastic ───────────────────────────────────────────────────────────────────

class ElasticSIEM(SIEMQueryEngine):
    """
    Elasticsearch via the _search API (KQL/EQL-style bool query).
    config: {base_url, api_key|token, index?, verify_ssl?}.
    """
    provider = "elastic"

    def build_query(self, time_start: datetime, time_end: datetime, host_filter: str | None) -> dict[str, Any]:
        must: list[dict[str, Any]] = [{
            "range": {"@timestamp": {
                "gte": time_start.isoformat(), "lte": time_end.isoformat()}}
        }, {"exists": {"field": "kibana.alert.rule.uuid"}}]
        if host_filter:
            must.append({"bool": {"should": [
                {"term": {"host.name": host_filter}},
                {"term": {"host.ip": host_filter}},
                {"term": {"destination.ip": host_filter}},
            ]}})
        return {"size": 500, "query": {"bool": {"must": must}}}

    async def query_alerts(self, time_start, time_end, host_filter=None) -> list[SIEMAlert]:
        base = self._config.get("base_url", "").rstrip("/")
        index = self._config.get("index", ".alerts-security.alerts-*")
        url = f"{base}/{index}/_search"
        headers = {"Content-Type": "application/json"}
        if self._config.get("api_key"):
            headers["Authorization"] = f"ApiKey {self._config['api_key']}"
        elif self._config.get("token"):
            headers["Authorization"] = f"Bearer {self._config['token']}"
        resp = await self._request("POST", url, headers=headers,
                                   json=self.build_query(time_start, time_end, host_filter))
        if resp is None:
            return []
        return self.parse_response(resp.json())

    def parse_response(self, data: dict[str, Any]) -> list[SIEMAlert]:
        alerts: list[SIEMAlert] = []
        for hit in data.get("hits", {}).get("hits", []):
            src = hit.get("_source", {})
            kibana = src.get("kibana", {}).get("alert", {}) if isinstance(src.get("kibana"), dict) else {}
            host = src.get("host", {})
            techniques = []
            for threat in src.get("threat", []) if isinstance(src.get("threat"), list) else []:
                tech = threat.get("technique", [])
                techniques += [t.get("id") for t in tech if isinstance(t, dict)]
            alerts.append(SIEMAlert(
                id=str(hit.get("_id", "")),
                title=(kibana.get("rule", {}) or {}).get("name") or src.get("message") or "Elastic alert",
                host=(host.get("name") if isinstance(host, dict) else None) or src.get("host.name"),
                timestamp=_parse_dt(src.get("@timestamp")),
                severity=(kibana.get("severity") or src.get("event", {}).get("severity")),
                technique=",".join([t for t in techniques if t]) or None,
                source="elastic",
                raw=src,
            ))
        return alerts


SIEM_PROVIDERS: dict[str, type[SIEMQueryEngine]] = {
    "splunk": SplunkSIEM,
    "sentinel": SentinelSIEM,
    "elastic": ElasticSIEM,
}


def build_siem_engine(provider: str, config: dict[str, Any]) -> SIEMQueryEngine | None:
    cls = SIEM_PROVIDERS.get((provider or "").lower())
    return cls(config) if cls else None
