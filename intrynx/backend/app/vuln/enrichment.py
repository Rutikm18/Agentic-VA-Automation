"""
VulnEnrichmentService

External data sources:
  NVD 2.0     https://services.nvd.nist.gov/rest/json/cves/2.0
  EPSS        https://api.first.org/data/v1/epss
  CISA KEV    https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
  MITRE       inferred from NVD references + internal mapping
"""
from __future__ import annotations

import time
from collections import OrderedDict
from decimal import Decimal
from typing import Any

import httpx
import structlog

from app.models.enums import AssetCriticality
from app.utils.hash import dedup_hash

logger = structlog.get_logger()

# ── Bounded TTL cache — evicts oldest entries when full ────────────────────────

class TTLCache(OrderedDict):
    """LRU + TTL eviction. Expired keys are purged on access; when ``maxsize``
    is exceeded the oldest entry (by insertion order) is evicted."""

    def __init__(self, maxsize: int, ttl: int):
        super().__init__()
        self.maxsize = maxsize
        self.ttl = ttl

    def __contains__(self, key: object) -> bool:
        try:
            self[key]
            return True
        except KeyError:
            return False

    def __getitem__(self, key: str):
        value, ts = super().__getitem__(key)
        if time.time() > ts + self.ttl:
            del self[key]
            raise KeyError(key)
        self.move_to_end(key)
        return value

    def __setitem__(self, key: str, value: Any):
        super().__setitem__(key, (value, time.time()))
        if len(self) > self.maxsize:
            self.popitem(last=False)

    def get(self, key: str, default: Any = None):
        try:
            return self[key]
        except KeyError:
            return default


# ── Cache TTLs ─────────────────────────────────────────────────────────────────
_NVD_MAXSIZE  = 256
_NVD_TTL_SEC  = 86_400   # 24 h per CVE (data is immutable per CVE)
_KEV_MAXSIZE  = 1        # single catalog key
_KEV_TTL_SEC  = 3_600    # 1 h — catalog updates infrequently
_EPSS_MAXSIZE = 256
_EPSS_TTL_SEC = 3_600    # 1 h

# ── Asset criticality → 0-1 weight ────────────────────────────────────────────
_CRIT_WEIGHT: dict[str, float] = {
    AssetCriticality.critical.value: 1.0,
    AssetCriticality.high.value:     0.75,
    AssetCriticality.medium.value:   0.5,
    AssetCriticality.low.value:      0.25,
}

# ── Known CVE → MITRE technique mappings (subset for common CVEs) ──────────────
_CVE_MITRE_HINTS: dict[str, list[str]] = {
    "CVE-2021-44228": ["T1190", "T1059"],      # Log4Shell — initial access + exec
    "CVE-2021-34527": ["T1068", "T1547"],      # PrintNightmare — privesc
    "CVE-2020-1472":  ["T1210", "T1068"],      # ZeroLogon — lateral + privesc
    "CVE-2017-0144":  ["T1210"],               # EternalBlue — lateral
    "CVE-2019-0708":  ["T1210"],               # BlueKeep — lateral
    "CVE-2022-30190": ["T1203"],               # Follina
    "CVE-2021-26855": ["T1190"],               # Exchange ProxyLogon
}


class VulnEnrichmentService:
    """Enriches Finding objects with NVD, EPSS, CISA KEV, and MITRE data."""

    def __init__(self, http_client: httpx.AsyncClient | None = None):
        self._http = http_client or httpx.AsyncClient(
            timeout=httpx.Timeout(15.0), follow_redirects=True
        )
        # Bounded TTL caches — maximum entries capped to stop unbounded growth
        self._nvd_cache:  TTLCache = TTLCache(_NVD_MAXSIZE, _NVD_TTL_SEC)
        self._epss_cache: TTLCache = TTLCache(_EPSS_MAXSIZE, _EPSS_TTL_SEC)
        self._kev_cache:  TTLCache = TTLCache(_KEV_MAXSIZE, _KEV_TTL_SEC)

    # ── enrich ────────────────────────────────────────────────────────────────

    async def enrich(
        self,
        finding_dict: dict[str, Any],
        asset_criticality: str = "medium",
    ) -> dict[str, Any]:
        """
        Add NVD CVSS, EPSS, KEV flag, MITRE techniques, and composite risk.
        Mutates and returns the finding dict.
        """
        cve_ids: list[str] = finding_dict.get("cve_ids") or []

        if not cve_ids:
            return finding_dict

        primary_cve = cve_ids[0]

        # Fetch all enrichment in parallel
        nvd_data, epss_data, is_kev, mitre_techs = await self._fetch_all(primary_cve)

        # Override CVSS if NVD has a better value
        if nvd_data.get("cvss_v3") and not finding_dict.get("cvss_score"):
            finding_dict["cvss_score"] = Decimal(str(nvd_data["cvss_v3"]))
        if nvd_data.get("cvss_vector") and not finding_dict.get("cvss_vector"):
            finding_dict["cvss_vector"] = nvd_data["cvss_vector"]
        if nvd_data.get("description") and not finding_dict.get("description"):
            finding_dict["description"] = nvd_data["description"]

        finding_dict["epss_score"] = Decimal(str(epss_data.get("epss_score", 0))) if epss_data else None

        if mitre_techs:
            existing = finding_dict.get("mitre_techniques") or []
            finding_dict["mitre_techniques"] = list(set(existing + mitre_techs))

        # Composite risk score
        finding_dict["risk_score"] = Decimal(str(
            self.compute_composite_risk(
                cvss=float(finding_dict.get("cvss_score") or 0),
                epss=float(finding_dict.get("epss_score") or 0),
                kev=is_kev,
                exploit_validated=bool(finding_dict.get("exploit_validated")),
                asset_criticality=asset_criticality,
            )
        ))

        # Store enrichment metadata in evidence
        evidence = finding_dict.get("evidence") or {}
        evidence["enrichment"] = {
            "kev": is_kev,
            "nvd_published": nvd_data.get("published_date"),
            "references": nvd_data.get("references", [])[:5],
            "epss_percentile": epss_data.get("percentile") if epss_data else None,
        }
        finding_dict["evidence"] = evidence

        return finding_dict

    # ── fetch_nvd ─────────────────────────────────────────────────────────────

    async def fetch_nvd(self, cve_id: str) -> dict[str, Any]:
        """Returns {cvss_v3, cvss_vector, description, references, published_date}."""
        cve_id = cve_id.upper()
        cached = self._nvd_cache.get(cve_id)
        if cached is not None:
            return cached

        try:
            resp = await self._http.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"cveId": cve_id},
                headers={"User-Agent": "ADVERSA-VAPT/1.0"},
            )
            resp.raise_for_status()
            data = resp.json()
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                return {}

            cve_obj = vulns[0]["cve"]
            description = next(
                (d["value"] for d in cve_obj.get("descriptions", []) if d["lang"] == "en"), ""
            )
            published = cve_obj.get("published", "")
            references = [r["url"] for r in cve_obj.get("references", [])[:10]]

            # CVSS v3.1 preferred, fallback to v3.0 then v2
            cvss_v3 = None
            cvss_vector = None
            for metric_key in ("cvssMetricV31", "cvssMetricV30"):
                metrics = cve_obj.get("metrics", {}).get(metric_key, [])
                if metrics:
                    cvss_data = metrics[0]["cvssData"]
                    cvss_v3 = cvss_data.get("baseScore")
                    cvss_vector = cvss_data.get("vectorString")
                    break

            result = {
                "cvss_v3": cvss_v3,
                "cvss_vector": cvss_vector,
                "description": description,
                "references": references,
                "published_date": published,
            }
            self._nvd_cache[cve_id] = result
            return result
        except Exception as exc:
            logger.warning("nvd.fetch.failed", cve=cve_id, error=str(exc))
            return {}

    # ── fetch_epss ────────────────────────────────────────────────────────────

    async def fetch_epss(self, cve_id: str) -> dict[str, Any]:
        """Returns {epss_score: float, percentile: float} or {}."""
        cve_id = cve_id.upper()
        cached = self._epss_cache.get(cve_id)
        if cached is not None:
            return cached

        try:
            resp = await self._http.get(
                "https://api.first.org/data/v1/epss",
                params={"cve": cve_id},
            )
            resp.raise_for_status()
            data = resp.json().get("data", [])
            if not data:
                return {}

            result = {
                "epss_score": float(data[0].get("epss", 0)),
                "percentile": float(data[0].get("percentile", 0)),
            }
            self._epss_cache[cve_id] = result
            return result
        except Exception as exc:
            logger.warning("epss.fetch.failed", cve=cve_id, error=str(exc))
            return {}

    # ── check_cisa_kev ────────────────────────────────────────────────────────

    async def check_cisa_kev(self, cve_id: str) -> bool:
        """True if CVE is in the CISA Known Exploited Vulnerabilities catalog."""
        kev_set = await self._get_kev_catalog()
        return cve_id.upper() in kev_set

    async def _get_kev_catalog(self) -> set[str]:
        cached = self._kev_cache.get("_kev_set")
        if cached is not None:
            return cached

        try:
            resp = await self._http.get(
                "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
            )
            resp.raise_for_status()
            vulns = resp.json().get("vulnerabilities", [])
            kev_set = {v["cveID"].upper() for v in vulns if "cveID" in v}
            self._kev_cache["_kev_set"] = kev_set
            logger.info("cisa.kev.loaded", count=len(kev_set))
            return kev_set
        except Exception as exc:
            logger.warning("cisa.kev.failed", error=str(exc))
            return set()

    # ── fetch_mitre_techniques ────────────────────────────────────────────────

    async def fetch_mitre_techniques(self, cve_id: str) -> list[str]:
        """
        Returns MITRE ATT&CK technique IDs linked to this CVE.
        Uses hardcoded hints for known CVEs; falls back to NVD reference scan.
        """
        cve_up = cve_id.upper()

        # 1. Known mapping
        if cve_up in _CVE_MITRE_HINTS:
            return _CVE_MITRE_HINTS[cve_up]

        # 2. Scan NVD references for attack.mitre.org URLs
        nvd = await self.fetch_nvd(cve_id)
        techniques = []
        for ref in nvd.get("references", []):
            if "attack.mitre.org/techniques/" in ref:
                # extract T-number from URL
                parts = ref.split("/techniques/")[-1].strip("/").split("/")
                tid = parts[0].upper()
                if tid.startswith("T") and tid[1:].isdigit():
                    sub = f"{tid}.{parts[1]}" if len(parts) > 1 else tid
                    techniques.append(sub)

        return list(set(techniques))

    # ── compute_composite_risk ────────────────────────────────────────────────

    def compute_composite_risk(
        self,
        cvss: float,
        epss: float,
        kev: bool,
        exploit_validated: bool,
        asset_criticality: str = "medium",
        path_depth: int | None = None,
        lateral_reachable_count: int | None = None,
    ) -> float:
        """
        Returns composite risk score on 0-1000 scale.

        Formula:
          (cvss*0.25 + epss*0.20 + kev_bonus*0.20 + exploit_validated*0.15
           + asset_crit*0.10 + path_depth*0.05 + lateral_impact*0.05) * 1000
        """
        # Normalize inputs to 0-1
        cvss_n  = min(float(cvss), 10.0) / 10.0
        epss_n  = min(max(float(epss), 0.0), 1.0)
        kev_n   = 1.0 if kev else 0.0
        expl_n  = 1.0 if exploit_validated else 0.0
        crit_n  = _CRIT_WEIGHT.get(asset_criticality, 0.5)

        # Path depth: shallower = higher risk (0 hops = 1.0, 10+ hops = 0.0)
        depth_n = max(0.0, 1.0 - path_depth / 10.0) if path_depth is not None else 0.5

        # Lateral impact: more reachable hosts = higher risk (capped at 50)
        lateral_n = min(lateral_reachable_count, 50) / 50.0 if lateral_reachable_count is not None else 0.5

        score = (
            cvss_n  * 0.25 +
            epss_n  * 0.20 +
            kev_n   * 0.20 +
            expl_n  * 0.15 +
            crit_n  * 0.10 +
            depth_n * 0.05 +
            lateral_n * 0.05
        ) * 1000

        return round(score, 2)

    # ── helpers ───────────────────────────────────────────────────────────────

    async def _fetch_all(self, cve_id: str):
        """Fetch NVD, EPSS, KEV and MITRE concurrently."""
        import asyncio
        nvd_task   = asyncio.create_task(self.fetch_nvd(cve_id))
        epss_task  = asyncio.create_task(self.fetch_epss(cve_id))
        kev_task   = asyncio.create_task(self.check_cisa_kev(cve_id))
        mitre_task = asyncio.create_task(self.fetch_mitre_techniques(cve_id))
        return await asyncio.gather(nvd_task, epss_task, kev_task, mitre_task)

    @staticmethod
    def dedup_hash(asset_id: str | None, cve_id: str | None, plugin_id: Any) -> str:
        """SHA-256 of (asset_id, cve_id, plugin_id) for deduplication."""
        return dedup_hash(asset_id, cve_id, plugin_id)
