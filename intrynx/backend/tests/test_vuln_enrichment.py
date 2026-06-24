"""
Unit tests for VulnEnrichmentService — all external HTTP calls mocked.
"""
from __future__ import annotations

from decimal import Decimal
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from app.vuln.enrichment import VulnEnrichmentService


# ── NVD fixture data ──────────────────────────────────────────────────────────

NVD_LOG4SHELL = {
    "vulnerabilities": [{
        "cve": {
            "id": "CVE-2021-44228",
            "published": "2021-12-10T10:15:09.143",
            "descriptions": [{"lang": "en", "value": "Apache Log4j2 RCE via JNDI lookup."}],
            "references": [
                {"url": "https://attack.mitre.org/techniques/T1190"},
                {"url": "https://logging.apache.org/log4j/2.x/security.html"},
            ],
            "metrics": {
                "cvssMetricV31": [{
                    "cvssData": {
                        "baseScore": 10.0,
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                    }
                }]
            },
        }
    }]
}

EPSS_LOG4SHELL = {
    "status": "OK",
    "data": [{"cve": "CVE-2021-44228", "epss": "0.97528", "percentile": "0.99975"}]
}

KEV_CATALOG = {
    "vulnerabilities": [
        {"cveID": "CVE-2021-44228", "vulnerabilityName": "Log4Shell"},
        {"cveID": "CVE-2017-0144",  "vulnerabilityName": "EternalBlue"},
    ]
}


def _make_http_mock(responses: dict[str, dict]):
    """Create a mock httpx.AsyncClient that returns different responses per URL."""
    async def _get(url, **kwargs):
        m = MagicMock()
        for key, resp_data in responses.items():
            if key in str(url):
                m.json.return_value = resp_data
                m.raise_for_status = MagicMock()
                return m
        m.json.return_value = {}
        m.raise_for_status = MagicMock()
        return m
    mock_client = AsyncMock()
    mock_client.get.side_effect = _get
    return mock_client


# ── fetch_nvd ─────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_fetch_nvd_success():
    svc = VulnEnrichmentService(http_client=_make_http_mock({"nvd.nist.gov": NVD_LOG4SHELL}))
    result = await svc.fetch_nvd("CVE-2021-44228")
    assert result["cvss_v3"] == 10.0
    assert result["cvss_vector"].startswith("CVSS:3.1")
    assert "Log4j2" in result["description"]
    assert result["published_date"] == "2021-12-10T10:15:09.143"


@pytest.mark.asyncio
async def test_fetch_nvd_not_found():
    mock_client = AsyncMock()
    mock_client.get.return_value = MagicMock(
        json=lambda: {"vulnerabilities": []},
        raise_for_status=MagicMock(),
    )
    svc = VulnEnrichmentService(http_client=mock_client)
    result = await svc.fetch_nvd("CVE-9999-99999")
    assert result == {}


@pytest.mark.asyncio
async def test_fetch_nvd_caches_result():
    svc = VulnEnrichmentService(http_client=_make_http_mock({"nvd.nist.gov": NVD_LOG4SHELL}))
    r1 = await svc.fetch_nvd("CVE-2021-44228")
    r2 = await svc.fetch_nvd("CVE-2021-44228")
    # Second call should hit cache — mock.get should only be called once
    assert svc._http.get.call_count == 1
    assert r1 == r2


# ── fetch_epss ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_fetch_epss_success():
    svc = VulnEnrichmentService(http_client=_make_http_mock({"api.first.org": EPSS_LOG4SHELL}))
    result = await svc.fetch_epss("CVE-2021-44228")
    assert result["epss_score"] == pytest.approx(0.97528, rel=1e-3)
    assert result["percentile"] == pytest.approx(0.99975, rel=1e-3)


@pytest.mark.asyncio
async def test_fetch_epss_empty():
    mock_client = AsyncMock()
    mock_client.get.return_value = MagicMock(
        json=lambda: {"data": []},
        raise_for_status=MagicMock(),
    )
    svc = VulnEnrichmentService(http_client=mock_client)
    result = await svc.fetch_epss("CVE-9999-0")
    assert result == {}


# ── check_cisa_kev ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_check_cisa_kev_present():
    svc = VulnEnrichmentService(http_client=_make_http_mock({"cisa.gov": KEV_CATALOG}))
    assert await svc.check_cisa_kev("CVE-2021-44228") is True


@pytest.mark.asyncio
async def test_check_cisa_kev_absent():
    svc = VulnEnrichmentService(http_client=_make_http_mock({"cisa.gov": KEV_CATALOG}))
    assert await svc.check_cisa_kev("CVE-2099-00001") is False


@pytest.mark.asyncio
async def test_check_cisa_kev_case_insensitive():
    svc = VulnEnrichmentService(http_client=_make_http_mock({"cisa.gov": KEV_CATALOG}))
    assert await svc.check_cisa_kev("cve-2017-0144") is True


# ── fetch_mitre_techniques ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_fetch_mitre_known_cve():
    svc = VulnEnrichmentService(http_client=AsyncMock())
    techs = await svc.fetch_mitre_techniques("CVE-2021-44228")
    assert "T1190" in techs


@pytest.mark.asyncio
async def test_fetch_mitre_from_nvd_references():
    svc = VulnEnrichmentService(http_client=_make_http_mock({"nvd.nist.gov": NVD_LOG4SHELL}))
    techs = await svc.fetch_mitre_techniques("CVE-2021-44228")
    # Should find T1190 from the mock NVD reference URL
    assert any(t.startswith("T") for t in techs)


# ── compute_composite_risk ────────────────────────────────────────────────────

def test_max_risk_score():
    svc = VulnEnrichmentService(http_client=AsyncMock())
    # path_depth=0 → depth_n=1.0 (on the target, zero hops), all other inputs maxed
    score = svc.compute_composite_risk(
        cvss=10.0, epss=1.0, kev=True,
        exploit_validated=True, asset_criticality="critical",
        path_depth=0, lateral_reachable_count=50,
    )
    assert score == pytest.approx(1000.0, abs=1.0)


def test_zero_risk_score():
    svc = VulnEnrichmentService(http_client=AsyncMock())
    score = svc.compute_composite_risk(
        cvss=0, epss=0, kev=False,
        exploit_validated=False, asset_criticality="low",
        path_depth=10, lateral_reachable_count=0,
    )
    assert score >= 0
    assert score < 200  # low risk


def test_kev_bonus_increases_score():
    svc = VulnEnrichmentService(http_client=AsyncMock())
    base = svc.compute_composite_risk(cvss=7.0, epss=0.3, kev=False, exploit_validated=False, asset_criticality="medium")
    with_kev = svc.compute_composite_risk(cvss=7.0, epss=0.3, kev=True, exploit_validated=False, asset_criticality="medium")
    assert with_kev > base


def test_risk_score_bounds():
    svc = VulnEnrichmentService(http_client=AsyncMock())
    for cvss in [0, 5.0, 10.0]:
        for kev in [True, False]:
            s = svc.compute_composite_risk(cvss=cvss, epss=0.5, kev=kev,
                                           exploit_validated=True, asset_criticality="high")
            assert 0 <= s <= 1000


# ── enrich (integration of all calls) ────────────────────────────────────────

@pytest.mark.asyncio
async def test_enrich_full():
    combined = {
        "nvd.nist.gov": NVD_LOG4SHELL,
        "api.first.org": EPSS_LOG4SHELL,
        "cisa.gov": KEV_CATALOG,
    }
    svc = VulnEnrichmentService(http_client=_make_http_mock(combined))

    finding = {
        "cve_ids": ["CVE-2021-44228"],
        "title": "Log4Shell",
        "description": None,
        "cvss_score": None,
        "epss_score": None,
        "mitre_techniques": None,
        "exploit_validated": True,
        "evidence": {},
    }

    enriched = await svc.enrich(finding, asset_criticality="critical")

    assert enriched["cvss_score"] == Decimal("10.0")
    assert enriched["epss_score"] is not None and float(enriched["epss_score"]) > 0
    assert enriched["risk_score"] is not None
    assert float(enriched["risk_score"]) > 800   # high risk for KEV + CVSS 10 + critical asset
    assert "enrichment" in enriched["evidence"]
    assert enriched["evidence"]["enrichment"]["kev"] is True


# ── dedup_hash ────────────────────────────────────────────────────────────────

def test_dedup_hash_stable():
    h1 = VulnEnrichmentService.dedup_hash("asset-1", "CVE-2021-44228", 12345)
    h2 = VulnEnrichmentService.dedup_hash("asset-1", "CVE-2021-44228", 12345)
    assert h1 == h2


def test_dedup_hash_case_insensitive_cve():
    h1 = VulnEnrichmentService.dedup_hash("a", "cve-2021-44228", 1)
    h2 = VulnEnrichmentService.dedup_hash("a", "CVE-2021-44228", 1)
    assert h1 == h2


def test_dedup_hash_different_inputs():
    h1 = VulnEnrichmentService.dedup_hash("asset-1", "CVE-2021-44228", 1)
    h2 = VulnEnrichmentService.dedup_hash("asset-2", "CVE-2021-44228", 1)
    assert h1 != h2
