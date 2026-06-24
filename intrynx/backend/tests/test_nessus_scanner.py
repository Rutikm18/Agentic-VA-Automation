"""
Unit tests for NessusScanner — all HTTP calls mocked.
"""
from __future__ import annotations

from decimal import Decimal
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.vuln.nessus import NessusScanner
from app.models.enums import FindingSeverity, FindingStatus


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def scanner():
    s = NessusScanner(verify_ssl=False)
    s._base_url = "https://nessus.corp.local:8834"
    s._api_keys = {"access_key": "AKTEST", "secret_key": "SKTEST"}
    return s


def _mock_response(json_data: dict, status_code: int = 200):
    m = MagicMock()
    m.json.return_value = json_data
    m.status_code = status_code
    m.raise_for_status = MagicMock()
    m.content = b"<NessusClientData_v2/>"
    return m


# ── authenticate ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_authenticate_api_key():
    s = NessusScanner()
    await s.authenticate("https://nessus:8834", "mykey", "mysecret")
    assert s._api_keys["access_key"] == "mykey"
    assert s._api_keys["secret_key"] == "mysecret"
    assert s._base_url == "https://nessus:8834"


# ── create_scan ───────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_create_scan(scanner):
    mock_client = AsyncMock()
    mock_client.get.return_value = _mock_response({
        "templates": [{"uuid": "abc-123", "name": "basic network scan", "policy_id": 1}]
    })
    mock_client.post.return_value = _mock_response({"scan": {"id": 42}})

    with patch.object(scanner, "_get_client", return_value=mock_client):
        scan_id = await scanner.create_scan(
            engagement_id="eng-001",
            target_ips=["10.10.10.1", "10.10.10.2"],
            policy_id=1,
        )
    assert scan_id == "42"


@pytest.mark.asyncio
async def test_create_scan_with_credentials(scanner):
    mock_client = AsyncMock()
    mock_client.get.return_value = _mock_response({"templates": [{"uuid": "t1", "name": "basic", "policy_id": 1}]})
    mock_client.post.return_value = _mock_response({"scan": {"id": 99}})

    with patch.object(scanner, "_get_client", return_value=mock_client):
        scan_id = await scanner.create_scan(
            "eng-002", ["10.0.0.1"], 1,
            credentials={"windows": {"domain": "corp.local", "username": "admin"}}
        )
    # Verify credentials were passed in the POST body
    call_kwargs = mock_client.post.call_args
    body = call_kwargs[1]["json"] if "json" in call_kwargs[1] else call_kwargs[0][1]
    assert "credentials" in body
    assert scan_id == "99"


# ── launch_scan ───────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_launch_scan(scanner):
    mock_client = AsyncMock()
    mock_client.post.return_value = _mock_response({"scan_uuid": "uuid-launch-001"})

    with patch.object(scanner, "_get_client", return_value=mock_client):
        scan_uuid = await scanner.launch_scan("42")

    assert scan_uuid == "uuid-launch-001"
    mock_client.post.assert_called_once_with("/scans/42/launch")


# ── poll_status ───────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_poll_status_running(scanner):
    mock_client = AsyncMock()
    mock_client.get.return_value = _mock_response({
        "info": {"status": "running", "hm_scanned": 5, "hm_total": 10, "hostcount": 3}
    })

    with patch.object(scanner, "_get_client", return_value=mock_client):
        result = await scanner.poll_status("42")

    assert result["status"] == "running"
    assert result["progress_percent"] == 50
    assert result["host_count"] == 3


@pytest.mark.asyncio
async def test_poll_status_completed(scanner):
    mock_client = AsyncMock()
    mock_client.get.return_value = _mock_response({
        "info": {"status": "completed", "hm_scanned": 10, "hm_total": 10, "hostcount": 10}
    })

    with patch.object(scanner, "_get_client", return_value=mock_client):
        result = await scanner.poll_status("42")

    assert result["status"] == "completed"
    assert result["progress_percent"] == 100


# ── map_finding ───────────────────────────────────────────────────────────────

def test_map_finding_critical(scanner):
    raw = {
        "plugin_id": 12345,
        "plugin_name": "Apache Log4Shell RCE",
        "severity": 4,
        "hostname": "10.10.10.5",
        "plugin_detail": {
            "pluginattributes": {
                "description": "A critical RCE vulnerability in Log4j.",
                "solution": "Upgrade to Log4j 2.17.1+",
                "synopsis": "Apache Log4j2 Remote Code Execution",
                "risk_information": {
                    "cvss3_base_score": "10.0",
                    "cvss3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                },
                "ref_information": {
                    "ref": [{"@name": "CVE", "#text": "CVE-2021-44228,CVE-2021-45046"}]
                },
                "vuln_information": {"exploit_available": True},
            }
        },
    }
    f = scanner.map_finding(raw)
    assert f["severity"] == FindingSeverity.critical
    assert f["title"] == "Apache Log4j2 Remote Code Execution"
    assert "CVE-2021-44228" in f["cve_ids"]
    assert "CVE-2021-45046" in f["cve_ids"]
    assert f["cvss_score"] == Decimal("10.0")
    assert f["exploitable"] is True
    assert f["status"] == FindingStatus.open
    assert f["evidence"]["plugin_id"] == 12345
    assert f["evidence"]["hostname"] == "10.10.10.5"


def test_map_finding_info_severity(scanner):
    raw = {"plugin_id": 1, "plugin_name": "Open Port", "severity": 0, "hostname": "10.0.0.1", "plugin_detail": {}}
    f = scanner.map_finding(raw)
    assert f["severity"] == FindingSeverity.info
    assert f["cve_ids"] == []


def test_map_finding_no_cvss(scanner):
    raw = {
        "plugin_id": 99, "plugin_name": "Test", "severity": 2, "hostname": "host",
        "plugin_detail": {"pluginattributes": {"risk_information": {}, "ref_information": {}}},
    }
    f = scanner.map_finding(raw)
    assert f["cvss_score"] is None
    assert f["severity"] == FindingSeverity.medium
