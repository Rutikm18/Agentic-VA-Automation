"""
Unit tests for the detection validation engine (Prompt 7).

SIEM/EDR HTTP is mocked at the response-parsing layer (no live Splunk/Sentinel/
CrowdStrike). Correlation, coverage, Sigma generation, and gap reporting are
pure-logic and fully covered. An integration test against a local Splunk
instance is provided but skipped unless --splunk-url is given.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
import yaml

from app.detection.correlator import AttackAction, DetectionCorrelator, DetectionGap
from app.detection.edr import (
    CrowdStrikeFalcon,
    EDRDetection,
    MicrosoftDefender,
    SentinelOne,
    build_edr_engine,
)
from app.detection.siem import (
    ElasticSIEM,
    SIEMAlert,
    SplunkSIEM,
    SentinelSIEM,
    build_siem_engine,
)
from app.detection.sigma import SigmaRuleGenerator
from app.models.enums import DetectionStatus

T0 = datetime(2026, 6, 11, 12, 0, 0, tzinfo=timezone.utc)


def _action(aid, tech, host, offset_min=0, ip="10.0.0.5", detail=None):
    return AttackAction(
        id=aid, mitre_technique=tech, target_ip=ip,
        timestamp=T0 + timedelta(minutes=offset_min), target_hostname=host,
        action="test", action_detail=detail or {},
    )


# ═══════════════════════════════════════════════════════════════════════════════
# DetectionCorrelator
# ═══════════════════════════════════════════════════════════════════════════════

class TestDetectionCorrelator:

    def setup_method(self):
        self.c = DetectionCorrelator()

    def test_detected_by_siem(self):
        actions = [_action("a1", "T1190", "web01")]
        siem = [SIEMAlert("s1", "RCE", "web01", T0 + timedelta(minutes=2))]
        res = self.c.correlate(actions, siem, [])
        assert res[0].status == DetectionStatus.detected
        assert res[0].siem_alerted is True
        assert res[0].detection_latency_sec == 120

    def test_prevented_by_edr(self):
        actions = [_action("a1", "T1003", "ws07")]
        edr = [EDRDetection("e1", "LSASS", "ws07", T0 + timedelta(minutes=1), action="blocked")]
        res = self.c.correlate(actions, [], edr)
        assert res[0].status == DetectionStatus.prevented
        assert res[0].edr_alerted is True

    def test_detected_when_edr_not_blocking(self):
        actions = [_action("a1", "T1003", "ws07")]
        edr = [EDRDetection("e1", "LSASS", "ws07", T0 + timedelta(minutes=1), action="detected")]
        res = self.c.correlate(actions, [], edr)
        assert res[0].status == DetectionStatus.detected

    def test_missed_when_nothing(self):
        res = self.c.correlate([_action("a1", "T1558.003", "dc01")], [], [])
        assert res[0].status == DetectionStatus.missed
        assert res[0].sigma_recommendation is not None

    def test_out_of_window_is_missed(self):
        actions = [_action("a1", "T1190", "web01")]
        siem = [SIEMAlert("s1", "RCE", "web01", T0 + timedelta(minutes=30))]  # outside ±5m
        res = self.c.correlate(actions, siem, [])
        assert res[0].status == DetectionStatus.missed

    def test_wrong_host_is_missed(self):
        actions = [_action("a1", "T1190", "web01")]
        siem = [SIEMAlert("s1", "RCE", "db99", T0 + timedelta(minutes=1))]
        res = self.c.correlate(actions, siem, [])
        assert res[0].status == DetectionStatus.missed

    def test_host_match_by_ip(self):
        actions = [_action("a1", "T1190", None, ip="10.0.0.5")]
        siem = [SIEMAlert("s1", "RCE", "10.0.0.5", T0 + timedelta(minutes=1))]
        res = self.c.correlate(actions, siem, [])
        assert res[0].status == DetectionStatus.detected

    def test_naive_timestamp_does_not_crash(self):
        naive_action = AttackAction("a1", "T1190", "10.0.0.5",
                                    datetime(2026, 6, 11, 12, 0, 0), target_hostname="web01")
        siem = [SIEMAlert("s1", "RCE", "web01", datetime(2026, 6, 11, 12, 1, 0))]
        res = self.c.correlate([naive_action], siem, [])
        assert res[0].status == DetectionStatus.detected

    def test_compute_coverage(self):
        actions = [_action("a1", "T1190", "web01"), _action("a2", "T1558.003", "dc01"),
                   _action("a3", "T1003", "ws07")]
        siem = [SIEMAlert("s1", "RCE", "web01", T0 + timedelta(minutes=1))]
        edr = [EDRDetection("e1", "LSASS", "ws07", T0 + timedelta(minutes=1), action="blocked")]
        res = self.c.correlate(actions, siem, edr)
        cov = self.c.compute_coverage(res)
        assert cov["total_actions"] == 3
        assert cov["total_techniques"] == 3
        assert cov["detected"] == 1
        assert cov["prevented"] == 1
        assert cov["missed"] == 1
        assert cov["coverage_pct"] == pytest.approx(66.7, abs=0.1)
        assert cov["by_technique"]["T1558.003"]["status"] == "gap"
        assert cov["by_technique"]["T1190"]["status"] == "covered"

    def test_coverage_empty(self):
        cov = self.c.compute_coverage([])
        assert cov["total_actions"] == 0
        assert cov["coverage_pct"] == 0.0

    def test_generate_gap_report(self):
        res = self.c.correlate([_action("a1", "T1558.003", "dc01")], [], [])
        gaps = self.c.generate_gap_report(res)
        assert len(gaps) == 1
        assert isinstance(gaps[0], DetectionGap)
        assert gaps[0].mitre_technique == "T1558.003"
        assert "$krb" not in gaps[0].recommended_sigma_rule  # it's a sigma rule, not a hash
        assert "detection" in gaps[0].recommended_sigma_rule

    def test_gap_report_ignores_detected(self):
        actions = [_action("a1", "T1190", "web01")]
        siem = [SIEMAlert("s1", "RCE", "web01", T0 + timedelta(minutes=1))]
        res = self.c.correlate(actions, siem, [])
        assert self.c.generate_gap_report(res) == []


# ═══════════════════════════════════════════════════════════════════════════════
# SigmaRuleGenerator
# ═══════════════════════════════════════════════════════════════════════════════

class TestSigmaRuleGenerator:

    def setup_method(self):
        self.gen = SigmaRuleGenerator()

    def test_known_technique_template(self):
        rule = self.gen.generate_sigma_for_technique("T1558.003", {"host": "dc01"})
        doc = yaml.safe_load(rule)
        assert doc["detection"]["selection"]["EventID"] == 4769
        assert doc["logsource"]["service"] == "security"
        assert "attack.t1558.003" in doc["tags"]

    def test_subtechnique_falls_back_to_parent(self):
        # T1059.001 has no entry but T1059 does.
        rule = self.gen.generate_sigma_for_technique("T1059.001", {})
        doc = yaml.safe_load(rule)
        assert doc["logsource"]["category"] == "process_creation"

    def test_unknown_technique_uses_generic(self):
        rule = self.gen.generate_sigma_for_technique("T9999", {})
        doc = yaml.safe_load(rule)
        assert "detection" in doc and "logsource" in doc

    def test_evidence_customises_rule(self):
        rule = self.gen.generate_sigma_for_technique("T1003", {"host": "ws07", "process": "mimikatz.exe"})
        doc = yaml.safe_load(rule)
        sel = doc["detection"]["selection"]
        assert sel.get("process") == "mimikatz.exe"
        assert "ws07" in str(sel.get("dest_host|contains"))

    def test_output_is_valid_yaml_and_stable_id(self):
        r1 = self.gen.generate_sigma_for_technique("T1190", {"host": "web01"})
        r2 = self.gen.generate_sigma_for_technique("T1190", {"host": "web01"})
        assert yaml.safe_load(r1)["id"] == yaml.safe_load(r2)["id"]  # deterministic


# ═══════════════════════════════════════════════════════════════════════════════
# SIEM engines — response parsing (mocked payloads)
# ═══════════════════════════════════════════════════════════════════════════════

class TestSIEMParsing:

    def test_splunk_parse(self):
        engine = SplunkSIEM({"base_url": "https://splunk", "token": "x"})
        body = (
            '{"result":{"event_id":"E1","search_name":"Notable","host":"web01",'
            '"_time":"2026-06-11T12:01:00Z","severity":"high"}}\n'
            'not-json-line\n'
        )
        alerts = engine.parse_response(body)
        assert len(alerts) == 1
        assert alerts[0].host == "web01"
        assert alerts[0].timestamp is not None

    def test_splunk_spl_includes_host_and_time(self):
        engine = SplunkSIEM({"base_url": "https://splunk", "token": "x", "index": "sec"})
        spl = engine.build_spl(T0, T0 + timedelta(minutes=10), "web01")
        assert "index=sec" in spl and "web01" in spl and "earliest=" in spl

    def test_sentinel_parse(self):
        engine = SentinelSIEM({"workspace_id": "w", "token": "x"})
        data = {"tables": [{
            "columns": [{"name": "SystemAlertId"}, {"name": "AlertName"},
                        {"name": "Computer"}, {"name": "TimeGenerated"}, {"name": "AlertSeverity"}],
            "rows": [["A1", "Suspicious", "dc01", "2026-06-11T12:01:00Z", "High"]],
        }]}
        alerts = engine.parse_response(data)
        assert alerts[0].host == "dc01"
        assert alerts[0].title == "Suspicious"

    def test_elastic_parse(self):
        engine = ElasticSIEM({"base_url": "https://es"})
        data = {"hits": {"hits": [{
            "_id": "H1",
            "_source": {
                "@timestamp": "2026-06-11T12:01:00Z",
                "host": {"name": "ws07"},
                "kibana": {"alert": {"rule": {"name": "EQL rule"}, "severity": "high"}},
                "threat": [{"technique": [{"id": "T1003"}]}],
            },
        }]}}
        alerts = engine.parse_response(data)
        assert alerts[0].host == "ws07"
        assert alerts[0].technique == "T1003"

    def test_factory(self):
        assert isinstance(build_siem_engine("splunk", {}), SplunkSIEM)
        assert isinstance(build_siem_engine("SENTINEL", {}), SentinelSIEM)
        assert build_siem_engine("bogus", {}) is None


# ═══════════════════════════════════════════════════════════════════════════════
# EDR engines — response parsing (mocked payloads)
# ═══════════════════════════════════════════════════════════════════════════════

class TestEDRParsing:

    def test_crowdstrike_parse(self):
        engine = CrowdStrikeFalcon({"token": "x"})
        data = {"resources": [{
            "detection_id": "D1",
            "created_timestamp": "2026-06-11T12:01:00Z",
            "device": {"hostname": "ws07"},
            "max_severity_displayname": "High",
            "behaviors": [{"display_name": "Credential Theft", "technique_id": "T1003",
                           "pattern_disposition_description": "Prevented"}],
        }]}
        dets = engine.parse_response(data)
        assert dets[0].host == "ws07"
        assert dets[0].is_prevented is True

    def test_defender_parse_and_host_filter(self):
        engine = MicrosoftDefender({"token": "x"})
        data = {"value": [{
            "id": "AL1", "title": "Mimikatz", "severity": "high",
            "createdDateTime": "2026-06-11T12:01:00Z",
            "mitreTechniques": ["T1003"],
            "determination": "detected",
            "evidence": [{"@odata.type": "#microsoft.graph.security.deviceEvidence",
                          "deviceDnsName": "ws07.corp.local"}],
        }]}
        dets = engine.parse_response(data, host_filter="ws07")
        assert len(dets) == 1
        assert dets[0].technique == "T1003"
        # filter to a different host removes it
        assert engine.parse_response(data, host_filter="db99") == []

    def test_sentinelone_parse(self):
        engine = SentinelOne({"base_url": "https://s1", "token": "x"})
        data = {"data": [{
            "id": "T1",
            "agentRealtimeInfo": {"agentComputerName": "ws07"},
            "threatInfo": {"threatName": "Trojan", "createdAt": "2026-06-11T12:01:00Z",
                           "mitigationStatus": "mitigated", "confidenceLevel": "malicious"},
        }]}
        dets = engine.parse_response(data)
        assert dets[0].host == "ws07"
        assert dets[0].is_prevented is True  # 'mitigated' is a prevention action

    def test_factory(self):
        assert isinstance(build_edr_engine("crowdstrike", {}), CrowdStrikeFalcon)
        assert isinstance(build_edr_engine("Defender", {}), MicrosoftDefender)
        assert build_edr_engine("nope", {}) is None


# ═══════════════════════════════════════════════════════════════════════════════
# Integration (skipped unless --splunk-url provided)
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.mark.integration
class TestSplunkIntegration:

    @pytest.fixture(autouse=True)
    def skip_without_flag(self, request):
        url = request.config.getoption("--splunk-url", default=None, skip=True)
        if not url:
            pytest.skip("--splunk-url not provided (integration test)")
        self.url = url

    @pytest.mark.asyncio
    async def test_live_query(self):
        engine = SplunkSIEM({"base_url": self.url, "token": "changeme", "verify_ssl": False})
        alerts = await engine.query_alerts(T0 - timedelta(days=1), T0)
        assert isinstance(alerts, list)


def pytest_addoption(parser):
    try:
        parser.addoption("--splunk-url", action="store", default=None,
                         help="Splunk base URL for integration tests")
    except ValueError:
        pass
