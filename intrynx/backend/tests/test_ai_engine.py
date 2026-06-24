"""
Unit tests for the AI engine (Prompt 8).

The Anthropic client is mocked (no API key, no network). XGBoost/SHAP are
optional, so prioritiser tests exercise the deterministic fallback path that
runs without the ML libraries installed.
"""
from __future__ import annotations

import uuid
from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

import app.ai.llm_report as llm_mod
from app.ai.hallucination import HallucinationGuard
from app.ai.llm_report import LLMReportGenerator, LLMUnavailableError
from app.ai.prioritizer import VulnPrioritizer, extract_features
from app.models.enums import ReviewStatus


def _finding(**kw):
    defaults = dict(
        id=uuid.uuid4(), engagement_id=uuid.uuid4(), asset_id=None,
        title="SQL injection", description="...", severity=SimpleNamespace(value="critical"),
        cvss_score=Decimal("9.1"), epss_score=Decimal("0.5"), cve_ids=["CVE-2021-44228"],
        mitre_techniques=["T1190"], exploit_validated=True, remediation="patch",
        evidence={"kev": True}, risk_score=Decimal("800"),
    )
    defaults.update(kw)
    return SimpleNamespace(**defaults)


def _asset(criticality="critical"):
    return SimpleNamespace(
        id=uuid.uuid4(), hostname="db01", ip_address="10.0.0.5",
        criticality=SimpleNamespace(value=criticality),
    )


# ═══════════════════════════════════════════════════════════════════════════════
# VulnPrioritizer (fallback path)
# ═══════════════════════════════════════════════════════════════════════════════

class TestVulnPrioritizer:

    def setup_method(self):
        self.p = VulnPrioritizer()

    def test_starts_untrained(self):
        assert self.p.is_trained is False

    def test_extract_features_order_and_values(self):
        feats = extract_features(_finding(), _asset("critical"), {"lateral_reachable_count": 10, "days_since_last_patch": 90})
        assert len(feats) == 7
        cvss, epss, kev, exploit, crit, lateral, days = feats
        assert cvss == 9.1
        assert epss == 0.5
        assert kev == 1.0
        assert exploit == 1.0
        assert crit == 1.0          # critical
        assert lateral == 10.0
        assert days == 90.0

    def test_predict_priority_uses_fallback_when_untrained(self):
        score = self.p.predict_priority(_finding(), _asset("critical"),
                                        {"lateral_reachable_count": 25, "days_since_last_patch": 365})
        assert 0.0 <= score <= 1000.0
        assert score > 0

    def test_higher_cvss_scores_higher(self):
        low = self.p.predict_priority(_finding(cvss_score=Decimal("2.0"), evidence={}, exploit_validated=False), _asset("low"))
        high = self.p.predict_priority(_finding(cvss_score=Decimal("9.8")), _asset("critical"))
        assert high > low

    def test_explain_prediction_fallback_shape(self):
        exp = self.p.explain_prediction(_finding(), _asset())
        assert exp["method"] == "weighted_formula"
        assert set(exp["contributions"]) == {
            "cvss", "epss", "kev_flag", "exploit_validated",
            "asset_criticality", "lateral_reachable_count", "days_since_last_patch",
        }
        # contributions sum to the score
        assert round(sum(exp["contributions"].values()), 2) == pytest.approx(exp["score"], abs=0.5)

    def test_fallback_score_capped(self):
        feats = [10, 1.0, 1.0, 1.0, 1.0, 999, 99999]
        assert self.p.fallback_score(feats) <= 1000.0

    def test_train_without_xgboost_raises(self):
        import app.ai.prioritizer as pm
        if pm._HAS_XGB:
            pytest.skip("xgboost installed — fallback-raise path not applicable")
        with pytest.raises(RuntimeError):
            self.p.train(MagicMock())


# ═══════════════════════════════════════════════════════════════════════════════
# HallucinationGuard
# ═══════════════════════════════════════════════════════════════════════════════

class TestHallucinationGuard:

    def setup_method(self):
        self.g = HallucinationGuard()

    def test_cve_invention_flagged(self):
        res = self.g.validate_cve_claims(
            "We found CVE-2021-44228 and also CVE-2099-00001.",
            ["CVE-2021-44228"],
        )
        assert res["valid"] is False
        assert "CVE-2099-00001" in res["invented"]

    def test_cve_all_known_valid(self):
        res = self.g.validate_cve_claims("CVE-2021-44228 is present.", ["CVE-2021-44228"])
        assert res["valid"] is True

    def test_cvss_mismatch_flagged(self):
        res = self.g.validate_cvss_scores("The CVSS score is 7.5.", {"CVE-x": 9.1})
        assert res["valid"] is False
        assert 7.5 in res["mismatched"]

    def test_cvss_match_passes(self):
        res = self.g.validate_cvss_scores("CVSS: 9.1 (critical)", {"CVE-x": 9.1})
        assert res["valid"] is True

    def test_destructive_command_flagged(self):
        res = self.g.validate_remediation_commands("Run `rm -rf /` to clean up.")
        assert res["valid"] is False
        assert res["flagged_commands"]

    def test_drop_table_flagged(self):
        res = self.g.validate_remediation_commands("Execute DROP TABLE users; to remove.")
        assert res["valid"] is False

    def test_safe_remediation_passes(self):
        res = self.g.validate_remediation_commands("Update the package: apt-get install --only-upgrade openssl.")
        assert res["valid"] is True

    def test_validate_aggregate_confidence(self):
        verdict = self.g.validate(
            "Patch CVE-2099-00001 and run rm -rf /tmp/x.",
            actual_cve_ids=["CVE-2021-44228"], actual_scores={}, check_commands=True,
        )
        assert verdict["valid"] is False
        assert len(verdict["issues"]) >= 2
        assert verdict["confidence"] < 1.0

    def test_validate_clean_text(self):
        verdict = self.g.validate(
            "CVE-2021-44228 has a CVSS of 9.1. Apply the vendor patch.",
            actual_cve_ids=["CVE-2021-44228"], actual_scores={"CVE-2021-44228": 9.1},
        )
        assert verdict["valid"] is True
        assert verdict["confidence"] == 1.0


# ═══════════════════════════════════════════════════════════════════════════════
# LLMReportGenerator (mocked Anthropic client)
# ═══════════════════════════════════════════════════════════════════════════════

def _resp(text: str):
    block = SimpleNamespace(type="text", text=text)
    return SimpleNamespace(content=[block])


def _mock_db():
    db = MagicMock()
    db.add = MagicMock()
    db.flush = AsyncMock()
    return db


class TestLLMReportGenerator:

    @pytest.mark.asyncio
    async def test_executive_summary_persists_pending(self):
        client = MagicMock()
        client.messages = MagicMock()
        client.messages.create = AsyncMock(return_value=_resp("Executive summary text."))
        db = _mock_db()
        gen = LLMReportGenerator(db, client=client)

        summary = {
            "engagement_id": str(uuid.uuid4()),
            "engagement_name": "Q2 Test",
            "total_findings": 5,
            "severity_counts": {"critical": 2, "high": 3},
            "top_critical": [{"title": "RCE", "cve_ids": ["CVE-2021-44228"], "cvss_score": 9.8}],
            "attack_path_count": 2, "shortest_path_hops": 2, "detection_coverage_pct": 66.7,
        }
        row = await gen.generate_executive_summary(summary)

        assert row.output == "Executive summary text."
        assert row.output_type == "executive_summary"
        assert row.review_status == ReviewStatus.pending
        assert row.validation is not None
        assert len(row.prompt_hash) == 64
        db.add.assert_called_once()

    @pytest.mark.asyncio
    async def test_technical_finding_runs_guard(self):
        # LLM invents a CVE not in the finding → validation should flag it.
        client = MagicMock()
        client.messages = MagicMock()
        client.messages.create = AsyncMock(
            return_value=_resp("This relates to CVE-2099-00001, a fake one."))
        gen = LLMReportGenerator(_mock_db(), client=client)
        row = await gen.generate_technical_finding(_finding(), _asset(), "whoami output")
        assert row.validation["valid"] is False
        assert any("CVE-2099-00001" in i for i in row.validation["issues"])

    @pytest.mark.asyncio
    async def test_unavailable_without_client(self, monkeypatch):
        # No injected client and no API key → available False, raises on generate.
        monkeypatch.setattr(llm_mod, "_HAS_ANTHROPIC", False)
        gen = LLMReportGenerator(_mock_db(), client=None)
        assert gen.available is False
        with pytest.raises(LLMUnavailableError):
            await gen.generate_remediation_steps(_finding())

    @pytest.mark.asyncio
    async def test_complete_retries_then_succeeds(self, monkeypatch):
        class _Transient(Exception):
            pass
        monkeypatch.setattr(llm_mod, "RateLimitError", _Transient)
        monkeypatch.setattr(llm_mod, "APIConnectionError", _Transient)
        monkeypatch.setattr(llm_mod.asyncio, "sleep", AsyncMock())

        client = MagicMock()
        client.messages = MagicMock()
        client.messages.create = AsyncMock(side_effect=[_Transient("429"), _resp("ok after retry")])
        gen = LLMReportGenerator(_mock_db(), client=client)

        text = await gen._complete("hello")
        assert text == "ok after retry"
        assert client.messages.create.await_count == 2

    @pytest.mark.asyncio
    async def test_detection_rule_explanation(self):
        client = MagicMock()
        client.messages = MagicMock()
        client.messages.create = AsyncMock(return_value=_resp("This rule detects Kerberoasting."))
        gen = LLMReportGenerator(_mock_db(), client=client)
        row = await gen.generate_detection_rule_explanation(
            "detection:\n  selection:\n    EventID: 4769", "T1558.003", uuid.uuid4()
        )
        assert row.output_type == "detection_rule_explanation"
        assert row.review_status == ReviewStatus.pending
