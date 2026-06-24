"""
DetectionCorrelator — matches red-team attack actions against blue-team SIEM
alerts and EDR detections to grade detection coverage.

For each attack action we look for any alert/detection on the *same host* within
a ±window (default 5 min). The action is then graded:
  * prevented — an EDR detection in-window actively blocked it.
  * detected  — a SIEM alert or EDR detection fired (but did not block).
  * missed    — nothing fired.

``compute_coverage`` rolls results into an ATT&CK coverage summary, and
``generate_gap_report`` turns each missed action into a DetectionGap carrying a
ready-to-deploy Sigma rule.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

import structlog

from app.detection.edr import EDRDetection
from app.detection.siem import SIEMAlert
from app.detection.sigma import SigmaRuleGenerator
from app.models.enums import DetectionStatus

logger = structlog.get_logger()

DEFAULT_WINDOW = timedelta(minutes=5)


@dataclass
class AttackAction:
    id: str
    mitre_technique: str | None
    target_ip: str | None
    timestamp: datetime
    target_hostname: str | None = None
    action: str | None = None
    finding_id: str | None = None
    action_detail: dict[str, Any] = field(default_factory=dict)


@dataclass
class DetectionResultDTO:
    attack_action_id: str
    mitre_technique: str | None
    host: str | None
    attack_timestamp: datetime
    status: DetectionStatus
    siem_alerted: bool
    edr_alerted: bool
    detection_latency_sec: int | None
    alert_ids: list[str]
    sigma_recommendation: str | None = None
    finding_id: str | None = None


@dataclass
class DetectionGap:
    mitre_technique: str | None
    host: str | None
    attack_timestamp: datetime
    recommended_sigma_rule: str


def _host_matches(action_host: str | None, alert_host: str | None) -> bool:
    if not action_host or not alert_host:
        return False
    a, b = action_host.lower(), alert_host.lower()
    return a == b or a in b or b in a


class DetectionCorrelator:
    def __init__(self, window: timedelta = DEFAULT_WINDOW, sigma: SigmaRuleGenerator | None = None):
        self._window = window
        self._sigma = sigma or SigmaRuleGenerator()

    # ── correlate ─────────────────────────────────────────────────────────────────

    def correlate(
        self,
        attack_timeline: list[AttackAction],
        siem_alerts: list[SIEMAlert],
        edr_detections: list[EDRDetection],
    ) -> list[DetectionResultDTO]:
        results: list[DetectionResultDTO] = []

        for action in attack_timeline:
            host = action.target_hostname or action.target_ip
            siem_hits = [a for a in siem_alerts if self._in_window(action.timestamp, a.timestamp)
                         and self._host_for(action, a.host)]
            edr_hits = [d for d in edr_detections if self._in_window(action.timestamp, d.timestamp)
                        and self._host_for(action, d.host)]

            prevented = any(d.is_prevented for d in edr_hits)
            siem_alerted = bool(siem_hits)
            edr_alerted = bool(edr_hits)

            if prevented:
                status = DetectionStatus.prevented
            elif siem_alerted or edr_alerted:
                status = DetectionStatus.detected
            else:
                status = DetectionStatus.missed

            alert_ids = [a.id for a in siem_hits] + [d.id for d in edr_hits]
            latency = self._min_latency(action.timestamp, siem_hits, edr_hits)

            sigma = None
            if status == DetectionStatus.missed:
                sigma = self._sigma.generate_sigma_for_technique(
                    action.mitre_technique,
                    {"host": host, "target_ip": action.target_ip, **(action.action_detail or {})},
                )

            results.append(DetectionResultDTO(
                attack_action_id=action.id,
                mitre_technique=action.mitre_technique,
                host=host,
                attack_timestamp=action.timestamp,
                status=status,
                siem_alerted=siem_alerted,
                edr_alerted=edr_alerted,
                detection_latency_sec=latency,
                alert_ids=alert_ids,
                sigma_recommendation=sigma,
                finding_id=action.finding_id,
            ))

        logger.info("detection.correlated", actions=len(attack_timeline), results=len(results))
        return results

    def _in_window(self, attack_ts: datetime, alert_ts: datetime | None) -> bool:
        if alert_ts is None:
            return False
        attack_ts, alert_ts = _aware(attack_ts), _aware(alert_ts)
        return abs(alert_ts - attack_ts) <= self._window

    @staticmethod
    def _host_for(action: AttackAction, alert_host: str | None) -> bool:
        return _host_matches(action.target_hostname, alert_host) or \
            _host_matches(action.target_ip, alert_host)

    @staticmethod
    def _min_latency(attack_ts: datetime, siem_hits, edr_hits) -> int | None:
        times = [h.timestamp for h in (*siem_hits, *edr_hits) if h.timestamp is not None]
        if not times:
            return None
        deltas = [(_aware(t) - _aware(attack_ts)).total_seconds() for t in times]
        # Latency is the soonest non-negative alert; if all are earlier, use abs of closest.
        non_neg = [d for d in deltas if d >= 0]
        chosen = min(non_neg) if non_neg else min(abs(d) for d in deltas)
        return int(chosen)

    # ── compute_coverage ──────────────────────────────────────────────────────────

    def compute_coverage(self, results: list[DetectionResultDTO]) -> dict[str, Any]:
        total = len(results)
        detected = sum(1 for r in results if r.status == DetectionStatus.detected)
        prevented = sum(1 for r in results if r.status == DetectionStatus.prevented)
        missed = sum(1 for r in results if r.status == DetectionStatus.missed)
        covered = detected + prevented
        coverage_pct = round((covered / total) * 100, 1) if total else 0.0

        # Per-technique rollup for the ATT&CK matrix.
        by_technique: dict[str, dict[str, int]] = {}
        for r in results:
            tech = r.mitre_technique or "unknown"
            bucket = by_technique.setdefault(
                tech, {"detected": 0, "prevented": 0, "missed": 0, "total": 0}
            )
            bucket["total"] += 1
            bucket[r.status.value] = bucket.get(r.status.value, 0) + 1
        for tech, b in by_technique.items():
            b["covered"] = b["detected"] + b["prevented"]
            b["status"] = "covered" if b["covered"] > 0 else "gap"

        return {
            "total_actions": total,
            "total_techniques": len(by_technique),
            "detected": detected,
            "prevented": prevented,
            "missed": missed,
            "coverage_pct": coverage_pct,
            "by_technique": by_technique,
        }

    # ── generate_gap_report ───────────────────────────────────────────────────────

    def generate_gap_report(self, missed_results: list[DetectionResultDTO]) -> list[DetectionGap]:
        gaps: list[DetectionGap] = []
        for r in missed_results:
            if r.status != DetectionStatus.missed:
                continue
            rule = r.sigma_recommendation or self._sigma.generate_sigma_for_technique(
                r.mitre_technique, {"host": r.host}
            )
            gaps.append(DetectionGap(
                mitre_technique=r.mitre_technique,
                host=r.host,
                attack_timestamp=r.attack_timestamp,
                recommended_sigma_rule=rule,
            ))
        return gaps


def _aware(dt: datetime) -> datetime:
    """Normalise naive datetimes to UTC so comparisons never raise."""
    from datetime import timezone
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)
