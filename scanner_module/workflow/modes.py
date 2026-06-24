"""
modes.py — engagement mode configurations. Each mode is a thin config that
tunes run_engagement()'s behavior; gates.py/cache.py never special-case a
mode by name — modes only set the few knobs (stop_after_banner,
service_filter, force_recheck_after) those modules already understand.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

VALID_SERVICES = {"tls", "web", "smb", "db", "mcp_ai", "udp"}


@dataclass
class EngagementMode:
    name: str
    stop_after_banner: bool
    service_filter: set[str] | None
    force_recheck_after: timedelta | None
    requires_prior_engagement: bool = False


def triage() -> EngagementMode:
    """Discovery + ports + banner only — no deep dives, no credentials."""
    return EngagementMode("triage", stop_after_banner=True,
                          service_filter=None, force_recheck_after=None)


def assessment() -> EngagementMode:
    """Full funnel, every branch the profile allows."""
    return EngagementMode("assessment", stop_after_banner=False,
                          service_filter=None, force_recheck_after=None)


def service_specific(services: set[str]) -> EngagementMode:
    if not services <= VALID_SERVICES:
        raise ValueError(f"unknown service(s): {services - VALID_SERVICES}; valid: {VALID_SERVICES}")
    return EngagementMode("service-specific", stop_after_banner=False,
                          service_filter=services, force_recheck_after=None)


def re_scan(recheck_older_than: timedelta) -> EngagementMode:
    """Loads a prior engagement's cache; only facts older than
    recheck_older_than get re-probed (deterministic ones included — a
    service really could have changed since last time), everything fresher
    is reused as-is."""
    return EngagementMode("re-scan", stop_after_banner=False,
                          service_filter=None, force_recheck_after=recheck_older_than,
                          requires_prior_engagement=True)


MODE_FACTORY = {
    "triage": lambda **kw: triage(),
    "assessment": lambda **kw: assessment(),
    "service-specific": lambda **kw: service_specific(kw["services"]),
    "re-scan": lambda **kw: re_scan(kw["recheck_older_than"]),
}
