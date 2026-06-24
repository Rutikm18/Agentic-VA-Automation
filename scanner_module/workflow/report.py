"""
report.py — JSON-safe Asset serialization, engagement summary, and the
re-scan delta diff (new/gone hosts, changed ports between two passes).
"""
from __future__ import annotations

from .asset import Asset
from .cache import WorkflowCache


def asset_to_dict(asset: Asset) -> dict:
    return {
        "host": asset.host,
        "aliases": sorted(asset.aliases),
        "last_seen_alive": asset.last_seen_alive.isoformat() if asset.last_seen_alive else None,
        "open_ports": {p: {"status": f.status, "proto": f.proto} for p, f in asset.open_ports.items()},
        "services": asset.services,
        "tls_facts": asset.tls_facts,
        "web_facts": asset.web_facts,
        "smb_state": asset.smb_state,
        "snmp_state": asset.snmp_state,
        "db_facts": asset.db_facts,
        "ai_facts": asset.ai_facts,
        "credential_inventory": asset.credential_inventory,
        "profile": asset.profile,
        "cred_collected": asset.cred_collected,
    }


def engagement_summary(assets: dict[str, Asset], elapsed_sec: float, cache: WorkflowCache) -> dict:
    alive = [a for a in assets.values() if a.last_seen_alive]
    with_open_ports = [a for a in alive if a.open_ports_for_deep_scan()]
    return {
        "hosts_total": len(assets),
        "hosts_alive": len(alive),
        "hosts_with_open_ports": len(with_open_ports),
        "elapsed_sec": round(elapsed_sec, 2),
        "cache_entries": len(cache._store),
    }


def diff_assets(prior: dict[str, Asset], current: dict[str, Asset]) -> dict:
    """re-scan mode's delta report: what changed between two engagements."""
    prior_hosts, current_hosts = set(prior), set(current)
    new_hosts = current_hosts - prior_hosts
    gone_hosts = prior_hosts - current_hosts
    common = prior_hosts & current_hosts

    changed_ports: dict[str, dict] = {}
    for h in common:
        before = {p: f.status for p, f in prior[h].open_ports.items()}
        after = {p: f.status for p, f in current[h].open_ports.items()}
        if before != after:
            changed_ports[h] = {"before": before, "after": after}

    return {
        "new_hosts": sorted(new_hosts),
        "gone_hosts": sorted(gone_hosts),
        "unchanged_hosts": len(common) - len(changed_ports),
        "changed_hosts": sorted(changed_ports),
        "changed_ports": changed_ports,
    }
