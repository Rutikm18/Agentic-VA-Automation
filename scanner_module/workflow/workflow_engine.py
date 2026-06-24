"""
workflow_engine.py — the async DAG executor. Loops through gates, checks
preconditions (gates.py), invokes the REAL scanner_module classes with
their real constructor signatures, merges results into Asset (asset.py)
and the cache (cache.py), and consults router.py for dynamic Gate-5
branch routing.

Every scanner is invoked via its real `scan_target(host) -> list[ScanResult]`
method directly (not its `.run(targets, writer)` fan-out helper) so this
engine can make per-host gating decisions between stages — `.run()`'s
internal asyncio.create_task fan-out has no hook for that. This means the
workflow engine, not BaseScanner, owns concurrency-across-hosts; each gate
below still scans its target list with bounded concurrency via
asyncio.gather over scan_target calls.

This module imports scanner_module's existing scanner/* classes as-is —
nothing in scanner/ is modified.
"""
from __future__ import annotations

import asyncio
from datetime import timedelta

from scanner.scanner_base import ScanResult, ScopeGuard
from scanner.host_discovery import HostDiscoveryScanner
from scanner.port_scanner import PortScanner
from scanner.service_banner import ServiceBannerScanner
from scanner.tls_scanner import TLSScanner
from scanner.web_scanner import WebScanner
from scanner.smb_scanner import SMBScanner
from scanner.snmp_scanner import SNMPScanner
from scanner.db_scanner import DBScanner, DEFAULT_DB_PORTS
from scanner.mcp_ai_scanner import MCPAIScanner
from scanner.udp_scanner import UDPScanner
from scanner.passive_collector import PassiveCollector
from scanner.ssh_collector import SSHCollector
from scanner.windows_collector import WindowsCollector

from .asset import Asset
from .cache import WorkflowCache
from .gates import (
    PROFILE_PORTS, TLS_PORTS, WEB_PORTS, SMB_PORTS, DB_PORTS, AI_PORTS, UDP_PORTS,
    gate_0_is_passive_profile, gate_2_host_discovery, gate_3_port_scan,
    gate_4_service_banner, gate_5_branch_eligible, gate_6_credentialed_collection,
)
from .router import route_branches


async def _gather_per_host(scanner, hosts: list[str]) -> list[ScanResult]:
    """Runs scanner.scan_target(host) across hosts concurrently; the
    scanner's own RateLimiter/Semaphore (set up in its constructor) still
    bounds in-flight work, so this gather doesn't bypass any throttling.
    """
    if not hosts:
        return []
    batches = await asyncio.gather(*(scanner.scan_target(h) for h in hosts))
    return [r for batch in batches for r in batch]


def _split_cached(cache: WorkflowCache, host: str, candidate_ports: list[int],
                  scanner_name: str, force_recheck_after: timedelta | None = None
                  ) -> tuple[list[int], list[ScanResult]]:
    """Splits candidate_ports into (ports that actually need a fresh probe,
    ScanResults that can be reused from cache) — the mechanism that makes
    deterministic facts collected once per engagement, not once per gate
    pass. force_recheck_after lets re-scan mode override even deterministic
    entries once they're old enough (see cache.py's should_recheck).
    """
    to_scan, reused = [], []
    for port in candidate_ports:
        if cache.should_recheck(host, port, scanner_name, force_recheck_after=force_recheck_after):
            to_scan.append(port)
        else:
            reused.append(cache.get(host, port, scanner_name).result)
    return to_scan, reused


class _Sink:
    """In-memory ResultWriter stand-in — PassiveCollector/SSHCollector/
    WindowsCollector are NOT BaseScanner subclasses (confirmed by reading
    each directly): they only expose .run(writer) / .run(targets, writer),
    never .scan_target(), so they can't be driven the same way the
    BaseScanner-derived scanners above are. This sink lets the engine
    capture their output the same way without writing to disk.
    """
    def __init__(self):
        self.results: list[ScanResult] = []
    def write(self, r: ScanResult):
        self.results.append(r)
    def close(self):
        pass


async def _run_passive(scope: ScopeGuard, listen_seconds: float) -> list[ScanResult]:
    collector = PassiveCollector(scope, listen_seconds=listen_seconds)
    sink = _Sink()
    await collector.run(sink)
    return sink.results


async def run_engagement(targets: list[str], scope: ScopeGuard, *, profile: str = "it",
                         rate: float = 200.0, concurrency: int = 100, timeout: float = 3.0,
                         disc_timeout: float = 1.5,
                         cache: WorkflowCache | None = None,
                         assets: dict[str, Asset] | None = None,
                         service_filter: set[str] | None = None,
                         stop_after_banner: bool = False,
                         force_recheck_after: timedelta | None = None,
                         ssh_creds: dict | None = None, win_creds: dict | None = None,
                         passive_listen_seconds: float = 60.0) -> dict[str, Asset]:
    """Runs gates 0/2-6 (in order) across `targets`, mutating and returning
    the Asset dict. Pass a pre-loaded `assets`/`cache` (e.g. from a prior
    engagement's JSONL) to get re-scan/delta behavior for free — gates and
    cache.should_recheck() naturally skip work that's still fresh.
    """
    cache = cache or WorkflowCache()
    assets = assets if assets is not None else {t: Asset(host=t, profile=profile) for t in targets}
    for t in targets:
        assets.setdefault(t, Asset(host=t, profile=profile))

    # --- Gate 0: OT passive-only hard stop ------------------------------
    if gate_0_is_passive_profile(profile):
        for r in await _run_passive(scope, passive_listen_seconds):
            assets.setdefault(r.target, Asset(host=r.target, profile=profile)).merge_result(r)
            cache.put(r)
        return assets

    # --- Gate 2: host discovery (per-host precondition) -----------------
    disc_targets = [t for t in targets if gate_2_host_discovery(assets[t], profile)]
    if disc_targets:
        disc = HostDiscoveryScanner(scope, rate=rate, concurrency=concurrency, timeout=disc_timeout)
        for r in await _gather_per_host(disc, disc_targets):
            assets[r.target].merge_result(r)
            cache.put(r)

    live_hosts = [t for t in targets if assets[t].last_seen_alive is not None]

    # --- Gate 3: port scan ------------------------------------------------
    port_targets = [t for t in live_hosts if gate_3_port_scan(assets[t], profile)]
    if port_targets:
        ports = PROFILE_PORTS.get(profile, [])
        scanner = PortScanner(scope, ports=ports, rate=rate, concurrency=concurrency, timeout=timeout)
        for r in await _gather_per_host(scanner, port_targets):
            assets[r.target].merge_result(r)
            cache.put(r)

    # --- Gate 4: service banner ------------------------------------------
    for host in live_hosts:
        asset = assets[host]
        if not gate_4_service_banner(asset):
            continue
        candidate_ports = sorted(asset.open_ports_for_deep_scan())
        to_scan, reused = _split_cached(cache, host, candidate_ports, "service_banner", force_recheck_after)
        for r in reused:
            asset.merge_result(r)
        if to_scan:
            banner = ServiceBannerScanner(scope, ports=to_scan, rate=rate, concurrency=concurrency, timeout=timeout)
            for r in await banner.scan_target(host):
                asset.merge_result(r)
                cache.put(r)

    if stop_after_banner:
        return assets  # triage mode: discovery + ports + banner only

    # --- Gate 5: dynamic routing + deep-scan branches ---------------------
    for host in live_hosts:
        asset = assets[host]
        routed = route_branches(asset)

        tls_dynamic = {p for p, b in routed.items() if "tls" in b}
        web_dynamic = {p for p, b in routed.items() if "web" in b}

        if gate_5_branch_eligible("tls", asset, profile, service_filter, bool(tls_dynamic)):
            ports = sorted((asset.open_ports_for_deep_scan() & TLS_PORTS) | tls_dynamic)
            to_scan, reused = _split_cached(cache, host, ports, "tls_scan", force_recheck_after)
            for r in reused:
                asset.merge_result(r)
            if to_scan:
                tls = TLSScanner(scope, ports=to_scan, rate=rate, concurrency=concurrency, timeout=timeout)
                for r in await tls.scan_target(host):
                    asset.merge_result(r)
                    cache.put(r)

        if gate_5_branch_eligible("web", asset, profile, service_filter, bool(web_dynamic)):
            ports = sorted((asset.open_ports_for_deep_scan() & WEB_PORTS) | web_dynamic)
            to_scan, reused = _split_cached(cache, host, ports, "web_scan", force_recheck_after)
            for r in reused:
                asset.merge_result(r)
            if to_scan:
                web = WebScanner(scope, ports=to_scan, rate=rate, concurrency=concurrency, timeout=timeout)
                for r in await web.scan_target(host):
                    asset.merge_result(r)
                    cache.put(r)

        if gate_5_branch_eligible("smb", asset, profile, service_filter):
            # host-level, not per-port (see asset.py's _merge_smb_scan)
            if cache.should_recheck(host, None, "smb_scan", force_recheck_after=force_recheck_after):
                smb = SMBScanner(scope, rate=rate, concurrency=concurrency, timeout=timeout)
                for r in await smb.scan_target(host):
                    asset.merge_result(r)
                    cache.put(r)
            else:
                asset.merge_result(cache.get(host, None, "smb_scan").result)

        if gate_5_branch_eligible("db", asset, profile, service_filter):
            ports = sorted(asset.open_ports_for_deep_scan() & DB_PORTS)
            to_scan, reused = _split_cached(cache, host, ports, "db_scan", force_recheck_after)
            for r in reused:
                asset.merge_result(r)
            if to_scan:
                port_map = {p: DEFAULT_DB_PORTS[p] for p in to_scan if p in DEFAULT_DB_PORTS}
                db = DBScanner(scope, port_map=port_map, rate=rate, concurrency=concurrency, timeout=timeout)
                for r in await db.scan_target(host):
                    asset.merge_result(r)
                    cache.put(r)

        if gate_5_branch_eligible("mcp_ai", asset, profile, service_filter):
            ports = sorted(asset.open_ports_for_deep_scan() & AI_PORTS)
            to_scan, reused = _split_cached(cache, host, ports, "mcp_ai_scan", force_recheck_after)
            for r in reused:
                asset.merge_result(r)
            if to_scan:
                ai = MCPAIScanner(scope, ports=to_scan, rate=rate, concurrency=concurrency, timeout=timeout)
                for r in await ai.scan_target(host):
                    asset.merge_result(r)
                    cache.put(r)

        if service_filter is None or "udp" in service_filter:
            udp_ports = sorted(UDP_PORTS)
            to_scan, reused = _split_cached(cache, host, udp_ports, "udp_scan", force_recheck_after)
            for r in reused:
                asset.merge_result(r)
            if to_scan:
                udp = UDPScanner(scope, ports=to_scan, rate=rate, concurrency=concurrency, timeout=timeout)
                for r in await udp.scan_target(host):
                    asset.merge_result(r)
                    cache.put(r)

    # --- Gate 6: credentialed collection -----------------------------------
    for host in live_hosts:
        asset = assets[host]
        if gate_6_credentialed_collection(asset, bool(ssh_creds), bool(win_creds)):
            if ssh_creds:
                ssh = SSHCollector(scope, **ssh_creds)
                sink = _Sink()
                await ssh.run([host], sink)
                for r in sink.results:
                    asset.merge_result(r)
                    cache.put(r)
            if win_creds:
                win = WindowsCollector(scope, **win_creds)
                sink = _Sink()
                await win.run([host], sink)
                for r in sink.results:
                    asset.merge_result(r)
                    cache.put(r)

    return assets
