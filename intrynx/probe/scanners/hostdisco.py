"""Fast host-liveness discovery via nmap ``-sn`` (no port scan).

This is the cheap "what's alive?" sweep you run first across large CIDRs: it does
ARP on the local segment and ICMP/TCP-ping off-segment, so it finds live hosts in
seconds without touching ports. For each live host it records IP, reverse DNS,
and (on the local L2 segment) MAC address + NIC vendor — useful for asset
inventory and rogue-device spotting.

Use ``service_fingerprint`` / ``port_scan`` afterwards on just the live hosts.
"""
from __future__ import annotations

import subprocess

from .base import normalize_targets, now, result, run_cmd, scanner
from .discovery import parse_nmap_xml


@scanner("host_discovery", "nmap", "Fast host-liveness sweep — live hosts, MAC, vendor")
def host_discovery(params: dict) -> dict:
    targets = normalize_targets(params)
    if not targets:
        return result("host_discovery", "nmap", [], ok=False, error="no targets provided")
    started = now()
    # -sn: ping scan, no ports. -PR/-PE/-PS handled automatically by nmap per segment.
    # -T4 fast timing; user args can override (e.g. add -PS22,80,443 for filtered nets).
    cmd = ["nmap", "-sn", "-T4", "-oX", "-"]
    extra = str(params.get("args", "")).split()
    if extra:
        cmd += extra
    if params.get("no_dns"):
        cmd.append("-n")
    cmd += targets
    try:
        proc = run_cmd(cmd, timeout=int(params.get("timeout", 900)))
    except subprocess.TimeoutExpired:
        return result("host_discovery", "nmap", targets, ok=False, error="nmap timed out", started=started)
    if proc.returncode != 0 and not proc.stdout:
        return result("host_discovery", "nmap", targets, ok=False,
                      error=f"nmap failed: {proc.stderr[:300]}", started=started)
    hosts = parse_nmap_xml(proc.stdout)
    # Liveness sweep emits no ports — keep only the identity fields, drop the empty port list.
    live = [{"ip": h["ip"], "hostname": h["hostname"], "mac": h["mac"], "vendor": h["vendor"]}
            for h in hosts]
    return result("host_discovery", "nmap", targets, hosts=live, host_count=len(live), started=started)
