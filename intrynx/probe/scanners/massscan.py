"""Internet-speed port sweep via masscan.

masscan uses its own async TCP stack to scan very large address/port ranges far
faster than nmap. Use it to sweep a big CIDR for open ports, then hand the live
host:port set to ``service_fingerprint`` for version detection.

Safety: the send ``rate`` is capped to a sane default (1000 pps) because masscan
can saturate a link; raise it deliberately via ``params.rate`` only on networks
you own. masscan needs raw sockets (the container / systemd unit grant CAP_NET_RAW).
"""
from __future__ import annotations

import json
import subprocess
from typing import Any

from .base import normalize_targets, now, result, run_cmd, scanner


def parse_masscan_json(output: str) -> list[dict[str, Any]]:
    """masscan ``-oJ -`` → [{ip, ports:[{port, protocol, status}]}], merged per host.

    masscan emits a JSON array, one record per (host, port), with stray brackets
    and trailing commas; parse line-by-line and tolerate junk.
    """
    by_host: dict[str, dict[str, Any]] = {}
    for line in output.splitlines():
        line = line.strip().rstrip(",")
        if not line.startswith("{"):
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        ip = row.get("ip")
        if not ip:
            continue
        host = by_host.setdefault(ip, {"ip": ip, "ports": []})
        for p in row.get("ports", []):
            host["ports"].append({
                "port": p.get("port"),
                "protocol": p.get("proto"),
                "status": p.get("status"),
            })
    return list(by_host.values())


@scanner("mass_scan", "masscan", "Internet-speed port sweep of large ranges")
def mass_scan(params: dict) -> dict:
    targets = normalize_targets(params)
    if not targets:
        return result("mass_scan", "masscan", [], ok=False, error="no targets provided")
    started = now()
    ports = str(params.get("ports", "1-1024"))
    rate = int(params.get("rate", 1000))
    cmd = ["masscan", "-p", ports, "--rate", str(rate), "-oJ", "-"]
    cmd += str(params.get("args", "")).split()
    cmd += targets
    try:
        proc = run_cmd(cmd, timeout=int(params.get("timeout", 1800)))
    except subprocess.TimeoutExpired:
        return result("mass_scan", "masscan", targets, ok=False, error="masscan timed out", started=started)
    # masscan exits 0 even with no results; only treat empty-stdout + error text as failure.
    if proc.returncode != 0 and not proc.stdout.strip():
        return result("mass_scan", "masscan", targets, ok=False,
                      error=f"masscan failed: {proc.stderr[:300]}", started=started)
    hosts = parse_masscan_json(proc.stdout)
    open_ports = sum(len(h["ports"]) for h in hosts)
    return result("mass_scan", "masscan", targets, hosts=hosts, host_count=len(hosts),
                  open_ports=open_ports, rate=rate, started=started)
