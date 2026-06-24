"""Fast TCP port scan via nmap (no service detection — quicker than discovery)."""
from __future__ import annotations

import subprocess

from .base import normalize_targets, now, result, run_cmd, scanner
from .discovery import parse_nmap_xml


@scanner("port_scan", "nmap", "Fast TCP port scan (open ports, no version detection)")
def port_scan(params: dict) -> dict:
    targets = normalize_targets(params)
    if not targets:
        return result("port_scan", "nmap", [], ok=False, error="no targets provided")
    started = now()
    cmd = ["nmap", "-Pn", "-T4", "--open", "-oX", "-"]
    ports = params.get("ports")
    if ports:
        cmd += ["-p", str(ports)]
    else:
        # default: top 1000 ports (fast); pass "-F" for top 100 via args
        cmd += str(params.get("args", "")).split()
    # Bound per-host time so a range still returns the live hosts (set "" to disable).
    host_timeout = params.get("host_timeout", "90s")
    if host_timeout and "--host-timeout" not in cmd:
        cmd += ["--host-timeout", str(host_timeout)]
    cmd += targets
    try:
        proc = run_cmd(cmd, timeout=int(params.get("timeout", 1200)))
    except subprocess.TimeoutExpired:
        return result("port_scan", "nmap", targets, ok=False, error="nmap timed out", started=started)
    if proc.returncode != 0 and not proc.stdout:
        return result("port_scan", "nmap", targets, ok=False,
                      error=f"nmap failed: {proc.stderr[:300]}", started=started)
    hosts = parse_nmap_xml(proc.stdout)
    open_ports = sum(len(h["ports"]) for h in hosts)
    return result("port_scan", "nmap", targets, hosts=hosts, host_count=len(hosts),
                  open_ports=open_ports, started=started)
