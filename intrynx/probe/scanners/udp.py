"""UDP service discovery via nmap ``-sU``.

UDP exposes a whole attack surface that TCP scans miss: SNMP (often public/private
community strings), DNS, NTP (amplification / monlist), NetBIOS, SIP, IKE/VPN,
mDNS, and SCADA protocols. UDP scanning is slow and needs raw sockets, so this
defaults to the top UDP ports and adds light ``-sV`` so found services are named.

``open|filtered`` is kept as well as ``open`` because UDP frequently can't be
distinguished without a response.
"""
from __future__ import annotations

import subprocess

from .base import normalize_targets, now, result, run_cmd, scanner
from .discovery import parse_nmap_xml


@scanner("udp_scan", "nmap", "UDP service discovery — SNMP/DNS/NTP/NetBIOS/SIP")
def udp_scan(params: dict) -> dict:
    targets = normalize_targets(params)
    if not targets:
        return result("udp_scan", "nmap", [], ok=False, error="no targets provided")
    started = now()
    cmd = ["nmap", "-sU", "-sV", "-Pn", "-T4", "-oX", "-"]
    if params.get("ports"):
        cmd += ["-p", str(params["ports"])]
    else:
        cmd += ["--top-ports", str(params.get("top_ports", 100))]
    cmd += str(params.get("args", "")).split()
    cmd += targets
    try:
        # UDP scans are slow; allow a generous default timeout.
        proc = run_cmd(cmd, timeout=int(params.get("timeout", 3000)))
    except subprocess.TimeoutExpired:
        return result("udp_scan", "nmap", targets, ok=False, error="nmap timed out", started=started)
    if proc.returncode != 0 and not proc.stdout:
        return result("udp_scan", "nmap", targets, ok=False,
                      error=f"nmap failed: {proc.stderr[:300]}", started=started)
    hosts = parse_nmap_xml(proc.stdout, include_states=("open", "open|filtered"))
    open_ports = sum(len(h["ports"]) for h in hosts)
    return result("udp_scan", "nmap", targets, hosts=hosts, host_count=len(hosts),
                  open_ports=open_ports, started=started)
