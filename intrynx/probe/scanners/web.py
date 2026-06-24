"""Web service fingerprinting via httpx (ProjectDiscovery).

When given a bare IP or hostname, probes a wide range of common web ports
on both HTTP and HTTPS so services on non-standard ports (3000, 5000, 8080,
etc.) are always found, not just the default 80/443.
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
from typing import Any

from .base import normalize_targets, now, result, run_cmd, scanner, split_host_port

# Ports probed when a bare IP/hostname is given (no explicit port in target).
WEB_DEFAULT_PORTS = [
    80, 443, 3000, 4000, 5000, 6000, 7000, 7443,
    8000, 8080, 8088, 8443, 8888, 9000, 9090, 9443,
]
# These ports default to HTTPS; probe both schemes.
_TLS_PORTS = {443, 7443, 8443, 9443}


def _build_web_urls(targets: list[str], extra_ports: list[int] | None = None) -> list[str]:
    """Expand targets to full HTTP(S) URLs for each port we should probe.

    Rules:
    * Already a URL (http:// / https://) → kept as-is.
    * host:port form → probe both http and https on that port.
    * Bare IP or hostname → probed on all ports in WEB_DEFAULT_PORTS (or extra_ports).
    """
    ports = extra_ports if extra_ports is not None else WEB_DEFAULT_PORTS
    seen: set[str] = set()
    urls: list[str] = []

    def _add(u: str) -> None:
        if u not in seen:
            seen.add(u)
            urls.append(u)

    for t in targets:
        t = t.strip()
        if t.startswith(("http://", "https://")):
            _add(t)
            continue
        host, port = split_host_port(t)
        if port:
            _add(f"http://{host}:{port}")
            _add(f"https://{host}:{port}")
            continue
        for p in ports:
            _add(f"http://{host}:{p}")
            if p in _TLS_PORTS:
                _add(f"https://{host}:{p}")
    return urls


def parse_httpx_jsonl(output: str) -> list[dict[str, Any]]:
    """httpx -json → [{url, status, title, webserver, tech}]."""
    out: list[dict[str, Any]] = []
    for line in output.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        a_list = row.get("a") if isinstance(row.get("a"), list) else None
        out.append({
            "url": row.get("url") or row.get("input"),
            "status": row.get("status_code") or row.get("status-code"),
            "title": row.get("title"),
            "webserver": row.get("webserver"),
            "tech": row.get("tech") or row.get("technologies") or [],
            "content_length": row.get("content_length") or row.get("content-length"),
            "ip": (a_list[0] if a_list else None) or row.get("host"),
        })
    return out


@scanner("web_scan", "httpx", "Web service fingerprinting — status, title, tech stack")
def web_scan(params: dict) -> dict:
    targets = normalize_targets(params)
    if not targets:
        return result("web_scan", "httpx", [], ok=False, error="no targets provided")
    started = now()

    # Caller can pass an explicit port list (int list) to override default port sweep.
    extra_ports: list[int] | None = None
    raw_ports = params.get("ports")
    if isinstance(raw_ports, list) and all(isinstance(p, int) for p in raw_ports):
        extra_ports = raw_ports

    urls = _build_web_urls(targets, extra_ports)

    try:
        import probe_logger
        probe_logger.log_note(
            f"probing {len(urls)} URL(s) across {len(targets)} target(s)",
            urls_sample=urls[:6],
        )
    except ImportError:
        pass

    tf = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False)
    try:
        tf.write("\n".join(urls))
        tf.close()
        cmd = [
            "httpx", "-l", tf.name, "-json", "-silent", "-no-color",
            "-title", "-tech-detect", "-status-code", "-web-server",
            "-timeout", str(params.get("http_timeout", 10)),
            "-rate-limit", str(params.get("rate_limit", 150)),
        ]
        try:
            proc = run_cmd(cmd, timeout=int(params.get("timeout", 900)))
        except subprocess.TimeoutExpired:
            return result("web_scan", "httpx", targets, ok=False,
                          error="httpx timed out", started=started)
    finally:
        try:
            os.unlink(tf.name)
        except OSError:
            pass

    services = parse_httpx_jsonl(proc.stdout)
    return result("web_scan", "httpx", targets, web_services=services,
                  service_count=len(services), endpoints_probed=len(urls), started=started)
