"""TLS/SSL configuration & certificate audit via sslscan.

When given a bare IP/hostname, probes common TLS ports (443, 8443, …) rather
than only port 443 so services on non-standard HTTPS ports are always checked.
"""
from __future__ import annotations

import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any

from .base import normalize_targets, now, result, run_cmd, scanner, split_host_port

_DEPRECATED_PROTOCOLS = {
    "SSLv2": "critical", "SSLv3": "high", "TLSv1.0": "medium", "TLSv1.1": "medium",
}

# Ports probed when the target has no explicit port.
TLS_DEFAULT_PORTS = [443, 8443, 4443, 7443, 9443]


def parse_sslscan_xml(xml_text: str, target: str) -> list[dict[str, Any]]:
    """sslscan --xml=- → findings about weak protocols, ciphers, and the cert."""
    findings: list[dict[str, Any]] = []
    if not xml_text.strip():
        return findings
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return findings

    test = root.find("ssltest")
    if test is None:
        test = root

    def add(title: str, severity: str, detail: str = "") -> None:
        findings.append({"target": target, "title": title, "severity": severity, "detail": detail})

    for proto in test.findall("protocol"):
        ver = proto.get("version", "")
        kind = proto.get("type", "").lower()
        label = f"{'SSLv' if kind == 'ssl' else 'TLSv'}{ver}"
        if proto.get("enabled") == "1" and label in _DEPRECATED_PROTOCOLS:
            add(f"Deprecated protocol enabled: {label}", _DEPRECATED_PROTOCOLS[label],
                "Disable legacy SSL/TLS versions.")

    for cipher in test.findall("cipher"):
        strength = (cipher.get("strength") or "").lower()
        name = cipher.get("cipher", "")
        if strength in ("null", "weak"):
            add(f"Weak cipher accepted: {name}", "high" if strength == "null" else "medium",
                f"strength={strength}")

    cert = test.find("certificate")
    if cert is None:
        cert = test.find("certificates/certificate")
    if cert is not None:
        self_signed = cert.findtext("self-signed")
        expired = cert.findtext("expired")
        not_after = cert.findtext("not-valid-after")
        if self_signed == "true":
            add("Self-signed certificate", "medium")
        if expired == "true":
            add("Expired certificate", "high")
        elif not_after:
            try:
                exp = datetime.fromisoformat(not_after.replace("Z", "+00:00"))
                if (exp - datetime.now(timezone.utc)).days < 30:
                    add("Certificate expiring within 30 days", "low", f"not_after={not_after}")
            except ValueError:
                pass
    return findings


@scanner("tls_scan", "sslscan", "TLS/SSL configuration & certificate audit")
def tls_scan(params: dict) -> dict:
    targets = normalize_targets(params)
    if not targets:
        return result("tls_scan", "sslscan", [], ok=False, error="no targets provided")
    started = now()

    # An explicit port= param pins the port for all targets; otherwise sweep TLS_DEFAULT_PORTS.
    custom_port = params.get("port")
    per_host_timeout = int(params.get("per_host_timeout", 30))

    findings: list[dict[str, Any]] = []
    errors: list[str] = []
    ports_scanned: list[str] = []

    for t in targets:
        host, pin = split_host_port(t)
        ports_to_scan = [pin] if pin else ([int(custom_port)] if custom_port else TLS_DEFAULT_PORTS)
        for port in ports_to_scan:
            addr = f"{host}:{port}"
            try:
                proc = run_cmd(
                    ["sslscan", "--no-colour", "--xml=-", addr],
                    timeout=per_host_timeout,
                )
                found = parse_sslscan_xml(proc.stdout, t)
                if found:
                    findings += found
                    ports_scanned.append(addr)
                # Non-TLS ports produce empty/error output — skip silently.
            except subprocess.TimeoutExpired:
                errors.append(f"{addr}: timed out")

    return result("tls_scan", "sslscan", targets,
                  findings=findings, finding_count=len(findings),
                  ports_scanned=ports_scanned or None,
                  errors=errors or None, started=started)
