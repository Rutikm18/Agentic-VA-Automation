"""
VA scanner module — pure collection/scanning layer.

Each submodule is an independent scanner with a unified output schema so you can
measure accuracy and false-positive rate per scanner in isolation:

  host_discovery   liveness (TCP probes)
  port_scanner     TCP connect scan (open/closed/filtered)
  service_banner   banner / version-string grabbing
  tls_scanner      TLS versions, ciphers, certificate facts
  udp_scanner      DNS/NTP/SNMP/NetBIOS UDP service detection
  smb_scanner      SMB dialect detection (SMBv1 enabled?)
  snmp_scanner     SNMP read-only enumeration (sysDescr)
  web_scanner      passive HTTP(S) fingerprinting
  mcp_ai_scanner   MCP / AI inference endpoint discovery
  nmap_wrapper     orchestrate nmap, normalize XML
  ssh_collector    credentialed Linux inventory (authorized creds)

All scanners enforce a scope allowlist before touching any target, and perform
NO exploitation, brute-forcing, or modification.
"""

from .scanner_base import (
    BaseScanner, ScanResult, ScopeGuard, RateLimiter, ResultWriter,
    expand_targets, parse_ports,
)

__all__ = [
    "BaseScanner", "ScanResult", "ScopeGuard", "RateLimiter",
    "ResultWriter", "expand_targets", "parse_ports",
]
