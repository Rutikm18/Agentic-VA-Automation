"""
Probe scanning module — capability registry + dispatcher.

Importing this package registers every scanner. The agent uses:
  * ``available_capabilities()`` — scan types whose tool is installed (advertised on register)
  * ``capability_catalog()``     — all known scan types + install status (for diagnostics)
  * ``dispatch(scan_type, params)`` — run a scan, returns the normalized result dict
"""
from __future__ import annotations

from typing import Any

from .base import REGISTRY, engine_label, sanitize

# Import the scanner modules so their @scanner decorators register them.
from . import discovery    # noqa: F401  host & service discovery (nmap -sV)
from . import hostdisco     # noqa: F401  fast liveness sweep (nmap -sn)
from . import portscan      # noqa: F401  fast TCP port scan (nmap)
from . import massscan      # noqa: F401  large-range sweep (masscan)
from . import fingerprint   # noqa: F401  installed-server inventory (nmap -sV --version-all)
from . import udp           # noqa: F401  UDP services (nmap -sU)
from . import vuln          # noqa: F401  vuln/misconfig (nuclei)
from . import tls           # noqa: F401  TLS/cert audit (sslscan)
from . import web           # noqa: F401  web fingerprint (httpx)
from . import smb           # noqa: F401  SMB/AD enum (netexec)
from . import mcp_ai        # noqa: F401  MCP + AI/LLM server discovery (builtin)
from . import passive       # noqa: F401  OT/ICS-safe passive discovery (builtin, listen-only)
from . import db            # noqa: F401  database fingerprint (builtin, raw sockets)
from . import ssh           # noqa: F401  credentialed Linux inventory (paramiko, optional)
from . import windows       # noqa: F401  credentialed Windows inventory (pywinrm/impacket, optional)

# Coarse backend job_type → default scan_type when params don't specify one.
DEFAULT_SCAN_FOR_JOBTYPE = {
    "discovery": "discovery",
    "lateral": "smb_enum",
    "cloud_scan": "vuln_scan",
}


def available_capabilities() -> list[str]:
    """Scan types this probe can actually run (tool present)."""
    return sorted(name for name, s in REGISTRY.items() if s.available())


def capability_catalog() -> list[dict[str, Any]]:
    """All known scan types with availability — for /diagnostics and logs.

    Exposes only the branded ``engine`` label, never the underlying binary.
    """
    return [
        {"scan_type": s.name, "engine": s.engine, "available": s.available(), "description": s.description}
        for s in sorted(REGISTRY.values(), key=lambda x: x.name)
    ]


def resolve_scan_type(job_type: str | None, params: dict) -> str:
    return params.get("scan_type") or DEFAULT_SCAN_FOR_JOBTYPE.get(job_type or "", "discovery")


def dispatch(scan_type: str, params: dict) -> dict:
    """Run the requested scan. Returns a normalized result dict (never raises)."""
    s = REGISTRY.get(scan_type)
    if s is None:
        return {"scan_type": scan_type, "ok": False,
                "error": f"unsupported scan_type '{scan_type}'",
                "supported": sorted(REGISTRY.keys())}
    if not s.available():
        return {"scan_type": scan_type, "engine": s.engine, "tool": s.engine, "ok": False,
                "error": f"the {s.engine} engine is not available on this probe"}

    targets = params.get("targets") or []
    if isinstance(targets, str):
        targets = [targets]
    try:
        import probe_logger
        probe_logger.begin(scan_type, list(targets))
    except ImportError:
        pass

    res: dict = {}
    try:
        res = s.run(params)
        return res
    except Exception as exc:  # a scanner bug must not crash the agent loop
        res = {"scan_type": scan_type, "engine": s.engine, "tool": s.engine, "ok": False,
               "error": sanitize(f"{type(exc).__name__}: {exc}")}
        return res
    finally:
        try:
            import probe_logger
            probe_logger.end(res)
        except ImportError:
            pass
