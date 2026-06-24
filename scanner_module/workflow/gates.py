"""
gates.py — precondition functions deciding whether each stage of the
workflow runs. Every function is pure (Asset + config in, bool out) so
workflow_engine.py's loop stays a thin "if precondition: run" driver with
no decision logic of its own.

Port tables below are copied VERBATIM from pipeline.py (and the relevant
scanner modules' own DEFAULT_* constants) — never re-derived or guessed —
since pipeline.py itself is left untouched (this is a new, parallel
orchestrator, not a modification of the existing one) and the two must
agree on what a profile actually means.
"""
from __future__ import annotations

from datetime import timedelta

from .asset import Asset

# --- verbatim from pipeline.py ------------------------------------------
IT_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 389, 443, 445, 465, 587,
           636, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 5985, 5986, 6379,
           8000, 8080, 8443, 9200, 11211, 27017]
IOT_PORTS = [22, 23, 80, 443, 554, 1883, 8883, 5683, 8080, 8443, 8888, 9000, 9100,
            49152, 62078, 5000, 8081, 37777]
TLS_PORTS = {443, 8443, 993, 995, 465, 636, 989, 990, 5986}
WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888, 9000, 9200, 8081, 5000}
SMB_PORTS = {139, 445}
DB_PORTS = {3306, 5432, 1433, 6379, 27017, 1521}     # DEFAULT_DB_PORTS.keys() in db_scanner.py
AI_PORTS = {11434, 8000, 8080, 5000, 3000, 1234, 8001, 7860, 11435}  # DEFAULT_AI_PORTS in mcp_ai_scanner.py
UDP_PORTS = {53, 123, 161, 137}                       # UDP_PROBES.keys() in udp_scanner.py

PROFILE_PORTS = {"it": IT_PORTS, "iot": IOT_PORTS, "ot": []}
PROFILE_DEEP_BRANCHES = {"it": {"tls", "web", "smb", "db"}, "iot": {"tls", "web"}, "ot": set()}
LIVENESS_RECHECK_THRESHOLD = {"it": timedelta(hours=1), "iot": timedelta(minutes=5)}

_BRANCH_PORT_TABLE = {"tls": TLS_PORTS, "web": WEB_PORTS, "smb": SMB_PORTS,
                      "db": DB_PORTS, "mcp_ai": AI_PORTS}


def gate_0_is_passive_profile(profile: str) -> bool:
    """True means OT/ICS passive-only mode — a hard stop, never reached by
    any active-probe gate below. workflow_engine.py checks this FIRST and
    routes to PassiveCollector exclusively when True."""
    return profile == "ot"


def gate_2_host_discovery(asset: Asset, profile: str) -> bool:
    if gate_0_is_passive_profile(profile):
        return False
    threshold = LIVENESS_RECHECK_THRESHOLD.get(profile, timedelta(hours=1))
    return asset.needs_recheck_live(threshold)


def gate_3_port_scan(asset: Asset, profile: str) -> bool:
    if gate_0_is_passive_profile(profile):
        return False
    return asset.last_seen_alive is not None


def gate_4_service_banner(asset: Asset) -> bool:
    return len(asset.open_ports_for_deep_scan()) > 0


def gate_5_branch_eligible(branch: str, asset: Asset, profile: str,
                           service_filter: set[str] | None,
                           dynamically_routed: bool = False) -> bool:
    """Does `branch` apply to this host?
      - Must be in this profile's allowed deep-scan set (ot allows none;
        iot allows tls/web only; it allows tls/web/smb/db).
      - If the caller passed an explicit --services filter, branch must be in it.
      - Either router.py already determined this branch applies from
        OBSERVED banner/handshake content (dynamically_routed=True — the
        HTTPS-on-9443 case, passed in by the caller, this function doesn't
        re-derive it), OR at least one open port falls in the branch's
        static port table (the fallback signal, weaker but still useful
        when nothing volunteered an identifying banner).
    """
    if branch not in PROFILE_DEEP_BRANCHES.get(profile, set()):
        return False
    if service_filter is not None and branch not in service_filter:
        return False
    if dynamically_routed:
        return True
    open_ports = asset.open_ports_for_deep_scan()
    return bool(open_ports & _BRANCH_PORT_TABLE.get(branch, set()))


def gate_6_credentialed_collection(asset: Asset, has_ssh_creds: bool, has_win_creds: bool) -> bool:
    if not has_ssh_creds and not has_win_creds:
        return False
    if asset.last_seen_alive is None:
        return False
    if asset.cred_collected:
        return False
    return True
