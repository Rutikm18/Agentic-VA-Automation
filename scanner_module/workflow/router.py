"""
router.py — dynamic Gate-5 branch routing from OBSERVED service_banner
content, not just port number. Solves the "HTTPS-on-9443" problem: a port
outside the static TLS_PORTS table still gets routed to tls_scan if its
banner says so.

THE KEY EMPIRICAL FINDING (verified directly against a real TLS listener,
not assumed): service_banner.py's _GENERIC_PROBE (b"\r\n") sent to a raw
TLS-only port does NOT provoke a recognizable TLS alert byte sequence — the
target's TLS stack treats the garbage input as a protocol violation and
closes the connection with no response at all. So a "this looks like TLS"
signal is NOT a byte-pattern match here; it's an open port with banner=None
that ISN'T one of the well-known silent-by-design protocols (the
_CLIENT_FIRST set, which service_banner.py already sends a real HTTP probe
to). That absence-of-banner-on-an-otherwise-silent-port signal is exactly
what a HTTPS server moved to a weird port looks like from this scanner's
vantage point, and tls_scan is cheap and harmless to try speculatively —
if it's not actually TLS, tls_scanner just reports a handshake failure.

HTTP detection, by contrast, has a strong positive signal — the literal
"HTTP/1." status line — since service_banner.py already sends a real HTTP
GET to ports it suspects might be HTTP (see _CLIENT_FIRST), and even on
ports it doesn't, an HTTP server typically responds to a bare "\r\n" with
a 400-class error that still starts "HTTP/1.x".
"""
from __future__ import annotations

from .asset import Asset

# Mirrors service_banner.py's own _CLIENT_FIRST set — ports where silence is
# EXPECTED regardless of protocol (an HTTP probe was already sent there), so
# banner=None on one of these is not a TLS signal, just "nothing interesting
# came back to our HTTP probe."
_CLIENT_FIRST = {80, 8080, 8000, 8888, 443, 8443}


def looks_like_http(banner_fact: dict) -> bool:
    first_line = (banner_fact or {}).get("first_line") or ""
    return first_line.startswith("HTTP/1.") or first_line.startswith("HTTP/2")


def looks_like_tls(port: int, banner_fact: dict | None) -> bool:
    """True when this port's banner result is exactly the silent-on-garbage
    signature a raw TLS listener produces — see module docstring. Only
    meaningful for ports the scanner didn't already expect to be silent.
    """
    if port in _CLIENT_FIRST:
        return False   # silence here is the normal HTTP-probe-got-nothing case
    if banner_fact is None:
        return False    # no banner attempt was made at all (port not open)
    return banner_fact.get("banner") is None


def route_branches(asset: Asset, candidate_branches: tuple[str, ...] = ("tls", "web")
                   ) -> dict[int, set[str]]:
    """For every open port with a banner fact, returns {port: {branches}}
    that observed content (not the static port table) justifies routing to.
    gates.py's gate_5_branch_eligible still makes the final per-branch
    decision (profile + --services filter), so the caller passes whatever
    this returns as that function's `dynamically_routed` hint, on a
    per-(port, branch) basis — this function never decides eligibility on
    its own, only "does the evidence support this branch."
    """
    routed: dict[int, set[str]] = {}
    for port in asset.open_ports_for_deep_scan():
        fact = asset.services.get(port)
        branches: set[str] = set()
        if "web" in candidate_branches and fact and looks_like_http(fact):
            branches.add("web")
        if "tls" in candidate_branches and looks_like_tls(port, fact):
            branches.add("tls")
        if branches:
            routed[port] = branches
    return routed
