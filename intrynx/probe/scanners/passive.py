"""OT/ICS-safe passive discovery — listens only, transmits nothing.

Every other scanner in this probe is ACTIVE — it opens a TCP connection or
sends a UDP probe to the target. On an IT or even an IoT network that is
fine. On an OPERATIONAL TECHNOLOGY network (ICS/SCADA: PLCs, RTUs, HMIs,
drives, safety controllers) it is NOT — an unsolicited connection or even a
burst of well-formed packets has, in the real world, hung or rebooted a PLC
and tripped a physical process. The rule on a control network is: you
LISTEN, you do not probe.

This module joins standard multicast discovery groups and binds broadcast /
industrial announcement UDP ports in RECEIVE-ONLY mode, then records
whichever in-scope hosts voluntarily announce themselves on the segment.
Connect the probe to a SPAN/mirror port or a passive network TAP to see real
traffic on a switched network — zero packets ever leave this scanner.

Sources listened to (all recv-only):
  mDNS         224.0.0.251:5353    printers, IoT, Apple/Bonjour device names
  SSDP/UPnP    239.255.255.250:1900  UPnP NOTIFY announcements (cameras, NAS)
  LLMNR        224.0.0.252:5355    Windows name resolution
  NetBIOS      broadcast :137      Windows host announcements
  BACnet/IP    broadcast :47808    building-automation controllers (OT)
  EtherNet/IP  broadcast :2222     Allen-Bradley / industrial I/O (OT)
"""
from __future__ import annotations

import select
import socket
import struct
import time

from .base import BUILTIN_PASSIVE, now, result, scanner, scope_check

# (multicast_group | None, port, label). group=None means "bind broadcast port".
# Nothing here is ever sent — these are only joined/bound for receiving.
PASSIVE_SOURCES: list[tuple[str | None, int, str]] = [
    ("224.0.0.251", 5353, "mdns"),
    ("239.255.255.250", 1900, "ssdp"),
    ("224.0.0.252", 5355, "llmnr"),
    (None, 137, "netbios"),
    (None, 47808, "bacnet"),      # OT: building automation (BACnet/IP)
    (None, 2222, "ethernet-ip"),  # OT: EtherNet/IP implicit I/O
]


def _printable_strings(data: bytes, min_len: int = 4, limit: int = 6) -> list[str]:
    """Pull short printable ASCII runs from a payload, for human-readable evidence."""
    out, cur = [], []
    for b in data:
        if 32 <= b < 127:
            cur.append(chr(b))
        else:
            if len(cur) >= min_len:
                out.append("".join(cur))
            cur = []
        if len(out) >= limit:
            break
    if len(cur) >= min_len and len(out) < limit:
        out.append("".join(cur))
    return out


def _device_hint(label: str, data: bytes) -> str | None:
    """Best-effort device label from an announcement payload (recv-only parsing)."""
    text = data.decode("latin-1", "replace")
    if label == "ssdp":
        for line in text.splitlines():
            low = line.lower()
            if low.startswith("server:") or low.startswith("usn:"):
                return line.strip()[:200]
    if label == "mdns":
        names = [s for s in _printable_strings(data, 4, 8) if "." in s or "_" in s]
        if names:
            return ", ".join(names[:3])[:200]
    hints = _printable_strings(data)
    return ", ".join(hints[:3])[:200] if hints else None


def _open_listener(group: str | None, port: int) -> socket.socket | None:
    """Open ONE recv-only UDP listener. Returns None on failure (e.g. port in
    use) — sends nothing, never falls back to anything active.

    For multicast, joins the group; for broadcast, just binds the port.
    SO_REUSEADDR/REUSEPORT let us coexist with the host's own services.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except (AttributeError, OSError):
            pass
        sock.bind(("", port))
        if group:
            mreq = struct.pack("4sl", socket.inet_aton(group), socket.INADDR_ANY)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        sock.setblocking(False)
        return sock
    except OSError:
        return None


@scanner("passive_discovery", BUILTIN_PASSIVE,
         "OT/ICS-safe passive discovery — listens only, sends nothing")
def passive_discovery(params: dict) -> dict:
    """Listen-only host discovery. Reports in-scope hosts that announce
    themselves within the listen window. Transmits NOTHING to any target.

    params:
      listen_seconds  how long to listen (default 60)
      allowed_cidrs   scope allowlist applied to OBSERVED sources — chatter
                       from a host outside this list is seen but never
                       recorded (mirrors scope_check(), applied here to what
                       was overheard rather than to an intended target list,
                       since a passive listener doesn't target anything).
    """
    started = now()
    listen_seconds = float(params.get("listen_seconds", 60))
    allowed_cidrs = params.get("allowed_cidrs") or params.get("scope_cidrs") or []

    socks: dict[int, tuple[socket.socket, str]] = {}
    for group, port, label in PASSIVE_SOURCES:
        s = _open_listener(group, port)
        if s is not None:
            socks[s.fileno()] = (s, label)

    if not socks:
        return result("passive_discovery", BUILTIN_PASSIVE, [], ok=False,
                      error="no passive listeners could be opened (all source "
                            "ports already in use on this probe)", started=started)

    fd_to_label = {fd: label for fd, (_s, label) in socks.items()}
    raw_socks = [s for s, _label in socks.values()]

    seen: dict[str, dict] = {}
    deadline = time.monotonic() + listen_seconds
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        ready, _, _ = select.select(raw_socks, [], [], min(remaining, 1.0))
        for sock in ready:
            try:
                data, addr = sock.recvfrom(4096)
            except OSError:
                continue
            src = addr[0]
            allowed, _blocked = scope_check([src], allowed_cidrs)
            if not allowed:
                continue  # out-of-scope chatter: observed, never recorded
            label = fd_to_label[sock.fileno()]
            rec = seen.setdefault(src, {"labels": set(), "hints": set(), "packets": 0})
            rec["labels"].add(label)
            rec["packets"] += 1
            hint = _device_hint(label, data)
            if hint:
                rec["hints"].add(hint)

    for s in raw_socks:
        try:
            s.close()
        except OSError:
            pass

    hosts = [
        {"ip": host, "announced_via": sorted(rec["labels"]),
         "device_hints": sorted(rec["hints"])[:5], "packets_observed": rec["packets"]}
        for host, rec in sorted(seen.items())
    ]
    return result("passive_discovery", BUILTIN_PASSIVE, [], hosts=hosts,
                  host_count=len(hosts), listen_seconds=listen_seconds, started=started)
