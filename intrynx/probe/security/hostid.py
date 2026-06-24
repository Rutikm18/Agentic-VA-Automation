"""Stable per-machine fingerprint used to lock a probe to one host.

The fingerprint is a SHA-256 over the most stable machine identifier available:

  * ``PROBE_HOST_ID`` env override — wins when set (use this in containers, where
    the OS machine-id is not stable across rebuilds);
  * Linux ``/etc/machine-id`` (or the dbus one);
  * macOS ``IOPlatformUUID``;
  * Windows BIOS UUID;
  * last resort: hostname + primary MAC.

A license is minted against this value, so a copied probe folder run on a
different machine produces a different fingerprint and is refused.
"""
from __future__ import annotations

import hashlib
import os
import platform
import re
import socket
import subprocess
import uuid


def _read(path: str) -> str | None:
    try:
        v = open(path, encoding="utf-8", errors="ignore").read().strip()
        return v or None
    except OSError:
        return None


def _machine_id() -> str | None:
    for p in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        v = _read(p)
        if v:
            return v
    sysname = platform.system()
    if sysname == "Darwin":
        try:
            out = subprocess.run(["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
                                 capture_output=True, text=True, timeout=5).stdout
            m = re.search(r'IOPlatformUUID"\s*=\s*"([^"]+)"', out)
            if m:
                return m.group(1)
        except (OSError, subprocess.SubprocessError):
            pass
    elif sysname == "Windows":
        try:
            out = subprocess.run(["wmic", "csproduct", "get", "UUID"],
                                 capture_output=True, text=True, timeout=5).stdout
            lines = [ln.strip() for ln in out.splitlines() if ln.strip()]
            if len(lines) >= 2:
                return lines[1]
        except (OSError, subprocess.SubprocessError):
            pass
    return None


def host_fingerprint() -> str:
    """Return the stable hex fingerprint for this machine."""
    override = os.environ.get("PROBE_HOST_ID")
    if override and override.strip():
        raw = "env:" + override.strip()
    else:
        mid = _machine_id()
        raw = ("mid:" + mid) if mid else f"host:{socket.gethostname()}|mac:{uuid.getnode():x}"
    return hashlib.sha256(raw.encode()).hexdigest()


def short_id(fingerprint: str | None = None) -> str:
    """A short, human-friendly form for display (first 12 hex chars)."""
    return (fingerprint or host_fingerprint())[:12]
