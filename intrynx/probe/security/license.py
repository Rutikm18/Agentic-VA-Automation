"""Signed deployment licenses (Ed25519) that lock a probe to a customer + machine.

A license is a small JSON payload signed with an **Ed25519 private key that only
the vendor holds**. The probe embeds only the matching **public key**, so it can
*verify* a license but can never *mint* one — copying the probe gives an attacker
no way to produce a valid license. The payload binds the probe to a machine
fingerprint and an expiry date.

Token format (compact, URL-safe):  ``<base64(payload_json)>.<base64(signature)>``
The signature covers the exact payload bytes that are base64-encoded, so there is
no canonicalization ambiguity on verify.

Every failure raises a ``LicenseError`` subclass whose ``.friendly`` attribute is a
plain-English sentence safe to show the operator.
"""
from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


# ── errors (each carries a plain-English message) ───────────────────────────────

class LicenseError(Exception):
    friendly = "This probe's deployment license could not be verified."


class LicenseMissing(LicenseError):
    friendly = ("No deployment license found. Set PROBE_LICENSE (or LICENSE_FILE) to the "
                "license your Intrynx administrator gave you.")


class LicenseInvalid(LicenseError):
    friendly = "The deployment license is invalid or has been tampered with. Refusing to run."


class LicenseExpired(LicenseError):
    friendly = "This deployment license has expired. Ask your Intrynx administrator for a new one."


class LicenseHostMismatch(LicenseError):
    friendly = ("This probe is locked to a different machine. Refusing to run. "
                "Contact your Intrynx administrator to re-issue the license for this host.")


# ── model ───────────────────────────────────────────────────────────────────────

@dataclass
class License:
    license_id: str
    customer: str
    host_fingerprint: str
    expires_at: str
    issued_at: str | None = None
    tenant: str | None = None
    probe_name: str | None = None
    network_segments: list[str] = field(default_factory=list)

    @property
    def locked_to_host(self) -> bool:
        return self.host_fingerprint != "*"


# ── encoding helpers ────────────────────────────────────────────────────────────

def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _payload_bytes(payload: dict) -> bytes:
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except (ValueError, AttributeError):
        return None


# ── mint (vendor side — needs the private key) ──────────────────────────────────

def mint_license(payload: dict, private_key: Ed25519PrivateKey) -> str:
    """Sign a license payload. Used by the vendor's mint tool and by tests."""
    msg = _payload_bytes(payload)
    sig = private_key.sign(msg)
    return f"{_b64e(msg)}.{_b64e(sig)}"


# ── verify (probe side — needs only the public key) ─────────────────────────────

def verify_license(token: str | None, public_key_pem: bytes, host_fp: str,
                   *, now: datetime | None = None) -> License:
    """Verify signature, expiry, and host binding. Raises a ``LicenseError`` subclass."""
    if not token or not token.strip():
        raise LicenseMissing()
    try:
        payload_b64, sig_b64 = token.strip().split(".", 1)
        msg, sig = _b64d(payload_b64), _b64d(sig_b64)
    except (ValueError, base64.binascii.Error) as exc:
        raise LicenseInvalid() from exc

    pub = serialization.load_pem_public_key(public_key_pem)
    if not isinstance(pub, Ed25519PublicKey):
        raise LicenseInvalid()
    try:
        pub.verify(sig, msg)
    except InvalidSignature as exc:
        raise LicenseInvalid() from exc

    try:
        payload = json.loads(msg)
    except json.JSONDecodeError as exc:
        raise LicenseInvalid() from exc

    expires = _parse_dt(payload.get("expires_at"))
    if expires is None:
        raise LicenseInvalid()
    if (now or datetime.now(timezone.utc)) > expires:
        raise LicenseExpired()

    allowed = payload.get("host_fingerprint")
    if allowed not in ("*", host_fp):
        raise LicenseHostMismatch()

    return License(
        license_id=payload.get("license_id", "unknown"),
        customer=payload.get("customer", "unknown"),
        host_fingerprint=allowed,
        expires_at=payload.get("expires_at"),
        issued_at=payload.get("issued_at"),
        tenant=payload.get("tenant"),
        probe_name=payload.get("probe_name"),
        network_segments=payload.get("network_segments") or [],
    )
