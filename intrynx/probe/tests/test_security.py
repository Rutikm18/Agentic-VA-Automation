"""Tests for the probe security layer — licensing, host-binding, state encryption.

These generate an ephemeral keypair in-process, so they need no shipped keys.
Run:  python3 -m pytest probe/tests -q
"""
from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from security import hostid
from security.license import (License, LicenseError, LicenseExpired, LicenseHostMismatch,
                              LicenseInvalid, LicenseMissing, mint_license, verify_license)
from security.state import decrypt_state, encrypt_state

HOST = "a" * 64


def _keypair():
    priv = Ed25519PrivateKey.generate()
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    return priv, pub_pem


def _payload(host=HOST, days=30, **extra):
    now = datetime.now(timezone.utc)
    p = {"v": 1, "license_id": "test-1", "customer": "ACME",
         "host_fingerprint": host,
         "issued_at": now.isoformat(),
         "expires_at": (now + timedelta(days=days)).isoformat()}
    p.update(extra)
    return p


# ── happy path ───────────────────────────────────────────────────────────────────

def test_valid_license():
    priv, pub = _keypair()
    token = mint_license(_payload(probe_name="dmz-01"), priv)
    lic = verify_license(token, pub, HOST)
    assert isinstance(lic, License)
    assert lic.customer == "ACME" and lic.probe_name == "dmz-01" and lic.locked_to_host


def test_wildcard_host_allows_any_machine():
    priv, pub = _keypair()
    token = mint_license(_payload(host="*"), priv)
    lic = verify_license(token, pub, "some-other-host")
    assert lic.locked_to_host is False


# ── failure modes (each must be a distinct, plain-English error) ──────────────────

def test_missing_license():
    _, pub = _keypair()
    with pytest.raises(LicenseMissing):
        verify_license("", pub, HOST)
    with pytest.raises(LicenseMissing):
        verify_license(None, pub, HOST)


def test_expired_license():
    priv, pub = _keypair()
    token = mint_license(_payload(days=-1), priv)
    with pytest.raises(LicenseExpired):
        verify_license(token, pub, HOST)


def test_host_mismatch():
    priv, pub = _keypair()
    token = mint_license(_payload(host="b" * 64), priv)
    with pytest.raises(LicenseHostMismatch):
        verify_license(token, pub, HOST)


def test_tampered_payload_is_rejected():
    priv, pub = _keypair()
    token = mint_license(_payload(customer="ACME"), priv)
    payload_b64, sig = token.split(".", 1)
    # flip a character in the payload → signature no longer matches
    bad = payload_b64[:-2] + ("AA" if payload_b64[-2:] != "AA" else "BB") + "." + sig
    with pytest.raises(LicenseInvalid):
        verify_license(bad, pub, HOST)


def test_wrong_key_is_rejected():
    priv, _ = _keypair()
    _, other_pub = _keypair()
    token = mint_license(_payload(), priv)
    with pytest.raises(LicenseInvalid):
        verify_license(token, other_pub, HOST)


def test_garbage_token_is_rejected():
    _, pub = _keypair()
    with pytest.raises(LicenseInvalid):
        verify_license("not-a-real-token", pub, HOST)


def test_friendly_messages_present():
    for exc in (LicenseError(), LicenseMissing(), LicenseInvalid(),
                LicenseExpired(), LicenseHostMismatch()):
        assert isinstance(exc.friendly, str) and len(exc.friendly) > 10


# ── host-bound state encryption ───────────────────────────────────────────────────

def test_state_roundtrip():
    blob = encrypt_state({"agent_id": "abc", "token": "secret"}, HOST)
    assert "agent_id" not in blob and "secret" not in blob   # actually encrypted
    assert decrypt_state(blob, HOST) == {"agent_id": "abc", "token": "secret"}


def test_state_wont_decrypt_on_another_machine():
    blob = encrypt_state({"token": "secret"}, HOST)
    assert decrypt_state(blob, "different-host") == {}        # copied file is useless
    assert decrypt_state("", HOST) == {}


# ── host fingerprint ───────────────────────────────────────────────────────────────

def test_fingerprint_is_stable_and_hex():
    fp1, fp2 = hostid.host_fingerprint(), hostid.host_fingerprint()
    assert fp1 == fp2 and len(fp1) == 64
    int(fp1, 16)  # valid hex
    assert hostid.short_id(fp1) == fp1[:12]


def test_host_id_override(monkeypatch):
    monkeypatch.setenv("PROBE_HOST_ID", "fixed-container-id")
    fp_a = hostid.host_fingerprint()
    monkeypatch.setenv("PROBE_HOST_ID", "another-id")
    fp_b = hostid.host_fingerprint()
    assert fp_a != fp_b                                       # override changes the fingerprint
