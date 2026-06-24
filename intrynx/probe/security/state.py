"""Host-bound encryption for the probe's cached identity file.

The saved ``agent_id`` / token is encrypted with a key derived from this machine's
fingerprint. A state file copied to another machine decrypts to nothing there, so
a stolen identity cannot be reused elsewhere — the probe simply re-registers.
"""
from __future__ import annotations

import base64
import hashlib
import json

from cryptography.fernet import Fernet, InvalidToken

_PEPPER = b"intrynx-probe-state-v1"


def _key(host_fp: str) -> bytes:
    return base64.urlsafe_b64encode(hashlib.sha256(_PEPPER + host_fp.encode()).digest())


def encrypt_state(data: dict, host_fp: str) -> str:
    return Fernet(_key(host_fp)).encrypt(json.dumps(data).encode()).decode()


def decrypt_state(blob: str, host_fp: str) -> dict:
    """Decrypt a state blob; returns {} if it was written on a different machine."""
    if not blob:
        return {}
    try:
        return json.loads(Fernet(_key(host_fp)).decrypt(blob.encode()).decode())
    except (InvalidToken, ValueError, TypeError):
        return {}
