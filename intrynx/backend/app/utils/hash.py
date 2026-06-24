"""
Shared hashing utilities — deduplication keys, fingerprinting.
"""
from __future__ import annotations

import hashlib
from typing import Any


def dedup_hash(asset_id: str | None, cve_id: str | None, plugin_id: Any) -> str:
    """
    SHA-256 of (asset_id, cve_id, plugin_id) for finding deduplication.

    Used by both VulnEnrichmentService and post-scan enrichment tasks so the
    dedup logic lives in one place.
    """
    key = f"{asset_id or ''}|{(cve_id or '').upper()}|{plugin_id or ''}"
    return hashlib.sha256(key.encode()).hexdigest()
