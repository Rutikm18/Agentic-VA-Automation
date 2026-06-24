"""
enrichment_db.py — load the pinned KEV/EPSS snapshots. Same discipline as
vuln_db.py: no network calls here, ever; update_snapshot.py is the only
module that fetches anything.
"""
from __future__ import annotations

import json
from pathlib import Path

from update_snapshot import DEFAULT_EPSS_PATH, DEFAULT_KEV_PATH


class KevDB:
    def __init__(self, cve_ids: set[str], fetched_at: str):
        self._cve_ids = cve_ids
        self.fetched_at = fetched_at

    def is_kev(self, cve_id: str) -> bool:
        return cve_id.upper() in self._cve_ids


class EpssDB:
    def __init__(self, scores: dict[str, dict], fetched_at: str):
        self._scores = scores
        self.fetched_at = fetched_at

    def get(self, cve_id: str) -> dict | None:
        """{'epss': float, 'percentile': float} or None if not covered."""
        return self._scores.get(cve_id.upper())


def load_kev(path: str | Path = DEFAULT_KEV_PATH) -> KevDB:
    with Path(path).open() as fh:
        snap = json.load(fh)
    return KevDB(set(snap["cve_ids"]), snap["fetched_at"])


def load_epss(path: str | Path = DEFAULT_EPSS_PATH) -> EpssDB:
    with Path(path).open() as fh:
        snap = json.load(fh)
    return EpssDB(snap["scores"], snap["fetched_at"])
