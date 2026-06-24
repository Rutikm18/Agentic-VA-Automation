"""
vuln_db.py — offline, pinned vulnerability data store.

NO LIVE API CALLS HAPPEN DURING MATCHING. sync_snapshot() is the only
function in this module that talks to the network, and it is never called
by the detection pipeline itself — only by the separate, explicit,
out-of-band update step (run this file directly, or call sync_snapshot()
from a scheduled job). load_snapshot()/VulnDB.lookup() read only the local
JSON file already on disk. Same snapshot in -> same findings out, on any
machine, on any day — that reproducibility is the entire point of pinning.

DATA SOURCE: OSV (https://osv.dev), not NVD — verified during this build
that NVD's REST API was unreachable from this environment, while OSV's was
not, AND the spec's own preference ordering already lists OSV first for
"best version-range semantics". OSV's `Debian:<release>` ecosystem uses the
exact same package names dpkg emits (see cpe_normalizer.py's
_PACKAGE_TO_CPE table) and tracks each advisory's fix status PER DEBIAN
RELEASE rather than against the upstream version string — this is the
correct, backport-aware behavior the spec's "Pitfall — distro backports"
warning asks for, not something this module has to reimplement by hand.

SNAPSHOT FORMAT (local JSON file):
{
  "fetched_at": "2026-06-24T00:00:00Z",
  "ecosystem": "Debian:12",
  "products": ["openssh", "nginx", ...],
  "content_hash": "<sha256 of the records below, hex>",
  "records": { "<product>": [ <raw OSV vuln object>, ... ], ... }
}
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_SNAPSHOT_PATH = Path(__file__).parent / "snapshots" / "osv_debian_snapshot.json"


def _default_products() -> list[str]:
    """Derives the synced product list from cpe_normalizer.py's tables —
    the single source of truth — rather than maintaining a second, separate
    list here. An earlier version of this file DID hardcode its own list,
    which silently drifted out of sync with cpe_normalizer.py's tables
    (different product-name conventions in each) and caused real
    lookup-key mismatches caught only by testing against live data; see
    cpe_normalizer.py's CPECandidate.lookup_key field and module comment.
    """
    from cpe_normalizer import all_osv_source_packages
    return all_osv_source_packages()


DEFAULT_PRODUCTS = _default_products()


def _content_hash(records: dict[str, list[dict]]) -> str:
    """Stable hash of the snapshot's actual vulnerability content — recorded
    in every run's metadata (Finding.db_snapshot_hash) so two runs against
    the same snapshot are provably comparable, and a run against a refreshed
    snapshot is visibly NOT the same basis for comparison.
    """
    canonical = json.dumps(records, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


@dataclass
class SnapshotMeta:
    fetched_at: str
    ecosystem: str
    products: list[str]
    content_hash: str
    path: str


class VulnDB:
    """In-memory index over a loaded snapshot: product -> OSV vuln records.
    Construction never touches the network — see load_snapshot().
    """

    def __init__(self, records: dict[str, list[dict]], meta: SnapshotMeta):
        self._records = records
        self.meta = meta

    def lookup(self, product: str) -> list[dict]:
        """Raw OSV vulnerability records for this product, or [] if the
        snapshot doesn't cover it. Returns the records AS STORED — range
        comparison is Phase 1.4's job (matcher.py), not this module's; this
        is an index lookup, not a matcher.
        """
        return self._records.get(product, [])

    def covers(self, product: str) -> bool:
        return product in self._records

    def get_cvss_vector(self, cve_id: str) -> str | None:
        """The CVSS v3 vector string OSV embedded for this CVE, if any.
        Searches ALL products, not just one — a CVE id is globally unique,
        so product-scoping here would only be a (premature) optimization,
        not a correctness requirement, and the caller (enrichment.py) may
        not always know which lookup_key produced a given Finding.
        """
        for records in self._records.values():
            for rec in records:
                if cve_id not in (rec.get("upstream") or [rec["id"]]):
                    continue
                for sev in rec.get("severity", []):
                    if sev.get("type") == "CVSS_V3":
                        return sev["score"]
        return None

    def known_products(self) -> list[str]:
        return sorted(self._records.keys())


def load_snapshot(path: str | Path = DEFAULT_SNAPSHOT_PATH) -> VulnDB:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(
            f"no vulnerability snapshot at {path} — run "
            f"`python3 vuln_db.py sync` first (out-of-band, not part of "
            f"detection itself)")
    with path.open("r", encoding="utf-8") as fh:
        snap = json.load(fh)
    recomputed = _content_hash(snap["records"])
    if recomputed != snap["content_hash"]:
        raise ValueError(
            f"snapshot {path} failed its own content-hash check "
            f"(expected {snap['content_hash'][:12]}, got {recomputed[:12]}) "
            f"— file was modified after being written; re-sync rather than "
            f"trust a snapshot that doesn't match its own pin")
    meta = SnapshotMeta(
        fetched_at=snap["fetched_at"], ecosystem=snap["ecosystem"],
        products=snap["products"], content_hash=snap["content_hash"],
        path=str(path))
    return VulnDB(snap["records"], meta)
