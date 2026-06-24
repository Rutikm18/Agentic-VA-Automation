"""
update_snapshot.py — the ONLY module in this package that talks to the
network. Run by hand or from a scheduled job, never imported by ingest.py,
cpe_normalizer.py, matcher.py, or any other part of the detection path —
that separation is what makes "detection never auto-pulls mid-run" a fact
about the import graph, not just a comment someone could violate by
accident later.

Usage:
    python3 update_snapshot.py [--ecosystem Debian:12] [--products a,b,c]

Queries OSV's real API (api.osv.dev — no key required) for each product in
the list, against the Debian ecosystem (see vuln_db.py's module docstring
for why Debian specifically: it gives backport-aware fix tracking by
package name, the same names dpkg emits). Writes a content-hashed,
dated snapshot to snapshots/osv_debian_snapshot.json.
"""
from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import urllib.request
import urllib.error

from vuln_db import DEFAULT_PRODUCTS, DEFAULT_SNAPSHOT_PATH, _content_hash

OSV_QUERY_URL = "https://api.osv.dev/v1/query"


def _ssl_context() -> ssl.SSLContext:
    """Some macOS python.org installs ship expecting `Install Certificates.
    command` to have been run (it populates
    .../Python.framework/.../etc/openssl/cert.pem) and never have been —
    ssl.create_default_context() then fails with CERTIFICATE_VERIFY_FAILED
    even though the system's own CA bundle (the one curl/Security.framework
    use) is right there at /etc/ssl/cert.pem. Fall back to it explicitly
    rather than disabling verification.
    """
    ctx = ssl.create_default_context()
    try:
        ctx.load_verify_locations(cafile="/etc/ssl/cert.pem")
    except (FileNotFoundError, ssl.SSLError):
        pass  # fine elsewhere (Linux etc.) where the default context already works
    return ctx


def _query_osv(product: str, ecosystem: str, timeout: float = 15.0) -> list[dict]:
    """All known vulnerabilities OSV has for this (product, ecosystem) pair,
    with no version filter — we want the full advisory history so the local
    matcher (Phase 1.4) can apply its own range comparison later; filtering
    by version at sync time would mean re-syncing every time a new host
    shows up with a different installed version.
    """
    payload = json.dumps({"package": {"name": product, "ecosystem": ecosystem}}).encode()
    req = urllib.request.Request(
        OSV_QUERY_URL, data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "detection-engine-sync/1.0"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ssl_context()) as resp:
            data = json.loads(resp.read().decode())
            return data.get("vulns", [])
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as exc:
        print(f"  WARN: {product}: {exc}", file=sys.stderr)
        return []


def sync_snapshot(products: list[str] = None, ecosystem: str = "Debian:12",
                  out_path: str | Path = DEFAULT_SNAPSHOT_PATH,
                  rate_limit_sec: float = 0.5) -> dict:
    """Fetch real OSV records for every product, write a pinned snapshot.

    rate_limit_sec is a small courtesy delay between requests — OSV's API is
    free/unauthenticated, this is good citizenship, not a documented
    requirement of theirs.
    """
    products = products or DEFAULT_PRODUCTS
    records: dict[str, list[dict]] = {}
    for product in products:
        print(f"  fetching {product} ({ecosystem}) ...", file=sys.stderr)
        records[product] = _query_osv(product, ecosystem)
        time.sleep(rate_limit_sec)

    snapshot = {
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "ecosystem": ecosystem,
        "products": products,
        "content_hash": _content_hash(records),
        "records": records,
    }

    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as fh:
        json.dump(snapshot, fh, indent=2)

    total = sum(len(v) for v in records.values())
    print(f"wrote {out_path} — {total} records across {len(products)} products, "
          f"hash {snapshot['content_hash'][:12]}", file=sys.stderr)
    return snapshot


KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
DEFAULT_KEV_PATH = Path(__file__).parent / "snapshots" / "kev_snapshot.json"
DEFAULT_EPSS_PATH = Path(__file__).parent / "snapshots" / "epss_snapshot.json"


def sync_kev_snapshot(out_path: str | Path = DEFAULT_KEV_PATH) -> dict:
    """The full CISA Known Exploited Vulnerabilities catalog — a single flat
    list, not per-product, so this is its own small pinned snapshot."""
    req = urllib.request.Request(KEV_URL, headers={"User-Agent": "detection-engine-sync/1.0"})
    with urllib.request.urlopen(req, timeout=20, context=_ssl_context()) as resp:
        data = json.loads(resp.read().decode())
    cve_ids = sorted({v["cveID"].upper() for v in data.get("vulnerabilities", []) if "cveID" in v})
    snapshot = {
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "cve_ids": cve_ids,
        "content_hash": _content_hash({"cve_ids": cve_ids}),
    }
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as fh:
        json.dump(snapshot, fh, indent=2)
    print(f"wrote {out_path} — {len(cve_ids)} KEV-listed CVEs, "
          f"hash {snapshot['content_hash'][:12]}", file=sys.stderr)
    return snapshot


def sync_epss_snapshot(cve_ids: list[str], out_path: str | Path = DEFAULT_EPSS_PATH,
                       batch_size: int = 100, rate_limit_sec: float = 0.5) -> dict:
    """EPSS scores for exactly the CVE IDs this detection run actually cares
    about (the ones in the vuln snapshot) — not the entire EPSS universe,
    which is the whole CVE namespace and would be wasteful to mirror in full.
    """
    scores: dict[str, dict] = {}
    batches = [cve_ids[i:i + batch_size] for i in range(0, len(cve_ids), batch_size)]
    for batch in batches:
        url = f"{EPSS_URL}?cve={','.join(batch)}"
        req = urllib.request.Request(url, headers={"User-Agent": "detection-engine-sync/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=15, context=_ssl_context()) as resp:
                data = json.loads(resp.read().decode())
            for row in data.get("data", []):
                scores[row["cve"].upper()] = {
                    "epss": float(row["epss"]), "percentile": float(row["percentile"])}
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as exc:
            print(f"  WARN: EPSS batch failed: {exc}", file=sys.stderr)
        time.sleep(rate_limit_sec)

    snapshot = {
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "cve_count": len(scores),
        "content_hash": _content_hash(scores),
        "scores": scores,
    }
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as fh:
        json.dump(snapshot, fh, indent=2)
    print(f"wrote {out_path} — {len(scores)}/{len(cve_ids)} EPSS scores, "
          f"hash {snapshot['content_hash'][:12]}", file=sys.stderr)
    return snapshot


def _all_known_cve_ids(vuln_snapshot_path: str | Path = DEFAULT_SNAPSHOT_PATH) -> list[str]:
    with Path(vuln_snapshot_path).open() as fh:
        snap = json.load(fh)
    cves: set[str] = set()
    for vulns in snap["records"].values():
        for v in vulns:
            cves.update(v.get("upstream") or [v["id"]])
    return sorted(cves)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", nargs="?", default="vulns",
                        choices=["vulns", "kev", "epss", "all"],
                        help="which snapshot(s) to refresh (default: vulns)")
    parser.add_argument("--ecosystem", default="Debian:12")
    parser.add_argument("--products", default=None,
                        help="comma-separated; default is the curated starter list")
    parser.add_argument("--out", default=str(DEFAULT_SNAPSHOT_PATH))
    args = parser.parse_args()
    products = args.products.split(",") if args.products else None

    if args.target in ("vulns", "all"):
        sync_snapshot(products=products, ecosystem=args.ecosystem, out_path=args.out)
    if args.target in ("kev", "all"):
        sync_kev_snapshot()
    if args.target in ("epss", "all"):
        sync_epss_snapshot(_all_known_cve_ids(args.out))


if __name__ == "__main__":
    main()
