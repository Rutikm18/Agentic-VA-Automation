"""
cpe_normalizer.py — observed strings -> CPE 2.3 candidates, deterministically.

WHY A CANDIDATE LIST, NOT A SINGLE CPE: a banner often supports several
products (an HTTP Server header naming a reverse proxy says nothing about
the real backend it fronts; a single header is the weakest evidence this
module handles). Every normalize_* function below returns zero or more
CPECandidate objects with an explicit confidence, never a bare CPE string —
collapsing to one early would silently discard the ambiguity Phase 1.4 (the
matcher) and Phase 3 (the verifier) both need to reason about.

CONFIDENCE LEVELS (deliberately only three, not a continuous score yet —
that calibration work belongs to Phase 3's verifier, not here):
  high   — credentialed package list (the host told us directly; this is
           the Fact.source_confidence == authoritative path) or a clean,
           unambiguous engine+version pair (e.g. db_scanner's real protocol
           handshake, not a guess).
  medium — a structured field that names a real product clearly but with
           some residual ambiguity (e.g. db_scanner's "mysql/mariadb" engine
           string covers two different real vendors).
  low    — a single banner/header string with no corroboration. Banners
           lie: honeypots, deception tech, and reverse proxies fronting a
           different real backend all produce a plausible-looking but wrong
           single-source match. This is the tier Phase 1.4 must treat as
           "suspected, backport-possible" rather than "confirmed", per spec.

Versions are NEVER discarded — every CPECandidate keeps version_raw exactly
as observed alongside whatever version_normalized this module could clean
out of it (distro suffixes, epoch). version_normalized is None when the
string couldn't be confidently cleaned; callers must not silently treat that
as "no version" without checking version_raw first.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from models import Fact, SourceConfidence


@dataclass
class CPECandidate:
    vendor: str
    product: str
    version_raw: str | None
    version_normalized: str | None
    confidence: str                # "high" | "medium" | "low" — PRODUCT/VERSION
                                    # identification certainty (e.g. is "mysql/mariadb"
                                    # ambiguous about vendor). NOT the same axis as
                                    # source_confidence below — a single HTTP header
                                    # can unambiguously identify "nginx" (so the
                                    # mapping itself is clean) while still being a
                                    # banner that could be lying (low source_confidence).
    source_confidence: SourceConfidence  # was the OBSERVATION authoritative
                                    # (credentialed) or inferred (network-observable)?
                                    # This is the field matcher.py's confirmed-vs-
                                    # suspected decision actually keys off — never
                                    # proxy that decision through `confidence` above.
    basis: str                     # human-readable: what observation produced this
    source_ref: str                # the Fact.ref() this candidate came from
    ai_assisted: bool = False       # True only for candidates ai_normalizer.py
                                    # produced (Phase 2) — every rule-based
                                    # normalize_* function in this module
                                    # leaves this at the default False.
    lookup_key: str = ""            # the key matcher.py queries the vuln DB
                                    # with — the OSV SOURCE PACKAGE name, which
                                    # often differs from both `product` (the
                                    # CPE vocabulary name) and whatever binary
                                    # package name was actually observed. See
                                    # _PACKAGE_TO_CPE's module-level comment.

    def cpe23(self) -> str:
        ver = self.version_normalized or self.version_raw or "*"
        return f"cpe:2.3:a:{self.vendor}:{self.product}:{ver}:*:*:*:*:*:*:*"


def clean_debian_version(raw: str) -> tuple[str, str | None]:
    """dpkg version syntax: [epoch:]upstream_version[-debian_revision].
    '1:8.4p1-5+deb11u1' -> ('8.4p1', epoch='1'). Strips the Debian revision
    (the part this distro controls) and keeps the upstream version (the part
    that maps to an upstream CPE) — never discards the epoch, just returns
    it separately since it's not part of the upstream version string at all.
    """
    epoch: str | None = None
    rest = raw
    if ":" in raw:
        epoch, rest = raw.split(":", 1)
    upstream = rest.split("-", 1)[0] if "-" in rest else rest
    return upstream, epoch


def clean_rpm_version(version_release: str) -> str:
    """rpm queried as '%{VERSION}-%{RELEASE}' (see ssh_collector.py's
    rpm_packages command) — VERSION and RELEASE are already separate rpm
    fields joined by us with '-', so the upstream version is simply
    everything before the LAST '-' (the release, e.g. '19.el8', is always
    the final segment; the version itself may legitimately contain '-').
    '8.0p1-19.el8' -> '8.0p1'.
    """
    return version_release.rsplit("-", 1)[0] if "-" in version_release else version_release


# Curated starter table — common, security-relevant services. NOT exhaustive
# (the real package universe is tens of thousands of names); extend as real
# engagements surface products this misses. A name with no entry here simply
# produces no CPECandidate, never a guessed/wrong one.
#
# binary_package_name -> (osv_source_package_name, cpe_vendor, cpe_product).
# The THREE strings are frequently different and each verified individually
# against the real OSV API while building this (not guessed):
#   - dpkg/rpm report the BINARY package name (e.g. "openssh-server").
#   - OSV's Debian ecosystem indexes vulnerabilities by SOURCE package name
#     (e.g. "openssh") — querying OSV for "openssh-server" returns nothing.
#   - CPE 2.3 uses its own vendor:product vocabulary (e.g. "openbsd:openssh"),
#     which can differ from both of the above.
# update_snapshot.py's product sync list and matcher.py's vuln_db lookups
# both derive from THIS table (via osv_source_package()/cpe_for() below) —
# there is deliberately no second, separately-maintained list anywhere else.
#
# KNOWN LIMITATION: Debian 12 ships no vanilla-MySQL source package (only
# MariaDB, due to MySQL's licensing) — "mysql-server" is mapped to MariaDB's
# OSV coverage as a best-effort approximation. A host running genuine Oracle
# MySQL will get MariaDB's CVE history, which is related but not identical.
# Documented here rather than silently assumed correct.
_PACKAGE_TO_CPE: dict[str, tuple[str, str, str]] = {
    # binary_pkg: (osv_source_pkg, cpe_vendor, cpe_product)
    "openssh-server": ("openssh", "openbsd", "openssh"),
    "openssh-client": ("openssh", "openbsd", "openssh"),
    "nginx": ("nginx", "nginx", "nginx"),
    "apache2": ("apache2", "apache", "http_server"),
    "httpd": ("apache2", "apache", "http_server"),
    "mysql-server": ("mariadb", "mysql", "mysql"),          # see KNOWN LIMITATION above
    "mariadb-server": ("mariadb", "mariadb", "mariadb"),
    "postgresql": ("postgresql-15", "postgresql", "postgresql"),
    "redis-server": ("redis", "redis", "redis"),
    "redis": ("redis", "redis", "redis"),
    "vsftpd": ("vsftpd", "vsftpd_project", "vsftpd"),
    "samba": ("samba", "samba", "samba"),
    "samba-common": ("samba", "samba", "samba"),
    "openssl": ("openssl", "openssl", "openssl"),
    "curl": ("curl", "haxx", "curl"),
    "bind9": ("bind9", "isc", "bind"),
    "proftpd-basic": ("proftpd-dfsg", "proftpd", "proftpd"),
    "dnsmasq": ("dnsmasq", "thekelleys", "dnsmasq"),
    "docker-ce": ("docker.io", "docker", "docker"),
}


def osv_source_packages() -> list[str]:
    """Every distinct OSV source-package name _PACKAGE_TO_CPE covers."""
    return sorted({v[0] for v in _PACKAGE_TO_CPE.values()})

# HTTP/SSH "product/version" header product names -> (osv_source_pkg,
# cpe_vendor, cpe_product). Lowercased lookup. Same 3-tuple shape and same
# "verified against the real OSV API, not guessed" discipline as
# _PACKAGE_TO_CPE above — "apache" is the http-header product name but
# "apache2" is its Debian/OSV source package, exactly the kind of mismatch
# that table's comment warns about.
_HEADER_PRODUCT_TO_CPE: dict[str, tuple[str, str, str]] = {
    "nginx": ("nginx", "nginx", "nginx"),
    "apache": ("apache2", "apache", "http_server"),
    "openssh": ("openssh", "openbsd", "openssh"),
    "microsoft-iis": ("iis", "microsoft", "internet_information_services"),
    "lighttpd": ("lighttpd", "lighttpd", "lighttpd"),
    "boa": ("boa", "boa", "boa"),  # not in OSV's Debian ecosystem (embedded
                                    # router software) — kept for CPE-display
                                    # completeness; will simply never match.
}

# Web tech_hints[] (scanner_module/scanner/web_scanner.py's _TECH_HINTS keys)
# -> CPE. These never carry a version (web_scanner only detects presence),
# so candidates from this table always have version_raw=None.
_TECH_HINT_TO_CPE: dict[str, tuple[str, str]] = {
    "wordpress": ("wordpress", "wordpress"),
    "drupal": ("drupal", "drupal"),
    "joomla": ("joomla", "joomla"),
    "jenkins": ("jenkins", "jenkins"),
    "grafana": ("grafana", "grafana"),
    "kibana": ("elastic", "kibana"),
}

# db_scanner.py's `data.engine` string -> (osv_source_pkg, vendor, product,
# confidence). "mysql/mariadb" maps to MariaDB's OSV coverage specifically
# (the only one of the two with a Debian source package — see
# _PACKAGE_TO_CPE's KNOWN LIMITATION note). The "medium" confidence here is
# the base/fallback value; normalize_db() below upgrades it to "high" (and,
# critically, only attempts a version match AT ALL) when the raw version
# string self-identifies as MariaDB — found necessary via testing against a
# real MySQL server, not assumed: the probe alone can't distinguish the two
# real, differently-CVE'd, differently-versioned products, and blindly
# matching an unrelated MySQL version against MariaDB's CVE ranges produces
# a flood of false positives (every MariaDB fix-version >= 10.0 looks newer
# than any MySQL 8.x/9.x string numerically). See normalize_db's docstring.
_DB_ENGINE_TO_CPE: dict[str, tuple[str, str, str, str]] = {
    # engine string -> (osv_source_pkg, vendor, product, confidence)
    "mysql/mariadb": ("mariadb", "mysql", "mysql", "medium"),
    "postgresql": ("postgresql-15", "postgresql", "postgresql", "high"),
    "redis": ("redis", "redis", "redis", "high"),
    # mongodb/mssql: VERIFIED zero Debian-ecosystem OSV coverage (neither is
    # Debian-packaged — proprietary licensing). Kept here for CPE-display
    # completeness and so a future non-Debian-ecosystem snapshot can cover
    # them without a cpe_normalizer.py change; they will simply never
    # produce a Finding against this Debian-only snapshot, by design.
    "mongodb": ("mongodb", "mongodb", "mongodb", "high"),
    "microsoft sql server": ("mssql", "microsoft", "sql_server", "medium"),
}

_SSH_BANNER_RE = re.compile(r"SSH-[\d.]+-OpenSSH_([\w.]+)")
# "product/version" header shape, e.g. "nginx/1.18.0 (Ubuntu)", "Boa/0.93.15".
_HTTP_SERVER_RE = re.compile(r"^([A-Za-z][\w.-]*?)/([\d][\w.+-]*)")


def normalize_banner(fact: Fact) -> list[CPECandidate]:
    """service_banner.py's first_line/banner text -> CPE. SSH only for now —
    generic banner text for other protocols is too unstructured to safely
    parse without a much larger per-protocol grammar; extend deliberately,
    not by loosening this regex.
    """
    text = fact.data.get("first_line") or fact.data.get("banner") or ""
    m = _SSH_BANNER_RE.search(text)
    if not m:
        return []
    return [CPECandidate(
        vendor="openbsd", product="openssh", lookup_key="openssh",
        version_raw=m.group(1), version_normalized=m.group(1),
        confidence="low", source_confidence=fact.source_confidence,
        basis=f"SSH banner: {text[:80]!r}", source_ref=fact.ref(),
    )]


def normalize_web(fact: Fact) -> list[CPECandidate]:
    """web_scanner.py's Server header + tech_hints[] -> CPE candidates."""
    out: list[CPECandidate] = []
    server = fact.data.get("server") or ""
    m = _HTTP_SERVER_RE.match(server)
    if m:
        mapped = _HEADER_PRODUCT_TO_CPE.get(m.group(1).lower())
        if mapped:
            osv_key, vendor, product = mapped
            out.append(CPECandidate(
                vendor=vendor, product=product, lookup_key=osv_key,
                version_raw=m.group(2), version_normalized=m.group(2),
                confidence="low", source_confidence=fact.source_confidence,
                basis=f"HTTP Server header: {server!r}", source_ref=fact.ref(),
            ))
    for hint in fact.data.get("tech_hints") or []:
        mapped = _TECH_HINT_TO_CPE.get(hint)
        if mapped:
            vendor, product = mapped
            out.append(CPECandidate(
                vendor=vendor, product=product, lookup_key=product,
                version_raw=None, version_normalized=None,
                confidence="low", source_confidence=fact.source_confidence,
                basis=f"tech_hint: {hint!r}", source_ref=fact.ref(),
            ))
    return out


def normalize_db(fact: Fact) -> list[CPECandidate]:
    """db_scanner.py's real-protocol-handshake engine + server_version -> CPE.

    "mysql/mariadb" needs special handling, found via testing against a real
    MySQL server, not assumed: MySQL and MariaDB have COMPLETELY UNRELATED
    version numbering (MariaDB: 10.x/11.x; MySQL: 8.x/9.x+ Innovation
    releases) — blindly range-matching a bare version string like "9.6.0"
    against MariaDB's CVE history makes EVERY MariaDB fix-version >= 10.0
    look like it applies (9 < 10 numerically), producing a flood of false
    "suspected" findings against a real, current, unrelated MySQL install.
    The wire protocol does carry a real disambiguating signal though: a
    genuine MariaDB server's version string self-identifies with a
    "-MariaDB" suffix (e.g. "10.11.6-MariaDB"); real Oracle MySQL doesn't.
    Only route to MariaDB's OSV coverage when that signal is actually
    present — otherwise this engine produces no version-matching candidate
    at all (OSV's Debian ecosystem has zero real MySQL coverage anyway, see
    _PACKAGE_TO_CPE's KNOWN LIMITATION; matching nothing is more honest
    than matching the wrong product).
    """
    engine = fact.data.get("engine")
    mapped = _DB_ENGINE_TO_CPE.get(engine) if engine else None
    if not mapped:
        return []
    osv_key, vendor, product, confidence = mapped
    version = fact.data.get("server_version")

    if engine == "mysql/mariadb":
        is_really_mariadb = bool(version) and "mariadb" in version.lower()
        if not is_really_mariadb:
            return []  # no safe OSV match available for this engine string
        confidence = "high"  # the suffix makes this unambiguous, not "medium"

    return [CPECandidate(
        vendor=vendor, product=product, lookup_key=osv_key,
        version_raw=version, version_normalized=version,
        confidence=confidence if version else "low",
        source_confidence=fact.source_confidence,
        basis=f"db_scan engine={engine!r} version={version!r}",
        source_ref=fact.ref(),
    )]


def _parse_package_lines(text: str, version_cleaner) -> list[tuple[str, str, str]]:
    """Yields (package_name, raw_version, upstream_version) for each
    'name version' line that maps to a known package."""
    out = []
    for line in text.splitlines():
        parts = line.strip().split(" ", 1)
        if len(parts) != 2 or not parts[1]:
            continue
        name, raw_version = parts
        if name in _PACKAGE_TO_CPE:
            out.append((name, raw_version, version_cleaner(raw_version)))
    return out


def normalize_credentialed_packages(fact: Fact) -> list[CPECandidate]:
    """ssh_inventory's dpkg_packages/rpm_packages -> CPE candidates. ALL high
    confidence — this is the host's own authoritative installed-package
    state (Fact.source_confidence == authoritative), not a guess.
    """
    inventory = fact.data.get("inventory") or {}
    out: list[CPECandidate] = []
    for name, raw_version, upstream in _parse_package_lines(
            inventory.get("dpkg_packages") or "",
            lambda v: clean_debian_version(v)[0]):
        osv_key, vendor, product = _PACKAGE_TO_CPE[name]
        out.append(CPECandidate(
            vendor=vendor, product=product, lookup_key=osv_key,
            version_raw=raw_version, version_normalized=upstream, confidence="high",
            source_confidence=fact.source_confidence,
            basis=f"dpkg package {name} {raw_version}", source_ref=fact.ref()))
    for name, raw_version, upstream in _parse_package_lines(
            inventory.get("rpm_packages") or "", clean_rpm_version):
        osv_key, vendor, product = _PACKAGE_TO_CPE[name]
        out.append(CPECandidate(
            vendor=vendor, product=product, lookup_key=osv_key,
            version_raw=raw_version, version_normalized=upstream, confidence="high",
            source_confidence=fact.source_confidence,
            basis=f"rpm package {name} {raw_version}", source_ref=fact.ref()))
    return out


_DISPATCH = {
    "service_banner": normalize_banner,
    "web_scan": normalize_web,
    "db_scan": normalize_db,
    "ssh_inventory": normalize_credentialed_packages,
}


def normalize(fact: Fact) -> list[CPECandidate]:
    """Dispatch a single Fact to the right parser based on which scanner
    produced it. A scanner with no registered parser yields no candidates —
    not an error, just nothing to normalize from that fact type yet.
    """
    parser = _DISPATCH.get(fact.scanner)
    return parser(fact) if parser else []


def all_osv_source_packages() -> list[str]:
    """Every distinct OSV source-package name across ALL three tables
    (credentialed packages, HTTP/SSH headers, db_scan engines) — what
    update_snapshot.py actually syncs. One combined function, not three
    separately-maintained product lists living in different files; that
    drift is exactly what caused the lookup_key/product mismatch bug this
    module's CPECandidate.lookup_key field exists to prevent from recurring.
    """
    keys = {v[0] for v in _PACKAGE_TO_CPE.values()}
    keys |= {v[0] for v in _HEADER_PRODUCT_TO_CPE.values()}
    keys |= {v[0] for v in _DB_ENGINE_TO_CPE.values()}
    return sorted(keys)
