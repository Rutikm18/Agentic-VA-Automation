"""
version_compare.py — per-scheme version comparators.

Spec calls this "the highest FP-risk component" — get Debian/RPM version
ordering wrong and every backport-fixed host looks vulnerable. Rather than
trust a from-scratch reimplementation of dpkg's notoriously fiddly
comparison algorithm (the `~` sort-before-everything rule, epoch handling,
and the letters-before-non-letters ASCII tweak are all easy to get subtly
wrong), this module PREFERS the real `dpkg --compare-versions` binary when
present — the authoritative reference implementation — and only falls back
to a hand-rolled pure-Python version when it isn't installed. Same
prefer-the-real-tool-fall-back-to-pure-Python pattern as
scanner_module/scanner/mass_scan.py's masscan/connect-sweep split.

The pure-Python fallback is unit-tested against the real dpkg binary as
ground truth (see tests/test_version_compare.py) wherever both are
available — not validated by hand-reasoning about the algorithm alone.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from functools import lru_cache

_HAVE_DPKG = shutil.which("dpkg") is not None


@lru_cache(maxsize=4096)
def _dpkg_compare_via_binary(a: str, b: str) -> int | None:
    """Real dpkg --compare-versions. None (not an error) if dpkg isn't
    installed or the call fails for any reason — callers fall back."""
    if not _HAVE_DPKG:
        return None
    try:
        lt = subprocess.run(["dpkg", "--compare-versions", a, "lt", b],
                            capture_output=True, timeout=5)
        if lt.returncode == 0:
            return -1
        eq = subprocess.run(["dpkg", "--compare-versions", a, "eq", b],
                            capture_output=True, timeout=5)
        if eq.returncode == 0:
            return 0
        return 1
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None


_SEGMENT_RE = re.compile(r"(\d+|\D+)")


def _char_order(c: str | None) -> int:
    """dpkg's non-digit character ordering: '~' sorts before EVERYTHING,
    including a segment that has already ended (so '1.0~beta1' < '1.0' —
    the tilde marks a pre-release, "earlier than the thing it modifies").
    Letters sort before non-letters; otherwise plain ASCII order within
    each class. End-of-string must rank ABOVE '~' but below every real
    character, or "1.0~beta1" would wrongly compare as > "1.0"."""
    if c == "~":
        return -1
    if c is None:
        return 0
    if c.isalpha():
        return ord(c)
    return ord(c) + 1000  # non-letters sort after all letters


def _compare_non_digit(a: str, b: str) -> int:
    la, lb = len(a), len(b)
    for i in range(max(la, lb)):
        oa = _char_order(a[i] if i < la else None)
        ob = _char_order(b[i] if i < lb else None)
        if oa != ob:
            return -1 if oa < ob else 1
    return 0


def _split_segments(v: str) -> list[str]:
    parts = _SEGMENT_RE.findall(v)
    if not parts or parts[0][0].isdigit():
        parts = [""] + parts
    return parts


def _compare_part(a: str, b: str) -> int:
    """upstream_version or debian_revision comparison (no epoch, no '-')."""
    a_parts, b_parts = _split_segments(a), _split_segments(b)
    n = max(len(a_parts), len(b_parts))
    for i in range(n):
        pa = a_parts[i] if i < len(a_parts) else ""
        pb = b_parts[i] if i < len(b_parts) else ""
        is_digit_turn = (i % 2 == 1)
        if is_digit_turn:
            ia, ib = int(pa or "0"), int(pb or "0")
            if ia != ib:
                return -1 if ia < ib else 1
        else:
            c = _compare_non_digit(pa, pb)
            if c != 0:
                return c
    return 0


def _split_dpkg_version(v: str) -> tuple[str, str, str]:
    """'1:8.4p1-5+deb11u1' -> (epoch='1', upstream='8.4p1', revision='5+deb11u1').
    No epoch prefix defaults to '0' — this is correct, standards-compliant
    dpkg behavior (and matches the real binary, which this module is
    cross-validated against) and must NOT be changed to "fix" the epoch-
    mismatch problem; see has_ambiguous_epoch() below for where that
    actually belongs.
    """
    epoch = "0"
    rest = v
    if ":" in v:
        epoch, rest = v.split(":", 1)
    if "-" in rest:
        upstream, revision = rest.rsplit("-", 1)
    else:
        upstream, revision = rest, "0"
    return epoch, upstream, revision


def has_ambiguous_epoch(a: str, b: str) -> bool:
    """True when exactly one of the two version strings carries an explicit,
    non-zero epoch prefix and the other has none at all.

    This is NOT a dpkg-semantics question (dpkg correctly treats a missing
    epoch as 0, always) — it's a DATA-PROVENANCE question this module is
    deliberately separate from: a banner/protocol-handshake-derived version
    (e.g. db_scanner.py reading a raw wire-protocol version string) can
    NEVER carry epoch info — the running binary has no concept of Debian
    packaging epochs at all — while a real Debian package version
    legitimately might. Comparing the two with dpkg's correct epoch=0
    default produces a comparison that LOOKS precise but is actually
    comparing across a representational gap (found via testing: a banner-
    derived MariaDB version compared against a real epoch-1 CVE fix range
    was wrongly judged "vulnerable" purely because of the epoch default,
    regardless of the actual upstream version numbers). Callers in
    matcher.py use this to skip a comparison entirely rather than trust a
    misleadingly confident answer.
    """
    # OSV's "0" is a universal sentinel meaning "no lower bound at all", not
    # a real version missing epoch info — never ambiguous against anything.
    if a == "0" or b == "0":
        return False
    ea, _, _ = _split_dpkg_version(a)
    eb, _, _ = _split_dpkg_version(b)
    a_has_epoch, b_has_epoch = ":" in a, ":" in b
    if a_has_epoch == b_has_epoch:
        return False  # both specify one (or both don't) — no ambiguity
    nonzero_epoch = eb if a_has_epoch is False else ea
    return nonzero_epoch != "0"


def _dpkg_compare_pure_python(a: str, b: str) -> int:
    ea, ua, ra = _split_dpkg_version(a)
    eb, ub, rb = _split_dpkg_version(b)
    if int(ea) != int(eb):
        return -1 if int(ea) < int(eb) else 1
    c = _compare_part(ua, ub)
    if c != 0:
        return c
    return _compare_part(ra, rb)


def dpkg_compare(a: str, b: str) -> int:
    """-1 if a<b, 0 if a==b, 1 if a>b, per Debian version ordering. Prefers
    the real dpkg binary; falls back to the pure-Python reimplementation."""
    if a == b:
        return 0
    via_binary = _dpkg_compare_via_binary(a, b)
    if via_binary is not None:
        return via_binary
    return _dpkg_compare_pure_python(a, b)


def semver_compare(a: str, b: str) -> int:
    """Plain dotted-numeric comparison for non-distro upstream versions
    (banner-derived, e.g. '8.4p1', '0.93.15'). Not full semver (no
    prerelease/build-metadata precedence rules) — deliberately simple,
    since banner strings rarely follow strict semver anyway; falls back to
    the dpkg-style comparator's segment logic, which handles mixed
    alpha/numeric segments like '8.4p1' sanely without needing distro
    epoch/revision splitting.
    """
    if a == b:
        return 0
    return _compare_part(a, b)
