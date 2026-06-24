"""
Cross-validates the pure-Python Debian version comparator against the real
`dpkg --compare-versions` binary (ground truth, not hand-reasoning about the
algorithm) across known pairs — per spec: "highest FP-risk component;
unit-test it against known pairs."

Pairs include real version strings pulled from the actual OSV snapshot
fetched in this session (nginx, openssh) plus the classic Debian-policy
edge cases (epoch, tilde, alpha-vs-non-alpha ordering) that are exactly
where a naive string/semver comparison gets it wrong.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from version_compare import _dpkg_compare_pure_python, _HAVE_DPKG, dpkg_compare

# (a, b, expected_sign) — expected_sign: -1 means a<b, 0 means a==b, 1 means a>b
KNOWN_PAIRS = [
    # basic numeric ordering
    ("1.0", "1.1", -1),
    ("1.10", "1.9", 1),          # numeric, not lexicographic ("10" > "9")
    ("1.0", "1.0", 0),
    # epoch dominates everything else
    ("1:1.0", "2.0", 1),
    ("1:8.4p1-5+deb11u1", "8.4p1", 1),
    # debian revision comparison
    ("1.0-1", "1.0-2", -1),
    ("0.7.61-3", "0.7.62", -1),   # real pair from the nginx OSV snapshot
    ("0.7.61-3", "0.7.61-3", 0),
    # tilde sorts before EVERYTHING, including the empty string
    ("1.0~beta1", "1.0", -1),
    ("1.0~~", "1.0~", -1),
    ("1.0~rc1", "1.0~rc2", -1),
    # real openssh-shaped pairs
    ("8.4p1-5+deb11u1", "8.4p1-6+deb11u1", -1),
    ("9.6p1-3", "8.4p1-5", 1),
    # rpm-shaped (no epoch, dot-separated release)
    ("8.0p1-19.el8", "8.0p1-20.el8", -1),
    ("2.4.37-65.el8", "2.4.37-43.el8", 1),
]


def test_pure_python_matches_known_pairs():
    for a, b, expected in KNOWN_PAIRS:
        got = _dpkg_compare_pure_python(a, b)
        sign = (got > 0) - (got < 0)
        assert sign == expected, f"_dpkg_compare_pure_python({a!r}, {b!r}) = {got} (sign {sign}), expected {expected}"


def test_pure_python_matches_real_dpkg_binary():
    if not _HAVE_DPKG:
        return  # nothing to cross-validate against on this machine
    for a, b, _expected in KNOWN_PAIRS:
        pure = _dpkg_compare_pure_python(a, b)
        pure_sign = (pure > 0) - (pure < 0)
        from version_compare import _dpkg_compare_via_binary
        real = _dpkg_compare_via_binary(a, b)
        assert real is not None
        assert pure_sign == real, (
            f"mismatch on ({a!r}, {b!r}): pure-python={pure_sign}, real dpkg={real}")


def test_dpkg_compare_public_api():
    assert dpkg_compare("1.0", "1.1") == -1
    assert dpkg_compare("1.0", "1.0") == 0
    assert dpkg_compare("2.0", "1.0") == 1


if __name__ == "__main__":
    test_pure_python_matches_known_pairs()
    print(f"test_pure_python_matches_known_pairs: PASS ({len(KNOWN_PAIRS)} pairs)")
    test_pure_python_matches_real_dpkg_binary()
    print(f"test_pure_python_matches_real_dpkg_binary: PASS (cross-validated against real dpkg={_HAVE_DPKG})")
    test_dpkg_compare_public_api()
    print("test_dpkg_compare_public_api: PASS")
