"""
cvss.py — CVSS v3.1 base score from a vector string. Pure arithmetic, no
network call — OSV's Debian-ecosystem records already embed the vector
string directly (see vuln_db's snapshot), this just derives the numeric
score the official way rather than guessing from impact letters.

Formula and constants are the official CVSS v3.1 specification
(first.org/cvss/v3.1/specification-document) §7 base score equations.
"""
from __future__ import annotations

import math

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup(x: float) -> float:
    """CVSS spec's exact rounding rule (avoids float-precision drift from a
    naive round-to-1-decimal): work in integer hundred-thousandths, round up
    to the next 0.1 unless already exactly on a 0.1 boundary.
    """
    int_input = round(x * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def parse_vector(vector: str) -> dict[str, str]:
    parts = vector.split("/")
    out: dict[str, str] = {}
    for p in parts:
        if ":" in p:
            k, v = p.split(":", 1)
            out[k] = v
    return out


def base_score(vector: str) -> float | None:
    """Returns the CVSS v3.1 base score (0.0-10.0), or None if the vector
    is missing required metrics (e.g. a CVSS v2 vector, or malformed input)
    — callers must treat None as "couldn't score", not as 0.0.
    """
    m = parse_vector(vector)
    try:
        av, ac, ui = _AV[m["AV"]], _AC[m["AC"]], _UI[m["UI"]]
        scope = m["S"]
        pr = (_PR_CHANGED if scope == "C" else _PR_UNCHANGED)[m["PR"]]
        c, i, a = _CIA[m["C"]], _CIA[m["I"]], _CIA[m["A"]]
    except KeyError:
        return None

    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    exploitability = 8.22 * av * ac * pr * ui

    if scope == "C":
        if iss <= 0:
            return 0.0
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
        return min(_roundup(1.08 * (impact + exploitability)), 10.0)
    else:
        if iss <= 0:
            return 0.0
        impact = 6.42 * iss
        return min(_roundup(impact + exploitability), 10.0)
