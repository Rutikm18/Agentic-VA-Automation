"""Vulnerability & misconfiguration scanning via nuclei."""
from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
from typing import Any

from .base import normalize_targets, now, result, run_cmd, scanner

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


def parse_nuclei_jsonl(output: str) -> list[dict[str, Any]]:
    """nuclei -jsonl → [{template_id, name, severity, matched_at, cves, tags, ...}]."""
    findings: list[dict[str, Any]] = []
    for line in output.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = row.get("info", {}) or {}
        tid = row.get("template-id") or row.get("templateID") or ""
        desc = info.get("description", "") or ""
        cves = sorted({m.upper() for m in _CVE_RE.findall(f"{tid} {desc}")})
        classification = info.get("classification", {}) or {}
        findings.append({
            "template_id": tid,
            "name": info.get("name", tid),
            "severity": (info.get("severity") or "info").lower(),
            "matched_at": row.get("matched-at") or row.get("host") or "",
            "type": row.get("type"),
            "cves": cves or (classification.get("cve-id") or []),
            "cvss": classification.get("cvss-score"),
            "tags": info.get("tags", []),
            "reference": info.get("reference", []),
            "curl": row.get("curl-command", ""),
        })
    return findings


@scanner("vuln_scan", "nuclei", "Vulnerability & misconfiguration scan")
def vuln_scan(params: dict) -> dict:
    targets = normalize_targets(params)
    if not targets:
        return result("vuln_scan", "nuclei", [], ok=False, error="no targets provided")
    started = now()

    tags = params.get("tags") or ["cve", "misconfiguration", "exposure", "default-login"]
    severity = params.get("severity")  # e.g. "critical,high,medium"

    tf = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False)
    try:
        tf.write("\n".join(targets))
        tf.close()
        cmd = [
            "nuclei", "-l", tf.name, "-jsonl", "-silent", "-no-color",
            "-rate-limit", str(params.get("rate_limit", 150)),
            "-timeout", str(params.get("http_timeout", 10)),
        ]
        if tags:
            cmd += ["-tags", ",".join(tags)]
        if severity:
            cmd += ["-severity", severity]
        try:
            proc = run_cmd(cmd, timeout=int(params.get("timeout", 1800)))
        except subprocess.TimeoutExpired:
            return result("vuln_scan", "nuclei", targets, ok=False, error="nuclei timed out", started=started)
    finally:
        try:
            os.unlink(tf.name)
        except OSError:
            pass

    findings = parse_nuclei_jsonl(proc.stdout)
    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
    return result("vuln_scan", "nuclei", targets, findings=findings,
                  finding_count=len(findings), by_severity=by_sev, started=started)
