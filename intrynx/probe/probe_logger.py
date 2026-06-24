"""Structured per-scan logging and real-time debug output.

Every scan writes a JSONL record to ./logs/<YYYYMMDD_HHMMSS>_<scan_type>.jsonl
containing the commands run, their stdout/stderr, timing, and result summary.

Enable real-time debug output in two ways:
  PROBE_DEBUG=1 ./scan <target>
  ./scan <target> --debug
"""
from __future__ import annotations

import json
import os
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROBE_DIR = Path(__file__).resolve().parent
LOG_DIR = PROBE_DIR / "logs"

# Thread-local: holds the active ScanLog for this thread's scan.
_ctx = threading.local()


def _debug() -> bool:
    return os.environ.get("PROBE_DEBUG", "").lower() in ("1", "true", "yes")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _dbg(msg: str) -> None:
    if sys.stderr.isatty():
        print(f"\033[2m[probe:debug] {msg}\033[0m", file=sys.stderr, flush=True)
    else:
        print(f"[probe:debug] {msg}", file=sys.stderr, flush=True)


class ScanLog:
    """Records one scan execution: commands run, notes, timing, and result summary."""

    def __init__(self, scan_type: str, targets: list[str]) -> None:
        self.scan_type = scan_type
        self.targets = list(targets)
        self.started_at = _now()
        self._wall_ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        self.entries: list[dict[str, Any]] = []
        if _debug():
            _dbg(f"── {scan_type} ──────────────────────────────")
            _dbg(f"targets: {targets[:5]}{'…' if len(targets) > 5 else ''}")

    def cmd(self, cmd: list[str], proc: Any, label: str = "") -> None:
        """Record a subprocess invocation: command, return code, stdout/stderr sizes."""
        rc = getattr(proc, "returncode", -1)
        stdout = getattr(proc, "stdout", "") or ""
        stderr = getattr(proc, "stderr", "") or ""
        self.entries.append({
            "ts": _now(),
            "kind": "cmd",
            "label": label or (cmd[0] if cmd else "?"),
            "cmd": [str(a) for a in cmd],
            "returncode": rc,
            "stdout_lines": len(stdout.splitlines()),
            "stdout_bytes": len(stdout.encode()),
            "stderr": stderr[:4000],
        })
        if _debug():
            _dbg("cmd: " + " ".join(str(a) for a in cmd))
            _dbg(f"     rc={rc}  stdout={len(stdout)}B  stderr={len(stderr)}B")
            if rc != 0 and stderr:
                _dbg("     STDERR ↓")
                for line in stderr[:800].splitlines():
                    _dbg("       " + line)
            elif rc != 0:
                _dbg("     (no output — tool may be missing, crashed, or needs root)")

    def note(self, msg: str, **kw: Any) -> None:
        """Record an informational event (e.g. how many URLs will be probed)."""
        self.entries.append({"ts": _now(), "kind": "note", "msg": msg, **kw})
        if _debug():
            extra = "  " + " ".join(f"{k}={v}" for k, v in kw.items()) if kw else ""
            _dbg(f"note: {msg}{extra}")

    def save(self, result: dict[str, Any]) -> str:
        """Persist this log to disk. Returns the file path."""
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        fpath = LOG_DIR / f"{self._wall_ts}_{self.scan_type}.jsonl"
        summary = {k: result[k] for k in (
            "ok", "error", "host_count", "finding_count",
            "service_count", "open_ports", "server_count", "endpoints_probed",
        ) if k in result}
        record = {
            "scan_type": self.scan_type,
            "targets": self.targets,
            "started_at": self.started_at,
            "finished_at": _now(),
            "summary": summary,
            "entries": self.entries,
        }
        with open(fpath, "a") as f:
            f.write(json.dumps(record) + "\n")
        if _debug():
            _dbg(f"log saved → {fpath}")
        return str(fpath)


# ── thread-local API (called from scanners/base.py and scanners/__init__.py) ───

def begin(scan_type: str, targets: list[str]) -> ScanLog:
    lg = ScanLog(scan_type, targets)
    _ctx.log = lg
    return lg


def end(result: dict[str, Any]) -> str | None:
    lg: ScanLog | None = getattr(_ctx, "log", None)
    if lg is None:
        return None
    path = lg.save(result)
    _ctx.log = None
    return path


def current() -> ScanLog | None:
    return getattr(_ctx, "log", None)


def log_cmd(cmd: list[str], proc: Any, label: str = "") -> None:
    lg = current()
    if lg is not None:
        lg.cmd(cmd, proc, label)


def log_note(msg: str, **kw: Any) -> None:
    lg = current()
    if lg is not None:
        lg.note(msg, **kw)


# ── diagnostic helpers (used by scan_cli.py --logs) ────────────────────────────

def recent_logs(n: int = 10) -> list[Path]:
    if not LOG_DIR.exists():
        return []
    return sorted(LOG_DIR.glob("*.jsonl"), key=lambda p: p.stat().st_mtime, reverse=True)[:n]


def tail_log(path: Path) -> dict[str, Any] | None:
    try:
        with open(path) as f:
            lines = [l for l in f.read().splitlines() if l.strip()]
        return json.loads(lines[-1]) if lines else None
    except Exception:
        return None
