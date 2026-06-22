"""
scanner_base.py — shared foundation for every scanner module.

SCOPE OF THIS MODULE (read before use):
  * This is a COLLECTION / SCANNING layer only. It observes and records.
  * It does NOT exploit, brute-force, spray credentials, or modify any target.
  * It does NOT do correlation, CVE matching, or risk scoring — that is a
    separate layer. Each scanner here only reports what it directly observed.

Every scanner inherits from BaseScanner, which enforces three things before any
network operation touches a host:
  1. ScopeGuard  — the target must be inside the authorized allowlist.
  2. RateLimiter — global pacing so a scan never floods a network.
  3. ScanResult  — one normalized output schema, so you can measure accuracy
                   and false-positive rate per scanner consistently.

Run any scanner standalone (e.g. `python -m scanner.port_scanner ...`) and it
will emit newline-delimited JSON (JSONL) you can diff against ground truth.
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import logging
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator

LOG = logging.getLogger("scanner")


# --------------------------------------------------------------------------- #
# Result schema — identical across every scanner.
# --------------------------------------------------------------------------- #
@dataclass
class ScanResult:
    """One observation about one target. Pure fact, no interpretation."""
    scanner: str                      # which module produced this
    target: str                       # ip or host the observation is about
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    port: int | None = None           # if the observation is port-scoped
    proto: str | None = None          # tcp / udp
    status: str = "observed"          # observed | open | closed | filtered | error
    data: dict[str, Any] = field(default_factory=dict)   # parsed fields
    evidence: str | None = None       # raw bytes/banner that justify the result
    error: str | None = None

    def to_json(self) -> str:
        return json.dumps(asdict(self), default=str, ensure_ascii=False)


# --------------------------------------------------------------------------- #
# ScopeGuard — the authorization allowlist. Nothing is scanned unless allowed.
# --------------------------------------------------------------------------- #
class ScopeError(Exception):
    pass


class ScopeGuard:
    """
    Loads an allowlist of CIDRs / IPs / hostnames and decides whether a target
    is in scope. This is the safety control: the scanner refuses to touch
    anything not explicitly authorized.

    Allowlist file format (one entry per line, '#' for comments):
        10.0.0.0/24
        192.168.1.50
        scanme.example.com
    """

    def __init__(self, networks: list[ipaddress._BaseNetwork],
                 hostnames: set[str]):
        self._networks = networks
        self._hostnames = {h.lower() for h in hostnames}

    @classmethod
    def from_file(cls, path: str | Path) -> "ScopeGuard":
        try:
            text = Path(path).read_text()
        except OSError as exc:
            raise ScopeError(f"cannot read scope file {str(path)!r}: {exc}") from exc

        nets: list[ipaddress._BaseNetwork] = []
        hosts: set[str] = set()
        for raw in text.splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            try:
                nets.append(ipaddress.ip_network(line, strict=False))
            except ValueError:
                hosts.add(line.lower())
        if not nets and not hosts:
            raise ScopeError(f"scope file {str(path)!r} contained no valid entries")
        LOG.info("scope loaded: %d network(s), %d hostname(s)",
                 len(nets), len(hosts))
        return cls(nets, hosts)

    @classmethod
    def from_list(cls, entries: Iterable[str]) -> "ScopeGuard":
        nets, hosts = [], set()
        for line in entries:
            line = line.strip()
            if not line:
                continue
            try:
                nets.append(ipaddress.ip_network(line, strict=False))
            except ValueError:
                hosts.add(line.lower())
        return cls(nets, hosts)

    def in_scope(self, target: str) -> bool:
        t = target.strip().lower()
        if t in self._hostnames:
            return True
        try:
            ip = ipaddress.ip_address(t)
        except ValueError:
            # a hostname not explicitly listed is out of scope by default
            return False
        return any(ip in net for net in self._networks)

    def assert_in_scope(self, target: str) -> None:
        if not self.in_scope(target):
            raise ScopeError(f"target {target!r} is NOT in authorized scope")

    def filter(self, targets: Iterable[str]) -> Iterator[str]:
        for t in targets:
            if self.in_scope(t):
                yield t
            else:
                LOG.warning("dropping out-of-scope target: %s", t)


# --------------------------------------------------------------------------- #
# RateLimiter — global pacing across all concurrent tasks.
# --------------------------------------------------------------------------- #
class RateLimiter:
    """Simple async rate limiter: at most `rate` operations per second."""

    def __init__(self, rate: float = 200.0):
        self.min_interval = 1.0 / rate if rate > 0 else 0.0
        self._lock = asyncio.Lock()
        self._next = 0.0

    async def wait(self) -> None:
        if self.min_interval <= 0:
            return
        async with self._lock:
            now = time.monotonic()
            if now < self._next:
                await asyncio.sleep(self._next - now)
                now = time.monotonic()
            self._next = now + self.min_interval


# --------------------------------------------------------------------------- #
# Target expansion — CIDR / range / single host -> list of host strings.
# --------------------------------------------------------------------------- #
def expand_targets(specs: Iterable[str], *, max_hosts: int = 200_000) -> list[str]:
    """
    Accepts CIDRs ('10.0.0.0/24'), single IPs, hostnames, and simple ranges
    ('10.0.0.1-10.0.0.20'). Returns a de-duplicated ordered list of hosts.

    `max_hosts` is a safety net against accidental catastrophic ranges (e.g. a
    typo'd /8): anything that would expand past it raises ValueError instead of
    silently trying to materialize millions of host strings / asyncio tasks.
    For genuinely large sweeps, use mass_scan.py, which scans CIDRs directly
    without pre-expanding them.
    """
    out: list[str] = []
    seen: set[str] = set()

    def add(x: str):
        if x not in seen:
            seen.add(x)
            out.append(x)

    for spec in specs:
        spec = spec.strip()
        if not spec:
            continue
        if "-" in spec and "/" not in spec:
            lo, hi = spec.split("-", 1)
            try:
                start = ipaddress.ip_address(lo.strip())
                end = ipaddress.ip_address(hi.strip())
            except ValueError:
                start = end = None
            if start is not None and end is not None:
                if int(end) < int(start):
                    raise ValueError(
                        f"invalid range {spec!r}: end address before start")
                span = int(end) - int(start) + 1
                if span > max_hosts:
                    raise ValueError(
                        f"range {spec!r} spans {span} hosts, exceeding the "
                        f"{max_hosts}-host safety cap — narrow it or use "
                        f"mass_scan.py for large sweeps")
                for cur in range(int(start), int(end) + 1):
                    add(str(ipaddress.ip_address(cur)))
                continue
        try:
            net = ipaddress.ip_network(spec, strict=False)
        except ValueError:
            add(spec)  # not an IP/CIDR -> treat as hostname
            continue
        if net.num_addresses > max_hosts:
            raise ValueError(
                f"{spec} contains {net.num_addresses} addresses, exceeding the "
                f"{max_hosts}-host safety cap — narrow the CIDR or use "
                f"mass_scan.py for large sweeps")
        if net.num_addresses == 1:
            add(str(net.network_address))
        else:
            for ip in net.hosts():
                add(str(ip))
    return out


def parse_ports(spec: str) -> list[int]:
    """Parse '22,80,443,8000-8100' into a sorted unique port list (1-65535)."""
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            if "-" in part:
                a_str, b_str = part.split("-", 1)
                a, b = int(a_str), int(b_str)
            else:
                a = b = int(part)
        except ValueError:
            raise ValueError(
                f"invalid port token {part!r} in port spec {spec!r}") from None
        if not (0 < a < 65536) or not (0 < b < 65536):
            raise ValueError(
                f"port token {part!r} out of range — ports must be 1-65535")
        if b < a:
            raise ValueError(f"invalid port range {part!r}: end before start")
        ports.update(range(a, b + 1))
    return sorted(ports)


# Commonly-useful default port sets (kept small and explicit on purpose).
TOP_TCP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445, 465,
    587, 636, 993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 5985,
    5986, 6379, 8000, 8080, 8443, 8888, 9200, 11211, 11434, 27017,
]


# --------------------------------------------------------------------------- #
# Output writer.
# --------------------------------------------------------------------------- #
class ResultWriter:
    """Writes ScanResult objects as JSONL to a file and/or stdout."""

    def __init__(self, path: str | None = None, also_stdout: bool = True):
        self._fh = None
        if path:
            parent = Path(path).parent
            if str(parent) not in ("", "."):
                parent.mkdir(parents=True, exist_ok=True)
            self._fh = open(path, "w", encoding="utf-8")
        self._stdout = also_stdout
        self.count = 0

    def write(self, result: ScanResult) -> None:
        line = result.to_json()
        if self._fh:
            self._fh.write(line + "\n")
            self._fh.flush()
        if self._stdout:
            print(line, flush=True)
        self.count += 1

    def close(self) -> None:
        if self._fh:
            self._fh.close()


# --------------------------------------------------------------------------- #
# BaseScanner — the contract every scanner module follows.
# --------------------------------------------------------------------------- #
class BaseScanner:
    """
    Subclasses implement `scan_target(self, target)` (async), returning a list
    of ScanResult. The base handles scope enforcement, rate limiting, and
    concurrency so every scanner behaves identically and is measurable.

    `self.sem` bounds the number of concurrent network operations — NOT
    targets. Subclasses must acquire it (`async with self.sem:`) around each
    individual socket operation (one port check, one banner grab, ...), never
    once per target. A single target can legitimately fan out across hundreds
    or thousands of ports; bounding only the target loop would still let
    `--concurrency 100` against a wide port range open tens of thousands of
    sockets at once (e.g. 100 targets x 65535 ports). Sharing one semaphore
    across both the target loop and every scanner's internal port fan-out
    keeps the total in-flight operation count equal to `--concurrency`,
    matching what the flag's help text promises.
    """

    name = "base"

    def __init__(self, scope: ScopeGuard, *, rate: float = 200.0,
                 concurrency: int = 100, timeout: float = 3.0):
        self.scope = scope
        self.limiter = RateLimiter(rate)
        self.timeout = timeout
        self.sem = asyncio.Semaphore(concurrency)

    async def scan_target(self, target: str) -> list[ScanResult]:
        raise NotImplementedError

    async def _guarded(self, target: str) -> list[ScanResult]:
        try:
            self.scope.assert_in_scope(target)
        except ScopeError as exc:
            return [ScanResult(self.name, target, status="error", error=str(exc))]
        try:
            return await self.scan_target(target)
        except Exception as exc:  # never let one target kill the run
            LOG.debug("scan error %s: %s", target, exc)
            return [ScanResult(self.name, target, status="error",
                               error=f"{type(exc).__name__}: {exc}")]

    async def run(self, targets: Iterable[str], writer: ResultWriter) -> None:
        in_scope = list(self.scope.filter(targets))
        LOG.info("[%s] scanning %d in-scope target(s)", self.name, len(in_scope))
        tasks = [asyncio.create_task(self._guarded(t)) for t in in_scope]
        for fut in asyncio.as_completed(tasks):
            for result in await fut:
                writer.write(result)


# --------------------------------------------------------------------------- #
# Shared CLI scaffolding so each scanner file gets the same flags.
# --------------------------------------------------------------------------- #
def base_argparser(description: str) -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=description)
    p.add_argument("-t", "--targets", nargs="+", required=True,
                   help="targets: CIDR, IP, hostname, or range a-b")
    p.add_argument("-s", "--scope", required=True,
                   help="path to authorization allowlist file (REQUIRED)")
    p.add_argument("-o", "--output", help="write JSONL results to this file")
    p.add_argument("--rate", type=float, default=200.0,
                   help="max operations per second (default 200)")
    p.add_argument("--concurrency", type=int, default=100,
                   help="max concurrent operations (default 100)")
    p.add_argument("--timeout", type=float, default=3.0,
                   help="per-operation timeout seconds (default 3.0)")
    p.add_argument("-v", "--verbose", action="store_true")
    return p


def setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )


def main_entrypoint(fn) -> None:
    """
    Run a scanner CLI's body with consistent, operator-friendly error handling.

    `fn` is a zero-argument callable. It may run synchronously and/or return a
    coroutine (e.g. `fn` can itself be an `async def` function passed by
    reference — calling it just creates the coroutine, which is then driven
    here). This lets every scanner's `main()` funnel both its argument
    validation (scope file, port specs, target expansion) and its async scan
    loop through one place, so none of them leak a raw Python traceback to the
    terminal for routine operator mistakes (bad scope file, bad -p spec,
    missing output directory, Ctrl+C mid-scan).
    """
    try:
        result = fn()
        if asyncio.iscoroutine(result):
            asyncio.run(result)
    except ScopeError as exc:
        LOG.error("scope error: %s", exc)
        sys.exit(1)
    except (OSError, ValueError) as exc:
        LOG.error("%s: %s", type(exc).__name__, exc)
        sys.exit(1)
    except KeyboardInterrupt:
        LOG.warning("interrupted by user — partial results (if any) were flushed")
        sys.exit(130)


async def run_cli(scanner_cls, args) -> None:
    """Wire argparse args into a scanner instance and execute it."""
    scope = ScopeGuard.from_file(args.scope)
    targets = expand_targets(args.targets)
    scanner = scanner_cls(
        scope,
        rate=args.rate,
        concurrency=args.concurrency,
        timeout=args.timeout,
    )
    writer = ResultWriter(args.output, also_stdout=True)
    try:
        await scanner.run(targets, writer)
    finally:
        writer.close()
        LOG.info("[%s] done — %d result(s)", scanner.name, writer.count)
