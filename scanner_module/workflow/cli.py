"""
cli.py — entrypoint for the conditional workflow engine. Flag conventions
follow run_scan.py's existing style (-t/-s/--rate/--concurrency/--timeout)
plus the new flags this orchestrator needs (--mode/--profile/--services/
--prior-engagement/--recheck-older-than/credential flags) — credentials
are integrated directly here (unlike run_scan.py, which deliberately keeps
ssh_collector/windows_collector on a separate invocation model); this is a
new orchestrator, not a modification of run_scan.py's conventions.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from datetime import timedelta
from pathlib import Path

from scanner.scanner_base import ScopeGuard, expand_targets, setup_logging

from .cache import WorkflowCache
from .modes import MODE_FACTORY, VALID_SERVICES
from .report import asset_to_dict, diff_assets, engagement_summary
from .workflow_engine import run_engagement


def _parse_duration(s: str) -> timedelta:
    """'7d' / '12h' / '30m' -> timedelta. Simple single-unit parser —
    engagements are re-run often enough that a fancier grammar isn't worth
    the complexity yet."""
    unit = s[-1]
    value = float(s[:-1])
    if unit == "d":
        return timedelta(days=value)
    if unit == "h":
        return timedelta(hours=value)
    if unit == "m":
        return timedelta(minutes=value)
    raise argparse.ArgumentTypeError(f"duration must end in d/h/m, got {s!r}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Conditional, caching, dependency-aware workflow engine")
    p.add_argument("-t", "--targets", nargs="+", required=True)
    p.add_argument("-s", "--scope", required=True)
    p.add_argument("--profile", choices=["it", "iot", "ot"], default="it")
    p.add_argument("--mode", choices=["triage", "assessment", "service-specific", "re-scan"],
                   default="assessment")
    p.add_argument("--services", nargs="+", choices=sorted(VALID_SERVICES),
                   help="service-specific mode: which deep-scan branches to run")
    p.add_argument("--prior-engagement", help="path to a prior run's cache JSONL (re-scan mode)")
    p.add_argument("--recheck-older-than", type=_parse_duration, default=timedelta(days=7),
                   help="re-scan mode: re-probe facts older than this (e.g. 7d, 12h)")
    p.add_argument("--rate", type=float, default=200.0)
    p.add_argument("--concurrency", type=int, default=100)
    p.add_argument("--timeout", type=float, default=3.0)
    p.add_argument("--disc-timeout", type=float, default=1.5)
    p.add_argument("--ssh-user")
    p.add_argument("--ssh-key")
    p.add_argument("--ssh-password-env", help="env var name holding the SSH password")
    p.add_argument("--win-user")
    p.add_argument("--win-password-env", help="env var name holding the Windows password")
    p.add_argument("--win-domain", default="")
    p.add_argument("-o", "--output", help="write the per-host Asset report (JSON) here")
    p.add_argument("--cache-out", help="persist this run's cache here (defaults to --prior-engagement if set)")
    p.add_argument("-v", "--verbose", action="store_true")
    return p


def _build_mode(args: argparse.Namespace):
    if args.mode == "service-specific":
        if not args.services:
            raise SystemExit("--mode service-specific requires --services")
        return MODE_FACTORY["service-specific"](services=set(args.services))
    if args.mode == "re-scan":
        if not args.prior_engagement:
            raise SystemExit("--mode re-scan requires --prior-engagement <path>")
        return MODE_FACTORY["re-scan"](recheck_older_than=args.recheck_older_than)
    return MODE_FACTORY[args.mode]()


def _build_creds(args: argparse.Namespace) -> tuple[dict | None, dict | None]:
    ssh_creds = None
    if args.ssh_user:
        ssh_creds = {"user": args.ssh_user, "key_path": args.ssh_key,
                    "password": os.environ.get(args.ssh_password_env) if args.ssh_password_env else None}
    win_creds = None
    if args.win_user:
        win_creds = {"user": args.win_user, "domain": args.win_domain,
                    "password": os.environ.get(args.win_password_env, "") if args.win_password_env else ""}
    return ssh_creds, win_creds


async def _main(args: argparse.Namespace) -> None:
    setup_logging(args.verbose)
    scope = ScopeGuard.from_file(args.scope)
    targets = expand_targets(args.targets)
    mode = _build_mode(args)
    ssh_creds, win_creds = _build_creds(args)

    cache_path = args.prior_engagement if mode.requires_prior_engagement else args.cache_out
    cache = WorkflowCache(path=cache_path)

    # Snapshot prior state BEFORE run_engagement mutates the cache in place
    # (WorkflowCache.put overwrites old entries with fresh ones — there is
    # no other record of "what we knew before this run" once it starts).
    prior_assets = None
    if mode.requires_prior_engagement:
        from .asset import Asset
        prior_assets = {}
        for entry in cache._store.values():
            prior_assets.setdefault(entry.host, Asset(host=entry.host)).merge_result(entry.result)

    t0 = time.monotonic()
    assets = await run_engagement(
        targets, scope, profile=args.profile, rate=args.rate, concurrency=args.concurrency,
        timeout=args.timeout, disc_timeout=args.disc_timeout, cache=cache,
        service_filter=mode.service_filter, stop_after_banner=mode.stop_after_banner,
        force_recheck_after=mode.force_recheck_after, ssh_creds=ssh_creds, win_creds=win_creds)
    elapsed = time.monotonic() - t0

    summary = engagement_summary(assets, elapsed, cache)
    print(json.dumps({"mode": mode.name, "profile": args.profile, "summary": summary}, indent=2))

    if mode.name == "re-scan" and prior_assets is not None:
        print(json.dumps({"delta": diff_assets(prior_assets, assets)}, indent=2, default=str))

    if args.output:
        out = {h: asset_to_dict(a) for h, a in assets.items()}
        Path(args.output).write_text(json.dumps(out, indent=2, default=str))

    if args.cache_out or mode.requires_prior_engagement:
        cache.path = Path(args.cache_out or args.prior_engagement)
        cache.save()


def main() -> None:
    args = build_parser().parse_args()
    asyncio.run(_main(args))


if __name__ == "__main__":
    main()
