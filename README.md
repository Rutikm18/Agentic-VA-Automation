# Agentic VA Scanner — workspace

Two separate, independently-runnable projects live here. They are related
(`intrynx/`'s probe consumes scanning concepts validated in `scanner_module/`)
but are **not merged** — each has its own purpose, dependencies, and
lifecycle. See `SESSION_SUMMARY.md` for how they came to share this root.

```
.
├── scanner_module/   the standalone scanner — pure-stdlib Python, 13
│                     unauthenticated network scanners + 2 credentialed
│                     collectors + an it/iot/ot staged-funnel pipeline.
│                     Runs on its own, no other part of this repo required.
│                     See scanner_module/CURRENT_STATE.md.
│
└── intrynx/          the VAPT platform — FastAPI+Postgres manager
                       (backend/) + Next.js dashboard (frontend/) + a
                       deployable scanning agent (probe/) that ports
                       validated logic from scanner_module/ into its own
                       scanner registry, rather than depending on it
                       directly. See intrynx/docs/ARCHITECTURE.md.
```

## Why two projects, not one

`scanner_module` is where new scanner logic gets designed and ground-truth
accuracy-tested first (see `scanner_module/MANUAL_TESTING.md`) — fixture-based,
fast iteration, no platform/deployment concerns. Once validated, the logic
gets **ported** into `intrynx/probe/scanners/` as a new `@scanner` registration
(matching its existing white-labeling/scope/licensing conventions) — never
copy-pasted as a standalone duplicate. `intrynx/` is the only one of the two
meant for actual deployment against a client's network.

## Running each

```bash
# scanner_module — no setup needed beyond Python 3.10+
cd scanner_module && ./test_all.sh 127.0.0.1

# intrynx — needs its own venv + node_modules (not included, see below)
cd intrynx/backend && python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
cd intrynx/probe && pip install -r requirements.txt   # optional: paramiko/pywinrm/impacket for credentialed scan_types
cd intrynx/frontend && npm install
# then: cd intrynx && make full   (see intrynx/docs/RUNBOOK.md)
```

`intrynx/` was copied in clean — `node_modules/`, `.venv/`, build caches, and
a few already-flagged dead/duplicate prototype directories were deliberately
excluded (see the note at the top of `intrynx/docs/ARCHITECTURE.md` for
exactly what and why). Reinstall dependencies fresh per the commands above
before running it.
