# Probe end-to-end test environment

Runs the **real probe** (`python -m probe run --once`) as a subprocess against a **reference
mock manager** that speaks the full `PROBE_PROTOCOL.md` contract with real Ed25519 signing +
NaCl Box encryption, over HTTPS with a self-signed cert + SPKI pinning.

## Run

```bash
cd adversa
python3 tests/e2e/run.py          # exit 0 = all scenarios pass
```

Requires the probe deps (`pip install -r probe/requirements.txt`). No real scanners needed —
the harness installs deterministic fake tools that emit realistic naabu/nmap/nuclei/testssl
output for `127.0.0.1` only.

## What it proves

| Scenario | Asserts |
|----------|---------|
| **A. Happy path** | enroll (pin-verified) → register → poll → decrypt+verify plan → scope gate → run 6-stage DAG via opaque tools → ship **2 findings** sealed; manager decrypts them; stages `start…done`. |
| **B. Tampered plan** | manager flips a bit in the plan ciphertext → probe rejects (`bad_envelope`), **no findings**. |
| **C. Wrong signing pin** | probe given a bad `mgrSigPub` pin → **refuses to enroll**, nonzero exit, nothing persisted. |

## Files

- `mock_manager.py` — the reference manager. **This is the spec for T14/T15**: the real Next.js
  manager must mint scope tokens (EdDSA JWT), compile + sign + Box-encrypt plans, and decrypt
  findings exactly as this does.
- `run.py` — orchestrator: fake tools, env wiring, the three scenarios.

## Real-tools variant (optional)

Point the probe at system scanners instead of fakes by setting `PROBE_TOOL_MAP` (e.g.
`portscan=naabu,svcscan=nmap,vulnscan=nuclei,tlsaudit=testssl.sh,websurf=httpx`) and authoring
plans whose `argv`/`output.format` match those tools. Scan only hosts you are authorized to scan.
