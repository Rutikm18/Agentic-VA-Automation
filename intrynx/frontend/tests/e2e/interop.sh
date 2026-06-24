#!/usr/bin/env bash
# Prove the TypeScript manager (lib/probe/*) and the Python probe agree on crypto:
# TS compiles + seals a plan and mints a scope token; Python opens and verifies them.
set -euo pipefail
cd "$(dirname "$0")/../.."

echo "→ compiling lib/probe (TS → CJS)…"
rm -rf /tmp/probe-ts
npx --yes tsc lib/probe/*.ts --module commonjs --target es2020 \
  --moduleResolution node --esModuleInterop --skipLibCheck \
  --outDir /tmp/probe-ts --rootDir lib/probe

echo "→ emitting sealed plan + scope token (manager side)…"
NODE_PATH="$PWD/node_modules" node /tmp/probe-ts/__interop_emit.js > /tmp/interop.json

echo "→ opening on the probe side (Python)…"
PYTHONPATH="$PWD" python3 tests/e2e/interop_verify.py /tmp/interop.json
