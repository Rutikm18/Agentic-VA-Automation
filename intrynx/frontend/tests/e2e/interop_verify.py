"""Verify the Python probe can open what the TypeScript manager sealed (T14 interop)."""
import base64
import json
import sys

from probe.crypto import b64d
from probe.envelope import open_plan
from probe.identity import Identity
from probe.plan import validate_plan
from probe.scope import ScopeVerifier

d = json.load(open(sys.argv[1]))
ident = Identity(
    probe_id="prb", probe_auth="auth",
    box_private=b64d(d["probeBoxSk"]), box_public=b64d(d["probeBoxPub"]),
    mgr_box_pub=b64d(d["mgrBoxPub"]), mgr_sig_pub=b64d(d["mgrSigPub"]),
)

plan = open_plan(d["envelope"], ident)
assert plan == d["plan"], "decrypted plan != emitted plan"
print("1) opened TS-sealed plan ✓  modules:", [m["id"] for m in plan["modules"]])

assert validate_plan(plan) == [], validate_plan(plan)
print("2) plan validates (VA-only) ✓")

sv = ScopeVerifier(b64d(d["mgrSigPub"]))
claims = sv.verify_token(d["scopeToken"])
assert claims["scanId"] == "scan-interop" and claims["targets"] == ["127.0.0.1"]
print("3) verified TS-minted EdDSA scope token ✓  targets:", claims["targets"])

bad = dict(d["envelope"])
ct = bytearray(b64d(bad["ct"])); ct[0] ^= 1
bad["ct"] = base64.b64encode(bytes(ct)).decode()
try:
    open_plan(bad, ident)
    raise SystemExit("FAIL: tampered envelope accepted")
except Exception:
    print("4) tampered TS envelope rejected ✓")

print("\nTS↔PYTHON INTEROP VERIFIED ✅")
