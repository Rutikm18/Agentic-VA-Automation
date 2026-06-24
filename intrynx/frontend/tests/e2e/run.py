"""End-to-end probe test: real probe process ↔ reference mock manager over HTTPS.

Runs three scenarios, each driving the actual `python -m probe run --once`:
  A. Happy path     — enroll (pin-verified) → register → poll → scan (fake tools) → ship findings.
  B. Tamper         — manager corrupts the plan blob → probe rejects it (bad_envelope), no findings.
  C. Pin mismatch   — probe given the wrong signing pin → refuses to enroll.

Default tools are deterministic fakes (no real scanners needed, scans only localhost). Exit 0 = all pass.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent                      # adversa/
sys.path.insert(0, str(HERE))
import mock_manager as MM                       # noqa: E402

SCOPE_TARGET = "127.0.0.1"


def make_fake_tools(d: Path) -> None:
    """Deterministic stand-ins emitting realistic output for 127.0.0.1."""
    scripts = {
        "t_ps": '#!/bin/sh\necho \'{"ip":"127.0.0.1","port":80}\'\necho \'{"ip":"127.0.0.1","port":443}\'\n',
        "t_sv": '#!/bin/sh\nprintf "Host: 127.0.0.1 ()\\tPorts: 80/open/tcp//http//nginx//, 443/open/tcp//ssl|https//nginx//\\n"\n',
        "t_we": '#!/bin/sh\necho \'{"url":"https://127.0.0.1:443","status_code":200}\'\n',
        "t_cv": '#!/bin/sh\necho \'{"template-id":"exposed-panel","info":{"name":"Exposed Admin Panel","severity":"medium"},"ip":"127.0.0.1","port":443,"matched-at":"https://127.0.0.1:443"}\'\n',
        "t_tl": '#!/bin/sh\necho "[{\\"id\\":\\"BEAST\\",\\"ip\\":\\"127.0.0.1\\",\\"port\\":443,\\"severity\\":\\"HIGH\\",\\"finding\\":\\"CBC cipher\\"}]" > "$2"\n',
    }
    manifest = {}
    roles = {"portscan": "t_ps", "svcscan": "t_sv", "websurf": "t_we", "vulnscan": "t_cv", "tlsaudit": "t_tl"}
    for fname, body in scripts.items():
        p = d / fname
        p.write_text(body)
        os.chmod(p, 0o755)
    for role, fname in roles.items():
        sha = hashlib.sha256((d / fname).read_bytes()).hexdigest()
        manifest[role] = {"asset": fname, "sha256": sha}
    (d / "manifest.json").write_text(json.dumps(manifest))


def scan_plan(scan_id: str) -> dict:
    return {"planId": "pln_test", "scanId": scan_id, "protocolVersion": 1, "stealth": 5,
            "createdAt": "t", "modules": [
        {"id": "discover", "kind": "host-discovery", "needs": [],
         "tool": {"ref": "portscan", "argv": ["{{scope.targets}}"]},
         "output": {"format": "json-lines", "produces": ["hosts"]}},
        {"id": "ports", "kind": "port-scan", "needs": ["discover"],
         "tool": {"ref": "portscan", "argv": ["-host", "{{hosts}}"]},
         "output": {"format": "json-lines", "produces": ["ports"]}},
        {"id": "svc", "kind": "service-id", "needs": ["ports"],
         "tool": {"ref": "svcscan", "argv": ["-p", "{{ports}}", "{{hosts}}"]},
         "output": {"format": "grepable", "produces": ["web-urls"]}},
        {"id": "web", "kind": "web-probe", "needs": ["svc"],
         "tool": {"ref": "websurf", "argv": ["{{web-urls}}"]},
         "output": {"format": "json-lines", "produces": ["web-urls"]}},
        {"id": "cve", "kind": "cve-scan", "needs": ["web"],
         "tool": {"ref": "vulnscan", "argv": ["{{web-urls}}"]},
         "output": {"format": "json-lines", "produces": ["findings"]},
         "content": {"packId": "p", "sha256": "x"}},
        {"id": "tls", "kind": "tls-check", "needs": ["svc"],
         "tool": {"ref": "tlsaudit", "argv": ["--jsonfile", "{{out_file}}", "{{web-urls}}"]},
         "output": {"format": "json-file", "produces": ["findings"]}},
    ]}


def probe_env(base, sig_pin, cert_pin, tools_dir, state_dir, enroll_token=None) -> dict:
    env = dict(os.environ)
    env.update({
        "PROBE_MANAGER_URL": base,
        "PROBE_MGR_SIG_PUB": sig_pin,
        "PROBE_CERT_PIN": cert_pin,
        "PROBE_INSECURE_SKIP_CA": "1",            # pin is the trust anchor for the self-signed cert
        "PROBE_TOOLS_DIR": str(tools_dir),
        "PROBE_STATE_DIR": str(state_dir),
        "PROBE_RUNTIME_DIR": str(state_dir / "run"),
        "PROBE_EXEC_DIR": str(state_dir / "bin"),
        "PROBE_APP_NAME": "netagent",
        "PROBE_PROC_NAME": "netagent-mod",
        "PYTHONWARNINGS": "ignore",               # silence self-signed TLS warning in test
    })
    if enroll_token:
        env["PROBE_ENROLL_TOKEN"] = enroll_token
    return env


def run_probe(env) -> subprocess.CompletedProcess:
    # PROBE_BIN lets us exercise a *compiled* binary (T11) instead of `python -m probe`.
    bin_path = os.environ.get("PROBE_BIN")
    cmd = ([bin_path, "run", "--once", "--log-level", "INFO"] if bin_path
           else [sys.executable, "-m", "probe", "run", "--once", "--log-level", "INFO"])
    return subprocess.run(cmd, cwd=str(REPO), env=env, capture_output=True, text=True, timeout=120)


def main() -> int:
    work = Path(tempfile.mkdtemp(prefix="probe-e2e-"))
    tools = work / "tools"; tools.mkdir(parents=True)
    make_fake_tools(tools)
    cert, key = str(work / "cert.pem"), str(work / "key.pem")
    ok = True

    # ── Scenario A + B share one manager + enrolled state ──
    state = MM.ManagerState(enroll_token="ENROLL-ABC", scope_targets=[SCOPE_TARGET])
    httpd, base, pin = MM.start(state, cert, key)
    sig_pin = state.mgr_sig_pub_b64
    state_dir = work / "stateA"

    print(f"\n=== Scenario A: happy path ===  manager={base}")
    state.queue_scan("scan-1", scan_plan("scan-1"))
    env = probe_env(base, sig_pin, pin, tools, state_dir, enroll_token="ENROLL-ABC")
    r = run_probe(env)
    enrolled = (state_dir / "state.json").exists()
    stages = [p.get("stage") for p in state.progress]
    a_ok = (r.returncode == 0 and enrolled and len(state.findings) == 2
            and "done" in stages and "scope_violation" not in stages)
    print(f"  exit={r.returncode} enrolled={enrolled} findings={len(state.findings)} stages={stages}")
    if state.findings:
        print("  findings:", [(f['source'], f['severity'], f['title']) for f in state.findings])
    print("  RESULT:", "PASS" if a_ok else "FAIL")
    if not a_ok:
        ok = False
        print("  stderr:\n" + "\n".join("    " + l for l in r.stderr.splitlines()[-15:]))

    print("\n=== Scenario B: tampered plan blob (must be rejected) ===")
    before = len(state.findings)
    state.tamper_next = True
    state.queue_scan("scan-2", scan_plan("scan-2"))
    r = run_probe(env)                            # already enrolled; just polls
    b_stages = [p.get("stage") for p in state.progress]
    b_ok = (r.returncode == 0 and len(state.findings) == before and "bad_envelope" in b_stages)
    print(f"  exit={r.returncode} new_findings={len(state.findings)-before} "
          f"saw_bad_envelope={'bad_envelope' in b_stages}")
    print("  RESULT:", "PASS" if b_ok else "FAIL")
    ok = ok and b_ok

    print("\n=== Scenario C: wrong signing pin (must refuse enrollment) ===")
    state_c = MM.ManagerState(enroll_token="ENROLL-XYZ", scope_targets=[SCOPE_TARGET])
    httpd_c, base_c, pin_c = MM.start(state_c, str(work / "c_cert.pem"), str(work / "c_key.pem"))
    wrong_pin = MM.b64e(b"\x00" * 32)             # not the manager's real signing key
    env_c = probe_env(base_c, wrong_pin, pin_c, tools, work / "stateC", enroll_token="ENROLL-XYZ")
    r = run_probe(env_c)
    c_enrolled = (work / "stateC" / "state.json").exists()
    c_ok = (r.returncode != 0 and not c_enrolled)
    print(f"  exit={r.returncode} (nonzero expected) enrolled={c_enrolled} (False expected)")
    refused = "does not match" in (r.stderr + r.stdout)
    print(f"  refusal logged: {refused}")
    print("  RESULT:", "PASS" if c_ok else "FAIL")
    ok = ok and c_ok

    httpd.shutdown(); httpd_c.shutdown()
    print("\n" + ("=" * 48))
    print("OVERALL:", "ALL SCENARIOS PASSED ✅" if ok else "FAILURES ❌")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
