"""Reference mock manager for end-to-end probe testing.

Implements the PROBE_PROTOCOL.md contract with REAL crypto (Ed25519 signing, NaCl Box
encryption) over HTTPS with a self-signed cert. This is the authoritative reference for what
the real Next.js manager must do in T14/T15 — if the probe talks to this, it'll talk to the
real manager once those endpoints match.

Endpoints:
  POST /api/agents/enroll                          → issue identity, return manager pubkeys
  POST /api/agents/register                        → issue session (agentId)
  GET  /api/agents/jobs/next                       → {jobId, scanId, scopeToken, planBlob}
  POST /api/agents/<id>/jobs/<jobId>/progress      → record status/stage
  POST /api/findings/ingest                        → decrypt + store findings
"""
from __future__ import annotations

import datetime
import json
import logging
import ssl
import sys
import threading
import time
import uuid
from base64 import b64decode as b64d, b64encode
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import jwt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID
from nacl.public import Box, PrivateKey, PublicKey
from nacl.signing import SigningKey

log = logging.getLogger("mock_manager")


def b64e(b: bytes) -> str:
    return b64encode(b).decode()


class ManagerState:
    def __init__(self, enroll_token: str, scope_targets: list[str]) -> None:
        self.mgr_sig = SigningKey.generate()                       # Ed25519
        self.mgr_box = PrivateKey.generate()                       # X25519
        self.sig_priv_pem = Ed25519PrivateKey.from_private_bytes(bytes(self.mgr_sig))
        self.enroll_token = enroll_token
        self.enroll_used = False
        self.scope_targets = scope_targets

        self.probes: dict[str, dict] = {}      # probeId → {boxPub(raw), auth}
        self.auth_to_probe: dict[str, str] = {} # probeAuth → probeId
        self.sessions: dict[str, str] = {}      # agentId → probeId
        self.pending_jobs: list[dict] = []      # queued {plan,...}
        self.findings: list[dict] = []
        self.progress: list[dict] = []
        self.tamper_next = False                # corrupt the next plan blob (negative test)

    # ── pubkeys ──
    @property
    def mgr_sig_pub_b64(self) -> str:
        return b64e(bytes(self.mgr_sig.verify_key))

    @property
    def mgr_box_pub_b64(self) -> str:
        return b64e(bytes(self.mgr_box.public_key))

    # ── job authoring ──
    def queue_scan(self, scan_id: str, plan: dict) -> str:
        job_id = "job_" + uuid.uuid4().hex[:8]
        self.pending_jobs.append({"jobId": job_id, "scanId": scan_id, "plan": plan})
        return job_id

    def _mint_scope_token(self, scan_id: str) -> str:
        now = int(time.time())
        return jwt.encode(
            {"scanId": scan_id, "targets": self.scope_targets,
             "notBefore": now - 60, "notAfter": now + 3600, "iat": now, "exp": now + 3600},
            self.sig_priv_pem, algorithm="EdDSA",
        )

    def _seal_plan(self, plan: dict, probe_box_pub_raw: bytes) -> dict:
        pt = json.dumps(plan, separators=(",", ":")).encode()
        enc = Box(self.mgr_box, PublicKey(probe_box_pub_raw)).encrypt(pt)
        ct = enc.ciphertext
        if self.tamper_next:
            ct = bytes([ct[0] ^ 0x01]) + ct[1:]            # flip a bit → must be rejected
            self.tamper_next = False
        return {
            "v": 1, "enc": "nacl-box", "sig": "ed25519",
            "epk": self.mgr_box_pub_b64,
            "nonce": b64e(enc.nonce), "ct": b64e(ct),
            "sigval": b64e(self.mgr_sig.sign(pt).signature),
        }

    def next_job_for(self, agent_id: str) -> dict | None:
        if agent_id not in self.sessions or not self.pending_jobs:
            return None
        probe_id = self.sessions[agent_id]
        box_pub = self.probes[probe_id]["boxPub"]
        job = self.pending_jobs.pop(0)
        return {
            "jobId": job["jobId"], "scanId": job["scanId"],
            "scopeToken": self._mint_scope_token(job["scanId"]),
            "planBlob": self._seal_plan(job["plan"], box_pub),
        }

    def ingest(self, agent_id: str, scan_id: str, blob: dict) -> int:
        pt = Box(self.mgr_box, PublicKey(b64d(blob["epk"]))).decrypt(
            b64d(blob["ct"]), b64d(blob["nonce"]))
        findings = json.loads(pt.decode())
        self.findings.extend(findings)
        return len(findings)


def _make_handler(state: ManagerState):
    def bearer(h) -> str:
        a = h.headers.get("Authorization", "")
        return a[7:].strip() if a.startswith("Bearer ") else ""

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):  # quiet
            pass

        def _body(self) -> dict:
            n = int(self.headers.get("Content-Length", 0))
            return json.loads(self.rfile.read(n) or b"{}")

        def _send(self, code: int, obj: dict | None = None):
            data = json.dumps(obj or {}).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):
            p = self.path
            try:
                if p == "/api/agents/enroll":
                    b = self._body()
                    if b.get("enrollToken") != state.enroll_token or state.enroll_used:
                        return self._send(401, {"error": "bad/used enroll token"})
                    state.enroll_used = True
                    probe_id = "prb_" + uuid.uuid4().hex[:8]
                    auth = "auth_" + uuid.uuid4().hex
                    state.probes[probe_id] = {"boxPub": b64d(b["probeBoxPub"]), "auth": auth}
                    state.auth_to_probe[auth] = probe_id
                    return self._send(200, {
                        "probeId": probe_id, "probeAuth": auth,
                        "mgrSigPub": state.mgr_sig_pub_b64, "mgrBoxPub": state.mgr_box_pub_b64,
                    })

                if p == "/api/agents/register":
                    probe_id = state.auth_to_probe.get(bearer(self))
                    if not probe_id:
                        return self._send(401, {"error": "unknown probe auth"})
                    agent_id = "agt_" + uuid.uuid4().hex[:8]
                    state.sessions[agent_id] = probe_id
                    return self._send(200, {"agentId": agent_id,
                                            "registeredAt": datetime.datetime.utcnow().isoformat()})

                if p.endswith("/progress"):
                    b = self._body()
                    state.progress.append({"path": p, **b})
                    return self._send(200, {"ok": True})

                if p == "/api/findings/ingest":
                    agent_id = bearer(self)
                    if agent_id not in state.sessions:
                        return self._send(401, {"error": "unknown session"})
                    b = self._body()
                    saved = state.ingest(agent_id, b.get("scanId", ""), b["blob"])
                    return self._send(200, {"saved": saved, "duplicates": 0})

                return self._send(404, {"error": "not found"})
            except Exception as exc:  # surface server errors to the probe as 500
                log.exception("handler error")
                return self._send(500, {"error": str(exc)})

        def do_GET(self):
            if self.path == "/api/agents/jobs/next":
                agent_id = bearer(self)
                job = state.next_job_for(agent_id)
                if job is None:
                    return self._send(204)
                return self._send(200, job)
            return self._send(404, {"error": "not found"})

    return Handler


def _self_signed(cert_path: str, key_path: str) -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName(
                [x509.DNSName("localhost"), x509.IPAddress(__import__("ipaddress").ip_address("127.0.0.1"))]),
                critical=False)
            .sign(key, hashes.SHA256()))
    open(cert_path, "wb").write(cert.public_bytes(serialization.Encoding.PEM))
    open(key_path, "wb").write(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()))
    return cert.public_bytes(serialization.Encoding.DER)


def spki_pin(cert_der: bytes) -> str:
    import hashlib
    cert = x509.load_der_x509_certificate(cert_der)
    spki = cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return b64e(hashlib.sha256(spki).digest())


class _QuietServer(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        # The probe's cert-pin pre-flight opens a TLS socket, reads the cert, then closes it —
        # which surfaces as a connection reset/SSL EOF here. Harmless; don't log it.
        import ssl as _ssl
        exc = sys.exc_info()[1]
        if isinstance(exc, (ConnectionError, BrokenPipeError, _ssl.SSLError)):
            return
        super().handle_error(request, client_address)


def start(state: ManagerState, cert_path: str, key_path: str, host: str = "127.0.0.1"):
    """Start the HTTPS server in a thread. Returns (httpd, base_url, pin_b64)."""
    der = _self_signed(cert_path, key_path)
    httpd = _QuietServer((host, 0), _make_handler(state))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_path, key_path)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, f"https://{host}:{port}", spki_pin(der)
