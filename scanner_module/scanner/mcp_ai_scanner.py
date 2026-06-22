"""
mcp_ai_scanner.py — discover exposed AI inference servers and MCP endpoints.

WHY: AI runtimes (Ollama, vLLM, etc.) and Model Context Protocol (MCP) servers
are a fast-growing internal attack surface, frequently deployed without auth.
This module DISCOVERS and FINGERPRINTS them and records whether they appear to
require authentication.

METHOD (collection only): unauthenticated benign GET/POST of well-known
discovery endpoints, e.g.:
  * Ollama:  GET /api/tags , GET /api/version
  * OpenAI-compatible servers (vLLM/LM Studio/TGI): GET /v1/models
  * MCP:     GET /sse , GET /mcp  (look for SSE / JSON-RPC signatures)
We only READ discovery/list endpoints. We do NOT call tools, send prompts that
trigger actions, upload models, or exercise any tool the server exposes. The
output is "an MCP/AI endpoint exists here and looks (un)authenticated" — a fact,
not an exploit.

ANTI-FALSE-POSITIVE DESIGN (read before changing the confirmation logic):
A bare HTTP 401/403 on an AI-shaped path is NOT evidence of an AI/MCP server.
Plenty of unrelated services return a blanket 401/403 for every path they
don't recognize — the canonical case found in testing is macOS's AirPlay
receiver (`Server: AirTunes`), which 403s identically on /api/tags, /v1/models,
/sse, /mcp, and literally any other path, because it has no routing at all.
Path-coincidence is not a signal.

The fix distinguishes "blanket because unrelated" from "blanket because the
service applies authentication globally before routing" (the latter is normal
and correct for many real, properly-secured AI gateways — auth middleware
commonly runs before route resolution, so a real auth-gated vLLM/MCP server
can legitimately 401 a bogus path too). So a same-as-control-path response is
NOT, by itself, disqualifying. What actually qualifies a 401/403 as evidence:

  1. RFC 7235 `WWW-Authenticate` header present — the HTTP-standard way a
     server declares "you must authenticate, here's how." Trusted on its own,
     regardless of whether a control probe gets the same header (a global
     auth gate legitimately behaves this way).
  2. MCP-specific (RFC 9728 / MCP Authorization spec, 2025-03+): an HTTP-
     transport MCP server that requires auth MUST send `WWW-Authenticate`
     referencing OAuth 2.0 Protected Resource Metadata
     (".well-known/oauth-protected-resource" / "resource_metadata"). Finding
     this exact signal is treated as near-certain confirmation of a real,
     spec-compliant MCP server.
  3. A JSON-content-typed error body that actually talks about auth/tokens/
     keys (e.g. FastAPI's `{"detail":"Not authenticated"}`). Trusted on its
     own merits too — and deliberately NOT required to differ from the
     control probe: a global FastAPI auth dependency commonly returns this
     exact body for every path, including ones that don't exist, and that is
     normal/correct behavior for a real secured API, not a tell of anything
     wrong. (An earlier version of this check required differing from the
     control path here, which silently produced a false NEGATIVE on exactly
     this common pattern — found via fixture testing, fixed by trusting the
     content-type+vocabulary signal directly instead of gating it on a
     differential that conflates "global auth gate" with "no evidence".)

A known false-positive denylist (Server header / body fingerprint, e.g.
AirPlay/AirTunes) is checked first and suppresses a candidate outright,
independent of the above — defense in depth, not a replacement for it.

Ollama ships with NO authentication by default. That's a documented fact
about the product, not a guess — so a 401/403 on an Ollama-shaped path with
no real auth evidence is *more* suspicious, not less. We don't hard-code an
Ollama-specific exception, though: the evidence-based gate above already
makes a genuine Ollama port (which never sends WWW-Authenticate or an
auth-shaped JSON 401) fail to confirm, while still allowing a *real*,
properly-proxied/secured Ollama-compatible gateway to confirm if it actually
presents standards-based auth evidence.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import random
import ssl
import urllib.request
import urllib.error

from .scanner_base import (
    BaseScanner, ScanResult, ScopeGuard, ResultWriter, expand_targets,
    parse_ports, setup_logging, base_argparser, main_entrypoint, LOG,
)

# Ports commonly used by AI runtimes and MCP servers.
DEFAULT_AI_PORTS = [11434, 8000, 8080, 5000, 3000, 1234, 8001, 7860, 11435]
_TLS_PORTS = {443, 8443}

# Discovery endpoints: (path, method, kind, signature substrings to confirm).
_PROBES = [
    ("/api/tags", "GET", "ollama", ["models", "name"]),
    ("/api/version", "GET", "ollama", ["version"]),
    ("/v1/models", "GET", "openai_compat", ["data", "object", "model"]),
    ("/sse", "GET", "mcp", ["event:", "data:", "jsonrpc"]),
    ("/mcp", "GET", "mcp", ["jsonrpc", "result", "capabilities", "tools"]),
]
_AUTH_CANDIDATE_PATHS = {"/v1/models", "/api/tags", "/sse", "/mcp"}

# Known non-AI services that commonly squat on these ports and return a
# blanket 401/403/404 for every path, producing path-coincidence false
# positives. Matched (case-insensitive) against the Server header and body.
_KNOWN_FALSE_POSITIVE_SIGNATURES = [
    "airtunes",   # Apple AirPlay receiver (macOS) — observed on port 5000
    "airplay",
]

# Substrings that, inside a JSON-typed error body, genuinely indicate the
# response is *about* authentication/credentials (not just any 401 text).
_AUTH_BODY_HINTS = [
    "unauthorized", "unauthenticated", "not authenticated", "invalid_api_key",
    "invalid api key", "missing api key", "no api key", "x-api-key",
    "bearer token", "bearer realm", "access_token", "authentication required",
    "auth required",
]


def _request(url: str, method: str, timeout: float) -> dict | None:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(
        url, headers={"User-Agent": "va-scanner/1.0",
                      "Accept": "application/json, text/event-stream"},
        method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(4096)
            return {"status": resp.status,
                    "headers": {k.lower(): v for k, v in resp.headers.items()},
                    "body": body.decode("latin-1", "replace")}
    except urllib.error.HTTPError as e:
        body = b""
        try:
            body = e.read(2048)
        except Exception:
            pass
        return {"status": e.code,
                "headers": {k.lower(): v for k, v in (e.headers or {}).items()},
                "body": body.decode("latin-1", "replace")}
    except Exception:
        return None


def _known_false_positive(headers: dict, body: str) -> str | None:
    """Server/body fingerprint match against known non-AI squatters, or None."""
    haystack = ((headers.get("server") or "") + " " + body[:500]).lower()
    for sig in _KNOWN_FALSE_POSITIVE_SIGNATURES:
        if sig in haystack:
            return sig
    return None


def _mcp_oauth_signal(headers: dict) -> str | None:
    """
    The strongest possible evidence for a real MCP server: a WWW-Authenticate
    header referencing OAuth 2.0 Protected Resource Metadata per RFC 9728, as
    required by the MCP Authorization spec for HTTP-transport servers that
    need auth. Returns the header value (truncated) if found, else None.
    """
    waa = headers.get("www-authenticate", "")
    if "oauth-protected-resource" in waa.lower() or "resource_metadata" in waa.lower():
        return waa[:300]
    return None


def _auth_shaped_json_body(headers: dict, body: str) -> bool:
    """JSON-typed body that actually talks about auth, not just any error text."""
    ct = (headers.get("content-type") or "").lower()
    if "json" not in ct:
        return False
    body_l = body.lower()
    return any(h in body_l for h in _AUTH_BODY_HINTS)


def _model_count(status: int, ct: str, body: str) -> int | None:
    if status >= 300 or not ct.startswith("application/json"):
        return None
    try:
        parsed = json.loads(body)
    except Exception:
        return None
    if not isinstance(parsed, dict):
        return None
    if isinstance(parsed.get("models"), list):
        return len(parsed["models"])
    if isinstance(parsed.get("data"), list):
        return len(parsed["data"])
    return None


class MCPAIScanner(BaseScanner):
    name = "mcp_ai_scan"

    def __init__(self, *args, ports: list[int], **kwargs):
        super().__init__(*args, **kwargs)
        self.ports = ports

    async def _fetch(self, loop, base: str, path: str, method: str) -> dict | None:
        await self.limiter.wait()
        async with self.sem:
            return await loop.run_in_executor(
                None, _request, base + path, method, self.timeout)

    def _result(self, target: str, port: int, kind: str, path: str, resp: dict,
                *, confidence: int, reason: str, auth_enforced: bool,
                checks: dict | None = None) -> ScanResult:
        ct = resp["headers"].get("content-type", "")
        data = {
            "kind": kind,
            "path": path,
            "http_status": resp["status"],
            "content_type": ct,
            "auth_enforced": auth_enforced,
            "unauthenticated_access": not auth_enforced,
            "confidence": confidence,
            "evidence_reason": reason,
        }
        mc = _model_count(resp["status"], ct, resp["body"])
        if mc is not None:
            data["model_count"] = mc
        if checks:
            data["checks"] = checks
        return ScanResult(
            self.name, target, port=port, proto="tcp", status="open",
            data=data,
            evidence=f"{kind} via {path} -> HTTP {resp['status']}, {reason}",
        )

    async def _probe_port(self, target: str, port: int) -> list[ScanResult]:
        scheme = "https" if port in _TLS_PORTS else "http"
        base = f"{scheme}://{target}:{port}"
        loop = asyncio.get_running_loop()
        found: list[ScanResult] = []

        # One control probe per port, against a path that cannot possibly
        # exist. Used only as corroboration for the weaker (body-substring)
        # evidence tier below — a real WWW-Authenticate header is trusted on
        # its own, since legitimate global auth gates answer every path
        # (including bogus ones) identically by design.
        control_path = f"/__va_control_{random.getrandbits(48):012x}__"
        control = await self._fetch(loop, base, control_path, "GET")

        for path, method, kind, sigs in _PROBES:
            resp = await self._fetch(loop, base, path, method)
            if resp is None:
                continue

            headers = resp["headers"]
            body = resp["body"]
            body_l = body.lower()
            ct = headers.get("content-type", "")
            matched = any(s.lower() in body_l for s in sigs)

            fp_sig = _known_false_positive(headers, body)
            if fp_sig:
                LOG.debug("mcp_ai: suppressing %s candidate %s:%d%s — matches "
                          "known false-positive fingerprint %r",
                          kind, target, port, path, fp_sig)
                continue

            # ---- Tier 1: strong positive — genuine 2xx + signature match ----
            if resp["status"] < 300 and matched:
                found.append(self._result(
                    target, port, kind, path, resp,
                    confidence=95, reason="2xx response body matched signature",
                    auth_enforced=False))
                continue

            # ---- Tier 2: candidate auth-gated finding — needs REAL evidence ----
            if resp["status"] not in (401, 403) or path not in _AUTH_CANDIDATE_PATHS:
                continue

            mcp_oauth = _mcp_oauth_signal(headers) if kind == "mcp" else None
            www_auth = headers.get("www-authenticate")
            auth_json = _auth_shaped_json_body(headers, body)
            same_as_control = (control is not None and
                               resp["status"] == control["status"] and
                               body == control["body"])

            if mcp_oauth:
                found.append(self._result(
                    target, port, kind, path, resp, confidence=95,
                    reason="MCP OAuth Protected Resource Metadata signal "
                           "(RFC 9728 / MCP Authorization spec)",
                    auth_enforced=True,
                    checks={"mcp_oauth_signal": mcp_oauth}))
            elif www_auth:
                found.append(self._result(
                    target, port, kind, path, resp, confidence=85,
                    reason=f"WWW-Authenticate header present: {www_auth[:120]!r}",
                    auth_enforced=True,
                    checks={"www_authenticate": www_auth[:200]}))
            elif auth_json:
                found.append(self._result(
                    target, port, kind, path, resp, confidence=70,
                    reason="JSON error body references authentication/credentials",
                    auth_enforced=True,
                    checks={"auth_shaped_json_body": True,
                            "same_as_control": same_as_control}))
            else:
                LOG.debug("mcp_ai: suppressing %s candidate %s:%d%s — HTTP %d "
                          "with no WWW-Authenticate header and no auth-shaped "
                          "JSON body (same_as_control=%s) — a status code alone "
                          "is not evidence", kind, target, port, path,
                          resp["status"], same_as_control)
        return found

    async def scan_target(self, target: str) -> list[ScanResult]:
        results: list[ScanResult] = []
        for port in self.ports:
            results.extend(await self._probe_port(target, port))
        return results


def main() -> None:
    parser = base_argparser("MCP / AI inference endpoint discovery scanner")
    parser.add_argument("-p", "--ports", default=None,
                        help="ports to probe (default: common AI/MCP ports)")
    args = parser.parse_args()
    setup_logging(args.verbose)

    async def _run():
        ports = parse_ports(args.ports) if args.ports else DEFAULT_AI_PORTS
        scope = ScopeGuard.from_file(args.scope)
        targets = expand_targets(args.targets)
        scanner = MCPAIScanner(scope, rate=args.rate, concurrency=args.concurrency,
                               timeout=args.timeout, ports=ports)
        writer = ResultWriter(args.output, also_stdout=True)
        try:
            await scanner.run(targets, writer)
        finally:
            writer.close()

    main_entrypoint(_run)


if __name__ == "__main__":
    main()
