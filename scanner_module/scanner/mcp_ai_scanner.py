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
"""

from __future__ import annotations

import argparse
import asyncio
import json
import ssl
import urllib.request
import urllib.error

from .scanner_base import (
    BaseScanner, ScanResult, ScopeGuard, ResultWriter, expand_targets,
    parse_ports, setup_logging, base_argparser, main_entrypoint,
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


def _looks_authenticated(status: int) -> bool:
    # 401/403 strongly suggest auth is enforced; 200 with valid signature = open.
    return status in (401, 403)


class MCPAIScanner(BaseScanner):
    name = "mcp_ai_scan"

    def __init__(self, *args, ports: list[int], **kwargs):
        super().__init__(*args, **kwargs)
        self.ports = ports

    async def _probe_port(self, target: str, port: int) -> list[ScanResult]:
        scheme = "https" if port in _TLS_PORTS else "http"
        base = f"{scheme}://{target}:{port}"
        loop = asyncio.get_running_loop()
        found: list[ScanResult] = []

        for path, method, kind, sigs in _PROBES:
            await self.limiter.wait()
            resp = await loop.run_in_executor(
                None, _request, base + path, method, self.timeout)
            if resp is None:
                continue
            body_l = resp["body"].lower()
            ct = resp["headers"].get("content-type", "")
            matched = any(s.lower() in body_l for s in sigs)
            auth_enforced = _looks_authenticated(resp["status"])

            # Confirm only when the signature matches a 2xx body OR auth is enforced
            # on a path that strongly implies the service exists.
            confirmed = (resp["status"] < 300 and matched) or \
                        (auth_enforced and path in ("/v1/models", "/api/tags",
                                                     "/sse", "/mcp"))
            if not confirmed:
                continue

            data = {
                "kind": kind,
                "path": path,
                "http_status": resp["status"],
                "content_type": ct,
                "auth_enforced": auth_enforced,
                "unauthenticated_access": (resp["status"] < 300 and matched),
            }
            # Pull a small, non-sensitive summary (e.g. model count) if present.
            try:
                if resp["status"] < 300 and ct.startswith("application/json"):
                    parsed = json.loads(resp["body"])
                    if isinstance(parsed, dict):
                        if "models" in parsed and isinstance(parsed["models"], list):
                            data["model_count"] = len(parsed["models"])
                        if "data" in parsed and isinstance(parsed["data"], list):
                            data["model_count"] = len(parsed["data"])
            except Exception:
                pass

            found.append(ScanResult(
                self.name, target, port=port, proto="tcp", status="open",
                data=data,
                evidence=(f"{kind} via {path} -> HTTP {resp['status']}, "
                          f"auth_enforced={auth_enforced}"),
            ))
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
