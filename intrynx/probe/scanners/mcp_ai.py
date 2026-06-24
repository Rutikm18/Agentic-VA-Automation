"""MCP and AI/LLM server discovery — pure-Python (httpx), no external CLI tool.

Two capabilities live here:

  * ``mcp_discovery`` — finds **Model Context Protocol** servers. It speaks the MCP
    JSON-RPC handshake (Streamable-HTTP ``initialize`` + legacy HTTP+SSE) and, when
    a server answers without credentials, enumerates its exposed ``tools`` /
    ``resources`` / ``prompts``. An unauthenticated MCP server on the network is a
    serious exposure — its tools are remotely-invokable capabilities (shell, files,
    SQL, HTTP), so any reachable client can drive them.

  * ``ai_service_discovery`` — finds **AI/LLM/ML inference services**: Ollama,
    OpenAI-compatible APIs (vLLM, LM Studio, LocalAI, llama.cpp, TGI), Jupyter,
    Ray, Triton, TorchServe, ComfyUI, Stable-Diffusion/Gradio, Open WebUI, MLflow.
    Each open, unauthenticated endpoint becomes a finding (model exfiltration,
    compute abuse, prompt-injection pivot, and — for Jupyter/Ray — RCE).

Both run entirely over the probe's own ``httpx`` dependency, so they're always
"available" (tool = ``builtin``). The detection logic is split into pure functions
(testable offline) and a thin concurrent I/O layer.
"""
from __future__ import annotations

import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable

from .base import BUILTIN, expand_hosts, normalize_targets, now, result, scanner, split_host_port

# ── MCP ────────────────────────────────────────────────────────────────────────

MCP_DEFAULT_PORTS = [3000, 8000, 8080, 8787, 9000, 5000, 6274, 8001]
MCP_DEFAULT_PATHS = ["/mcp", "/", "/rpc", "/messages", "/api/mcp"]
MCP_PROTOCOL_VERSION = "2025-06-18"

# Tool names/descriptions that make an exposed MCP server high-impact (remote code/data).
_DANGEROUS_TOOL_RE = re.compile(
    r"(exec|shell|command|spawn|eval|subprocess|delete|remove|drop|write[_-]?file|"
    r"put[_-]?file|read[_-]?file|filesystem|\bsql\b|query|browser|fetch|request|ssh|"
    r"deploy|terraform|kubectl|docker)", re.I)


def _initialize_payload() -> dict[str, Any]:
    return {
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "intrynx-probe", "version": "1.0"},
        },
    }


def parse_jsonrpc(content_type: str, body: str) -> dict[str, Any] | None:
    """Extract a JSON-RPC object from a JSON body *or* an SSE ``data:`` frame.

    MCP Streamable-HTTP servers reply either ``application/json`` or
    ``text/event-stream`` (one ``event: message`` / ``data: {json}`` frame).
    Returns the parsed object, or None if nothing JSON-RPC-shaped is found.
    """
    body = body or ""
    ct = (content_type or "").lower()
    if "text/event-stream" in ct or body.lstrip().startswith(("event:", "data:")):
        for line in body.splitlines():
            line = line.strip()
            if line.startswith("data:"):
                data = line[5:].strip()
                if data.startswith("{"):
                    try:
                        return json.loads(data)
                    except json.JSONDecodeError:
                        continue
        return None
    body = body.strip()
    if not body.startswith("{"):
        return None
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        return None


def extract_mcp_server_info(obj: dict[str, Any] | None) -> dict[str, Any] | None:
    """If ``obj`` is an MCP ``initialize`` result, return its server descriptor.

    Returns ``{name, version, protocolVersion, capabilities:[...]}`` or None.
    """
    if not isinstance(obj, dict):
        return None
    res = obj.get("result")
    if not isinstance(res, dict):
        return None
    # An MCP initialize result has protocolVersion + capabilities (+ usually serverInfo).
    if "protocolVersion" not in res and "serverInfo" not in res:
        return None
    info = res.get("serverInfo") or {}
    return {
        "name": info.get("name"),
        "version": info.get("version"),
        "protocolVersion": res.get("protocolVersion"),
        "capabilities": sorted((res.get("capabilities") or {}).keys()),
    }


def classify_mcp_tools(tools: list[dict[str, Any]]) -> tuple[list[str], bool]:
    """Return (tool_names, has_dangerous). Flags tools that imply code/data access."""
    names = [t.get("name", "") for t in tools if isinstance(t, dict)]
    dangerous = any(
        _DANGEROUS_TOOL_RE.search(f"{t.get('name', '')} {t.get('description', '')}")
        for t in tools if isinstance(t, dict)
    )
    return [n for n in names if n], dangerous


# ── AI / LLM / ML service signatures ───────────────────────────────────────────

def _json_or_none(text: str) -> Any:
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return None


def _match_ollama(status: int, headers: dict, text: str) -> dict | None:
    if status == 200 and '"models"' in text:
        obj = _json_or_none(text) or {}
        models = [m.get("name") for m in obj.get("models", []) if isinstance(m, dict)]
        return {"product": "Ollama", "models": [m for m in models if m]}
    return None


def _match_openai(status: int, headers: dict, text: str) -> dict | None:
    if status == 200 and '"data"' in text and ('"object"' in text or '"id"' in text):
        obj = _json_or_none(text) or {}
        data = obj.get("data") if isinstance(obj, dict) else None
        if not isinstance(data, list):
            return None
        models = [m.get("id") for m in data if isinstance(m, dict) and m.get("id")]
        server = (headers.get("server") or "").lower()
        product = "OpenAI-compatible API"
        if "lmstudio" in server or "lm studio" in server:
            product = "LM Studio"
        elif "uvicorn" in server or "vllm" in server:
            product = "vLLM / OpenAI-compatible API"
        return {"product": product, "models": models, "server": headers.get("server")}
    return None


def _match_jupyter(status: int, headers: dict, text: str) -> dict | None:
    server = (headers.get("server") or "").lower()
    if status == 200 and ("tornadoserver" in server or '"version"' in text and "jupyter" in text.lower()):
        obj = _json_or_none(text) or {}
        return {"product": "Jupyter", "version": obj.get("version") if isinstance(obj, dict) else None}
    return None


def _match_ray(status: int, headers: dict, text: str) -> dict | None:
    if status == 200 and "ray_version" in text:
        obj = _json_or_none(text) or {}
        data = obj.get("data") if isinstance(obj, dict) else {}
        return {"product": "Ray Dashboard", "version": (data or {}).get("rayVersion")}
    return None


def _match_triton(status: int, headers: dict, text: str) -> dict | None:
    if status == 200 and '"name"' in text and "triton" in text.lower():
        obj = _json_or_none(text) or {}
        return {"product": "NVIDIA Triton", "version": obj.get("version") if isinstance(obj, dict) else None}
    return None


def _match_torchserve(status: int, headers: dict, text: str) -> dict | None:
    if status == 200 and '"models"' in text and "modelName" in text:
        obj = _json_or_none(text) or {}
        models = [m.get("modelName") for m in obj.get("models", []) if isinstance(m, dict)]
        return {"product": "TorchServe", "models": [m for m in models if m]}
    return None


def _match_comfyui(status: int, headers: dict, text: str) -> dict | None:
    if status == 200 and '"devices"' in text and '"system"' in text:
        return {"product": "ComfyUI"}
    return None


def _match_gradio(status: int, headers: dict, text: str) -> dict | None:
    if status == 200 and '"components"' in text and '"version"' in text:
        obj = _json_or_none(text) or {}
        title = (obj.get("title") or "").lower() if isinstance(obj, dict) else ""
        product = "Stable Diffusion WebUI" if "stable diffusion" in title else "Gradio app"
        return {"product": product, "version": obj.get("version") if isinstance(obj, dict) else None}
    return None


def _match_openwebui(status: int, headers: dict, text: str) -> dict | None:
    if status == 200 and '"name"' in text and ('"features"' in text or "open-webui" in text.lower()):
        obj = _json_or_none(text) or {}
        return {"product": "Open WebUI", "version": obj.get("version") if isinstance(obj, dict) else None}
    return None


def _match_mlflow(status: int, headers: dict, text: str) -> dict | None:
    if status == 200 and "experiments" in text.lower() and '"experiment' in text.lower():
        return {"product": "MLflow"}
    return None


# Each signature: name, category, ports, (method, path), matcher, severity, exposure text.
AI_SIGNATURES: list[dict[str, Any]] = [
    {"name": "Ollama", "category": "llm-runtime", "ports": [11434],
     "method": "GET", "path": "/api/tags", "match": _match_ollama,
     "severity": "high", "exposure": "Unauthenticated Ollama LLM runtime exposed"},
    {"name": "OpenAI-API", "category": "llm-api", "ports": [8000, 1234, 8080, 5000, 3000, 8001],
     "method": "GET", "path": "/v1/models", "match": _match_openai,
     "severity": "medium", "exposure": "Open OpenAI-compatible inference API (no auth)"},
    {"name": "Jupyter", "category": "notebook", "ports": [8888, 8889, 8000],
     "method": "GET", "path": "/api/sessions", "match": _match_jupyter,
     "severity": "critical", "exposure": "Jupyter server reachable without token (RCE)"},
    {"name": "Ray", "category": "compute", "ports": [8265],
     "method": "GET", "path": "/api/version", "match": _match_ray,
     "severity": "high", "exposure": "Ray dashboard exposed (remote job submission → RCE)"},
    {"name": "Triton", "category": "inference", "ports": [8000],
     "method": "GET", "path": "/v2", "match": _match_triton,
     "severity": "medium", "exposure": "NVIDIA Triton inference server exposed"},
    {"name": "TorchServe", "category": "inference", "ports": [8081, 8080],
     "method": "GET", "path": "/models", "match": _match_torchserve,
     "severity": "medium", "exposure": "TorchServe management API exposed"},
    {"name": "ComfyUI", "category": "gen-ai-ui", "ports": [8188],
     "method": "GET", "path": "/system_stats", "match": _match_comfyui,
     "severity": "medium", "exposure": "ComfyUI exposed (workflow execution)"},
    {"name": "Gradio", "category": "gen-ai-ui", "ports": [7860],
     "method": "GET", "path": "/config", "match": _match_gradio,
     "severity": "medium", "exposure": "Gradio / Stable-Diffusion WebUI exposed"},
    {"name": "OpenWebUI", "category": "chat-ui", "ports": [8080, 3000],
     "method": "GET", "path": "/api/config", "match": _match_openwebui,
     "severity": "medium", "exposure": "Open WebUI chat interface exposed"},
    {"name": "MLflow", "category": "ml-platform", "ports": [5000],
     "method": "GET", "path": "/ajax-api/2.0/mlflow/experiments/search?max_results=1", "match": _match_mlflow,
     "severity": "medium", "exposure": "MLflow tracking server exposed (artifact RCE risk)"},
]


def match_ai_signature(sig: dict[str, Any], status: int, headers: dict, text: str) -> dict | None:
    """Run one signature's matcher; returns an evidence dict (with name/category/
    severity merged in) or None."""
    fn: Callable = sig["match"]
    ev = fn(status, headers or {}, text or "")
    if ev is None:
        return None
    ev = {**ev}
    ev.setdefault("product", sig["name"])
    ev["name"] = sig["name"]
    ev["category"] = sig["category"]
    ev["severity"] = sig["severity"]
    ev["exposure"] = sig["exposure"]
    return ev


def assess_ai_findings(services: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Turn discovered AI services into severity-tagged findings."""
    findings: list[dict[str, Any]] = []
    for s in services:
        detail_bits = []
        if s.get("version"):
            detail_bits.append(f"version={s['version']}")
        if s.get("models"):
            detail_bits.append(f"models={len(s['models'])}: " + ", ".join(s["models"][:5]))
        findings.append({
            "target": s.get("host"),
            "port": s.get("port"),
            "title": s.get("exposure") or f"{s.get('product')} exposed",
            "severity": s.get("severity", "medium"),
            "product": s.get("product"),
            "url": s.get("url"),
            "detail": "; ".join(detail_bits),
        })
    return findings


# ── I/O layer (httpx, imported lazily so the module loads without it) ───────────

def _client(params: dict):
    import httpx  # lazy: pure-function tests don't need httpx installed
    timeout = httpx.Timeout(
        connect=float(params.get("connect_timeout", 2.0)),
        read=float(params.get("read_timeout", 5.0)),
        write=5.0, pool=5.0,
    )
    return httpx.Client(timeout=timeout, verify=False, follow_redirects=True,
                        headers={"User-Agent": "intrynx-probe/1.0"})


def _http(client, method: str, url: str, **kw):
    """Single request → (status, headers_lower, text). None on any network error."""
    import httpx
    try:
        resp = client.request(method, url, **kw)
        text = resp.text[:200_000]  # cap body to keep memory bounded
        headers = {k.lower(): v for k, v in resp.headers.items()}
        return resp.status_code, headers, text
    except (httpx.HTTPError, OSError, ValueError):
        return None


def _post_jsonrpc(client, url: str, payload: dict, session_id: str | None = None):
    """POST a JSON-RPC request, reading JSON or a single SSE frame. → (obj, session_id)."""
    import httpx
    headers = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
    if session_id:
        headers["Mcp-Session-Id"] = session_id
    try:
        with client.stream("POST", url, json=payload, headers=headers) as resp:
            ct = resp.headers.get("content-type", "")
            sid = resp.headers.get("mcp-session-id") or session_id
            if "text/event-stream" in ct.lower():
                buf = []
                for line in resp.iter_lines():
                    buf.append(line)
                    if line.startswith("data:"):
                        obj = parse_jsonrpc(ct, "\n".join(buf))
                        if obj is not None:
                            return obj, sid
                    if len("\n".join(buf)) > 100_000:
                        break
                return parse_jsonrpc(ct, "\n".join(buf)), sid
            resp.read()
            return parse_jsonrpc(ct, resp.text[:200_000]), sid
    except (httpx.HTTPError, OSError, ValueError):
        return None, session_id


def _enumerate_mcp(client, url: str, session_id: str | None) -> dict[str, Any]:
    """Best-effort: send initialized notification, then list tools/resources/prompts."""
    out: dict[str, Any] = {"tools": [], "resources": [], "prompts": []}
    # initialized notification (no id, no response expected)
    _post_jsonrpc(client, url, {"jsonrpc": "2.0", "method": "notifications/initialized"}, session_id)
    for key, method in (("tools", "tools/list"), ("resources", "resources/list"), ("prompts", "prompts/list")):
        obj, _ = _post_jsonrpc(client, url, {"jsonrpc": "2.0", "id": 2, "method": method}, session_id)
        if isinstance(obj, dict) and isinstance(obj.get("result"), dict):
            out[key] = obj["result"].get(key, []) or []
    return out


def _check_legacy_sse(client, host: str, port: int, scheme: str) -> dict | None:
    """Legacy MCP HTTP+SSE transport (pre-Streamable-HTTP): GET /sse and look
    for GENUINE MCP protocol evidence in the stream, not just "200 + an
    event-stream content-type" — any unrelated SSE endpoint (logging,
    notifications, live-reload) produces that signal just as easily, the same
    class of weak-evidence bug already found and fixed in the primary
    discovery path (see extract_mcp_server_info, which requires an actual
    JSON-RPC initialize result rather than trusting a status code).

    Real evidence here is either of:
      * an `event: endpoint` frame — the legacy MCP spec's actual signal,
        carrying the JSON-RPC POST endpoint as its data; or
      * a JSON-RPC-shaped `data:` frame (reused via parse_jsonrpc).

    Uses a STREAMING read (like _post_jsonrpc already does) rather than the
    blocking _http() helper: a genuinely long-lived SSE connection never
    reaches EOF, so a non-streaming client.request() would simply block until
    the read timeout on every real SSE server — silently making the previous
    version of this check non-functional against exactly the servers it was
    meant to detect, not just inaccurate against unrelated ones.
    """
    import httpx
    url = f"{scheme}://{host}:{port}/sse"
    try:
        with client.stream("GET", url, headers={"Accept": "text/event-stream"}) as resp:
            if resp.status_code != 200:
                return None
            ct = resp.headers.get("content-type", "")
            if "text/event-stream" not in ct.lower():
                return None
            buf: list[str] = []
            for line in resp.iter_lines():
                buf.append(line)
                joined = "\n".join(buf)
                if "event: endpoint" in joined or "event:endpoint" in joined:
                    break
                if parse_jsonrpc(ct, joined) is not None:
                    break
                if len(joined) > 4096 or len(buf) > 20:
                    return None  # read enough without finding real evidence — give up
            else:
                return None
    except (httpx.HTTPError, OSError, ValueError):
        return None
    return {"host": host, "port": port, "url": url, "transport": "http+sse",
            "server_name": None, "server_version": None, "protocol_version": None,
            "capabilities": [], "tools": [], "resource_count": 0,
            "prompt_count": 0, "dangerous_tools": False}


def _probe_mcp_host(client, host: str, port: int, paths: list[str], scheme: str) -> dict | None:
    """Try the MCP handshake against one host:port across candidate paths."""
    for path in paths:
        url = f"{scheme}://{host}:{port}{path}"
        obj, sid = _post_jsonrpc(client, url, _initialize_payload())
        info = extract_mcp_server_info(obj)
        if info is None:
            continue
        enum = _enumerate_mcp(client, url, sid)
        tool_names, dangerous = classify_mcp_tools(enum["tools"])
        return {
            "host": host, "port": port, "url": url, "transport": "streamable-http",
            "server_name": info["name"], "server_version": info["version"],
            "protocol_version": info["protocolVersion"], "capabilities": info["capabilities"],
            "tools": tool_names, "resource_count": len(enum["resources"]),
            "prompt_count": len(enum["prompts"]), "dangerous_tools": dangerous,
        }
    return _check_legacy_sse(client, host, port, scheme)


def _mcp_findings(servers: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings = []
    for s in servers:
        dangerous = s.get("dangerous_tools")
        sev = "critical" if dangerous else "high"
        detail = f"transport={s['transport']}"
        if s.get("server_name"):
            detail += f"; server={s['server_name']} {s.get('server_version') or ''}".rstrip()
        if s.get("tools"):
            detail += f"; tools[{len(s['tools'])}]: " + ", ".join(s["tools"][:8])
        findings.append({
            "target": s["host"], "port": s["port"], "url": s["url"],
            "title": "Unauthenticated MCP server exposed"
                     + (" with code/data tools" if dangerous else ""),
            "severity": sev, "detail": detail,
        })
    return findings


# ── scanners ────────────────────────────────────────────────────────────────────

@scanner("mcp_discovery", BUILTIN, "MCP server discovery — JSON-RPC handshake + tool enumeration")
def mcp_discovery(params: dict) -> dict:
    targets = normalize_targets(params)
    if not targets:
        return result("mcp_discovery", BUILTIN, [], ok=False, error="no targets provided")
    started = now()
    scheme = params.get("scheme", "http")
    paths = params.get("paths") or MCP_DEFAULT_PATHS
    default_ports = params.get("ports") or MCP_DEFAULT_PORTS
    concurrency = int(params.get("concurrency", 40))

    # Build (host, port) work items. host:port targets pin their own port.
    work: list[tuple[str, int]] = []
    for tok in targets:
        host, port = split_host_port(tok)
        for h in expand_hosts([host], max_hosts=int(params.get("max_hosts", 1024))):
            ports = [port] if port else default_ports
            work += [(h, p) for p in ports]

    servers: list[dict[str, Any]] = []
    client = _client(params)
    try:
        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            futs = {pool.submit(_probe_mcp_host, client, h, p, paths, scheme): (h, p) for h, p in work}
            for fut in as_completed(futs):
                try:
                    found = fut.result()
                except Exception:  # one probe must never sink the scan
                    found = None
                if found:
                    servers.append(found)
    finally:
        client.close()

    findings = _mcp_findings(servers)
    return result("mcp_discovery", BUILTIN, targets, mcp_servers=servers,
                  server_count=len(servers), findings=findings,
                  finding_count=len(findings), endpoints_probed=len(work), started=started)


@scanner("ai_service_discovery", BUILTIN,
         "AI/LLM/ML server discovery — Ollama, vLLM, Jupyter, Ray, Triton, ComfyUI, …")
def ai_service_discovery(params: dict) -> dict:
    targets = normalize_targets(params)
    if not targets:
        return result("ai_service_discovery", BUILTIN, [], ok=False, error="no targets provided")
    started = now()
    scheme = params.get("scheme", "http")
    concurrency = int(params.get("concurrency", 40))
    only = set(params.get("signatures") or [])  # optional whitelist of signature names
    sigs = [s for s in AI_SIGNATURES if not only or s["name"] in only]

    # Build (host, signature, port) work items.
    hosts: list[str] = []
    pinned: dict[str, int] = {}
    for tok in targets:
        host, port = split_host_port(tok)
        for h in expand_hosts([host], max_hosts=int(params.get("max_hosts", 1024))):
            hosts.append(h)
            if port:
                pinned[h] = port

    work: list[tuple[str, dict, int]] = []
    for h in hosts:
        for sig in sigs:
            ports = [pinned[h]] if h in pinned else sig["ports"]
            work += [(h, sig, p) for p in ports]

    services: list[dict[str, Any]] = []
    client = _client(params)

    def _one(host: str, sig: dict, port: int) -> dict | None:
        url = f"{scheme}://{host}:{port}{sig['path']}"
        res = _http(client, sig["method"], url)
        if not res:
            return None
        status, headers, text = res
        ev = match_ai_signature(sig, status, headers, text)
        if ev is None:
            return None
        ev["host"], ev["port"], ev["url"] = host, port, url
        return ev

    try:
        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            futs = [pool.submit(_one, h, sig, p) for h, sig, p in work]
            for fut in as_completed(futs):
                try:
                    found = fut.result()
                except Exception:
                    found = None
                if found:
                    services.append(found)
    finally:
        client.close()

    # de-dupe (host, port, product) — a host can match multiple signatures on a shared port
    seen: set[tuple] = set()
    uniq = []
    for s in services:
        key = (s["host"], s["port"], s["product"])
        if key not in seen:
            seen.add(key)
            uniq.append(s)

    findings = assess_ai_findings(uniq)
    by_cat: dict[str, int] = {}
    for s in uniq:
        by_cat[s["category"]] = by_cat.get(s["category"], 0) + 1
    return result("ai_service_discovery", BUILTIN, targets, ai_services=uniq,
                  service_count=len(uniq), by_category=by_cat, findings=findings,
                  finding_count=len(findings), endpoints_probed=len(work), started=started)
