"""
Unit tests for the probe scanning module — parsers + registry/dispatch.

These exercise the output-parsing logic with sample tool output, so they run
without any scanning tools installed. Run:  python3 -m pytest probe/tests -q
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import scanners
from scanners.base import (
    BUILTIN, BUILTIN_PASSIVE, BUILTIN_DB, BUILTIN_SSH, BUILTIN_WINRM, expand_hosts,
    normalize_targets, split_host_port,
)
from scanners.discovery import parse_nmap_xml
from scanners.vuln import parse_nuclei_jsonl
from scanners.tls import parse_sslscan_xml
from scanners.web import parse_httpx_jsonl
from scanners.passive import _device_hint, _printable_strings
from scanners.smb import parse_nxc_smb
from scanners.fingerprint import build_inventory, categorize
from scanners.massscan import parse_masscan_json
from scanners import mcp_ai


# ── registry / dispatch ────────────────────────────────────────────────────────

def test_all_capabilities_registered():
    assert set(scanners.base.REGISTRY) == {
        "discovery", "host_discovery", "port_scan", "mass_scan", "service_fingerprint",
        "udp_scan", "vuln_scan", "tls_scan", "web_scan", "smb_enum",
        "mcp_discovery", "ai_service_discovery", "passive_discovery", "db_fingerprint",
        "ssh_inventory", "windows_inventory",
    }


def test_builtin_scanners_always_available():
    # MCP/AI scanners are pure-Python (binary=builtin) → available regardless of host tools.
    assert scanners.base.REGISTRY["mcp_discovery"].available() is True
    assert scanners.base.REGISTRY["ai_service_discovery"].available() is True
    assert scanners.base.REGISTRY["mcp_discovery"].binary == BUILTIN
    assert scanners.base.REGISTRY["mcp_discovery"].engine == "ix-aiscan"
    # passive_discovery uses a distinct builtin sentinel so it gets its own
    # engine label instead of being mislabeled as the AI scanner.
    assert scanners.base.REGISTRY["passive_discovery"].available() is True
    assert scanners.base.REGISTRY["passive_discovery"].binary == BUILTIN_PASSIVE
    assert scanners.base.REGISTRY["passive_discovery"].engine == "ix-passivescan"
    assert scanners.base.REGISTRY["db_fingerprint"].available() is True
    assert scanners.base.REGISTRY["db_fingerprint"].binary == BUILTIN_DB
    assert scanners.base.REGISTRY["db_fingerprint"].engine == "ix-dbscan"


def test_ssh_inventory_availability_matches_paramiko():
    # Unlike the always-available builtins above, ssh_inventory's
    # availability depends on an optional Python import — assert it tracks
    # that import rather than hard-coding True/False (robust regardless of
    # whether paramiko happens to be installed wherever this test runs).
    from scanners.ssh import _HAVE_PARAMIKO
    assert scanners.base.REGISTRY["ssh_inventory"].binary == BUILTIN_SSH
    assert scanners.base.REGISTRY["ssh_inventory"].engine == "ix-sshaudit"
    assert scanners.base.REGISTRY["ssh_inventory"].available() == _HAVE_PARAMIKO


def test_ssh_inventory_requires_credentials():
    if not scanners.base.REGISTRY["ssh_inventory"].available():
        return  # paramiko not installed here — nothing to exercise
    res = scanners.dispatch("ssh_inventory", {"targets": ["10.0.0.5"]})
    assert res["ok"] is False
    assert "credentials" in res["error"]


def test_windows_inventory_availability_matches_either_transport():
    from scanners.windows import _HAVE_WINRM, _HAVE_IMPACKET
    assert scanners.base.REGISTRY["windows_inventory"].binary == BUILTIN_WINRM
    assert scanners.base.REGISTRY["windows_inventory"].engine == "ix-winaudit"
    assert (scanners.base.REGISTRY["windows_inventory"].available()
            == (_HAVE_WINRM or _HAVE_IMPACKET))


def test_windows_inventory_requires_credentials():
    if not scanners.base.REGISTRY["windows_inventory"].available():
        return  # neither pywinrm nor impacket installed here — nothing to exercise
    res = scanners.dispatch("windows_inventory", {"targets": ["10.0.0.5"]})
    assert res["ok"] is False
    assert "credentials" in res["error"]


def test_full_user_prefixes_domain_only_when_needed():
    from scanners.windows import _full_user
    assert _full_user({"username": "alice", "domain": "CORP"}) == "CORP\\alice"
    assert _full_user({"username": "CORP\\alice", "domain": "CORP"}) == "CORP\\alice"
    assert _full_user({"username": "alice@corp.local", "domain": "CORP"}) == "alice@corp.local"
    assert _full_user({"username": "alice"}) == "alice"


# ── white-labeling: the underlying open-source tools must never leak ────────────

_RAW_TOOL_NAMES = ("nmap", "masscan", "nuclei", "httpx", "sslscan", "netexec", "nxc")


def test_capability_catalog_hides_tools():
    cat = scanners.capability_catalog()
    blob = json.dumps(cat).lower()
    for raw in _RAW_TOOL_NAMES:
        assert raw not in blob, f"catalog leaks tool name: {raw}"
    # every entry advertises a branded engine label instead
    assert all(c["engine"].startswith("ix-") for c in cat)


def test_dispatch_errors_hide_tools():
    # unavailable engine → branded message, no raw tool name
    r = scanners.dispatch("mass_scan", {"targets": ["10.0.0.1"]})
    if not scanners.base.REGISTRY["mass_scan"].available():
        assert "masscan" not in r["error"].lower()
        assert r["engine"] == "ix-fastsweep" and "ix-fastsweep" in r["error"]


def test_result_envelope_is_branded():
    from scanners.base import result
    env = result("discovery", "nmap", ["x"], ok=False, error="nmap timed out")
    assert env["engine"] == "ix-netscan" and env["tool"] == "ix-netscan"
    assert "nmap" not in env["error"] and "scan-engine" in env["error"]


def test_resolve_scan_type():
    assert scanners.resolve_scan_type("discovery", {}) == "discovery"
    assert scanners.resolve_scan_type("lateral", {}) == "smb_enum"
    assert scanners.resolve_scan_type("cloud_scan", {}) == "vuln_scan"
    assert scanners.resolve_scan_type("discovery", {"scan_type": "tls_scan"}) == "tls_scan"


def test_dispatch_unknown():
    r = scanners.dispatch("nope", {})
    assert r["ok"] is False and "unsupported" in r["error"]


def test_dispatch_missing_tool_is_graceful():
    # sslscan unlikely installed in CI → must report not-installed, not crash
    r = scanners.dispatch("tls_scan", {"targets": ["example.com"]})
    if not scanners.base.REGISTRY["tls_scan"].available():
        assert r["ok"] is False and "not available" in r["error"]


def test_normalize_targets():
    assert normalize_targets({"targets": ["10.0.0.0/24", "x"]}) == ["10.0.0.0/24", "x"]
    assert normalize_targets({"targets": "10.0.0.1, 10.0.0.2 10.0.0.3"}) == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
    assert normalize_targets({}) == []


# ── nmap ────────────────────────────────────────────────────────────────────────

NMAP_XML = """<?xml version="1.0"?><nmaprun>
<host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/>
<hostnames><hostname name="web01"/></hostnames>
<ports>
  <port protocol="tcp" portid="443"><state state="open"/><service name="https" product="nginx" version="1.25"/></port>
  <port protocol="tcp" portid="22"><state state="closed"/></port>
</ports></host>
<host><status state="down"/><address addr="10.0.0.9" addrtype="ipv4"/></host>
</nmaprun>"""


def test_parse_nmap_xml():
    hosts = parse_nmap_xml(NMAP_XML)
    assert len(hosts) == 1                       # down host excluded
    h = hosts[0]
    assert h["ip"] == "10.0.0.5" and h["hostname"] == "web01"
    assert len(h["ports"]) == 1                  # closed port excluded
    assert h["ports"][0]["port"] == 443 and h["ports"][0]["product"] == "nginx"


def test_parse_nmap_xml_malformed():
    assert parse_nmap_xml("not xml") == []


# ── nuclei ──────────────────────────────────────────────────────────────────────

NUCLEI_JSONL = (
    '{"template-id":"CVE-2021-44228","info":{"name":"Log4Shell","severity":"critical","tags":["cve","log4j"]},'
    '"matched-at":"http://10.0.0.5:8080/","type":"http"}\n'
    'garbage line\n'
    '{"template-id":"open-redirect","info":{"name":"Open Redirect","severity":"medium"},"matched-at":"http://x/"}\n'
)


def test_parse_nuclei_jsonl():
    f = parse_nuclei_jsonl(NUCLEI_JSONL)
    assert len(f) == 2
    assert f[0]["severity"] == "critical"
    assert f[0]["cves"] == ["CVE-2021-44228"]
    assert f[1]["severity"] == "medium"


# ── sslscan ──────────────────────────────────────────────────────────────────────

SSLSCAN_XML = """<document><ssltest host="10.0.0.5" port="443">
  <protocol type="ssl" version="3" enabled="1"/>
  <protocol type="tls" version="1.0" enabled="1"/>
  <protocol type="tls" version="1.2" enabled="1"/>
  <cipher status="accepted" cipher="NULL-MD5" strength="null"/>
  <cipher status="accepted" cipher="AES256-GCM" strength="strong"/>
  <certificate><self-signed>true</self-signed><expired>false</expired></certificate>
</ssltest></document>"""


def test_parse_sslscan_xml():
    f = parse_sslscan_xml(SSLSCAN_XML, "10.0.0.5")
    titles = [x["title"] for x in f]
    assert any("SSLv3" in t for t in titles)
    assert any("TLSv1.0" in t for t in titles)
    assert any("NULL-MD5" in t for t in titles)
    assert any("Self-signed" in t for t in titles)
    assert not any("AES256" in t for t in titles)   # strong cipher not flagged


# ── httpx ────────────────────────────────────────────────────────────────────────

HTTPX_JSONL = (
    '{"url":"http://10.0.0.5:8080","status_code":200,"title":"Welcome","webserver":"nginx","tech":["Nginx","PHP"]}\n'
    '{"url":"https://10.0.0.6","status_code":403,"title":"Forbidden","webserver":"Apache"}\n'
)


def test_parse_httpx_jsonl():
    s = parse_httpx_jsonl(HTTPX_JSONL)
    assert len(s) == 2
    assert s[0]["status"] == 200 and "Nginx" in s[0]["tech"]
    assert s[1]["status"] == 403


# ── netexec (nxc) ─────────────────────────────────────────────────────────────────

NXC_OUTPUT = (
    "SMB  10.0.0.5  445  DC01  [*] Windows Server 2019 Build 17763 (name:DC01) (domain:corp.local) (signing:False) (SMBv1:True)\n"
    "SMB  10.0.0.6  445  FS01  [*] Windows 10 Build 19041 (name:FS01) (domain:corp.local) (signing:True) (SMBv1:False)\n"
)


def test_parse_nxc_smb():
    parsed = parse_nxc_smb(NXC_OUTPUT)
    assert len(parsed["hosts"]) == 2
    dc = next(h for h in parsed["hosts"] if h["ip"] == "10.0.0.5")
    assert dc["signing"] is False and dc["smbv1"] is True and dc["domain"] == "corp.local"
    titles = [f["title"] for f in parsed["findings"]]
    assert "SMB signing not required" in titles   # from DC01 (signing:False)
    assert "SMBv1 enabled" in titles
    # FS01 has signing:True → should NOT produce a signing finding for it
    assert sum(1 for f in parsed["findings"] if f["title"] == "SMB signing not required") == 1


def test_printable_strings():
    # "hi" is only 2 chars (< min_len=4) and must be discarded, not just trimmed.
    assert _printable_strings(b"hi\x00\x00world!!\x01", 4, 6) == ["world!!"]


def test_device_hint_ssdp():
    payload = (b"NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
               b"SERVER: Linux/3.10 UPnP/1.0 MyDevice/1.0\r\n"
               b"USN: uuid:1234::upnp:rootdevice\r\n\r\n")
    assert _device_hint("ssdp", payload) == "SERVER: Linux/3.10 UPnP/1.0 MyDevice/1.0"


def test_device_hint_mdns():
    # length-prefix bytes (non-printable) act as separators around real labels,
    # same as a real mDNS service-type record (e.g. a Chromecast announcing
    # _googlecast._tcp.local).
    payload = b"\x00\x00\x84\x00\x0b_googlecast\x04_tcp\x05local\x00"
    # "local" has neither "." nor "_" so it's correctly excluded from the hint.
    assert _device_hint("mdns", payload) == "_googlecast, _tcp"


# ── base helpers: target/host expansion ──────────────────────────────────────────

def test_split_host_port():
    assert split_host_port("10.0.0.5:8080") == ("10.0.0.5", 8080)
    assert split_host_port("10.0.0.5") == ("10.0.0.5", None)
    assert split_host_port("[::1]:443") == ("::1", 443)
    assert split_host_port("example.com:1234") == ("example.com", 1234)


def test_expand_hosts():
    # /30 has 2 usable hosts; hostnames pass through; cap is honoured.
    assert expand_hosts(["10.0.0.0/30"]) == ["10.0.0.1", "10.0.0.2"]
    assert expand_hosts(["example.com"]) == ["example.com"]
    assert expand_hosts(["10.0.0.5"]) == ["10.0.0.5"]
    assert len(expand_hosts(["10.0.0.0/16"], max_hosts=50)) == 50


# ── nmap CPE / MAC enrichment ────────────────────────────────────────────────────

NMAP_CPE_XML = """<?xml version="1.0"?><nmaprun>
<host><status state="up"/>
<address addr="10.0.0.5" addrtype="ipv4"/>
<address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Dell Inc."/>
<ports><port protocol="tcp" portid="443"><state state="open"/>
  <service name="https" product="nginx" version="1.25" tunnel="ssl">
    <cpe>cpe:/a:nginx:nginx:1.25</cpe></service></port></ports>
<os><osmatch name="Linux 5.x" accuracy="96"/></os></host>
</nmaprun>"""


def test_parse_nmap_xml_cpe_mac():
    h = parse_nmap_xml(NMAP_CPE_XML)[0]
    assert h["mac"] == "AA:BB:CC:DD:EE:FF" and h["vendor"] == "Dell Inc."
    assert h["os"] == "Linux 5.x" and h["os_accuracy"] == 96
    p = h["ports"][0]
    assert p["cpe"] == ["cpe:/a:nginx:nginx:1.25"] and p["tunnel"] == "ssl"


def test_parse_nmap_xml_udp_states():
    xml = ('<nmaprun><host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/>'
           '<ports><port protocol="udp" portid="161"><state state="open|filtered"/>'
           '<service name="snmp"/></port></ports></host></nmaprun>')
    # default keeps only "open" → none; explicit include keeps open|filtered
    assert parse_nmap_xml(xml)[0]["ports"] == []
    assert parse_nmap_xml(xml, include_states=("open", "open|filtered"))[0]["ports"][0]["service"] == "snmp"


# ── service_fingerprint: categorization + inventory ──────────────────────────────

def test_categorize():
    assert categorize({"service": "http", "product": "nginx"}) == "web-server"
    assert categorize({"service": "mysql", "product": "MySQL"}) == "database"
    assert categorize({"service": "ssh", "product": "OpenSSH"}) == "remote-access"
    assert categorize({"product": "Ollama"}) == "ai-ml"
    assert categorize({"cpe": ["cpe:/a:redis:redis"]}) == "cache"
    assert categorize({"service": "unknown"}) is None


def test_build_inventory():
    hosts = [{"ip": "10.0.0.5", "ports": [
        {"port": 443, "protocol": "tcp", "service": "https", "product": "nginx",
         "version": "1.25", "cpe": ["cpe:/a:nginx:nginx:1.25"]},
        {"port": 3306, "protocol": "tcp", "service": "mysql", "product": "MySQL",
         "version": "8.0", "cpe": []},
        {"port": 9999, "protocol": "tcp", "service": "unknown", "product": None, "cpe": []},
    ]}]
    inv = build_inventory(hosts)
    assert inv["by_category"] == {"web-server": 1, "database": 1}  # unknown skipped
    assert inv["software"]["nginx 1.25"] == 1
    assert len(inv["servers"]) == 2


# ── masscan ──────────────────────────────────────────────────────────────────────

MASSCAN_JSON = (
    "[\n"
    '{   "ip": "10.0.0.5",   "timestamp": "1", "ports": [ {"port": 80, "proto": "tcp", "status": "open"} ] },\n'
    '{   "ip": "10.0.0.5",   "timestamp": "1", "ports": [ {"port": 443, "proto": "tcp", "status": "open"} ] },\n'
    '{   "ip": "10.0.0.6",   "timestamp": "1", "ports": [ {"port": 22, "proto": "tcp", "status": "open"} ] }\n'
    "]\n"
)


def test_parse_masscan_json():
    hosts = parse_masscan_json(MASSCAN_JSON)
    assert len(hosts) == 2                       # merged per host
    h5 = next(h for h in hosts if h["ip"] == "10.0.0.5")
    assert sorted(p["port"] for p in h5["ports"]) == [80, 443]


# ── MCP discovery ─────────────────────────────────────────────────────────────────

MCP_INIT_JSON = json.dumps({
    "jsonrpc": "2.0", "id": 1,
    "result": {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}, "resources": {}},
               "serverInfo": {"name": "demo-mcp", "version": "0.3.1"}},
})

MCP_INIT_SSE = "event: message\ndata: " + MCP_INIT_JSON + "\n\n"


def test_parse_jsonrpc_json_and_sse():
    assert mcp_ai.parse_jsonrpc("application/json", MCP_INIT_JSON)["id"] == 1
    assert mcp_ai.parse_jsonrpc("text/event-stream", MCP_INIT_SSE)["id"] == 1
    assert mcp_ai.parse_jsonrpc("application/json", "not json") is None


def test_extract_mcp_server_info():
    info = mcp_ai.extract_mcp_server_info(json.loads(MCP_INIT_JSON))
    assert info["name"] == "demo-mcp" and info["protocolVersion"] == "2025-06-18"
    assert set(info["capabilities"]) == {"tools", "resources"}
    # a plain JSON-RPC error / non-MCP result is rejected
    assert mcp_ai.extract_mcp_server_info({"jsonrpc": "2.0", "result": {"foo": 1}}) is None
    assert mcp_ai.extract_mcp_server_info({"error": {}}) is None


def test_classify_mcp_tools():
    names, dangerous = mcp_ai.classify_mcp_tools(
        [{"name": "list_notes"}, {"name": "run_shell", "description": "execute a command"}])
    assert names == ["list_notes", "run_shell"] and dangerous is True
    names, dangerous = mcp_ai.classify_mcp_tools([{"name": "get_weather"}])
    assert dangerous is False


def test_mcp_findings_severity():
    servers = [{"host": "10.0.0.5", "port": 8000, "url": "http://10.0.0.5:8000/mcp",
                "transport": "streamable-http", "server_name": "x", "server_version": "1",
                "tools": ["run_shell"], "dangerous_tools": True}]
    f = mcp_ai._mcp_findings(servers)[0]
    assert f["severity"] == "critical" and "code/data tools" in f["title"]


# ── AI service discovery ───────────────────────────────────────────────────────────

def test_match_ollama():
    ev = mcp_ai._match_ollama(200, {}, '{"models":[{"name":"llama3:8b"},{"name":"qwen:7b"}]}')
    assert ev["product"] == "Ollama" and ev["models"] == ["llama3:8b", "qwen:7b"]
    assert mcp_ai._match_ollama(404, {}, "") is None


def test_match_openai_and_server_header():
    body = '{"object":"list","data":[{"id":"gpt-4o","object":"model"}]}'
    ev = mcp_ai._match_openai(200, {"server": "uvicorn"}, body)
    assert "vLLM" in ev["product"] and ev["models"] == ["gpt-4o"]


def test_match_ai_signature_merges_metadata():
    sig = next(s for s in mcp_ai.AI_SIGNATURES if s["name"] == "Ollama")
    ev = mcp_ai.match_ai_signature(sig, 200, {}, '{"models":[{"name":"llama3"}]}')
    assert ev["category"] == "llm-runtime" and ev["severity"] == "high"
    assert mcp_ai.match_ai_signature(sig, 500, {}, "") is None


def test_db_findings_redis_unauth_only():
    from scanners.db import _db_findings
    services = [
        {"host": "10.0.0.5", "port": 6379, "engine": "redis",
         "auth_required": False, "server_version": "7.2.4"},
        {"host": "10.0.0.6", "port": 6379, "engine": "redis",
         "auth_required": True, "server_version": None},
        {"host": "10.0.0.7", "port": 27017, "engine": "mongodb",
         "wire_reply_opcode": 1, "server_version": "6.0.1"},
        {"host": "10.0.0.8", "port": 3306, "engine": "mysql/mariadb", "server_version": "8.0.23"},
    ]
    findings = _db_findings(services)
    # Only the unauthenticated Redis produces a finding — a successful
    # MongoDB isMaster or a plain MySQL/MSSQL/Postgres handshake never
    # proves auth is disabled, so those three stay inventory-only.
    assert len(findings) == 1
    assert findings[0]["target"] == "10.0.0.5" and findings[0]["severity"] == "critical"
    assert "7.2.4" in findings[0]["detail"]


def test_check_legacy_sse_rejects_generic_stream():
    # A bare 200 + text/event-stream content-type is NOT MCP-specific
    # evidence — any unrelated SSE service (log tailer, live-reload,
    # heartbeat) produces exactly this signal. This is the same class of
    # weak-evidence bug found and fixed in scanner_module's mcp_ai_scanner.py
    # (trusting a status code instead of real protocol content) — applied
    # here to the legacy MCP SSE fallback path specifically.
    import httpx
    from scanners.mcp_ai import _check_legacy_sse

    def handler(request):
        return httpx.Response(200, headers={"content-type": "text/event-stream"},
                              text="event: heartbeat\ndata: tick\n\n")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    assert _check_legacy_sse(client, "10.0.0.5", 8080, "http") is None
    client.close()


def test_check_legacy_sse_confirms_real_endpoint_event():
    # The legacy MCP HTTP+SSE transport spec's actual signal: an
    # "event: endpoint" frame carrying the JSON-RPC POST endpoint.
    import httpx
    from scanners.mcp_ai import _check_legacy_sse

    def handler(request):
        return httpx.Response(200, headers={"content-type": "text/event-stream"},
                              text="event: endpoint\ndata: /messages?sessionId=abc\n\n")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    res = _check_legacy_sse(client, "10.0.0.5", 8080, "http")
    assert res is not None and res["transport"] == "http+sse" and res["host"] == "10.0.0.5"
    client.close()


def test_check_legacy_sse_rejects_non_sse_content_type():
    import httpx
    from scanners.mcp_ai import _check_legacy_sse

    def handler(request):
        return httpx.Response(200, headers={"content-type": "text/html"}, text="<html></html>")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    assert _check_legacy_sse(client, "10.0.0.5", 8080, "http") is None
    client.close()


def test_assess_ai_findings():
    services = [{"host": "10.0.0.5", "port": 11434, "product": "Ollama", "severity": "high",
                 "exposure": "Unauthenticated Ollama LLM runtime exposed",
                 "models": ["llama3", "qwen"], "url": "http://10.0.0.5:11434/api/tags"}]
    f = mcp_ai.assess_ai_findings(services)[0]
    assert f["severity"] == "high" and f["port"] == 11434 and "models=2" in f["detail"]
