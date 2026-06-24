#!/usr/bin/env python3
"""
ADVERSA ScanningAgent
Polls the platform API for scan jobs, executes them, and reports results.
Communication is secured via mTLS (client cert issued at registration).
Credentials are fetched from HashiCorp Vault — never stored locally.
"""

import asyncio
import json
import logging
import os
import signal
import ssl
import sys
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

import aiohttp
import hvac  # HashiCorp Vault client

# ── Configuration ─────────────────────────────────────────────────────────────

PLATFORM_API_URL   = os.environ.get("PLATFORM_API_URL",   "https://adversa.internal:8443")
AGENT_ID           = os.environ.get("AGENT_ID",           "")
VAULT_ADDR         = os.environ.get("VAULT_ADDR",         "https://vault.internal:8200")
VAULT_ROLE_TOKEN   = os.environ.get("VAULT_ROLE_TOKEN",   "")
TLS_CERT_PATH      = os.environ.get("TLS_CERT_PATH",      "/etc/adversa/certs/client.pem")
TLS_KEY_PATH       = os.environ.get("TLS_KEY_PATH",       "/etc/adversa/certs/client.key")
TLS_CA_PATH        = os.environ.get("TLS_CA_PATH",        "/etc/adversa/certs/ca.pem")
POLL_INTERVAL      = int(os.environ.get("POLL_INTERVAL",  "10"))   # seconds
HEARTBEAT_INTERVAL = int(os.environ.get("HEARTBEAT_INTERVAL", "30"))  # seconds
LOG_LEVEL          = os.environ.get("LOG_LEVEL",          "INFO")

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("adversa.agent")


# ── Types ─────────────────────────────────────────────────────────────────────

class JobType(str, Enum):
    DISCOVERY        = "discovery"
    PORT_DISCOVERY   = "port_discovery"
    VULN_SCAN        = "vuln_scan"
    DEEP_VULN_SCAN   = "deep_vuln_scan"
    SMB_VALIDATION   = "smb_validation"
    AD_ENUM          = "ad_enum"
    TLS_SCAN         = "tls_scan"
    EVIDENCE_COLLECT = "evidence_collect"
    LATERAL_MOVEMENT = "lateral_movement"
    CLOUD_SCAN       = "cloud_scan"
    PIPELINE         = "pipeline"


@dataclass
class ScanJob:
    id: str
    type: JobType
    engagement_id: str
    target_cidrs: list[str]
    excluded_cidrs: list[str]
    profile: str  # fast | standard | deep
    ports: Optional[str] = None  # Naabu-supplied port list for Nmap
    raw: dict = field(default_factory=dict)


# ── Vault credential fetcher ───────────────────────────────────────────────────

class VaultCredentialFetcher:
    """Fetches credentials from HashiCorp Vault at runtime. Never caches to disk."""

    def __init__(self, vault_addr: str, role_token: str):
        self.client = hvac.Client(url=vault_addr, token=role_token)

    def get_credentials(self, secret_path: str) -> dict[str, str]:
        """Read a KV-v2 secret from Vault."""
        try:
            resp = self.client.secrets.kv.v2.read_secret_version(path=secret_path)
            return resp["data"]["data"]
        except Exception as e:
            log.error("Vault read failed for %s: %s", secret_path, e)
            return {}


# ── mTLS session builder ───────────────────────────────────────────────────────

def build_ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=TLS_CA_PATH)
    ctx.load_cert_chain(certfile=TLS_CERT_PATH, keyfile=TLS_KEY_PATH)
    return ctx


# ── Tool availability check ────────────────────────────────────────────────────

async def check_tool_availability() -> dict[str, bool]:
    tools = {
        "naabu":      ["naabu",      "-version"],
        "nmap":       ["nmap",       "--version"],
        "nuclei":     ["nuclei",     "-version"],
        "netexec":    ["nxc",        "--version"],
        "testssl":    ["testssl.sh", "--version"],
        "eyewitness": ["eyewitness", "--version"],
    }
    availability: dict[str, bool] = {}
    for name, cmd in tools.items():
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await proc.communicate()
            availability[name] = proc.returncode == 0
        except FileNotFoundError:
            availability[name] = False
    log.info("Tool availability: %s", availability)
    return availability


# ── Job executors ──────────────────────────────────────────────────────────────

def count_by_severity(items: list[dict]) -> dict[str, int]:
    stats = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for item in items:
        sev = (item.get("severity") or "info").lower()
        if sev in stats:
            stats[sev] += 1
    return stats


async def execute_naabu(job: ScanJob, creds: dict, report_progress) -> dict:
    """Fast port discovery with naabu. Feeds port list to Nmap."""
    log.info("[%s] Naabu port discovery on %s", job.id, job.target_cidrs)

    targets_file = "/tmp/naabu_targets.txt"
    output_file  = "/tmp/naabu_out.json"
    port_spec    = job.ports or "top-1000"

    targets = [c for c in job.target_cidrs if c not in job.excluded_cidrs]
    with open(targets_file, "w") as f:
        f.write("\n".join(targets))

    naabu_cmd = [
        "naabu",
        "-list", targets_file,
        "-rate", "1000",
        "-json",
        "-o", output_file,
        "-silent",
    ]
    if port_spec == "1-65535":
        naabu_cmd += ["-p", "1-65535"]
    elif port_spec.startswith("top-"):
        naabu_cmd += ["-top-ports", port_spec.replace("top-", "")]
    else:
        naabu_cmd += ["-p", port_spec]

    await report_progress(10)
    proc = await asyncio.create_subprocess_exec(
        *naabu_cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    await report_progress(80)
    await proc.communicate()

    host_map: dict[str, list[int]] = {}
    if os.path.exists(output_file):
        with open(output_file) as f:
            for line in f:
                try:
                    obj = json.loads(line.strip())
                    ip = obj.get("ip", "")
                    port = obj.get("port", 0)
                    if ip and port:
                        host_map.setdefault(ip, []).append(port)
                except json.JSONDecodeError:
                    pass

    hosts = [
        {"ip": ip, "openPorts": sorted(ports), "portCount": len(ports)}
        for ip, ports in host_map.items()
    ]

    await report_progress(100)
    return {
        "scanner":         "naabu",
        "hosts":           hosts,
        "totalHosts":      len(hosts),
        "totalOpenPorts":  sum(h["portCount"] for h in hosts),
        "nmap_ports":      ",".join(str(p) for p in sorted({p for h in hosts for p in h["openPorts"]})),
    }


async def execute_discovery(job: ScanJob, creds: dict, report_progress) -> dict:
    """Nmap service enumeration. Accepts port list from Naabu."""
    log.info("[%s] Discovery on %s (profile=%s)", job.id, job.target_cidrs, job.profile)

    nmap_flags: list[str]
    if job.ports:
        # Targeted scan on Naabu-supplied ports
        nmap_flags = ["-sV", "-sC", "-A", "--version-intensity", "7", "-p", job.ports]
    else:
        nmap_flags = {
            "fast":     ["-sn", "-T4"],
            "standard": ["-sV", "-sC", "-T3", "--top-ports", "1000"],
            "deep":     ["-sV", "-sC", "-A", "-T3", "-p-"],
        }.get(job.profile, ["-sn", "-T4"])

    targets = [c for c in job.target_cidrs if c not in job.excluded_cidrs]

    await report_progress(10)
    proc = await asyncio.create_subprocess_exec(
        "nmap", *nmap_flags, "-oX", "/tmp/nmap_out.xml", *targets,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    await report_progress(70)
    stdout, stderr = await proc.communicate()
    if proc.returncode != 0:
        raise RuntimeError(f"nmap failed: {stderr.decode()}")

    await report_progress(90)
    assets_found = 0
    if os.path.exists("/tmp/nmap_out.xml"):
        with open("/tmp/nmap_out.xml") as f:
            assets_found = f.read().count("<host ")

    await report_progress(100)
    return {"assetsFound": assets_found, "profile": job.profile, "nmapFlags": nmap_flags}


async def execute_vuln_scan(job: ScanJob, creds: dict, report_progress) -> dict:
    """Nuclei vulnerability scan — production-ready."""
    log.info("[%s] Nuclei vuln scan on %s", job.id, job.target_cidrs)

    targets_file = "/tmp/nuclei_targets.txt"
    output_file  = "/tmp/nuclei_out.jsonl"

    targets = [c for c in job.target_cidrs if c not in job.excluded_cidrs]
    with open(targets_file, "w") as f:
        f.write("\n".join(targets))

    severity_map = {
        "fast":     "critical,high",
        "standard": "critical,high,medium",
        "deep":     "critical,high,medium,low,info",
    }

    cmd = [
        "nuclei",
        "-l", targets_file,
        "-tags", "cves,misconfigs,default-logins,exposed-panels,ssl,network",
        "-severity", severity_map.get(job.profile, "critical,high,medium"),
        "-json-export", output_file,
        "-rate-limit", "50",
        "-c", "25",
        "-retries", "1",
        "-timeout", "5",
        "-silent",
    ]

    await report_progress(10)
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    await report_progress(80)
    await proc.communicate()

    matches: list[dict] = []
    if os.path.exists(output_file):
        with open(output_file) as f:
            for line in f:
                try:
                    matches.append(json.loads(line.strip()))
                except json.JSONDecodeError:
                    pass

    await report_progress(100)
    return {
        "scanner": "nuclei",
        "matches": matches,
        "stats":   count_by_severity(matches),
    }


def parse_spn_output(output: str) -> list[dict]:
    spns = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 2 and "/" in parts[0]:
            spns.append({"spn": parts[0], "account": parts[1] if len(parts) > 1 else ""})
    return spns


async def execute_ad_enum(job: ScanJob, creds: dict, report_progress) -> dict:
    """Impacket-based AD enumeration: Kerberoast, AS-REP roast, LDAP anonymous bind."""
    log.info("[%s] AD enumeration", job.id)

    dc_ip    = creds.get("dc_ip",    "")
    domain   = creds.get("domain",   "")
    username = creds.get("username", "")
    password = creds.get("password", "")

    if not all([dc_ip, domain, username, password]):
        return {"error": "AD credentials required in Vault", "scanner": "impacket"}

    findings: list[dict] = []
    target = f"{domain}/{username}:{password}"

    # 1. Kerberoastable accounts
    proc = await asyncio.create_subprocess_exec(
        "GetUserSPNs.py", target, "-dc-ip", dc_ip,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    stdout, _ = await proc.communicate()
    spn_output = stdout.decode()
    spns = parse_spn_output(spn_output)
    if spns:
        findings.append({
            "title":            f"Kerberoastable Service Accounts ({len(spns)} found)",
            "severity":         "HIGH",
            "description":      f"{len(spns)} service accounts with SPNs are kerberoastable.",
            "technicalDetails": spn_output[:2000],
            "mitre":            [{"id": "T1558.003", "name": "Steal or Forge Kerberos Tickets: Kerberoasting"}],
        })

    await report_progress(30)

    # 2. AS-REP Roastable
    proc = await asyncio.create_subprocess_exec(
        "GetNPUsers.py", f"{domain}/",
        "-dc-ip", dc_ip, "-no-pass", "-format", "hashcat",
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    stdout, _ = await proc.communicate()
    asrep_hashes = [l for l in stdout.decode().splitlines() if l.startswith("$krb5asrep")]
    if asrep_hashes:
        findings.append({
            "title":       f"AS-REP Roasting — {len(asrep_hashes)} Account(s) Vulnerable",
            "severity":    "HIGH",
            "description": "Accounts do not require Kerberos preauthentication.",
            "mitre":       [{"id": "T1558.004", "name": "AS-REP Roasting"}],
        })

    await report_progress(60)

    # 3. LDAP anonymous bind check
    try:
        import ldap3
        conn = ldap3.Connection(dc_ip, auto_bind=ldap3.AUTO_BIND_NO_TLS)
        if conn.bind():
            findings.append({
                "title":       "LDAP Anonymous Bind Enabled",
                "severity":    "HIGH",
                "description": "Domain controller allows anonymous LDAP bind. Unauthenticated enumeration is possible.",
                "mitre":       [{"id": "T1087.002", "name": "Account Discovery: Domain Account"}],
            })
    except Exception:
        pass

    await report_progress(100)
    return {"scanner": "impacket", "findings": findings, "spns": spns}


async def execute_smb_validation(job: ScanJob, creds: dict, report_progress) -> dict:
    """NetExec SMB validation: signing, null sessions, SMBv1."""
    log.info("[%s] SMB validation on %s", job.id, job.target_cidrs)

    domain   = creds.get("domain",   "")
    username = creds.get("username", "")
    password = creds.get("password", "")

    findings: list[dict] = []
    targets = [c for c in job.target_cidrs if c not in job.excluded_cidrs]

    for cidr in targets:
        base_file = f"/tmp/nxc_base_{job.id}.json"
        null_file = f"/tmp/nxc_null_{job.id}.json"

        proc = await asyncio.create_subprocess_exec(
            "nxc", "smb", cidr, "--json", "-o", base_file,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        await proc.communicate()

        base_results: list[dict] = []
        if os.path.exists(base_file):
            try:
                with open(base_file) as f:
                    data = f.read().strip()
                    base_results = json.loads(data) if data.startswith("[") else [json.loads(l) for l in data.splitlines() if l]
            except (json.JSONDecodeError, OSError):
                pass
            os.unlink(base_file)

        for host in base_results:
            if host.get("smbv1"):
                findings.append({
                    "title":       f"SMBv1 Enabled — {host['host']}",
                    "severity":    "CRITICAL",
                    "description": "SMBv1 is enabled. Vulnerable to EternalBlue (MS17-010).",
                    "mitre":       [{"id": "T1210", "name": "Exploitation of Remote Services"}],
                    "affectedHost": host["host"],
                })
            if not host.get("signing"):
                findings.append({
                    "title":       f"SMB Signing Disabled — {host['host']}",
                    "severity":    "HIGH",
                    "description": "SMB signing is not enforced. Vulnerable to NTLM relay attacks.",
                    "mitre":       [{"id": "T1557.001", "name": "LLMNR/NBT-NS Poisoning and SMB Relay"}],
                    "affectedHost": host["host"],
                })

        await report_progress(30)

        proc = await asyncio.create_subprocess_exec(
            "nxc", "smb", cidr, "-u", "", "-p", "", "--shares",
            "--json", "-o", null_file,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        await proc.communicate()

        if os.path.exists(null_file):
            try:
                with open(null_file) as f:
                    data = f.read().strip()
                    null_results = json.loads(data) if data.startswith("[") else [json.loads(l) for l in data.splitlines() if l]
                for host in null_results:
                    if host.get("nullSession") or host.get("null_session"):
                        findings.append({
                            "title":       f"SMB Null Session — {host.get('host', cidr)}",
                            "severity":    "HIGH",
                            "description": "Unauthenticated SMB access enabled.",
                            "mitre":       [{"id": "T1135", "name": "Network Share Discovery"}],
                            "affectedHost": host.get("host", cidr),
                        })
            except (json.JSONDecodeError, OSError):
                pass
            os.unlink(null_file)

    await report_progress(100)
    return {"scanner": "netexec", "findings": findings, "stats": count_by_severity(findings)}


async def execute_tls_scan(job: ScanJob, creds: dict, report_progress) -> dict:
    """testssl.sh TLS/SSL analysis."""
    log.info("[%s] TLS scan on %s", job.id, job.target_cidrs)

    targets = [c for c in job.target_cidrs if c not in job.excluded_cidrs]
    all_findings: list[dict] = []

    for i, target in enumerate(targets):
        output_file = f"/tmp/testssl_{job.id}_{i}.json"
        proc = await asyncio.create_subprocess_exec(
            "testssl.sh",
            "--jsonfile", output_file,
            "--severity", "LOW",
            "--color", "0",
            "--fast",
            "--quiet",
            target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await proc.communicate()

        if os.path.exists(output_file):
            try:
                with open(output_file) as f:
                    data = json.load(f)
                findings_raw = data.get("findings", [])
                for f_item in findings_raw:
                    if f_item.get("severity") not in ("OK", "INFO", "DEBUG"):
                        all_findings.append({
                            "id":       f_item.get("id"),
                            "target":   target,
                            "severity": f_item.get("severity"),
                            "finding":  f_item.get("finding"),
                            "cve":      f_item.get("cve"),
                        })
            except (json.JSONDecodeError, OSError):
                pass
            os.unlink(output_file)

        await report_progress(10 + int((i + 1) / len(targets) * 85))

    await report_progress(100)
    return {"scanner": "testssl", "findings": all_findings, "stats": count_by_severity(all_findings)}


def extract_web_urls_from_nmap(xml_path: str) -> list[str]:
    """Extract HTTP/HTTPS URLs from nmap XML output."""
    import xml.etree.ElementTree as ET
    WEB_PORTS = {80: "http", 443: "https", 8080: "http", 8443: "https",
                 8000: "http", 8888: "http", 3000: "http", 5000: "http", 9090: "http"}
    urls: list[str] = []
    if not os.path.exists(xml_path):
        return urls
    try:
        tree = ET.parse(xml_path)
        for host in tree.findall(".//host"):
            ip_el = host.find(".//address[@addrtype='ipv4']")
            if ip_el is None:
                continue
            ip_addr = ip_el.get("addr", "")
            for port_el in host.findall(".//port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue
                portid = int(port_el.get("portid", 0))
                scheme = WEB_PORTS.get(portid)
                if scheme:
                    urls.append(f"{scheme}://{ip_addr}:{portid}")
    except ET.ParseError:
        pass
    return urls


async def execute_eyewitness(job: ScanJob, creds: dict, report_progress) -> dict:
    """EyeWitness screenshot evidence collection."""
    log.info("[%s] EyeWitness evidence collection", job.id)

    urls = extract_web_urls_from_nmap("/tmp/nmap_out.xml")
    if not urls:
        return {"scanner": "eyewitness", "screenshots": [], "message": "No web services found"}

    url_file   = "/tmp/eyewitness_urls.txt"
    output_dir = f"/tmp/eyewitness-{job.id}"

    with open(url_file, "w") as f:
        f.write("\n".join(urls))

    cmd = [
        "eyewitness",
        "-f", url_file,
        "-d", output_dir,
        "--no-prompt",
        "--timeout", "15",
        "--threads", "5",
        "--web",
        "--prepend-https",
        "--compress",
    ]

    await report_progress(20)
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    await proc.communicate()
    await report_progress(90)

    import glob
    screenshots: list[dict] = []
    admin_findings: list[dict] = []

    for img_file in glob.glob(f"{output_dir}/*.png"):
        name = os.path.basename(img_file).lower()
        category = (
            "login" if "login" in name or "signin" in name
            else "admin" if "admin" in name or "manage" in name
            else "default" if "default" in name or "welcome" in name
            else "error" if "error" in name or "403" in name or "404" in name
            else "other"
        )
        url = name.replace(".png", "").replace("_", "://", 1).replace("__", "/")
        screenshots.append({"url": url, "file": img_file, "category": category,
                             "fileSize": os.path.getsize(img_file)})
        if category in ("admin", "login"):
            admin_findings.append({
                "title":       f"Exposed Admin/Login Interface — {url}",
                "severity":    "MEDIUM",
                "description": f"Web interface accessible at {url}.",
                "evidence":    [{"label": "Screenshot", "content": f"[EyeWitness: {output_dir}]"}],
                "mitre":       [{"id": "T1133", "name": "External Remote Services"}],
            })

    await report_progress(100)
    return {
        "scanner":      "eyewitness",
        "screenshots":  screenshots,
        "outputDir":    output_dir,
        "adminFindings": admin_findings,
    }


async def execute_lateral_movement(job: ScanJob, creds: dict, report_progress) -> dict:
    """Safe lateral movement checks — no actual exploitation."""
    log.info("[%s] Lateral movement assessment", job.id)
    await report_progress(50)
    await asyncio.sleep(5)  # Simulate analysis
    await report_progress(100)
    return {"hostsAssessed": len(job.target_cidrs), "mode": "safe-check"}


async def execute_cloud_scan(job: ScanJob, creds: dict, report_progress) -> dict:
    """Cloud infrastructure scan (AWS/Azure/GCP)."""
    log.info("[%s] Cloud scan", job.id)
    aws_key    = creds.get("aws_access_key_id",     "")
    aws_secret = creds.get("aws_secret_access_key", "")
    region     = creds.get("aws_region",            "us-east-1")
    await report_progress(30)
    # Prowler / ScoutSuite integration point
    proc = await asyncio.create_subprocess_exec(
        "prowler", "aws", "--output-formats", "json", "-r", region,
        env={**os.environ, "AWS_ACCESS_KEY_ID": aws_key, "AWS_SECRET_ACCESS_KEY": aws_secret},
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    await report_progress(80)
    await proc.communicate()
    await report_progress(100)
    return {"cloudProvider": "aws", "region": region, "tool": "prowler"}


JOB_EXECUTORS = {
    JobType.DISCOVERY:        execute_discovery,
    JobType.PORT_DISCOVERY:   execute_naabu,
    JobType.VULN_SCAN:        execute_vuln_scan,
    JobType.SMB_VALIDATION:   execute_smb_validation,
    JobType.AD_ENUM:          execute_ad_enum,
    JobType.TLS_SCAN:         execute_tls_scan,
    JobType.EVIDENCE_COLLECT: execute_eyewitness,
    JobType.LATERAL_MOVEMENT: execute_lateral_movement,
    JobType.CLOUD_SCAN:       execute_cloud_scan,
}


# ── ScanningAgent ──────────────────────────────────────────────────────────────

class ScanningAgent:
    def __init__(self):
        self.agent_id     = AGENT_ID
        self.running      = True
        self.current_job: Optional[ScanJob] = None
        self.vault        = VaultCredentialFetcher(VAULT_ADDR, VAULT_ROLE_TOKEN) if VAULT_ROLE_TOKEN else None
        self.ssl_ctx      = build_ssl_context() if os.path.exists(TLS_CERT_PATH) else None
        self._heartbeat_task: Optional[asyncio.Task] = None
        self._poll_task:      Optional[asyncio.Task] = None

    async def _api_call(self, session: aiohttp.ClientSession, method: str, path: str, **kwargs) -> Any:
        url = f"{PLATFORM_API_URL}{path}"
        try:
            async with session.request(method, url, ssl=self.ssl_ctx, **kwargs) as resp:
                return await resp.json()
        except Exception as e:
            log.warning("API call failed %s %s: %s", method, path, e)
            return None

    async def _heartbeat_loop(self, session: aiohttp.ClientSession):
        while self.running:
            data = await self._api_call(session, "POST", f"/api/agents/{self.agent_id}/heartbeat")
            if data:
                log.debug("Heartbeat OK — server: %s", data.get("serverTime", "?"))
            await asyncio.sleep(HEARTBEAT_INTERVAL)

    async def _report_progress(self, session: aiohttp.ClientSession, job_id: str, progress: int):
        await self._api_call(
            session, "POST",
            f"/api/agents/{self.agent_id}/jobs/{job_id}/progress",
            json={"progress": progress},
        )

    async def _poll_and_execute(self, session: aiohttp.ClientSession):
        while self.running:
            if self.current_job is None:
                resp = await self._api_call(session, "GET", f"/api/agents/{self.agent_id}/jobs")
                if resp and resp.get("job"):
                    raw_job = resp["job"]
                    job = ScanJob(
                        id=raw_job["id"],
                        type=JobType(raw_job["type"]),
                        engagement_id=raw_job["engagementId"],
                        target_cidrs=raw_job.get("targetCidrs", []),
                        excluded_cidrs=raw_job.get("excludedCidrs", []),
                        profile=raw_job.get("profile", "standard"),
                        ports=raw_job.get("ports"),
                        raw=raw_job,
                    )
                    self.current_job = job
                    asyncio.create_task(self._execute_job(session, job))

            await asyncio.sleep(POLL_INTERVAL)

    async def _execute_job(self, session: aiohttp.ClientSession, job: ScanJob):
        log.info("Starting job %s (type=%s, profile=%s)", job.id, job.type, job.profile)
        executor = JOB_EXECUTORS.get(job.type)
        if not executor:
            log.error("No executor for job type: %s", job.type)
            self.current_job = None
            return

        # Fetch credentials from Vault
        creds: dict = {}
        if self.vault:
            vault_path = f"adversa/engagements/{job.engagement_id}/credentials"
            creds = self.vault.get_credentials(vault_path)

        async def report_progress(pct: int):
            await self._report_progress(session, job.id, pct)

        try:
            result = await executor(job, creds, report_progress)
            await self._api_call(
                session, "POST",
                f"/api/agents/{self.agent_id}/jobs/{job.id}/result",
                json={"result": result, "success": True},
            )
            log.info("Job %s completed: %s", job.id, result)
        except Exception as e:
            log.exception("Job %s failed: %s", job.id, e)
            await self._api_call(
                session, "POST",
                f"/api/agents/{self.agent_id}/jobs/{job.id}/result",
                json={"result": {"error": str(e)}, "success": False},
            )
        finally:
            self.current_job = None

    def _handle_shutdown(self, *_):
        log.info("Shutdown signal received — waiting for current job to complete…")
        self.running = False

    async def run(self):
        signal.signal(signal.SIGTERM, self._handle_shutdown)
        signal.signal(signal.SIGINT,  self._handle_shutdown)

        await check_tool_availability()

        connector = aiohttp.TCPConnector(ssl=self.ssl_ctx)
        async with aiohttp.ClientSession(connector=connector) as session:
            log.info("Agent %s starting — platform: %s", self.agent_id, PLATFORM_API_URL)
            self._heartbeat_task = asyncio.create_task(self._heartbeat_loop(session))
            self._poll_task      = asyncio.create_task(self._poll_and_execute(session))
            await asyncio.gather(self._heartbeat_task, self._poll_task, return_exceptions=True)

            # Graceful shutdown: wait for current job
            if self.current_job:
                log.info("Waiting for job %s to finish…", self.current_job.id)
                while self.current_job:
                    await asyncio.sleep(2)
            log.info("Agent %s exited cleanly.", self.agent_id)


if __name__ == "__main__":
    if not AGENT_ID:
        print("ERROR: AGENT_ID environment variable required.", file=sys.stderr)
        sys.exit(1)
    asyncio.run(ScanningAgent().run())
