"""Deep service / installed-server fingerprinting via nmap ``-sV``.

Where ``discovery`` does a quick ``-sV`` pass, this runs **aggressive version
detection** (``--version-all``) and turns the raw banners into an *installed-server
inventory*: every detected product is mapped to a server category (web / database /
cache / mail / directory / message-queue / remote-access / virtualization /
monitoring / ci-cd / ai-ml / …) and its **CPE** is surfaced so the manager can
correlate CVEs server-side.

Optional knobs (job ``params``):
  ports        port spec (default: nmap top-1000)
  os_detect    add ``-O`` for OS fingerprinting (needs raw sockets / root)
  scripts      add ``-sC`` (default NSE scripts) for extra service detail
  intensity    ``--version-intensity`` 0–9 (default 7)
"""
from __future__ import annotations

import subprocess
from typing import Any

from .base import normalize_targets, now, result, run_cmd, scanner
from .discovery import parse_nmap_xml

# Server taxonomy — ordered most-specific → most-generic; first hit wins.
# Each entry: (category, [keywords matched against service+product+cpe+extrainfo]).
_CATEGORIES: list[tuple[str, list[str]]] = [
    ("ai-ml", ["ollama", "triton", "tensorflow", "torchserve", "kserve", "mlflow",
               "jupyter", "ray", "kubeflow", "vllm", "llama", "comfyui", "gradio"]),
    ("database", ["mysql", "mariadb", "postgresql", "postgres", "mongodb", "oracle",
                  "microsoft sql server", "ms-sql", "mssql", "cassandra", "elasticsearch",
                  "couchdb", "influxdb", "neo4j", "clickhouse", "cockroach", "db2",
                  "sybase", "firebird", "rethinkdb"]),
    ("cache", ["redis", "memcached", "hazelcast", "aerospike"]),
    ("message-queue", ["rabbitmq", "amqp", "kafka", "activemq", "mosquitto", "mqtt",
                       "nats", "zeromq", "stomp", "pulsar"]),
    ("mail", ["postfix", "exim", "sendmail", "dovecot", "courier", "exchange",
              "smtp", "imap", "pop3", "zimbra"]),
    ("directory", ["ldap", "active directory", "openldap", "kerberos", "freeipa"]),
    ("remote-access", ["ssh", "openssh", "rdp", "ms-wbt-server", "vnc", "telnet",
                       "teamviewer", "winrm", "anydesk", "x11"]),
    ("file-sharing", ["smb", "samba", "netbios", "microsoft-ds", "nfs", "ftp",
                      "vsftpd", "proftpd", "pure-ftpd", "tftp", "rsync", "webdav"]),
    ("dns", ["bind", "dnsmasq", "powerdns", "unbound", "domain"]),
    ("virtualization", ["vmware", "esxi", "vcenter", "proxmox", "docker", "kubelet",
                        "kubernetes", "etcd", "hyper-v", "xen", "libvirt"]),
    ("monitoring", ["prometheus", "grafana", "zabbix", "nagios", "splunk", "kibana",
                    "graylog", "datadog", "telegraf", "node_exporter"]),
    ("ci-cd", ["jenkins", "gitlab", "gitea", "gerrit", "sonarqube", "nexus",
               "artifactory", "teamcity", "bamboo", "argocd"]),
    ("app-server", ["tomcat", "jboss", "wildfly", "weblogic", "websphere",
                    "glassfish", "gunicorn", "uvicorn", "kestrel", "passenger"]),
    ("web-server", ["nginx", "apache", "httpd", "iis", "lighttpd", "caddy", "openresty",
                    "traefik", "haproxy", "envoy", "http", "https", "litespeed"]),
    ("voip", ["asterisk", "sip", "freeswitch", "rtp"]),
    ("industrial", ["modbus", "s7", "bacnet", "dnp3", "ethernet/ip", "scada"]),
]


def categorize(port: dict[str, Any]) -> str | None:
    """Map a parsed nmap port record to a server category, or None if unknown."""
    haystack = " ".join(str(x).lower() for x in (
        port.get("service"), port.get("product"), port.get("extrainfo"),
        *(port.get("cpe") or []),
    ) if x)
    if not haystack.strip():
        return None
    for category, keywords in _CATEGORIES:
        if any(kw in haystack for kw in keywords):
            return category
    return None


def build_inventory(hosts: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate detected products into an installed-server inventory.

    Returns ``{servers:[{host, port, category, product, version, cpe}],
               by_category:{cat: n}, software:{"product version": n}}``.
    """
    servers: list[dict[str, Any]] = []
    by_category: dict[str, int] = {}
    software: dict[str, int] = {}
    for h in hosts:
        for p in h.get("ports", []):
            category = categorize(p)
            product = p.get("product")
            if not category and not product:
                continue  # nothing identifiable on this port
            rec = {
                "host": h.get("ip") or h.get("hostname"),
                "port": p.get("port"),
                "protocol": p.get("protocol"),
                "category": category,
                "service": p.get("service"),
                "product": product,
                "version": p.get("version"),
                "cpe": p.get("cpe") or [],
            }
            servers.append(rec)
            if category:
                by_category[category] = by_category.get(category, 0) + 1
            if product:
                key = f"{product} {p.get('version')}".strip() if p.get("version") else product
                software[key] = software.get(key, 0) + 1
    return {"servers": servers, "by_category": by_category, "software": software}


@scanner("service_fingerprint", "nmap",
         "Installed-server inventory — product, version, CPE, category")
def service_fingerprint(params: dict) -> dict:
    targets = normalize_targets(params)
    if not targets:
        return result("service_fingerprint", "nmap", [], ok=False, error="no targets provided")
    started = now()
    cmd = ["nmap", "-sV", "--version-all",
           "--version-intensity", str(params.get("intensity", 7)),
           "-Pn", "-T4", "-oX", "-"]
    if params.get("os_detect"):
        cmd.append("-O")
    if params.get("scripts"):
        cmd.append("-sC")
    if params.get("ports"):
        cmd += ["-p", str(params["ports"])]
    cmd += str(params.get("args", "")).split()
    # Bound per-host time so a range still returns the live hosts (set "" to disable).
    host_timeout = params.get("host_timeout", "180s")
    if host_timeout and "--host-timeout" not in cmd:
        cmd += ["--host-timeout", str(host_timeout)]
    cmd += targets
    try:
        proc = run_cmd(cmd, timeout=int(params.get("timeout", 2400)))
    except subprocess.TimeoutExpired:
        return result("service_fingerprint", "nmap", targets, ok=False,
                      error="nmap timed out", started=started)
    if proc.returncode != 0 and not proc.stdout:
        return result("service_fingerprint", "nmap", targets, ok=False,
                      error=f"nmap failed: {proc.stderr[:300]}", started=started)
    hosts = parse_nmap_xml(proc.stdout)
    inv = build_inventory(hosts)
    return result("service_fingerprint", "nmap", targets,
                  hosts=hosts, host_count=len(hosts),
                  servers=inv["servers"], server_count=len(inv["servers"]),
                  by_category=inv["by_category"], software=inv["software"],
                  started=started)
