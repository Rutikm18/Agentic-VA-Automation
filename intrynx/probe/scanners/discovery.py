"""Host & service discovery via nmap (-sV).

After nmap finishes, ports that nmap couldn't identify (product=None, service
from the port DB such as "ppp"/"rtsp") receive a quick HTTP HEAD probe so
web services on non-standard ports get a meaningful label in results.
"""
from __future__ import annotations

import http.client
import re
import socket
import subprocess
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from .base import normalize_targets, now, result, run_cmd, scanner

# --version-intensity 7: probes more aggressively than the default (5) to help
# nmap identify non-standard services.  --script=banner grabs raw greeting text
# (e.g. MySQL handshake) for services nmap still can't match.
NMAP_DEFAULT_ARGS = "-sV --version-intensity 7 -T4 -Pn --script=banner"

# Service names that nmap returns from its port→name DB when version detection
# fails — these are port-numbering conventions, not real service IDs.
_DB_FALLBACK_SERVICES = frozenset({
    "ppp", "rtsp", "zope", "afs3-fileserver", "ipp", "vnc-1",
    "unknown", "tcpwrapped", "ssl", "",
})


def parse_nmap_xml(xml_text: str, include_states: tuple[str, ...] = ("open",)) -> list[dict[str, Any]]:
    """Parse ``nmap -oX -`` output into a normalized host list.

    Returns ``[{ip, hostname, mac, vendor, os, os_accuracy,
                ports:[{port, protocol, state, service, product, version,
                        extrainfo, tunnel, cpe:[...], banner, http_title}]}]``.

    ``include_states`` selects which port states to keep (default: only ``open``;
    pass ``("open", "open|filtered")`` for UDP scans where filtered is common).
    Malformed XML returns ``[]`` rather than raising.
    """
    hosts: list[dict[str, Any]] = []
    if not xml_text.strip():
        return hosts
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return hosts

    for host in root.findall("host"):
        st = host.find("status")
        if st is not None and st.get("state") != "up":
            continue
        ip = mac = vendor = None
        for addr in host.findall("address"):
            atype = addr.get("addrtype")
            if atype in ("ipv4", "ipv6"):
                ip = addr.get("addr")
            elif atype == "mac":
                mac = addr.get("addr")
                vendor = addr.get("vendor")
        hn = host.find("hostnames/hostname")
        os_el = host.find("os/osmatch")
        ports = []
        for p in host.findall("ports/port"):
            pst = p.find("state")
            state = pst.get("state") if pst is not None else None
            if state not in include_states:
                continue
            svc = p.find("service")
            cpes = [c.text for c in p.findall("service/cpe") if c.text] if svc is not None else []

            # NSE script outputs: banner (raw greeting) and http-title (HTTP page title).
            # Note: http-title only fires if nmap recognises the port as HTTP; for
            # ports labelled "ppp"/"rtsp" etc. by the DB we rely on banner + the
            # HTTP fallback probe below.
            banner = None
            http_title = None
            for script in p.findall("script"):
                sid = script.get("id", "")
                if sid == "banner":
                    raw = (script.get("output") or "").strip()
                    banner = "".join(c if c.isprintable() else "." for c in raw)[:200] or None
                elif sid == "http-title":
                    http_title = (script.get("output") or "").strip() or None

            svc_name = svc.get("name") if svc is not None else None
            product = svc.get("product") if svc is not None else None
            # Promote http-title to product when nmap didn't match a product.
            if http_title and not product:
                product = f"HTTP: {http_title}"
            ports.append({
                "port": int(p.get("portid")),
                "protocol": p.get("protocol"),
                "state": state,
                "service": svc_name,
                "product": product,
                "version": svc.get("version") if svc is not None else None,
                "extrainfo": svc.get("extrainfo") if svc is not None else None,
                "tunnel": svc.get("tunnel") if svc is not None else None,  # e.g. "ssl"
                "cpe": cpes,
                "banner": banner,
                "http_title": http_title,
            })
        hosts.append({
            "ip": ip,
            "hostname": hn.get("name") if hn is not None else None,
            "mac": mac,
            "vendor": vendor,
            "os": os_el.get("name") if os_el is not None else None,
            "os_accuracy": int(os_el.get("accuracy")) if (os_el is not None and os_el.get("accuracy")) else None,
            "ports": ports,
        })
    return hosts


_TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.I | re.S)


def _http_probe(host: str, port: int, timeout: float = 3.0) -> str | None:
    """HTTP probe (GET /) to identify services that nmap couldn't fingerprint.

    Returns a label like 'http/200 (Next.js) "ADVERSA — Ops Platform"' or None.
    Uses only stdlib — no external deps.
    """
    import re as _re
    for scheme_cls, scheme in ((http.client.HTTPConnection, "http"),
                                (http.client.HTTPSConnection, "https")):
        try:
            conn = scheme_cls(host, port, timeout=timeout)
            # GET to capture the page body for title extraction; cap at 8 KB.
            conn.request("GET", "/", headers={
                "User-Agent": "intrynx-probe/1.0",
                "Accept": "text/html,*/*",
                "Connection": "close",
            })
            r = conn.getresponse()
            body = r.read(8192)
            conn.close()

            server = (r.getheader("Server") or "").strip()
            label = f"{scheme}/{r.status}"
            if server:
                label += f" ({server[:40]})"

            # Extract <title> from HTML body for a human-readable service label.
            m = _TITLE_RE.search(body)
            if m:
                title = m.group(1).decode("utf-8", errors="replace").strip()[:60]
                title = " ".join(title.split())  # collapse whitespace
                if title:
                    label += f' "{title}"'
            return label
        except Exception:
            continue
    return None


def _enrich_unidentified(hosts: list[dict[str, Any]], timeout: float = 3.0) -> None:
    """For TCP ports nmap couldn't identify, try a quick HTTP HEAD probe.

    Mutates hosts in-place — sets port["product"] when HTTP responds.
    Uses a thread pool so a /24 scan doesn't take minutes here.
    """
    work: list[tuple[dict, dict]] = []   # (host_dict, port_dict) pairs to probe
    for h in hosts:
        if not h.get("ip"):
            continue
        for p in h.get("ports", []):
            if (p.get("protocol") == "tcp"
                    and p.get("product") is None
                    and (p.get("service") or "") in _DB_FALLBACK_SERVICES):
                work.append((h, p))

    if not work:
        return

    try:
        import probe_logger
        probe_logger.log_note(f"http fallback probe on {len(work)} unidentified port(s)",
                              ports=[f"{h['ip']}:{p['port']}" for h, p in work[:10]])
    except ImportError:
        pass

    def _probe(h: dict, p: dict) -> tuple[dict, str | None]:
        return p, _http_probe(h["ip"], p["port"], timeout=timeout)

    with ThreadPoolExecutor(max_workers=min(len(work), 20)) as pool:
        futs = {pool.submit(_probe, h, p): (h, p) for h, p in work}
        for fut in as_completed(futs):
            try:
                port_dict, label = fut.result()
                if label:
                    port_dict["product"] = label
                    port_dict["service"] = "http"
            except Exception:
                pass


@scanner("discovery", "nmap", "Host & service discovery — open ports, service + version")
def discovery(params: dict) -> dict:
    targets = normalize_targets(params)
    if not targets:
        return result("discovery", "nmap", [], ok=False, error="no targets provided")
    started = now()
    cmd = ["nmap", *str(params.get("args", NMAP_DEFAULT_ARGS)).split(), "-oX", "-"]
    if params.get("ports"):
        cmd += ["-p", str(params["ports"])]
    host_timeout = params.get("host_timeout", "120s")
    if host_timeout and "--host-timeout" not in cmd:
        cmd += ["--host-timeout", str(host_timeout)]
    cmd += targets
    try:
        proc = run_cmd(cmd, timeout=int(params.get("timeout", 1800)))
    except subprocess.TimeoutExpired:
        return result("discovery", "nmap", targets, ok=False, error="nmap timed out", started=started)
    if proc.returncode != 0 and not proc.stdout:
        return result("discovery", "nmap", targets, ok=False,
                      error=f"nmap failed: {proc.stderr[:300]}", started=started)
    hosts = parse_nmap_xml(proc.stdout)

    # Enrich unidentified ports with a quick HTTP probe (no external tools).
    if params.get("http_fallback", True):
        _enrich_unidentified(hosts, timeout=float(params.get("http_fallback_timeout", 3.0)))

    return result("discovery", "nmap", targets, hosts=hosts, host_count=len(hosts), started=started)
