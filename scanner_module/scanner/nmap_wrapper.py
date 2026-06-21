"""
nmap_wrapper.py — orchestrate nmap and normalize its XML into ScanResult.

WHY: nmap is 25+ years of battle-tested scanning. For discovery, SYN scanning
(root), service/version detection (-sV), OS detection (-O), and protocol checks
(NSE), wrapping it is the right call — do not reimplement it. This module runs
nmap as a subprocess and parses its XML so its findings land in the SAME schema
as the pure-Python scanners, letting you compare accuracy/FP between engines.

LICENSING NOTE: nmap is distributed under the Nmap Public Source License
(GPLv2-derived). Redistributing nmap inside a commercial product can trigger
licensing obligations — review before bundling. Here we INVOKE an nmap that is
already installed on the system rather than shipping it.

COLLECTION ONLY: we run discovery/version/OS/safe NSE categories. We do NOT run
exploit/intrusive NSE scripts.
"""

from __future__ import annotations

import argparse
import asyncio
import shutil
import subprocess
import xml.etree.ElementTree as ET

from .scanner_base import (
    ScanResult, ScopeGuard, ResultWriter, expand_targets,
    setup_logging, base_argparser, LOG, main_entrypoint,
)

# Scan profiles. Note: -sS (SYN) and -O (OS) require root; -sT/-sV do not.
PROFILES = {
    "discovery": ["-sn", "-PR", "-PE", "-PS80,443", "-PA80"],
    "version":   ["-sT", "-sV", "--version-intensity", "5"],
    "os":        ["-sT", "-O"],
    "smb":       ["-p", "139,445", "--script", "smb-protocols,smb2-security-mode"],
    "fast":      ["-sT", "-F"],
}


def _have_nmap() -> bool:
    return shutil.which("nmap") is not None


def _run_nmap(targets: list[str], extra: list[str], timeout: int) -> str | None:
    cmd = ["nmap", "-oX", "-", "-n", *extra, *targets]
    LOG.info("running: %s", " ".join(cmd))
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout)
    except subprocess.TimeoutExpired:
        LOG.error("nmap timed out")
        return None
    except FileNotFoundError:
        LOG.error("nmap not found on PATH")
        return None
    if proc.returncode not in (0, 1):
        LOG.warning("nmap returned %d: %s", proc.returncode, proc.stderr[:200])
    return proc.stdout


def _parse_nmap_xml(xml_text: str, profile: str) -> list[ScanResult]:
    results: list[ScanResult] = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        LOG.error("failed to parse nmap xml: %s", exc)
        return results

    for host in root.findall("host"):
        # NOTE: `Element.find(...) or Element.find(...)` is a classic ElementTree
        # trap — an Element with no children is falsy even when found (it tests
        # len(), not identity), so the first match would be silently discarded.
        # Explicit `is not None` checks avoid that.
        addr_el = host.find("address[@addrtype='ipv4']")
        if addr_el is None:
            addr_el = host.find("address")
        addr = addr_el.get("addr") if addr_el is not None else "?"

        status_el = host.find("status")
        host_state = status_el.get("state") if status_el is not None else "unknown"

        # Host-level (discovery / OS) result.
        if profile in ("discovery", "os"):
            data = {"host_state": host_state}
            os_el = host.find("os")
            if os_el is not None:
                matches = [{"name": m.get("name"), "accuracy": m.get("accuracy")}
                           for m in os_el.findall("osmatch")]
                if matches:
                    data["os_matches"] = matches[:3]
            results.append(ScanResult(
                "nmap_" + profile, addr,
                status="open" if host_state == "up" else "filtered",
                data=data, evidence=f"host {host_state}"))

        # Port-level results.
        for port in host.findall(".//port"):
            portid = int(port.get("portid"))
            proto = port.get("protocol")
            st = port.find("state")
            state = st.get("state") if st is not None else "unknown"
            svc = port.find("service")
            data = {}
            evidence = state
            if svc is not None:
                data = {
                    "service": svc.get("name"),
                    "product": svc.get("product"),
                    "version": svc.get("version"),
                    "extrainfo": svc.get("extrainfo"),
                    "cpe": [c.text for c in svc.findall("cpe")],
                }
                evidence = " ".join(filter(None, [
                    svc.get("name"), svc.get("product"), svc.get("version")]))
            # NSE script output (e.g. smb-protocols).
            scripts = {s.get("id"): s.get("output") for s in port.findall("script")}
            if scripts:
                data["scripts"] = scripts
            if state == "open" or profile == "smb":
                results.append(ScanResult(
                    "nmap_" + profile, addr, port=portid, proto=proto,
                    status=state, data=data, evidence=evidence))
    return results


def main() -> None:
    parser = base_argparser("nmap orchestrator (discovery/version/os/smb)")
    parser.add_argument("--profile", choices=list(PROFILES.keys()),
                        default="version", help="nmap scan profile")
    parser.add_argument("--nmap-timeout", type=int, default=900,
                        help="overall nmap subprocess timeout (s)")
    parser.add_argument("--extra-args", default="",
                        help="extra raw nmap args (advanced)")
    args = parser.parse_args()
    setup_logging(args.verbose)

    def _run() -> None:
        if not _have_nmap():
            LOG.error("nmap is not installed. Install nmap or use the pure-Python "
                      "scanners (port_scanner.py, service_banner.py, ...).")
            return

        scope = ScopeGuard.from_file(args.scope)
        targets = [t for t in expand_targets(args.targets) if scope.in_scope(t)]
        if not targets:
            LOG.error("no in-scope targets")
            return

        extra = list(PROFILES[args.profile])
        if args.extra_args:
            extra += args.extra_args.split()

        xml_text = _run_nmap(targets, extra, args.nmap_timeout)
        if not xml_text:
            return
        results = _parse_nmap_xml(xml_text, args.profile)

        writer = ResultWriter(args.output, also_stdout=True)
        try:
            for r in results:
                writer.write(r)
        finally:
            writer.close()
        LOG.info("nmap_%s done — %d result(s)", args.profile, writer.count)

    main_entrypoint(_run)


if __name__ == "__main__":
    main()
