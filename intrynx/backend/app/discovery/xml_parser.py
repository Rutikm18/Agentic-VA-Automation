"""
Nmap XML output parser.
Converts -oX output into structured ParsedHost / ParsedPort objects.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ParsedPort:
    port: int
    protocol: str
    state: str
    service: str = ""
    product: str = ""
    version: str = ""
    extra_info: str = ""
    cpe: str = ""


@dataclass
class ParsedHost:
    ip: str
    hostname: str = ""
    fqdn: str = ""
    state: str = "unknown"
    os: str = ""
    os_accuracy: int = 0
    mac_address: str = ""
    mac_vendor: str = ""
    ports: list[ParsedPort] = field(default_factory=list)

    @property
    def open_ports(self) -> list[ParsedPort]:
        return [p for p in self.ports if p.state == "open"]


class NmapXMLParser:
    """Parse nmap -oX XML into a list of ParsedHost objects."""

    def parse(self, xml_text: str) -> list[ParsedHost]:
        if not xml_text or not xml_text.strip():
            return []
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError:
            return []
        return [self._parse_host(h) for h in root.findall("host")]

    def _parse_host(self, host_el: ET.Element) -> ParsedHost:
        # State
        status = host_el.find("status")
        state = status.get("state", "unknown") if status is not None else "unknown"

        # Addresses
        ip = mac = mac_vendor = ""
        for addr in host_el.findall("address"):
            atype = addr.get("addrtype", "")
            if atype == "ipv4":
                ip = addr.get("addr", "")
            elif atype == "mac":
                mac = addr.get("addr", "")
                mac_vendor = addr.get("vendor", "")

        # Hostnames
        hostname = fqdn = ""
        names_el = host_el.find("hostnames")
        if names_el is not None:
            for hn in names_el.findall("hostname"):
                ht = hn.get("type", "")
                val = hn.get("name", "")
                if ht == "PTR":
                    hostname = val
                elif ht == "user":
                    fqdn = val
                if not hostname:
                    hostname = val

        # OS detection
        os_name = ""
        os_acc = 0
        os_el = host_el.find("os")
        if os_el is not None:
            best = None
            for osm in os_el.findall("osmatch"):
                acc = int(osm.get("accuracy", 0))
                if acc > os_acc:
                    os_acc = acc
                    best = osm
            if best is not None:
                os_name = best.get("name", "")

        # Ports
        ports = []
        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                ports.append(self._parse_port(port_el))

        return ParsedHost(
            ip=ip,
            hostname=hostname,
            fqdn=fqdn,
            state=state,
            os=os_name,
            os_accuracy=os_acc,
            mac_address=mac,
            mac_vendor=mac_vendor,
            ports=ports,
        )

    def _parse_port(self, port_el: ET.Element) -> ParsedPort:
        port_num = int(port_el.get("portid", 0))
        proto = port_el.get("protocol", "tcp")

        state_el = port_el.find("state")
        state = state_el.get("state", "unknown") if state_el is not None else "unknown"

        svc_el = port_el.find("service")
        service = product = version = extra = cpe_val = ""
        if svc_el is not None:
            service = svc_el.get("name", "")
            product = svc_el.get("product", "")
            version = svc_el.get("version", "")
            extra = svc_el.get("extrainfo", "")
            cpe_el = svc_el.find("cpe")
            if cpe_el is not None and cpe_el.text:
                cpe_val = cpe_el.text.strip()

        return ParsedPort(
            port=port_num,
            protocol=proto,
            state=state,
            service=service,
            product=product,
            version=version,
            extra_info=extra,
            cpe=cpe_val,
        )
