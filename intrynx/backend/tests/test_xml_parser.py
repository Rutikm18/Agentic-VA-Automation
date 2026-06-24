"""Unit tests for NmapXMLParser."""
import pytest
from app.discovery.xml_parser import NmapXMLParser

FULL_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="10.10.10.5" addrtype="ipv4"/>
    <address addr="00:0C:29:AB:CD:EF" addrtype="mac" vendor="VMware"/>
    <hostnames>
      <hostname name="dc01.corp.local" type="PTR"/>
      <hostname name="dc01" type="user"/>
    </hostnames>
    <os>
      <osmatch name="Windows Server 2019" accuracy="95"/>
      <osmatch name="Windows Server 2022" accuracy="80"/>
    </os>
    <ports>
      <port portid="445" protocol="tcp">
        <state state="open"/>
        <service name="microsoft-ds" product="Microsoft Windows SMB" version=""/>
      </port>
      <port portid="88" protocol="tcp">
        <state state="open"/>
        <service name="kerberos-sec" product="Microsoft Windows Kerberos">
          <cpe>cpe:/a:microsoft:windows</cpe>
        </service>
      </port>
      <port portid="3389" protocol="tcp">
        <state state="closed"/>
        <service name="rdp"/>
      </port>
    </ports>
  </host>
</nmaprun>"""

EMPTY_XML = """<?xml version="1.0"?><nmaprun></nmaprun>"""
MALFORMED_XML = "this is not xml <<<"


class TestNmapXMLParser:
    def setup_method(self):
        self.parser = NmapXMLParser()

    def test_parse_full_host(self):
        hosts = self.parser.parse(FULL_XML)
        assert len(hosts) == 1
        h = hosts[0]
        assert h.ip == "10.10.10.5"
        assert h.hostname == "dc01.corp.local"
        assert h.fqdn == "dc01"
        assert h.state == "up"
        assert h.os == "Windows Server 2019"
        assert h.os_accuracy == 95
        assert h.mac_address == "00:0C:29:AB:CD:EF"
        assert h.mac_vendor == "VMware"

    def test_open_ports_only(self):
        hosts = self.parser.parse(FULL_XML)
        open_ports = hosts[0].open_ports
        assert len(open_ports) == 2
        assert {p.port for p in open_ports} == {445, 88}

    def test_port_details(self):
        hosts = self.parser.parse(FULL_XML)
        smb = next(p for p in hosts[0].open_ports if p.port == 445)
        assert smb.protocol == "tcp"
        assert smb.service == "microsoft-ds"

    def test_cpe_extraction(self):
        hosts = self.parser.parse(FULL_XML)
        kerb = next(p for p in hosts[0].open_ports if p.port == 88)
        assert kerb.cpe == "cpe:/a:microsoft:windows"

    def test_empty_scan(self):
        hosts = self.parser.parse(EMPTY_XML)
        assert hosts == []

    def test_malformed_xml_returns_empty(self):
        hosts = self.parser.parse(MALFORMED_XML)
        assert hosts == []

    def test_empty_string(self):
        assert self.parser.parse("") == []

    def test_none_safe(self):
        assert self.parser.parse(None) == []

    def test_multiple_hosts(self):
        xml = """<nmaprun>
          <host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/><ports/></host>
          <host><status state="down"/><address addr="10.0.0.2" addrtype="ipv4"/><ports/></host>
        </nmaprun>"""
        hosts = self.parser.parse(xml)
        assert len(hosts) == 2
        assert hosts[0].ip == "10.0.0.1"
        assert hosts[1].state == "down"
