"""Unit tests for ServiceIdentifier."""
import pytest
from app.discovery.service_id import ServiceIdentifier


class TestServiceIdentifier:
    def setup_method(self):
        self.si = ServiceIdentifier()

    def _id(self, banner, port):
        return self.si.identify(banner, port)

    def test_ssh_banner(self):
        fp = self._id("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.3", 22)
        assert fp.service == "ssh"
        assert fp.confidence_score >= 0.7
        assert "OpenSSH" in fp.product or fp.version

    def test_http_server_header(self):
        fp = self._id("HTTP/1.1 200 OK\r\nServer: Apache/2.4.54\r\n", 80)
        assert fp.service == "http"
        assert fp.confidence_score >= 0.7

    def test_smtp_banner(self):
        fp = self._id("220 mail.corp.local ESMTP Postfix", 25)
        assert fp.service == "smtp"

    def test_ftp_banner(self):
        fp = self._id("220 ProFTPD 1.3.7b Server (corp FTP) [10.0.0.5]", 21)
        assert fp.service == "ftp"

    def test_smb_detection(self):
        fp = self._id("NTLMSSP\x00\x01\x00\x00\x00", 445)
        assert fp.service == "smb"

    def test_mysql_banner(self):
        fp = self._id("\x4a\x00\x00\x00\x0a5.7.39-log\x00mysql_native_password", 3306)
        assert fp.service == "mysql"

    def test_redis_pong(self):
        fp = self._id("+PONG\r\n", 6379)
        assert fp.service == "redis"

    def test_mssql_banner(self):
        fp = self._id("Microsoft SQL Server 2019 RTM", 1433)
        assert fp.service == "mssql"

    def test_kerberos_banner(self):
        fp = self._id("KRB5 Kerberos", 88)
        assert fp.service == "kerberos"

    def test_ldap_banner(self):
        fp = self._id("\x30\x0c\x02\x01\x01\x61\x07\x0a\x01\x00ldap", 389)
        assert fp.service == "ldap"

    def test_rdp_port_hint(self):
        fp = self._id("", 3389)
        assert fp.service == "rdp"
        assert fp.confidence_score == pytest.approx(0.3)

    def test_version_extraction(self):
        fp = self._id("SSH-2.0-OpenSSH_9.1p1", 22)
        assert "9.1" in fp.version or "2.0" in fp.version

    def test_unknown_service_empty_banner(self):
        fp = self._id("", 9999)
        assert fp.service == "unknown"
        assert fp.confidence_score == 0.0

    def test_confidence_floor_port_hint(self):
        fp = self._id("garbage banner xyz", 80)
        assert fp.service == "http"
        assert fp.confidence_score >= 0.3

    def test_high_confidence_combined(self):
        fp = self._id("SSH-2.0-OpenSSH_8.4p1", 22)
        assert fp.confidence_score >= 0.9
