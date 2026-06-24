"""
LDAPEnumerator — read-only Active Directory enumeration over LDAP/LDAPS.

Uses ldap3 for the bind + searches. ldap3 is an optional dependency: if it is
not installed the class still imports cleanly and ``connect`` raises a typed
``DependencyMissingError`` so the API layer can return a clean 503 instead of an
ImportError 500.

Everything here is read-only — we never write to the directory. Security
descriptor (ACL) parsing for ACE abuse detection is best-effort: when impacket's
``ldaptypes`` is available we decode the raw ``nTSecurityDescriptor`` blob,
otherwise ``get_aces`` returns an empty list and logs a hint.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

from app.ad.findings import (
    DC_PRIMARY_GROUP_IDS,
    PRIVILEGED_GROUPS,
    UAC_DONT_REQ_PREAUTH,
    UAC_SERVER_TRUST_ACCOUNT,
    UAC_TRUSTED_FOR_DELEGATION,
    ADConnectionError,
    DependencyMissingError,
)

logger = structlog.get_logger()

try:
    import ldap3
    from ldap3 import ALL, NTLM, SUBTREE, Connection, Server
    from ldap3.core.exceptions import LDAPException

    _HAS_LDAP3 = True
except ImportError:  # pragma: no cover - exercised only without ldap3 installed
    ldap3 = None  # type: ignore
    _HAS_LDAP3 = False
    LDAPException = Exception  # type: ignore

try:
    from impacket.ldap import ldaptypes  # type: ignore

    _HAS_LDAPTYPES = True
except ImportError:  # pragma: no cover
    ldaptypes = None  # type: ignore
    _HAS_LDAPTYPES = False


# ── Result objects ─────────────────────────────────────────────────────────────

@dataclass
class ADUser:
    samaccountname: str
    sid: str | None = None
    memberof: list[str] = field(default_factory=list)
    spn: list[str] = field(default_factory=list)
    no_preauth: bool = False
    admin_count: bool = False
    enabled: bool = True
    dn: str | None = None


@dataclass
class ADComputer:
    hostname: str
    os: str | None = None
    ip: str | None = None
    is_dc: bool = False
    dn: str | None = None


@dataclass
class ADGroup:
    name: str
    members: list[str] = field(default_factory=list)
    is_privileged: bool = False
    dn: str | None = None


@dataclass
class ACE:
    """A simplified access-control entry parsed from nTSecurityDescriptor."""
    trustee_sid: str
    ace_type: str          # "ALLOW" | "DENY"
    rights: list[str] = field(default_factory=list)
    object_type: str | None = None
    inherited: bool = False


# Mapped subset of ACCESS_MASK bits we care about for ACL abuse.
_ACCESS_RIGHTS: list[tuple[int, str]] = [
    (0x10000000, "GenericAll"),
    (0x40000000, "GenericWrite"),
    (0x00040000, "WriteDacl"),
    (0x00080000, "WriteOwner"),
    (0x00000020, "WriteProperty"),
    (0x00000100, "ExtendedRight"),  # covers DCSync / ForceChangePassword
]


def _domain_to_base_dn(domain: str) -> str:
    """corp.local -> DC=corp,DC=local"""
    return ",".join(f"DC={part}" for part in domain.split(".") if part)


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value]
    return [str(value)]


class LDAPEnumerator:
    """Read-only AD enumeration. One instance == one bound connection."""

    def __init__(self) -> None:
        self._conn: Any = None
        self._base_dn: str | None = None
        self._domain: str | None = None

    # ── connect ────────────────────────────────────────────────────────────────

    def connect(
        self,
        dc_ip: str,
        domain: str,
        username: str,
        password: str,
        use_kerberos: bool = False,
        use_ssl: bool = False,
        port: int | None = None,
    ) -> "LDAPEnumerator":
        """
        Bind to the domain controller. Returns self for chaining.

        Raises DependencyMissingError if ldap3 is unavailable and
        ADConnectionError on bind failure.
        """
        if not _HAS_LDAP3:
            raise DependencyMissingError(
                "ldap3 is not installed — `pip install ldap3` to run AD enumeration"
            )

        self._domain = domain
        self._base_dn = _domain_to_base_dn(domain)
        server = Server(
            dc_ip,
            port=port or (636 if use_ssl else 389),
            use_ssl=use_ssl,
            get_info=ALL,
        )

        try:
            if use_kerberos:
                conn = Connection(
                    server,
                    authentication=ldap3.SASL,
                    sasl_mechanism=ldap3.KERBEROS,
                    auto_bind=True,
                )
            else:
                user_principal = f"{domain}\\{username}" if "\\" not in username else username
                conn = Connection(
                    server,
                    user=user_principal,
                    password=password,
                    authentication=NTLM,
                    auto_bind=True,
                )
        except LDAPException as exc:
            raise ADConnectionError(f"LDAP bind to {dc_ip} failed: {exc}") from exc

        if not conn.bound:
            raise ADConnectionError(f"LDAP bind to {dc_ip} did not complete")

        self._conn = conn
        logger.info("ad.ldap.connected", dc=dc_ip, domain=domain, kerberos=use_kerberos)
        return self

    @property
    def connection(self) -> Any:
        return self._conn

    def _require_conn(self) -> Any:
        if self._conn is None:
            raise ADConnectionError("Not connected — call connect() first")
        return self._conn

    def _search(self, ldap_filter: str, attributes: list[str]) -> list[Any]:
        conn = self._require_conn()
        conn.search(
            search_base=self._base_dn,
            search_filter=ldap_filter,
            search_scope=SUBTREE,
            attributes=attributes,
        )
        return list(conn.entries)

    @staticmethod
    def _attr(entry: Any, name: str) -> Any:
        try:
            val = entry[name].value
            return val
        except Exception:
            return None

    # ── get_users ────────────────────────────────────────────────────────────────

    def get_users(self) -> list[ADUser]:
        """All user accounts (excludes computer accounts)."""
        entries = self._search(
            "(&(objectCategory=person)(objectClass=user))",
            ["sAMAccountName", "objectSid", "memberOf", "servicePrincipalName",
             "userAccountControl", "adminCount"],
        )
        users: list[ADUser] = []
        for e in entries:
            uac = int(self._attr(e, "userAccountControl") or 0)
            admin_count = int(self._attr(e, "adminCount") or 0)
            users.append(ADUser(
                samaccountname=str(self._attr(e, "sAMAccountName") or ""),
                sid=self._attr(e, "objectSid"),
                memberof=_as_list(self._attr(e, "memberOf")),
                spn=_as_list(self._attr(e, "servicePrincipalName")),
                no_preauth=bool(uac & UAC_DONT_REQ_PREAUTH),
                admin_count=admin_count == 1,
                enabled=not bool(uac & 0x2),
                dn=str(getattr(e, "entry_dn", "")) or None,
            ))
        logger.info("ad.ldap.users", count=len(users))
        return users

    # ── get_computers ─────────────────────────────────────────────────────────────

    def get_computers(self) -> list[ADComputer]:
        entries = self._search(
            "(objectClass=computer)",
            ["dNSHostName", "operatingSystem", "userAccountControl",
             "primaryGroupID", "sAMAccountName"],
        )
        computers: list[ADComputer] = []
        for e in entries:
            uac = int(self._attr(e, "userAccountControl") or 0)
            primary_gid = int(self._attr(e, "primaryGroupID") or 0)
            is_dc = bool(uac & UAC_SERVER_TRUST_ACCOUNT) or primary_gid in DC_PRIMARY_GROUP_IDS
            hostname = (
                self._attr(e, "dNSHostName")
                or str(self._attr(e, "sAMAccountName") or "").rstrip("$")
            )
            computers.append(ADComputer(
                hostname=str(hostname or ""),
                os=self._attr(e, "operatingSystem"),
                ip=None,  # resolved separately by discovery; LDAP rarely holds it
                is_dc=is_dc,
                dn=str(getattr(e, "entry_dn", "")) or None,
            ))
        logger.info("ad.ldap.computers", count=len(computers))
        return computers

    # ── get_groups ────────────────────────────────────────────────────────────────

    def get_groups(self) -> list[ADGroup]:
        entries = self._search(
            "(objectClass=group)",
            ["cn", "sAMAccountName", "member"],
        )
        groups: list[ADGroup] = []
        for e in entries:
            name = str(self._attr(e, "sAMAccountName") or self._attr(e, "cn") or "")
            groups.append(ADGroup(
                name=name,
                members=_as_list(self._attr(e, "member")),
                is_privileged=name.lower() in PRIVILEGED_GROUPS,
                dn=str(getattr(e, "entry_dn", "")) or None,
            ))
        logger.info("ad.ldap.groups", count=len(groups))
        return groups

    # ── check_anonymous_bind ────────────────────────────────────────────────────

    def check_anonymous_bind(self, dc_ip: str, port: int = 389) -> bool:
        """
        True if the DC accepts an anonymous bind that can read directory data
        (a misconfiguration). Uses an independent throwaway connection.
        """
        if not _HAS_LDAP3:
            raise DependencyMissingError("ldap3 is not installed")
        try:
            server = Server(dc_ip, port=port, get_info=ALL)
            conn = Connection(server, auto_bind=True)  # anonymous
            if not conn.bound:
                return False
            # Confirm we can actually read something, not just bind.
            base = self._base_dn or ""
            conn.search(base, "(objectClass=*)", search_scope="BASE", attributes=["defaultNamingContext"])
            readable = bool(conn.entries)
            conn.unbind()
            logger.info("ad.ldap.anonymous_bind", dc=dc_ip, readable=readable)
            return readable
        except LDAPException as exc:
            logger.info("ad.ldap.anonymous_bind.refused", dc=dc_ip, error=str(exc))
            return False

    # ── get_aces ──────────────────────────────────────────────────────────────────

    def get_aces(self, object_dn: str) -> list[ACE]:
        """
        Parse the nTSecurityDescriptor of an object into a list of ACEs for ACL
        abuse detection (e.g. low-priv principal with GenericAll/WriteDacl).

        Requires impacket's ldaptypes for SD decoding; returns [] without it.
        """
        conn = self._require_conn()
        conn.search(
            search_base=object_dn,
            search_filter="(objectClass=*)",
            search_scope="BASE",
            attributes=["nTSecurityDescriptor"],
            controls=[("1.2.840.113556.1.4.801", True, b"\x30\x03\x02\x01\x07")],  # DACL only
        )
        if not conn.entries:
            return []

        raw = self._attr(conn.entries[0], "nTSecurityDescriptor")
        if not raw:
            return []
        if isinstance(raw, str):
            raw = raw.encode("latin-1", errors="ignore")

        if not _HAS_LDAPTYPES:
            logger.warning(
                "ad.ldap.aces.no_ldaptypes",
                hint="install impacket for nTSecurityDescriptor parsing",
            )
            return []

        return self._parse_security_descriptor(raw)

    def _parse_security_descriptor(self, raw: bytes) -> list[ACE]:
        aces: list[ACE] = []
        try:
            sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=raw)
        except Exception as exc:  # malformed blob — never crash enumeration
            logger.warning("ad.ldap.aces.parse_failed", error=str(exc))
            return aces

        dacl = getattr(sd, "Dacl", None)
        if dacl is None:
            return aces

        for entry in dacl.aces:
            ace_struct = entry["Ace"]
            try:
                sid = ace_struct["Sid"].formatCanonical()
            except Exception:
                continue
            mask = int(ace_struct["Mask"]["Mask"])
            rights = [name for bit, name in _ACCESS_RIGHTS if mask & bit]
            ace_type = "DENY" if "DENIED" in entry["TypeName"].upper() else "ALLOW"
            object_type = None
            if "ObjectType" in ace_struct.fields and ace_struct["ObjectType"]:
                try:
                    object_type = ace_struct["ObjectType"].hex()
                except Exception:
                    object_type = None
            aces.append(ACE(
                trustee_sid=sid,
                ace_type=ace_type,
                rights=rights,
                object_type=object_type,
                inherited=bool(int(entry["AceFlags"]) & 0x10),
            ))
        return aces

    def unbind(self) -> None:
        if self._conn is not None:
            try:
                self._conn.unbind()
            except Exception:
                pass
            self._conn = None
