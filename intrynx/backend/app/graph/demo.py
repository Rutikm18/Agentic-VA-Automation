"""
Demo dataset generator for the attack-path engine.

Produces a small but realistic engagement topology with lightweight stand-in
objects (no DB required) so GraphBuilder/PathAnalyzer can be exercised in tests,
local development, and documentation.

Topology:
                internet
                   │  (exploit on web01)
              ┌── web01 (DMZ, exposed) ──┐
   SAME_SEGMENT│                          │CONNECTS_TO
              app01 ───CONNECTS_TO──── db01 (critical)
                │                          ▲
   CREDENTIAL_REUSE                        │ EXPLOITS (SQLi, validated)
              jump01 ──────CONNECTS_TO─────┘
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any


@dataclass
class DemoAsset:
    id: uuid.UUID
    hostname: str
    ip_address: str
    criticality: str = "medium"
    environment: str = "internal"
    tags: dict = field(default_factory=dict)


@dataclass
class DemoService:
    id: uuid.UUID
    asset_id: uuid.UUID
    port: int
    service_name: str


@dataclass
class DemoFinding:
    id: uuid.UUID
    asset_id: uuid.UUID
    title: str
    severity: str
    cvss_score: Decimal | None
    exploitable: bool = False
    exploit_validated: bool = False
    cvss_vector: str | None = None
    mitre_techniques: list[str] = field(default_factory=list)


def generate_demo_dataset() -> dict[str, Any]:
    """
    Returns {engagement_id, assets, services, findings, credentials,
    network_topology, critical_asset_id} ready to feed GraphBuilder.
    """
    eng_id = uuid.uuid4()
    web01 = DemoAsset(uuid.uuid4(), "web01", "203.0.113.10", "high", "dmz",
                      {"internet_exposed": True})
    app01 = DemoAsset(uuid.uuid4(), "app01", "10.0.1.20", "medium", "internal")
    jump01 = DemoAsset(uuid.uuid4(), "jump01", "10.0.1.30", "medium", "internal")
    db01 = DemoAsset(uuid.uuid4(), "db01", "10.0.2.40", "critical", "internal")
    assets = [web01, app01, jump01, db01]

    services = [
        DemoService(uuid.uuid4(), web01.id, 443, "https"),
        DemoService(uuid.uuid4(), app01.id, 8080, "http"),
        DemoService(uuid.uuid4(), jump01.id, 22, "ssh"),
        DemoService(uuid.uuid4(), db01.id, 1433, "mssql"),
    ]

    findings = [
        DemoFinding(uuid.uuid4(), web01.id, "Unauthenticated RCE in web app",
                    "critical", Decimal("9.8"), exploitable=True, exploit_validated=True,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    mitre_techniques=["T1190"]),
        DemoFinding(uuid.uuid4(), app01.id, "Deserialization flaw",
                    "high", Decimal("8.1"), exploitable=True,
                    cvss_vector="CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H",
                    mitre_techniques=["T1059"]),
        DemoFinding(uuid.uuid4(), db01.id, "SQL injection to OS command",
                    "critical", Decimal("9.1"), exploitable=True, exploit_validated=True,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
                    mitre_techniques=["T1190", "T1505"]),
        DemoFinding(uuid.uuid4(), jump01.id, "Outdated OpenSSH",
                    "medium", Decimal("5.3"), exploitable=False,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    ]

    network_topology = {
        "segments": {
            "dmz": [str(web01.id)],
            "app-tier": [str(app01.id), str(jump01.id)],
            "data-tier": [str(db01.id)],
        },
        "connections": [
            [str(web01.id), str(app01.id)],
            [str(app01.id), str(db01.id)],
            [str(jump01.id), str(db01.id)],
        ],
    }

    credentials = [
        {"id": uuid.uuid4(), "label": "svc_app local admin",
         "reused_on": [str(app01.id), str(jump01.id)]},
    ]

    return {
        "engagement_id": eng_id,
        "assets": assets,
        "services": services,
        "findings": findings,
        "credentials": credentials,
        "network_topology": network_topology,
        "critical_asset_id": str(db01.id),
        "exposed_asset_id": str(web01.id),
    }
