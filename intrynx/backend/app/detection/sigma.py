"""
SigmaRuleGenerator — produces a Sigma detection rule (YAML) for a MITRE
technique that the blue team missed, customised with field values observed in
the attack evidence.

A small template library provides a base rule per technique (logsource +
detection skeleton). The generator fills in observed values (target host,
process, command line, SPN, etc.) so the rule is immediately actionable rather
than generic.
"""
from __future__ import annotations

import copy
from typing import Any

import structlog
import yaml

logger = structlog.get_logger()


# Base Sigma templates keyed by MITRE technique id. Each is a plain dict that
# yaml.safe_dump renders to a valid Sigma rule.
SIGMA_TEMPLATES: dict[str, dict[str, Any]] = {
    "T1190": {  # Exploit Public-Facing Application
        "logsource": {"category": "webserver"},
        "detection": {
            "selection": {"cs-method": ["POST", "GET"], "sc-status": [200, 500]},
            "condition": "selection",
        },
    },
    "T1059": {  # Command and Scripting Interpreter
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection": {
            "selection": {"Image|endswith": ["\\cmd.exe", "\\powershell.exe", "\\wscript.exe"]},
            "condition": "selection",
        },
    },
    "T1558.003": {  # Kerberoasting
        "logsource": {"product": "windows", "service": "security"},
        "detection": {
            "selection": {"EventID": 4769, "TicketEncryptionType": "0x17"},
            "condition": "selection",
        },
    },
    "T1558.004": {  # AS-REP Roasting
        "logsource": {"product": "windows", "service": "security"},
        "detection": {
            "selection": {"EventID": 4768, "PreAuthType": "0"},
            "condition": "selection",
        },
    },
    "T1110": {  # Brute Force
        "logsource": {"product": "windows", "service": "security"},
        "detection": {
            "selection": {"EventID": 4625},
            "timeframe": "5m",
            "condition": "selection | count() > 10",
        },
    },
    "T1003": {  # OS Credential Dumping
        "logsource": {"category": "process_access", "product": "windows"},
        "detection": {
            "selection": {"TargetImage|endswith": "\\lsass.exe",
                          "GrantedAccess": ["0x1010", "0x1410"]},
            "condition": "selection",
        },
    },
    "T1021": {  # Remote Services / lateral movement
        "logsource": {"product": "windows", "service": "security"},
        "detection": {
            "selection": {"EventID": 4624, "LogonType": [3, 10]},
            "condition": "selection",
        },
    },
    "T1557.001": {  # LLMNR/NBT-NS Poisoning and SMB Relay
        "logsource": {"product": "windows", "service": "security"},
        "detection": {
            "selection": {"EventID": 4624, "AuthenticationPackageName": "NTLM", "LogonType": 3},
            "condition": "selection",
        },
    },
    "T1649": {  # Steal or Forge Authentication Certificates (AD CS)
        "logsource": {"product": "windows", "service": "security"},
        "detection": {
            "selection": {"EventID": [4886, 4887]},
            "condition": "selection",
        },
    },
    "T1046": {  # Network Service Discovery
        "logsource": {"category": "firewall"},
        "detection": {
            "selection": {"action": "denied"},
            "timeframe": "1m",
            "condition": "selection | count(dst_port) by src_ip > 20",
        },
    },
}

# Fallback skeleton when the technique has no specific template.
_GENERIC_TEMPLATE: dict[str, Any] = {
    "logsource": {"category": "process_creation"},
    "detection": {"selection": {}, "condition": "selection"},
}


class SigmaRuleGenerator:

    def generate_sigma_for_technique(
        self,
        mitre_technique: str | None,
        missed_evidence: dict[str, Any] | None = None,
    ) -> str:
        """
        Return a Sigma rule (YAML string) for the technique, customised with the
        observed evidence. Looks up by full technique id, then by parent id
        (e.g. ``T1558.003`` → ``T1558``), else uses a generic skeleton.
        """
        evidence = missed_evidence or {}
        technique = (mitre_technique or "").strip() or "UNKNOWN"

        template = self._lookup_template(technique)
        rule = copy.deepcopy(template)

        host = evidence.get("host") or evidence.get("target_ip")
        rule_doc: dict[str, Any] = {
            "title": f"[ADVERSA gap] Detection for {technique}",
            "id": evidence.get("rule_id") or _stable_rule_id(technique, host),
            "status": "experimental",
            "description": (
                f"Auto-generated from a detection gap: attack technique {technique} "
                "was executed during the engagement but no SIEM/EDR alert fired. "
                "Tune fields and thresholds before deploying."
            ),
            "references": [f"https://attack.mitre.org/techniques/{technique.replace('.', '/')}/"],
            "tags": [f"attack.{technique.lower()}"],
            "logsource": rule["logsource"],
            "detection": self._customise_detection(rule["detection"], evidence, host),
            "falsepositives": ["Legitimate administrative activity"],
            "level": evidence.get("severity", "high"),
        }
        return yaml.safe_dump(rule_doc, sort_keys=False, default_flow_style=False, width=100)

    def _lookup_template(self, technique: str) -> dict[str, Any]:
        if technique in SIGMA_TEMPLATES:
            return SIGMA_TEMPLATES[technique]
        parent = technique.split(".")[0]
        if parent in SIGMA_TEMPLATES:
            return SIGMA_TEMPLATES[parent]
        return _GENERIC_TEMPLATE

    @staticmethod
    def _customise_detection(detection: dict[str, Any], evidence: dict[str, Any], host: str | None) -> dict[str, Any]:
        out = copy.deepcopy(detection)
        selection = out.get("selection")
        if isinstance(selection, dict):
            # Pin observed high-signal fields so the rule matches this attack.
            if host:
                selection["dest_host|contains"] = host
            for key in ("process", "Image", "CommandLine", "spn", "user", "src_ip"):
                if evidence.get(key):
                    selection[key] = evidence[key]
        return out


def _stable_rule_id(technique: str, host: str | None) -> str:
    import hashlib
    import uuid

    seed = f"adversa-{technique}-{host or 'any'}"
    return str(uuid.UUID(hashlib.md5(seed.encode()).hexdigest()))
