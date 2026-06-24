/**
 * Static mock data for the dashboard.
 *
 * TODO: Replace each export with the real API response once the corresponding
 *       endpoints ship. Keeping them here keeps page.tsx and DashboardCharts.tsx
 *       focused on layout and data fetching, not placeholder data.
 */

export type Severity   = "CRITICAL" | "HIGH" | "MEDIUM";
export type PathStatus = "VALIDATED" | "SIMULATING" | "PENDING";
export type AgentStatus= "ACTIVE" | "THINKING" | "IDLE";

export interface AttackPath {
  id: string;
  origin: string;
  target: string;
  severity: Severity;
  confidence: number;
  status: PathStatus;
}

export interface SlaFinding {
  id: string;
  title: string;
  severity: Severity;
  status: string;
  deadline: string;
  hoursTotal: number;
}

export interface ProtocolRisk {
  name: string;
  value: number;
}

export interface ZoneHealth {
  name: string;
  score: number;
}

export const ATTACK_PATHS: AttackPath[] = [
  { id: "AP-001", origin: "WS-042",   target: "DC01",         severity: "CRITICAL", confidence: 97, status: "VALIDATED"  },
  { id: "AP-002", origin: "SVC-SQL",  target: "DOMAIN ADMIN", severity: "CRITICAL", confidence: 94, status: "VALIDATED"  },
  { id: "AP-003", origin: "VLAN30",   target: "VLAN10",       severity: "HIGH",     confidence: 88, status: "SIMULATING" },
  { id: "AP-004", origin: "WS-042",   target: "10.10.10.0/24",severity: "HIGH",     confidence: 82, status: "SIMULATING" },
  { id: "AP-005", origin: "INT-SEG",  target: "NTLM-RELAY",   severity: "MEDIUM",   confidence: 71, status: "PENDING"    },
];

export const SLA_FINDINGS: SlaFinding[] = [
  { id: "VAPT-CRIT-001", title: "Unconstrained Kerberos Delegation on DC01",      severity: "CRITICAL", status: "OPEN",           deadline: "2026-05-11T09:32:00Z", hoursTotal: 24  },
  { id: "VAPT-CRIT-002", title: "Kerberoastable svc_backup → Domain Admin",       severity: "CRITICAL", status: "IN_REVIEW",      deadline: "2026-05-11T10:14:00Z", hoursTotal: 24  },
  { id: "VAPT-HIGH-001", title: "LLMNR/NBT-NS Poisoning — NTLM Credential Relay", severity: "HIGH",     status: "IN_REMEDIATION", deadline: "2026-05-13T11:05:00Z", hoursTotal: 72  },
  { id: "VAPT-HIGH-002", title: "Lateral Movement via WMI — WS-042 to CORP",      severity: "HIGH",     status: "OPEN",           deadline: "2026-05-13T14:22:00Z", hoursTotal: 72  },
  { id: "VAPT-MED-001",  title: "Network Segmentation Bypass — VLAN30 to VLAN10", severity: "MEDIUM",   status: "VERIFIED",       deadline: "2026-05-18T09:15:00Z", hoursTotal: 168 },
];

export const PROTOCOLS: ProtocolRisk[] = [
  { name: "LDAP",     value: 91 },
  { name: "SMB",      value: 78 },
  { name: "Kerberos", value: 65 },
  { name: "RPC",      value: 43 },
];

export const ZONES: ZoneHealth[] = [
  { name: "MGMT", score: 96 },
  { name: "DMZ",  score: 94 },
  { name: "OT",   score: 88 },
  { name: "CORP", score: 71 },
];

export const TOP_FINDINGS = [
  { id: "VAPT-CRIT-001", title: "Unconstrained Delegation — DC01",      host: "DC01",    score: 970, severity: "CRITICAL" as const, status: "OPEN"          },
  { id: "VAPT-CRIT-002", title: "Kerberoastable svc_backup → DA",       host: "SVC-SQL", score: 920, severity: "CRITICAL" as const, status: "IN_REMEDIATION"},
  { id: "VAPT-CRIT-003", title: "Log4Shell (CVE-2021-44228)",            host: "WEB-01",  score: 910, severity: "CRITICAL" as const, status: "VERIFIED"      },
  { id: "VAPT-HIGH-001", title: "SMB Signing Not Required — 4 Hosts",   host: "WS-042",  score: 730, severity: "HIGH"     as const, status: "OPEN"          },
  { id: "VAPT-HIGH-003", title: "AD CS ESC1 — UserAuthentication Tmpl", host: "corp-CA", score: 720, severity: "HIGH"     as const, status: "OPEN"          },
];
