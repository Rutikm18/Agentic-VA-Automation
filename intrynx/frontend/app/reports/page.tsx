"use client";

import React, { useState, useCallback } from "react";
import { Menu, FileText, Download, ChevronDown, ChevronRight, Printer } from "lucide-react";
import { Sidebar } from "../../components/Sidebar";
import { useToast } from "../../hooks/useToast";

/* ─── Types ─── */
type ReportType = "executive" | "technical" | "compliance" | "evidence";
type ComplianceFramework = "ALL" | "NIST_800_115" | "NIST_800_53" | "ISO_27001" | "PCI_DSS" | "CIS_V8" | "MITRE";

interface ComplianceControl {
  controlId: string;
  controlName: string;
  requirement: string;
  findingRefs: string[];
  status: "GAP" | "PARTIAL" | "COMPLIANT" | "NOT_APPLICABLE";
  evidenceSummary: string;
  remediationPriority: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
}

interface ComplianceFrameworkData {
  id: ComplianceFramework;
  name: string;
  shortName: string;
  version: string;
  totalControls: number;
  compliant: number;
  partial: number;
  gap: number;
  controls: ComplianceControl[];
}

/* ─── Evidence Stats ─── */
const evidenceStats = {
  totalFindings: 14,
  critical: 2,
  high: 5,
  medium: 4,
  low: 3,
  exploitedPaths: 6,
  avgConfidence: 87,
  evidenceArtifacts: 31,
  screenshotsCount: 12,
  commandOutputs: 19,
  remediatedCount: 0,
  inProgressCount: 2,
  openCount: 12,
  engagementDays: 5,
  scopeHosts: 317,
  scopeSubnets: "10.10.0.0/24, 10.10.10.0/24, 172.16.1.0/24, 192.168.100.0/24",
};

/* ─── Compliance Framework Data ─── */
const frameworks: ComplianceFrameworkData[] = [
  {
    id: "NIST_800_115",
    name: "NIST SP 800-115",
    shortName: "NIST 800-115",
    version: "Technical Guide to Information Security Testing and Assessment",
    totalControls: 8,
    compliant: 3,
    partial: 3,
    gap: 2,
    controls: [
      {
        controlId: "NIST-800-115 §4.1",
        controlName: "Network Discovery — Target Identification",
        requirement: "Testers must perform network discovery to identify live hosts, open ports, and running services within the defined scope.",
        findingRefs: [],
        status: "COMPLIANT",
        evidenceSummary: "Full Nmap scan performed (SYN + version detection) across 4 subnets. 317 hosts identified, 2,841 open ports enumerated. Network topology mapped including firewall rules.",
        remediationPriority: "LOW",
      },
      {
        controlId: "NIST-800-115 §4.2",
        controlName: "Port and Service Scanning",
        requirement: "Identify all services exposed on in-scope hosts; document protocol versions and patch levels.",
        findingRefs: ["VAPT-HIGH-001"],
        status: "COMPLIANT",
        evidenceSummary: "Nessus + Nmap service detection run. LLMNR/NetBIOS enumeration confirmed legacy protocols active on all CORP workstations. 14 CVEs identified via Tenable scan (7 critical/high).",
        remediationPriority: "LOW",
      },
      {
        controlId: "NIST-800-115 §4.3",
        controlName: "Vulnerability Identification",
        requirement: "Enumerate and validate vulnerabilities using a combination of automated scanning and manual verification.",
        findingRefs: ["VAPT-CRIT-001", "VAPT-CRIT-002", "VAPT-HIGH-001", "VAPT-HIGH-002", "VAPT-MED-001"],
        status: "COMPLIANT",
        evidenceSummary: "5 findings manually validated with proof-of-exploitation evidence. Tenable.io automated scan corroborates 4/5 findings. 1 finding (delegation) identified manually only.",
        remediationPriority: "LOW",
      },
      {
        controlId: "NIST-800-115 §5.1",
        controlName: "Target Identification and Analysis — Password Attacks",
        requirement: "Attempt to identify and exploit weakly-configured authentication mechanisms including password policies and credential stores.",
        findingRefs: ["VAPT-CRIT-002"],
        status: "GAP",
        evidenceSummary: "Kerberoasting demonstrated (svc_backup password cracked in 4h). Client has no detection for TGS-REQ Event 4769 with etype 0x17. Password policy requires enhancement.",
        remediationPriority: "CRITICAL",
      },
      {
        controlId: "NIST-800-115 §5.2",
        controlName: "Target Vulnerability Validation",
        requirement: "Validate identified vulnerabilities by demonstrating exploitability in a controlled manner. Document all steps taken and evidence obtained.",
        findingRefs: ["VAPT-CRIT-001", "VAPT-CRIT-002"],
        status: "COMPLIANT",
        evidenceSummary: "All critical findings validated with step-by-step command evidence, tool output screenshots, and post-exploitation artifacts. Evidence included in technical annex.",
        remediationPriority: "LOW",
      },
      {
        controlId: "NIST-800-115 §5.3",
        controlName: "Exploitation and Post-Exploitation",
        requirement: "Document the extent of access gained after exploitation, including lateral movement and privilege escalation paths.",
        findingRefs: ["VAPT-CRIT-001", "VAPT-HIGH-002"],
        status: "PARTIAL",
        evidenceSummary: "Domain Admin compromise demonstrated via two independent paths. Lateral movement to 18 CORP hosts via WMI documented. Full scope of post-exploitation limited per engagement rules of engagement.",
        remediationPriority: "HIGH",
      },
      {
        controlId: "NIST-800-115 §6.1",
        controlName: "Reporting — Technical Findings",
        requirement: "Report must include: vulnerability description, risk rating, proof-of-concept evidence, and specific remediation guidance.",
        findingRefs: [],
        status: "COMPLIANT",
        evidenceSummary: "All 5 validated findings include: CVSS v3.1 score, technical description, evidence artifacts, attack path, and prioritized remediation steps. This report meets §6.1 requirements.",
        remediationPriority: "LOW",
      },
      {
        controlId: "NIST-800-115 §6.2",
        controlName: "Reporting — Remediation Recommendations",
        requirement: "Each finding must include actionable, prioritized remediation recommendations with specific technical steps.",
        findingRefs: [],
        status: "PARTIAL",
        evidenceSummary: "Remediation steps provided for all findings. Long-term architectural recommendations (e.g., gMSA rollout, SMB signing enforcement) require organizational planning not covered in this initial report.",
        remediationPriority: "MEDIUM",
      },
    ],
  },
  {
    id: "NIST_800_53",
    name: "NIST SP 800-53 Rev 5",
    shortName: "NIST 800-53",
    version: "Security and Privacy Controls for Information Systems and Organizations",
    totalControls: 10,
    compliant: 2,
    partial: 4,
    gap: 4,
    controls: [
      {
        controlId: "CA-8",
        controlName: "Penetration Testing",
        requirement: "The organization employs an independent penetration agent or penetration team to perform penetration testing on the information system.",
        findingRefs: [],
        status: "COMPLIANT",
        evidenceSummary: "Independent VAPT engagement conducted by Adversa Security. External + internal testing performed. Scope covered: network, AD, protocol, segmentation. Report serves as CA-8 evidence.",
        remediationPriority: "LOW",
      },
      {
        controlId: "RA-5",
        controlName: "Vulnerability Monitoring and Scanning",
        requirement: "Scan for vulnerabilities in the system and hosted applications at defined frequencies; employ vulnerability scanning tools and techniques.",
        findingRefs: ["VAPT-CRIT-001", "VAPT-CRIT-002"],
        status: "PARTIAL",
        evidenceSummary: "Tenable.io scans running but misconfiguration findings (delegation) not detectable by automated scanning. Manual validation required. Scanning frequency not verified as meeting defined intervals.",
        remediationPriority: "HIGH",
      },
      {
        controlId: "SI-2",
        controlName: "Flaw Remediation",
        requirement: "Identify, report, and correct information system flaws; test software and firmware updates prior to installation.",
        findingRefs: ["VAPT-CRIT-002", "VAPT-HIGH-001"],
        status: "GAP",
        evidenceSummary: "svc_backup account (Kerberoastable) password unchanged for 14 months. RC4 encryption still permitted despite AES256 availability since Windows Server 2012. No patch/config remediation process observed.",
        remediationPriority: "CRITICAL",
      },
      {
        controlId: "AC-6",
        controlName: "Least Privilege",
        requirement: "Employ the principle of least privilege, allowing only authorized accesses for users which are necessary to accomplish assigned tasks.",
        findingRefs: ["VAPT-CRIT-002", "VAPT-CRIT-001"],
        status: "GAP",
        evidenceSummary: "svc_backup is a member of Domain Admins — no operational justification found. WS-042$ has TrustedForDelegation=TRUE unnecessarily. 7 accounts in Domain Admins vs. recommended maximum of 3.",
        remediationPriority: "CRITICAL",
      },
      {
        controlId: "IA-5",
        controlName: "Authenticator Management",
        requirement: "Manage information system authenticators by verifying the identity of individual, group, role, service, or device prior to issuing/generating authenticators.",
        findingRefs: ["VAPT-CRIT-002"],
        status: "GAP",
        evidenceSummary: "Service account passwords not rotated per policy (svc_backup: 14 months, svc_iis: 14 months). No gMSA deployed for service accounts. Weak password policy (8 chars min). RC4 Kerberos still permitted.",
        remediationPriority: "CRITICAL",
      },
      {
        controlId: "SC-7",
        controlName: "Boundary Protection",
        requirement: "Monitor and control communications at the external boundary of the system and at key internal boundaries within the system.",
        findingRefs: ["VAPT-MED-001", "VAPT-HIGH-001"],
        status: "GAP",
        evidenceSummary: "CORP→MGMT boundary unrestricted (ACL-002 permits ANY TCP). DMZ→CORP allows SMB/445 (ACL-003). LLMNR broadcast protocols not blocked at network layer. Segmentation boundaries inadequately enforced.",
        remediationPriority: "HIGH",
      },
      {
        controlId: "AU-12",
        controlName: "Audit Record Generation",
        requirement: "Allow or disallow audit record generation capabilities for defined auditable events.",
        findingRefs: ["VAPT-HIGH-002"],
        status: "GAP",
        evidenceSummary: "Process creation auditing (Event 4688) disabled on 73% of CORP endpoints. Command-line logging not enabled. WMI lateral movement unlogged. SIEM received no telemetry for 18-host WMI exercise.",
        remediationPriority: "HIGH",
      },
      {
        controlId: "SC-8",
        controlName: "Transmission Confidentiality and Integrity",
        requirement: "Implement cryptographic mechanisms to prevent unauthorized disclosure of information and detect changes during transmission.",
        findingRefs: ["VAPT-HIGH-001"],
        status: "PARTIAL",
        evidenceSummary: "SMB signing disabled on 67% of CORP hosts. NTLM relay attack succeeded against SVC-SQL. Kerberos available but NTLMv2 fallback still permitted. TLS enforced on external services.",
        remediationPriority: "HIGH",
      },
      {
        controlId: "AC-17",
        controlName: "Remote Access",
        requirement: "Establish and document usage restrictions, configuration/connection requirements, and implementation guidance for remote access.",
        findingRefs: ["VAPT-HIGH-002"],
        status: "PARTIAL",
        evidenceSummary: "WMI remote access permitted from CORP VLAN without network-level restrictions. Jump host policy exists for MGMT but bypassed via CORP→MGMT segmentation gap. RDP from DEV to CORP unrestricted.",
        remediationPriority: "HIGH",
      },
      {
        controlId: "IR-4",
        controlName: "Incident Handling",
        requirement: "Implement an incident handling capability for security incidents including preparation, detection, analysis, containment, eradication, and recovery.",
        findingRefs: [],
        status: "PARTIAL",
        evidenceSummary: "No security events triggered during 5-day engagement. Incident detection capability appears insufficient to identify an active threat actor. Recommend tabletop exercise to validate IR procedures.",
        remediationPriority: "MEDIUM",
      },
    ],
  },
  {
    id: "ISO_27001",
    name: "ISO/IEC 27001:2022",
    shortName: "ISO 27001",
    version: "Annex A Information Security Controls",
    totalControls: 9,
    compliant: 2,
    partial: 3,
    gap: 4,
    controls: [
      {
        controlId: "A.8.8",
        controlName: "Management of Technical Vulnerabilities",
        requirement: "Information about technical vulnerabilities of information systems in use shall be obtained in a timely fashion, the organisation's exposure to such vulnerabilities evaluated, and appropriate measures taken to address the associated risk.",
        findingRefs: ["VAPT-CRIT-001", "VAPT-CRIT-002"],
        status: "GAP",
        evidenceSummary: "Unconstrained delegation on DC01 and Kerberoastable DA service account represent unmanaged technical vulnerabilities. No evidence of prior vulnerability management process identifying these misconfigurations.",
        remediationPriority: "CRITICAL",
      },
      {
        controlId: "A.8.9",
        controlName: "Configuration Management",
        requirement: "Configurations, including security configurations, of hardware, software, services and networks shall be established, documented, implemented, monitored and reviewed.",
        findingRefs: ["VAPT-CRIT-001"],
        status: "GAP",
        evidenceSummary: "TrustedForDelegation=TRUE on DC01 and WS-042$ indicates no baseline hardening review. No CIS Benchmark or STIGs applied. Default configurations prevalent across CORP endpoints.",
        remediationPriority: "CRITICAL",
      },
      {
        controlId: "A.5.17",
        controlName: "Authentication Information",
        requirement: "Allocation and management of authentication information shall be controlled by a management process, including advising personnel on appropriate handling of authentication information.",
        findingRefs: ["VAPT-CRIT-002"],
        status: "GAP",
        evidenceSummary: "Service account svc_backup: password unchanged 14 months, cracked in 4 hours. No gMSA or automatic rotation. Minimum password length 8 characters — below ISO 27002 guidance of 12+ characters.",
        remediationPriority: "CRITICAL",
      },
      {
        controlId: "A.8.20",
        controlName: "Networks Security",
        requirement: "Networks and network devices shall be managed and controlled to protect information in systems and applications.",
        findingRefs: ["VAPT-HIGH-001"],
        status: "GAP",
        evidenceSummary: "LLMNR/NBT-NS broadcast protocols active — enables network-level credential interception. SMB signing disabled on majority of hosts. No network-level controls preventing NTLM relay attacks.",
        remediationPriority: "HIGH",
      },
      {
        controlId: "A.8.22",
        controlName: "Segregation of Networks",
        requirement: "Groups of information services, users and information systems shall be segregated in networks.",
        findingRefs: ["VAPT-MED-001"],
        status: "GAP",
        evidenceSummary: "CORP-to-MGMT boundary permits unrestricted TCP. DMZ-to-CORP allows SMB. Network zone boundaries are defined in documentation but not enforced in technical controls. VLAN isolation incomplete.",
        remediationPriority: "HIGH",
      },
      {
        controlId: "A.8.15",
        controlName: "Logging",
        requirement: "Logs that record activities, exceptions, faults and other relevant events shall be produced, stored, protected and analysed.",
        findingRefs: ["VAPT-HIGH-002"],
        status: "PARTIAL",
        evidenceSummary: "Security event logging enabled on DCs and servers but Process Creation (4688) disabled on 73% of endpoints. SIEM ingests DC and server logs but not workstation telemetry. Log retention policy not verified.",
        remediationPriority: "HIGH",
      },
      {
        controlId: "A.8.29",
        controlName: "Security Testing in Development and Acceptance",
        requirement: "Security testing processes shall be defined and implemented in the development life cycle.",
        findingRefs: [],
        status: "NOT_APPLICABLE",
        evidenceSummary: "No custom application development identified in scope. This control applies to the client's software development lifecycle — not assessed in this network VAPT engagement.",
        remediationPriority: "LOW",
      },
      {
        controlId: "A.5.36",
        controlName: "Compliance with Policies, Rules and Standards",
        requirement: "Compliance with the organisation's information security policy, topic-specific policies, rules and standards shall be regularly reviewed.",
        findingRefs: [],
        status: "PARTIAL",
        evidenceSummary: "ISMS policy documents exist but technical controls do not reflect policy requirements. Segmentation policy requires CORP-MGMT isolation — not technically enforced. Annual penetration testing initiated (this engagement).",
        remediationPriority: "MEDIUM",
      },
      {
        controlId: "A.5.23",
        controlName: "Information Security for Use of Cloud Services",
        requirement: "Processes for acquisition, use, management and exit from cloud services shall be defined and implemented in accordance with the organisation's information security requirements.",
        findingRefs: [],
        status: "COMPLIANT",
        evidenceSummary: "Cloud services were out of scope for this engagement. Client confirmed cloud workloads are managed under a separate cloud security programme with dedicated cloud security posture management (CSPM) tooling.",
        remediationPriority: "LOW",
      },
    ],
  },
  {
    id: "PCI_DSS",
    name: "PCI DSS v4.0",
    shortName: "PCI DSS",
    version: "Payment Card Industry Data Security Standard, Version 4.0 (March 2022)",
    totalControls: 10,
    compliant: 3,
    partial: 4,
    gap: 3,
    controls: [
      {
        controlId: "Req 11.3.1",
        controlName: "External Penetration Testing",
        requirement: "External penetration testing is performed at least once every 12 months, after any significant infrastructure change, and after any significant system or software change.",
        findingRefs: [],
        status: "COMPLIANT",
        evidenceSummary: "This engagement constitutes the annual external penetration test. Testing performed from external internet perspective against DMZ-exposed services. No significant infrastructure changes since last assessment.",
        remediationPriority: "LOW",
      },
      {
        controlId: "Req 11.3.2",
        controlName: "Internal Penetration Testing",
        requirement: "Internal penetration testing is performed at least once every 12 months and after any significant infrastructure or system change. Covers the entire CDE perimeter and critical systems.",
        findingRefs: ["VAPT-CRIT-001", "VAPT-CRIT-002", "VAPT-HIGH-001", "VAPT-HIGH-002"],
        status: "COMPLIANT",
        evidenceSummary: "Full internal penetration test conducted. All critical findings documented with exploitation evidence. Attack paths to CDE systems mapped. 4 findings directly relevant to CDE access control.",
        remediationPriority: "LOW",
      },
      {
        controlId: "Req 11.3.2.1",
        controlName: "Penetration Testing — Segmentation Validation",
        requirement: "If segmentation is used to isolate the CDE from other networks, penetration testing is performed to verify the effectiveness of segmentation methods at least every 6 months.",
        findingRefs: ["VAPT-MED-001"],
        status: "GAP",
        evidenceSummary: "CORP-to-MGMT segmentation bypass (VAPT-MED-001) confirmed. VLAN boundary between CORP and MGMT zones is ineffective. DMZ-to-CORP SMB bypass also confirmed. CDE zone isolation cannot be verified as effective.",
        remediationPriority: "CRITICAL",
      },
      {
        controlId: "Req 7.2.1",
        controlName: "Access Control System",
        requirement: "All access rights to system components are reviewed at defined intervals to confirm only authorised access, and that any inappropriate access is removed promptly.",
        findingRefs: ["VAPT-CRIT-002"],
        status: "GAP",
        evidenceSummary: "svc_backup is a member of Domain Admins with no operational justification. 7 Domain Admin accounts identified — no evidence of recent access review. No formal joiner/mover/leaver process identified for privileged accounts.",
        remediationPriority: "CRITICAL",
      },
      {
        controlId: "Req 8.3.1",
        controlName: "User Authentication",
        requirement: "All user IDs and authentication factors for users are managed per the entity's authentication policies and procedures.",
        findingRefs: ["VAPT-CRIT-002"],
        status: "GAP",
        evidenceSummary: "Service account password policy not enforced (no gMSA). svc_backup password cracked in 4 hours. Minimum password length 8 characters — below PCI DSS requirement of 12+ characters for user accounts.",
        remediationPriority: "CRITICAL",
      },
      {
        controlId: "Req 8.6.1",
        controlName: "Application and System Accounts",
        requirement: "Interactive use of application and system accounts is prohibited, access is managed and authenticated using an approved method.",
        findingRefs: ["VAPT-CRIT-002"],
        status: "PARTIAL",
        evidenceSummary: "Service accounts (svc_backup, svc_iis) are not using Managed Service Accounts or gMSA. Interactive login is technically possible. Password management is manual. No evidence of privileged access workstation requirement.",
        remediationPriority: "HIGH",
      },
      {
        controlId: "Req 1.3.1",
        controlName: "Network Access Controls — Inbound",
        requirement: "Inbound traffic to the CDE is restricted to only that traffic which is necessary and all other traffic is explicitly denied.",
        findingRefs: ["VAPT-HIGH-001"],
        status: "PARTIAL",
        evidenceSummary: "SMB (TCP/445) inbound from DMZ to CORP is permitted — not necessary for CDE operations. LLMNR broadcast responses not blocked. Palo Alto NGFW rules reviewed; several ANY-permit rules identified.",
        remediationPriority: "HIGH",
      },
      {
        controlId: "Req 6.3.3",
        controlName: "All System Components Are Protected From Known Vulnerabilities",
        requirement: "All system components are protected from known vulnerabilities by installing applicable security patches/updates. Critical patches installed within 1 month of release.",
        findingRefs: [],
        status: "PARTIAL",
        evidenceSummary: "Tenable scan identified 7 critical/high CVEs across in-scope hosts. Patch cadence not documented. 3 Windows Server hosts running versions without latest CU. SQL Server 2016 without latest service pack.",
        remediationPriority: "HIGH",
      },
      {
        controlId: "Req 10.3.1",
        controlName: "Protect Audit Logs From Destruction and Unauthorized Modifications",
        requirement: "Read access to audit log files is limited to those with a job-related need. Current audit log files are protected to prevent modifications by individuals.",
        findingRefs: [],
        status: "COMPLIANT",
        evidenceSummary: "Splunk log management in place with RBAC. Log forwarding from DCs and servers confirmed. Log integrity not explicitly tested in this engagement scope.",
        remediationPriority: "LOW",
      },
      {
        controlId: "Req 12.10.1",
        controlName: "Incident Response Plan",
        requirement: "An incident response plan exists and is ready to be activated in the event of a system breach. The plan addresses containment, eradication, recovery, communication procedures.",
        findingRefs: [],
        status: "PARTIAL",
        evidenceSummary: "IR plan exists (reviewed in scoping call). No security alerts triggered during 5-day engagement despite full domain compromise. Recommend IR plan tabletop exercise specifically for AD-compromise scenario.",
        remediationPriority: "MEDIUM",
      },
    ],
  },
  {
    id: "CIS_V8",
    name: "CIS Controls v8",
    shortName: "CIS Controls",
    version: "Center for Internet Security Controls, Version 8 (May 2021)",
    totalControls: 8,
    compliant: 1,
    partial: 3,
    gap: 4,
    controls: [
      {
        controlId: "CIS 5.4",
        controlName: "Restrict Administrator Privileges to Dedicated Administrator Accounts",
        requirement: "Restrict administrator privileges to dedicated administrator accounts on enterprise assets. Conduct general computing activities, such as internet browsing, email, and productivity suite use, from the user's primary, non-privileged account.",
        findingRefs: ["VAPT-CRIT-002"],
        status: "GAP",
        evidenceSummary: "svc_backup (a service account) is a Domain Admin. Standard user john.doe escalated to DA via Kerberoasting — no controls prevented this. No evidence of privileged access workstation (PAW) program.",
        remediationPriority: "CRITICAL",
      },
      {
        controlId: "CIS 6.3",
        controlName: "Require MFA for Externally-Exposed Applications",
        requirement: "Require all externally-exposed enterprise or third-party applications to enforce MFA, where supported.",
        findingRefs: [],
        status: "COMPLIANT",
        evidenceSummary: "External-facing VPN confirmed to require MFA. External web applications protected by Azure AD Conditional Access. MFA enforced for all external email access. Meets CIS 6.3 requirements.",
        remediationPriority: "LOW",
      },
      {
        controlId: "CIS 7.1",
        controlName: "Establish and Maintain a Vulnerability Management Process",
        requirement: "Establish and maintain a documented vulnerability management process for enterprise assets. Review and update documentation annually, or when significant enterprise changes occur.",
        findingRefs: ["VAPT-CRIT-001", "VAPT-CRIT-002"],
        status: "PARTIAL",
        evidenceSummary: "Tenable.io in use for automated scanning. No evidence that AD misconfiguration findings (delegation, over-privileged service accounts) are included in vulnerability management scope. Process documentation not reviewed.",
        remediationPriority: "HIGH",
      },
      {
        controlId: "CIS 7.5",
        controlName: "Prioritize Remediation of Vulnerabilities",
        requirement: "Establish and maintain a process to triage vulnerabilities based on the CVSSv3.1 score, compensating controls, and asset criticality. Remediate critical vulnerabilities within 15 days.",
        findingRefs: ["VAPT-CRIT-001", "VAPT-CRIT-002"],
        status: "GAP",
        evidenceSummary: "Critical findings (VAPT-CRIT-001, VAPT-CRIT-002) represent unmanaged risk from delegating and over-privileged service accounts. No evidence of prior identification. Remediation SLA process not established.",
        remediationPriority: "CRITICAL",
      },
      {
        controlId: "CIS 12.2",
        controlName: "Establish and Maintain a Secure Network Architecture",
        requirement: "Establish and maintain a secure network architecture. A secure network architecture must address segmentation, least privilege, and availability, at a minimum.",
        findingRefs: ["VAPT-MED-001", "VAPT-HIGH-001"],
        status: "GAP",
        evidenceSummary: "Network architecture reviewed. CORP-MGMT boundary not enforced. DMZ-CORP allows unnecessary protocols. LLMNR/NBT-NS active on all CORP hosts. Flat network structure within CORP zone enables easy lateral movement.",
        remediationPriority: "HIGH",
      },
      {
        controlId: "CIS 13.3",
        controlName: "Deploy a Network Intrusion Detection Solution",
        requirement: "Deploy a network intrusion detection solution on enterprise assets, where appropriate. Example implementations include host-based IDS or behavioural network analysis tools.",
        findingRefs: ["VAPT-HIGH-001"],
        status: "PARTIAL",
        evidenceSummary: "Darktrace (AI-NDR) deployed but at 44% coverage. No network-level IDS rules for LLMNR poisoning, Kerberoasting TGS patterns, or WMI lateral movement signatures. Palo Alto NGFW IPS enabled but signature base not current.",
        remediationPriority: "HIGH",
      },
      {
        controlId: "CIS 16.1",
        controlName: "Establish and Maintain a Secure Application Development Process",
        requirement: "Establish and maintain a secure application development process.",
        findingRefs: [],
        status: "NOT_APPLICABLE",
        evidenceSummary: "No in-house application development identified in scope. Control not applicable to this infrastructure VAPT engagement.",
        remediationPriority: "LOW",
      },
      {
        controlId: "CIS 18.1",
        controlName: "Establish and Maintain a Penetration Testing Program",
        requirement: "Establish and maintain a penetration testing program appropriate to the size, complexity, and maturity of the enterprise. Penetration testing program includes external and internal penetration testing.",
        findingRefs: [],
        status: "PARTIAL",
        evidenceSummary: "This engagement represents the first formal penetration test conducted by an external party. No formal penetration testing program document exists. Recommend establishing annual schedule, scope criteria, and remediation SLAs.",
        remediationPriority: "MEDIUM",
      },
    ],
  },
];

/* ─── Helpers ─── */
function statusColor(s: ComplianceControl["status"]) {
  if (s === "COMPLIANT")      return "#059669";
  if (s === "PARTIAL")        return "#FF9900";
  if (s === "GAP")            return "#FF4444";
  return "#64748B";
}

function statusLabel(s: ComplianceControl["status"]) {
  if (s === "COMPLIANT")      return "COMPLIANT";
  if (s === "PARTIAL")        return "PARTIAL";
  if (s === "GAP")            return "GAP";
  return "N/A";
}

function prioColor(p: ComplianceControl["remediationPriority"]) {
  if (p === "CRITICAL") return "#FF4444";
  if (p === "HIGH")     return "#FF9900";
  if (p === "MEDIUM")   return "#FFD500";
  return "#64748B";
}

/* ─── Executive Summary Content ─── */
function ExecutiveSummary() {
  return (
    <div style={{ maxWidth: 860 }}>
      <div style={{ marginBottom: 24 }}>
        <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-text-muted)", letterSpacing: 2, marginBottom: 8 }}>EXECUTIVE SUMMARY</div>
        <h2 style={{ fontFamily: "'Inter', sans-serif", fontWeight: 700, fontSize: 22, color: "var(--adv-text)", margin: "0 0 8px 0" }}>
          Internal Network Vulnerability Assessment & Penetration Test
        </h2>
        <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: "var(--adv-text-muted)" }}>
          Client: Acme Corporation Ltd. &nbsp;|&nbsp; Engagement Dates: May 10–14, 2026 &nbsp;|&nbsp; Classification: CONFIDENTIAL
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))", gap: 12, marginBottom: 24 }}>
        {[
          { label: "CRITICAL FINDINGS", value: evidenceStats.critical,        color: "#FF4444" },
          { label: "HIGH FINDINGS",     value: evidenceStats.high,             color: "#FF9900" },
          { label: "EXPLOITED PATHS",   value: evidenceStats.exploitedPaths,   color: "#FF4444" },
          { label: "HOSTS IN SCOPE",    value: evidenceStats.scopeHosts,       color: "var(--adv-accent)" },
          { label: "EVIDENCE ITEMS",    value: evidenceStats.evidenceArtifacts, color: "var(--adv-text)" },
          { label: "AVG CONFIDENCE",    value: `${evidenceStats.avgConfidence}%`, color: "#059669" },
        ].map((s) => (
          <div key={s.label} style={{ background: "var(--adv-panel)", border: "1px solid var(--adv-border)", borderRadius: 6, padding: "12px 14px" }}>
            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 8.5, color: "var(--adv-text-muted)", marginBottom: 6, letterSpacing: 1 }}>{s.label}</div>
            <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 24, fontWeight: 700, color: s.color, lineHeight: 1 }}>{s.value}</div>
          </div>
        ))}
      </div>

      <div style={{ background: "var(--adv-panel)", border: "1px solid var(--adv-border)", borderRadius: 6, padding: "16px 20px", marginBottom: 16 }}>
        <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-text-muted)", marginBottom: 8, letterSpacing: 1 }}>RISK POSTURE</div>
        <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 14, color: "var(--adv-text)", lineHeight: 1.7 }}>
          The internal network penetration test identified a <span style={{ color: "#FF4444", fontWeight: 700 }}>CRITICAL risk posture</span> across the in-scope environment. Two independent attack paths to full domain compromise were validated, with the primary path requiring only standard domain user credentials and publicly available tooling (Kerberoasting). The domain controller DC01 is configured with unconstrained Kerberos delegation — meaning any user who authenticates to a service on DC01 exposes their Ticket Granting Ticket, which can be extracted for persistent, privileged access.
        </div>
        <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 14, color: "var(--adv-text)", lineHeight: 1.7, marginTop: 8 }}>
          Network segmentation between the CORP and MGMT zones is technically ineffective — CORP-zone hosts can reach management infrastructure without passing through enforced controls. Detection coverage for the identified attack techniques is estimated at <span style={{ color: "#FF9900", fontWeight: 700 }}>54% overall</span>, meaning a skilled threat actor could achieve domain compromise without triggering a single alert in the current security stack.
        </div>
      </div>

      <div style={{ background: "var(--adv-panel)", border: "1px solid #FF444430", borderRadius: 6, padding: "14px 18px", marginBottom: 16 }}>
        <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "#FF4444", marginBottom: 10, letterSpacing: 1 }}>TOP 5 CRITICAL FINDINGS — IMMEDIATE ACTION REQUIRED</div>
        {[
          { id: "VAPT-CRIT-001", title: "Unconstrained Kerberos Delegation on DC01",                cvss: "9.8", action: "Disable delegation, enable Protected Users, deploy Credential Guard" },
          { id: "VAPT-CRIT-002", title: "Kerberoastable DA Service Account (svc_backup)",          cvss: "9.1", action: "Remove from Domain Admins, deploy gMSA, enforce AES256 encryption" },
          { id: "VAPT-HIGH-001", title: "LLMNR/NBT-NS Poisoning — NTLM Relay Active",              cvss: "8.1", action: "Disable LLMNR/NBT-NS via GPO, enable SMB signing on all hosts" },
          { id: "VAPT-HIGH-002", title: "WMI Lateral Movement — 18 Hosts Compromised",            cvss: "7.5", action: "Block WMI via FW rules, deploy LAPS, enable process auditing" },
          { id: "VAPT-MED-001",  title: "CORP→MGMT Segmentation Bypass (VLAN Bypass)",            cvss: "6.4", action: "Apply DENY ACL on MGMT ingress for all non-jumphost CORP sources" },
        ].map((f, i) => (
          <div key={f.id} style={{ display: "flex", gap: 12, padding: "8px 0", borderBottom: i < 4 ? "1px solid rgba(37,99,235,0.06)" : "none", alignItems: "flex-start" }}>
            <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-accent)", flexShrink: 0, width: 110 }}>{f.id}</span>
            <div style={{ flex: 1 }}>
              <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 13, color: "var(--adv-text)", fontWeight: 500 }}>{f.title}</div>
              <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-text-muted)", marginTop: 2 }}>Action: {f.action}</div>
            </div>
            <span style={{ fontFamily: "'Inter', sans-serif", fontSize: 14, fontWeight: 700, color: parseFloat(f.cvss) >= 9 ? "#FF4444" : "#FF9900", flexShrink: 0 }}>CVSS {f.cvss}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ─── Compliance Report Content ─── */
function ComplianceReport({ framework, setFramework }: { framework: ComplianceFramework; setFramework: (f: ComplianceFramework) => void }) {
  const [expandedControl, setExpandedControl] = useState<string | null>(null);

  const activeFrameworks = framework === "ALL" ? frameworks : frameworks.filter((f) => f.id === framework);

  return (
    <div>
      {/* Framework Tabs */}
      <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 20 }}>
        <button onClick={() => setFramework("ALL")} style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, padding: "4px 12px", borderRadius: 4, border: "1px solid", borderColor: framework === "ALL" ? "#2563EB" : "#E2E8F0", background: framework === "ALL" ? "rgba(37,99,235,0.08)" : "transparent", color: framework === "ALL" ? "#2563EB" : "#64748B", cursor: "pointer" }}>ALL FRAMEWORKS</button>
        {frameworks.map((f) => (
          <button key={f.id} onClick={() => setFramework(f.id)} style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, padding: "4px 12px", borderRadius: 4, border: "1px solid", borderColor: framework === f.id ? "#2563EB" : "#E2E8F0", background: framework === f.id ? "rgba(37,99,235,0.08)" : "transparent", color: framework === f.id ? "#2563EB" : "#64748B", cursor: "pointer" }}>{f.shortName}</button>
        ))}
      </div>

      {/* Framework scorecards */}
      {(framework === "ALL") && (
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))", gap: 12, marginBottom: 24 }}>
          {frameworks.map((fw) => {
            const pct = Math.round(((fw.compliant + fw.partial * 0.5) / fw.totalControls) * 100);
            return (
              <div key={fw.id} onClick={() => setFramework(fw.id)} style={{ background: "var(--adv-panel)", border: "1px solid var(--adv-border)", borderRadius: 6, padding: "14px 16px", cursor: "pointer", transition: "border-color 0.15s" }}>
                <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: "var(--adv-text)", marginBottom: 4 }}>{fw.name}</div>
                <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", marginBottom: 10 }}>{fw.version.slice(0, 50)}…</div>
                <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
                  <div style={{ flex: 1, height: 5, background: "rgba(37,99,235,0.06)", borderRadius: 3, overflow: "hidden" }}>
                    <div style={{ height: "100%", width: `${pct}%`, background: pct >= 70 ? "#059669" : pct >= 50 ? "#FF9900" : "#FF4444" }} />
                  </div>
                  <span style={{ fontFamily: "'Inter', sans-serif", fontSize: 14, fontWeight: 700, color: pct >= 70 ? "#059669" : pct >= 50 ? "#FF9900" : "#FF4444" }}>{pct}%</span>
                </div>
                <div style={{ display: "flex", gap: 12 }}>
                  <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "#059669" }}>✓ {fw.compliant}</span>
                  <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "#FF9900" }}>~ {fw.partial}</span>
                  <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "#FF4444" }}>✗ {fw.gap}</span>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Control details */}
      {activeFrameworks.map((fw) => (
        <div key={fw.id} style={{ marginBottom: 32 }}>
          <div style={{ marginBottom: 14 }}>
            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 13, color: "var(--adv-accent)", marginBottom: 2 }}>{fw.name}</div>
            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-text-muted)" }}>{fw.version}</div>
          </div>

          <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            {fw.controls.map((ctrl) => {
              const isExpanded = expandedControl === `${fw.id}-${ctrl.controlId}`;
              return (
                <div
                  key={ctrl.controlId}
                  style={{
                    background: "var(--adv-panel)",
                    border: "1px solid var(--adv-border)",
                    borderLeft: `3px solid ${statusColor(ctrl.status)}`,
                    borderRadius: 4,
                    overflow: "hidden",
                  }}
                >
                  <div
                    onClick={() => setExpandedControl(isExpanded ? null : `${fw.id}-${ctrl.controlId}`)}
                    style={{ padding: "10px 14px", cursor: "pointer", display: "flex", alignItems: "center", gap: 10 }}
                  >
                    {isExpanded ? <ChevronDown size={13} color="#2563EB" /> : <ChevronRight size={13} color="#64748B" />}
                    <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-accent)", width: 130, flexShrink: 0 }}>{ctrl.controlId}</span>
                    <span style={{ fontFamily: "'Inter', sans-serif", fontSize: 13, color: "var(--adv-text)", flex: 1, fontWeight: 500 }}>{ctrl.controlName}</span>
                    <div style={{ display: "flex", alignItems: "center", gap: 8, flexShrink: 0 }}>
                      {ctrl.findingRefs.length > 0 && (
                        <div style={{ display: "flex", gap: 4 }}>
                          {ctrl.findingRefs.map((ref) => (
                            <span key={ref} style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 8, color: "#FF4444", padding: "1px 4px", border: "1px solid #FF444440", borderRadius: 2 }}>{ref}</span>
                          ))}
                        </div>
                      )}
                      <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: prioColor(ctrl.remediationPriority), width: 55, textAlign: "right" }}>{ctrl.remediationPriority}</span>
                      <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: statusColor(ctrl.status), padding: "2px 6px", background: `${statusColor(ctrl.status)}20`, borderRadius: 3, width: 80, textAlign: "center" }}>{statusLabel(ctrl.status)}</span>
                    </div>
                  </div>

                  {isExpanded && (
                    <div style={{ padding: "0 14px 14px 37px", borderTop: "1px solid var(--adv-border)" }}>
                      <div style={{ paddingTop: 10, display: "flex", flexDirection: "column", gap: 10 }}>
                        <div>
                          <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", marginBottom: 4, letterSpacing: 1 }}>REQUIREMENT</div>
                          <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 13, color: "var(--adv-text)", lineHeight: 1.6, padding: "8px 12px", background: "var(--adv-bg)", borderRadius: 3, border: "1px solid var(--adv-border)" }}>{ctrl.requirement}</div>
                        </div>
                        <div>
                          <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", marginBottom: 4, letterSpacing: 1 }}>ASSESSMENT EVIDENCE</div>
                          <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: "var(--adv-text)", lineHeight: 1.6, padding: "8px 12px", background: "var(--adv-bg)", borderRadius: 3, border: `1px solid ${statusColor(ctrl.status)}30` }}>{ctrl.evidenceSummary}</div>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      ))}
    </div>
  );
}

/* ─── Evidence Summary Content ─── */
function EvidenceSummary() {
  return (
    <div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 12, marginBottom: 24 }}>
        {[
          { label: "TOTAL FINDINGS",        value: evidenceStats.totalFindings,      color: "var(--adv-text)" },
          { label: "EVIDENCE ARTIFACTS",    value: evidenceStats.evidenceArtifacts,  color: "var(--adv-accent)" },
          { label: "COMMAND OUTPUTS",       value: evidenceStats.commandOutputs,     color: "var(--adv-accent)" },
          { label: "SCREENSHOTS",           value: evidenceStats.screenshotsCount,   color: "var(--adv-accent)" },
          { label: "AVG CONFIDENCE",        value: `${evidenceStats.avgConfidence}%`,color: "#059669" },
          { label: "SCOPE (HOSTS)",         value: evidenceStats.scopeHosts,         color: "var(--adv-text)" },
          { label: "ENGAGEMENT (DAYS)",     value: evidenceStats.engagementDays,     color: "var(--adv-text)" },
          { label: "OPEN FINDINGS",         value: evidenceStats.openCount,          color: "#FF4444" },
        ].map((s) => (
          <div key={s.label} style={{ background: "var(--adv-panel)", border: "1px solid var(--adv-border)", borderRadius: 6, padding: "14px 16px" }}>
            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", marginBottom: 6, letterSpacing: 1 }}>{s.label}</div>
            <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 24, fontWeight: 700, color: s.color, lineHeight: 1 }}>{s.value}</div>
          </div>
        ))}
      </div>

      {/* Severity Distribution */}
      <div style={{ background: "var(--adv-panel)", border: "1px solid var(--adv-border)", borderRadius: 6, padding: "16px 20px", marginBottom: 16 }}>
        <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: "var(--adv-text)", marginBottom: 14, letterSpacing: 1 }}>FINDING DISTRIBUTION BY SEVERITY</div>
        {[
          { label: "CRITICAL", value: evidenceStats.critical, total: evidenceStats.totalFindings, color: "#FF4444" },
          { label: "HIGH",     value: evidenceStats.high,     total: evidenceStats.totalFindings, color: "#FF9900" },
          { label: "MEDIUM",   value: evidenceStats.medium,   total: evidenceStats.totalFindings, color: "#FFD500" },
          { label: "LOW",      value: evidenceStats.low,      total: evidenceStats.totalFindings, color: "var(--adv-accent)" },
        ].map((row) => (
          <div key={row.label} style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 8 }}>
            <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: row.color, width: 70, flexShrink: 0 }}>{row.label}</span>
            <div style={{ flex: 1, height: 8, background: "rgba(37,99,235,0.06)", borderRadius: 4, overflow: "hidden" }}>
              <div style={{ height: "100%", width: `${(row.value / row.total) * 100}%`, background: row.color, borderRadius: 4 }} />
            </div>
            <span style={{ fontFamily: "'Inter', sans-serif", fontSize: 14, fontWeight: 700, color: row.color, width: 20 }}>{row.value}</span>
            <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", width: 40 }}>{Math.round((row.value / row.total) * 100)}%</span>
          </div>
        ))}
      </div>

      {/* Scope */}
      <div style={{ background: "var(--adv-panel)", border: "1px solid var(--adv-border)", borderRadius: 6, padding: "14px 18px" }}>
        <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: "var(--adv-text)", marginBottom: 10, letterSpacing: 1 }}>ENGAGEMENT SCOPE</div>
        {[
          { label: "Target Networks",    value: evidenceStats.scopeSubnets },
          { label: "Total Hosts",        value: evidenceStats.scopeHosts.toString() },
          { label: "Engagement Window",  value: "May 10–14, 2026 (5 business days)" },
          { label: "Testing Methodology", value: "Black-box internal + Grey-box AD assessment" },
          { label: "Tools Used",         value: "Nmap, Nessus, Responder, Impacket, Mimikatz, BloodHound, CrackMapExec, Hashcat" },
          { label: "Rules of Engagement", value: "No DoS attacks, no data exfiltration, business-hours testing only, pre-approved IPs" },
        ].map((row, i, arr) => (
          <div key={row.label} style={{ display: "flex", gap: 16, padding: "6px 0", borderBottom: i < arr.length - 1 ? "1px solid rgba(37,99,235,0.06)" : "none" }}>
            <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-text-muted)", width: 180, flexShrink: 0 }}>{row.label}</span>
            <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-text)", lineHeight: 1.5 }}>{row.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ─── Main Page ─── */
export default function ReportsPage() {
  const { success } = useToast();
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [reportType, setReportType]   = useState<ReportType>("executive");
  const [framework, setFramework]     = useState<ComplianceFramework>("ALL");

  const exportPDF = useCallback(() => {
    success("Exporting PDF", "Print dialog opening — save as PDF for best results.");
    setTimeout(() => window.print(), 300);
  }, [success]);

  const totalGaps     = frameworks.reduce((sum, f) => sum + f.gap, 0);
  const totalPartial  = frameworks.reduce((sum, f) => sum + f.partial, 0);
  const totalControls = frameworks.reduce((sum, f) => sum + f.totalControls, 0);

  return (
    <div
      style={{
        display: "flex",
        height: "100vh",
        background: "var(--adv-bg)",
        fontFamily: "'Inter', sans-serif",
        overflow: "hidden",
      }}
    >
      {sidebarOpen && (
        <div className="md:hidden" onClick={() => setSidebarOpen(false)} style={{ position: "fixed", inset: 0, background: "rgba(15,23,42,0.75)", zIndex: 40 }} />
      )}

      <Sidebar open={sidebarOpen} onClose={() => setSidebarOpen(false)} />

      <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
        {/* Header */}
        <header style={{ height: 52, borderBottom: "1px solid var(--adv-border)", display: "flex", alignItems: "center", justifyContent: "space-between", padding: "0 20px", flexShrink: 0, background: "linear-gradient(90deg, rgba(37,99,235,0.06) 0%, rgba(37,99,235,0.05) 40%, var(--adv-bg) 100%)", boxShadow: "0 1px 0 #CBD5E1, 0 2px 16px rgba(37,99,235,0.06)" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <button className="md:hidden" onClick={() => setSidebarOpen(true)} style={{ background: "none", border: "none", cursor: "pointer", padding: 0 }}>
              <Menu size={20} color="#2563EB" />
            </button>
            <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 18, color: "var(--adv-accent)", letterSpacing: 3 }}>ADVERSA</span>
            <span style={{ color: "var(--adv-border)" }}>|</span>
            <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: "var(--adv-text-muted)" }}>REPORTS v0.9.1</span>
            <FileText size={14} color="#2563EB" style={{ marginLeft: 4 }} />
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <button
              onClick={exportPDF}
              className="no-print"
              style={{
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: 10,
                padding: "5px 14px",
                borderRadius: 4,
                border: "1px solid #2563EB",
                background: "rgba(37,99,235,0.08)",
                color: "var(--adv-accent)",
                cursor: "pointer",
                display: "flex",
                alignItems: "center",
                gap: 6,
              }}
            >
              <Printer size={12} />
              EXPORT PDF
            </button>
          </div>
        </header>

        {/* Report type selector */}
        <div style={{ display: "flex", borderBottom: "1px solid var(--adv-border)", flexShrink: 0, background: "linear-gradient(90deg, rgba(37,99,235,0.06) 0%, rgba(37,99,235,0.05) 40%, var(--adv-bg) 100%)", boxShadow: "0 1px 0 #CBD5E1, 0 2px 16px rgba(37,99,235,0.06)" }}>
          {(["executive", "technical", "compliance", "evidence"] as ReportType[]).map((t) => {
            const labels: Record<ReportType, string> = {
              executive:  "Executive Summary",
              technical:  "Technical Findings",
              compliance: "Compliance Mapping",
              evidence:   "Evidence Summary",
            };
            return (
              <button
                key={t}
                onClick={() => setReportType(t)}
                style={{
                  padding: "11px 22px",
                  background: reportType === t ? "rgba(37,99,235,0.04)" : "transparent",
                  border: "none",
                  borderBottom: reportType === t ? "2px solid #2563EB" : "2px solid transparent",
                  color: reportType === t ? "#0F172A" : "#64748B",
                  fontFamily: "'JetBrains Mono', monospace",
                  fontSize: 11,
                  cursor: "pointer",
                  whiteSpace: "nowrap",
                  letterSpacing: 0.5,
                }}
              >
                {labels[t]}
              </button>
            );
          })}
        </div>

        {/* Side-by-side: quick stats + report content */}
        <div style={{ flex: 1, display: "flex", overflow: "hidden" }}>
          {/* Left: stats rail */}
          <aside
            className="hidden xl:flex"
            style={{
              width: 220,
              borderRight: "1px solid var(--adv-border)",
              flexDirection: "column",
              flexShrink: 0,
              overflow: "hidden",
            }}
          >
            <div style={{ padding: "12px 14px", borderBottom: "1px solid var(--adv-border)", fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-text)", letterSpacing: 1 }}>
              REPORT STATS
            </div>
            <div style={{ flex: 1, overflowY: "auto", padding: "8px 0" }}>
              {[
                { label: "Total Findings", value: evidenceStats.totalFindings, color: "var(--adv-text)" },
                { label: "Critical",       value: evidenceStats.critical,       color: "#FF4444" },
                { label: "High",           value: evidenceStats.high,           color: "#FF9900" },
                { label: "Medium",         value: evidenceStats.medium,         color: "#FFD500" },
                { label: "Exploited",      value: evidenceStats.exploitedPaths, color: "#FF4444" },
                { label: "Open",           value: evidenceStats.openCount,      color: "#FF4444" },
                { label: "In Progress",    value: evidenceStats.inProgressCount, color: "#FF9900" },
                { label: "Remediated",     value: evidenceStats.remediatedCount, color: "#059669" },
                { label: "Evidence Items", value: evidenceStats.evidenceArtifacts, color: "var(--adv-accent)" },
                { label: "Controls Assessed", value: totalControls,            color: "var(--adv-text)" },
                { label: "Compliance Gaps", value: totalGaps,                  color: "#FF4444" },
                { label: "Partial Comply", value: totalPartial,                color: "#FF9900" },
              ].map((s, i, arr) => (
                <div key={s.label} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "7px 14px", borderBottom: i < arr.length - 1 ? "1px solid rgba(37,99,235,0.06)" : "none" }}>
                  <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-text-muted)" }}>{s.label}</span>
                  <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: s.color, fontWeight: 600 }}>{s.value}</span>
                </div>
              ))}
            </div>
          </aside>

          {/* Main report content */}
          <div style={{ flex: 1, overflowY: "auto", padding: 24 }}>
            {reportType === "executive"  && <ExecutiveSummary />}
            {reportType === "compliance" && <ComplianceReport framework={framework} setFramework={setFramework} />}
            {reportType === "evidence"   && <EvidenceSummary />}
            {reportType === "technical"  && (
              <div style={{ maxWidth: 860 }}>
                <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-text-muted)", letterSpacing: 2, marginBottom: 14 }}>TECHNICAL FINDINGS REPORT</div>
                <div style={{ background: "var(--adv-panel)", border: "1px solid var(--adv-border)", borderRadius: 6, padding: "14px 18px" }}>
                  <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: "var(--adv-accent)", marginBottom: 6 }}>FINDINGS DETAIL</div>
                  <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 14, color: "var(--adv-text)", lineHeight: 1.6 }}>
                    Full technical details including command outputs, exploitation evidence, and step-by-step attack paths are documented in the <strong style={{ color: "var(--adv-accent)" }}>Findings</strong> module. Navigate to Findings in the sidebar to view per-finding evidence, CVSS scores, attack paths, and remediation guidance.
                  </div>
                  <div style={{ marginTop: 12, display: "flex", gap: 12 }}>
                    <a href="/findings" style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-accent)", textDecoration: "none", padding: "5px 14px", border: "1px solid #2563EB", borderRadius: 4, background: "rgba(37,99,235,0.08)" }}>
                      → OPEN FINDINGS MODULE
                    </a>
                  </div>
                </div>
                <div style={{ marginTop: 16, fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-text-muted)", letterSpacing: 1, marginBottom: 8 }}>FINDING INDEX</div>
                {[
                  { id: "VAPT-CRIT-001", title: "Unconstrained Kerberos Delegation on DC01",     cvss: "9.8", cat: "Active Directory" },
                  { id: "VAPT-CRIT-002", title: "Kerberoastable Service Account → Domain Admin",  cvss: "9.1", cat: "Active Directory" },
                  { id: "VAPT-HIGH-001", title: "LLMNR/NBT-NS Poisoning — NTLM Relay",           cvss: "8.1", cat: "Protocol Abuse"   },
                  { id: "VAPT-HIGH-002", title: "Lateral Movement via WMI (18 hosts)",            cvss: "7.5", cat: "Lateral Movement" },
                  { id: "VAPT-MED-001",  title: "Network Segmentation Bypass CORP→MGMT",         cvss: "6.4", cat: "Segmentation"     },
                ].map((f, i) => (
                  <div key={f.id} style={{ display: "flex", gap: 12, padding: "9px 14px", background: "var(--adv-panel)", border: "1px solid var(--adv-border)", borderRadius: 4, marginBottom: 6, alignItems: "center" }}>
                    <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-accent)", width: 110, flexShrink: 0 }}>{f.id}</span>
                    <span style={{ fontFamily: "'Inter', sans-serif", fontSize: 13, color: "var(--adv-text)", flex: 1 }}>{f.title}</span>
                    <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)" }}>{f.cat}</span>
                    <span style={{ fontFamily: "'Inter', sans-serif", fontSize: 13, fontWeight: 700, color: parseFloat(f.cvss) >= 9 ? "#FF4444" : "#FF9900" }}>CVSS {f.cvss}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Footer */}
        <footer style={{ height: 32, borderTop: "1px solid var(--adv-border)", background: "linear-gradient(90deg, rgba(37,99,235,0.06) 0%, var(--adv-panel) 60%)", display: "flex", alignItems: "center", padding: "0 20px", gap: 16, flexShrink: 0 }}>
          <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-text-muted)" }}>FRAMEWORKS: <span style={{ color: "var(--adv-accent)" }}>{frameworks.length}</span></span>
          <span style={{ color: "var(--adv-border)" }}>|</span>
          <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-text-muted)" }}>CONTROLS: <span style={{ color: "var(--adv-text)" }}>{totalControls}</span></span>
          <span style={{ color: "var(--adv-border)" }}>|</span>
          <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-text-muted)" }}>GAPS: <span style={{ color: "#FF4444" }}>{totalGaps}</span></span>
          <span style={{ color: "var(--adv-border)" }}>|</span>
          <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-text-muted)" }}>PARTIAL: <span style={{ color: "#FF9900" }}>{totalPartial}</span></span>
          <span style={{ color: "var(--adv-border)" }}>|</span>
          <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-text-muted)" }}>REPORT DATE: <span style={{ color: "var(--adv-text)" }}>2026-05-12</span></span>
        </footer>
      </div>
    </div>
  );
}
