import { NextResponse } from "next/server";

// Simulates LDAPEnumerator, KerberoastChecker, ASREPRoastChecker,
// NTLMRelayChecker, and ADCSChecker results for the AD assessment module.

export async function GET() {
  const data = {
    domain: {
      name: "corp.local",
      netbios: "CORP",
      dcs: ["DC01.corp.local (PDC)", "DC02.corp.local"],
      functionalLevel: "Windows Server 2016",
      totalUsers: 842,
      totalComputers: 317,
      totalGroups: 94,
      domainAdmins: 7,
      enumeratedAt: "2026-05-10T09:32:00Z",
      anonymousBindEnabled: true,
    },

    // LDAPEnumerator.get_aces — ACL abuse opportunities
    aclFindings: [
      { object: "CN=Domain Admins,CN=Users,DC=corp,DC=local", trustee: "helpdesk1", right: "GenericWrite", inherited: false, risk: "CRITICAL" },
      { object: "CN=Administrator,CN=Users,DC=corp,DC=local", trustee: "svc_hr", right: "WriteDACL", inherited: false, risk: "HIGH" },
      { object: "OU=ServiceAccounts,DC=corp,DC=local", trustee: "net_admin", right: "GenericAll", inherited: false, risk: "CRITICAL" },
    ],

    // KerberoastChecker.get_spn_accounts
    kerberoastAccounts: [
      { samAccountName: "svc_backup", spn: "MSSQLSvc/SQL01.corp.local:1433", passwordLastSet: "2024-01-15", hashType: "RC4-HMAC (Etype 23)", tgsHashFragment: "$krb5tgs$23$*svc_backup$corp.local$...[truncated for evidence]", crackable: true, groups: ["Domain Users", "Backup Operators"] },
      { samAccountName: "svc_iis",    spn: "HTTP/web01.corp.local",           passwordLastSet: "2024-03-20", hashType: "RC4-HMAC (Etype 23)", tgsHashFragment: "$krb5tgs$23$*svc_iis$corp.local$...[truncated for evidence]",    crackable: true, groups: ["Domain Users"] },
      { samAccountName: "svc_monitor",spn: "WSMAN/mon01.corp.local",          passwordLastSet: "2025-06-10", hashType: "AES256-CTS-HMAC-SHA1", tgsHashFragment: null, crackable: false, groups: ["Domain Users"] },
    ],

    // ASREPRoastChecker.get_no_preauth_accounts
    asrepAccounts: [
      { samAccountName: "testuser01", dn: "CN=testuser01,OU=TestAccounts,DC=corp,DC=local", asrepHashFragment: "$krb5asrep$23$testuser01@corp.local:...[truncated]", hashObtained: true, cracked: true  },
      { samAccountName: "svc_legacy", dn: "CN=svc_legacy,OU=ServiceAccounts,DC=corp,DC=local", asrepHashFragment: "$krb5asrep$23$svc_legacy@corp.local:...[truncated]", hashObtained: true, cracked: false },
    ],

    // NTLMRelayChecker.check_smb_signing
    smbSigningHosts: [
      { ip: "10.0.1.10", hostname: "WS-042",   smbSigningEnabled: false, smbSigningRequired: false, risk: "HIGH" },
      { ip: "10.0.1.11", hostname: "WS-128",   smbSigningEnabled: false, smbSigningRequired: false, risk: "HIGH" },
      { ip: "10.0.1.20", hostname: "SVC-SQL",  smbSigningEnabled: true,  smbSigningRequired: false, risk: "MEDIUM" },
      { ip: "10.0.0.10", hostname: "DC01",     smbSigningEnabled: true,  smbSigningRequired: true,  risk: "LOW" },
      { ip: "10.0.0.11", hostname: "DC02",     smbSigningEnabled: true,  smbSigningRequired: true,  risk: "LOW" },
      { ip: "10.0.1.30", hostname: "FS-01",    smbSigningEnabled: false, smbSigningRequired: false, risk: "HIGH" },
    ],

    // NTLMRelayChecker.check_ldap_signing
    ldapSigning: {
      dcIp: "10.0.0.10",
      ldapSigningRequired: false,
      ldapChannelBindingRequired: false,
      risk: "HIGH",
    },

    // ADCSChecker results
    adcsTemplates: [
      {
        name: "UserAuthentication",
        displayName: "User Authentication",
        oid: "1.3.6.1.4.1.311.21.8.123",
        enrolleeSuppliesSubject: true,
        lowPrivEnrollment: true,
        lowPrivWriteAccess: false,
        ntlmRelayable: false,
        esc1: true, esc4: false, esc8: false,
        enrollmentRights: ["Domain Users"],
        ekus: ["Client Authentication", "Smart Card Logon"],
        risk: "CRITICAL",
      },
      {
        name: "WebServer",
        displayName: "Web Server",
        oid: "1.3.6.1.4.1.311.21.8.456",
        enrolleeSuppliesSubject: false,
        lowPrivEnrollment: false,
        lowPrivWriteAccess: true,
        ntlmRelayable: false,
        esc1: false, esc4: true, esc8: false,
        enrollmentRights: ["Domain Admins", "Enterprise Admins"],
        ekus: ["Server Authentication"],
        risk: "HIGH",
      },
    ],

    // ADCSChecker.check_esc8 — CA HTTP endpoint
    adcsCA: {
      name: "corp-CA",
      webEnrollmentUrl: "http://10.0.0.15/certsrv",
      ntlmAuthEnabled: true,
      esc8Vulnerable: true,
      risk: "CRITICAL",
    },

    delegationEntries: [
      { accountName: "DC01$",   accountType: "computer", delegationType: "Unconstrained", allowedTo: "ANY (TrustedForDelegation = TRUE)", risk: "CRITICAL" },
      { accountName: "svc_iis", accountType: "user",     delegationType: "Constrained",   allowedTo: "HTTP/web01.corp.local",            risk: "MEDIUM"   },
      { accountName: "WS-042$", accountType: "computer", delegationType: "Unconstrained", allowedTo: "ANY (TrustedForDelegation = TRUE)", risk: "CRITICAL" },
    ],

    privilegedGroups: [
      { name: "Domain Admins",     memberCount: 7, members: ["Administrator", "john.admin", "svc_backup", "jane.doe", "backup_svc", "sqlsa", "deploy_svc"], risk: "CRITICAL" },
      { name: "Enterprise Admins", memberCount: 2, members: ["Administrator", "john.admin"], risk: "CRITICAL" },
      { name: "Backup Operators",  memberCount: 4, members: ["svc_backup", "BKUP01$", "waldo.hicks", "net_admin"], risk: "HIGH" },
      { name: "Server Operators",  memberCount: 3, members: ["svc_deploy", "net_admin", "WS-042$"], risk: "HIGH" },
      { name: "Account Operators", memberCount: 5, members: ["helpdesk1", "helpdesk2", "helpdesk3", "svc_hr", "admin_temp"], risk: "MEDIUM" },
    ],

    passwordPolicy: [
      { attribute: "Min Password Length",    value: "8 chars",      status: "FAIL", note: "Below 12 char recommendation" },
      { attribute: "Password History",        value: "10 passwords", status: "PASS", note: "Meets baseline" },
      { attribute: "Max Password Age",        value: "90 days",      status: "PASS", note: "Acceptable" },
      { attribute: "Complexity Requirement",  value: "Enabled",      status: "PASS", note: "" },
      { attribute: "Account Lockout",         value: "5 attempts",   status: "PASS", note: "Meets baseline" },
      { attribute: "Fine-Grained PSO",        value: "None found",   status: "WARN", note: "No PSO for privileged accounts" },
      { attribute: "Reversible Encryption",   value: "Disabled",     status: "PASS", note: "" },
      { attribute: "Kerberos Encryption",     value: "RC4 + AES",    status: "WARN", note: "RC4 still allowed (CVE-2022-37967)" },
    ],

    trustRelationships: [
      { domain: "dev.corp.local", direction: "Bidirectional", type: "Forest",   sidFiltering: false, risk: "HIGH" },
      { domain: "partner.ext",    direction: "Inbound",       type: "External", sidFiltering: true,  risk: "LOW"  },
      { domain: "legacy.corp",    direction: "Bidirectional", type: "External", sidFiltering: false, risk: "HIGH" },
    ],
  };

  return NextResponse.json(data);
}
