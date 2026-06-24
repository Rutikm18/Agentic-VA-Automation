// Detection Validation Engine
// AttackLogger · SIEMQueryEngine · EDRQueryEngine · DetectionCorrelator · SigmaRuleGenerator

export type DetectionOutcome = "detected" | "prevented" | "missed";

// ── AttackLogger ─────────────────────────────────────────────────────────────

export interface AttackAction {
  id: string;
  engagementId: string;
  findingId?: string;
  mitreTechnique: string;
  mitreId: string;
  targetIp: string;
  timestamp: string;          // ISO-8601
  actionDetail: string;
  tactic: string;
  actor: string;
}

// Mocked attack timeline — AttackLogger.log_action results
const ATTACK_TIMELINE: AttackAction[] = [
  { id: "ATK-001", engagementId: "ENG-001", findingId: "VAPT-HIGH-001",  mitreId: "T1557.001", mitreTechnique: "LLMNR/NBT-NS Poisoning & Relay", tactic: "Credential Access",    targetIp: "10.0.1.10", timestamp: "2026-05-10T09:05:00Z", actionDetail: "Responder started; LLMNR broadcast poisoning on eth0. Captured NTLMv2 hash from WS-042 within 12s.", actor: "analyst@adversa.io" },
  { id: "ATK-002", engagementId: "ENG-001", findingId: "VAPT-CRIT-002",  mitreId: "T1558.003", mitreTechnique: "Kerberoasting",                   tactic: "Credential Access",    targetIp: "10.0.1.20", timestamp: "2026-05-10T09:18:00Z", actionDetail: "GetUserSPNs.py executed. 3 TGS hashes captured for svc_backup, svc_iis, svc_monitor.", actor: "analyst@adversa.io" },
  { id: "ATK-003", engagementId: "ENG-001", findingId: "VAPT-CRIT-001",  mitreId: "T1134.001", mitreTechnique: "Token Impersonation/Theft",        tactic: "Privilege Escalation", targetIp: "10.0.1.10", timestamp: "2026-05-10T09:35:00Z", actionDetail: "Mimikatz sekurlsa::tickets executed on WS-042. DA token extracted from memory.", actor: "analyst@adversa.io" },
  { id: "ATK-004", engagementId: "ENG-001",                              mitreId: "T1003.006", mitreTechnique: "DCSync",                            tactic: "Credential Access",    targetIp: "10.0.0.10", timestamp: "2026-05-10T09:52:00Z", actionDetail: "secretsdump.py /drsuapi DCSync against DC01. All domain hashes exfiltrated.", actor: "analyst@adversa.io" },
  { id: "ATK-005", engagementId: "ENG-001", findingId: "VAPT-HIGH-002",  mitreId: "T1021.003", mitreTechnique: "DCOM Remote Execution",             tactic: "Lateral Movement",     targetIp: "10.0.1.11", timestamp: "2026-05-10T10:10:00Z", actionDetail: "WMI /node:WS-128 remote process creation via COMObject MMC20.Application.", actor: "analyst@adversa.io" },
  { id: "ATK-006", engagementId: "ENG-001",                              mitreId: "T1550.002", mitreTechnique: "Pass the Hash",                     tactic: "Lateral Movement",     targetIp: "10.0.0.20", timestamp: "2026-05-10T10:28:00Z", actionDetail: "psexec.py with NTLM hash for local admin account. Authenticated to MGMT-SRV.", actor: "analyst@adversa.io" },
  { id: "ATK-007", engagementId: "ENG-001",                              mitreId: "T1110.002", mitreTechnique: "Password Cracking",                  tactic: "Credential Access",    targetIp: "10.0.0.10", timestamp: "2026-05-10T11:00:00Z", actionDetail: "Offline hashcat cracking of RC4 TGS for svc_backup. Password 'Summer2023!' cracked in 4min.", actor: "analyst@adversa.io" },
  { id: "ATK-008", engagementId: "ENG-001",                              mitreId: "T1055",     mitreTechnique: "Process Injection",                  tactic: "Defense Evasion",      targetIp: "10.0.1.10", timestamp: "2026-05-10T10:05:00Z", actionDetail: "Injected shellcode into svchost.exe via NtCreateThreadEx for C2 persistence.", actor: "analyst@adversa.io" },
];

// ── Mocked SIEM/EDR responses (SIEMQueryEngine + EDRQueryEngine) ─────────────

export interface SIEMAlert {
  id: string; source: "Splunk" | "Sentinel" | "Elastic";
  timestamp: string; targetIp: string; mitreId: string;
  ruleName: string; severity: string; splQuery?: string; kqlQuery?: string;
}

export interface EDRDetection {
  id: string; source: "CrowdStrike" | "MicrosoftDefender" | "SentinelOne";
  timestamp: string; targetIp: string; mitreId: string;
  alertName: string; prevented: boolean; confidence: number;
}

// SIEMQueryEngine.query_alerts — mocked Splunk/Sentinel/Elastic results
const SIEM_ALERTS: SIEMAlert[] = [
  { id: "SIEM-001", source: "Splunk",   timestamp: "2026-05-10T09:54:10Z", targetIp: "10.0.0.10", mitreId: "T1003.006", ruleName: "KRBTGT-TGS-001",    severity: "HIGH",   splQuery: "index=wineventlog EventCode=4662 ObjectType=*replication* | stats count by src_ip" },
  { id: "SIEM-002", source: "Splunk",   timestamp: "2026-05-10T09:19:30Z", targetIp: "10.0.1.20", mitreId: "T1558.003", ruleName: "KERBEROAST-TGS-REQ", severity: "MEDIUM", splQuery: "index=wineventlog EventCode=4769 TicketEncryptionType=0x17 | bucket _time span=1h | stats count by src_ip" },
  { id: "SIEM-003", source: "Sentinel", timestamp: "2026-05-10T10:30:00Z", targetIp: "10.0.0.20", mitreId: "T1550.002", ruleName: "PTH-DETECTION",      severity: "HIGH",   kqlQuery: "SecurityEvent | where EventID == 4624 and LogonType == 3 and AuthenticationPackageName == 'NTLM'" },
  { id: "SIEM-004", source: "Splunk",   timestamp: "2026-05-10T10:11:00Z", targetIp: "10.0.1.11", mitreId: "T1021.003", ruleName: "WMI-REMOTE-EXEC",    severity: "HIGH",   splQuery: "index=wineventlog EventCode=4688 NewProcessName=*wmic* CommandLine=*/node*" },
];

// EDRQueryEngine.query_detections — mocked EDR results
const EDR_DETECTIONS: EDRDetection[] = [
  { id: "EDR-001", source: "CrowdStrike",       timestamp: "2026-05-10T09:53:50Z", targetIp: "10.0.0.10", mitreId: "T1003.006", alertName: "DCSYNC-DETECTED",        prevented: false, confidence: 97 },
  { id: "EDR-002", source: "CrowdStrike",       timestamp: "2026-05-10T10:06:00Z", targetIp: "10.0.1.10", mitreId: "T1055",     alertName: "PROCESS-INJECTION-NTAPI",prevented: true,  confidence: 91 },
  { id: "EDR-003", source: "MicrosoftDefender", timestamp: "2026-05-10T10:29:30Z", targetIp: "10.0.0.20", mitreId: "T1550.002", alertName: "SUSPECTED-PTH",          prevented: false, confidence: 78 },
  { id: "EDR-004", source: "CrowdStrike",       timestamp: "2026-05-10T10:10:45Z", targetIp: "10.0.1.11", mitreId: "T1021.003", alertName: "WMI-LATERAL-MOVE",       prevented: false, confidence: 84 },
];

// ── DetectionCorrelator ──────────────────────────────────────────────────────

export interface DetectionResult {
  attackActionId: string;
  mitreId: string;
  mitreTechnique: string;
  tactic: string;
  targetIp: string;
  timestamp: string;
  outcome: DetectionOutcome;
  matchedSiemAlerts: SIEMAlert[];
  matchedEdrDetections: EDRDetection[];
  windowMinutes: number;
}

export interface CoverageStats {
  totalTechniques: number;
  detected: number;
  prevented: number;
  missed: number;
  coveragePct: number;
}

const WINDOW_MS = 5 * 60 * 1000; // ±5 minutes

function isInWindow(attackTs: string, alertTs: string): boolean {
  return Math.abs(new Date(attackTs).getTime() - new Date(alertTs).getTime()) <= WINDOW_MS;
}

function isSameHost(ip1: string, ip2: string): boolean {
  return ip1 === ip2;
}

// DetectionCorrelator.correlate
function correlate(): DetectionResult[] {
  return ATTACK_TIMELINE.map((action) => {
    const matchedSiem = SIEM_ALERTS.filter(
      (a) => a.mitreId === action.mitreId &&
             isSameHost(a.targetIp, action.targetIp) &&
             isInWindow(action.timestamp, a.timestamp)
    );
    const matchedEdr = EDR_DETECTIONS.filter(
      (d) => d.mitreId === action.mitreId &&
             isSameHost(d.targetIp, action.targetIp) &&
             isInWindow(action.timestamp, d.timestamp)
    );

    const prevented = matchedEdr.some((d) => d.prevented);
    const detected  = matchedSiem.length > 0 || matchedEdr.length > 0;

    const outcome: DetectionOutcome = prevented ? "prevented" : detected ? "detected" : "missed";

    return {
      attackActionId: action.id,
      mitreId: action.mitreId,
      mitreTechnique: action.mitreTechnique,
      tactic: action.tactic,
      targetIp: action.targetIp,
      timestamp: action.timestamp,
      outcome,
      matchedSiemAlerts: matchedSiem,
      matchedEdrDetections: matchedEdr,
      windowMinutes: 5,
    };
  });
}

// DetectionCorrelator.compute_coverage
function computeCoverage(results: DetectionResult[]): CoverageStats {
  const detected  = results.filter((r) => r.outcome === "detected").length;
  const prevented = results.filter((r) => r.outcome === "prevented").length;
  const missed    = results.filter((r) => r.outcome === "missed").length;
  const total     = results.length;
  return {
    totalTechniques: total,
    detected, prevented, missed,
    coveragePct: Math.round(((detected + prevented) / total) * 100),
  };
}

// ── SigmaRuleGenerator ────────────────────────────────────────────────────────

export interface SigmaRule {
  mitreId: string;
  technique: string;
  yaml: string;
  logSource: string;
  status: "stable" | "experimental";
}

const SIGMA_TEMPLATES: Record<string, (evidence?: string) => string> = {
  "T1557.001": () => `title: LLMNR/NBT-NS Poisoning Response from Non-Authoritative Host
id: sigma-llmnr-001
status: experimental
description: Detects LLMNR responses from hosts that are not authoritative DNS servers — indicator of Responder-style poisoning attack.
references:
  - https://attack.mitre.org/techniques/T1557/001/
author: ADVERSA Detection Engine
date: 2026-05-10
tags:
  - attack.credential_access
  - attack.t1557.001
logsource:
  category: network_traffic
  product: zeek
detection:
  selection:
    proto: LLMNR
    src_ip|not:
      - 10.0.0.10   # DC01 — authoritative DNS
      - 10.0.0.11   # DC02
  condition: selection
falsepositives:
  - Misconfigured network devices responding to LLMNR
level: high
fields:
  - src_ip
  - dst_ip
  - query`,

  "T1558.003": () => `title: Kerberoasting — RC4 TGS Request Volume Anomaly
id: sigma-kerberoast-001
status: stable
description: Detects multiple Kerberos TGS requests with RC4 encryption (Etype 23) from a single non-DC source — characteristic of Kerberoasting.
references:
  - https://attack.mitre.org/techniques/T1558/003/
author: ADVERSA Detection Engine
date: 2026-05-10
tags:
  - attack.credential_access
  - attack.t1558.003
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4769
    TicketEncryptionType: '0x17'
    ServiceName|endswith: '$'
    ServiceName|not: 'krbtgt'
  filter_dc:
    IpAddress:
      - '10.0.0.10'
      - '10.0.0.11'
  timeframe: 1h
  condition: selection and not filter_dc | count() by IpAddress > 5
falsepositives:
  - Legacy applications requiring RC4
level: high
fields:
  - IpAddress
  - TargetUserName
  - ServiceName
  - TicketEncryptionType`,

  "T1134.001": () => `title: Suspicious Token Impersonation via LSASS Memory Access
id: sigma-token-impersonation-001
status: experimental
description: Detects process access to LSASS memory with handle rights indicative of Mimikatz sekurlsa::tickets or credential dumping.
references:
  - https://attack.mitre.org/techniques/T1134/001/
author: ADVERSA Detection Engine
date: 2026-05-10
tags:
  - attack.privilege_escalation
  - attack.t1134.001
logsource:
  category: process_access
  product: windows
detection:
  selection:
    TargetImage|endswith: '\\lsass.exe'
    GrantedAccess|contains:
      - '0x1010'
      - '0x1410'
      - '0x147a'
      - '0x1fffff'
  filter_legitimate:
    SourceImage|contains:
      - '\\MsMpEng.exe'
      - '\\csrss.exe'
      - '\\wininit.exe'
  condition: selection and not filter_legitimate
falsepositives:
  - AV/EDR products performing memory scanning
level: critical
fields:
  - SourceImage
  - SourceProcessId
  - GrantedAccess`,

  "T1021.003": () => `title: DCOM Lateral Movement — Remote MMC Application
id: sigma-dcom-lateral-001
status: experimental
description: Detects DCOM-based lateral movement using MMC20.Application or ShellWindows objects spawning child processes on remote hosts.
references:
  - https://attack.mitre.org/techniques/T1021/003/
author: ADVERSA Detection Engine
date: 2026-05-10
tags:
  - attack.lateral_movement
  - attack.t1021.003
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    ParentImage|endswith:
      - '\\mmc.exe'
      - '\\explorer.exe'
    ParentCommandLine|contains: '-Embedding'
    Image|not:
      - 'C:\\Windows\\System32\\dllhost.exe'
  filter_local:
    Network|contains: '127.0.0.1'
  condition: selection and not filter_local
falsepositives:
  - Legitimate remote management via MMC
level: high
fields:
  - ParentImage
  - Image
  - CommandLine
  - Network`,

  "T1110.002": () => `title: Kerberos RC4 Hash Susceptibility — Offline Crack Detection
id: sigma-pw-crack-preventive-001
status: stable
description: Offline password cracking of Kerberos RC4 hashes is undetectable post-exfiltration. This rule detects the upstream condition — TGS request with weak encryption that enables offline cracking.
references:
  - https://attack.mitre.org/techniques/T1110/002/
author: ADVERSA Detection Engine
date: 2026-05-10
tags:
  - attack.credential_access
  - attack.t1110.002
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4769
    TicketEncryptionType: '0x17'
    TicketOptions: '0x40810010'
  filter_normal:
    IpAddress:
      - '10.0.0.10'
      - '10.0.0.11'
  condition: selection and not filter_normal
falsepositives:
  - Legacy service accounts using RC4 by necessity
level: high
fields:
  - IpAddress
  - TargetUserName
  - ServiceName
note: 'Mitigate: Set msDS-SupportedEncryptionTypes=24 on all service accounts to enforce AES256. Deploy gMSA for service accounts.'`,

  "T1550.002": () => `title: Pass-the-Hash — NTLM Authentication from Unusual Source
id: sigma-pth-001
status: stable
description: Detects Pass-the-Hash attacks by correlating NTLM logon type 3 events from sources that have not previously authenticated with passwords.
references:
  - https://attack.mitre.org/techniques/T1550/002/
author: ADVERSA Detection Engine
date: 2026-05-10
tags:
  - attack.lateral_movement
  - attack.t1550.002
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4624
    LogonType: 3
    AuthenticationPackageName: 'NTLM'
    WorkstationName|not: ''
  filter_local:
    IpAddress: '127.0.0.1'
  filter_known:
    SubjectUserName|endswith: '$'
  timeframe: 1h
  condition: (selection and not filter_local and not filter_known) | count() by IpAddress > 3
falsepositives:
  - Legacy applications using NTLM
  - IT management tools with pass-through authentication
level: high
fields:
  - IpAddress
  - TargetUserName
  - WorkstationName
  - LogonType`,
};

// SigmaRuleGenerator.generate_sigma_for_technique
function generateSigma(mitreId: string, technique: string): SigmaRule {
  const template = SIGMA_TEMPLATES[mitreId];
  const yaml = template
    ? template()
    : `title: Detection Rule for ${technique}
id: sigma-${mitreId.toLowerCase().replace(".", "-")}-001
status: experimental
description: Auto-generated Sigma rule for ${technique} (${mitreId}).
tags:
  - attack.${mitreId.toLowerCase()}
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains:
      - '${mitreId}'
  condition: selection
level: medium`;

  const logSourceMap: Record<string, string> = {
    "T1557.001": "Zeek network monitoring (LLMNR)",
    "T1558.003": "Windows Security Event 4769",
    "T1134.001": "Windows Sysmon Event 10 (Process Access)",
    "T1021.003": "Windows Sysmon Event 1 (Process Creation)",
    "T1110.002": "Windows Security Event 4769",
    "T1550.002": "Windows Security Event 4624",
    "T1003.006": "Windows Security Event 4662 (DS Replication)",
    "T1055":     "Windows Sysmon Event 10 (Process Access)",
  };

  return {
    mitreId, technique, yaml,
    logSource: logSourceMap[mitreId] ?? "Windows Event Log",
    status: SIGMA_TEMPLATES[mitreId] ? "stable" : "experimental",
  };
}

// ── SIEM configuration store ─────────────────────────────────────────────────

export interface SIEMConfig {
  type: "Splunk" | "Sentinel" | "Elastic";
  host: string;
  port?: number;
  token: string;
  index?: string;
  workspace?: string;
  configured: boolean;
  lastTested?: string;
}

const siemConfigs = new Map<string, SIEMConfig>();

// Correlation job store
const correlationRuns = new Map<string, {
  jobId: string; engagementId: string; status: "running" | "completed";
  startedAt: string; completedAt?: string;
  results?: DetectionResult[]; coverage?: CoverageStats;
}>();

// ── Public API ────────────────────────────────────────────────────────────────

export const detectionStore = {
  // AttackLogger.log_action
  getTimeline(engagementId: string): AttackAction[] {
    return ATTACK_TIMELINE.filter((a) => a.engagementId === engagementId);
  },

  // SIEMQueryEngine (mocked)
  getSiemAlerts(): SIEMAlert[] { return SIEM_ALERTS; },

  // EDRQueryEngine (mocked)
  getEdrDetections(): EDRDetection[] { return EDR_DETECTIONS; },

  // POST /detection-validation/run
  runCorrelation(engagementId: string): string {
    const jobId = Math.random().toString(36).slice(2, 9).toUpperCase();
    const run = {
      jobId, engagementId, status: "running" as const,
      startedAt: new Date().toISOString(),
    };
    correlationRuns.set(jobId, run);

    // Simulate async job — resolve immediately (sync for simplicity)
    const results = correlate();
    const coverage = computeCoverage(results);
    correlationRuns.set(jobId, {
      ...run, status: "completed",
      completedAt: new Date().toISOString(), results, coverage,
    });
    return jobId;
  },

  getRunStatus(jobId: string) {
    return correlationRuns.get(jobId) ?? null;
  },

  // GET /detection-validation/results
  getLatestResults(engagementId: string): DetectionResult[] {
    const runs = [...correlationRuns.values()]
      .filter((r) => r.engagementId === engagementId && r.status === "completed")
      .sort((a, b) => b.startedAt.localeCompare(a.startedAt));
    return runs[0]?.results ?? correlate(); // fall back to on-demand correlation
  },

  // GET /detection-validation/coverage
  getCoverage(engagementId: string): CoverageStats {
    const results = this.getLatestResults(engagementId);
    return computeCoverage(results);
  },

  // GET /detection-validation/gaps (missed only, with Sigma rules)
  getGaps(engagementId: string): { result: DetectionResult; sigmaRule: SigmaRule }[] {
    const results = this.getLatestResults(engagementId);
    return results
      .filter((r) => r.outcome === "missed")
      .map((result) => ({
        result,
        sigmaRule: generateSigma(result.mitreId, result.mitreTechnique),
      }));
  },

  // POST /detection-validation/siem-config
  saveSiemConfig(engagementId: string, config: SIEMConfig): SIEMConfig {
    const key = `${engagementId}:${config.type}`;
    const saved = { ...config, configured: true, lastTested: new Date().toISOString() };
    siemConfigs.set(key, saved);
    return saved;
  },

  getSiemConfigs(engagementId: string): SIEMConfig[] {
    return [...siemConfigs.entries()]
      .filter(([k]) => k.startsWith(engagementId))
      .map(([, v]) => v);
  },

  // Direct sigma generation
  generateSigma,
};
