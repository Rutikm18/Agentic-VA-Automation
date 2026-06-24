export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type ScanProfile = 'fast' | 'standard' | 'deep';

export type ScanTool =
  // External recon (DOMAIN targets only — runs only when scope is a domain name)
  | 'subfinder'        // passive subdomain enum via OSINT
  | 'dns-recon'        // public DNS records, PTR sweep, zone transfer attempt
  // Network discovery (IP / CIDR targets — the primary path)
  | 'host-discovery'   // multi-protocol ping (ICMP/ARP/TCP-SYN/TCP-ACK/UDP)
  | 'naabu'            // TCP port discovery (fast)
  | 'udp-scan'         // UDP top-N discovery (nmap -sU)
  | 'nmap'             // service / version probe + NSE
  | 'os-detect'        // OS fingerprint (nmap -O)
  // Service enumeration (per-service deep dive — auto-fired by what's open)
  | 'smb-enum'         // SMB version, shares, signing, null sessions (port 445/139)
  | 'netbios-enum'     // NetBIOS name discovery, domain ID (port 137/139)
  | 'snmp-enum'        // SNMP community strings, sysDescr, interfaces (port 161/162)
  | 'ldap-enum'        // LDAP anonymous bind, base DN, users (port 389/636)
  | 'rpc-enum'         // RPC endpoint mapper (port 111/135)
  | 'nfs-enum'         // NFS exports, mount attempts (port 111/2049)
  | 'rdp-fingerprint'  // RDP version + cert + NLA detection (port 3389)
  | 'db-enum'          // MSSQL/MySQL/PostgreSQL/Redis/Mongo banner + auth check
  // Web (on internal network — common admin interfaces)
  | 'httpx'            // live HTTP service probe + tech
  | 'whatweb'          // tech fingerprint
  | 'ffuf'             // directory busting
  // Vulnerability
  | 'nuclei'           // CVE / template scan
  // Crypto
  | 'testssl'          // TLS audit
  | 'ssh-audit';       // SSH config / cipher audit

export type DiscoveryDepth = 'quick' | 'standard' | 'thorough' | 'exhaustive';

export interface ScanOptions {
  targets: string[];
  profile: ScanProfile;
  stealth: number;
  tools: ScanTool[];
  save: boolean;
  engagementId?: string;
  scanId?: string;
  /** Optional config knobs used by individual modules */
  options?: {
    /** How aggressive port + host discovery should be */
    discoveryDepth?:  DiscoveryDepth;
    /** Port range — overrides depth defaults; either named ('top-100') or '1-65535' */
    portRange?:       'top-100' | 'top-1000' | 'top-5000' | 'all' | string;
    /** Include UDP top-100 scan */
    udpScan?:         boolean;
    /** Run nmap OS fingerprinting */
    osDetect?:        boolean;
    /** nmap NSE script intensity */
    nseIntensity?:    'safe' | 'default' | 'discovery' | 'aggressive';
    /** ffuf wordlist path (or env override) */
    ffufWordlist?:    string;
    ffufMaxPaths?:    number;
    httpxThreads?:    number;
  };
}

export interface DiscoveredHost {
  ip: string;
  ports: number[];
  services: { port: number; proto: string; name?: string; version?: string }[];
  os?: string;
  osConfidence?: number;          // 0-100, from nmap OS detection
  osMethod?: 'tcp-stack' | 'nse' | 'service-banner';
  hostnames?: string[];
  /** How this host was found — useful for forensic attribution */
  discoveryMethod?: 'icmp-echo' | 'icmp-timestamp' | 'arp' | 'tcp-syn-ping' | 'tcp-ack-ping' | 'udp-ping' | 'ptr-sweep' | 'naabu' | 'manual';
  /** UDP ports discovered separately from TCP */
  udpPorts?: number[];
}

export interface Evidence {
  label: string;
  content: string;
  timestamp: string;
}

export interface LiveFinding {
  id: string;
  title: string;
  severity: Severity;
  cvss?: string;
  cvssVector?: string;
  host: string;
  port?: number;
  protocol?: string;
  service?: string;
  serviceVersion?: string;
  evidence: Evidence[];
  source: 'nmap' | 'nuclei' | 'testssl' | 'naabu' | 'openvas' | 'manual' | 'agent' | 'httpx' | 'whatweb' | 'ffuf' | 'subfinder' | 'ssh-audit' | 'host-discovery' | 'smb-enum' | 'netbios-enum' | 'snmp-enum' | 'ldap-enum' | 'rpc-enum' | 'nfs-enum' | 'rdp-fingerprint' | 'db-enum';
  cveIds?: string[];
  mitre?: { id: string; name: string }[];
  compliance?: { framework: string; refs: string[] }[];
  attackPath?: string;
  remediation?: string;
  timestamp: string;
  engagementId?: string;
  status: 'OPEN' | 'IN_REVIEW' | 'IN_REMEDIATION' | 'VERIFIED' | 'CLOSED';
  slaDeadline?: string;
  falsePositive?: boolean;
  falsePositiveReason?: string;
}

export interface ScanCallbacks {
  onStageStart:    (stage: string) => void;
  onStageComplete: (stage: string, summary: string) => void | Promise<void>;
  onHostDiscovered:(host: DiscoveredHost) => void;
  onFinding:       (finding: LiveFinding) => void;
  onProgress:      (pct: number, message: string) => void;
  onError:         (stage: string, error: string) => void;
  onComplete:      (summary: ScanSummary) => void | Promise<void>;
}

export interface ScanSummary {
  scanId: string;
  startTime: string;
  endTime: string;
  duration: number;
  hostsScanned: number;
  portsFound: number;
  totalFindings: number;
  bySeverity: Record<Severity, number>;
  savedCount: number;
  engagementId?: string;
}

export interface AgentJob {
  id: string;
  type: 'scan' | 'exploit' | 'verify';
  scanId: string;
  targets: string[];
  profile?: ScanProfile;
  stealth?: number;
  tools?: string[];
  scopeToken: string;
  exploitCommand?: string;
  createdAt: string;
}

export interface AgentJobResult {
  jobId: string;
  agentId: string;
  status: 'COMPLETE' | 'FAILED' | 'PARTIAL';
  findings: LiveFinding[];
  error?: string;
  duration: number;
}
