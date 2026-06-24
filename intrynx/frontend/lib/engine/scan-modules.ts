/**
 * Scan module catalog.
 *
 * A scan module is one offensive-security capability the operator can enable.
 * Each module has:
 *   - category    — where it sits in the kill chain (Recon / Discovery / Web / Vuln / Crypto / Auth)
 *   - tool        — binary or script name (used for the doctor check)
 *   - requires    — what this module needs as input (targets / hosts / urls)
 *   - produces    — what it adds to the scan state (hosts / web-urls / findings)
 *   - default     — included in the default "standard" profile
 *   - description — one-line operator-facing summary
 *   - installHint — how to install the underlying binary
 *
 * The wizard reads this catalog to build its category-grouped picker.
 * The scanner reads it (indirectly via opts.tools) to know what to run.
 */
import type { ScanTool } from './types';

export type ModuleCategory =
  | 'External Recon'   // OSINT — only for domain-scoped engagements
  | 'Discovery'        // host + port + service discovery (internal network)
  | 'Enumeration'      // per-service deep dive (SMB, SNMP, LDAP, etc.)
  | 'Web'              // web-service-specific (when web ports are found internally)
  | 'Vulnerability'    // CVE / known-issue scanning
  | 'Crypto';          // TLS / SSH / cipher auditing

export type ModuleInput  = 'targets' | 'hosts' | 'urls';
export type ModuleOutput = 'hosts' | 'urls' | 'findings' | 'subdomains';

export interface ScanModule {
  id:           ScanTool;
  label:        string;
  category:     ModuleCategory;
  tool:         string;            // binary name for doctor / install check
  requires:     ModuleInput[];
  produces:     ModuleOutput[];
  default:      boolean;
  description:  string;
  installHint:  string;
  /** Ordering hint within a stage; lower runs first */
  order:        number;
  /** If true, this module ONLY makes sense for domain-name targets (not IPs) */
  domainOnly?:  boolean;
  /** Ports that trigger this module via service-aware auto-enumeration. */
  triggerPorts?: number[];
}

export const MODULES: ScanModule[] = [
  // ── External Recon (domain-only) ─────────────────────────────────
  {
    id:          'subfinder',
    label:       'Subdomain enumeration',
    category:    'External Recon',
    tool:        'subfinder',
    requires:    ['targets'],
    produces:    ['subdomains'],
    default:     false,
    domainOnly:  true,
    description: 'Passive subdomain discovery via OSINT (cert transparency, public APIs). Only useful when scope is a domain name.',
    installHint: 'Bundled — runs natively if subfinder not installed.',
    order:       10,
  },
  {
    id:          'dns-recon',
    label:       'Public DNS recon',
    category:    'External Recon',
    tool:        'dig',
    requires:    ['targets'],
    produces:    ['hosts', 'findings'],
    default:     false,
    domainOnly:  true,
    description: 'Public DNS records (A/AAAA/MX/NS/TXT), reverse DNS, zone transfer attempt. Domain targets only.',
    installHint: 'Native — uses Node dns module.',
    order:       12,
  },

  // ── Discovery ────────────────────────────────────────────────────
  {
    id:          'host-discovery',
    label:       'Host discovery (multi-protocol)',
    category:    'Discovery',
    tool:        'nmap',
    requires:    ['targets'],
    produces:    ['hosts'],
    default:     false,
    description: 'ICMP-echo + ICMP-timestamp + ARP + TCP-SYN + TCP-ACK + UDP ping. Records which method found each host.',
    installHint: 'brew install nmap',
    order:       20,
  },
  {
    id:          'naabu',
    label:       'Port discovery (TCP, fast)',
    category:    'Discovery',
    tool:        'naabu',
    requires:    ['targets'],
    produces:    ['hosts'],
    default:     true,
    description: 'Fast TCP port discovery — range configurable (top-100 / top-1000 / all 65535).',
    installHint: 'go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest',
    order:       30,
  },
  {
    id:          'udp-scan',
    label:       'UDP port discovery',
    category:    'Discovery',
    tool:        'nmap',
    requires:    ['hosts'],
    produces:    ['hosts', 'findings'],
    default:     false,
    description: 'UDP top-100 (DNS/SNMP/NTP/NetBIOS/LDAP/SSDP). Slow but often reveals critical services TCP misses.',
    installHint: 'brew install nmap',
    order:       35,
  },
  {
    id:          'nmap',
    label:       'Service + NSE probe',
    category:    'Discovery',
    tool:        'nmap',
    requires:    ['hosts'],
    produces:    ['hosts', 'findings'],
    default:     true,
    description: 'Service version detection + NSE scripts (intensity: safe / default / discovery / aggressive).',
    installHint: 'brew install nmap',
    order:       40,
  },
  {
    id:          'os-detect',
    label:       'OS fingerprinting',
    category:    'Discovery',
    tool:        'nmap',
    requires:    ['hosts'],
    produces:    ['hosts'],
    default:     false,
    description: 'TCP/IP stack fingerprinting via nmap -O. Records OS family + confidence per host.',
    installHint: 'brew install nmap (needs raw socket — sudo on Linux/macOS)',
    order:       45,
  },

  // ── Enumeration (auto-fired by what's open on each host) ─────────
  {
    id:           'smb-enum',
    label:        'SMB enumeration',
    category:     'Enumeration',
    tool:         'nmap',
    requires:     ['hosts'],
    produces:     ['findings'],
    default:      true,
    triggerPorts: [139, 445],
    description:  'SMB version + OS + shares + signing + null sessions (nmap NSE smb-os-discovery, smb-enum-shares, smb-enum-users, smb2-security-mode).',
    installHint:  'brew install nmap',
    order:        50,
  },
  {
    id:           'netbios-enum',
    label:        'NetBIOS enumeration',
    category:     'Enumeration',
    tool:         'nmap',
    requires:     ['hosts'],
    produces:     ['findings'],
    default:      true,
    triggerPorts: [137, 139],
    description:  'NetBIOS name service: hostname, workgroup/domain, MAC address (nmap nbstat).',
    installHint:  'brew install nmap',
    order:        51,
  },
  {
    id:           'snmp-enum',
    label:        'SNMP enumeration',
    category:     'Enumeration',
    tool:         'nmap',
    requires:     ['hosts'],
    produces:     ['findings'],
    default:      true,
    triggerPorts: [161, 162],
    description:  'SNMPv1/v2c community string brute (public/private/etc.) + sysDescr + interfaces (nmap snmp-brute, snmp-info).',
    installHint:  'brew install nmap',
    order:        52,
  },
  {
    id:           'ldap-enum',
    label:        'LDAP / AD enumeration',
    category:     'Enumeration',
    tool:         'nmap',
    requires:     ['hosts'],
    produces:     ['findings'],
    default:      true,
    triggerPorts: [389, 636, 3268, 3269],
    description:  'Anonymous bind, base DN, user list, group membership (nmap ldap-rootdse, ldap-search).',
    installHint:  'brew install nmap',
    order:        53,
  },
  {
    id:           'rpc-enum',
    label:        'RPC enumeration',
    category:     'Enumeration',
    tool:         'nmap',
    requires:     ['hosts'],
    produces:     ['findings'],
    default:      true,
    triggerPorts: [111, 135],
    description:  'RPC endpoint mapper (portmap on Unix, MS-RPC on Windows) — lists registered services.',
    installHint:  'brew install nmap',
    order:        54,
  },
  {
    id:           'nfs-enum',
    label:        'NFS enumeration',
    category:     'Enumeration',
    tool:         'nmap',
    requires:     ['hosts'],
    produces:     ['findings'],
    default:      true,
    triggerPorts: [111, 2049],
    description:  'NFS exports list + mount attempt (showmount equivalent).',
    installHint:  'brew install nmap',
    order:        55,
  },
  {
    id:           'rdp-fingerprint',
    label:        'RDP fingerprint',
    category:     'Enumeration',
    tool:         'nmap',
    requires:     ['hosts'],
    produces:     ['findings'],
    default:      true,
    triggerPorts: [3389],
    description:  'RDP version, NLA status, cert subject (nmap rdp-ntlm-info, rdp-enum-encryption).',
    installHint:  'brew install nmap',
    order:        56,
  },
  {
    id:           'db-enum',
    label:        'Database service enumeration',
    category:     'Enumeration',
    tool:         'nmap',
    requires:     ['hosts'],
    produces:     ['findings'],
    default:      true,
    triggerPorts: [1433, 1521, 3306, 5432, 6379, 27017, 9200, 11211],
    description:  'MSSQL/Oracle/MySQL/PostgreSQL/Redis/Mongo/ES/memcached — version + default cred + unauth-access check.',
    installHint:  'brew install nmap',
    order:        57,
  },

  // ── Web (fires when web ports are discovered, even internally) ──
  {
    id:           'httpx',
    label:        'HTTP probing',
    category:     'Web',
    tool:         'httpx',
    requires:     ['hosts'],
    produces:     ['urls', 'findings'],
    default:      true,
    triggerPorts: [80, 443, 8080, 8443, 8000, 8081, 3000, 5000, 9090, 9000, 7070, 8888, 8181, 8090, 5984, 9200, 8761],
    description:  'Probe discovered web ports for status, title, tech, TLS cert. Catches printer / router / admin UIs on internal networks.',
    installHint:  'Bundled — runs natively if httpx not installed.',
    order:        60,
  },
  {
    id:           'whatweb',
    label:        'Tech fingerprinting',
    category:     'Web',
    tool:         'whatweb',
    requires:     ['urls'],
    produces:     ['findings'],
    default:      true,
    triggerPorts: [80, 443, 8080, 8443],
    description:  'Identify CMS, framework, language, web server, JS libs (WhatWeb / native Wappalyzer rules).',
    installHint:  'Native — Wappalyzer-style rules embedded.',
    order:        62,
  },
  {
    id:           'ffuf',
    label:        'Directory busting',
    category:     'Web',
    tool:         'ffuf',
    requires:     ['urls'],
    produces:     ['findings'],
    default:      false,
    triggerPorts: [80, 443, 8080, 8443],
    description:  'Path enumeration via wordlist. Off by default — produces noise; enable when you want it.',
    installHint:  'Native — embedded mini wordlist + GET probe.',
    order:        64,
  },

  // ── Vulnerability ────────────────────────────────────────────────
  {
    id:          'nuclei',
    label:       'CVE scanner (templates)',
    category:    'Vulnerability',
    tool:        'nuclei',
    requires:    ['hosts'],
    produces:    ['findings'],
    default:     true,
    description: 'Template-driven CVE detection against discovered services.',
    installHint: 'go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest',
    order:       80,
  },

  // ── Crypto ───────────────────────────────────────────────────────
  {
    id:           'testssl',
    label:        'TLS / SSL audit',
    category:     'Crypto',
    tool:         'testssl.sh',
    requires:     ['hosts'],
    produces:     ['findings'],
    default:      false,
    triggerPorts: [443, 8443, 465, 587, 636, 993, 995, 3389, 5986],
    description:  'TLS configuration audit: protocol versions, ciphers, cert validity (native or testssl.sh).',
    installHint:  'Native fallback; install testssl.sh for deep audit.',
    order:        90,
  },
  {
    id:           'ssh-audit',
    label:        'SSH config audit',
    category:     'Crypto',
    tool:         'ssh-audit',
    requires:     ['hosts'],
    produces:     ['findings'],
    default:      true,
    triggerPorts: [22, 2222],
    description:  'SSH banner + cipher / kex / MAC audit against best practice.',
    installHint:  'pip install ssh-audit',
    order:        100,
  },
];

export function moduleById(id: ScanTool): ScanModule | undefined {
  return MODULES.find((m) => m.id === id);
}

export function modulesByCategory(): Record<ModuleCategory, ScanModule[]> {
  const out: Partial<Record<ModuleCategory, ScanModule[]>> = {};
  for (const m of MODULES) {
    if (!out[m.category]) out[m.category] = [];
    out[m.category]!.push(m);
  }
  for (const k of Object.keys(out) as ModuleCategory[]) {
    out[k]!.sort((a, b) => a.order - b.order);
  }
  return out as Record<ModuleCategory, ScanModule[]>;
}

export function defaultModules(): ScanTool[] {
  return MODULES.filter((m) => m.default).map((m) => m.id);
}

export function profileModules(profile: 'fast' | 'standard' | 'deep'): ScanTool[] {
  switch (profile) {
    case 'fast':
      // Quick triage — port discovery + CVE only
      return ['naabu', 'nuclei'];
    case 'standard':
      // Normal internal engagement — discovery + service enum + vuln
      return [
        'host-discovery', 'naabu', 'nmap',
        // Service-aware enumeration auto-fires on matching ports
        'smb-enum', 'netbios-enum', 'snmp-enum', 'ldap-enum', 'rpc-enum', 'rdp-fingerprint', 'db-enum',
        // Web modules trigger only if web ports are open
        'httpx', 'whatweb',
        // SSH audit triggers only if 22 open
        'ssh-audit',
        'nuclei',
      ];
    case 'deep':
      // Thorough — adds UDP, OS detect, NFS, full TLS, all enum
      return [
        'host-discovery', 'naabu', 'udp-scan', 'nmap', 'os-detect',
        'smb-enum', 'netbios-enum', 'snmp-enum', 'ldap-enum', 'rpc-enum', 'nfs-enum', 'rdp-fingerprint', 'db-enum',
        'httpx', 'whatweb', 'ffuf',
        'nuclei', 'testssl', 'ssh-audit',
      ];
  }
}

/** Which enumeration modules should auto-fire given a set of discovered open ports? */
export function modulesForPorts(openPorts: Set<number>): ScanTool[] {
  return MODULES
    .filter((m) => m.triggerPorts && m.triggerPorts.some((p) => openPorts.has(p)))
    .map((m) => m.id);
}

/** Default discovery options by depth — drives port range, UDP, OS, NSE intensity */
export function depthDefaults(depth: 'quick' | 'standard' | 'thorough' | 'exhaustive') {
  switch (depth) {
    case 'quick':
      return { portRange: 'top-100' as const,  udpScan: false, osDetect: false, nseIntensity: 'safe' as const };
    case 'standard':
      return { portRange: 'top-1000' as const, udpScan: false, osDetect: false, nseIntensity: 'default' as const };
    case 'thorough':
      return { portRange: 'top-1000' as const, udpScan: true,  osDetect: true,  nseIntensity: 'discovery' as const };
    case 'exhaustive':
      return { portRange: 'all' as const,      udpScan: true,  osDetect: true,  nseIntensity: 'aggressive' as const };
  }
}
