/**
 * Native DNS recon — no external binaries required.
 *
 * Uses Node's built-in dns module. Provides what `dig` + `dnsrecon` would
 * give us for typical engagement enumeration:
 *   - A / AAAA records
 *   - MX, NS, TXT, SOA, CNAME, SRV
 *   - Reverse DNS (PTR) sweep over a CIDR
 *   - Zone-transfer attempt (AXFR) — most servers refuse but worth trying
 *   - Common subdomain bruteforce
 */
import { Resolver } from 'dns/promises';
import { Socket } from 'net';

export interface DnsReconResult {
  domain:       string;
  a:            string[];
  aaaa:         string[];
  mx:           Array<{ exchange: string; priority: number }>;
  ns:           string[];
  txt:          string[];
  cname?:       string;
  soa?:         { nsname: string; hostmaster: string; serial: number; refresh: number; retry: number; expire: number; minttl: number };
  zoneTransfer: { attempted: boolean; succeeded: boolean; records?: number };
  subdomains:   string[];
}

export interface PtrSweepResult {
  ip:       string;
  hostname: string;
}

const COMMON_SUBDOMAINS = [
  'www', 'mail', 'ftp', 'webmail', 'smtp', 'pop', 'imap', 'ns1', 'ns2',
  'dns', 'mx', 'mx1', 'mx2', 'remote', 'vpn', 'ssh', 'admin', 'test',
  'dev', 'staging', 'beta', 'api', 'app', 'm', 'mobile', 'portal',
  'secure', 'login', 'auth', 'sso', 'jira', 'confluence', 'wiki',
  'git', 'gitlab', 'github', 'jenkins', 'ci', 'build', 'docker',
  'monitoring', 'grafana', 'kibana', 'elk', 'splunk', 'mysql', 'postgres',
  'db', 'database', 'redis', 'mongo', 'cache', 'cdn', 'static', 'assets',
  'blog', 'news', 'shop', 'store', 'crm', 'erp', 'support', 'help',
  'docs', 'documentation', 'status', 'health', 'metrics',
  // Cloud
  's3', 'ec2', 'cloud', 'aws', 'azure', 'gcp', 'k8s',
  // Internal
  'intranet', 'internal', 'corp', 'office', 'hr', 'finance',
];

async function safe<T>(p: Promise<T>): Promise<T | null> {
  try { return await p; } catch { return null; }
}

export async function nativeDnsRecon(domain: string): Promise<DnsReconResult> {
  const r = new Resolver();

  const [a, aaaa, mx, ns, txt, cname, soa] = await Promise.all([
    safe(r.resolve4(domain)).then((x) => x ?? []),
    safe(r.resolve6(domain)).then((x) => x ?? []),
    safe(r.resolveMx(domain)).then((x) => x ?? []),
    safe(r.resolveNs(domain)).then((x) => x ?? []),
    safe(r.resolveTxt(domain)).then((x) => (x ?? []).map((arr) => arr.join(''))),
    safe(r.resolveCname(domain)).then((x) => x?.[0]),
    safe(r.resolveSoa(domain)),
  ]);

  // Zone transfer attempt against each NS — most refuse, but it's free to try
  const zt = { attempted: ns.length > 0, succeeded: false, records: undefined as number | undefined };
  for (const nsName of ns) {
    const ok = await attemptZoneTransfer(domain, nsName);
    if (ok) { zt.succeeded = true; zt.records = ok; break; }
  }

  // Common subdomain bruteforce (DNS resolution only — passive-ish)
  const subdomains: string[] = [];
  await Promise.all(
    COMMON_SUBDOMAINS.map(async (sub) => {
      const ips = await safe(r.resolve4(`${sub}.${domain}`));
      if (ips && ips.length > 0) subdomains.push(`${sub}.${domain}`);
    }),
  );

  return {
    domain, a, aaaa, mx, ns, txt,
    cname: cname || undefined,
    soa:   soa || undefined,
    zoneTransfer: zt,
    subdomains,
  };
}

/**
 * Try a zone transfer (AXFR) on port 53/tcp against the given nameserver.
 * Returns the record count if successful, null otherwise.
 * Most modern servers refuse with NOTAUTH — but enterprise misconfigs do exist.
 */
function attemptZoneTransfer(domain: string, ns: string): Promise<number | null> {
  return new Promise((resolve) => {
    const sock = new Socket();
    sock.setTimeout(3000);
    let response = Buffer.alloc(0);
    let resolved = false;

    const done = (count: number | null): void => {
      if (resolved) return;
      resolved = true;
      sock.destroy();
      resolve(count);
    };

    sock.on('connect', () => {
      // Build minimal AXFR query: header + question for <domain> AXFR IN
      const labels = domain.split('.').flatMap((l) => [Buffer.from([l.length]), Buffer.from(l)]);
      const qname = Buffer.concat([...labels, Buffer.from([0])]);
      const header = Buffer.from([
        0x12, 0x34,  // tx id
        0x00, 0x00,  // flags (standard query)
        0x00, 0x01,  // 1 question
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      ]);
      const tail = Buffer.from([0x00, 0xfc, 0x00, 0x01]);  // QTYPE=AXFR, QCLASS=IN
      const payload = Buffer.concat([header, qname, tail]);
      const lenPrefix = Buffer.alloc(2);
      lenPrefix.writeUInt16BE(payload.length, 0);
      sock.write(Buffer.concat([lenPrefix, payload]));
    });

    sock.on('data', (chunk: Buffer) => {
      response = Buffer.concat([response, chunk]);
      // If we got multiple-message-size response it's almost certainly AXFR data
      if (response.length > 2000) {
        // Rough record count: each record is ~30+ bytes; this is a lower bound estimate
        done(Math.floor(response.length / 50));
      }
    });
    sock.on('timeout', () => done(null));
    sock.on('error',   () => done(null));
    sock.on('end',     () => done(response.length > 100 ? Math.floor(response.length / 50) : null));

    sock.connect(53, ns);
  });
}

/**
 * Reverse-DNS sweep across a list of IPs. Useful inside an internal engagement
 * to identify hostnames without sending TCP probes.
 */
export async function nativePtrSweep(ips: string[]): Promise<PtrSweepResult[]> {
  const r = new Resolver();
  const out: PtrSweepResult[] = [];
  await Promise.all(
    ips.map(async (ip) => {
      const names = await safe(r.reverse(ip));
      if (names && names.length > 0) out.push({ ip, hostname: names[0] });
    }),
  );
  return out;
}
