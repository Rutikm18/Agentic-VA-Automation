import { spawn, type SpawnOptions } from 'child_process';
import { readFileSync, unlinkSync, existsSync, mkdirSync } from 'fs';
import { tmpdir, homedir } from 'os';
import { join } from 'path';
import { request as httpRequestNative }    from 'http';
import { request as httpsRequestNative }   from 'https';
import { Socket as NetSocket }             from 'net';
import type { DiscoveredHost, ScanCallbacks, LiveFinding } from './types';
import { parseNmapXml }                        from '../nmap-parser';
import { parseNucleiLine, nucleiSeverityToSeverity } from '../nuclei-parser';
import { parseTestsslJson }                    from '../testssl-parser';
import { parseNaabuLine, groupNaabuResults }   from '../naabu-parser';
import { generateFindingId }                   from '../finding-id';
import { diagnoseSpawnError, Errors }          from '../errors';
import { nativePortScan, groupResults }        from './native/port-scan';
import { nativeHttpProbe }                     from './native/http-probe';
import { nativeDirBust }                       from './native/dir-bust';
import { nativeTlsInfo }                       from './native/tls-info';
import { nativeDnsRecon, nativePtrSweep }      from './native/dns-recon';
import { execSync }                            from 'child_process';
import { managedPath, isManaged }              from '../tools/installer';

// ── Stealth mappings (index = stealth level 0–9) ─────────────────
const NAABU_RATE    = [0, 50, 100, 300, 500, 1000, 2000, 3000, 5000];
const NMAP_TIMING   = [0, 1,  1,   2,   2,   3,    3,    4,    4,   5];

// ── Platform helpers ─────────────────────────────────────────────
function isWindows(): boolean {
  return process.platform === 'win32';
}

/** Cheap check: is this binary on PATH? */
function hasSystemBinary(bin: string): boolean {
  try {
    const cmd = isWindows() ? 'where' : 'command -v';
    execSync(`${cmd} ${bin}`, { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

/**
 * Resolve which binary path to actually invoke for a tool. Priority:
 *   1. ADVERSA-managed (~/.adversa/tools/) — what we bundled
 *   2. System PATH — power users who installed via brew / go install
 *   3. (caller falls back to native implementation if neither exists)
 *
 * Returns the path to execute, or null if no binary is available — in which
 * case the caller should use its native fallback.
 */
function resolveBinPath(tool: string): { path: string; managed: boolean } | null {
  // Strip platform-specific suffix when checking the managed catalog
  const baseId = tool.replace(/\.(exe|sh)$/, '');
  if (isManaged(baseId)) return { path: managedPath(baseId), managed: true };
  if (hasSystemBinary(tool)) return { path: tool, managed: false };
  return null;
}

/** Compatibility helper for the old call sites that just want a yes/no. */
function hasBinary(tool: string): boolean {
  return resolveBinPath(tool) !== null;
}

/**
 * Resolve to the actual executable path for a tool. Managed binary wins; falls
 * back to system PATH (relying on the OS to find it); finally returns the bare
 * name which will fail with ENOENT — caller may have a native fallback.
 */
function bin(tool: string): string {
  if (isManaged(tool)) return managedPath(tool);
  return binName(tool);
}

function binName(tool: string): string {
  const win: Record<string, string> = { nmap: 'nmap.exe', naabu: 'naabu.exe', nuclei: 'nuclei.exe', testssl: 'testssl.sh' };
  const unix: Record<string, string> = { nmap: 'nmap', naabu: 'naabu', nuclei: 'nuclei', testssl: 'testssl.sh' };
  return isWindows() ? (win[tool] ?? tool) : (unix[tool] ?? tool);
}

function spawnOpts(extraEnv?: Record<string, string>): SpawnOptions {
  const base: SpawnOptions = {
    stdio: ['ignore', 'pipe', 'pipe'],
    env:   { ...process.env, ...(extraEnv ?? {}) },
  };
  if (isWindows()) {
    // Prevent console window flash on Windows
    (base as SpawnOptions & { windowsHide: boolean }).windowsHide = true;
    base.shell = true;
  }
  return base;
}

// ── Helper: run a process and stream stdout line by line ─────────
// Captures stderr too so we can produce a useful error when things go wrong.
interface ProcessResult { code: number; stderr: string; }

function streamProcess(
  bin:     string,
  args:    string[],
  onLine:  (line: string) => void,
  opts?:   SpawnOptions,
): Promise<ProcessResult> {
  return new Promise((resolve) => {
    let buf = '';
    let stderr = '';
    let spawnError = '';
    const proc = spawn(bin, args, opts ?? spawnOpts());

    proc.stdout?.on('data', (chunk: Buffer | string) => {
      buf += chunk.toString();
      const lines = buf.split('\n');
      buf = lines.pop() ?? '';
      for (const l of lines) if (l.trim()) onLine(l);
    });
    proc.stderr?.on('data', (chunk: Buffer | string) => {
      stderr += chunk.toString();
    });

    proc.on('error', (err) => {
      spawnError = err.message;
      resolve({ code: -1, stderr: stderr || spawnError });
    });
    proc.on('close', (code) => {
      if (buf.trim()) onLine(buf);
      resolve({ code: code ?? 0, stderr });
    });
  });
}

function collectProcess(bin: string, args: string[], opts?: SpawnOptions): Promise<{ stdout: string; code: number; stderr: string }> {
  return new Promise((resolve) => {
    let stdout = '';
    let stderr = '';
    const proc = spawn(bin, args, opts ?? spawnOpts());
    proc.stdout?.on('data', (c: Buffer | string) => { stdout += c.toString(); });
    proc.stderr?.on('data', (c: Buffer | string) => { stderr += c.toString(); });
    proc.on('error', (err) => resolve({ stdout, code: -1, stderr: err.message }));
    proc.on('close', (code) => resolve({ stdout, code: code ?? 0, stderr }));
  });
}

// ── runNaabu ─────────────────────────────────────────────────────
// Tries external naabu (faster); falls back to native TCP connect scan.
export async function runNaabu(
  targets:  string[],
  stealth:  number,
  cb:       ScanCallbacks,
): Promise<DiscoveredHost[]> {
  if (hasBinary('naabu')) {
    const rate    = NAABU_RATE[Math.min(stealth, 9)] ?? 1000;
    const results: import('../naabu-parser').NaabuResult[] = [];

    const { code, stderr } = await streamProcess(
      bin('naabu'),
      ['-host', targets.join(','), '-rate', String(rate), '-s', 'c', '-json', '-silent'],
      (line) => {
        const r = parseNaabuLine(line);
        if (r) {
          results.push(r);
          const existing = results.filter((x) => x.ip === r.ip);
          cb.onHostDiscovered({
            ip:       r.ip,
            ports:    existing.map((x) => x.port),
            services: existing.map((x) => ({ port: x.port, proto: x.protocol })),
          });
        }
      },
      spawnOpts(),
    );

    if (code !== 0 && results.length === 0) {
      cb.onError('naabu', diagnoseSpawnError('naabu', code, stderr).render({ useColor: false, withMark: false }));
    }
    return groupNaabuResults(results);
  }

  // Native fallback — pure Node, no external binary.
  // Slower than naabu but works on every machine out of the box.
  const stealthToConc: Record<number, number> = { 1: 30, 2: 50, 3: 80, 4: 120, 5: 200, 6: 300, 7: 400, 8: 500, 9: 700 };
  const concurrency = stealthToConc[Math.min(stealth, 9)] ?? 200;
  cb.onProgress(10, 'native port scan (no naabu installed)');

  const results = await nativePortScan(targets, {
    ports:       'top-1000',
    concurrency,
    timeoutMs:   1500,
    grabBanner:  true,
    onProgress:  (done, total) => cb.onProgress(Math.min(24, 10 + Math.floor((done / total) * 14)), `${done}/${total} probes`),
  });
  const hosts = groupResults(results);
  for (const h of hosts) cb.onHostDiscovered(h);
  return hosts;
}

// ── runNmap ──────────────────────────────────────────────────────
// Strategy: run nmap PER HOST in parallel with a short per-host timeout.
// For any port we couldn't fingerprint via nmap, fall back to a native
// banner grab (HTTP header for web ports, raw TCP banner for others).
// This is much faster than one big nmap call AND more accurate because the
// native HTTP probe parses the Server header that nmap's HTTP probes miss.
export async function runNmap(
  hosts:   DiscoveredHost[],
  stealth: number,
  cb:      ScanCallbacks,
): Promise<void> {
  if (hosts.length === 0) return;

  const timing = NMAP_TIMING[Math.min(stealth, 9)] ?? 3;

  // Run nmap per host in parallel (max 8 concurrent — avoid OS resource exhaustion)
  const CONCURRENCY = Math.min(8, hosts.length);
  let next = 0;
  const workers: Promise<void>[] = [];

  const runOne = async (host: DiscoveredHost): Promise<void> => {
    if (host.ports.length === 0) return;
    const portArg = host.ports.join(',');
    const args = [
      '-sT',                            // TCP connect (no raw socket needed)
      '-sV',                            // service version detection
      '--version-intensity', '7',       // sane default — try common probes (was 9: too slow)
      '-Pn',                            // skip host discovery (we already know they're up)
      `-T${timing}`,
      '-p', portArg,
      '--host-timeout', '45s',          // hard cap per host (was 300s)
      '--max-retries', '1',
      '--script', 'http-server-header,http-title,ssl-cert',
      '-oX', '-',
      host.ip,
    ];
    const { stdout, code, stderr } = await collectProcess(bin('nmap'), args, spawnOpts());
    if (code !== 0 && !stdout) {
      cb.onError('nmap', diagnoseSpawnError('nmap', code, stderr).render({ useColor: false, withMark: false }));
      return;
    }
    const parsed = parseNmapXml(stdout);
    const fromXml = parsed.find((p) => p.ip === host.ip);
    if (fromXml) {
      const open = fromXml.services.filter((s) => s.state === 'open');
      host.services = open.map((s) => ({
        port:    s.port,
        proto:   s.proto,
        name:    s.name,
        version: [s.product, s.version].filter(Boolean).join(' ') || undefined,
      }));
      host.os        = fromXml.os;
      host.hostnames = fromXml.hostnames;
    }
    // ── Fallback: for any port WITHOUT a real version, try native banner grab
    await Promise.all(host.ports.map(async (port) => {
      const existing = host.services.find((s) => s.port === port);
      if (existing && existing.version) return;   // already fingerprinted
      const banner = await nativeBannerGrab(host.ip, port);
      if (!banner) return;
      if (existing) {
        existing.name    = banner.name    ?? existing.name;
        existing.version = banner.version ?? existing.version;
      } else {
        host.services.push({ port, proto: 'tcp', name: banner.name, version: banner.version });
      }
    }));
    cb.onHostDiscovered(host);
  };

  // Run pool — per-host failures are isolated (logged via cb.onError) so a
  // single bad host can't crash the engagement.
  while (next < hosts.length) {
    while (workers.length < CONCURRENCY && next < hosts.length) {
      const h = hosts[next++];
      const p: Promise<void> = runOne(h)
        .catch((err: unknown) => {
          const msg = err instanceof Error ? err.message : String(err);
          cb.onError('nmap', `host ${h.ip}: ${msg}`);
        })
        .then(() => {
          const idx = workers.indexOf(p);
          if (idx >= 0) workers.splice(idx, 1);
        });
      workers.push(p);
    }
    if (workers.length > 0) await Promise.race(workers).catch(() => undefined);
  }
  await Promise.allSettled(workers);
  return;
}

// ── Global safety net — unhandled rejections elsewhere shouldn't kill the wizard
if (typeof process !== 'undefined' && process.listenerCount && process.listenerCount('unhandledRejection') === 0) {
  process.on('unhandledRejection', (reason) => {
    // eslint-disable-next-line no-console
    console.error('[adversa] unhandledRejection caught:', reason instanceof Error ? reason.message : reason);
  });
}

// ── Native banner grab — fast fallback when nmap can't fingerprint ──
//
// For HTTP/HTTPS ports: GET / with short timeout, parse Server header + title.
// For other ports: TCP connect, read first 500 bytes, identify by prefix.
//
// This is what catches dev servers (Node.js Express, Flask, Next.js, etc.)
// that nmap's static probes miss.
async function nativeBannerGrab(host: string, port: number): Promise<{ name?: string; version?: string } | null> {
  const WEB_PORTS = new Set([80, 443, 8080, 8443, 8000, 8081, 3000, 5000, 9000, 9090, 8888, 8181, 7070]);
  if (WEB_PORTS.has(port)) {
    return await httpBannerGrab(host, port, port === 443 || port === 8443 || port === 9443);
  }
  return await tcpBannerGrab(host, port);
}

async function httpBannerGrab(host: string, port: number, https: boolean): Promise<{ name?: string; version?: string } | null> {
  return new Promise((resolve) => {
    let resolved = false;
    const done = (r: { name?: string; version?: string } | null): void => {
      if (resolved) return;
      resolved = true;
      resolve(r);
    };

    try {
      const baseOpts = { hostname: host, port, path: '/', method: 'GET', timeout: 3500, headers: { 'User-Agent': 'adversa-scanner/1.0' } };
      const onResponse = (res: import('http').IncomingMessage) => {
        const server   = res.headers['server'];
        const xPowered = res.headers['x-powered-by'];
        let body = '';
        res.on('data', (chunk: Buffer | string) => {
          body += chunk.toString();
          if (body.length > 2048) { try { req.destroy(); } catch { /* ignore */ } }
        });
        res.on('end', () => {
          try {
            const titleMatch = body.match(/<title[^>]*>([^<]+)<\/title>/i);
            const title = titleMatch ? titleMatch[1].trim().slice(0, 60) : undefined;
            let name: string | undefined;
            let version: string | undefined;
            if (typeof server === 'string')              { name = 'http'; version = server; }
            else if (typeof xPowered === 'string')       { name = 'http'; version = xPowered; }
            else if (title)                              { name = 'http'; version = title; }
            else                                         { name = 'http'; }
            done({ name, version });
          } catch { done({ name: 'http' }); }
        });
        res.on('error', () => done(null));
      };
      const req = https
        ? httpsRequestNative({ ...baseOpts, rejectUnauthorized: false }, onResponse)
        : httpRequestNative(baseOpts, onResponse);
      req.on('timeout', () => { try { req.destroy(); } catch { /* ignore */ } done(null); });
      req.on('error',   () => done(null));
      req.end();
    } catch {
      done(null);
    }
  });
}

async function tcpBannerGrab(host: string, port: number): Promise<{ name?: string; version?: string } | null> {
  return new Promise((resolve) => {
    let resolved = false;
    const done = (r: { name?: string; version?: string } | null): void => {
      if (resolved) return;
      resolved = true;
      try { sock.destroy(); } catch { /* ignore */ }
      resolve(r);
    };

    let sock: NetSocket;
    try {
      sock = new NetSocket();
    } catch {
      resolve(null);
      return;
    }

    let banner = '';
    sock.setTimeout(3000);
    sock.on('connect', () => {
      setTimeout(() => {
        if (banner.length === 0) {
          try { sock.write('\r\n'); } catch { /* ignore */ }
        }
      }, 500);
      setTimeout(() => {
        try {
          const trimmed = banner.split(/\r?\n/)[0].trim().slice(0, 120);
          if (trimmed.length === 0) { done(null); return; }
          if (/^SSH-/i.test(trimmed))                     done({ name: 'ssh',  version: trimmed.replace(/^SSH-[\d.]+-/, '') });
          else if (/^220.*FTP/i.test(trimmed))            done({ name: 'ftp',  version: trimmed.replace(/^220[- ]/, '') });
          else if (/^220.*SMTP|^220.*ESMTP/i.test(trimmed)) done({ name: 'smtp', version: trimmed.replace(/^220[- ]/, '') });
          else if (/^\+OK/i.test(trimmed))                done({ name: 'pop3', version: trimmed.replace(/^\+OK\s*/, '') });
          else if (/^\* OK.*IMAP/i.test(trimmed))         done({ name: 'imap', version: trimmed.replace(/^\* OK\s*/, '') });
          else if (/redis/i.test(trimmed))                done({ name: 'redis', version: trimmed });
          else if (/mysql/i.test(trimmed))                done({ name: 'mysql', version: trimmed });
          else                                            done({ name: 'banner', version: trimmed });
        } catch { done(null); }
      }, 1800);
    });
    sock.on('data',    (chunk: Buffer) => { banner += chunk.toString('utf8'); });
    sock.on('timeout', () => done(null));
    sock.on('error',   () => done(null));
    sock.on('close',   () => done(null));
    try { sock.connect(port, host); } catch { done(null); }
  });
}

// ── runNuclei ────────────────────────────────────────────────────
export async function runNuclei(
  hosts: DiscoveredHost[],
  cb:    ScanCallbacks,
): Promise<LiveFinding[]> {
  const WEB_PROTO: Record<number, string> = { 80: 'http', 443: 'https', 8080: 'http', 8443: 'https', 8000: 'http', 3000: 'http', 5000: 'http' };
  const urls = hosts.flatMap((h) =>
    h.ports
      .filter((p) => WEB_PROTO[p])
      .map((p) => `${WEB_PROTO[p]}://${h.ip}:${p}`),
  );

  if (urls.length === 0) return [];

  const findings: LiveFinding[] = [];
  const now = new Date().toISOString();

  // Resolve a writable templates dir, in this order:
  //   1. NUCLEI_TEMPLATE_DIR env var (operator override)
  //   2. ~/nuclei-templates (default nuclei install location)
  //   3. /opt/nuclei-templates (legacy)
  //   4. let nuclei use its built-in default
  const candidates = [
    process.env.NUCLEI_TEMPLATE_DIR,
    join(homedir(), 'nuclei-templates'),
    '/opt/nuclei-templates',
  ].filter(Boolean) as string[];
  const templateDir = candidates.find((p) => existsSync(p));

  // Give nuclei a writable config dir. We can't rely on $HOME being correct
  // for every spawn context, so we set NUCLEI_CONFIG_DIR explicitly and
  // pre-create it. Falls back through three paths.
  const configCandidates = [
    process.env.NUCLEI_CONFIG_DIR,
    join(homedir(), '.config', 'nuclei'),
    join(tmpdir(), 'adversa-nuclei-config'),
  ].filter(Boolean) as string[];

  let configDir = '';
  for (const path of configCandidates) {
    try {
      mkdirSync(path, { recursive: true });
      configDir = path;
      break;
    } catch { /* try the next one */ }
  }

  const args = [
    '-json', '-silent', '-no-color',
    ...(templateDir ? ['-t', templateDir] : []),
    ...urls.flatMap((u) => ['-u', u]),
  ];

  const env: Record<string, string> = {};
  if (configDir) {
    env.NUCLEI_CONFIG_DIR = configDir;
    env.XDG_CONFIG_HOME   = join(configDir, '..');  // backup for older nuclei
  }

  const { code, stderr } = await streamProcess(
    bin('nuclei'),
    args,
    (line) => {
      const match = parseNucleiLine(line);
      if (!match) return;
      const sev = nucleiSeverityToSeverity(match.severity);
      const finding: LiveFinding = {
        id:        generateFindingId(sev),
        title:     match.name,
        severity:  sev,
        host:      match.ip ?? match.host,
        port:      match.port,
        source:    'nuclei',
        cveIds:    match.cveIds,
        evidence:  [{ label: 'nuclei match', content: match.matchedAt, timestamp: now }],
        status:    'OPEN',
        timestamp: now,
      };
      findings.push(finding);
      cb.onFinding(finding);
    },
    spawnOpts(env),
  );

  if (code !== 0 && findings.length === 0) {
    cb.onError('nuclei', diagnoseSpawnError('nuclei', code, stderr).render({ useColor: false, withMark: false }));
  }
  return findings;
}

// ── runTestssl ───────────────────────────────────────────────────
export async function runTestssl(
  hosts: DiscoveredHost[],
  cb:    ScanCallbacks,
): Promise<LiveFinding[]> {
  const TLS_PORTS = new Set([443, 8443]);
  const targets   = hosts.filter((h) => h.ports.some((p) => TLS_PORTS.has(p)));
  if (targets.length === 0) return [];

  const all: LiveFinding[] = [];

  for (const host of targets) {
    const port    = host.ports.find((p) => TLS_PORTS.has(p)) ?? 443;
    const outFile = join(tmpdir(), `adv-testssl-${host.ip}-${Date.now()}.json`);

    const { code, stderr } = await collectProcess(
      binName('testssl'),
      ['--fast', '--jsonfile', outFile, '--color', '0', '--quiet', `${host.ip}:${port}`],
      spawnOpts(),
    );

    if (code !== 0 && !existsSync(outFile)) {
      cb.onError('testssl', diagnoseSpawnError('testssl', code, stderr).render({ useColor: false, withMark: false }));
      continue;
    }

    if (existsSync(outFile)) {
      try {
        const content  = readFileSync(outFile, 'utf-8');
        const findings = parseTestsslJson(content, host.ip, port);
        for (const f of findings) { all.push(f); cb.onFinding(f); }
      } catch { /* ignore parse errors */ }
      try { unlinkSync(outFile); } catch { /* ignore */ }
    }
  }

  return all;
}

// ── runHostDiscovery (nmap -sn ping sweep) ───────────────────────
export async function runHostDiscovery(
  targets: string[],
  cb: ScanCallbacks,
): Promise<DiscoveredHost[]> {
  const live: DiscoveredHost[] = [];
  const args = ['-sn', '-PE', '-PA21,22,80,443,3389', '-n', '--max-retries', '1', ...targets];
  const { stdout, code, stderr } = await collectProcess(binName('nmap'), args, spawnOpts());

  if (code !== 0 && !stdout) {
    cb.onError('host-discovery', diagnoseSpawnError('nmap', code, stderr).render({ useColor: false, withMark: false }));
    return live;
  }

  // nmap -sn prints lines like:  "Nmap scan report for 192.168.0.5"
  for (const m of stdout.matchAll(/Nmap scan report for (?:\S+ \()?(\d{1,3}(?:\.\d{1,3}){3})/g)) {
    const ip = m[1];
    if (!live.find((h) => h.ip === ip)) {
      const h: DiscoveredHost = { ip, ports: [], services: [] };
      live.push(h);
      cb.onHostDiscovered(h);
    }
  }
  return live;
}

// ── runDnsRecon (native — no external binary needed) ─────────────
export async function runDnsRecon(
  targets: string[],
  cb: ScanCallbacks,
): Promise<{ hosts: DiscoveredHost[]; findings: LiveFinding[]; subdomains: string[] }> {
  const findings: LiveFinding[] = [];
  const subdomains: string[] = [];
  const newHosts: DiscoveredHost[] = [];
  const now = new Date().toISOString();

  const domains = targets.filter((t) => /[a-z]/i.test(t) && !/^\d/.test(t) && !t.includes('/'));
  if (domains.length === 0) return { hosts: newHosts, findings, subdomains };

  for (const domain of domains) {
    try {
      const result = await nativeDnsRecon(domain);

      // Record subdomain discoveries
      for (const sub of result.subdomains) {
        if (!subdomains.includes(sub)) subdomains.push(sub);
      }

      // Zone transfer success is a real finding
      if (result.zoneTransfer.succeeded) {
        findings.push({
          id:        generateFindingId('HIGH'),
          title:     `DNS zone transfer (AXFR) succeeded on ${domain}`,
          severity:  'HIGH',
          host:      domain,
          port:      53,
          source:    'host-discovery',
          evidence:  [{ label: 'AXFR', content: `Recovered ~${result.zoneTransfer.records ?? '?'} records from ${result.ns[0]}`, timestamp: now }],
          status:    'OPEN',
          timestamp: now,
        });
      }

      // Always emit an INFO finding with the DNS picture
      findings.push({
        id:        generateFindingId('INFO'),
        title:     `DNS ${domain}: ${result.a.length} A · ${result.subdomains.length} subdomains · ${result.ns.length} NS`,
        severity:  'INFO',
        host:      domain,
        source:    'host-discovery',
        evidence:  [{
          label:   'DNS recon',
          content: JSON.stringify({ a: result.a, mx: result.mx, ns: result.ns, txt: result.txt, subdomains: result.subdomains }),
          timestamp: now,
        }],
        status:    'OPEN',
        timestamp: now,
      });
      for (const f of findings) cb.onFinding(f);

      // Convert A records into new hosts (so downstream stages have something)
      for (const ip of result.a) {
        if (!newHosts.find((h) => h.ip === ip)) {
          const h: DiscoveredHost = {
            ip,
            ports:    [],
            services: [],
            hostnames: [domain],
            discoveryMethod: 'ptr-sweep',
          };
          newHosts.push(h);
          cb.onHostDiscovered(h);
        }
      }
    } catch (e) {
      cb.onError('host-discovery', e instanceof Error ? e.message : String(e));
    }
  }

  return { hosts: newHosts, findings, subdomains };
}

// ── runSubfinder (passive subdomain enum) ────────────────────────
export async function runSubfinder(
  targets: string[],
  cb: ScanCallbacks,
): Promise<string[]> {
  const subdomains: string[] = [];
  const domains = targets.filter((t) => /[a-z]/i.test(t) && !/^\d/.test(t));
  if (domains.length === 0) return subdomains;

  for (const domain of domains) {
    const args = ['-d', domain, '-silent', '-all'];
    const { stdout, code, stderr } = await collectProcess(bin('subfinder'), args, spawnOpts());
    if (code !== 0 && !stdout) {
      cb.onError('subfinder', diagnoseSpawnError('subfinder', code, stderr).render({ useColor: false, withMark: false }));
      return subdomains;
    }
    for (const sub of stdout.split(/\r?\n/).map((s) => s.trim()).filter(Boolean)) {
      if (!subdomains.includes(sub)) subdomains.push(sub);
    }
  }
  return subdomains;
}

// ── runHttpx (HTTP service probe) ────────────────────────────────
interface HttpxLine {
  url?: string; host?: string; port?: number; status_code?: number;
  title?: string; tech?: string[]; webserver?: string; scheme?: string;
}

export async function runHttpx(
  hosts: DiscoveredHost[],
  cb: ScanCallbacks,
): Promise<{ urls: string[]; findings: LiveFinding[] }> {
  const urls: string[] = [];
  const findings: LiveFinding[] = [];
  const now = new Date().toISOString();

  // Build target list — host:port for every open TCP port
  const inputs = hosts.flatMap((h) => h.ports.map((p) => `${h.ip}:${p}`));
  if (inputs.length === 0) return { urls, findings };

  // Native fallback when httpx isn't installed
  if (!hasBinary('httpx')) {
    const results = await nativeHttpProbe(hosts.map((h) => ({ ip: h.ip, ports: h.ports })));
    for (const r of results) {
      urls.push(r.url);
      const techStr = r.tech.map((t) => `${t.name}${t.version ? '/' + t.version : ''}`).join(', ');
      const f: LiveFinding = {
        id:        generateFindingId('INFO'),
        title:     `HTTP ${r.status}  ${r.title || r.url}${techStr ? '  [' + techStr.slice(0, 50) + ']' : ''}`,
        severity:  'INFO',
        host:      r.host,
        port:      r.port,
        service:   r.server || 'http',
        source:    'httpx',
        evidence:  [{
          label:   'native HTTP probe',
          content: JSON.stringify({ status: r.status, title: r.title, server: r.server, tech: r.tech, tlsInfo: r.tlsInfo }),
          timestamp: now,
        }],
        status:    'OPEN',
        timestamp: now,
      };
      findings.push(f);
      cb.onFinding(f);
    }
    return { urls, findings };
  }

  const args = ['-json', '-silent', '-no-color', '-threads', '50', '-l', '/dev/stdin'];
  const proc = spawn(bin('httpx'), args, { ...spawnOpts(), stdio: ['pipe', 'pipe', 'pipe'] });

  return new Promise((resolve) => {
    let buf = ''; let stderr = '';
    proc.stdout?.on('data', (chunk: Buffer | string) => {
      buf += chunk.toString();
      const lines = buf.split('\n');
      buf = lines.pop() ?? '';
      for (const line of lines) {
        if (!line.trim()) continue;
        try {
          const j = JSON.parse(line) as HttpxLine;
          if (j.url) urls.push(j.url);
          // Emit one INFO finding per live web service
          if (j.url) {
            const f: LiveFinding = {
              id:        generateFindingId('INFO'),
              title:     `HTTP service: ${j.title || j.url}`,
              severity:  'INFO',
              host:      j.host || j.url,
              port:      j.port,
              service:   j.webserver || 'http',
              source:    'httpx',
              evidence:  [{ label: 'httpx', content: JSON.stringify(j), timestamp: now }],
              status:    'OPEN',
              timestamp: now,
            };
            findings.push(f);
            cb.onFinding(f);
          }
        } catch { /* malformed line — skip */ }
      }
    });
    proc.stderr?.on('data', (c: Buffer | string) => { stderr += c.toString(); });
    proc.on('error', (err) => {
      cb.onError('httpx', diagnoseSpawnError('httpx', -1, err.message).render({ useColor: false, withMark: false }));
      resolve({ urls, findings });
    });
    proc.on('close', (code) => {
      if (code !== 0 && urls.length === 0) {
        cb.onError('httpx', diagnoseSpawnError('httpx', code ?? 1, stderr).render({ useColor: false, withMark: false }));
      }
      resolve({ urls, findings });
    });
    proc.stdin?.write(inputs.join('\n'));
    proc.stdin?.end();
  });
}

// ── runWhatweb (tech fingerprint) ────────────────────────────────
export async function runWhatweb(
  urls: string[],
  cb: ScanCallbacks,
): Promise<LiveFinding[]> {
  if (urls.length === 0) return [];
  const findings: LiveFinding[] = [];
  const now = new Date().toISOString();

  // Native fallback — already produced tech data in httpx phase, so this
  // re-probes each URL to attach tech findings explicitly tagged as 'whatweb'.
  if (!hasBinary(binName('whatweb'))) {
    const targets = urls.map((u) => {
      try {
        const url = new URL(u);
        return { ip: url.hostname, ports: [parseInt(url.port, 10) || (url.protocol === 'https:' ? 443 : 80)] };
      } catch { return null; }
    }).filter((x): x is { ip: string; ports: number[] } => !!x);
    const results = await nativeHttpProbe(targets);
    for (const r of results) {
      if (r.tech.length === 0) continue;
      const techStr = r.tech.map((t) => `${t.name}${t.version ? '/' + t.version : ''}`).join(', ');
      const f: LiveFinding = {
        id:        generateFindingId('INFO'),
        title:     `Tech stack: ${techStr.slice(0, 80)}`,
        severity:  'INFO',
        host:      r.host,
        port:      r.port,
        source:    'whatweb',
        evidence:  [{ label: 'native fingerprint', content: JSON.stringify(r.tech), timestamp: now }],
        status:    'OPEN',
        timestamp: now,
      };
      findings.push(f);
      cb.onFinding(f);
    }
    return findings;
  }

  const args = ['--no-errors', '--log-json=/dev/stdout', '-q', ...urls];
  const { stdout, code, stderr } = await collectProcess(binName('whatweb'), args, spawnOpts());
  if (code !== 0 && !stdout) {
    cb.onError('whatweb', diagnoseSpawnError('whatweb', code, stderr).render({ useColor: false, withMark: false }));
    return findings;
  }

  for (const line of stdout.split(/\r?\n/)) {
    if (!line.trim()) continue;
    try {
      const j = JSON.parse(line) as { target?: string; plugins?: Record<string, unknown> };
      if (!j.target || !j.plugins) continue;
      const tech = Object.keys(j.plugins).join(', ');
      const host = new URL(j.target).hostname;
      const port = parseInt(new URL(j.target).port, 10) || (new URL(j.target).protocol === 'https:' ? 443 : 80);
      const f: LiveFinding = {
        id:        generateFindingId('INFO'),
        title:     `Tech stack: ${tech.slice(0, 60)}`,
        severity:  'INFO',
        host,
        port,
        source:    'whatweb',
        evidence:  [{ label: 'whatweb', content: line, timestamp: now }],
        status:    'OPEN',
        timestamp: now,
      };
      findings.push(f);
      cb.onFinding(f);
    } catch { /* malformed line */ }
  }
  return findings;
}

// ── runFfuf (directory busting) ──────────────────────────────────
export async function runFfuf(
  urls: string[],
  cb: ScanCallbacks,
  wordlistPath?: string,
  maxPaths = 50,
): Promise<LiveFinding[]> {
  if (urls.length === 0) return [];
  const findings: LiveFinding[] = [];
  const now = new Date().toISOString();

  // Native fallback — uses built-in mini wordlist if no ffuf installed
  if (!hasBinary('ffuf')) {
    for (const url of urls) {
      const results = await nativeDirBust(url, { wordlistPath, maxPaths });
      for (const r of results) {
        const u = new URL(r.url);
        const f: LiveFinding = {
          id:        generateFindingId(r.status === 401 || r.status === 403 ? 'LOW' : 'INFO'),
          title:     `Path discovered: ${u.pathname}  (${r.status} ${r.reason || ''})`.trim(),
          severity:  r.status === 401 || r.status === 403 ? 'LOW' : 'INFO',
          host:      u.hostname,
          port:      parseInt(u.port, 10) || (u.protocol === 'https:' ? 443 : 80),
          source:    'ffuf',
          evidence:  [{ label: 'native dir bust', content: `${r.url} → ${r.status} (${r.contentLength} bytes)`, timestamp: now }],
          status:    'OPEN',
          timestamp: now,
        };
        findings.push(f);
        cb.onFinding(f);
      }
    }
    return findings;
  }

  // Find a wordlist. Prefer the operator override, then common locations.
  const candidates = [
    wordlistPath,
    process.env.ADVERSA_FFUF_WORDLIST,
    '/opt/SecLists/Discovery/Web-Content/common.txt',
    '/usr/share/wordlists/dirb/common.txt',
    '/usr/local/share/seclists/Discovery/Web-Content/common.txt',
  ].filter(Boolean) as string[];

  const wordlist = candidates.find((p) => existsSync(p));
  if (!wordlist) {
    cb.onError('ffuf', 'No wordlist found. Set ADVERSA_FFUF_WORDLIST to a path, or install SecLists (`brew install seclists`).');
    return findings;
  }

  for (const url of urls) {
    const args = ['-u', `${url}/FUZZ`, '-w', wordlist, '-mc', '200,204,301,302,403', '-of', 'json', '-o', '/dev/stdout', '-s'];
    const { stdout, code, stderr } = await collectProcess(bin('ffuf'), args, spawnOpts());
    if (code !== 0 && !stdout) {
      cb.onError('ffuf', diagnoseSpawnError('ffuf', code, stderr).render({ useColor: false, withMark: false }));
      continue;
    }
    try {
      const result = JSON.parse(stdout) as { results?: Array<{ url: string; status: number; length: number }> };
      const items = (result.results ?? []).slice(0, maxPaths);
      for (const r of items) {
        const u = new URL(r.url);
        const f: LiveFinding = {
          id:        generateFindingId('LOW'),
          title:     `Path discovered: ${u.pathname}  (${r.status})`,
          severity:  'LOW',
          host:      u.hostname,
          port:      parseInt(u.port, 10) || (u.protocol === 'https:' ? 443 : 80),
          source:    'ffuf',
          evidence:  [{ label: 'ffuf', content: `${r.url} → ${r.status} (${r.length} bytes)`, timestamp: now }],
          status:    'OPEN',
          timestamp: now,
        };
        findings.push(f);
        cb.onFinding(f);
      }
    } catch { /* malformed ffuf JSON */ }
  }
  return findings;
}

// ── runSshAudit (SSH config / cipher audit) ──────────────────────
export async function runSshAudit(
  hosts: DiscoveredHost[],
  cb: ScanCallbacks,
): Promise<LiveFinding[]> {
  const sshHosts = hosts.filter((h) => h.ports.includes(22));
  if (sshHosts.length === 0) return [];

  const findings: LiveFinding[] = [];
  const now = new Date().toISOString();

  for (const host of sshHosts) {
    const args = ['-j', host.ip];   // -j → JSON output
    const { stdout, code, stderr } = await collectProcess(binName('ssh-audit'), args, spawnOpts());
    // ssh-audit returns non-zero when issues are found — that's the EXPECTED case
    if (!stdout) {
      cb.onError('ssh-audit', diagnoseSpawnError('ssh-audit', code, stderr).render({ useColor: false, withMark: false }));
      continue;
    }
    try {
      const j = JSON.parse(stdout) as {
        cves?: Array<{ name: string; description?: string; cvssv2?: number }>;
        recommendations?: { critical?: Record<string, string[]>; warning?: Record<string, string[]> };
      };
      // CVE findings
      for (const cve of j.cves ?? []) {
        const sev = (cve.cvssv2 ?? 0) >= 7 ? 'HIGH' : (cve.cvssv2 ?? 0) >= 4 ? 'MEDIUM' : 'LOW';
        const f: LiveFinding = {
          id:        generateFindingId(sev),
          title:     `SSH: ${cve.name} ${cve.description ? '— ' + cve.description.slice(0, 60) : ''}`,
          severity:  sev,
          host:      host.ip,
          port:      22,
          source:    'ssh-audit',
          cveIds:    [cve.name],
          evidence:  [{ label: 'ssh-audit', content: JSON.stringify(cve), timestamp: now }],
          status:    'OPEN',
          timestamp: now,
        };
        findings.push(f);
        cb.onFinding(f);
      }
      // Critical-rec findings (weak ciphers, etc.)
      for (const [bucket, items] of Object.entries(j.recommendations?.critical ?? {})) {
        for (const item of items) {
          const f: LiveFinding = {
            id:        generateFindingId('MEDIUM'),
            title:     `SSH ${bucket}: ${item}`,
            severity:  'MEDIUM',
            host:      host.ip,
            port:      22,
            source:    'ssh-audit',
            evidence:  [{ label: 'ssh-audit', content: `${bucket} → ${item}`, timestamp: now }],
            status:    'OPEN',
            timestamp: now,
          };
          findings.push(f);
          cb.onFinding(f);
        }
      }
    } catch { /* malformed */ }
  }
  return findings;
}

// ── Network enumeration runners (nmap NSE-driven) ────────────────
//
// These are the modules a real internal network pentester runs after port
// discovery. Each one targets a specific protocol and is gated by the
// presence of its port on the host.
//
// All use the system nmap with curated NSE script sets, which is the de-facto
// standard for these enumerations. Output is parsed line-by-line for findings.

interface NseRunSpec {
  scripts:      string;       // comma-separated NSE script names
  ports:        number[];     // restrict scan to these ports
  finding:      (host: string, port: number, output: string) => LiveFinding[];
  source:       LiveFinding['source'];
  label:        string;       // for error messages
}

async function runNmapNse(
  hosts:    DiscoveredHost[],
  cb:       ScanCallbacks,
  spec:     NseRunSpec,
): Promise<LiveFinding[]> {
  const out: LiveFinding[] = [];
  const matching = hosts.filter((h) => spec.ports.some((p) => h.ports.includes(p)));
  if (matching.length === 0) return out;

  const portStr = spec.ports.join(',');
  for (const host of matching) {
    const hostPorts = host.ports.filter((p) => spec.ports.includes(p));
    if (hostPorts.length === 0) continue;
    const args = ['-Pn', '-sV', '-p', hostPorts.join(','), '--script', spec.scripts, '-oN', '-', host.ip];
    const { stdout, code, stderr } = await collectProcess(bin('nmap'), args, spawnOpts());
    if (code !== 0 && !stdout) {
      cb.onError(spec.source, diagnoseSpawnError('nmap', code, stderr).render({ useColor: false, withMark: false }));
      continue;
    }
    for (const port of hostPorts) {
      const findings = spec.finding(host.ip, port, stdout);
      for (const f of findings) { out.push(f); cb.onFinding(f); }
    }
  }
  return out;
}

// Parse helper — extract NSE script output blocks
function nseSection(stdout: string, scriptName: string): string {
  const re = new RegExp(`\\|\\s*${scriptName}:\\s*\\n((?:\\|.*\\n)+)`, 'g');
  const matches: string[] = [];
  let m: RegExpExecArray | null;
  while ((m = re.exec(stdout)) !== null) matches.push(m[1]);
  return matches.join('\n');
}

// ── SMB enumeration ──────────────────────────────────────────────
export async function runSmbEnum(hosts: DiscoveredHost[], cb: ScanCallbacks): Promise<LiveFinding[]> {
  return runNmapNse(hosts, cb, {
    label:   'SMB',
    source:  'smb-enum',
    ports:   [139, 445],
    scripts: 'smb-os-discovery,smb-protocols,smb2-security-mode,smb-enum-shares,smb-enum-users,smb-vuln-ms17-010',
    finding: (host, port, stdout) => {
      const findings: LiveFinding[] = [];
      const now = new Date().toISOString();

      const osInfo = nseSection(stdout, 'smb-os-discovery');
      if (osInfo) {
        const osMatch = osInfo.match(/OS:\s*(.+)/);
        const domainMatch = osInfo.match(/Domain name:\s*(.+)/);
        findings.push({
          id: generateFindingId('INFO'),
          title: `SMB host: ${osMatch?.[1]?.trim() || 'unknown OS'}${domainMatch ? ` · domain: ${domainMatch[1].trim()}` : ''}`,
          severity: 'INFO', host, port, source: 'smb-enum',
          evidence: [{ label: 'smb-os-discovery', content: osInfo, timestamp: now }],
          status: 'OPEN', timestamp: now,
        });
      }

      const signing = nseSection(stdout, 'smb2-security-mode');
      if (signing && /not required/i.test(signing)) {
        findings.push({
          id: generateFindingId('MEDIUM'),
          title: 'SMB signing not required — vulnerable to NTLM relay',
          severity: 'MEDIUM', host, port, source: 'smb-enum',
          evidence: [{ label: 'smb2-security-mode', content: signing, timestamp: now }],
          status: 'OPEN', timestamp: now,
          remediation: 'Set RequireSecuritySignature on the host (GPO or registry HKLM\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters\\RequireSecuritySignature=1).',
        });
      }

      const shares = nseSection(stdout, 'smb-enum-shares');
      if (shares) {
        const shareLines = [...shares.matchAll(/\\\\.+\\(\S+):/g)].map((m) => m[1]);
        if (shareLines.length > 0) {
          findings.push({
            id: generateFindingId('LOW'),
            title: `SMB shares enumerated: ${shareLines.join(', ')}`,
            severity: 'LOW', host, port, source: 'smb-enum',
            evidence: [{ label: 'smb-enum-shares', content: shares, timestamp: now }],
            status: 'OPEN', timestamp: now,
          });
        }
      }

      // MS17-010 (EternalBlue) is critical
      const ms17010 = nseSection(stdout, 'smb-vuln-ms17-010');
      if (ms17010 && /VULNERABLE/i.test(ms17010)) {
        findings.push({
          id: generateFindingId('CRITICAL'),
          title: 'MS17-010 (EternalBlue) — pre-auth SMB RCE',
          severity: 'CRITICAL', host, port, source: 'smb-enum',
          cveIds: ['CVE-2017-0143', 'CVE-2017-0144', 'CVE-2017-0145', 'CVE-2017-0146', 'CVE-2017-0148'],
          evidence: [{ label: 'smb-vuln-ms17-010', content: ms17010, timestamp: now }],
          status: 'OPEN', timestamp: now,
          remediation: 'Apply MS17-010 patch immediately. Disable SMBv1 entirely.',
        });
      }
      return findings;
    },
  });
}

// ── NetBIOS enumeration ──────────────────────────────────────────
export async function runNetbiosEnum(hosts: DiscoveredHost[], cb: ScanCallbacks): Promise<LiveFinding[]> {
  return runNmapNse(hosts, cb, {
    label:   'NetBIOS',
    source:  'netbios-enum',
    ports:   [137, 139],
    scripts: 'nbstat,smb-os-discovery',
    finding: (host, port, stdout) => {
      const now = new Date().toISOString();
      const nbs = nseSection(stdout, 'nbstat');
      if (!nbs) return [];
      return [{
        id: generateFindingId('INFO'),
        title: `NetBIOS: ${nbs.split('\n').filter((l) => l.includes('NetBIOS')).join(' · ').slice(0, 100)}`,
        severity: 'INFO', host, port, source: 'netbios-enum',
        evidence: [{ label: 'nbstat', content: nbs, timestamp: now }],
        status: 'OPEN', timestamp: now,
      }];
    },
  });
}

// ── SNMP enumeration ─────────────────────────────────────────────
export async function runSnmpEnum(hosts: DiscoveredHost[], cb: ScanCallbacks): Promise<LiveFinding[]> {
  return runNmapNse(hosts, cb, {
    label:   'SNMP',
    source:  'snmp-enum',
    ports:   [161, 162],
    scripts: 'snmp-brute,snmp-info,snmp-sysdescr,snmp-interfaces',
    finding: (host, port, stdout) => {
      const findings: LiveFinding[] = [];
      const now = new Date().toISOString();

      const brute = nseSection(stdout, 'snmp-brute');
      if (brute) {
        const validCommunities = [...brute.matchAll(/(\w+)\s+-\s+Valid credentials/g)].map((m) => m[1]);
        if (validCommunities.length > 0) {
          const sev = validCommunities.includes('public') || validCommunities.includes('private') ? 'HIGH' : 'MEDIUM';
          findings.push({
            id: generateFindingId(sev),
            title: `SNMP community strings found: ${validCommunities.join(', ')}`,
            severity: sev, host, port: 161, protocol: 'udp', source: 'snmp-enum',
            evidence: [{ label: 'snmp-brute', content: brute, timestamp: now }],
            status: 'OPEN', timestamp: now,
            remediation: 'Change default community strings (public/private). Use SNMPv3 with authentication.',
          });
        }
      }
      const sysDescr = nseSection(stdout, 'snmp-sysdescr');
      if (sysDescr) {
        findings.push({
          id: generateFindingId('INFO'),
          title: `SNMP sysDescr: ${sysDescr.replace(/\|/g, ' ').slice(0, 100)}`,
          severity: 'INFO', host, port, protocol: 'udp', source: 'snmp-enum',
          evidence: [{ label: 'snmp-sysdescr', content: sysDescr, timestamp: now }],
          status: 'OPEN', timestamp: now,
        });
      }
      return findings;
    },
  });
}

// ── LDAP enumeration ─────────────────────────────────────────────
export async function runLdapEnum(hosts: DiscoveredHost[], cb: ScanCallbacks): Promise<LiveFinding[]> {
  return runNmapNse(hosts, cb, {
    label:   'LDAP',
    source:  'ldap-enum',
    ports:   [389, 636, 3268, 3269],
    scripts: 'ldap-rootdse,ldap-search',
    finding: (host, port, stdout) => {
      const findings: LiveFinding[] = [];
      const now = new Date().toISOString();
      const root = nseSection(stdout, 'ldap-rootdse');
      if (root) {
        const dnMatch = root.match(/defaultNamingContext:\s*([^\s]+)/);
        const baseDn = dnMatch?.[1];
        findings.push({
          id: generateFindingId('LOW'),
          title: baseDn ? `LDAP anonymous bind allowed — base DN: ${baseDn}` : 'LDAP rootDSE accessible',
          severity: 'LOW', host, port, source: 'ldap-enum',
          evidence: [{ label: 'ldap-rootdse', content: root, timestamp: now }],
          status: 'OPEN', timestamp: now,
          remediation: 'Disable anonymous LDAP queries; require authenticated bind.',
        });
      }
      return findings;
    },
  });
}

// ── RPC enumeration ──────────────────────────────────────────────
export async function runRpcEnum(hosts: DiscoveredHost[], cb: ScanCallbacks): Promise<LiveFinding[]> {
  return runNmapNse(hosts, cb, {
    label:   'RPC',
    source:  'rpc-enum',
    ports:   [111, 135],
    scripts: 'rpcinfo,msrpc-enum',
    finding: (host, port, stdout) => {
      const findings: LiveFinding[] = [];
      const now = new Date().toISOString();
      const rpcinfo = nseSection(stdout, 'rpcinfo');
      if (rpcinfo) {
        findings.push({
          id: generateFindingId('INFO'),
          title: 'RPC endpoint mapper accessible — services enumerated',
          severity: 'INFO', host, port, source: 'rpc-enum',
          evidence: [{ label: 'rpcinfo', content: rpcinfo.slice(0, 500), timestamp: now }],
          status: 'OPEN', timestamp: now,
        });
      }
      return findings;
    },
  });
}

// ── NFS enumeration ──────────────────────────────────────────────
export async function runNfsEnum(hosts: DiscoveredHost[], cb: ScanCallbacks): Promise<LiveFinding[]> {
  return runNmapNse(hosts, cb, {
    label:   'NFS',
    source:  'nfs-enum',
    ports:   [111, 2049],
    scripts: 'nfs-ls,nfs-showmount,nfs-statfs',
    finding: (host, port, stdout) => {
      const findings: LiveFinding[] = [];
      const now = new Date().toISOString();
      const exports_ = nseSection(stdout, 'nfs-showmount');
      if (exports_ && exports_.length > 10) {
        findings.push({
          id: generateFindingId('MEDIUM'),
          title: 'NFS exports world-readable / discoverable',
          severity: 'MEDIUM', host, port, source: 'nfs-enum',
          evidence: [{ label: 'nfs-showmount', content: exports_, timestamp: now }],
          status: 'OPEN', timestamp: now,
          remediation: 'Restrict exports in /etc/exports to specific networks. Require Kerberos auth (sec=krb5).',
        });
      }
      return findings;
    },
  });
}

// ── RDP fingerprint ──────────────────────────────────────────────
export async function runRdpFingerprint(hosts: DiscoveredHost[], cb: ScanCallbacks): Promise<LiveFinding[]> {
  return runNmapNse(hosts, cb, {
    label:   'RDP',
    source:  'rdp-fingerprint',
    ports:   [3389],
    scripts: 'rdp-ntlm-info,rdp-enum-encryption,rdp-vuln-ms12-020',
    finding: (host, port, stdout) => {
      const findings: LiveFinding[] = [];
      const now = new Date().toISOString();
      const ntlm = nseSection(stdout, 'rdp-ntlm-info');
      if (ntlm) {
        const dnsMatch = ntlm.match(/DNS_Domain_Name:\s*(.+)/);
        const hostMatch = ntlm.match(/Target_Name:\s*(.+)/);
        findings.push({
          id: generateFindingId('INFO'),
          title: `RDP: ${hostMatch?.[1]?.trim() || ''}${dnsMatch ? ` · domain: ${dnsMatch[1].trim()}` : ''}`,
          severity: 'INFO', host, port, source: 'rdp-fingerprint',
          evidence: [{ label: 'rdp-ntlm-info', content: ntlm, timestamp: now }],
          status: 'OPEN', timestamp: now,
        });
      }
      const enc = nseSection(stdout, 'rdp-enum-encryption');
      if (enc && /SSL\/TLS:.*RDP/i.test(enc) && !/NLA/i.test(enc)) {
        findings.push({
          id: generateFindingId('MEDIUM'),
          title: 'RDP allows non-NLA connections — pre-auth attack surface',
          severity: 'MEDIUM', host, port, source: 'rdp-fingerprint',
          evidence: [{ label: 'rdp-enum-encryption', content: enc, timestamp: now }],
          status: 'OPEN', timestamp: now,
          remediation: 'Enforce Network Level Authentication (NLA) via GPO.',
        });
      }
      return findings;
    },
  });
}

// ── Database service enumeration ─────────────────────────────────
export async function runDbEnum(hosts: DiscoveredHost[], cb: ScanCallbacks): Promise<LiveFinding[]> {
  const findings: LiveFinding[] = [];
  const now = new Date().toISOString();

  // Map of port → (label, NSE scripts) for each database family
  const dbProfiles: Record<number, { name: string; scripts: string }> = {
    1433:  { name: 'MSSQL',      scripts: 'ms-sql-info,ms-sql-empty-password,ms-sql-ntlm-info' },
    1521:  { name: 'Oracle',     scripts: 'oracle-sid-brute,oracle-tns-version' },
    3306:  { name: 'MySQL',      scripts: 'mysql-info,mysql-empty-password,mysql-users' },
    5432:  { name: 'PostgreSQL', scripts: 'pgsql-brute' },
    6379:  { name: 'Redis',      scripts: 'redis-info' },
    27017: { name: 'MongoDB',    scripts: 'mongodb-info,mongodb-databases' },
    9200:  { name: 'ElasticSearch', scripts: 'http-elastix-rce' },
    11211: { name: 'memcached',  scripts: 'memcached-info' },
  };

  for (const host of hosts) {
    for (const port of host.ports) {
      const profile = dbProfiles[port];
      if (!profile) continue;
      const args = ['-Pn', '-sV', '-p', String(port), '--script', profile.scripts, '-oN', '-', host.ip];
      const { stdout, code, stderr } = await collectProcess(bin('nmap'), args, spawnOpts());
      if (code !== 0 && !stdout) {
        cb.onError('db-enum', diagnoseSpawnError('nmap', code, stderr).render({ useColor: false, withMark: false }));
        continue;
      }

      // Always emit an INFO finding noting the database service was identified
      findings.push({
        id: generateFindingId('INFO'),
        title: `${profile.name} service identified on ${host.ip}:${port}`,
        severity: 'INFO', host: host.ip, port, source: 'db-enum',
        evidence: [{ label: profile.name, content: stdout.slice(0, 500), timestamp: now }],
        status: 'OPEN', timestamp: now,
      });

      // Empty/default password findings
      if (/empty-password.*Login Successful/i.test(stdout) || /no authentication/i.test(stdout)) {
        findings.push({
          id: generateFindingId('CRITICAL'),
          title: `${profile.name} accepts unauthenticated / empty password`,
          severity: 'CRITICAL', host: host.ip, port, source: 'db-enum',
          evidence: [{ label: profile.name, content: stdout.slice(0, 500), timestamp: now }],
          status: 'OPEN', timestamp: now,
          remediation: `Require authentication on ${profile.name}. Rotate any service-account credentials.`,
        });
      }
    }
  }

  for (const f of findings) cb.onFinding(f);
  return findings;
}
