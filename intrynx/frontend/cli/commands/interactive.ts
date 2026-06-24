/**
 * Interactive wizard — the default `adversa` experience.
 * Users pick from menus and fill fields; the product does the rest.
 */
import { Command }                       from 'commander';
import * as readline                     from 'readline';
import { existsSync, readFileSync, writeFileSync } from 'fs';
import path                              from 'path';
import { runScan, generateFindingId }    from '../../lib/engine/scanner';
import { getAllFindings, getFindingById, updateFinding, updateFindingStatus } from '../../lib/findings-store';
import { MODULES, modulesByCategory, profileModules } from '../../lib/engine/scan-modules';
import type { ScanTool } from '../../lib/engine/types';
import { execSync } from 'child_process';
import type {
  ScanOptions, ScanCallbacks,
  LiveFinding, DiscoveredHost,
} from '../../lib/engine/types';
import * as out                          from '../ui/output';
import * as llm                          from '../llm';
import {
  requireAuth, loadSession, saveSession,
  apiFetch, serverUrl, clearSession,
}                                        from '../auth';

// ── ANSI shortcuts ──────────────────────────────────────────────────
const A = {
  reset: '\x1b[0m', bold: '\x1b[1m', dim: '\x1b[2m',
  red: '\x1b[1;31m', green: '\x1b[1;32m', yellow: '\x1b[33m',
  cyan: '\x1b[1;36m', blue: '\x1b[1;34m', gray: '\x1b[90m',
};
const w  = (s: string) => process.stdout.write(s);
const ln = (s = '')   => process.stdout.write(s + '\n');

// ── Prompt helpers ──────────────────────────────────────────────────
function makeRl(): readline.Interface {
  return readline.createInterface({ input: process.stdin, output: process.stdout });
}

function ask(question: string, dflt?: string): Promise<string> {
  return new Promise((resolve) => {
    const rl = makeRl();
    const hint = dflt ? `${A.dim} [${dflt}]${A.reset}` : '';
    rl.question(`  ${A.cyan}?${A.reset} ${question}${hint} `, (answer) => {
      rl.close();
      const trimmed = answer.trim();
      resolve(trimmed === '' ? (dflt ?? '') : trimmed);
    });
  });
}

function askSecret(question: string): Promise<string> {
  return new Promise((resolve) => {
    const rl = makeRl();
    w(`  ${A.cyan}?${A.reset} ${question} `);
    (process.stdin as NodeJS.ReadStream).setRawMode?.(true);
    let input = '';
    process.stdin.resume();
    process.stdin.setEncoding('utf8');
    const handler = (char: string): void => {
      if (char === '\r' || char === '\n') {
        process.stdin.removeListener('data', handler);
        (process.stdin as NodeJS.ReadStream).setRawMode?.(false);
        w('\n');
        rl.close();
        resolve(input);
      } else if (char === '\x7f' || char === '\b') {
        if (input.length > 0) { input = input.slice(0, -1); w('\b \b'); }
      } else if (char === '\x03') {
        process.exit();
      } else {
        input += char;
        w('*');
      }
    };
    process.stdin.on('data', handler);
  });
}

async function confirm(question: string, dflt = true): Promise<boolean> {
  const ans = await ask(`${question} ${dflt ? '(Y/n)' : '(y/N)'}`);
  if (!ans) return dflt;
  return /^y(es)?$/i.test(ans);
}

async function choose<T>(
  question: string,
  options: { label: string; value: T; hint?: string }[],
): Promise<T> {
  ln();
  ln(`  ${A.bold}${question}${A.reset}`);
  options.forEach((o, i) => {
    const hint = o.hint ? `  ${A.dim}${o.hint}${A.reset}` : '';
    ln(`    ${A.cyan}${i + 1}${A.reset}) ${o.label}${hint}`);
  });
  ln();
  while (true) {
    const raw = await ask(`Choose 1–${options.length}`, '1');
    const n = parseInt(raw, 10);
    if (!isNaN(n) && n >= 1 && n <= options.length) return options[n - 1].value;
    ln(`  ${A.red}Invalid choice.${A.reset}`);
  }
}

function banner(): void {
  ln();
  ln(`  ${A.blue}▄▄▄  ██▄  ▄  ██▄ ▄  ██▄ ██▄  ▄▄${A.reset}    ${A.bold}ADVERSA${A.reset}`);
  ln(`  ${A.blue}▀▀▀█  █ █  █  █   ██ █ █  █ █ █${A.reset}    ${A.dim}Network VAPT Platform${A.reset}`);
  ln(`  ${A.blue}▀▀▀▀  ▀▀▀  ▀  ▀▀▀ ▀  ▀▀▀  ▀▀▀${A.reset}     ${A.dim}Interactive mode${A.reset}`);
  ln();
}

function divider(): void {
  ln(`  ${A.gray}${'─'.repeat(68)}${A.reset}`);
}

// ── Auth wizard ─────────────────────────────────────────────────────
async function ensureAuthenticated(): Promise<void> {
  const existing = loadSession();
  if (existing) return;

  ln(`  ${A.yellow}You're not logged in.${A.reset} Let's get you authenticated.`);
  ln();
  const server = serverUrl();
  ln(`  ${A.dim}Server: ${server}${A.reset}`);
  ln();

  const email = await ask('Email');
  if (!email || !email.includes('@')) {
    ln(`  ${A.red}Invalid email.${A.reset}`);
    process.exit(1);
  }

  ln(`  ${A.dim}Requesting magic code…${A.reset}`);
  const reqRes = await fetch(`${server}/api/auth/request`, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({ email }),
  }).catch(() => null);

  if (!reqRes?.ok) {
    ln(`  ${A.red}Could not reach the server.${A.reset}`);
    ln(`  ${A.dim}Is it running? Try: ./run.sh start${A.reset}`);
    process.exit(1);
  }

  const reqData = await reqRes.json() as { dev?: boolean; otp?: string };
  if (reqData.dev && reqData.otp) {
    ln(`  ${A.yellow}[DEV]${A.reset} OTP: ${A.green}${reqData.otp}${A.reset}`);
  } else {
    ln(`  ${A.dim}Check ${email} for a 6-digit code.${A.reset}`);
  }

  const otp = await askSecret('Enter code');
  if (!otp) { ln(`  ${A.red}No code entered.${A.reset}`); process.exit(1); }

  const verRes = await fetch(`${server}/api/auth/verify`, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({ email, otp }),
  }).catch(() => null);

  const verData = await verRes?.json().catch(() => null) as
    { token?: string; role?: string; error?: string } | null;

  if (!verRes?.ok || !verData?.token) {
    ln(`  ${A.red}${verData?.error ?? 'Authentication failed'}${A.reset}`);
    process.exit(1);
  }

  saveSession({
    email,
    token:   verData.token,
    role:    verData.role ?? 'operator',
    savedAt: new Date().toISOString(),
  });

  ln(`  ${A.green}✓${A.reset} Authenticated as ${A.bold}${email}${A.reset}${verData.role === 'admin' ? ` ${A.cyan}[admin]${A.reset}` : ''}`);
  ln();
}

// ── Target picker — 6 scope modes ──────────────────────────────────
interface TargetSpec {
  targets:                  string[];
  recommendHostDiscovery:   boolean;
  source:                   string;   // human-readable origin label
}

/** A target looks like a single host if it's an IP or hostname with no CIDR/range marker. */
function isSingleHost(t: string): boolean {
  return !t.includes('/') && !t.includes('-');
}

/** Auto-detect the operator's current LAN subnet via the default route. */
function detectLocalSubnet(): string | null {
  try {
    // macOS: route -n get default → "interface: en0"; then ifconfig en0 → inet 192.168.1.42 ...
    if (process.platform === 'darwin') {
      const route = execSync('route -n get default 2>/dev/null', { encoding: 'utf-8' });
      const ifMatch = route.match(/interface:\s*(\S+)/);
      if (!ifMatch) return null;
      const iface = ifMatch[1];
      const ifc = execSync(`ifconfig ${iface}`, { encoding: 'utf-8' });
      const ip = ifc.match(/inet\s+(\d+\.\d+\.\d+\.\d+)\s+netmask\s+0x([0-9a-f]+)/i);
      if (!ip) return null;
      const mask = parseInt(ip[2], 16);
      let prefix = 0;
      for (let m = mask; m & 0x80000000; m <<= 1) prefix++;
      const parts = ip[1].split('.').map(Number);
      const ipInt = ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
      const net = ipInt & (mask >>> 0);
      return `${(net >>> 24) & 255}.${(net >>> 16) & 255}.${(net >>> 8) & 255}.${net & 255}/${prefix}`;
    }
    // Linux: ip -4 route show default → "default via X dev eth0"; ip -4 addr show eth0
    const route = execSync('ip -4 route show default 2>/dev/null', { encoding: 'utf-8' });
    const ifMatch = route.match(/dev\s+(\S+)/);
    if (!ifMatch) return null;
    const iface = ifMatch[1];
    const ifc = execSync(`ip -4 addr show ${iface}`, { encoding: 'utf-8' });
    const ip = ifc.match(/inet\s+(\d+\.\d+\.\d+\.\d+\/\d+)/);
    return ip ? ip[1] : null;
  } catch {
    return null;
  }
}

async function pickTargets(): Promise<TargetSpec | null> {
  ln();
  const mode = await choose<'single' | 'cidr' | 'file' | 'previous' | 'local' | 'domain'>(
    'How do you want to define your scan scope?',
    [
      { label: 'Single host or short list',          value: 'single',   hint: 'e.g. 192.168.1.30  or  10.0.0.1,10.0.0.2' },
      { label: 'CIDR / IP range',                    value: 'cidr',     hint: 'e.g. 192.168.1.0/24 — host discovery runs first' },
      { label: 'Read targets from a file',           value: 'file',     hint: 'one target per line' },
      { label: 'Reuse hosts from previous scan',     value: 'previous', hint: 'pre-seeds from data/findings.json' },
      { label: 'Auto-detect my current local LAN',   value: 'local',    hint: 'reads your default-gateway interface' },
      { label: 'From a domain (subdomain enum)',     value: 'domain',   hint: 'subfinder + DNS recon → discovered hosts' },
    ],
  );

  if (mode === 'single') {
    const raw = await ask('Host(s)', '127.0.0.1');
    const targets = raw.split(',').map((t) => t.trim()).filter(Boolean);
    return { targets, recommendHostDiscovery: false, source: 'typed (single host list)' };
  }

  if (mode === 'cidr') {
    const raw = await ask('CIDR or range', '192.168.1.0/24');
    const targets = raw.split(',').map((t) => t.trim()).filter(Boolean);
    return { targets, recommendHostDiscovery: true, source: 'CIDR / range' };
  }

  if (mode === 'file') {
    const file = await ask('File path', 'targets.txt');
    if (!existsSync(file)) { ln(`  ${A.red}File not found.${A.reset}`); return null; }
    const targets = readFileSync(file, 'utf-8').split(/[\r\n]+/).map((t) => t.trim()).filter(Boolean);
    const needDiscovery = targets.some((t) => !isSingleHost(t));
    return { targets, recommendHostDiscovery: needDiscovery, source: `file: ${file}` };
  }

  if (mode === 'previous') {
    const targets = inferHostsFromFindings([]).map((h) => h.ip);
    if (targets.length === 0) {
      ln(`  ${A.red}No prior hosts in data/findings.json.${A.reset}`);
      return null;
    }
    ln(`  ${A.green}✓${A.reset} Loaded ${targets.length} host(s) from previous scans.`);
    return { targets, recommendHostDiscovery: false, source: 'reused (previous findings)' };
  }

  if (mode === 'local') {
    const subnet = detectLocalSubnet();
    if (!subnet) {
      ln(`  ${A.red}Could not detect local subnet.${A.reset}`);
      ln(`  ${A.dim}Use the CIDR option instead, or run \`ip route\` / \`ifconfig\` to find it manually.${A.reset}`);
      return null;
    }
    ln(`  ${A.dim}Detected:${A.reset} ${subnet}`);
    ln(`  ${A.yellow}!${A.reset} ${A.dim}Scanning your LAN will touch every device — phones, IoT, printers, neighbours on the same Wi-Fi. Only proceed if you own / are authorized for every device on this subnet.${A.reset}`);
    if (!(await confirm(`Use ${subnet} as scan scope?`, false))) return null;
    return { targets: [subnet], recommendHostDiscovery: true, source: `auto-detected LAN: ${subnet}` };
  }

  if (mode === 'domain') {
    const domain = await ask('Domain', 'example.com');
    if (!domain || !domain.includes('.')) { ln(`  ${A.red}Invalid domain.${A.reset}`); return null; }
    return { targets: [domain], recommendHostDiscovery: false, source: `domain: ${domain} (subdomain enum will run)` };
  }

  return null;
}

// ── Wizard: run a scan ──────────────────────────────────────────────
type Tool = ScanTool;

/**
 * Category-based stage picker — like a real offensive-sec operator workflow.
 * For each category, asks "include any from this category?", then asks per-tool.
 * Pre-selected modules (the defaults) get a [Y/n] prompt; off-by-default ones get [y/N].
 */
async function pickModulesByCategory(
  initial: Set<Tool>,
  isDomainScope: boolean,
  allowedModules?: Tool[],   // optional: restrict picker to this subset
): Promise<Tool[]> {
  const chosen = new Set<Tool>(initial);
  const cats = modulesByCategory();
  const isAllowed = (id: Tool): boolean => !allowedModules || allowedModules.includes(id);

  for (const [category, modules] of Object.entries(cats)) {
    if (category === 'External Recon' && !isDomainScope) continue;

    const visibleModules = modules.filter((m) => isAllowed(m.id));
    if (visibleModules.length === 0) continue;

    ln();
    ln(`  ${A.bold}${category}${A.reset}`);
    for (const m of visibleModules) {
      if (m.domainOnly && !isDomainScope) continue;
      const currentlyOn = chosen.has(m.id);
      const triggerHint = m.triggerPorts ? `${A.dim} [auto-fires on ports ${m.triggerPorts.slice(0, 4).join(',')}${m.triggerPorts.length > 4 ? '…' : ''}]${A.reset}` : '';
      const want = await confirm(`  ${m.label}${triggerHint}  ${A.dim}— ${m.description}${A.reset}`, currentlyOn);
      if (want) chosen.add(m.id); else chosen.delete(m.id);
    }
  }

  return [...chosen];
}

async function wizardScan(): Promise<void> {
  ln();
  ln(`  ${A.cyan}▶ Run a scan${A.reset}`);
  divider();

  // ── Targets: 6 scope-definition modes ───────────────────────────
  const scope = await pickTargets();
  if (!scope) return;
  const { targets, recommendHostDiscovery, source } = scope;
  if (targets.length === 0) { ln(`  ${A.red}No targets.${A.reset}`); return; }

  ln();
  ln(`  ${A.green}✓${A.reset} ${targets.length} target(s) from ${source}: ${A.dim}${targets.slice(0, 3).join(', ')}${targets.length > 3 ? ` …+${targets.length - 3}` : ''}${A.reset}`);
  if (recommendHostDiscovery) {
    ln(`  ${A.dim}Host discovery will run first to identify live hosts.${A.reset}`);
  } else {
    ln(`  ${A.dim}Direct port scan (targets look like specific hosts — host discovery skipped).${A.reset}`);
  }

  // ── Engagement mode — host-only / autonomous / iterative / one-shot / validate ─
  const mode2 = await choose<'host_only' | 'autonomous' | 'iterative' | 'oneshot' | 'validate_only'>(
    'How do you want to drive this engagement?', [
      { label: 'Host discovery only',                  value: 'host_only',     hint: 'Quick ping sweep — just show me what\'s alive on the network, then stop' },
      { label: 'Autonomous (AI drives, you approve)',  value: 'autonomous',    hint: 'Claude picks each tool call; safety envelope gates risky actions; you set the rung' },
      { label: 'Phase-by-phase (iterative)',           value: 'iterative',     hint: 'You pick each phase; AI advises' },
      { label: 'Quick one-shot (full pipeline)',       value: 'oneshot',       hint: 'Pick all stages up front, run to completion' },
      { label: 'Validate existing findings',           value: 'validate_only', hint: 'No new scan — re-verify what\'s in data/findings.json' },
    ],
  );

  if (mode2 === 'validate_only') {
    ln();
    await runValidationFlow();
    return;
  }

  if (mode2 === 'host_only') {
    await runHostDiscoveryOnly(targets, source);
    return;
  }

  if (mode2 === 'autonomous') {
    await runAutonomousMode(targets, source);
    return;
  }

  if (mode2 === 'iterative') {
    await runIterativeEngagement(targets, recommendHostDiscovery, source);
    return;
  }

  // ── one-shot path falls through to the original flow ──────────────
  const kind: 'discover' | 'discover_vuln' = 'discover_vuln';

  // ── Profile vs custom selection
  const mode = await choose<'profile' | 'custom'>('How do you want to pick scan stages?', [
    { label: 'Use a profile',            value: 'profile', hint: 'fast / standard / deep' },
    { label: 'Pick modules by category', value: 'custom',  hint: 'recon / discovery / web / vuln / crypto — full control' },
  ]);

  let tools: Tool[];
  let profile: 'fast' | 'standard' | 'deep' = 'standard';

  // Modules in the "discovery" bucket — what runs in phase 1.
  const DISCOVERY_MODULES: Tool[] = [
    'subfinder', 'dns-recon',
    'host-discovery', 'naabu', 'udp-scan', 'nmap', 'os-detect',
    'smb-enum', 'netbios-enum', 'snmp-enum', 'ldap-enum', 'rpc-enum', 'nfs-enum', 'rdp-fingerprint', 'db-enum',
    'httpx', 'whatweb',
  ];

  if (mode === 'profile') {
    profile = await choose<'fast' | 'standard' | 'deep'>('Scan profile', [
      { label: 'Fast',     value: 'fast',     hint: 'naabu + service enum  ·  ~minutes' },
      { label: 'Standard', value: 'standard', hint: 'host discovery + naabu + nmap + service enum  ·  recommended' },
      { label: 'Deep',     value: 'deep',     hint: 'full discovery + UDP + OS detect + every enum module' },
    ]);
    tools = profileModules(profile);
    // Honour the smart-routing recommendation from the scope picker
    if (recommendHostDiscovery && !tools.includes('host-discovery')) {
      tools = ['host-discovery', ...tools];
    } else if (!recommendHostDiscovery) {
      tools = tools.filter((t) => t !== 'host-discovery');
    }
    // Domain scope auto-enables subfinder + dns-recon
    if (source.startsWith('domain:')) {
      if (!tools.includes('subfinder'))  tools = ['subfinder', ...tools];
      if (!tools.includes('dns-recon'))  tools = ['dns-recon', ...tools];
    }
  } else {
    ln();
    ln(`  ${A.bold}Pick DISCOVERY modules${A.reset}  ${A.dim}(vuln check selection comes after discovery completes)${A.reset}`);
    const startSelection = new Set<Tool>(profileModules('standard').filter((t) => DISCOVERY_MODULES.includes(t)));
    if (recommendHostDiscovery) startSelection.add('host-discovery');
    else                        startSelection.delete('host-discovery');
    if (source.startsWith('domain:')) {
      startSelection.add('subfinder');
      startSelection.add('dns-recon');
    }
    const isDomainScope = source.startsWith('domain:');
    tools = await pickModulesByCategory(startSelection, isDomainScope, DISCOVERY_MODULES);
    if (tools.length === 0) { ln(`  ${A.red}No modules picked.${A.reset}`); return; }
  }

  // ── Reuse previous hosts when skipping naabu
  let reusedHosts: DiscoveredHost[] = [];
  if (!tools.includes('naabu')) {
    ln();
    ln(`  ${A.yellow}Note:${A.reset} you skipped naabu (port discovery). Later stages need a host:port list.`);
    const source = await choose<'previous' | 'manual' | 'skip'>('Where should hosts come from?', [
      { label: 'Reuse hosts from previous scan findings', value: 'previous', hint: 'inferred from data/findings.json' },
      { label: 'I will type the ports manually',           value: 'manual',   hint: 'e.g. 127.0.0.1:80,443' },
      { label: 'Just run what you can without host list',  value: 'skip',     hint: 'most stages will produce 0 results' },
    ]);
    if (source === 'previous') {
      reusedHosts = inferHostsFromFindings(targets);
      if (reusedHosts.length === 0) {
        ln(`  ${A.red}No prior findings match these targets.${A.reset}`);
        if (!(await confirm('Continue anyway?', false))) return;
      } else {
        ln(`  ${A.green}✓${A.reset} Loaded ${reusedHosts.length} host(s) from findings store.`);
        for (const h of reusedHosts) {
          ln(`    ${A.dim}${h.ip}${A.reset}  ports: ${h.ports.join(', ')}`);
        }
      }
    } else if (source === 'manual') {
      const raw = await ask('host:port,host:port  (e.g. 127.0.0.1:80,127.0.0.1:8080)');
      reusedHosts = parseManualHosts(raw);
      if (reusedHosts.length === 0) { ln(`  ${A.red}Could not parse any host:port pairs.${A.reset}`); return; }
      ln(`  ${A.green}✓${A.reset} Using ${reusedHosts.length} host(s) you specified.`);
    }
  }

  // ── Stealth
  const stealthRaw = await ask('Stealth level (1 = quiet, 9 = fast)', '5');
  const stealth = Math.min(9, Math.max(1, parseInt(stealthRaw, 10) || 5));

  // ── Output options
  ln();
  ln(`  ${A.bold}Output options${A.reset}`);
  const save  = await confirm('Persist findings to data/findings.json?', true);
  const useAi = await confirm('Enable AI commentary during scan?',       true);

  // ── Optional engagement
  const tagEng = await confirm('Tag this scan to an engagement?', false);
  let engagementId: string | undefined;
  if (tagEng) {
    engagementId = await pickEngagementId();
  }

  // ── Summary + confirm
  ln();
  ln(`  ${A.bold}Review${A.reset}`);
  ln(`    ${A.dim}Targets:${A.reset}    ${targets.join(', ')}`);
  ln(`    ${A.dim}Stages:${A.reset}     ${tools.join(' → ')}`);
  ln(`    ${A.dim}Stealth:${A.reset}    ${stealth}/9`);
  if (reusedHosts.length > 0) {
    ln(`    ${A.dim}Reused:${A.reset}     ${reusedHosts.length} host(s) from previous data`);
  }
  ln(`    ${A.dim}Save:${A.reset}       ${save ? 'yes' : 'no'}`);
  ln(`    ${A.dim}AI:${A.reset}         ${useAi ? 'yes' : 'no'}`);
  if (engagementId) ln(`    ${A.dim}Engagement:${A.reset} ${engagementId}`);
  ln();
  if (!(await confirm('Start scan?', true))) return;

  const opts: ScanOptions = {
    targets, profile, stealth,
    tools,
    save,
    engagementId,
    scanId: `SCAN-${Date.now()}`,
  };

  const session = requireAuth();
  out.banner();
  out.scanHeader(targets, profile, stealth, opts.tools);
  ln(`  ${A.dim}Operator:${A.reset} ${session.email}`);
  ln();

  const discovered: DiscoveredHost[] = [];
  const allFindings: LiveFinding[]   = [];
  const stageFindings = new Map<string, LiveFinding[]>();
  let   currentStage = '';

  const printAiComment = (text: string): void => {
    for (const line of text.split('\n')) {
      ln(`  ${A.dim}${A.cyan}▸${A.reset} ${A.dim}${line}${A.reset}`);
    }
  };

  const callbacks: ScanCallbacks = {
    onStageStart(stage) { currentStage = stage; stageFindings.set(stage, []); out.stageStart(stage); },
    async onStageComplete(stage, summary) {
      out.stageComplete(stage, summary);
      if (useAi) {
        const c = await llm.commentOnStage(stage, summary, discovered, allFindings);
        if (c) printAiComment(c);
        const found = stageFindings.get(stage) ?? [];
        if (found.length > 0) {
          const ctx = await llm.explainFindings(found);
          for (const [id] of ctx) {
            const f = found.find((x) => x.id === id);
            if (f) ln(`    ${A.dim}└─ ${ctx.get(id)}${A.reset}`);
          }
        }
      }
    },
    onHostDiscovered(host) {
      if (!discovered.find((h) => h.ip === host.ip)) discovered.push(host);
      out.hostLine(host);
    },
    onFinding(f) {
      allFindings.push(f);
      stageFindings.get(currentStage)?.push(f);
      out.findingLine(f);
    },
    onProgress(pct, msg) { out.stageProgress(pct, msg); },
    onError(stage, err)   { out.stageError(stage, err); },
    async onComplete(s) {
      out.summary(s);
      if (useAi && allFindings.length > 0) {
        ln(`\n  ${A.cyan}AI Attack Path Analysis${A.reset}`);
        const p = await llm.suggestAttackPath(discovered, allFindings, s);
        if (p) printAiComment(p);
        ln();
      }
      if (save) out.info(`Findings saved to data/findings.json (${allFindings.length} new)`);
    },
  };

  // Seed reusedHosts into the discovered list so later stages see them.
  // The scanner.ts hand-off happens via tool-runners' input args. The cleanest
  // way to inject is via the onStageStart hook for the first non-naabu stage:
  // we replace its host arg list. Simpler: monkey-patch by re-injecting hosts
  // through the host-discovered callback before runScan starts, so the
  // tool-runners' hosts parameter (built inside scanner.ts from naabu output)
  // is supplemented. Since the scanner currently reads from naabu's return,
  // when naabu is skipped, the hosts array stays empty. We patch that by
  // exposing reusedHosts via env: tool-runners read process.env.ADVERSA_REUSED_HOSTS.
  if (reusedHosts.length > 0) {
    process.env.ADVERSA_REUSED_HOSTS = JSON.stringify(reusedHosts);
  } else {
    delete process.env.ADVERSA_REUSED_HOSTS;
  }

  try {
    await runScan(opts, callbacks);
  } catch (e) {
    out.error(`Scan failed: ${e instanceof Error ? e.message : String(e)}`);
  } finally {
    delete process.env.ADVERSA_REUSED_HOSTS;
  }

  // ── Phase 2: Vuln assessment (only if user picked "Discovery + Vuln") ─
  if (kind === 'discover_vuln' && discovered.length > 0) {
    ln();
    ln(`  ${A.cyan}━━━━━ Discovery complete — moving to vulnerability assessment ━━━━━${A.reset}`);
    ln();
    await runVulnAssessmentFlow(discovered, allFindings, source.startsWith('domain:'), useAi);
  }
}

// ────────────────────────────────────────────────────────────────────
//  HOST DISCOVERY ONLY — quick "what's alive on my network" sweep
// ────────────────────────────────────────────────────────────────────

async function runHostDiscoveryOnly(targets: string[], source: string): Promise<void> {
  ln();
  ln(`  ${A.cyan}━━━━━ Host discovery only ━━━━━${A.reset}`);
  ln(`  ${A.dim}Multi-protocol ping (ICMP / ARP / TCP-SYN / TCP-ACK / UDP) against ${targets.join(', ')}${A.reset}`);
  ln(`  ${A.dim}This just finds live hosts — no port scan, no service detect, no vuln check.${A.reset}`);
  ln();

  const opts: ScanOptions = {
    targets,
    profile: 'fast',
    stealth: 5,
    tools:   ['host-discovery'],
    save:    false,
    scanId:  `HOSTDISC-${Date.now()}`,
  };

  const discovered: DiscoveredHost[] = [];
  const callbacks: ScanCallbacks = {
    onStageStart(s)             { out.stageStart(s); },
    onStageComplete(s, summary) { out.stageComplete(s, summary); },
    onHostDiscovered(h)         { discovered.push(h); out.hostLine(h); },
    onFinding(f)                { out.findingLine(f); },
    onProgress(pct, msg)        { out.stageProgress(pct, msg); },
    onError(s, e)               { out.stageError(s, e); },
    onComplete()                {},
  };

  try {
    await runScan(opts, callbacks);
  } catch (e) {
    out.error(`Discovery failed: ${e instanceof Error ? e.message : String(e)}`);
    return;
  }

  ln();
  ln(`  ${A.cyan}━━━━━ Discovery complete ━━━━━${A.reset}`);
  ln();
  if (discovered.length === 0) {
    ln(`  ${A.yellow}No live hosts found.${A.reset}`);
    ln();
    ln(`  ${A.dim}Common causes:${A.reset}`);
    ln(`    1. Wi-Fi isolation (guest networks block client-to-client traffic)`);
    ln(`    2. ICMP blocked on hosts and tcp-ping probe ports not open`);
    ln(`    3. Wrong subnet — verify with ${A.dim}arp -a${A.reset}`);
    ln(`    4. Empty network — actually nothing on the range`);
    ln();
    return;
  }

  ln(`  ${A.bold}${discovered.length} live host(s) on ${targets.join(', ')}${A.reset}`);
  ln(`  ${A.gray}${'─'.repeat(68)}${A.reset}`);
  for (const h of discovered) {
    const hostname = h.hostnames?.[0] ? `  ${A.dim}(${h.hostnames[0]})${A.reset}` : '';
    const method = h.discoveryMethod ? `  ${A.dim}[${h.discoveryMethod}]${A.reset}` : '';
    ln(`    ${A.cyan}${h.ip}${A.reset}${hostname}${method}`);
  }
  ln();

  const save = await confirm('Save these hosts as INFO findings to data/findings.json?', false);
  if (save) {
    try {
      const { saveFindings } = await import('../../lib/findings-store');
      const now = new Date().toISOString();
      const findings: LiveFinding[] = discovered.map((h) => ({
        id:        generateFindingId('INFO'),
        title:     `Live host: ${h.ip}${h.hostnames?.[0] ? ` (${h.hostnames[0]})` : ''}`,
        severity:  'INFO',
        host:      h.ip,
        source:    'host-discovery',
        evidence:  [{ label: 'host discovery', content: `Method: ${h.discoveryMethod ?? 'unknown'} · Source: ${source}`, timestamp: now }],
        status:    'OPEN',
        timestamp: now,
      }));
      const saved = saveFindings(findings);
      ln(`  ${A.green}✓${A.reset} Saved ${saved} host record(s) to data/findings.json`);
    } catch (e) {
      out.error(`Could not save: ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  ln();
  const next = await choose<'port_scan' | 'menu' | 'stop'>('What now?', [
    { label: 'Continue — port scan these hosts',  value: 'port_scan', hint: 'find open TCP ports on what we just discovered' },
    { label: 'Return to main menu',                value: 'menu' },
    { label: 'Stop',                                value: 'stop' },
  ]);

  if (next === 'port_scan') {
    // Hand off to iterative engagement, pre-seeding the discovered hosts
    process.env.ADVERSA_REUSED_HOSTS = JSON.stringify(discovered);
    try {
      await runIterativeEngagement(discovered.map((h) => h.ip), false, `${source} (continued from host discovery)`);
    } finally {
      delete process.env.ADVERSA_REUSED_HOSTS;
    }
  }
}

// ────────────────────────────────────────────────────────────────────
//  AUTONOMOUS MODE — Claude drives via tool-use, safety envelope gates
// ────────────────────────────────────────────────────────────────────

async function runAutonomousMode(targets: string[], source: string): Promise<void> {
  ln();
  ln(`  ${A.cyan}━━━━━ Autonomous engagement ━━━━━${A.reset}`);
  ln();
  if (!process.env.ANTHROPIC_API_KEY) {
    ln(`  ${A.red}ANTHROPIC_API_KEY is not set in .env.local.${A.reset}`);
    ln(`  ${A.dim}Autonomous mode requires AI. Set the key and restart the server.${A.reset}`);
    return;
  }

  const { runAutonomousEngagement } = await import('../../lib/agent/agent');

  const rung = await choose<1 | 2 | 3>('Pick the autonomy rung', [
    { label: 'Rung 1 — Co-pilot',     value: 1, hint: 'You approve every tool call. Safest for first run.' },
    { label: 'Rung 2 — Bounded',      value: 2, hint: 'Auto-runs READ_ONLY + ACTIVE. You approve STATE_CHANGE.' },
    { label: 'Rung 3 — Engagement autonomous', value: 3, hint: 'Auto-runs everything except DESTRUCTIVE. Use only when you trust the scope policy.' },
  ]);

  const budgetRaw = await ask('Action budget (max tool calls before forced stop)', '25');
  const actionBudget = Math.max(5, Math.min(200, parseInt(budgetRaw, 10) || 25));

  ln();
  ln(`  ${A.bold}Review${A.reset}`);
  ln(`    ${A.dim}Scope:${A.reset}        ${targets.join(', ')}`);
  ln(`    ${A.dim}Origin:${A.reset}       ${source}`);
  ln(`    ${A.dim}Rung:${A.reset}         ${rung}`);
  ln(`    ${A.dim}Budget:${A.reset}       ${actionBudget} tool calls`);
  ln();
  if (!(await confirm('Start autonomous engagement?', true))) return;

  ln();
  ln(`  ${A.dim}Claude will now drive the engagement. Press Ctrl+C to interrupt.${A.reset}`);
  ln();

  // UI wrappers
  const printAgentText = (text: string): void => {
    for (const line of text.split('\n')) {
      ln(`  ${A.cyan}AI${A.reset}  ${A.dim}${line}${A.reset}`);
    }
  };
  const riskColor = (r: string): string => r === 'DESTRUCTIVE' ? A.red : r === 'STATE_CHANGE' ? A.yellow : r === 'ACTIVE' ? A.cyan : A.green;

  const state = await runAutonomousEngagement(
    {
      scope:        targets,
      scopeLabel:   source,
      rung,
      actionBudget,
    },
    {
      cb: {
        onStageStart(s)            { out.stageStart(s); },
        onStageComplete(s, summary){ out.stageComplete(s, summary); },
        onHostDiscovered(h)        { out.hostLine(h); },
        onFinding(f)               { out.findingLine(f); },
        onProgress(p, m)           { out.stageProgress(p, m); },
        onError(s, e)              { out.stageError(s, e); },
        onComplete()               {},
      },
      ui: {
        onAgentThinking: (text) => { ln(); printAgentText(text); },
        onProposal: (tool, input, risk) => {
          ln(`  ${A.dim}→${A.reset} ${A.bold}${tool}${A.reset}  ${riskColor(risk)}[${risk}]${A.reset}  ${A.dim}${JSON.stringify(input).slice(0, 100)}${A.reset}`);
        },
        requestApproval: async (tool, input, risk) => {
          ln();
          ln(`  ${A.yellow}⚠  Approval required:${A.reset} ${A.bold}${tool}${A.reset}  ${riskColor(risk)}[${risk}]${A.reset}`);
          ln(`     ${A.dim}args:${A.reset} ${JSON.stringify(input)}`);
          return await confirm('  Approve?', false);
        },
        onResult: (tool, ok, summary) => {
          if (ok) ln(`  ${A.green}✓${A.reset} ${tool} → ${A.dim}${summary}${A.reset}`);
          else    ln(`  ${A.red}✗${A.reset} ${tool} failed: ${summary}`);
        },
        onFinalSummary: (reason, st) => {
          ln();
          ln(`  ${A.cyan}━━━━━ Engagement complete ━━━━━${A.reset}`);
          ln(`    ${A.dim}Reason:${A.reset}   ${reason}`);
          ln(`    ${A.dim}Hosts:${A.reset}    ${st.hosts.length}`);
          ln(`    ${A.dim}Findings:${A.reset} ${st.findings.length}  (${A.red}${st.findings.filter((f) => f.severity === 'CRITICAL').length} crit${A.reset}, ${st.findings.filter((f) => f.severity === 'HIGH').length} high)`);
          ln(`    ${A.dim}Tool calls:${A.reset} ${st.log.length}`);
          ln();
        },
        onError: (msg) => { ln(`  ${A.red}✗${A.reset} ${msg}`); },
      },
    },
  );

  // Hand off to validation if findings exist
  if (state.findings.length > 0) {
    ln();
    if (await confirm('Validate the agent\'s findings now?', true)) {
      await runValidationFlow(state.findings, true);
    }
  }
}

// ────────────────────────────────────────────────────────────────────
//  ITERATIVE ENGAGEMENT — phase-by-phase with decision points
// ────────────────────────────────────────────────────────────────────
//
// The flow matches how a real pentester actually works on an internal network:
//   1. Find live hosts (host discovery only — no port scan yet)
//   2. Look at what's there, decide which hosts to probe
//   3. Port scan those hosts
//   4. Look at open ports, decide whether to do service detection
//   5. Service detection
//   6. Now we know what's running — pick service-specific enumeration
//   7. Vulnerability assessment on the high-value services
//   8. Validate findings (manual / AI batch)
//   9. (Optional) Exploit verified findings — human-gated, AI-planned

interface PhaseState {
  hosts:    DiscoveredHost[];
  findings: LiveFinding[];
  source:   string;          // scope origin for context
  useAi:    boolean;
}

async function runIterativeEngagement(
  targets:               string[],
  recommendHostDiscovery: boolean,
  source:                string,
): Promise<void> {
  ln();
  ln(`  ${A.cyan}━━━━━ Phase-by-phase engagement starting ━━━━━${A.reset}`);
  ln(`  ${A.dim}You'll see what each phase found before deciding the next move.${A.reset}`);
  ln();

  const useAi = !!process.env.ANTHROPIC_API_KEY && await confirm('Enable AI commentary + next-phase recommendations?', true);
  const state: PhaseState = { hosts: [], findings: [], source, useAi };

  // ── Phase 1 — ALWAYS run host discovery for CIDR / LAN / range scopes
  if (recommendHostDiscovery) {
    ln();
    ln(`  ${A.cyan}▶ Phase 1: Host discovery${A.reset}`);
    state.hosts = await runPhaseHostDiscovery(targets);
    if (state.hosts.length === 0) {
      ln(`  ${A.red}No live hosts found.${A.reset}`);
      printHostDiscoveryDiagnostic(targets);
      return;
    }
    printHostSummary(state.hosts, 'Live hosts found');
  } else {
    // Single host / list — seed directly
    state.hosts = targets.map((t) => ({ ip: t, ports: [], services: [] }));
    ln(`  ${A.dim}Targets are specific hosts — skipping host discovery.${A.reset}`);
  }

  // ── Iterative loop ─────────────────────────────────────────────
  let cycle = 1;
  while (true) {
    const next = await chooseNextPhase(state);
    if (next === 'stop' || next === 'report') {
      if (next === 'report') ln(`  ${A.dim}Tip: use the main menu → Generate AI report to write a full report.${A.reset}`);
      break;
    }

    ln();
    ln(`  ${A.cyan}▶ Phase ${++cycle}: ${phaseLabel(next)}${A.reset}`);

    if (next === 'port_scan')      state.hosts    = await runPhasePortScan(state.hosts);
    if (next === 'service_detect') state.hosts    = await runPhaseServiceDetect(state.hosts);
    if (next === 'enumerate')      state.findings = state.findings.concat(await runPhaseEnumeration(state.hosts));
    if (next === 'vuln_assess')    state.findings = state.findings.concat(await runPhaseVulnAssess(state.hosts));
    if (next === 'validate')       await runValidationFlow(state.findings.length > 0 ? state.findings : undefined, state.useAi);
    if (next === 'exploit')        await runPhaseExploitation(state);

    printStateSummary(state);
  }

  // Persist findings
  if (state.findings.length > 0) {
    try {
      const { saveFindings } = await import('../../lib/findings-store');
      const saved = saveFindings(state.findings);
      ln(`  ${A.green}✓${A.reset} ${saved} finding(s) saved to data/findings.json`);
    } catch (e) {
      out.error(`Could not persist findings: ${e instanceof Error ? e.message : String(e)}`);
    }
  }
}

function phaseLabel(p: string): string {
  return ({
    host_discovery: 'Host discovery',
    port_scan:      'Port scan',
    service_detect: 'Service detection',
    enumerate:      'Service enumeration',
    vuln_assess:    'Vulnerability assessment',
    validate:       'Validation',
    exploit:        'Exploitation',
    report:         'Reporting',
    stop:           'Stop',
  } as Record<string, string>)[p] ?? p;
}

// ── State summary printer ────────────────────────────────────────
function printStateSummary(state: PhaseState): void {
  const openPorts = state.hosts.reduce((s, h) => s + h.ports.length, 0);
  const withServices = state.hosts.filter((h) => h.services.some((s) => s.name)).length;
  const crit = state.findings.filter((f) => f.severity === 'CRITICAL').length;
  const high = state.findings.filter((f) => f.severity === 'HIGH').length;
  const verified = state.findings.filter((f) => f.status === 'VERIFIED').length;
  ln();
  ln(`  ${A.dim}State:${A.reset} ${state.hosts.length} hosts · ${openPorts} open ports · ${withServices} hosts with service info · ${state.findings.length} findings (${A.red}${crit} crit, ${high} high${A.reset}, ${A.green}${verified} verified${A.reset})`);
}

function printHostSummary(hosts: DiscoveredHost[], heading: string): void {
  ln();
  ln(`  ${A.bold}${heading}${A.reset}`);
  for (const h of hosts.slice(0, 20)) {
    const portStr = h.ports.length > 0 ? `  ports: ${h.ports.slice(0, 8).join(',')}${h.ports.length > 8 ? '+…' : ''}` : '';
    const hostnameStr = h.hostnames?.[0] ? `  ${A.dim}(${h.hostnames[0]})${A.reset}` : '';
    const osStr = h.os ? `  ${A.dim}[${h.os}]${A.reset}` : '';
    ln(`    ${A.cyan}${h.ip}${A.reset}${hostnameStr}${portStr}${osStr}`);
  }
  if (hosts.length > 20) ln(`    ${A.dim}…+${hosts.length - 20} more${A.reset}`);
}

function printHostDiscoveryDiagnostic(targets: string[]): void {
  ln();
  ln(`  ${A.yellow}Possible causes:${A.reset}`);
  ln(`    1. Target unreachable — wrong subnet / VPN not connected. Try: ${A.dim}ping ${targets[0]?.split('/')[0]}${A.reset}`);
  ln(`    2. ICMP blocked — switch to "Single host" mode to skip host discovery`);
  ln(`    3. Firewall — try higher stealth (slower) or a single IP first`);
  ln(`    4. Empty subnet — nothing on the range. Try ${A.dim}arp -a${A.reset} to verify`);
}

// ── Next-phase chooser (with AI recommendation) ──────────────────
async function chooseNextPhase(state: PhaseState): Promise<string> {
  const hasPorts    = state.hosts.some((h) => h.ports.length > 0);
  const hasServices = state.hosts.some((h) => h.services.some((s) => s.name));
  const hasFindings = state.findings.length > 0;
  const hasVerified = state.findings.some((f) => f.status === 'VERIFIED');

  const options: Array<{ id: string; label: string; hint: string }> = [];
  if (!hasPorts)                  options.push({ id: 'port_scan',      label: 'Port scan (TCP)',                 hint: 'find open ports on each host' });
  if (hasPorts && !hasServices)   options.push({ id: 'service_detect', label: 'Service / version detection',     hint: 'identify what\'s running on each port' });
  if (hasPorts && hasServices)    options.push({ id: 'service_detect', label: 'Re-run service detection (deeper)', hint: 'force nmap -sV with max version intensity for unidentified services' });
  if (hasServices)                options.push({ id: 'enumerate',      label: 'Service-specific enumeration',    hint: 'SMB / SNMP / LDAP / RPC / RDP / DB deep dive (auto-fires on matching ports)' });
  if (hasPorts)                   options.push({ id: 'vuln_assess',    label: 'Vulnerability assessment',        hint: 'CVE scan + TLS audit + SSH audit on the open services' });
  if (hasFindings)  options.push({ id: 'validate',       label: 'Validate findings',                hint: 'AI batch triage / manual / rule-based' });
  if (hasVerified)  options.push({ id: 'exploit',        label: 'Attempt exploitation',             hint: 'AI-planned, human-approved, verification-only by default' });
  options.push(     { id: 'report',     label: 'Generate report',  hint: 'AI pentest report on what was found' });
  options.push(     { id: 'stop',       label: 'Stop here',         hint: 'save findings and exit the engagement loop' });

  ln();
  ln(`  ${A.bold}What's next?${A.reset}`);

  // AI recommendation (if available + enabled)
  if (state.useAi) {
    const rec = await llm.recommendNextPhase(state.hosts, state.findings, options.map((o) => o.id) as llm.PhaseId[]);
    if (rec) {
      const idx = options.findIndex((o) => o.id === rec.recommended);
      if (idx >= 0) {
        ln(`  ${A.dim}${A.cyan}▸ AI recommends:${A.reset} ${options[idx].label}  ${A.dim}— ${rec.reasoning}${A.reset}`);
        ln();
      }
    }
  }

  return choose<string>('Choose next phase', options.map((o) => ({ label: o.label, value: o.id, hint: o.hint })));
}

// ── Per-phase runners (thin wrappers over runScan with the right tools) ─
async function runPhaseWithTools(hosts: DiscoveredHost[], tools: Tool[], targets?: string[]): Promise<{ hosts: DiscoveredHost[]; findings: LiveFinding[] }> {
  const newHosts: DiscoveredHost[] = [...hosts];
  const newFindings: LiveFinding[] = [];

  const opts: ScanOptions = {
    targets: targets ?? hosts.map((h) => h.ip),
    profile: 'standard',
    stealth: 5,
    tools,
    save:    false,    // we save once at the end of the engagement
    scanId:  `PHASE-${Date.now()}`,
  };

  // Pass current host state via env (so port-scan/enum stages don't re-discover).
  // For naabu / host-discovery phases we must NOT inherit a stale ADVERSA_REUSED_HOSTS
  // value from a prior phase — that would cause scanner.ts to pre-seed and re-emit
  // every previously-discovered host even if the user selected only a subset to scan.
  if (hosts.length > 0 && !tools.includes('host-discovery') && !tools.includes('naabu')) {
    process.env.ADVERSA_REUSED_HOSTS = JSON.stringify(hosts);
  } else {
    delete process.env.ADVERSA_REUSED_HOSTS;
  }

  const cb: ScanCallbacks = {
    onStageStart(s)            { out.stageStart(s); },
    onStageComplete(s, summary) { out.stageComplete(s, summary); },
    onHostDiscovered(h)        {
      const existing = newHosts.find((x) => x.ip === h.ip);
      if (existing) {
        // Merge: union ports / services
        for (const p of h.ports) if (!existing.ports.includes(p)) existing.ports.push(p);
        for (const s of h.services) {
          const has = existing.services.find((es) => es.port === s.port);
          if (!has) existing.services.push(s);
          else if (s.name && !has.name) Object.assign(has, s);
        }
        if (h.os && !existing.os) existing.os = h.os;
        if (h.hostnames && !existing.hostnames) existing.hostnames = h.hostnames;
      } else {
        newHosts.push(h);
      }
      out.hostLine(h);
    },
    onFinding(f)               { newFindings.push(f); out.findingLine(f); },
    onProgress(p, m)           { out.stageProgress(p, m); },
    onError(s, e)              { out.stageError(s, e); },
    onComplete()               { /* no-op — we keep state in newHosts/newFindings */ },
  };

  try {
    await runScan(opts, cb);
  } catch (e) {
    out.error(`Phase failed: ${e instanceof Error ? e.message : String(e)}`);
  } finally {
    delete process.env.ADVERSA_REUSED_HOSTS;
  }

  return { hosts: newHosts, findings: newFindings };
}

async function runPhaseHostDiscovery(targets: string[]): Promise<DiscoveredHost[]> {
  const result = await runPhaseWithTools([], ['host-discovery'], targets);
  return result.hosts;
}

async function runPhasePortScan(hosts: DiscoveredHost[]): Promise<DiscoveredHost[]> {
  // Optional host targeting — let user narrow if there are many
  const chosen = await pickHostSubset(hosts, 'Which hosts do you want to port-scan?');
  if (chosen.length === 0) return hosts;
  const result = await runPhaseWithTools(chosen, ['naabu']);
  // Merge back into original hosts list (preserving any not-picked hosts)
  return mergeHosts(hosts, result.hosts);
}

async function runPhaseServiceDetect(hosts: DiscoveredHost[]): Promise<DiscoveredHost[]> {
  const chosen = await pickHostSubset(hosts.filter((h) => h.ports.length > 0), 'Which hosts do you want to fingerprint?');
  if (chosen.length === 0) return hosts;
  const result = await runPhaseWithTools(chosen, ['nmap']);
  return mergeHosts(hosts, result.hosts);
}

async function runPhaseEnumeration(hosts: DiscoveredHost[]): Promise<LiveFinding[]> {
  // The scanner auto-fires enum modules based on open ports — we just enable all of them
  const enumTools: Tool[] = ['smb-enum', 'netbios-enum', 'snmp-enum', 'ldap-enum', 'rpc-enum', 'nfs-enum', 'rdp-fingerprint', 'db-enum', 'httpx', 'whatweb'];
  const result = await runPhaseWithTools(hosts, enumTools);
  return result.findings;
}

async function runPhaseVulnAssess(hosts: DiscoveredHost[]): Promise<LiveFinding[]> {
  // Ask which vuln checks to run
  ln();
  ln(`  ${A.bold}Vulnerability checks${A.reset}`);
  const wantNuclei = await confirm('CVE template scanner (nuclei)?', true);
  const wantTls    = await confirm('TLS / SSL audit?', hosts.some((h) => [443, 8443, 636, 993, 995].some((p) => h.ports.includes(p))));
  const wantSsh    = await confirm('SSH config audit?', hosts.some((h) => h.ports.includes(22)));

  const tools: Tool[] = [];
  if (wantNuclei) tools.push('nuclei');
  if (wantTls)    tools.push('testssl');
  if (wantSsh)    tools.push('ssh-audit');
  if (tools.length === 0) return [];

  const result = await runPhaseWithTools(hosts, tools);
  return result.findings;
}

// ── Exploitation phase (AI-planned, human-approved) ──────────────
async function runPhaseExploitation(state: PhaseState): Promise<void> {
  const verified = state.findings.filter((f) => f.status === 'VERIFIED');
  if (verified.length === 0) {
    ln(`  ${A.yellow}No VERIFIED findings to exploit.${A.reset} Run validation first.`);
    return;
  }

  ln(`  ${A.dim}${verified.length} verified finding(s) available for exploitation.${A.reset}`);
  ln(`  ${A.red}⚠  Exploitation is destructive. Only proceed if you have explicit authorization.${A.reset}`);
  ln();

  const sevOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
  const sorted = [...verified].sort((a, b) => sevOrder.indexOf(a.severity) - sevOrder.indexOf(b.severity));

  const choices = sorted.slice(0, 15).map((f) => ({
    label: `${f.severity.padEnd(8)}  ${f.host}${f.port ? ':' + f.port : ''}  ${f.title.slice(0, 50)}`,
    value: f.id,
    hint:  `${f.id} · source: ${f.source}`,
  }));
  choices.push({ label: 'Cancel — return to phase menu', value: '__cancel', hint: '' });

  const pickedId = await choose<string>('Pick a finding to exploit', choices);
  if (pickedId === '__cancel') return;

  const finding = verified.find((f) => f.id === pickedId);
  if (!finding) return;

  ln();
  ln(`  ${A.dim}Asking Claude to plan a verification-only exploit…${A.reset}`);
  const plan = await llm.planExploit(finding);
  if (!plan) {
    ln(`  ${A.red}AI exploit planner unavailable.${A.reset} Set ANTHROPIC_API_KEY or write a manual PoC by hand.`);
    return;
  }

  // ── Render the plan ─────────────────────────────────────────────
  ln();
  ln(`  ${A.bold}Exploit plan${A.reset}`);
  ln(`    ${A.dim}Tool:${A.reset}    ${plan.tool}  ${plan.module ? '· ' + plan.module : ''}`);
  ln(`    ${A.dim}Risk:${A.reset}    ${plan.risk === 'DESTRUCTIVE' ? A.red : plan.risk === 'STATE_CHANGE' ? A.yellow : ''}${plan.risk}${A.reset}  ${plan.verificationOnly ? `${A.green}(verification-only)${A.reset}` : ''}`);
  ln(`    ${A.dim}Description:${A.reset} ${plan.explanation}`);
  ln();
  ln(`    ${A.cyan}${plan.command}${A.reset}`);
  ln();
  ln(`    ${A.dim}Success:${A.reset} ${plan.successIndicator}`);
  ln(`    ${A.dim}Failure:${A.reset} ${plan.failureIndicator}`);
  ln();

  // ── Safety gate ─────────────────────────────────────────────────
  if (plan.risk === 'DESTRUCTIVE') {
    ln(`  ${A.red}✗ DESTRUCTIVE actions are blocked.${A.reset} ADVERSA will not execute this.`);
    return;
  }
  if (plan.requiresApproval || plan.risk === 'STATE_CHANGE') {
    if (plan.reasonNeedsApproval) ln(`  ${A.yellow}Approval reason: ${plan.reasonNeedsApproval}${A.reset}`);
    if (!(await confirm(`Approve and execute this ${plan.risk} command?`, false))) {
      ln(`  ${A.dim}Skipped.${A.reset}`);
      return;
    }
  }

  ln();
  ln(`  ${A.dim}ADVERSA does not execute exploit commands directly.${A.reset}`);
  ln(`  ${A.dim}Copy the command above into your own terminal where you have authorization to run it.${A.reset}`);
  ln(`  ${A.dim}When you have results, return to the wizard and use Validate findings to record outcomes.${A.reset}`);
}

// ── Host subset picker ───────────────────────────────────────────
async function pickHostSubset(hosts: DiscoveredHost[], question: string): Promise<DiscoveredHost[]> {
  if (hosts.length === 0) return [];
  if (hosts.length === 1) return hosts;

  const mode = await choose<'all' | 'pick' | 'top_n'>(question, [
    { label: `All ${hosts.length} host(s)`,                value: 'all' },
    { label: 'Pick specific hosts by IP',                    value: 'pick' },
    { label: `Top N by port count (most interesting first)`, value: 'top_n' },
  ]);

  if (mode === 'all') return hosts;
  if (mode === 'top_n') {
    const n = parseInt(await ask('How many?', String(Math.min(10, hosts.length))), 10) || 10;
    return [...hosts].sort((a, b) => b.ports.length - a.ports.length).slice(0, n);
  }
  // pick by IP — list with checkboxes
  ln();
  ln(`  ${A.dim}Toggle each host (y to include, n to skip)${A.reset}`);
  const picked: DiscoveredHost[] = [];
  for (const h of hosts.slice(0, 50)) {
    const portInfo = h.ports.length > 0 ? `  [${h.ports.slice(0, 6).join(',')}${h.ports.length > 6 ? '+…' : ''}]` : '';
    if (await confirm(`  ${h.ip}${portInfo}`, h.ports.length > 0)) picked.push(h);
  }
  return picked;
}

// ── Merge two host lists, preferring the newer one's data ────────
function mergeHosts(prior: DiscoveredHost[], updated: DiscoveredHost[]): DiscoveredHost[] {
  const byIp = new Map(prior.map((h) => [h.ip, h]));
  for (const u of updated) {
    const existing = byIp.get(u.ip);
    if (!existing) { byIp.set(u.ip, u); continue; }
    for (const p of u.ports) if (!existing.ports.includes(p)) existing.ports.push(p);
    for (const s of u.services) {
      const has = existing.services.find((es) => es.port === s.port);
      if (!has) existing.services.push(s);
      else if (s.name && !has.name) Object.assign(has, s);
    }
    existing.ports.sort((a, b) => a - b);
    if (u.os && !existing.os) existing.os = u.os;
    if (u.hostnames && !existing.hostnames) existing.hostnames = u.hostnames;
  }
  return [...byIp.values()];
}

// ── Vuln check picker — categorized like a real engagement ─────────
async function runVulnAssessmentFlow(
  hosts: DiscoveredHost[],
  priorFindings: LiveFinding[],
  isDomainScope: boolean,
  useAi: boolean,
): Promise<void> {
  ln(`  ${A.bold}Discovered:${A.reset} ${hosts.length} host(s), ${hosts.reduce((s, h) => s + h.ports.length, 0)} open port(s)`);

  const openPorts = new Set(hosts.flatMap((h) => h.ports));
  // Recommend vuln checks based on what's actually open
  const recommendations: Tool[] = [];
  if (openPorts.size > 0)                    recommendations.push('nuclei');
  if ([443, 8443, 636, 993, 995].some((p) => openPorts.has(p))) recommendations.push('testssl');
  if (openPorts.has(22) || openPorts.has(2222)) recommendations.push('ssh-audit');

  if (recommendations.length > 0) {
    ln(`  ${A.dim}Recommended for this attack surface: ${recommendations.join(', ')}${A.reset}`);
  }
  ln();

  ln(`  ${A.bold}What kinds of vulnerability checks?${A.reset}  ${A.dim}(pick what you want to run now)${A.reset}`);
  ln();

  const wantNuclei  = await confirm('Run CVE template scanner (nuclei)? — checks for known CVEs across discovered services', recommendations.includes('nuclei'));
  const wantTls     = await confirm('Run TLS / SSL audit? — protocol versions, weak ciphers, expired certs', recommendations.includes('testssl'));
  const wantSsh     = await confirm('Run SSH config audit? — algorithms, banner, known weak configs', recommendations.includes('ssh-audit'));
  const wantWebVuln = await confirm('Run web vulnerability templates? — XSS / SQLi / SSRF nuclei templates against discovered web services', false);
  const wantDefault = await confirm('Run default credentials check? — try public/private/admin/admin on discovered services', false);

  const vulnTools: Tool[] = [];
  if (wantNuclei)  vulnTools.push('nuclei');
  if (wantTls)     vulnTools.push('testssl');
  if (wantSsh)     vulnTools.push('ssh-audit');
  // wantWebVuln and wantDefault are nuclei-tag-controlled — both use nuclei but with different template paths

  if (vulnTools.length === 0 && !wantWebVuln && !wantDefault) {
    ln(`  ${A.yellow}No vuln checks selected — skipping assessment.${A.reset}`);
    return;
  }

  ln();
  ln(`  ${A.bold}Review${A.reset}`);
  ln(`    ${A.dim}Tools:${A.reset}        ${vulnTools.join(', ') || '(none)'}`);
  if (wantWebVuln) ln(`    ${A.dim}Web vulns:${A.reset}    nuclei -tags xss,sqli,ssrf,rce`);
  if (wantDefault) ln(`    ${A.dim}Default creds:${A.reset} nuclei -tags default-login`);
  ln();
  if (!(await confirm('Run vulnerability assessment now?', true))) return;

  // Run vuln tools by reusing scan engine, with vuln-only tools + reused hosts
  const vulnOpts: ScanOptions = {
    targets: hosts.map((h) => h.ip),
    profile: 'standard',
    stealth: 5,
    tools:   vulnTools,
    save:    true,
    scanId:  `VULN-${Date.now()}`,
  };

  // Seed hosts so engine doesn't re-discover
  process.env.ADVERSA_REUSED_HOSTS = JSON.stringify(hosts);

  const newFindings: LiveFinding[] = [];
  const vulnCb: ScanCallbacks = {
    onStageStart(s)    { out.stageStart(s); },
    onStageComplete(s, summary) { out.stageComplete(s, summary); },
    onHostDiscovered() {},
    onFinding(f)       { newFindings.push(f); out.findingLine(f); },
    onProgress(p, m)   { out.stageProgress(p, m); },
    onError(s, e)      { out.stageError(s, e); },
    onComplete(s)      { out.summary(s); },
  };

  try {
    await runScan(vulnOpts, vulnCb);
  } catch (e) {
    out.error(`Vuln assessment failed: ${e instanceof Error ? e.message : String(e)}`);
  } finally {
    delete process.env.ADVERSA_REUSED_HOSTS;
  }

  // ── Phase 3: Validation prompt ───────────────────────────────────
  if (newFindings.length === 0) {
    ln(`  ${A.dim}No new findings to validate.${A.reset}`);
    return;
  }
  ln();
  ln(`  ${A.cyan}━━━━━ Vuln assessment complete — ${newFindings.length} new finding(s) ━━━━━${A.reset}`);
  ln();
  const wantValidate = await confirm('Validate the new findings now?', true);
  if (!wantValidate) return;
  await runValidationFlow(newFindings, useAi);
}

// ── Validation flow with AI + rule-based options ─────────────────
async function runValidationFlow(scopeFindings?: LiveFinding[], useAi?: boolean): Promise<void> {
  const findings = scopeFindings ?? getAllFindings().filter((f) => f.status === 'OPEN');
  if (findings.length === 0) {
    ln(`  ${A.yellow}No findings to validate.${A.reset}`);
    return;
  }

  ln(`  ${A.bold}Validation${A.reset}  ${A.dim}— ${findings.length} finding(s) in scope${A.reset}`);
  ln();

  const action = await choose<'ai_batch' | 'rule_based' | 'pick_one' | 'cancel'>(
    'How do you want to validate?', [
      { label: 'AI batch triage — Claude reviews every finding\'s evidence', value: 'ai_batch',   hint: 'gives confidence + likely TP/FP verdict on each' },
      { label: 'Apply rule-based conditions — auto-mark based on rules',     value: 'rule_based', hint: 'e.g. INFO older than 30d → ARCHIVED' },
      { label: 'Pick one finding and validate it manually',                  value: 'pick_one' },
      { label: 'Cancel',                                                      value: 'cancel' },
    ],
  );

  if (action === 'cancel') return;
  if (action === 'pick_one') { await wizardValidate(); return; }

  if (action === 'rule_based') {
    await runRuleBasedValidation(findings);
    return;
  }

  // AI batch triage
  ln();
  ln(`  ${A.dim}Sending ${findings.length} finding(s) to Claude for verdict…${A.reset}`);
  const verdicts = await llm.validateFindings(findings);

  if (verdicts.size === 0) {
    ln(`  ${A.red}No verdicts returned${A.reset} — ANTHROPIC_API_KEY missing or AI unreachable.`);
    return;
  }

  ln();
  let confirmed = 0, falsePositives = 0, review = 0;
  for (const f of findings) {
    const v = verdicts.get(f.id);
    if (!v) continue;

    const sym = v.verdict === 'LIKELY_TRUE_POSITIVE'
      ? `${A.red}✓ TRUE${A.reset}`
      : v.verdict === 'LIKELY_FALSE_POSITIVE'
        ? `${A.green}✗ FALSE${A.reset}`
        : `${A.yellow}? REVIEW${A.reset}`;
    ln(`  ${sym}  [${v.confidence}]  ${f.id}  ${f.host}${f.port ? ':' + f.port : ''}  ${f.title.slice(0, 50)}`);
    ln(`    ${A.dim}${v.reasoning}${A.reset}`);
    if (v.verdict === 'LIKELY_TRUE_POSITIVE') confirmed++;
    if (v.verdict === 'LIKELY_FALSE_POSITIVE') falsePositives++;
    if (v.verdict === 'NEEDS_HUMAN_REVIEW')   review++;
  }
  ln();
  ln(`  ${A.bold}AI summary:${A.reset}  ${confirmed} likely TRUE  ·  ${falsePositives} likely FALSE  ·  ${review} need human review`);
  ln();

  const apply = await confirm('Apply these verdicts? (TRUE → VERIFIED, FALSE → CLOSED+falsePositive)', false);
  if (!apply) return;

  for (const f of findings) {
    const v = verdicts.get(f.id);
    if (!v) continue;
    if (v.verdict === 'LIKELY_TRUE_POSITIVE' && v.confidence !== 'LOW') {
      updateFinding(f.id, {
        status: 'VERIFIED',
        evidence: [...f.evidence, { label: 'ai validation', content: `Verdict: TRUE / ${v.confidence} confidence. ${v.reasoning}`, timestamp: new Date().toISOString() }],
      });
    } else if (v.verdict === 'LIKELY_FALSE_POSITIVE' && v.confidence !== 'LOW') {
      updateFinding(f.id, {
        status:              'CLOSED',
        falsePositive:       true,
        falsePositiveReason: `AI verdict (${v.confidence} confidence): ${v.reasoning}`,
      });
    }
  }
  ln(`  ${A.green}✓${A.reset} Applied verdicts. ${A.dim}NEEDS_HUMAN_REVIEW items left as OPEN.${A.reset}`);
}

async function runRuleBasedValidation(findings: LiveFinding[]): Promise<void> {
  ln();
  ln(`  ${A.bold}Rule-based validation${A.reset}  ${A.dim}— pick rules to apply${A.reset}`);
  const rules: Array<{ id: string; description: string; predicate: (f: LiveFinding) => boolean; action: (f: LiveFinding) => Partial<LiveFinding> }> = [
    {
      id: 'info-age',
      description: 'INFO findings older than 30 days → CLOSED',
      predicate: (f) => f.severity === 'INFO' && (Date.now() - new Date(f.timestamp).getTime()) > 30 * 86400000,
      action:    () => ({ status: 'CLOSED' }),
    },
    {
      id: 'high-no-evidence',
      description: 'HIGH/CRITICAL with no evidence content → REVIEW',
      predicate: (f) => (f.severity === 'HIGH' || f.severity === 'CRITICAL') && (f.evidence.length === 0 || f.evidence.every((e) => !e.content.trim())),
      action:    () => ({ status: 'IN_REVIEW' }),
    },
    {
      id: 'dedup',
      description: 'Duplicate findings (same host + title) → keep newest, CLOSE older',
      predicate: () => false,    // handled specially below
      action:    () => ({ status: 'CLOSED' }),
    },
  ];

  const toApply: typeof rules = [];
  for (const r of rules) {
    if (await confirm(`  ${r.description}`, false)) toApply.push(r);
  }
  if (toApply.length === 0) { ln(`  ${A.dim}No rules selected.${A.reset}`); return; }

  let touched = 0;
  for (const f of findings) {
    for (const r of toApply) {
      if (r.id === 'dedup') continue;
      if (r.predicate(f)) {
        updateFinding(f.id, r.action(f));
        touched++;
      }
    }
  }

  // Dedup needs a second pass — group by host + title, close all but the newest
  if (toApply.some((r) => r.id === 'dedup')) {
    const groups = new Map<string, LiveFinding[]>();
    for (const f of findings) {
      const key = `${f.host}::${f.title}`;
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key)!.push(f);
    }
    for (const group of groups.values()) {
      if (group.length < 2) continue;
      const sorted = [...group].sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
      for (const stale of sorted.slice(1)) {
        updateFinding(stale.id, { status: 'CLOSED', falsePositive: true, falsePositiveReason: `Superseded by newer finding ${sorted[0].id}` });
        touched++;
      }
    }
  }

  ln(`  ${A.green}✓${A.reset} Applied rules to ${touched} finding(s).`);
}

// ── Host inference helpers ──────────────────────────────────────────
function inferHostsFromFindings(targetFilter: string[]): DiscoveredHost[] {
  const all = getAllFindings();
  const byHost = new Map<string, { ports: Set<number>; services: Map<number, string> }>();

  for (const f of all) {
    if (!byHost.has(f.host)) {
      byHost.set(f.host, { ports: new Set(), services: new Map() });
    }
    if (f.port) {
      byHost.get(f.host)!.ports.add(f.port);
      if (f.service) byHost.get(f.host)!.services.set(f.port, f.service);
    }
  }

  // Filter to the targets the operator just specified (substring match)
  const filtered: DiscoveredHost[] = [];
  for (const [ip, info] of byHost) {
    const matchesFilter = targetFilter.length === 0
      || targetFilter.some((t) => ip === t || ip.startsWith(t.split('/')[0].split('.').slice(0, 2).join('.')));
    if (!matchesFilter) continue;
    if (info.ports.size === 0) continue;
    filtered.push({
      ip,
      ports:    [...info.ports].sort((a, b) => a - b),
      services: [...info.ports].map((p) => ({ port: p, proto: 'tcp', name: info.services.get(p) })),
    });
  }
  return filtered;
}

function parseManualHosts(raw: string): DiscoveredHost[] {
  const map = new Map<string, Set<number>>();
  for (const pair of raw.split(',').map((s) => s.trim()).filter(Boolean)) {
    const [host, portStr] = pair.split(':');
    const port = parseInt(portStr, 10);
    if (!host || isNaN(port) || port < 1 || port > 65535) continue;
    if (!map.has(host)) map.set(host, new Set());
    map.get(host)!.add(port);
  }
  return [...map.entries()].map(([ip, portSet]) => ({
    ip,
    ports:    [...portSet].sort((a, b) => a - b),
    services: [...portSet].map((p) => ({ port: p, proto: 'tcp' })),
  }));
}

// ── Wizard: validate findings (re-verify, mark FP / VERIFIED) ─────
async function wizardValidate(): Promise<void> {
  ln();
  ln(`  ${A.cyan}▶ Validate findings${A.reset}`);
  divider();

  const findings = getAllFindings().filter((f) => f.status !== 'CLOSED');
  if (findings.length === 0) {
    ln(`  ${A.yellow}No open findings to validate.${A.reset}`);
    return;
  }

  ln(`  ${A.dim}${findings.length} open finding(s). Pick which one to work on.${A.reset}`);
  ln();

  // Group by severity for the picker
  const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
  const sorted = [...findings].sort(
    (a, b) => order.indexOf(a.severity) - order.indexOf(b.severity),
  );

  // Show top 20 to keep the menu sane
  const slice = sorted.slice(0, 20);
  const options = slice.map((f) => ({
    label: `${f.severity.padEnd(8)}  ${f.host}${f.port ? `:${f.port}` : ''}  ${f.title.slice(0, 40)}`,
    value: f.id,
    hint:  `${f.id} · status: ${f.status}`,
  }));
  if (sorted.length > 20) {
    ln(`  ${A.dim}(showing the top 20 by severity; use option 2 — View findings — for the full list)${A.reset}`);
  }

  const id = await choose<string>('Pick a finding to validate', options);
  const f  = getFindingById(id);
  if (!f) { ln(`  ${A.red}Could not load finding.${A.reset}`); return; }

  ln();
  out.findingDetail(f);
  ln();

  const action = await choose<'rescan' | 'confirm' | 'falsePositive' | 'cancel'>('What do you want to do with this finding?', [
    { label: 'Re-run a targeted scan to re-verify',  value: 'rescan',        hint: 'fires nuclei against just this host:port' },
    { label: 'Mark as VERIFIED (confirmed by hand)',  value: 'confirm',       hint: 'records your manual verification' },
    { label: 'Mark as false positive',               value: 'falsePositive', hint: 'asks you for a reason; finding is hidden from active lists' },
    { label: 'Cancel',                               value: 'cancel' },
  ]);

  if (action === 'cancel') return;

  if (action === 'confirm') {
    const note = await ask('Verification note (how did you confirm?)');
    updateFinding(f.id, {
      status: 'VERIFIED',
      evidence: [
        ...f.evidence,
        { label: 'manual verification', content: note || '(no note)', timestamp: new Date().toISOString() },
      ],
    });
    ln(`  ${A.green}✓${A.reset} Marked ${f.id} as VERIFIED.`);
    return;
  }

  if (action === 'falsePositive') {
    const reason = await ask('Why is this a false positive?');
    updateFinding(f.id, {
      status:              'CLOSED',
      falsePositive:       true,
      falsePositiveReason: reason || '(no reason given)',
    });
    ln(`  ${A.green}✓${A.reset} Marked ${f.id} as false positive.`);
    return;
  }

  // ── rescan: targeted nuclei run against just this host:port
  if (action === 'rescan') {
    if (!f.port) {
      ln(`  ${A.yellow}This finding has no port — cannot target a single service. Use option 1 (Run a scan) instead.${A.reset}`);
      return;
    }
    ln();
    ln(`  ${A.dim}Running targeted re-scan on ${f.host}:${f.port}…${A.reset}`);
    ln(`  ${A.dim}This re-runs the same stages but scoped to one host.${A.reset}`);
    ln();

    const opts: ScanOptions = {
      targets: [f.host],
      profile: 'fast',
      stealth: 5,
      tools:   ['nuclei'],
      save:    false,
      engagementId: f.engagementId,
      scanId:  `VALIDATE-${Date.now()}`,
    };

    // Seed the single host so naabu can be skipped
    process.env.ADVERSA_REUSED_HOSTS = JSON.stringify([{
      ip: f.host, ports: [f.port], services: [{ port: f.port, proto: 'tcp' }],
    }]);

    const reverified: LiveFinding[] = [];
    const callbacks: ScanCallbacks = {
      onStageStart(s)    { out.stageStart(s); },
      onStageComplete(s, summary) { out.stageComplete(s, summary); },
      onHostDiscovered() {},
      onFinding(nf)      {
        reverified.push(nf);
        out.findingLine(nf);
      },
      onProgress(pct, m) { out.stageProgress(pct, m); },
      onError(s, e)      { out.stageError(s, e); },
      onComplete()       {},
    };

    try {
      await runScan(opts, callbacks);
    } finally {
      delete process.env.ADVERSA_REUSED_HOSTS;
    }

    ln();
    const matched = reverified.find((nf) =>
      nf.host === f.host && nf.port === f.port &&
      (nf.title === f.title || nf.cveIds?.some((c) => f.cveIds?.includes(c))),
    );

    if (matched) {
      ln(`  ${A.red}✗ Finding re-confirmed.${A.reset}  This issue is still present on ${f.host}:${f.port}.`);
      if (await confirm('Mark as VERIFIED?', true)) {
        updateFinding(f.id, {
          status:   'VERIFIED',
          evidence: [
            ...f.evidence,
            { label: 'automated re-verification', content: `Re-confirmed by targeted nuclei scan at ${new Date().toISOString()}`, timestamp: new Date().toISOString() },
          ],
        });
        ln(`  ${A.green}✓${A.reset} Marked ${f.id} as VERIFIED.`);
      }
    } else {
      ln(`  ${A.green}✓ Finding no longer present.${A.reset}`);
      ln(`  ${A.dim}Either the issue was remediated, or this was a transient/false-positive detection.${A.reset}`);
      const next = await choose<'fp' | 'close' | 'keep'>('What now?', [
        { label: 'Mark as false positive',  value: 'fp' },
        { label: 'Mark as CLOSED (fixed)',  value: 'close' },
        { label: 'Keep status as is',       value: 'keep' },
      ]);
      if (next === 'fp') {
        const reason = await ask('Reason', 'No longer reproducible on re-scan');
        updateFinding(f.id, { status: 'CLOSED', falsePositive: true, falsePositiveReason: reason });
        ln(`  ${A.green}✓${A.reset} Marked ${f.id} as false positive.`);
      } else if (next === 'close') {
        updateFindingStatus(f.id, 'CLOSED');
        ln(`  ${A.green}✓${A.reset} Marked ${f.id} as CLOSED.`);
      }
    }
  }
}

// ── Wizard: view findings ──────────────────────────────────────────
async function wizardFindings(): Promise<void> {
  ln();
  ln(`  ${A.cyan}▶ View findings${A.reset}`);
  divider();

  const view = await choose<'all' | 'filter' | 'detail' | 'stats'>('What do you want to see?', [
    { label: 'All findings (table)',           value: 'all' },
    { label: 'Filter by severity / host',      value: 'filter' },
    { label: 'Full detail of one finding',     value: 'detail' },
    { label: 'Summary stats (counts, SLA)',    value: 'stats' },
  ]);

  let findings = getAllFindings();
  if (findings.length === 0) {
    ln(`  ${A.yellow}No findings yet.${A.reset} Run a scan first (option: ${A.bold}Run a scan${A.reset}).`);
    return;
  }

  if (view === 'filter') {
    const sev = await choose<string>('Severity filter', [
      { label: 'Any',      value: '' },
      { label: 'CRITICAL', value: 'CRITICAL' },
      { label: 'HIGH',     value: 'HIGH' },
      { label: 'MEDIUM',   value: 'MEDIUM' },
      { label: 'LOW',      value: 'LOW' },
      { label: 'INFO',     value: 'INFO' },
    ]);
    if (sev) findings = findings.filter((f) => f.severity === sev);

    const host = await ask('Host substring (blank for any)');
    if (host) findings = findings.filter((f) => f.host.toLowerCase().includes(host.toLowerCase()));
  }

  if (view === 'detail') {
    const id = await ask('Finding ID');
    const f  = getFindingById(id);
    if (!f) { ln(`  ${A.red}Not found.${A.reset}`); return; }
    out.findingDetail(f);
    return;
  }

  if (view === 'stats') {
    const bySev: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    const byStatus: Record<string, number> = {};
    let breached = 0;
    for (const f of findings) {
      bySev[f.severity] = (bySev[f.severity] ?? 0) + 1;
      byStatus[f.status] = (byStatus[f.status] ?? 0) + 1;
      if (f.slaDeadline && Date.now() > new Date(f.slaDeadline).getTime() && f.status === 'OPEN') breached++;
    }
    ln();
    ln(`  ${A.bold}FINDINGS SUMMARY${A.reset}  ${A.dim}(${findings.length} total)${A.reset}`);
    for (const s of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']) {
      const n = bySev[s] ?? 0;
      if (n === 0) continue;
      ln(`    ${out.sevBadge(s)}  ${String(n).padStart(3)}  ${'█'.repeat(Math.min(n, 40))}`);
    }
    ln();
    for (const [s, n] of Object.entries(byStatus)) ln(`    ${s.padEnd(18)} ${n}`);
    if (breached > 0) ln(`\n  ${A.red}⚠ ${breached} open finding(s) past SLA${A.reset}`);
    ln();
    return;
  }

  out.findingsTable(findings);

  if (await confirm('See full detail of one finding?', false)) {
    const id = await ask('Finding ID');
    const f  = getFindingById(id);
    if (f) out.findingDetail(f);
    else ln(`  ${A.red}Not found.${A.reset}`);
  }
}

// ── Wizard: ask AI ──────────────────────────────────────────────────
async function wizardAsk(): Promise<void> {
  ln();
  ln(`  ${A.cyan}▶ Ask the AI${A.reset}`);
  divider();

  const findings = getAllFindings();
  const hosts: DiscoveredHost[] = [...new Map(
    findings.map((f) => [f.host, { ip: f.host, ports: f.port ? [f.port] : [], services: [] }]),
  ).values()];

  if (findings.length === 0) {
    ln(`  ${A.yellow}No findings loaded — the AI has no scan context.${A.reset}`);
    if (!(await confirm('Continue anyway?', false))) return;
  } else {
    ln(`  ${A.dim}Context: ${findings.length} findings, ${hosts.length} hosts.${A.reset}`);
  }

  ln();
  ln(`  ${A.dim}Type a question and press Enter. Empty line to return to menu.${A.reset}`);
  ln();

  const history: { role: 'user' | 'assistant'; content: string }[] = [];

  while (true) {
    const q = await ask(`${A.cyan}You${A.reset}`);
    if (!q) break;

    w(`  ${A.cyan}AI${A.reset}  `);
    let answer = '';
    await llm.streamAsk(
      q, findings, hosts,
      (chunk) => { w(chunk); answer += chunk; },
      history,
    );
    w('\n\n');
    history.push({ role: 'user', content: q });
    history.push({ role: 'assistant', content: answer });
  }
}

// ── Engagement utilities ────────────────────────────────────────────
interface EngagementRow {
  id: string; name: string; client: string; status: string;
  findingCount: number; assetCount: number; progress: number;
  startDate: string; endDate: string;
  scopeCidrs: string[]; excludedCidrs: string[];
  assessor: string; description?: string;
}

async function fetchEngagements(): Promise<EngagementRow[]> {
  const s = requireAuth();
  const res = await apiFetch(s, '/api/engagements').catch(() => null);
  if (!res?.ok) return [];
  const data = await res.json() as { engagements: EngagementRow[] };
  return data.engagements;
}

async function pickEngagementId(): Promise<string | undefined> {
  const list = await fetchEngagements();
  if (list.length === 0) {
    ln(`  ${A.yellow}No engagements found.${A.reset} Create one from the main menu first.`);
    return undefined;
  }
  const choices = list.map((e) => ({
    label: `${e.id}  ${e.name}`,
    value: e.id,
    hint:  `${e.client} · ${e.status} · ${e.findingCount} findings`,
  }));
  return choose<string>('Pick an engagement', choices);
}

// ── Wizard: engagements ─────────────────────────────────────────────
async function wizardEngagement(): Promise<void> {
  ln();
  ln(`  ${A.cyan}▶ Engagements${A.reset}`);
  divider();

  const action = await choose<'list' | 'show' | 'create'>('What do you want to do?', [
    { label: 'List all engagements',  value: 'list' },
    { label: 'Show one in detail',    value: 'show' },
    { label: 'Create a new one',      value: 'create' },
  ]);

  if (action === 'list' || action === 'show') {
    const list = await fetchEngagements();
    if (list.length === 0) { ln(`  ${A.yellow}None yet.${A.reset}`); return; }

    ln();
    ln(`  ${'ID'.padEnd(10)} ${'STATUS'.padEnd(12)} ${'CLIENT'.padEnd(28)} FINDINGS`);
    ln(`  ${'─'.repeat(70)}`);
    for (const e of list) {
      ln(`  ${e.id.padEnd(10)} ${e.status.padEnd(12)} ${e.client.slice(0, 28).padEnd(28)} ${e.findingCount}`);
    }
    ln();

    if (action === 'show') {
      const id = await pickEngagementId();
      if (!id) return;
      const e = list.find((x) => x.id === id);
      if (!e) return;
      ln(`\n  ${A.bold}${e.name}${A.reset}  ·  ${e.id}`);
      ln(`  ${A.gray}${'─'.repeat(68)}${A.reset}`);
      ln(`  Client      ${e.client}`);
      ln(`  Status      ${e.status}`);
      ln(`  Assessor    ${e.assessor}`);
      ln(`  Window      ${e.startDate} → ${e.endDate}`);
      ln(`  Progress    ${e.progress}%`);
      ln(`  Assets      ${e.assetCount}`);
      ln(`  Findings    ${e.findingCount}`);
      if (e.scopeCidrs.length)    ln(`  Scope       ${e.scopeCidrs.join(', ')}`);
      if (e.excludedCidrs.length) ln(`  Excluded    ${e.excludedCidrs.join(', ')}`);
      if (e.description)          ln(`\n  ${A.dim}${e.description}${A.reset}`);
      ln();
    }
    return;
  }

  // ── create
  const session = requireAuth();
  const name        = await ask('Engagement name');
  const client      = await ask('Client / organization');
  const startDate   = await ask('Start date (YYYY-MM-DD)', new Date().toISOString().slice(0, 10));
  const endDate     = await ask('End date (YYYY-MM-DD)');
  const scopeRaw    = await ask('In-scope CIDRs (comma-separated, blank for none)');
  const excludeRaw  = await ask('Excluded CIDRs (comma-separated, blank for none)');
  const description = await ask('Description (optional)');

  const body = {
    name, client, startDate, endDate,
    scopeCidrs:    scopeRaw.split(',').map((s) => s.trim()).filter(Boolean),
    excludedCidrs: excludeRaw.split(',').map((s) => s.trim()).filter(Boolean),
    description,
    assessor: session.email,
  };

  const res = await apiFetch(session, '/api/engagements', {
    method: 'POST',
    body:   JSON.stringify(body),
  }).catch(() => null);

  if (!res?.ok) {
    const err = (await res?.json().catch(() => ({})) as { error?: string }).error;
    ln(`  ${A.red}${err ?? 'Could not create engagement.'}${A.reset}`);
    return;
  }
  const { engagement } = await res.json() as { engagement: EngagementRow };
  ln(`\n  ${A.green}✓${A.reset} Created ${A.bold}${engagement.id}${A.reset} — ${engagement.name}\n`);
}

// ── Wizard: AI report ───────────────────────────────────────────────
async function wizardReport(): Promise<void> {
  ln();
  ln(`  ${A.cyan}▶ Generate AI report${A.reset}`);
  divider();

  const id = await pickEngagementId();
  if (!id) return;

  const dest = await choose<'terminal' | 'file' | 'both'>('Where do you want the report?', [
    { label: 'Show in terminal',          value: 'terminal' },
    { label: 'Write to a JSON file',      value: 'file' },
    { label: 'Both',                      value: 'both' },
  ]);

  let outFile: string | undefined;
  if (dest === 'file' || dest === 'both') {
    outFile = await ask('Output file', `report-${id}.json`);
  }

  // ── Field selection
  ln();
  ln(`  ${A.bold}Which sections do you want in the terminal view?${A.reset}`);
  const wantSummary    = await confirm('Executive summary?',     true);
  const wantScorecard  = await confirm('Risk scorecard?',        true);
  const wantFindings   = await confirm('Per-finding detail?',    true);
  const wantRoadmap    = await confirm('Remediation roadmap?',   true);
  const wantPositive   = await confirm('Positive findings?',     true);

  const s = requireAuth();
  ln();
  ln(`  ${A.dim}Generating report — this can take 30–60 seconds…${A.reset}`);
  const res = await apiFetch(s, `/api/engagements/${id}/ai-report`, {
    method: 'POST',
  }).catch(() => null);

  if (!res?.ok) {
    const err = (await res?.json().catch(() => ({})) as { error?: string }).error;
    ln(`  ${A.red}${err ?? 'Report generation failed.'}${A.reset}`);
    return;
  }

  type Report = {
    executive_summary?: string;
    risk_scorecard?:    Record<string, number>;
    findings?:          Array<Record<string, unknown>>;
    remediation_roadmap?: { priority_1_24h?: string[]; priority_2_30d?: string[]; priority_3_90d?: string[] };
    positive_findings?: string;
  };
  const report = await res.json() as Report;

  if (outFile) {
    writeFileSync(path.resolve(outFile), JSON.stringify(report, null, 2));
    ln(`  ${A.green}✓${A.reset} Report written to ${outFile}`);
  }

  if (dest === 'file') { ln(); return; }

  // ── Render selected sections
  if (wantSummary && report.executive_summary) {
    ln(`\n  ${A.cyan}═══ EXECUTIVE SUMMARY ═══${A.reset}\n`);
    ln(`  ${report.executive_summary.replace(/\n/g, '\n  ')}`);
  }
  if (wantScorecard && report.risk_scorecard) {
    ln(`\n  ${A.cyan}═══ RISK SCORECARD ═══${A.reset}\n`);
    const sc = report.risk_scorecard;
    ln(`    Overall ${sc.overall ?? '-'}/100   Network ${sc.network ?? '-'}   Auth ${sc.auth ?? '-'}   Config ${sc.config ?? '-'}   Patches ${sc.patches ?? '-'}   Web ${sc.web ?? '-'}`);
  }
  if (wantFindings && report.findings?.length) {
    ln(`\n  ${A.cyan}═══ FINDINGS (${report.findings.length}) ═══${A.reset}\n`);
    for (const f of report.findings as Array<{ severity?: string; finding_id?: string; title?: string; business_impact?: string; remediation_detail?: string }>) {
      ln(`  [${f.severity ?? '?'}] ${f.finding_id ?? ''} — ${f.title ?? ''}`);
      if (f.business_impact)     ln(`    ${A.dim}Impact:${A.reset} ${f.business_impact}`);
      if (f.remediation_detail)  ln(`    ${A.dim}Fix:${A.reset}    ${f.remediation_detail}`);
      ln();
    }
  }
  if (wantRoadmap && report.remediation_roadmap) {
    const r = report.remediation_roadmap;
    ln(`\n  ${A.cyan}═══ REMEDIATION ROADMAP ═══${A.reset}\n`);
    ln(`    ${A.red}24h${A.reset}  ${(r.priority_1_24h ?? []).join(', ') || '(none)'}`);
    ln(`    ${A.yellow}30d${A.reset}  ${(r.priority_2_30d ?? []).join(', ') || '(none)'}`);
    ln(`    ${A.cyan}90d${A.reset}  ${(r.priority_3_90d ?? []).join(', ') || '(none)'}`);
  }
  if (wantPositive && report.positive_findings) {
    ln(`\n  ${A.green}═══ POSITIVE FINDINGS ═══${A.reset}\n`);
    ln(`  ${report.positive_findings.replace(/\n/g, '\n  ')}`);
  }
  ln();
}

// ── Wizard: status ──────────────────────────────────────────────────
async function wizardStatus(): Promise<void> {
  ln();
  ln(`  ${A.cyan}▶ Scan status${A.reset}`);
  divider();

  const s   = requireAuth();
  const res = await apiFetch(s, '/api/scans/list').catch(() => null);
  if (!res?.ok) { ln(`  ${A.red}Could not reach server.${A.reset}`); return; }

  const scans = await res.json() as Array<{
    scanId: string; status: string; targets: string[]; profile: string; createdAt: string;
  }>;
  if (scans.length === 0) { ln(`  ${A.yellow}No scans yet.${A.reset}`); return; }

  ln();
  ln(`  ${'SCAN ID'.padEnd(28)} ${'STATUS'.padEnd(12)} ${'PROFILE'.padEnd(10)} TARGETS`);
  ln(`  ${'─'.repeat(72)}`);
  for (const x of scans) {
    const tgts = (x.targets ?? []).slice(0, 2).join(', ') + ((x.targets?.length ?? 0) > 2 ? '…' : '');
    ln(`  ${x.scanId.padEnd(28)} ${x.status.padEnd(12)} ${(x.profile ?? '').padEnd(10)} ${tgts}`);
  }
  ln();
}

// ── Wizard: admin ───────────────────────────────────────────────────
async function wizardAdmin(): Promise<void> {
  ln();
  ln(`  ${A.cyan}▶ Admin${A.reset}`);
  divider();

  const s = requireAuth();
  if (s.role !== 'admin') {
    ln(`  ${A.yellow}You are not an admin — this menu is read-only.${A.reset}`);
  }

  const action = await choose<'list' | 'add' | 'scope' | 'remove'>('What do you want to do?', [
    { label: 'List users',           value: 'list' },
    { label: 'Add a user',           value: 'add' },
    { label: 'Change a user\'s scope', value: 'scope' },
    { label: 'Remove a user',        value: 'remove' },
  ]);

  if (action === 'list') {
    const res = await apiFetch(s, '/api/admin/users').catch(() => null);
    if (!res?.ok) { ln(`  ${A.red}Failed to list users.${A.reset}`); return; }
    const users = await res.json() as Array<{ email: string; role: string; allowedScopes: string[] }>;
    ln();
    ln(`  ${'EMAIL'.padEnd(34)} ${'ROLE'.padEnd(10)} SCOPES`);
    ln(`  ${'─'.repeat(72)}`);
    for (const u of users) {
      ln(`  ${u.email.padEnd(34)} ${u.role.padEnd(10)} ${u.allowedScopes.join(', ') || '(all)'}`);
    }
    ln();
    return;
  }

  if (action === 'add') {
    const email = await ask('Email');
    const role  = await choose<'operator' | 'admin'>('Role', [
      { label: 'Operator', value: 'operator' },
      { label: 'Admin',    value: 'admin' },
    ]);
    const scopes = (await ask('Allowed CIDRs (comma-separated, blank = none)'))
      .split(',').map((x) => x.trim()).filter(Boolean);

    const res = await apiFetch(s, '/api/admin/users', {
      method: 'POST',
      body:   JSON.stringify({ email, role, allowedScopes: scopes }),
    }).catch(() => null);
    if (!res?.ok) {
      const err = (await res?.json().catch(() => ({})) as { error?: string }).error;
      ln(`  ${A.red}${err ?? 'Could not add user.'}${A.reset}`);
      return;
    }
    ln(`  ${A.green}✓${A.reset} ${email} added as ${role}`);
    return;
  }

  if (action === 'scope') {
    const email = await ask('Email');
    const scopes = (await ask('New CIDR list (comma-separated)'))
      .split(',').map((x) => x.trim()).filter(Boolean);
    const res = await apiFetch(s, `/api/admin/users/${encodeURIComponent(email)}`, {
      method: 'PUT',
      body:   JSON.stringify({ allowedScopes: scopes }),
    }).catch(() => null);
    if (!res?.ok) { ln(`  ${A.red}Failed.${A.reset}`); return; }
    ln(`  ${A.green}✓${A.reset} Updated ${email}`);
    return;
  }

  if (action === 'remove') {
    const email = await ask('Email');
    if (!(await confirm(`Remove ${email}? This cannot be undone.`, false))) return;
    const res = await apiFetch(s, `/api/admin/users/${encodeURIComponent(email)}`, {
      method: 'DELETE',
    }).catch(() => null);
    if (!res?.ok) { ln(`  ${A.red}Failed.${A.reset}`); return; }
    ln(`  ${A.green}✓${A.reset} Removed ${email}`);
  }
}

// ── Main menu loop ──────────────────────────────────────────────────
async function mainMenu(): Promise<void> {
  while (true) {
    const session = loadSession();
    const role    = session?.role === 'admin' ? ` ${A.cyan}[admin]${A.reset}` : '';
    ln();
    ln(`  ${A.bold}Main menu${A.reset}  ${A.dim}— logged in as${A.reset} ${session?.email ?? '?'}${role}`);
    divider();

    type Action = 'scan' | 'findings' | 'validate' | 'ask' | 'report' | 'engagement' | 'status' | 'admin' | 'logout' | 'exit';
    const action = await choose<Action>('Choose an action', [
      { label: 'Run a scan',              value: 'scan',       hint: 'pick stages / reuse previous hosts / AI commentary' },
      { label: 'View findings',           value: 'findings',   hint: 'table, filter, detail, or stats' },
      { label: 'Validate findings',       value: 'validate',   hint: 're-verify, mark confirmed or false-positive' },
      { label: 'Ask the AI',              value: 'ask',        hint: 'streaming Q&A with scan context' },
      { label: 'Generate AI report',      value: 'report',     hint: 'pick engagement, choose sections' },
      { label: 'Manage engagements',      value: 'engagement', hint: 'list, show, create' },
      { label: 'Scan status',             value: 'status',     hint: 'recent scans + their state' },
      { label: 'Admin — user management', value: 'admin',      hint: 'list / add / scope / remove' },
      { label: 'Log out',                 value: 'logout' },
      { label: 'Exit',                    value: 'exit' },
    ]);

    try {
      switch (action) {
        case 'scan':       await wizardScan();       break;
        case 'findings':   await wizardFindings();   break;
        case 'validate':   await wizardValidate();   break;
        case 'ask':        await wizardAsk();        break;
        case 'report':     await wizardReport();     break;
        case 'engagement': await wizardEngagement(); break;
        case 'status':     await wizardStatus();     break;
        case 'admin':      await wizardAdmin();      break;
        case 'logout':
          clearSession();
          ln(`  ${A.green}✓${A.reset} Logged out.`);
          await ensureAuthenticated();
          break;
        case 'exit':
          ln(`  ${A.dim}Goodbye.${A.reset}`);
          return;
      }
    } catch (e) {
      ln(`  ${A.red}Error: ${e instanceof Error ? e.message : String(e)}${A.reset}`);
    }

    ln();
    if (!(await confirm('Return to main menu?', true))) return;
  }
}

export function buildInteractiveCommand(): Command {
  return new Command('menu')
    .alias('start')
    .description('Launch interactive mode (the default)')
    .action(async () => {
      banner();
      await ensureAuthenticated();
      await mainMenu();
    });
}

export async function runInteractive(): Promise<void> {
  banner();
  await ensureAuthenticated();
  await mainMenu();
}
