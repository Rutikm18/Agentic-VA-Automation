/**
 * `adversa doctor` — system health check.
 *
 * Reports the status of every component the product depends on. Each item
 * carries an actionable fix when red. Designed to be the first thing a user
 * runs when anything misbehaves.
 */
import { Command }            from 'commander';
import { spawnSync }          from 'child_process';
import { existsSync, readFileSync } from 'fs';
import path                   from 'path';
import { loadSession, serverUrl } from '../auth';

interface CheckResult {
  name:     string;
  status:   'ok' | 'warn' | 'fail';
  detail?:  string;
  fix?:     string;
  meta?:    Record<string, string>;
}

const C = {
  reset:   '\x1b[0m',
  bold:    '\x1b[1m',
  dim:     '\x1b[2m',
  green:   '\x1b[1;32m',
  yellow:  '\x1b[33m',
  red:     '\x1b[1;31m',
  cyan:    '\x1b[1;36m',
  gray:    '\x1b[90m',
};

const w  = (s: string) => process.stdout.write(s);
const ln = (s = '')   => process.stdout.write(s + '\n');

function symbol(status: CheckResult['status']): string {
  return status === 'ok'   ? `${C.green}✓${C.reset}`
       : status === 'warn' ? `${C.yellow}!${C.reset}`
       :                     `${C.red}✗${C.reset}`;
}

function render(checks: CheckResult[]): void {
  ln();
  ln(`  ${C.bold}ADVERSA system health${C.reset}`);
  ln(`  ${C.gray}${'─'.repeat(68)}${C.reset}`);
  ln();

  let okCount = 0, warnCount = 0, failCount = 0;

  for (const c of checks) {
    ln(`  ${symbol(c.status)} ${c.name.padEnd(34)} ${c.detail ? `${C.dim}${c.detail}${C.reset}` : ''}`);
    if (c.fix && c.status !== 'ok') {
      ln(`     ${C.cyan}Fix:${C.reset} ${c.fix}`);
    }
    if (c.status === 'ok')   okCount++;
    if (c.status === 'warn') warnCount++;
    if (c.status === 'fail') failCount++;
  }

  ln();
  ln(`  ${C.gray}${'─'.repeat(68)}${C.reset}`);
  ln(`  ${okCount} ok  ·  ${warnCount} warning  ·  ${failCount} failing`);
  ln();
  if (failCount === 0) {
    ln(`  ${C.green}Ready to scan.${C.reset}  Run: ${C.bold}./run.sh app${C.reset}`);
  } else {
    ln(`  ${C.red}${failCount} critical issue(s) — fix the items above and re-run \`adversa doctor\`.${C.reset}`);
  }
  ln();
}

// ── Individual checks ─────────────────────────────────────────────

function which(bin: string): string | null {
  const r = spawnSync(process.platform === 'win32' ? 'where' : 'which', [bin], { encoding: 'utf8' });
  if (r.status !== 0) return null;
  return r.stdout.trim().split(/\r?\n/)[0] || null;
}

function checkNode(): CheckResult {
  const major = parseInt(process.versions.node.split('.')[0], 10);
  if (major >= 20) {
    return { name: 'Node.js', status: 'ok', detail: `v${process.versions.node}` };
  }
  return {
    name:   'Node.js',
    status: 'fail',
    detail: `v${process.versions.node} — needs ≥ 20`,
    fix:    process.platform === 'darwin' ? '`brew install node`' : 'Use nvm: `nvm install 20`',
  };
}

function checkTool(tool: string, installCmd: string, optional = false, nativeFallback?: string): CheckResult {
  const p = which(tool);
  if (p) {
    const v = spawnSync(tool, ['-version'], { encoding: 'utf8' });
    const versionLine = (v.stdout || v.stderr).split(/\r?\n/)[0]?.trim();
    return { name: tool, status: 'ok', detail: `external: ${versionLine || p}`, meta: { path: p, mode: 'external' } };
  }
  if (nativeFallback) {
    return {
      name:   tool,
      status: 'ok',
      detail: `native fallback (${nativeFallback})`,
      meta:   { mode: 'native' },
    };
  }
  return {
    name:   tool,
    status: optional ? 'warn' : 'fail',
    detail: optional ? 'missing (that scan stage will be skipped)' : 'missing',
    fix:    installCmd,
  };
}

function checkEnvFile(): CheckResult {
  const envPath = path.join(process.cwd(), '.env.local');
  if (!existsSync(envPath)) {
    return {
      name:   '.env.local',
      status: 'fail',
      detail: 'missing',
      fix:    'Run `./run.sh setup` to generate defaults.',
    };
  }
  return { name: '.env.local', status: 'ok', detail: envPath };
}

function checkEnvKey(key: string, required = true): CheckResult {
  const envPath = path.join(process.cwd(), '.env.local');
  if (!existsSync(envPath)) {
    return { name: key, status: required ? 'fail' : 'warn', detail: '.env.local missing', fix: 'Run `./run.sh setup`.' };
  }
  const content = readFileSync(envPath, 'utf8');
  const match   = content.match(new RegExp(`^${key}=(.*)$`, 'm'));
  const value   = match?.[1]?.trim();
  if (!value) {
    return {
      name:   key,
      status: required ? 'fail' : 'warn',
      detail: 'empty',
      fix:    `Set ${key} in .env.local${key === 'ANTHROPIC_API_KEY' ? ' to enable AI features' : ''}.`,
    };
  }
  return { name: key, status: 'ok', detail: `set (${value.length} chars)` };
}

function checkNodeModules(): CheckResult {
  const p = path.join(process.cwd(), 'node_modules');
  if (existsSync(p)) return { name: 'node_modules', status: 'ok' };
  return {
    name:   'node_modules',
    status: 'fail',
    detail: 'missing',
    fix:    'Run `npm install` or `./run.sh setup`.',
  };
}

function checkDataDir(): CheckResult {
  const p = path.join(process.cwd(), 'data');
  if (existsSync(p)) return { name: 'data/', status: 'ok' };
  return {
    name:   'data/',
    status: 'warn',
    detail: 'missing — will be created on first scan',
    fix:    'No action needed; will be auto-created.',
  };
}

function checkSession(): CheckResult {
  const s = loadSession();
  if (s) {
    const age = Math.floor((Date.now() - new Date(s.savedAt).getTime()) / 86400000);
    return {
      name:   'CLI session',
      status: 'ok',
      detail: `${s.email} (${s.role}) · ${age}d old`,
    };
  }
  return {
    name:   'CLI session',
    status: 'warn',
    detail: 'not logged in',
    fix:    'Run `./run.sh app` and log in — first user becomes admin automatically.',
  };
}

async function checkServer(): Promise<CheckResult> {
  const url = serverUrl();
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 3000);
    const res = await fetch(`${url}/api/auth/me`, { signal: ctrl.signal }).catch(() => null);
    clearTimeout(t);
    if (!res) {
      return {
        name:   'API server',
        status: 'fail',
        detail: `not reachable at ${url}`,
        fix:    'Run `./run.sh start` and wait for "Server up".',
      };
    }
    // Even a 401 means the server is up
    return { name: 'API server', status: 'ok', detail: `reachable at ${url} (HTTP ${res.status})` };
  } catch (e) {
    return {
      name:   'API server',
      status: 'fail',
      detail: `error: ${e instanceof Error ? e.message : String(e)}`,
      fix:    'Run `./run.sh start` and check `.adversa-server.log`.',
    };
  }
}

// ── Command ───────────────────────────────────────────────────────

export function buildDoctorCommand(): Command {
  return new Command('doctor')
    .description('Run a system health check — verify every dependency')
    .option('--json', 'Output machine-readable JSON')
    .action(async (opts: { json?: boolean }) => {
      const checks: CheckResult[] = [];

      // Runtime
      checks.push(checkNode());
      checks.push(checkNodeModules());
      checks.push(checkDataDir());

      // Scanner tools — most have native fallbacks now, so missing = warn not fail
      checks.push(checkTool('naabu',     '`brew install libpcap go && go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest`',           true, 'TCP connect scan in Node'));
      checks.push(checkTool('nmap',      '`brew install nmap`',                                                                                          false));
      checks.push(checkTool('nuclei',    '`go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`',                                      false));
      checks.push(checkTool('testssl.sh','`git clone https://github.com/drwetter/testssl.sh ~/testssl.sh && sudo ln -s ~/testssl.sh/testssl.sh /usr/local/bin/testssl.sh`', true, 'basic cert + protocol check in Node'));
      checks.push(checkTool('subfinder', '`go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest`',                                true, 'DNS bruteforce in Node'));
      checks.push(checkTool('httpx',     '`go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest`',                                           true, 'fetch-based HTTP probe in Node'));
      checks.push(checkTool('ffuf',      '`brew install ffuf` (+ `brew install seclists`)',                                                              true, 'GET vs embedded mini-wordlist in Node'));
      checks.push(checkTool('whatweb',   '`brew install whatweb`',                                                                                       true, 'Wappalyzer-style rules in Node'));
      checks.push(checkTool('ssh-audit', '`pip install ssh-audit`',                                                                                      true));

      // Configuration
      checks.push(checkEnvFile());
      checks.push(checkEnvKey('AUTH_SECRET'));
      checks.push(checkEnvKey('SCOPE_SECRET'));
      checks.push(checkEnvKey('AGENT_SECRET'));
      checks.push(checkEnvKey('ANTHROPIC_API_KEY', false));

      // Runtime state
      checks.push(checkSession());
      checks.push(await checkServer());

      if (opts.json) {
        process.stdout.write(JSON.stringify(checks, null, 2) + '\n');
        return;
      }

      render(checks);
      const fails = checks.filter((c) => c.status === 'fail').length;
      process.exit(fails > 0 ? 1 : 0);
    });
}
