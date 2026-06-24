/**
 * Native directory busting — HTTP GET against an embedded wordlist.
 * Replaces ffuf for casual use; users can still set ADVERSA_FFUF_WORDLIST
 * to point at SecLists for deeper enumeration.
 *
 * Strategy:
 *   1. GET the base URL once → record status + content-length baseline
 *   2. For each path: GET, compare against baseline, flag interesting status
 *   3. Status 200/204/301/302/401/403 + length-differs-from-baseline = report
 */
import { readFileSync, existsSync } from 'fs';
import { request as httpsRequest } from 'https';
import { request as httpRequest } from 'http';

/** Built-in mini wordlist — most-hit ~120 paths from real engagements. */
const BUILTIN_PATHS = [
  // Admin / management
  'admin', 'administrator', 'login', 'wp-admin', 'wp-login.php',
  'phpmyadmin', 'cpanel', 'webmail', 'manager', 'manage',
  // API
  'api', 'api/v1', 'api/v2', 'graphql', 'swagger', 'swagger-ui', 'swagger.json',
  'openapi.json', 'docs', 'redoc',
  // Common files
  'robots.txt', 'sitemap.xml', '.env', '.git/config', '.git/HEAD',
  'web.config', 'crossdomain.xml', 'humans.txt', '.well-known/security.txt',
  // Backups
  'backup', 'backups', 'old', 'bak', 'backup.zip', 'backup.tar.gz',
  'database.sql', 'dump.sql', '.bak', '.old', '.zip',
  // Config
  'config', 'config.php', 'config.json', 'config.yml', 'configuration.php',
  'wp-config.php', 'settings', 'settings.json',
  // Static
  'static', 'public', 'uploads', 'files', 'images', 'js', 'css', 'assets',
  // Auth
  'register', 'signup', 'signin', 'logout', 'forgot-password', 'reset-password',
  'oauth', 'sso', 'auth',
  // Common app paths
  'dashboard', 'profile', 'account', 'settings', 'preferences',
  'home', 'index', 'search', 'help', 'support', 'contact',
  // Dev / debug
  'debug', 'test', 'dev', 'staging', 'demo', 'beta',
  'phpinfo.php', 'info.php', 'test.php', 'health', 'healthz', 'status',
  'metrics', 'actuator', 'actuator/health', 'actuator/env',
  // CMS
  'wp-content', 'wp-includes', 'wp-json', 'wp-cron.php', 'xmlrpc.php',
  'sites/default', 'modules', 'themes', 'plugins',
  // Cloud / containers
  'console', '.aws', '.kube', 'kubernetes', 'docker',
  // Tomcat / JBoss / etc.
  'manager/html', 'host-manager', 'jmx-console', 'web-console',
  // Common files (.well-known)
  '.well-known/openid-configuration', '.well-known/oauth-authorization-server',
  // CVE-related quick checks
  '_ignition/execute-solution', 'console',
];

export interface DirBustResult {
  url:            string;
  status:         number;
  contentLength:  number;
  baselineStatus: number;
  interesting:    boolean;
  reason?:        string;
}

interface ProbeResp {
  status: number;
  length: number;
}

function probe(url: string): Promise<ProbeResp> {
  return new Promise((resolve) => {
    const u = new URL(url);
    const port = Number(u.port) || (u.protocol === 'https:' ? 443 : 80);
    const baseOpts = { hostname: u.hostname, port, path: u.pathname, method: 'GET', timeout: 3000, headers: { 'User-Agent': 'adversa-scanner/1.0' } };
    const onResponse = (res: import('http').IncomingMessage) => {
      let len = 0;
      res.on('data', (chunk: Buffer | string) => { len += chunk.length; if (len > 50_000) req.destroy(); });
      res.on('end', () => resolve({ status: res.statusCode ?? 0, length: len }));
    };
    const req = u.protocol === 'https:'
      ? httpsRequest({ ...baseOpts, rejectUnauthorized: false }, onResponse)
      : httpRequest(baseOpts, onResponse);
    req.on('timeout', () => { req.destroy(); resolve({ status: 0, length: 0 }); });
    req.on('error',   () => resolve({ status: 0, length: 0 }));
    req.end();
  });
}

export interface NativeDirOpts {
  wordlistPath?: string;
  maxPaths?:    number;
  concurrency?: number;
  onProgress?:  (done: number, total: number) => void;
}

function loadWordlist(opts: NativeDirOpts): string[] {
  const path = opts.wordlistPath || process.env.ADVERSA_FFUF_WORDLIST;
  if (path && existsSync(path)) {
    try {
      const lines = readFileSync(path, 'utf-8').split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
      return lines.slice(0, opts.maxPaths ?? 500);
    } catch { /* fall through */ }
  }
  return BUILTIN_PATHS.slice(0, opts.maxPaths ?? BUILTIN_PATHS.length);
}

/**
 * Bust paths against a base URL. Returns only interesting hits.
 * Interesting = status 200/204/301/302/401/403 and length differs from the
 * "not found" baseline by more than 10 bytes.
 */
export async function nativeDirBust(
  baseUrl: string,
  opts: NativeDirOpts = {},
): Promise<DirBustResult[]> {
  const u = new URL(baseUrl);
  const base = `${u.protocol}//${u.host}`;

  // Baseline: probe a guaranteed-non-existent path
  const baseline = await probe(`${base}/this-path-cannot-exist-${Date.now()}`);

  const paths  = loadWordlist(opts);
  const concurrency = opts.concurrency ?? 25;
  const out: DirBustResult[] = [];
  let active = 0; let next = 0; let done = 0;

  await new Promise<void>((resolve) => {
    const launch = (): void => {
      while (active < concurrency && next < paths.length) {
        const path = paths[next++];
        const url  = `${base}/${path}`;
        active++;
        probe(url).then((r) => {
          active--; done++;
          // Reportable: not the same as baseline AND status is meaningful
          const sizeDiff = Math.abs(r.length - baseline.length) > 10;
          const statusInteresting = [200, 204, 301, 302, 401, 403].includes(r.status);
          const statusDiff = r.status !== baseline.status;
          const interesting = statusInteresting && (statusDiff || sizeDiff);
          if (interesting) {
            out.push({
              url,
              status: r.status,
              contentLength: r.length,
              baselineStatus: baseline.status,
              interesting: true,
              reason: r.status === 401 ? 'auth-required' : r.status === 403 ? 'forbidden' : 'found',
            });
          }
          opts.onProgress?.(done, paths.length);
          if (next < paths.length) launch();
          else if (active === 0) resolve();
        });
      }
    };
    if (paths.length === 0) resolve();
    else launch();
  });

  return out;
}
