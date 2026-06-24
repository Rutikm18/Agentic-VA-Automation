/**
 * Native HTTP probe + tech fingerprinting.
 *
 * Replaces httpx (live web service detection) and whatweb (tech fingerprint)
 * for the common case. Uses Node's built-in fetch — no external binaries.
 *
 * What it produces per URL:
 *   - status code, title, server, content-length
 *   - tech stack indicators (CMS, framework, web server, JS lib)
 *   - TLS info if HTTPS (cert subject, issuer, expiry)
 *   - redirect chain
 *
 * The tech fingerprint ruleset is intentionally small and curated — covers
 * the ~30 highest-value matchers an operator actually cares about. Full
 * Wappalyzer-style coverage would need a 5MB JSON file.
 */
import { request as httpsRequest } from 'https';
import { request as httpRequest } from 'http';
import type { TLSSocket } from 'tls';

const WEB_PORT_PROTO: Record<number, 'http' | 'https'> = {
  80: 'http', 8080: 'http', 8000: 'http', 8081: 'http', 3000: 'http', 5000: 'http',
  443: 'https', 8443: 'https', 4443: 'https', 9443: 'https',
};

/** ── Tech fingerprint rules ────────────────────────────────────────
 * Each rule has: name, evidence (header regex, body regex, cookie name),
 * optional version-extract regex.
 */
interface TechRule {
  name:        string;
  category:    'cms' | 'framework' | 'server' | 'js' | 'language' | 'cdn' | 'security';
  header?:     { name: string; pattern: RegExp; version?: RegExp };
  body?:       { pattern: RegExp; version?: RegExp };
  cookie?:     RegExp;
}

const TECH_RULES: TechRule[] = [
  // CMS
  { name: 'WordPress',  category: 'cms',      body: { pattern: /wp-content|wp-includes/i, version: /content="WordPress (\d+\.\d+\.\d+)"/i } },
  { name: 'Drupal',     category: 'cms',      header: { name: 'x-drupal-cache', pattern: /.+/i } },
  { name: 'Joomla',     category: 'cms',      body: { pattern: /<meta name="generator" content="Joomla/i, version: /Joomla! (\d+\.\d+\.\d+)/i } },
  { name: 'Magento',    category: 'cms',      body: { pattern: /Mage\.Cookies|var BLANK_URL/i } },
  { name: 'Shopify',    category: 'cms',      header: { name: 'x-shopify-stage', pattern: /.+/i } },
  // Frameworks
  { name: 'Django',     category: 'framework', cookie: /csrftoken|django/i },
  { name: 'Rails',      category: 'framework', header: { name: 'x-powered-by', pattern: /phusion passenger/i } },
  { name: 'Express',    category: 'framework', header: { name: 'x-powered-by', pattern: /express/i } },
  { name: 'ASP.NET',    category: 'framework', header: { name: 'x-powered-by', pattern: /ASP\.NET/i, version: /ASP\.NET[^\d]*(\d+\.\d+)/i } },
  { name: 'Laravel',    category: 'framework', cookie: /laravel_session/i },
  { name: 'Next.js',    category: 'framework', header: { name: 'x-powered-by', pattern: /next\.js/i, version: /Next\.js[^\d]*(\d+\.\d+)/i } },
  // Web servers
  { name: 'nginx',      category: 'server',   header: { name: 'server', pattern: /^nginx/i, version: /nginx\/(\d+\.\d+\.\d+)/i } },
  { name: 'Apache',     category: 'server',   header: { name: 'server', pattern: /^apache/i, version: /Apache\/(\d+\.\d+\.\d+)/i } },
  { name: 'IIS',        category: 'server',   header: { name: 'server', pattern: /^microsoft-iis/i, version: /Microsoft-IIS\/(\d+\.\d+)/i } },
  { name: 'LiteSpeed',  category: 'server',   header: { name: 'server', pattern: /litespeed/i } },
  { name: 'Caddy',      category: 'server',   header: { name: 'server', pattern: /^caddy/i } },
  { name: 'Cloudflare', category: 'cdn',      header: { name: 'server', pattern: /cloudflare/i } },
  { name: 'AWS CloudFront', category: 'cdn',  header: { name: 'via', pattern: /cloudfront/i } },
  // Languages
  { name: 'PHP',        category: 'language',  header: { name: 'x-powered-by', pattern: /^php/i, version: /PHP\/(\d+\.\d+\.\d+)/i } },
  { name: 'Python',     category: 'language',  header: { name: 'server', pattern: /python/i } },
  // JS frameworks
  { name: 'React',      category: 'js',       body: { pattern: /<div id="(root|__next)"|data-react/i } },
  { name: 'Vue.js',     category: 'js',       body: { pattern: /data-v-app|Vue\.config|<script[^>]*vue/i } },
  { name: 'Angular',    category: 'js',       body: { pattern: /ng-version|ng-app/i } },
  { name: 'jQuery',     category: 'js',       body: { pattern: /jquery[-.]([\d.]+)/i, version: /jquery[-.]([\d.]+)/i } },
  // Security / WAF
  { name: 'Cloudflare WAF', category: 'security', header: { name: 'cf-ray', pattern: /.+/i } },
  { name: 'Sucuri',     category: 'security', header: { name: 'x-sucuri-id', pattern: /.+/i } },
  { name: 'AWS WAF',    category: 'security', header: { name: 'x-amzn-trace-id', pattern: /.+/i } },
  // Other
  { name: 'Tomcat',     category: 'server',   header: { name: 'server', pattern: /apache-coyote|tomcat/i } },
  { name: 'Jetty',      category: 'server',   header: { name: 'server', pattern: /^jetty/i, version: /Jetty\(([^\)]+)\)/i } },
  { name: 'GraphQL',    category: 'framework', body: { pattern: /<title>GraphiQL|graphqlEndpoint/i } },
  { name: 'Swagger UI', category: 'framework', body: { pattern: /<title>Swagger UI|swagger-ui-bundle/i } },
];

export interface HttpProbeResult {
  url:           string;
  scheme:        'http' | 'https';
  host:          string;
  port:          number;
  status:        number;
  title?:        string;
  server?:       string;
  contentLength?: number;
  tech:          Array<{ name: string; category: string; version?: string }>;
  redirects:     string[];
  tlsInfo?: {
    subject?:    string;
    issuer?:     string;
    validFrom?:  string;
    validTo?:    string;
    daysToExpiry?: number;
    altNames?:   string[];
    selfSigned?: boolean;
  };
  durationMs:    number;
  error?:        string;
}

function extractTitle(body: string): string | undefined {
  const m = body.match(/<title[^>]*>([^<]+)<\/title>/i);
  return m ? m[1].trim().slice(0, 200) : undefined;
}

function fingerprint(headers: Record<string, string>, body: string, cookies: string[]): HttpProbeResult['tech'] {
  const matched: HttpProbeResult['tech'] = [];
  for (const rule of TECH_RULES) {
    let version: string | undefined;
    let hit = false;

    if (rule.header) {
      const val = headers[rule.header.name.toLowerCase()];
      if (val && rule.header.pattern.test(val)) {
        hit = true;
        if (rule.header.version) {
          const m = val.match(rule.header.version);
          if (m) version = m[1];
        }
      }
    }
    if (!hit && rule.body) {
      if (rule.body.pattern.test(body)) {
        hit = true;
        if (rule.body.version) {
          const m = body.match(rule.body.version);
          if (m) version = m[1];
        }
      }
    }
    if (!hit && rule.cookie) {
      if (cookies.some((c) => rule.cookie!.test(c))) hit = true;
    }
    if (hit && !matched.find((x) => x.name === rule.name)) {
      matched.push({ name: rule.name, category: rule.category, version });
    }
  }
  return matched;
}

function probeOne(host: string, port: number, scheme: 'http' | 'https'): Promise<HttpProbeResult> {
  return new Promise((resolve) => {
    const url = `${scheme}://${host}:${port}/`;
    const start = Date.now();
    let resolved = false;
    const done = (r: HttpProbeResult): void => {
      if (resolved) return;
      resolved = true;
      resolve(r);
    };
    const fail = (error: string): void => done({ url, scheme, host, port, status: 0, tech: [], redirects: [], durationMs: Date.now() - start, error });

    let req: ReturnType<typeof httpRequest>;
    try {
      // The HTTPS overload supports rejectUnauthorized; HTTP doesn't but ignores it harmlessly.
      // Use a single options object cast through unknown to satisfy both signatures.
      const requestOpts: unknown = {
        hostname: host,
        port,
        path: '/',
        method: 'GET',
        timeout: 5000,
        rejectUnauthorized: false,
        headers: { 'User-Agent': 'adversa-scanner/1.0', 'Accept': '*/*' },
      };
      req = (scheme === 'https' ? httpsRequest : httpRequest)(requestOpts as Parameters<typeof httpsRequest>[0], (res) => {
        let body = '';
        try { res.setEncoding('utf8'); } catch { /* ignore */ }
        res.on('data', (chunk: string) => {
          try {
            body += chunk;
            if (body.length > 50_000) { try { req.destroy(); } catch { /* ignore */ } }
          } catch { /* ignore */ }
        });
        res.on('error', () => fail('response-error'));
        res.on('end', () => {
          try {
            const headers: Record<string, string> = {};
            for (const [k, v] of Object.entries(res.headers)) {
              if (typeof v === 'string') headers[k.toLowerCase()] = v;
              else if (Array.isArray(v)) headers[k.toLowerCase()] = v.join(', ');
            }
            const cookies = Array.isArray(res.headers['set-cookie']) ? res.headers['set-cookie'] : [];
            let tech: HttpProbeResult['tech'] = [];
            try { tech = fingerprint(headers, body, cookies); } catch { tech = []; }

            let tlsInfo: HttpProbeResult['tlsInfo'];
            try {
              if (scheme === 'https' && req.socket && (req.socket as TLSSocket).getPeerCertificate) {
                const cert = (req.socket as TLSSocket).getPeerCertificate();
                if (cert && cert.subject) {
                  const expiry = cert.valid_to ? new Date(cert.valid_to).getTime() : 0;
                  const cn = (s: unknown): string | undefined => {
                    if (typeof s === 'string') return s;
                    if (Array.isArray(s)) return s[0];
                    return undefined;
                  };
                  tlsInfo = {
                    subject:    cn(cert.subject?.CN),
                    issuer:     cn(cert.issuer?.CN),
                    validFrom:  cert.valid_from,
                    validTo:    cert.valid_to,
                    daysToExpiry: expiry ? Math.floor((expiry - Date.now()) / 86400000) : undefined,
                    altNames:   typeof cert.subjectaltname === 'string' ? cert.subjectaltname.split(', ') : undefined,
                    selfSigned: cn(cert.issuer?.CN) === cn(cert.subject?.CN),
                  };
                }
              }
            } catch { /* TLS info best-effort */ }

            done({
              url, scheme, host, port,
              status: res.statusCode ?? 0,
              title:  extractTitle(body),
              server: headers['server'],
              contentLength: parseInt(headers['content-length'] ?? '0', 10) || body.length,
              tech,
              redirects: [],
              tlsInfo,
              durationMs: Date.now() - start,
            });
          } catch (e) {
            fail(e instanceof Error ? e.message : 'parse-error');
          }
        });
      });
      req.on('timeout', () => { try { req.destroy(); } catch { /* ignore */ } fail('timeout'); });
      req.on('error',   (err) => fail(err.message ?? 'request-error'));
      req.end();
    } catch (e) {
      fail(e instanceof Error ? e.message : 'setup-error');
      return;
    }
  });
}

export interface NativeHttpOpts {
  concurrency?: number;
  onProgress?:  (done: number, total: number) => void;
}

/**
 * Probe each host:port that looks like a web service. Returns one result per
 * URL that successfully responded (status > 0).
 */
export async function nativeHttpProbe(
  hosts: { ip: string; ports: number[] }[],
  opts: NativeHttpOpts = {},
): Promise<HttpProbeResult[]> {
  const queue: Array<[string, number, 'http' | 'https']> = [];
  for (const h of hosts) {
    for (const p of h.ports) {
      const proto = WEB_PORT_PROTO[p];
      if (proto) queue.push([h.ip, p, proto]);
    }
  }

  const concurrency = opts.concurrency ?? 30;
  const out: HttpProbeResult[] = [];
  let active = 0; let next = 0; let done = 0;

  await new Promise<void>((resolve) => {
    const launch = (): void => {
      while (active < concurrency && next < queue.length) {
        const [ip, port, scheme] = queue[next++];
        active++;
        probeOne(ip, port, scheme).catch((): HttpProbeResult => ({
          url: `${scheme}://${ip}:${port}/`, scheme, host: ip, port,
          status: 0, tech: [], redirects: [], durationMs: 0,
          tlsInfo: undefined,
          error: 'probe-rejected',
        })).then((r) => {
          active--; done++;
          if (r.status > 0 || r.tlsInfo) out.push(r);
          opts.onProgress?.(done, queue.length);
          if (next < queue.length) launch();
          else if (active === 0) resolve();
        });
      }
    };
    if (queue.length === 0) resolve();
    else launch();
  });

  return out;
}
