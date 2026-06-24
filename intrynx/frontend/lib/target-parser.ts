const IP_RE    = /^(\d{1,3}\.){3}\d{1,3}$/;
const CIDR_RE  = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;
const RANGE_RE = /^(\d{1,3}\.){3}\d{1,3}-(\d{1,3}\.){3}\d{1,3}$/;
const HOST_RE  = /^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$/;

const RFC1918 = [
  /^10\.\d+\.\d+\.\d+$/,
  /^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$/,
  /^192\.168\.\d+\.\d+$/,
];

function validOctets(ip: string): boolean {
  return ip.split('.').every((o) => {
    const n = Number(o);
    return Number.isInteger(n) && n >= 0 && n <= 255;
  });
}

export function isValidTarget(target: string): boolean {
  const t = target.trim();
  if (!t) return false;
  if (IP_RE.test(t))    return validOctets(t);
  if (CIDR_RE.test(t)) {
    const [ip, prefix] = t.split('/');
    return validOctets(ip) && Number(prefix) >= 0 && Number(prefix) <= 32;
  }
  if (RANGE_RE.test(t)) {
    const [start, end] = t.split('-');
    return validOctets(start) && validOctets(end);
  }
  if (HOST_RE.test(t)) return true;
  return false;
}

export function isPrivateRange(target: string): boolean {
  return RFC1918.some((re) => re.test(target.trim()));
}

// ── Host count estimator ─────────────────────────────────────────
function estimateHostCount(targets: string[]): number {
  let total = 0;
  for (const t of targets) {
    if (CIDR_RE.test(t)) {
      const prefix = Number(t.split('/')[1]);
      total += prefix >= 31 ? 1 : Math.pow(2, 32 - prefix) - 2;
    } else if (RANGE_RE.test(t)) {
      const [s, e] = t.split('-').map((ip) =>
        ip.split('.').reduce((acc, o) => acc * 256 + Number(o), 0),
      );
      total += Math.max(1, e - s + 1);
    } else {
      total += 1;
    }
  }
  return total;
}

// ── ParseResult — used by the scan UI ───────────────────────────
export interface ParseResult {
  valid:          string[];
  invalid:        string[];
  hasPublicIPs:   boolean;
  hasPrivateIPs:  boolean;
  totalHosts:     number;   // estimated host count (CIDRs expanded, IPs counted as 1)
}

// Overload 1: called from scan UI with raw text + exclusion list → ParseResult
export function parseTargets(rawText: string, exclusions: string[]): ParseResult;
// Overload 2: called from CLI / API with string or string[] → string[] (throws on invalid)
export function parseTargets(input: string | string[]): string[];

export function parseTargets(
  input: string | string[],
  exclusions?: string[],
): string[] | ParseResult {
  // ── UI mode (exclusions provided) ──────────────────────────
  if (exclusions !== undefined) {
    const raw = (input as string);
    const lines = raw
      .split(/[\n,;]+/)
      .map((l) => l.trim())
      .filter((l) => l.length > 0 && !l.startsWith('#'));

    const excSet = new Set(
      exclusions.map((e) => e.trim()).filter(Boolean),
    );

    const valid:   string[] = [];
    const invalid: string[] = [];

    for (const t of [...new Set(lines)]) {
      if (excSet.has(t)) continue;
      if (isValidTarget(t)) {
        valid.push(t);
      } else {
        invalid.push(t);
      }
    }

    return {
      valid,
      invalid,
      hasPublicIPs:  valid.some((t) => IP_RE.test(t) && !isPrivateRange(t)),
      hasPrivateIPs: valid.some((t) => isPrivateRange(t)),
      totalHosts:    estimateHostCount(valid),
    };
  }

  // ── CLI / API mode (no exclusions) — throws on invalid ─────
  const lines: string[] = Array.isArray(input)
    ? input
    : (input as string).split(/[\n,]+/);

  const cleaned = lines
    .map((l) => l.trim())
    .filter((l) => l.length > 0 && !l.startsWith('#'));

  const bad = cleaned.filter((t) => !isValidTarget(t));
  if (bad.length > 0) {
    throw new Error(`Invalid target(s): ${bad.join(', ')}`);
  }

  return [...new Set(cleaned)];
}

// ── toApiTargets — extracts valid[] from a ParseResult ──────────
export function toApiTargets(result: ParseResult): string[] {
  return result.valid;
}

// ── COMMON_RANGES — quick-insert buttons in the scan UI ─────────
export const COMMON_RANGES: { cidr: string; label: string }[] = [
  { cidr: '10.0.0.0/8',       label: '10.0.0.0/8' },
  { cidr: '172.16.0.0/12',    label: '172.16.0.0/12' },
  { cidr: '192.168.0.0/16',   label: '192.168.0.0/16' },
  { cidr: '192.168.1.0/24',   label: '192.168.1.0/24' },
  { cidr: '10.0.0.0/24',      label: '10.0.0.0/24' },
  { cidr: '10.10.0.0/16',     label: '10.10.0.0/16' },
  { cidr: '172.20.0.0/16',    label: '172.20.0.0/16' },
  { cidr: '100.64.0.0/10',    label: '100.64.0.0/10' },
];
