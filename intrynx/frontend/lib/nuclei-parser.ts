import type { Severity } from './engine/types';

export type NucleiMatch = {
  templateId: string;
  name: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info' | 'unknown';
  description?: string;
  host: string;
  ip?: string;
  port?: number;
  matchedAt: string;
  cveIds: string[];
  extractedResults: string[];
  timestamp: string;
};

interface NucleiRaw {
  'template-id'?: string;
  info?: {
    name?: string;
    severity?: string;
    description?: string;
    classification?: {
      'cve-id'?: string | string[];
    };
  };
  host?: string;
  ip?: string;
  port?: string | number;
  'matched-at'?: string;
  'extracted-results'?: string[];
  timestamp?: string;
}

export function parseNucleiLine(jsonl: string): NucleiMatch | null {
  if (!jsonl || !jsonl.trim()) return null;
  try {
    const raw = JSON.parse(jsonl.trim()) as NucleiRaw;
    if (!raw['template-id'] || !raw.host) return null;

    const rawCves = raw.info?.classification?.['cve-id'];
    const cveIds = rawCves
      ? (Array.isArray(rawCves) ? rawCves : [rawCves]).filter(Boolean)
      : [];

    const sevRaw = (raw.info?.severity ?? 'unknown').toLowerCase();
    const severity = (['critical', 'high', 'medium', 'low', 'info'].includes(sevRaw)
      ? sevRaw
      : 'unknown') as NucleiMatch['severity'];

    const port = raw.port ? Number(raw.port) : undefined;

    return {
      templateId:       raw['template-id'],
      name:             raw.info?.name ?? raw['template-id'],
      severity,
      description:      raw.info?.description,
      host:             raw.host,
      ip:               raw.ip,
      port:             port && !isNaN(port) ? port : undefined,
      matchedAt:        raw['matched-at'] ?? raw.host,
      cveIds,
      extractedResults: raw['extracted-results'] ?? [],
      timestamp:        raw.timestamp ?? new Date().toISOString(),
    };
  } catch {
    return null;
  }
}

export function nucleiSeverityToSeverity(s: string): Severity {
  switch (s.toLowerCase()) {
    case 'critical': return 'CRITICAL';
    case 'high':     return 'HIGH';
    case 'medium':   return 'MEDIUM';
    case 'low':      return 'LOW';
    default:         return 'INFO';
  }
}

// ── Backwards-compat shims for pre-refactor dashboard routes ──────────
export type NucleiRawLine = NucleiMatch;

export function nucleiMatchToFinding(match: NucleiMatch): Record<string, unknown> {
  return {
    title:     match.name,
    severity:  nucleiSeverityToSeverity(match.severity),
    host:      match.host,
    port:      match.port,
    source:    'nuclei',
    cveIds:    match.cveIds,
    evidence:  [{ label: 'nuclei match', content: match.matchedAt, timestamp: match.timestamp }],
    status:    'OPEN',
    timestamp: match.timestamp,
  };
}

export function countBySeverity(findings: { severity: string }[]): Record<string, number> {
  const out: Record<string, number> = {};
  for (const f of findings) {
    out[f.severity] = (out[f.severity] ?? 0) + 1;
  }
  return out;
}
