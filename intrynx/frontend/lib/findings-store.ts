import fs   from 'fs';
import path from 'path';
import type { LiveFinding, Severity, Evidence } from './engine/types';
import { generateFindingId } from './finding-id';

// Backwards-compat type alias used by openvas-client.ts
export type FindingSeverity = Severity;

const DEFAULT_DATA_PATH = path.join(process.cwd(), 'data', 'findings.json');
export let DATA_PATH = process.env.DATA_PATH ?? DEFAULT_DATA_PATH;

// Exposed for tests: override the data file path
export function setDataPath(p: string): void { DATA_PATH = p; }

const SLA_HOURS: Partial<Record<Severity, number>> = {
  CRITICAL: 24,
  HIGH:     72,
  MEDIUM:   168,
  LOW:      720,
};

function ensureDir(): void {
  const dir = path.dirname(DATA_PATH);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

function slaDeadline(severity: Severity): string | undefined {
  const h = SLA_HOURS[severity];
  if (!h) return undefined;
  return new Date(Date.now() + h * 3_600_000).toISOString();
}

export function getAllFindings(): LiveFinding[] {
  ensureDir();
  if (!fs.existsSync(DATA_PATH)) return [];
  try {
    return JSON.parse(fs.readFileSync(DATA_PATH, 'utf-8')) as LiveFinding[];
  } catch {
    return [];
  }
}

function isDuplicate(existing: LiveFinding, candidate: LiveFinding): boolean {
  if (existing.host !== candidate.host) return false;
  const eCves = existing.cveIds ?? [];
  const cCves = candidate.cveIds ?? [];
  if (eCves.length > 0 && cCves.length > 0 && eCves.some((c) => cCves.includes(c))) return true;
  return existing.title.toLowerCase().trim() === candidate.title.toLowerCase().trim();
}

export function saveFindings(findings: LiveFinding[], engagementId?: string): number {
  const existing = getAllFindings();
  let added = 0;

  for (const f of findings) {
    const dup = existing.find((e) => isDuplicate(e, f));
    if (dup) {
      dup.evidence   = [...(dup.evidence ?? []), ...(f.evidence ?? [])];
      dup.timestamp  = new Date().toISOString();
    } else {
      existing.push({
        ...f,
        engagementId: engagementId ?? f.engagementId,
        slaDeadline:  slaDeadline(f.severity),
      });
      added++;
    }
  }

  ensureDir();
  fs.writeFileSync(DATA_PATH, JSON.stringify(existing, null, 2));
  return added;
}

export function getFindingById(id: string): LiveFinding | undefined {
  return getAllFindings().find((f) => f.id === id);
}

export function updateFindingStatus(id: string, status: LiveFinding['status']): boolean {
  const findings = getAllFindings();
  const idx = findings.findIndex((f) => f.id === id);
  if (idx === -1) return false;
  findings[idx].status    = status;
  findings[idx].timestamp = new Date().toISOString();
  ensureDir();
  fs.writeFileSync(DATA_PATH, JSON.stringify(findings, null, 2));
  return true;
}

export function getFindingsByEngagement(engagementId: string): LiveFinding[] {
  return getAllFindings().filter((f) => f.engagementId === engagementId);
}

export function getFindingStats(): {
  total: number;
  bySeverity: Record<Severity, number>;
  byStatus: Record<string, number>;
} {
  const findings = getAllFindings();
  const bySeverity: Record<Severity, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  const byStatus: Record<string, number> = {};

  for (const f of findings) {
    bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;
    byStatus[f.status]     = (byStatus[f.status] ?? 0) + 1;
  }

  return { total: findings.length, bySeverity, byStatus };
}

// ── Backwards-compat shims for pre-refactor dashboard routes ──────────
export const readFindings = getAllFindings;

export function createFinding(data: Partial<LiveFinding> | Record<string, unknown>): LiveFinding {
  const d = data as Record<string, unknown>;
  const now = new Date().toISOString();
  const severity = (d.severity as Severity) ?? 'INFO';
  const finding: LiveFinding = {
    id:        String(d.id ?? generateFindingId(severity)),
    title:     String(d.title ?? 'Untitled'),
    severity,
    host:      String(d.host ?? d.affectedHost ?? 'unknown'),
    source:    (d.source as LiveFinding['source']) ?? 'manual',
    evidence:  (d.evidence as Evidence[]) ?? [],
    status:    (d.status as LiveFinding['status']) ?? 'OPEN',
    timestamp: String(d.timestamp ?? d.discoveredAt ?? now),
  };
  saveFindings([finding]);
  return finding;
}

export function updateFinding(id: string, patch: Record<string, unknown>): LiveFinding | null {
  const findings = getAllFindings();
  const idx = findings.findIndex((f) => f.id === id);
  if (idx === -1) return null;
  findings[idx] = { ...findings[idx], ...patch, timestamp: new Date().toISOString() } as LiveFinding;
  ensureDir();
  fs.writeFileSync(DATA_PATH, JSON.stringify(findings, null, 2));
  return findings[idx];
}

export function deleteFinding(id: string): boolean {
  const findings = getAllFindings();
  const next = findings.filter((f) => f.id !== id);
  if (next.length === findings.length) return false;
  ensureDir();
  fs.writeFileSync(DATA_PATH, JSON.stringify(next, null, 2));
  return true;
}
