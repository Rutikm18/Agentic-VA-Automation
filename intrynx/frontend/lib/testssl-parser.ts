import type { LiveFinding, Severity } from './engine/types';
import { generateFindingId } from './finding-id';

export type TestsslIssue = {
  id: string;
  severity: string;
  finding: string;
  cve?: string;
  cwe?: string;
};

const SKIP_SEVERITY = new Set(['OK', 'INFO', 'DEBUG']);

function mapSeverity(raw: string): Severity {
  switch (raw.toUpperCase()) {
    case 'CRITICAL': return 'CRITICAL';
    case 'HIGH':
    case 'WARN':     return 'HIGH';
    case 'MEDIUM':   return 'MEDIUM';
    case 'LOW':      return 'LOW';
    default:         return 'INFO';
  }
}

// Backwards-compat shims for pre-refactor dashboard routes
export type TestsslOutput = { findings: TestsslIssue[] } | TestsslIssue[];

export function parseTestsslOutput(
  data: TestsslOutput | string,
  host: string,
  port = 443,
): LiveFinding[] {
  if (typeof data === 'string') return parseTestsslJson(data, host, port);
  const issues = Array.isArray(data) ? data : (data as { findings: TestsslIssue[] }).findings ?? [];
  return parseTestsslJson(JSON.stringify(issues), host, port);
}

export function parseTestsslJson(
  jsonContent: string,
  host: string,
  port: number,
): LiveFinding[] {
  if (!jsonContent || !jsonContent.trim()) return [];

  let issues: TestsslIssue[];
  try {
    const parsed = JSON.parse(jsonContent);
    issues = Array.isArray(parsed) ? parsed : (parsed?.findings ?? []);
  } catch {
    return [];
  }

  const findings: LiveFinding[] = [];
  const now = new Date().toISOString();

  for (const issue of issues) {
    if (!issue || SKIP_SEVERITY.has((issue.severity ?? '').toUpperCase())) continue;

    const severity = mapSeverity(issue.severity ?? '');
    const title    = `${issue.id}: ${(issue.finding ?? '').slice(0, 60)}`;

    findings.push({
      id:        generateFindingId(severity),
      title,
      severity,
      host,
      port,
      evidence:  [{ label: 'testssl output', content: issue.finding ?? '', timestamp: now }],
      source:    'testssl',
      cveIds:    issue.cve ? [issue.cve] : [],
      status:    'OPEN',
      timestamp: now,
    });
  }

  return findings;
}
