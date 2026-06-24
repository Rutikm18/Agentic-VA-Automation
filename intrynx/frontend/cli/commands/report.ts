import { Command }              from 'commander';
import fs                       from 'fs';
import path                     from 'path';
import { requireAuth, apiFetch } from '../auth';

interface Engagement {
  id:           string;
  name:         string;
  client:       string;
  status:       string;
  findingCount: number;
}

interface AiReport {
  executive_summary?: string;
  risk_scorecard?: {
    overall?:  number;
    network?:  number;
    auth?:     number;
    config?:   number;
    patches?:  number;
    web?:      number;
  };
  findings?: Array<{
    finding_id?:        string;
    title?:             string;
    severity?:          string;
    business_impact?:   string;
    technical_detail?:  string;
    remediation_detail?: string;
  }>;
  remediation_roadmap?: {
    priority_1_24h?: string[];
    priority_2_30d?: string[];
    priority_3_90d?: string[];
  };
  positive_findings?: string;
}

function errExit(msg: string): never {
  process.stderr.write(`\x1b[1;31m[ERR]\x1b[0m ${msg}\n`);
  process.exit(1);
}

function renderReport(r: AiReport): void {
  const w = (s: string) => process.stdout.write(s);

  w('\n  \x1b[1;36m═══ EXECUTIVE SUMMARY ═══\x1b[0m\n\n');
  w(`  ${(r.executive_summary ?? '(no summary)').replace(/\n/g, '\n  ')}\n\n`);

  if (r.risk_scorecard) {
    const s = r.risk_scorecard;
    w('  \x1b[1;36m═══ RISK SCORECARD ═══\x1b[0m\n\n');
    w(`    Overall ${s.overall ?? '-'}/100   Network ${s.network ?? '-'}   Auth ${s.auth ?? '-'}   Config ${s.config ?? '-'}   Patches ${s.patches ?? '-'}   Web ${s.web ?? '-'}\n\n`);
  }

  if (r.findings?.length) {
    w(`  \x1b[1;36m═══ FINDINGS (${r.findings.length}) ═══\x1b[0m\n\n`);
    for (const f of r.findings) {
      const sevColor: Record<string, string> = {
        CRITICAL: '\x1b[1;31m', HIGH: '\x1b[31m', MEDIUM: '\x1b[33m', LOW: '\x1b[36m', INFO: '\x1b[90m',
      };
      const col = sevColor[(f.severity ?? '').toUpperCase()] ?? '';
      w(`  ${col}[${f.severity ?? '?'}]\x1b[0m ${f.finding_id ?? ''} — ${f.title ?? '(no title)'}\n`);
      if (f.business_impact) w(`    \x1b[2mImpact:\x1b[0m ${f.business_impact}\n`);
      if (f.remediation_detail) w(`    \x1b[2mFix:\x1b[0m    ${f.remediation_detail}\n`);
      w('\n');
    }
  }

  if (r.remediation_roadmap) {
    const r2 = r.remediation_roadmap;
    w('  \x1b[1;36m═══ REMEDIATION ROADMAP ═══\x1b[0m\n\n');
    w(`    \x1b[1;31m24h\x1b[0m  ${(r2.priority_1_24h ?? []).join(', ') || '(none)'}\n`);
    w(`    \x1b[33m30d\x1b[0m  ${(r2.priority_2_30d ?? []).join(', ') || '(none)'}\n`);
    w(`    \x1b[36m90d\x1b[0m  ${(r2.priority_3_90d ?? []).join(', ') || '(none)'}\n\n`);
  }

  if (r.positive_findings) {
    w('  \x1b[1;32m═══ POSITIVE FINDINGS ═══\x1b[0m\n\n');
    w(`  ${r.positive_findings.replace(/\n/g, '\n  ')}\n\n`);
  }
}

export function buildReportCommand(): Command {
  const cmd = new Command('report');
  cmd.description('Generate AI-powered pentest report for an engagement');

  cmd
    .argument('<engagementId>', 'Engagement ID (e.g. ENG-001)')
    .option('--json',          'Output raw JSON instead of formatted report')
    .option('-o, --output <file>', 'Write report to file')
    .action(async (engagementId: string, opts: { json?: boolean; output?: string }) => {
      const s = requireAuth();

      // Verify engagement exists first for a clean error
      const listRes = await apiFetch(s, '/api/engagements').catch(() => null);
      if (!listRes?.ok) errExit('Could not reach server');
      const { engagements } = await listRes.json() as { engagements: Engagement[] };
      const eng = engagements.find((e) => e.id === engagementId);
      if (!eng) errExit(`Engagement not found: ${engagementId}`);

      process.stdout.write(`\n  \x1b[2mGenerating AI report for\x1b[0m \x1b[1m${eng.name}\x1b[0m \x1b[2m(${eng.findingCount} findings)…\x1b[0m\n`);
      process.stdout.write('  \x1b[2mThis may take 30–60 seconds.\x1b[0m\n');

      const res = await apiFetch(s, `/api/engagements/${engagementId}/ai-report`, {
        method: 'POST',
      }).catch(() => null);

      if (!res?.ok) {
        const err = (await res?.json().catch(() => ({})) as { error?: string }).error;
        errExit(err ?? 'Report generation failed');
      }

      const report = await res.json() as AiReport;

      if (opts.output) {
        const outPath = path.resolve(opts.output);
        fs.writeFileSync(outPath, JSON.stringify(report, null, 2));
        process.stdout.write(`\n  \x1b[1;32m✓\x1b[0m Report written to ${outPath}\n\n`);
        return;
      }

      if (opts.json) {
        process.stdout.write(JSON.stringify(report, null, 2) + '\n');
        return;
      }

      renderReport(report);
    });

  return cmd;
}
