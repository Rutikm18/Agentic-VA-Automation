import { Command }              from 'commander';
import { requireAuth, apiFetch } from '../auth';

interface Engagement {
  id:                 string;
  name:               string;
  client:             string;
  status:             string;
  startDate:          string;
  endDate:            string;
  scopeCidrs:         string[];
  excludedCidrs:      string[];
  assessor:           string;
  assetCount:         number;
  findingCount:       number;
  findingsBySeverity: { CRITICAL: number; HIGH: number; MEDIUM: number; LOW: number };
  progress:           number;
  createdAt:          string;
  description?:       string;
  tags:               string[];
}

const STATUS_COLOR: Record<string, string> = {
  PLANNING:  '\x1b[33m',
  ACTIVE:    '\x1b[1;36m',
  PAUSED:    '\x1b[90m',
  COMPLETED: '\x1b[32m',
  ARCHIVED:  '\x1b[2m',
};

function errExit(msg: string): never {
  process.stderr.write(`\x1b[1;31m[ERR]\x1b[0m ${msg}\n`);
  process.exit(1);
}

export function buildEngagementCommand(): Command {
  const cmd = new Command('engagement');
  cmd.alias('eng').description('Manage VAPT engagements');

  /* ── list ─────────────────────────────────────────────────── */
  cmd
    .command('list', { isDefault: true })
    .description('List all engagements')
    .option('--json', 'Output raw JSON')
    .action(async (opts: { json?: boolean }) => {
      const s   = requireAuth();
      const res = await apiFetch(s, '/api/engagements').catch(() => null);
      if (!res?.ok) {
        const err = (await res?.json().catch(() => ({})) as { error?: string }).error;
        errExit(err ?? 'Could not reach server');
      }
      const data = await res.json() as {
        engagements: Engagement[];
        stats: { totalFindings: number; activeEngagements: number; totalAssets: number };
      };

      if (opts.json) {
        process.stdout.write(JSON.stringify(data, null, 2) + '\n');
        return;
      }

      const { engagements, stats } = data;
      process.stdout.write(`\n  \x1b[1mEngagements\x1b[0m  ·  ${engagements.length} total  ·  ${stats.activeEngagements} active  ·  ${stats.totalFindings} findings\n`);
      process.stdout.write(`  ${'─'.repeat(78)}\n`);
      process.stdout.write(`  ${'ID'.padEnd(10)} ${'STATUS'.padEnd(11)} ${'CLIENT'.padEnd(28)} ${'FINDINGS'.padEnd(10)} PROGRESS\n`);
      process.stdout.write(`  ${'─'.repeat(78)}\n`);

      for (const e of engagements) {
        const color  = STATUS_COLOR[e.status] ?? '';
        const status = `${color}${e.status}\x1b[0m`.padEnd(11 + (color ? 8 : 0));
        const client = (e.client.length > 26 ? e.client.slice(0, 25) + '…' : e.client).padEnd(28);
        const bs     = e.findingsBySeverity;
        const finds  = `\x1b[1;31m${bs.CRITICAL ?? 0}\x1b[0m·\x1b[31m${bs.HIGH ?? 0}\x1b[0m·\x1b[33m${bs.MEDIUM ?? 0}\x1b[0m·\x1b[36m${bs.LOW ?? 0}\x1b[0m`;
        process.stdout.write(`  ${e.id.padEnd(10)} ${status} ${client} ${finds.padEnd(10 + 24)} ${e.progress}%\n`);
        process.stdout.write(`  ${''.padEnd(10)} \x1b[2m${e.name}\x1b[0m\n`);
      }
      process.stdout.write('\n');
    });

  /* ── show ─────────────────────────────────────────────────── */
  cmd
    .command('show <id>')
    .description('Show engagement detail')
    .action(async (id: string) => {
      const s   = requireAuth();
      const res = await apiFetch(s, '/api/engagements').catch(() => null);
      if (!res?.ok) errExit('Could not reach server');
      const { engagements } = await res.json() as { engagements: Engagement[] };
      const e = engagements.find((x) => x.id === id);
      if (!e) errExit(`Engagement not found: ${id}`);

      process.stdout.write(`\n  \x1b[1m${e.name}\x1b[0m  ·  ${e.id}\n`);
      process.stdout.write(`  ${'─'.repeat(68)}\n`);
      process.stdout.write(`  Client       ${e.client}\n`);
      process.stdout.write(`  Status       ${(STATUS_COLOR[e.status] ?? '') + e.status}\x1b[0m\n`);
      process.stdout.write(`  Assessor     ${e.assessor}\n`);
      process.stdout.write(`  Window       ${e.startDate} → ${e.endDate}\n`);
      process.stdout.write(`  Progress     ${e.progress}%\n`);
      process.stdout.write(`  Assets       ${e.assetCount}\n`);
      process.stdout.write(`  Findings     ${e.findingCount}  (C:${e.findingsBySeverity.CRITICAL}  H:${e.findingsBySeverity.HIGH}  M:${e.findingsBySeverity.MEDIUM}  L:${e.findingsBySeverity.LOW})\n`);
      if (e.scopeCidrs.length) {
        process.stdout.write(`  Scope        ${e.scopeCidrs.join(', ')}\n`);
      }
      if (e.excludedCidrs.length) {
        process.stdout.write(`  Excluded     ${e.excludedCidrs.join(', ')}\n`);
      }
      if (e.description) {
        process.stdout.write(`\n  \x1b[2m${e.description}\x1b[0m\n`);
      }
      process.stdout.write('\n');
    });

  /* ── create ───────────────────────────────────────────────── */
  cmd
    .command('create')
    .description('Create a new engagement')
    .requiredOption('--name <name>',       'Engagement name')
    .requiredOption('--client <client>',   'Client / organization name')
    .requiredOption('--start <YYYY-MM-DD>', 'Start date')
    .requiredOption('--end <YYYY-MM-DD>',   'End date')
    .option('--scope <cidrs>',     'Comma-separated CIDRs in scope')
    .option('--exclude <cidrs>',   'Comma-separated CIDRs excluded')
    .option('--description <text>', 'Free-text description')
    .action(async (opts: {
      name: string; client: string; start: string; end: string;
      scope?: string; exclude?: string; description?: string;
    }) => {
      const s = requireAuth();
      const body = {
        name:          opts.name,
        client:        opts.client,
        startDate:     opts.start,
        endDate:       opts.end,
        scopeCidrs:    opts.scope    ? opts.scope.split(',').map((x) => x.trim()).filter(Boolean) : [],
        excludedCidrs: opts.exclude  ? opts.exclude.split(',').map((x) => x.trim()).filter(Boolean) : [],
        description:   opts.description,
        assessor:      s.email,
      };
      const res = await apiFetch(s, '/api/engagements', {
        method: 'POST',
        body:   JSON.stringify(body),
      }).catch(() => null);

      if (!res?.ok) {
        const err = (await res?.json().catch(() => ({})) as { error?: string }).error;
        errExit(err ?? 'Could not create engagement');
      }
      const { engagement } = await res.json() as { engagement: Engagement };
      process.stdout.write(`\n  \x1b[1;32m✓\x1b[0m Created engagement \x1b[1m${engagement.id}\x1b[0m\n`);
      process.stdout.write(`    ${engagement.name}  ·  ${engagement.client}\n\n`);
    });

  return cmd;
}
