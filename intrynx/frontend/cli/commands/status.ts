import { Command }             from 'commander';
import { requireAuth, apiFetch } from '../auth';

interface ScanRow {
  scanId:    string;
  status:    string;
  targets:   string[];
  profile:   string;
  createdAt: string;
  operator:  string;
}

const STATUS_COLOR: Record<string, string> = {
  PENDING:    '\x1b[33m',
  DISPATCHED: '\x1b[36m',
  RUNNING:    '\x1b[1;36m',
  COMPLETE:   '\x1b[32m',
  FAILED:     '\x1b[31m',
};

export function buildStatusCommand(): Command {
  return new Command('status')
    .description('List recent scans and their status')
    .action(async () => {
      const s   = requireAuth();
      const res = await apiFetch(s, '/api/scans/list').catch(() => null);

      if (!res?.ok) {
        const err = (await res?.json().catch(() => ({})) as { error?: string }).error;
        process.stderr.write(`\x1b[1;31m[ERR]\x1b[0m ${err ?? 'Could not reach server'}\n`);
        process.exit(1);
      }

      const scans = await res.json() as ScanRow[];
      if (scans.length === 0) {
        process.stdout.write('No scans found.\n');
        return;
      }

      process.stdout.write(`\n  ${'SCAN ID'.padEnd(30)} ${'STATUS'.padEnd(12)} ${'PROFILE'.padEnd(10)} TARGETS\n`);
      process.stdout.write(`  ${'─'.repeat(75)}\n`);

      for (const scan of scans) {
        const color  = STATUS_COLOR[scan.status] ?? '';
        const status = `${color}${scan.status}\x1b[0m`.padEnd(12 + color.length + 4);
        const date   = new Date(scan.createdAt).toLocaleString();
        const tgts   = (scan.targets ?? []).slice(0, 2).join(', ') + ((scan.targets?.length ?? 0) > 2 ? '…' : '');
        process.stdout.write(`  ${scan.scanId.padEnd(30)} ${status} ${(scan.profile ?? '').padEnd(10)} ${tgts}\n`);
        process.stdout.write(`  ${''.padEnd(30)} \x1b[2m${date}\x1b[0m\n`);
      }
      process.stdout.write('\n');
    });
}
