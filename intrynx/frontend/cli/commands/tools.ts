import { Command }              from 'commander';
import {
  installAll, installTool, removeTool, listStatus,
  managedPath, isManaged, getInstalledRecord,
}                                  from '../../lib/tools/installer';
import { TOOL_MANIFEST }           from '../../lib/tools/manifest';

const C = {
  reset:   '\x1b[0m', bold: '\x1b[1m', dim: '\x1b[2m',
  red:     '\x1b[1;31m', green: '\x1b[1;32m', yellow: '\x1b[33m',
  cyan:    '\x1b[1;36m', gray:  '\x1b[90m',
};
const w  = (s: string) => process.stdout.write(s);
const ln = (s = '')   => process.stdout.write(s + '\n');

function showSpinner(msg: string): () => void {
  if (!process.stdout.isTTY) {
    ln(`  ${msg}…`);
    return () => undefined;
  }
  const frames = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
  let i = 0;
  const handle = setInterval(() => {
    w(`\r  ${C.cyan}${frames[i = (i + 1) % frames.length]}${C.reset} ${msg}`);
  }, 80);
  return () => { clearInterval(handle); w(`\r${' '.repeat(80)}\r`); };
}

export function buildToolsCommand(): Command {
  const cmd = new Command('tools');
  cmd.description('Manage bundled scanner binaries (~/.adversa/tools/)');

  // ── status ─────────────────────────────────────────────────────
  cmd
    .command('status', { isDefault: true })
    .description('Show installed tools and pinned versions')
    .option('--json', 'Output machine-readable JSON')
    .action((opts: { json?: boolean }) => {
      const status = listStatus();
      if (opts.json) {
        ln(JSON.stringify(status, null, 2));
        return;
      }
      ln();
      ln(`  ${C.bold}ADVERSA bundled scanner tools${C.reset}`);
      ln(`  ${C.gray}${'─'.repeat(72)}${C.reset}`);
      ln(`  ${'TOOL'.padEnd(12)} ${'STATUS'.padEnd(14)} ${'INSTALLED'.padEnd(11)} ${'PINNED'.padEnd(11)} DESCRIPTION`);
      ln(`  ${C.gray}${'─'.repeat(72)}${C.reset}`);
      for (const s of status) {
        const symbol = s.installed
          ? (s.upToDate ? `${C.green}✓ ok${C.reset}` : `${C.yellow}! stale${C.reset}`)
          : `${C.red}✗ missing${C.reset}`;
        const installed = s.installedVersion ?? '—';
        const desc = s.description.length > 30 ? s.description.slice(0, 29) + '…' : s.description;
        const symLen = s.installed ? (s.upToDate ? 4 : 7) : 9;
        ln(`  ${s.id.padEnd(12)} ${symbol.padEnd(14 + (symbol.length - symLen))} ${installed.padEnd(11)} ${s.pinnedVersion.padEnd(11)} ${C.dim}${desc}${C.reset}`);
      }
      ln();
      const total = status.length;
      const ok = status.filter((s) => s.upToDate).length;
      const stale = status.filter((s) => s.installed && !s.upToDate).length;
      const missing = total - ok - stale;
      ln(`  ${ok} up to date  ·  ${stale} stale  ·  ${missing} missing`);
      if (missing + stale > 0) {
        ln(`  ${C.cyan}Run \`adversa tools install\` to install / update${C.reset}`);
      }
      ln();
    });

  // ── install ────────────────────────────────────────────────────
  cmd
    .command('install [tool]')
    .description('Download missing tools (or just one named tool)')
    .action(async (target?: string) => {
      ln();
      ln(`  ${C.bold}Installing scanner tools into ~/.adversa/tools/${C.reset}`);
      ln(`  ${C.dim}Source: official upstream GitHub releases${C.reset}`);
      ln();

      if (target) {
        const tool = TOOL_MANIFEST.find((t) => t.id === target);
        if (!tool) {
          ln(`  ${C.red}Unknown tool: ${target}${C.reset}`);
          ln(`  Available: ${TOOL_MANIFEST.map((t) => t.id).join(', ')}`);
          process.exit(1);
        }
        const stop = showSpinner(`Installing ${tool.id} ${tool.version}`);
        try {
          await installTool(target, {
            onWarn: (msg) => ln(`  ${C.yellow}!${C.reset} ${msg}`),
          });
          stop();
          ln(`  ${C.green}✓${C.reset} ${tool.id} ${tool.version} installed`);
        } catch (e) {
          stop();
          ln(`  ${C.red}✗${C.reset} ${tool.id}: ${e instanceof Error ? e.message : String(e)}`);
          process.exit(1);
        }
        return;
      }

      // Install all
      let currentTool = '';
      const stop = showSpinner('Preparing');
      const result = await installAll({
        onTool:     (t) => { currentTool = t.id; stop(); ln(`  ${C.cyan}▶${C.reset} ${t.id} ${C.dim}${t.version}${C.reset}`); },
        onPhase:    (phase) => {
          if (phase === 'download') process.stdout.write(`    ${C.dim}downloading…${C.reset} `);
          if (phase === 'verify')   process.stdout.write(`${C.dim}verifying… ${C.reset}`);
          if (phase === 'extract')  process.stdout.write(`${C.dim}extracting… ${C.reset}`);
          if (phase === 'done')     ln(`${C.green}done${C.reset}`);
        },
        onDownload: (pct) => process.stdout.write(`\r    ${C.dim}downloading… ${pct}%${C.reset}    `),
        onWarn:     (msg) => ln(`    ${C.yellow}!${C.reset} ${msg}`),
      });
      stop();

      ln();
      ln(`  ${C.bold}Summary${C.reset}`);
      ln(`  ${C.green}✓${C.reset} ${result.installed.length} installed: ${result.installed.join(', ') || '(none)'}`);
      if (result.skipped.length)  ln(`  ${C.dim}·${C.reset} ${result.skipped.length} skipped (already up to date): ${result.skipped.join(', ')}`);
      if (result.failed.length) {
        ln(`  ${C.red}✗${C.reset} ${result.failed.length} failed:`);
        for (const f of result.failed) ln(`     ${f.id}: ${f.error}`);
      }
      ln();
      if (result.failed.length === 0) {
        ln(`  ${C.green}Tools installed.${C.reset}  Run \`./run.sh app\` to start scanning.`);
      }
      ln();
      process.exit(result.failed.length > 0 ? 1 : 0);
    });

  // ── update — same as install but force re-install if version changed
  cmd
    .command('update')
    .description('Update all tools to currently-pinned versions')
    .action(async () => {
      ln();
      ln(`  ${C.dim}Updating to pinned versions defined in lib/tools/manifest.ts${C.reset}`);
      ln();

      // Remove stale ones first, then install all
      const status = listStatus();
      for (const s of status) {
        if (s.installed && !s.upToDate) {
          removeTool(s.id);
          ln(`  ${C.dim}Removed stale ${s.id} ${s.installedVersion}${C.reset}`);
        }
      }

      const stop = showSpinner('Updating');
      const result = await installAll({
        onTool:  (t) => { stop(); ln(`  ${C.cyan}▶${C.reset} ${t.id} → ${t.version}`); },
        onPhase: (phase) => { if (phase === 'done') ln(`    ${C.green}✓${C.reset}`); },
        onWarn:  (msg) => ln(`    ${C.yellow}!${C.reset} ${msg}`),
      });
      stop();
      ln();
      ln(`  ${result.installed.length} updated · ${result.skipped.length} already current · ${result.failed.length} failed`);
      ln();
      process.exit(result.failed.length > 0 ? 1 : 0);
    });

  // ── remove
  cmd
    .command('remove <tool>')
    .description('Remove one tool from ~/.adversa/tools/')
    .action((target: string) => {
      const ok = removeTool(target);
      if (ok) {
        ln(`  ${C.green}✓${C.reset} Removed ${target}`);
      } else {
        ln(`  ${C.red}✗${C.reset} ${target} was not installed under ADVERSA management`);
        process.exit(1);
      }
    });

  // ── path — for shell scripts / debugging
  cmd
    .command('path <tool>')
    .description('Print the managed path for a tool (empty if not installed)')
    .action((target: string) => {
      if (isManaged(target)) ln(managedPath(target));
      else process.exit(1);
    });

  return cmd;
}
