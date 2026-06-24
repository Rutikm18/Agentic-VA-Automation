import { Command }              from 'commander';
import { clearSession, loadSession } from '../auth';

export function buildLogoutCommand(): Command {
  return new Command('logout')
    .description('Clear your ADVERSA session')
    .action(() => {
      const s = loadSession();
      if (!s) {
        process.stdout.write('Not logged in.\n');
        return;
      }
      clearSession();
      process.stdout.write(`\x1b[1;32m✓\x1b[0m Logged out (${s.email})\n`);
    });
}
