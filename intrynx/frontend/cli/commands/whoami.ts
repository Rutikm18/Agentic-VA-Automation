import { Command }             from 'commander';
import { requireAuth, apiFetch } from '../auth';

export function buildWhoamiCommand(): Command {
  return new Command('whoami')
    .description('Show currently authenticated user')
    .action(async () => {
      const s = requireAuth();
      const res = await apiFetch(s, '/api/auth/me').catch(() => null);
      if (!res?.ok) {
        process.stderr.write('\x1b[1;31m[ERR]\x1b[0m Session invalid or server unreachable. Run: adversa login\n');
        process.exit(1);
      }
      const data = await res.json() as { email: string; role: string; allowedScopes: string[] };
      process.stdout.write(`\x1b[1m${data.email}\x1b[0m`);
      if (data.role === 'admin') process.stdout.write(' \x1b[36m[admin]\x1b[0m');
      process.stdout.write('\n');
      if (data.allowedScopes.length > 0) {
        process.stdout.write(`Scopes: ${data.allowedScopes.join(', ')}\n`);
      } else if (data.role !== 'admin') {
        process.stdout.write('\x1b[33mNo scopes assigned. Ask an admin: adversa admin add-user\x1b[0m\n');
      } else {
        process.stdout.write('Scopes: \x1b[36mall (admin)\x1b[0m\n');
      }
    });
}
