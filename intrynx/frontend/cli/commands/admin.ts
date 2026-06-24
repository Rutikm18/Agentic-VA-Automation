import { Command }             from 'commander';
import { requireAuth, apiFetch } from '../auth';
import type { PermittedUser }  from '../../lib/permissions-store';

const c = {
  bold:  (s: string) => `\x1b[1m${s}\x1b[0m`,
  cyan:  (s: string) => `\x1b[36m${s}\x1b[0m`,
  green: (s: string) => `\x1b[32m${s}\x1b[0m`,
  red:   (s: string) => `\x1b[31m${s}\x1b[0m`,
  dim:   (s: string) => `\x1b[2m${s}\x1b[0m`,
};

export function buildAdminCommand(): Command {
  const admin = new Command('admin').description('User & permission management (admin only)');

  // adversa admin list-users
  admin
    .command('list-users')
    .description('List all permitted users')
    .action(async () => {
      const s   = requireAuth();
      const res = await apiFetch(s, '/api/admin/users').catch(() => null);
      if (!res?.ok) {
        const err = (await res?.json().catch(() => ({})) as { error?: string }).error;
        process.stderr.write(`\x1b[1;31m[ERR]\x1b[0m ${err ?? 'Failed'}\n`);
        process.exit(1);
      }
      const users = await res.json() as PermittedUser[];
      if (users.length === 0) {
        process.stdout.write('No users.\n');
        return;
      }
      process.stdout.write(`\n  ${'EMAIL'.padEnd(36)} ${'ROLE'.padEnd(10)} SCOPES\n`);
      process.stdout.write(`  ${'─'.repeat(70)}\n`);
      for (const u of users) {
        const role  = u.role === 'admin' ? c.cyan(u.role.padEnd(10)) : u.role.padEnd(10);
        const scope = u.allowedScopes.length > 0 ? u.allowedScopes.join(', ') : c.dim('none');
        process.stdout.write(`  ${u.email.padEnd(36)} ${role} ${scope}\n`);
      }
      process.stdout.write('\n');
    });

  // adversa admin add-user <email> [--scope cidr,cidr] [--role operator|admin]
  admin
    .command('add-user <email>')
    .description('Add a user and set their allowed scan scope')
    .option('--scope <cidrs>', 'Comma-separated CIDRs or IPs the user may scan')
    .option('--role <role>',   'operator (default) or admin', 'operator')
    .action(async (email: string, opts: { scope?: string; role?: string }) => {
      const s      = requireAuth();
      const scopes = opts.scope ? opts.scope.split(',').map((x) => x.trim()).filter(Boolean) : [];
      const res    = await apiFetch(s, '/api/admin/users', {
        method: 'POST',
        body:   JSON.stringify({ email, role: opts.role ?? 'operator', allowedScopes: scopes }),
      }).catch(() => null);

      const data = await res?.json().catch(() => ({})) as { email?: string; error?: string };
      if (!res?.ok) {
        process.stderr.write(`\x1b[1;31m[ERR]\x1b[0m ${data?.error ?? 'Failed'}\n`);
        process.exit(1);
      }
      process.stdout.write(`${c.green('✓')} Added ${c.bold(data.email ?? email)}`);
      if (scopes.length > 0) process.stdout.write(` scope: ${scopes.join(', ')}`);
      process.stdout.write('\n');
    });

  // adversa admin set-scope <email> --scope cidr,cidr
  admin
    .command('set-scope <email>')
    .description("Update a user's allowed scan scope")
    .requiredOption('--scope <cidrs>', 'Comma-separated CIDRs or IPs')
    .action(async (email: string, opts: { scope: string }) => {
      const s      = requireAuth();
      const scopes = opts.scope.split(',').map((x) => x.trim()).filter(Boolean);
      const res    = await apiFetch(s, `/api/admin/users/${encodeURIComponent(email)}`, {
        method: 'PUT',
        body:   JSON.stringify({ allowedScopes: scopes }),
      }).catch(() => null);

      const data = await res?.json().catch(() => ({})) as { error?: string };
      if (!res?.ok) {
        process.stderr.write(`\x1b[1;31m[ERR]\x1b[0m ${data?.error ?? 'Failed'}\n`);
        process.exit(1);
      }
      process.stdout.write(`${c.green('✓')} Scope updated for ${c.bold(email)}: ${scopes.join(', ')}\n`);
    });

  // adversa admin remove-user <email>
  admin
    .command('remove-user <email>')
    .description('Remove a user')
    .action(async (email: string) => {
      const s   = requireAuth();
      const res = await apiFetch(s, `/api/admin/users/${encodeURIComponent(email)}`, {
        method: 'DELETE',
      }).catch(() => null);

      const data = await res?.json().catch(() => ({})) as { error?: string };
      if (!res?.ok) {
        process.stderr.write(`\x1b[1;31m[ERR]\x1b[0m ${data?.error ?? 'Failed'}\n`);
        process.exit(1);
      }
      process.stdout.write(`${c.green('✓')} Removed ${c.bold(email)}\n`);
    });

  return admin;
}
