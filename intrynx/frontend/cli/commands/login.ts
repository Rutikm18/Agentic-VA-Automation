import { Command }                    from 'commander';
import * as readline                  from 'readline';
import { saveSession, serverUrl, loadSession } from '../auth';

function prompt(question: string): Promise<string> {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer.trim());
    });
  });
}

function promptSilent(question: string): Promise<string> {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    process.stdout.write(question);
    // Disable echo for OTP entry
    (process.stdin as NodeJS.ReadStream).setRawMode?.(true);
    let input = '';
    process.stdin.resume();
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', function handler(char: string) {
      if (char === '\r' || char === '\n') {
        process.stdin.removeListener('data', handler);
        (process.stdin as NodeJS.ReadStream).setRawMode?.(false);
        process.stdout.write('\n');
        rl.close();
        resolve(input);
      } else if (char === '\x7f' || char === '\b') {
        if (input.length > 0) {
          input = input.slice(0, -1);
          process.stdout.write('\b \b');
        }
      } else if (char === '\x03') {
        process.exit();
      } else {
        input += char;
        process.stdout.write('*');
      }
    });
  });
}

export function buildLoginCommand(): Command {
  return new Command('login')
    .description('Authenticate with ADVERSA via email magic code')
    .action(async () => {
      const existing = loadSession();
      if (existing) {
        process.stdout.write(`\x1b[33mAlready logged in as \x1b[1m${existing.email}\x1b[0m\n`);
        process.stdout.write(`Run \x1b[1madversa logout\x1b[0m first to switch accounts.\n`);
        return;
      }

      const server = serverUrl();
      process.stdout.write(`\x1b[1;36mADVERSA\x1b[0m  ${server}\n\n`);

      const email = await prompt('Email: ');
      if (!email || !email.includes('@')) {
        process.stderr.write('\x1b[1;31m[ERR]\x1b[0m Invalid email\n');
        process.exit(1);
      }

      process.stdout.write('\x1b[2mRequesting code…\x1b[0m\n');

      let res = await fetch(`${server}/api/auth/request`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ email }),
      }).catch(() => null);

      if (!res?.ok) {
        process.stderr.write('\x1b[1;31m[ERR]\x1b[0m Could not reach the ADVERSA server.\n');
        process.stderr.write(`Server: ${server}\n`);
        process.exit(1);
      }

      const requestData = await res.json() as { dev?: boolean; otp?: string };

      if (requestData.dev && requestData.otp) {
        process.stdout.write(`\n\x1b[33m[DEV MODE]\x1b[0m OTP: \x1b[1;32m${requestData.otp}\x1b[0m\n\n`);
      } else {
        process.stdout.write(`\nCode sent to \x1b[1m${email}\x1b[0m — check your inbox.\n\n`);
      }

      const otp = await promptSilent('Enter code: ');
      if (!otp) {
        process.stderr.write('\x1b[1;31m[ERR]\x1b[0m No code entered\n');
        process.exit(1);
      }

      process.stdout.write('\x1b[2mVerifying…\x1b[0m\n');

      res = await fetch(`${server}/api/auth/verify`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ email, otp }),
      }).catch(() => null);

      const verifyData = await res?.json() as { token?: string; role?: string; error?: string } | undefined;

      if (!res?.ok || !verifyData?.token) {
        process.stderr.write(`\x1b[1;31m[ERR]\x1b[0m ${verifyData?.error ?? 'Authentication failed'}\n`);
        process.exit(1);
      }

      saveSession({
        email,
        token:   verifyData.token,
        role:    verifyData.role ?? 'operator',
        savedAt: new Date().toISOString(),
      });

      process.stdout.write(`\n\x1b[1;32m✓\x1b[0m Authenticated as \x1b[1m${email}\x1b[0m`);
      process.stdout.write(verifyData.role === 'admin' ? ' \x1b[36m[admin]\x1b[0m' : '');
      process.stdout.write('\n');
    });
}
