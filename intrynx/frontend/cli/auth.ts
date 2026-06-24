import fs   from 'fs';
import path from 'path';
import os   from 'os';

const SESSION_DIR  = path.join(os.homedir(), '.adversa');
const SESSION_FILE = path.join(SESSION_DIR, 'session.json');

export interface Session {
  email:     string;
  token:     string;
  role:      string;
  savedAt:   string;
}

export function loadSession(): Session | null {
  try {
    if (!fs.existsSync(SESSION_FILE)) return null;
    return JSON.parse(fs.readFileSync(SESSION_FILE, 'utf-8')) as Session;
  } catch {
    return null;
  }
}

export function saveSession(session: Session): void {
  if (!fs.existsSync(SESSION_DIR)) fs.mkdirSync(SESSION_DIR, { recursive: true, mode: 0o700 });
  fs.writeFileSync(SESSION_FILE, JSON.stringify(session, null, 2), { mode: 0o600 });
}

export function clearSession(): void {
  try { fs.unlinkSync(SESSION_FILE); } catch { /* already gone */ }
}

export function requireAuth(): Session {
  const s = loadSession();
  if (!s) {
    process.stderr.write('\x1b[1;31m[ERR]\x1b[0m Not authenticated. Run: adversa login\n');
    process.exit(1);
  }
  return s;
}

export function serverUrl(): string {
  return process.env.ADVERSA_SERVER ?? 'http://localhost:3000';
}

export async function apiFetch(
  session: Session,
  endpoint: string,
  opts?: RequestInit,
): Promise<Response> {
  return fetch(`${serverUrl()}${endpoint}`, {
    ...opts,
    headers: {
      'Content-Type':  'application/json',
      'Authorization': `Bearer ${session.token}`,
      ...(opts?.headers ?? {}),
    },
  });
}
