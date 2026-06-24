import fs   from 'fs';
import path from 'path';

const DATA_PATH = path.join(process.cwd(), 'data', 'permissions.json');

export type UserRole = 'admin' | 'operator';

export interface PermittedUser {
  email:         string;
  role:          UserRole;
  allowedScopes: string[];   // CIDRs + individual IPs/hostnames
  addedAt:       string;
  addedBy:       string;
}

interface PermissionsFile {
  users: PermittedUser[];
}

function ensureDir(): void {
  const dir = path.dirname(DATA_PATH);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

function read(): PermissionsFile {
  ensureDir();
  if (!fs.existsSync(DATA_PATH)) return { users: [] };
  try {
    return JSON.parse(fs.readFileSync(DATA_PATH, 'utf-8')) as PermissionsFile;
  } catch {
    return { users: [] };
  }
}

function write(data: PermissionsFile): void {
  ensureDir();
  fs.writeFileSync(DATA_PATH, JSON.stringify(data, null, 2));
}

export function getAllUsers(): PermittedUser[] {
  return read().users;
}

export function getUser(email: string): PermittedUser | undefined {
  return read().users.find((u) => u.email === email.toLowerCase());
}

export function isEmailAllowed(email: string): boolean {
  const data = read();
  // First ever user becomes admin automatically
  if (data.users.length === 0) return true;
  return data.users.some((u) => u.email === email.toLowerCase());
}

export function isAdmin(email: string): boolean {
  const user = getUser(email);
  return user?.role === 'admin';
}

export function addUser(
  email:         string,
  role:          UserRole,
  allowedScopes: string[],
  addedBy:       string,
): PermittedUser {
  const data = read();
  const key  = email.toLowerCase();
  const existing = data.users.findIndex((u) => u.email === key);

  const user: PermittedUser = {
    email:         key,
    role,
    allowedScopes,
    addedAt:       new Date().toISOString(),
    addedBy:       addedBy.toLowerCase(),
  };

  if (existing >= 0) {
    data.users[existing] = user;
  } else {
    data.users.push(user);
  }

  // First user ever is always admin
  if (data.users.length === 1) user.role = 'admin';

  write(data);
  return user;
}

export function removeUser(email: string): boolean {
  const data = read();
  const before = data.users.length;
  data.users = data.users.filter((u) => u.email !== email.toLowerCase());
  if (data.users.length === before) return false;
  write(data);
  return true;
}

export function updateScopes(email: string, allowedScopes: string[]): boolean {
  const data = read();
  const user = data.users.find((u) => u.email === email.toLowerCase());
  if (!user) return false;
  user.allowedScopes = allowedScopes;
  write(data);
  return true;
}

export function isScopeAllowed(email: string, target: string): boolean {
  const data = read();
  // First user (no users yet) or admin → all scopes allowed
  if (data.users.length === 0) return true;
  const user = getUser(email);
  if (!user) return false;
  if (user.role === 'admin') return true;
  // Check if target starts with or is contained in any allowed scope
  return user.allowedScopes.some((s) => targetMatchesScope(target, s));
}

function ipToInt(ip: string): number {
  return ip.split('.').reduce((acc, octet) => (acc * 256) + Number(octet), 0) >>> 0;
}

function targetMatchesScope(target: string, scope: string): boolean {
  if (target === scope) return true;

  // scope is a CIDR — check if the target IP/CIDR's base address falls inside
  if (scope.includes('/')) {
    const [netAddr, prefixStr] = scope.split('/');
    const prefix = Number(prefixStr);
    if (isNaN(prefix) || prefix < 0 || prefix > 32) return false;

    const mask    = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
    const netInt  = ipToInt(netAddr) & mask;

    // target may itself be a CIDR (e.g. user scanned 10.0.0.0/24) — use base address
    const targetIp = target.includes('/') ? target.split('/')[0] : target;
    if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(targetIp)) return false;

    const targetInt = ipToInt(targetIp) >>> 0;
    return (targetInt & mask) === netInt;
  }

  return false;
}
