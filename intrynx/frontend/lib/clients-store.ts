import fs from "fs";
import path from "path";

const DATA_PATH = path.join(process.cwd(), "data", "clients.json");

export type ClientStatus = "ACTIVE" | "SUSPENDED" | "ARCHIVED";

export interface ClientJiraConfig {
  baseUrl?: string;
  projectKey?: string;
  email?: string;
  apiToken?: string;       // stored server-side only; never sent to the browser
}

export interface ClientNotifyConfig {
  emails?: string[];       // recipients for notifications
  onNewCritical?: boolean;
  onStatusChange?: boolean;
}

export interface ClientSettings {
  branding?: { displayName?: string; accent?: string };
  jira?: ClientJiraConfig;
  notify?: ClientNotifyConfig;
}

export interface Client {
  id: string;
  subdomain: string;        // tenant key, e.g. "acme" → acme.<root>
  name: string;
  status: ClientStatus;
  createdAt: string;
  settings: ClientSettings;
}

interface ClientsFile {
  clients: Client[];
}

// Seeded from the existing engagement client strings so the portal has tenants on first run.
const SEED: Client[] = [
  { id: "C-ACME",   subdomain: "acme",   name: "ACME Corporation", status: "ACTIVE", createdAt: "2026-05-01T00:00:00Z", settings: {} },
  { id: "C-GLOBEX", subdomain: "globex", name: "Globex Financial", status: "ACTIVE", createdAt: "2026-05-05T00:00:00Z", settings: {} },
  { id: "C-TECHCORP", subdomain: "techcorp", name: "TechCorp Inc.", status: "ARCHIVED", createdAt: "2026-04-01T00:00:00Z", settings: {} },
];

function ensureDir(): void {
  const dir = path.dirname(DATA_PATH);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

function read(): ClientsFile {
  ensureDir();
  if (!fs.existsSync(DATA_PATH)) {
    const seeded: ClientsFile = { clients: SEED };
    write(seeded);
    return seeded;
  }
  try {
    return JSON.parse(fs.readFileSync(DATA_PATH, "utf-8")) as ClientsFile;
  } catch {
    return { clients: [] };
  }
}

function write(data: ClientsFile): void {
  ensureDir();
  fs.writeFileSync(DATA_PATH, JSON.stringify(data, null, 2));
}

const slugify = (s: string): string =>
  s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 40);

export function listClients(): Client[] {
  return read().clients;
}

export function getClient(id: string): Client | undefined {
  return read().clients.find((c) => c.id === id);
}

export function getClientBySubdomain(subdomain: string): Client | undefined {
  const sub = subdomain.toLowerCase();
  return read().clients.find((c) => c.subdomain === sub);
}

export function createClient(name: string, subdomain?: string): Client {
  const data = read();
  const sub = slugify(subdomain || name);
  if (!sub) throw new Error("invalid subdomain");
  if (data.clients.some((c) => c.subdomain === sub)) throw new Error(`subdomain '${sub}' already in use`);
  const client: Client = {
    id: "C-" + sub.toUpperCase().replace(/-/g, "_"),
    subdomain: sub,
    name,
    status: "ACTIVE",
    createdAt: new Date().toISOString(),
    settings: {},
  };
  data.clients.push(client);
  write(data);
  return client;
}

export function updateClient(id: string, patch: Partial<Omit<Client, "id" | "createdAt">>): Client | null {
  const data = read();
  const c = data.clients.find((x) => x.id === id);
  if (!c) return null;
  if (patch.subdomain) patch.subdomain = slugify(patch.subdomain);
  Object.assign(c, patch);
  write(data);
  return c;
}

/** Merge a partial settings patch (deep-ish for the known keys). */
export function updateClientSettings(id: string, settings: Partial<ClientSettings>): Client | null {
  const data = read();
  const c = data.clients.find((x) => x.id === id);
  if (!c) return null;
  c.settings = {
    ...c.settings,
    ...settings,
    jira: settings.jira ? { ...c.settings.jira, ...settings.jira } : c.settings.jira,
    notify: settings.notify ? { ...c.settings.notify, ...settings.notify } : c.settings.notify,
    branding: settings.branding ? { ...c.settings.branding, ...settings.branding } : c.settings.branding,
  };
  write(data);
  return c;
}
