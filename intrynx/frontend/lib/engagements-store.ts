export type EngagementStatus = "PLANNING" | "ACTIVE" | "PAUSED" | "COMPLETED" | "ARCHIVED";

export interface Credential {
  type: "ssh" | "winrm" | "domain" | "api";
  label: string;
  username?: string;
  vaultRef: string;
}

export interface Engagement {
  id: string;
  name: string;
  client: string;
  clientId: string;        // tenant FK → clients-store (Client.id)
  status: EngagementStatus;
  startDate: string;
  endDate: string;
  scopeCidrs: string[];
  excludedCidrs: string[];
  credentials: Credential[];
  assessor: string;
  assetCount: number;
  findingCount: number;
  findingsBySeverity: { CRITICAL: number; HIGH: number; MEDIUM: number; LOW: number };
  progress: number;
  createdAt: string;
  updatedAt: string;
  description?: string;
  tags: string[];
}

function genId() { return Math.random().toString(36).slice(2, 9).toUpperCase(); }

const STORE: Engagement[] = [
  {
    id: "ENG-001",
    name: "ACME Corp — Q2 VAPT",
    client: "ACME Corporation",
    clientId: "C-ACME",
    status: "ACTIVE",
    startDate: "2026-05-10",
    endDate: "2026-05-24",
    scopeCidrs: ["10.0.0.0/8", "192.168.1.0/24", "172.16.0.0/12"],
    excludedCidrs: ["10.0.0.1", "172.16.0.1"],
    credentials: [{ type: "domain", label: "corp.local standard user", username: "pentest@corp.local", vaultRef: "vault/eng-001/domain" }],
    assessor: "analyst@adversa.io",
    assetCount: 317,
    findingCount: 14,
    findingsBySeverity: { CRITICAL: 3, HIGH: 4, MEDIUM: 5, LOW: 2 },
    progress: 72,
    createdAt: "2026-05-09T08:00:00Z",
    updatedAt: "2026-05-20T14:30:00Z",
    description: "Full-scope network VAPT including AD assessment, lateral movement, and detection validation.",
    tags: ["ad", "network", "red-team"],
  },
  {
    id: "ENG-002",
    name: "Globex Financial — AD Red Team",
    client: "Globex Financial",
    clientId: "C-GLOBEX",
    status: "PLANNING",
    startDate: "2026-06-03",
    endDate: "2026-06-14",
    scopeCidrs: ["172.20.0.0/16"],
    excludedCidrs: ["172.20.0.1"],
    credentials: [],
    assessor: "analyst@adversa.io",
    assetCount: 0,
    findingCount: 0,
    findingsBySeverity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 },
    progress: 0,
    createdAt: "2026-05-18T10:00:00Z",
    updatedAt: "2026-05-18T10:00:00Z",
    tags: ["ad", "financial"],
  },
  {
    id: "ENG-003",
    name: "TechCorp — Cloud Infra Review",
    client: "TechCorp Inc.",
    clientId: "C-TECHCORP",
    status: "COMPLETED",
    startDate: "2026-04-01",
    endDate: "2026-04-15",
    scopeCidrs: ["10.100.0.0/16"],
    excludedCidrs: [],
    credentials: [{ type: "api", label: "AWS IAM read-only", vaultRef: "vault/eng-003/aws" }],
    assessor: "analyst@adversa.io",
    assetCount: 89,
    findingCount: 9,
    findingsBySeverity: { CRITICAL: 1, HIGH: 3, MEDIUM: 4, LOW: 1 },
    progress: 100,
    createdAt: "2026-03-28T09:00:00Z",
    updatedAt: "2026-04-16T17:00:00Z",
    tags: ["cloud", "aws"],
  },
];

const ACTIVITY: { id: string; engagementId: string; timestamp: string; actor: string; action: string; detail: string }[] = [
  { id: "A1", engagementId: "ENG-001", timestamp: "2026-05-20T14:30:00Z", actor: "analyst", action: "FINDING_CREATED",  detail: "Added AD CS ESC8 finding (CRITICAL)" },
  { id: "A2", engagementId: "ENG-001", timestamp: "2026-05-20T13:10:00Z", actor: "analyst", action: "EXPLOIT_VALIDATED", detail: "Confirmed CVE-2021-44228 on WEB-01" },
  { id: "A3", engagementId: "ENG-001", timestamp: "2026-05-20T11:45:00Z", actor: "manager", action: "REPORT_APPROVED",   detail: "Executive summary approved" },
  { id: "A4", engagementId: "ENG-001", timestamp: "2026-05-20T09:05:00Z", actor: "analyst", action: "SCAN_COMPLETED",    detail: "Nmap deep scan: 317 hosts, 1203 open ports" },
  { id: "A5", engagementId: "ENG-002", timestamp: "2026-05-18T10:00:00Z", actor: "manager", action: "ENG_CREATED",       detail: "Globex Financial engagement created" },
  { id: "A6", engagementId: "ENG-003", timestamp: "2026-04-16T17:00:00Z", actor: "analyst", action: "ENG_COMPLETED",     detail: "TechCorp engagement marked complete" },
];

// Simulated findings-over-time for the last 30 days
const now = new Date("2026-05-20");
export const FINDINGS_TIMELINE = Array.from({ length: 30 }, (_, i) => {
  const d = new Date(now);
  d.setDate(d.getDate() - (29 - i));
  const base = i > 5 ? Math.max(0, i - 5) : 0;
  return {
    date: d.toISOString().slice(0, 10),
    CRITICAL: i === 10 ? 2 : i === 15 ? 1 : i === 19 ? 3 : 0,
    HIGH:     Math.min(4, Math.floor(base * 0.3)),
    MEDIUM:   Math.min(5, Math.floor(base * 0.5)),
    LOW:      Math.min(2, Math.floor(base * 0.2)),
  };
});

export const engagementsStore = {
  list(): Engagement[] { return STORE; },

  get(id: string): Engagement | null {
    return STORE.find((e) => e.id === id) ?? null;
  },

  create(data: Omit<Engagement, "id" | "createdAt" | "updatedAt" | "assetCount" | "findingCount" | "findingsBySeverity" | "progress">): Engagement {
    const eng: Engagement = {
      id: `ENG-${genId()}`,
      assetCount: 0, findingCount: 0,
      findingsBySeverity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 },
      progress: 0,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      ...data,
    };
    STORE.push(eng);
    return eng;
  },

  update(id: string, patch: Partial<Engagement>): Engagement | null {
    const idx = STORE.findIndex((e) => e.id === id);
    if (idx === -1) return null;
    STORE[idx] = { ...STORE[idx], ...patch, updatedAt: new Date().toISOString() };
    return STORE[idx];
  },

  listActivity(engagementId?: string) {
    return engagementId
      ? ACTIVITY.filter((a) => a.engagementId === engagementId)
      : ACTIVITY;
  },

  getTimeline() { return FINDINGS_TIMELINE; },

  // ── Tenancy helpers ──
  listByClient(clientId: string): Engagement[] {
    return STORE.filter((e) => e.clientId === clientId);
  },

  /** Engagement ids belonging to a tenant — used to scope findings to a client. */
  engagementIdsForClient(clientId: string): string[] {
    return STORE.filter((e) => e.clientId === clientId).map((e) => e.id);
  },

  /** Reverse lookup: which tenant owns this engagement. */
  clientIdForEngagement(engagementId: string): string | null {
    return STORE.find((e) => e.id === engagementId)?.clientId ?? null;
  },
};
