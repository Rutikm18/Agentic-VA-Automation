import fs from "fs";
import path from "path";

export type CaseSeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
export type CaseStatus = "OPEN" | "IN_REVIEW" | "IN_REMEDIATION" | "VERIFIED" | "CLOSED";

export interface CaseComment {
  id: string;
  author: string;
  content: string;
  timestamp: string;
}

export interface CaseActivity {
  id: string;
  action: string;
  actor: string;
  timestamp: string;
  field?: string;
  oldValue?: string;
  newValue?: string;
}

export interface Case {
  id: string;
  findingId: string;
  title: string;
  severity: CaseSeverity;
  status: CaseStatus;
  assignee: string;
  category: string;
  cvss: string;
  affectedHost: string;
  createdAt: string;
  updatedAt: string;
  dueDate: string;
  slaHours: number;
  mitre: { id: string; name: string }[];
  comments: CaseComment[];
  activities: CaseActivity[];
  integrations: {
    jiraKey?: string;
    jiraUrl?: string;
    slackNotified?: boolean;
    slackTs?: string;
    emailSent?: boolean;
    emailSentAt?: string;
  };
}

const DATA_FILE = path.join(process.cwd(), "data", "cases.json");

const SLA_HOURS: Record<CaseSeverity, number> = {
  CRITICAL: 24,
  HIGH: 72,
  MEDIUM: 168,
  LOW: 720,
};

/* seed data */
const SEED_CASES: Case[] = [
  {
    id: "CASE-001",
    findingId: "VAPT-CRIT-001",
    title: "Unconstrained Kerberos Delegation on DC01",
    severity: "CRITICAL",
    status: "OPEN",
    assignee: "Alex Chen",
    category: "Active Directory",
    cvss: "9.8",
    affectedHost: "DC01.corp.local",
    createdAt: "2026-05-10T09:32:00Z",
    updatedAt: "2026-05-10T09:32:00Z",
    dueDate: new Date(new Date("2026-05-10T09:32:00Z").getTime() + 24 * 3600 * 1000).toISOString(),
    slaHours: 24,
    mitre: [
      { id: "T1558.003", name: "Kerberoasting" },
      { id: "T1134.001", name: "Token Impersonation" },
    ],
    comments: [
      {
        id: "c1",
        author: "Sarah Kim",
        content: "Confirmed reproduction. DC01 has TrustedForDelegation=TRUE. Coordinating with AD team.",
        timestamp: "2026-05-10T11:00:00Z",
      },
    ],
    activities: [
      { id: "a1", action: "Case created", actor: "System", timestamp: "2026-05-10T09:32:00Z" },
      { id: "a2", action: "Assigned to Alex Chen", actor: "Sarah Kim", timestamp: "2026-05-10T09:45:00Z" },
    ],
    integrations: {},
  },
  {
    id: "CASE-002",
    findingId: "VAPT-CRIT-002",
    title: "Kerberoastable svc_backup → Domain Admin",
    severity: "CRITICAL",
    status: "IN_REVIEW",
    assignee: "Marcus Lee",
    category: "Active Directory",
    cvss: "9.1",
    affectedHost: "corp.local (svc_backup)",
    createdAt: "2026-05-10T10:14:00Z",
    updatedAt: "2026-05-10T14:00:00Z",
    dueDate: new Date(new Date("2026-05-10T10:14:00Z").getTime() + 24 * 3600 * 1000).toISOString(),
    slaHours: 24,
    mitre: [
      { id: "T1558.003", name: "Kerberoasting" },
      { id: "T1110.002", name: "Password Cracking" },
    ],
    comments: [
      {
        id: "c2",
        author: "Marcus Lee",
        content: "Password cracked in 4h using Hashcat. Forcing AES256 and removing DA membership now.",
        timestamp: "2026-05-10T14:00:00Z",
      },
    ],
    activities: [
      { id: "a3", action: "Case created", actor: "System", timestamp: "2026-05-10T10:14:00Z" },
      { id: "a4", action: "Status changed to IN_REVIEW", actor: "Marcus Lee", timestamp: "2026-05-10T13:30:00Z", field: "status", oldValue: "OPEN", newValue: "IN_REVIEW" },
    ],
    integrations: { emailSent: true, emailSentAt: "2026-05-10T10:30:00Z" },
  },
  {
    id: "CASE-003",
    findingId: "VAPT-HIGH-001",
    title: "LLMNR/NBT-NS Poisoning — NTLM Credential Relay",
    severity: "HIGH",
    status: "IN_REMEDIATION",
    assignee: "Priya Sharma",
    category: "Protocol Abuse",
    cvss: "8.1",
    affectedHost: "10.10.10.0/24 CORP VLAN",
    createdAt: "2026-05-10T11:05:00Z",
    updatedAt: "2026-05-11T09:00:00Z",
    dueDate: new Date(new Date("2026-05-10T11:05:00Z").getTime() + 72 * 3600 * 1000).toISOString(),
    slaHours: 72,
    mitre: [{ id: "T1557.001", name: "LLMNR Poisoning" }],
    comments: [
      {
        id: "c3",
        author: "Priya Sharma",
        content: "GPO pushed to disable LLMNR. SMB signing rollout in progress — 147/241 hosts complete.",
        timestamp: "2026-05-11T09:00:00Z",
      },
    ],
    activities: [
      { id: "a5", action: "Case created", actor: "System", timestamp: "2026-05-10T11:05:00Z" },
      { id: "a6", action: "Jira ticket created: SEC-1247", actor: "Priya Sharma", timestamp: "2026-05-10T12:00:00Z" },
      { id: "a7", action: "Status changed to IN_REMEDIATION", actor: "Priya Sharma", timestamp: "2026-05-11T08:00:00Z", field: "status", oldValue: "IN_REVIEW", newValue: "IN_REMEDIATION" },
    ],
    integrations: { jiraKey: "SEC-1247", jiraUrl: "https://corp.atlassian.net/browse/SEC-1247", slackNotified: true },
  },
  {
    id: "CASE-004",
    findingId: "VAPT-HIGH-002",
    title: "Lateral Movement via WMI — WS-042 to CORP",
    severity: "HIGH",
    status: "OPEN",
    assignee: "Alex Chen",
    category: "Lateral Movement",
    cvss: "7.5",
    affectedHost: "WS-042, 10.10.10.0/24",
    createdAt: "2026-05-10T14:22:00Z",
    updatedAt: "2026-05-10T14:22:00Z",
    dueDate: new Date(new Date("2026-05-10T14:22:00Z").getTime() + 72 * 3600 * 1000).toISOString(),
    slaHours: 72,
    mitre: [{ id: "T1047", name: "Windows Management Instrumentation" }],
    comments: [],
    activities: [
      { id: "a8", action: "Case created", actor: "System", timestamp: "2026-05-10T14:22:00Z" },
    ],
    integrations: {},
  },
  {
    id: "CASE-005",
    findingId: "VAPT-MED-001",
    title: "Network Segmentation Bypass VLAN30 → VLAN10",
    severity: "MEDIUM",
    status: "VERIFIED",
    assignee: "Marcus Lee",
    category: "Segmentation",
    cvss: "6.4",
    affectedHost: "VLAN30 → VLAN10 inter-VLAN routing",
    createdAt: "2026-05-11T09:15:00Z",
    updatedAt: "2026-05-13T11:00:00Z",
    dueDate: new Date(new Date("2026-05-11T09:15:00Z").getTime() + 168 * 3600 * 1000).toISOString(),
    slaHours: 168,
    mitre: [{ id: "T1599", name: "Network Boundary Bridging" }],
    comments: [
      {
        id: "c4",
        author: "Marcus Lee",
        content: "ACL deny rule applied. Verified: WS-042 can no longer reach MGMT VLAN directly.",
        timestamp: "2026-05-13T11:00:00Z",
      },
    ],
    activities: [
      { id: "a9",  action: "Case created", actor: "System", timestamp: "2026-05-11T09:15:00Z" },
      { id: "a10", action: "Status changed to VERIFIED", actor: "Marcus Lee", timestamp: "2026-05-13T11:00:00Z", field: "status", oldValue: "IN_REMEDIATION", newValue: "VERIFIED" },
    ],
    integrations: { emailSent: true, slackNotified: true },
  },
];

function ensureDataDir() {
  const dir = path.join(process.cwd(), "data");
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

export function readCases(): Case[] {
  ensureDataDir();
  if (!fs.existsSync(DATA_FILE)) {
    fs.writeFileSync(DATA_FILE, JSON.stringify(SEED_CASES, null, 2));
    return SEED_CASES;
  }
  try {
    return JSON.parse(fs.readFileSync(DATA_FILE, "utf-8")) as Case[];
  } catch {
    return SEED_CASES;
  }
}

export function writeCases(cases: Case[]) {
  ensureDataDir();
  fs.writeFileSync(DATA_FILE, JSON.stringify(cases, null, 2));
}

export function getCaseById(id: string): Case | undefined {
  return readCases().find((c) => c.id === id);
}

export function createCase(data: Omit<Case, "id" | "comments" | "activities" | "integrations" | "createdAt" | "updatedAt">): Case {
  const cases = readCases();
  const seq = cases.length + 1;
  const id = `CASE-${String(seq).padStart(3, "0")}`;
  const now = new Date().toISOString();
  const slaHours = SLA_HOURS[data.severity];
  const dueDate = new Date(Date.now() + slaHours * 3600 * 1000).toISOString();

  const newCase: Case = {
    ...data,
    id,
    slaHours,
    dueDate,
    createdAt: now,
    updatedAt: now,
    comments: [],
    activities: [{ id: `a-${Date.now()}`, action: "Case created", actor: "System", timestamp: now }],
    integrations: {},
  };
  writeCases([...cases, newCase]);
  return newCase;
}

export function updateCase(id: string, patch: Partial<Case>, actor = "System"): Case | null {
  const cases = readCases();
  const idx = cases.findIndex((c) => c.id === id);
  if (idx === -1) return null;

  const old = cases[idx];
  const now = new Date().toISOString();
  const activities = [...old.activities];

  if (patch.status && patch.status !== old.status) {
    activities.push({
      id: `a-${Date.now()}`,
      action: `Status changed to ${patch.status}`,
      actor,
      timestamp: now,
      field: "status",
      oldValue: old.status,
      newValue: patch.status,
    });
  }
  if (patch.assignee && patch.assignee !== old.assignee) {
    activities.push({
      id: `a-${Date.now() + 1}`,
      action: `Reassigned to ${patch.assignee}`,
      actor,
      timestamp: now,
      field: "assignee",
      oldValue: old.assignee,
      newValue: patch.assignee,
    });
  }

  const updated: Case = { ...old, ...patch, updatedAt: now, activities };
  cases[idx] = updated;
  writeCases(cases);
  return updated;
}

export function addComment(caseId: string, author: string, content: string): Case | null {
  const cases = readCases();
  const idx = cases.findIndex((c) => c.id === caseId);
  if (idx === -1) return null;

  const now = new Date().toISOString();
  const comment: CaseComment = { id: `c-${Date.now()}`, author, content, timestamp: now };
  const activity: CaseActivity = {
    id: `a-${Date.now()}`,
    action: `Comment added by ${author}`,
    actor: author,
    timestamp: now,
  };

  cases[idx] = {
    ...cases[idx],
    comments: [...cases[idx].comments, comment],
    activities: [...cases[idx].activities, activity],
    updatedAt: now,
  };
  writeCases(cases);
  return cases[idx];
}

export function getSlaInfo(c: Case): {
  hoursLeft: number;
  pctLeft: number;
  breached: boolean;
  color: string;
} {
  const due = new Date(c.dueDate).getTime();
  const created = new Date(c.createdAt).getTime();
  const now = Date.now();
  const totalMs = due - created;
  const leftMs = due - now;
  const hoursLeft = Math.max(0, leftMs / 3600000);
  const pctLeft = Math.max(0, Math.min(100, (leftMs / totalMs) * 100));
  const breached = now > due;

  let color = "#00E676";
  if (breached)     color = "#FF1744";
  else if (pctLeft < 10)  color = "#FF1744";
  else if (pctLeft < 25)  color = "#FF6D00";
  else if (pctLeft < 50)  color = "#FFD600";

  return { hoursLeft, pctLeft, breached, color };
}
