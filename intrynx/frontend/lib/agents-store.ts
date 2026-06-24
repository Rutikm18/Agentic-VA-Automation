// ScanningAgent store — agent registry, jobs, heartbeats, Kafka topic status
import fs   from 'fs';
import path from 'path';

export type AgentStatus    = "ONLINE" | "OFFLINE" | "BUSY" | "ERROR";
export type JobStatus      = "PENDING" | "RUNNING" | "COMPLETED" | "FAILED" | "CANCELLED";
export type JobType        = "discovery" | "vuln_scan" | "ad_enum" | "lateral_movement" | "cloud_scan";
export type KafkaTopic     = "scan-jobs" | "scan-results" | "findings" | "alerts" | "audit-events";

export interface AgentCapability {
  type: JobType;
  enabled: boolean;
}

export interface Agent {
  id: string;
  name: string;
  location: string;
  status: AgentStatus;
  capabilities: AgentCapability[];
  networkSegments: string[];
  registeredAt: string;
  lastHeartbeat: string;
  currentJobId?: string;
  tlsCertExpiry: string;
  vaultRoleToken: string;
  version: string;
  ip: string;
}

export interface ScanJob {
  id: string;
  agentId?: string;
  engagementId: string;
  type: JobType;
  status: JobStatus;
  targetCidrs: string[];
  excludedCidrs: string[];
  profile: "fast" | "standard" | "deep";
  progress: number;
  createdAt: string;
  startedAt?: string;
  completedAt?: string;
  result?: Record<string, unknown>;
  errorMessage?: string;
}

export interface KafkaTopicInfo {
  name: KafkaTopic;
  partitions: number;
  replicationFactor: number;
  retentionMs: number;
  messageCount: number;
  lag: number;
  consumers: string[];
  producers: string[];
  description: string;
}

function genId() { return Math.random().toString(36).slice(2, 9).toUpperCase(); }
function nowIso() { return new Date().toISOString(); }
function futureIso(days: number) {
  const d = new Date();
  d.setDate(d.getDate() + days);
  return d.toISOString();
}

// Demo agents
const AGENTS: Agent[] = [
  {
    id: "AGT-001",
    name: "corp-agent-01",
    location: "On-Premise / CORP network",
    status: "BUSY",
    capabilities: [
      { type: "discovery",        enabled: true  },
      { type: "vuln_scan",        enabled: true  },
      { type: "ad_enum",          enabled: true  },
      { type: "lateral_movement", enabled: true  },
      { type: "cloud_scan",       enabled: false },
    ],
    networkSegments: ["10.0.0.0/8", "192.168.1.0/24"],
    registeredAt:   "2026-05-10T08:00:00Z",
    lastHeartbeat:  nowIso(),
    currentJobId:   "JOB-001",
    tlsCertExpiry:  futureIso(365),
    vaultRoleToken: "s.REDACTED",
    version:        "1.4.2",
    ip:             "10.0.50.10",
  },
  {
    id: "AGT-002",
    name: "dmz-agent-01",
    location: "On-Premise / DMZ",
    status: "ONLINE",
    capabilities: [
      { type: "discovery",        enabled: true  },
      { type: "vuln_scan",        enabled: true  },
      { type: "ad_enum",          enabled: false },
      { type: "lateral_movement", enabled: false },
      { type: "cloud_scan",       enabled: false },
    ],
    networkSegments: ["192.168.10.0/24", "192.168.20.0/24"],
    registeredAt:  "2026-05-10T08:05:00Z",
    lastHeartbeat: nowIso(),
    tlsCertExpiry: futureIso(365),
    vaultRoleToken: "s.REDACTED",
    version:        "1.4.2",
    ip:             "192.168.10.50",
  },
  {
    id: "AGT-003",
    name: "cloud-agent-aws-01",
    location: "AWS / us-east-1",
    status: "ONLINE",
    capabilities: [
      { type: "discovery",        enabled: true  },
      { type: "vuln_scan",        enabled: true  },
      { type: "ad_enum",          enabled: false },
      { type: "lateral_movement", enabled: false },
      { type: "cloud_scan",       enabled: true  },
    ],
    networkSegments: ["10.100.0.0/16"],
    registeredAt:  "2026-05-12T10:00:00Z",
    lastHeartbeat: nowIso(),
    tlsCertExpiry: futureIso(365),
    vaultRoleToken: "s.REDACTED",
    version:        "1.4.2",
    ip:             "10.100.0.15",
  },
];

// Demo jobs
const JOBS: ScanJob[] = [
  {
    id: "JOB-001",
    agentId: "AGT-001",
    engagementId: "ENG-001",
    type: "ad_enum",
    status: "RUNNING",
    targetCidrs: ["10.0.0.0/8"],
    excludedCidrs: ["10.0.0.1"],
    profile: "deep",
    progress: 67,
    createdAt: "2026-05-20T09:00:00Z",
    startedAt: "2026-05-20T09:01:00Z",
  },
  {
    id: "JOB-002",
    agentId: "AGT-002",
    engagementId: "ENG-001",
    type: "vuln_scan",
    status: "COMPLETED",
    targetCidrs: ["192.168.10.0/24"],
    excludedCidrs: [],
    profile: "standard",
    progress: 100,
    createdAt: "2026-05-20T07:00:00Z",
    startedAt: "2026-05-20T07:01:00Z",
    completedAt: "2026-05-20T08:45:00Z",
    result: { assetsScanned: 12, vulnerabilitiesFound: 7 },
  },
  {
    id: "JOB-003",
    engagementId: "ENG-001",
    type: "discovery",
    status: "PENDING",
    targetCidrs: ["10.0.1.0/24"],
    excludedCidrs: [],
    profile: "fast",
    progress: 0,
    createdAt: "2026-05-20T14:00:00Z",
  },
];

// Kafka topic definitions
const KAFKA_TOPICS: KafkaTopicInfo[] = [
  {
    name: "scan-jobs",
    partitions: 12, replicationFactor: 3, retentionMs: 86400000,
    messageCount: 142, lag: 0,
    consumers: ["agent-corp-01", "agent-dmz-01", "agent-cloud-01"],
    producers: ["orchestrator-service"],
    description: "ScanJob assignments published by orchestrator, consumed by scanning agents. Partitioned by engagement_id for ordering.",
  },
  {
    name: "scan-results",
    partitions: 12, replicationFactor: 3, retentionMs: 604800000,
    messageCount: 89, lag: 2,
    consumers: ["enrichment-service"],
    producers: ["agent-corp-01", "agent-dmz-01", "agent-cloud-01"],
    description: "Job results published by agents, consumed by enrichment service for vulnerability processing.",
  },
  {
    name: "findings",
    partitions: 24, replicationFactor: 3, retentionMs: 2592000000,
    messageCount: 1203, lag: 0,
    consumers: ["enrichment-service", "notification-service", "risk-scoring-service"],
    producers: ["enrichment-service", "api-service"],
    description: "New/updated findings consumed by enrichment, notification, and risk scoring services.",
  },
  {
    name: "alerts",
    partitions: 6, replicationFactor: 3, retentionMs: 86400000,
    messageCount: 47, lag: 1,
    consumers: ["dashboard-ws-service", "notification-service"],
    producers: ["api-service", "enrichment-service", "detection-service"],
    description: "Platform-level alerts for real-time dashboard WebSocket broadcast.",
  },
  {
    name: "audit-events",
    partitions: 6, replicationFactor: 3, retentionMs: 31536000000,
    messageCount: 8924, lag: 0,
    consumers: ["audit-archiver"],
    producers: ["api-service", "agent-manager", "orchestrator-service"],
    description: "All user and system actions for immutable audit log. 1-year retention.",
  },
];

export const agentsStore = {
  // Agent registry
  listAgents(): Agent[] { return AGENTS; },

  getAgent(id: string): Agent | null {
    return AGENTS.find((a) => a.id === id) ?? null;
  },

  register(data: {
    agentName: string; location: string;
    capabilities: JobType[]; networkSegments: string[];
    ip?: string; version?: string;
  }): Agent {
    const agent: Agent = {
      id: `AGT-${genId()}`,
      name: data.agentName,
      location: data.location,
      status: "ONLINE",
      capabilities: data.capabilities.map((type) => ({ type, enabled: true })),
      networkSegments: data.networkSegments,
      registeredAt: nowIso(),
      lastHeartbeat: nowIso(),
      tlsCertExpiry: futureIso(365),
      vaultRoleToken: `s.${genId()}${genId()}`,
      version: data.version ?? "1.4.2",
      ip: data.ip ?? "unknown",
    };
    AGENTS.push(agent);
    return agent;
  },

  heartbeat(id: string): Agent | null {
    const agent = AGENTS.find((a) => a.id === id);
    if (!agent) return null;
    agent.lastHeartbeat = nowIso();
    if (agent.status === "OFFLINE") agent.status = "ONLINE";
    return agent;
  },

  // Jobs
  listJobs(agentId?: string): ScanJob[] {
    return agentId ? JOBS.filter((j) => j.agentId === agentId) : JOBS;
  },

  getPendingJob(agentId: string): ScanJob | null {
    const agent = this.getAgent(agentId);
    if (!agent) return null;
    return JOBS.find(
      (j) => j.status === "PENDING" &&
             agent.capabilities.some((c) => c.enabled && c.type === j.type)
    ) ?? null;
  },

  updateProgress(jobId: string, progress: number): ScanJob | null {
    const job = JOBS.find((j) => j.id === jobId);
    if (!job) return null;
    job.progress = Math.min(100, progress);
    if (job.status === "PENDING") { job.status = "RUNNING"; job.startedAt = nowIso(); }
    return job;
  },

  submitResult(jobId: string, result: Record<string, unknown>, success: boolean): ScanJob | null {
    const job = JOBS.find((j) => j.id === jobId);
    if (!job) return null;
    job.status = success ? "COMPLETED" : "FAILED";
    job.progress = success ? 100 : job.progress;
    job.completedAt = nowIso();
    job.result = result;
    if (!success) job.errorMessage = (result.error as string) ?? "Unknown error";
    const agent = AGENTS.find((a) => a.id === job.agentId);
    if (agent) { agent.currentJobId = undefined; agent.status = "ONLINE"; }
    return job;
  },

  createJob(data: Omit<ScanJob, "id" | "status" | "progress" | "createdAt">): ScanJob {
    const job: ScanJob = {
      id: `JOB-${genId()}`, status: "PENDING", progress: 0,
      createdAt: nowIso(), ...data,
    };
    JOBS.unshift(job);
    return job;
  },

  // Kafka
  listTopics(): KafkaTopicInfo[] { return KAFKA_TOPICS; },
  getTopic(name: KafkaTopic): KafkaTopicInfo | null {
    return KAFKA_TOPICS.find((t) => t.name === name) ?? null;
  },

  // Stats
  stats() {
    const online  = AGENTS.filter((a) => a.status === "ONLINE" || a.status === "BUSY").length;
    const busy    = AGENTS.filter((a) => a.status === "BUSY").length;
    const pending = JOBS.filter((j) => j.status === "PENDING").length;
    const running = JOBS.filter((j) => j.status === "RUNNING").length;
    return { total: AGENTS.length, online, busy, pending, running };
  },
};

// ── File-based persistent store for CLI agents (Python agent protocol) ──────

const FIELD_AGENTS_FILE = path.join(process.cwd(), 'data', 'agents.json');

export interface FieldAgent {
  id: string;
  sessionId: string;
  hostname: string;
  os: string;
  osVersion: string;
  arch: string;
  agentVersion: string;
  capabilities: string[];
  networkInterfaces: { name: string; ip: string; cidr: string }[];
  status: 'ONLINE' | 'OFFLINE' | 'BUSY' | 'ERROR';
  registeredAt: string;
  lastSeen: string;
}

function ensureDataDir(): void {
  const dir = path.dirname(FIELD_AGENTS_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

function readFieldAgents(): FieldAgent[] {
  ensureDataDir();
  if (!fs.existsSync(FIELD_AGENTS_FILE)) return [];
  try { return JSON.parse(fs.readFileSync(FIELD_AGENTS_FILE, 'utf-8')) as FieldAgent[]; }
  catch { return []; }
}

function writeFieldAgents(agents: FieldAgent[]): void {
  ensureDataDir();
  fs.writeFileSync(FIELD_AGENTS_FILE, JSON.stringify(agents, null, 2));
}

function genFieldAgentId(): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let s = '';
  for (let i = 0; i < 6; i++) s += chars[Math.floor(Math.random() * chars.length)];
  return `AGT-${s}`;
}

export function registerAgent(
  data: Omit<FieldAgent, 'id' | 'registeredAt' | 'lastSeen' | 'status'>,
): FieldAgent {
  const agents = readFieldAgents();
  const now    = new Date().toISOString();
  const dup    = agents.find((a) => a.sessionId === data.sessionId);
  if (dup) {
    Object.assign(dup, { ...data, status: 'ONLINE' as const, lastSeen: now });
    writeFieldAgents(agents);
    return dup;
  }
  const agent: FieldAgent = {
    id: genFieldAgentId(),
    ...data,
    status: 'ONLINE',
    registeredAt: now,
    lastSeen: now,
  };
  agents.push(agent);
  writeFieldAgents(agents);
  return agent;
}

export function updateAgentLastSeen(agentId: string): void {
  const agents = readFieldAgents();
  const agent  = agents.find((a) => a.id === agentId);
  if (!agent) return;
  agent.lastSeen = new Date().toISOString();
  if (agent.status === 'OFFLINE') agent.status = 'ONLINE';
  writeFieldAgents(agents);
}

export function getAllAgents(): FieldAgent[] {
  return readFieldAgents();
}

export function getAgent(agentId: string): FieldAgent | undefined {
  return readFieldAgents().find((a) => a.id === agentId);
}
