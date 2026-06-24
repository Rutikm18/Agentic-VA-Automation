import type { NucleiMatch } from "./nuclei-parser";
import type { OpenVASFinding } from "./openvas-client";

export type ScanTool = "naabu" | "nmap" | "nuclei" | "openvas" | "netexec" | "impacket" | "testssl" | "eyewitness";
export type ScanProfile = "fast" | "standard" | "deep";

export interface StageState {
  status: "waiting" | "running" | "done" | "error" | "skipped";
  progress: number;
  message: string;
  result?: Record<string, unknown>;
  error?: string;
}

export interface PipelineContext {
  targets: string[];
  profile: ScanProfile;
  credentials: {
    domain?: string;
    username?: string;
    password?: string;
    dcIp?: string;
  };
  naabuPorts?: Record<string, number[]>;
  nmapHosts?: unknown[];
  nucleiMatches?: NucleiMatch[];
  testsslFindings?: unknown[];
  nxcResults?: unknown[];
  impacketFindings?: unknown[];
  eyewitnessScreenshots?: unknown[];
}

export interface PipelineState {
  scanId: string;
  status: "idle" | "running" | "complete" | "error";
  profile: ScanProfile;
  targets: string[];
  stages: Record<ScanTool, StageState>;
  overallProgress: number;
  startedAt: string;
  completedAt?: string;
  totalFindings: number;
  findingIds: string[];
  context: PipelineContext;
}

export const STAGE_WEIGHTS: Record<ScanTool, number> = {
  naabu:      0.05,
  nmap:       0.20,
  nuclei:     0.25,
  openvas:    0.20,
  netexec:    0.10,
  impacket:   0.10,
  testssl:    0.05,
  eyewitness: 0.05,
};

export const PROFILE_TOOLS: Record<ScanProfile, ScanTool[]> = {
  fast:     ["naabu", "nmap", "nuclei", "testssl"],
  standard: ["naabu", "nmap", "nuclei", "netexec", "testssl", "eyewitness"],
  deep:     ["naabu", "nmap", "nuclei", "openvas", "netexec", "impacket", "testssl", "eyewitness"],
};

const pipelineStore = new Map<string, PipelineState>();
const eventQueues   = new Map<string, unknown[]>();

export function getPipeline(scanId: string): PipelineState | undefined {
  return pipelineStore.get(scanId);
}

export function setPipeline(scanId: string, state: PipelineState): void {
  pipelineStore.set(scanId, state);
}

/** Push a finding/host SSE event so the stream can drain it to the client. */
export function pushScanEvent(scanId: string, event: unknown): void {
  const q = eventQueues.get(scanId) ?? [];
  q.push(event);
  eventQueues.set(scanId, q);
}

/** Drain and return all pending events, resetting the queue. */
export function drainScanEvents(scanId: string): unknown[] {
  const q = eventQueues.get(scanId) ?? [];
  eventQueues.set(scanId, []);
  return q;
}

export function createInitialPipelineState(
  scanId: string,
  targets: string[],
  profile: ScanProfile,
  credentials: PipelineContext["credentials"],
  tools: ScanTool[],
): PipelineState {
  const emptyStage: StageState = { status: "waiting", progress: 0, message: "Waiting" };
  const stages = Object.fromEntries(
    (["naabu", "nmap", "nuclei", "openvas", "netexec", "impacket", "testssl", "eyewitness"] as ScanTool[]).map(
      (t) => [t, tools.includes(t) ? { ...emptyStage } : { status: "skipped" as const, progress: 0, message: "Not selected" }],
    ),
  ) as Record<ScanTool, StageState>;

  return {
    scanId,
    status: "idle",
    profile,
    targets,
    stages,
    overallProgress: 0,
    startedAt: new Date().toISOString(),
    totalFindings: 0,
    findingIds: [],
    context: { targets, profile, credentials },
  };
}

export function computeOverallProgress(stages: Record<ScanTool, StageState>, tools: ScanTool[]): number {
  let total = 0;
  let weightSum = 0;
  for (const tool of tools) {
    const w = STAGE_WEIGHTS[tool] ?? 0.1;
    const s = stages[tool];
    const p = s.status === "done" || s.status === "skipped" ? 100
      : s.status === "running" ? s.progress
      : s.status === "error" ? 100
      : 0;
    total += p * w;
    weightSum += w;
  }
  return weightSum > 0 ? Math.round(total / weightSum) : 0;
}
