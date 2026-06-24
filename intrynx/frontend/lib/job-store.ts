import fs   from 'fs';
import path from 'path';

const JOBS_FILE = path.join(process.cwd(), 'data', 'jobs.json');

export type JobStatus = 'PENDING' | 'DISPATCHED' | 'RUNNING' | 'COMPLETE' | 'FAILED';

export interface Job {
  id: string;
  type: 'scan' | 'exploit' | 'verify';
  agentId?: string;
  status: JobStatus;
  payload: Record<string, unknown>;
  scopeToken: string;
  createdAt: string;
  dispatchedAt?: string;
  completedAt?: string;
}

function ensureDir(): void {
  const dir = path.dirname(JOBS_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

function readJobs(): Job[] {
  ensureDir();
  if (!fs.existsSync(JOBS_FILE)) return [];
  try { return JSON.parse(fs.readFileSync(JOBS_FILE, 'utf-8')) as Job[]; }
  catch { return []; }
}

function writeJobs(jobs: Job[]): void {
  ensureDir();
  fs.writeFileSync(JOBS_FILE, JSON.stringify(jobs, null, 2));
}

function genJobId(): string {
  return `JOB-${Date.now()}-${Math.random().toString(36).slice(2, 7).toUpperCase()}`;
}

export function createJob(
  type: Job['type'],
  payload: object,
  scopeToken: string,
  agentId?: string,
): Job {
  const jobs = readJobs();
  const job: Job = {
    id: genJobId(),
    type,
    agentId,
    status: 'PENDING',
    payload: payload as Record<string, unknown>,
    scopeToken,
    createdAt: new Date().toISOString(),
  };
  jobs.push(job);
  writeJobs(jobs);
  return job;
}

export function getNextJobForAgent(agentId: string, capabilities: string[]): Job | undefined {
  const jobs = readJobs();
  return jobs.find((j) => {
    if (j.status !== 'PENDING') return false;
    if (j.agentId && j.agentId !== agentId) return false;
    if (j.type === 'scan'    && !capabilities.includes('naabu') && !capabilities.includes('nmap')) return false;
    if (j.type === 'exploit' && !capabilities.includes('nuclei')) return false;
    return true;
  });
}

export function markDispatched(jobId: string, agentId: string): void {
  const jobs = readJobs();
  const job  = jobs.find((j) => j.id === jobId);
  if (!job) return;
  job.status       = 'DISPATCHED';
  job.agentId      = agentId;
  job.dispatchedAt = new Date().toISOString();
  writeJobs(jobs);
}

export function updateJobStatus(jobId: string, status: JobStatus): void {
  const jobs = readJobs();
  const job  = jobs.find((j) => j.id === jobId);
  if (!job) return;
  job.status = status;
  if (status === 'COMPLETE' || status === 'FAILED') {
    job.completedAt = new Date().toISOString();
  }
  writeJobs(jobs);
}

export function getAllJobs(): Job[] {
  return readJobs();
}

export function getJobByScanId(scanId: string): Job | undefined {
  return readJobs().find((j) => (j.payload as { scanId?: string }).scanId === scanId);
}
