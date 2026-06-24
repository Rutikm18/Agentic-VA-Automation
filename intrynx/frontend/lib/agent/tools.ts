/**
 * Tool registry for the autonomous agent.
 *
 * Each tool is exposed to Claude via the tool-use API. Claude proposes calls
 * with arguments matching the JSON Schema; ADVERSA executes them and feeds
 * the result back into the conversation.
 *
 * This is a simplified, in-process equivalent of MCP. We could wrap these
 * as proper MCP servers later — the function shapes match cleanly.
 */
import type { DiscoveredHost, LiveFinding, ScanCallbacks, ScanOptions } from '../engine/types';
import { runScan }                                      from '../engine/scanner';
import { runHostDiscovery, runNaabu, runNmap }          from '../engine/tool-runners';
import { saveFindings, updateFinding, getAllFindings }  from '../findings-store';

export interface AgentState {
  hosts:    DiscoveredHost[];
  findings: LiveFinding[];
  log:      Array<{ tool: string; input: object; result: string; ts: string }>;
  done:     boolean;
  doneReason?: string;
}

/** Risk classification — the safety envelope uses this to gate execution. */
export type Risk = 'READ_ONLY' | 'ACTIVE' | 'STATE_CHANGE' | 'DESTRUCTIVE';

export interface ToolDef {
  name:        string;
  description: string;
  risk:        Risk;
  schema:      {
    type:       'object';
    properties: Record<string, { type: string; description: string; items?: { type: string }; enum?: string[] }>;
    required:   string[];
  };
  /** Executes the tool against the live engagement state. */
  execute:     (input: Record<string, unknown>, state: AgentState, cb: ScanCallbacks) => Promise<string>;
}

// ── Helper: run a single scanner phase ──────────────────────────────
async function runOnePhase(
  state:   AgentState,
  cb:      ScanCallbacks,
  tools:   ScanOptions['tools'],
  targets: string[],
): Promise<{ hosts: DiscoveredHost[]; findings: LiveFinding[] }> {
  const newHosts:    DiscoveredHost[] = [];
  const newFindings: LiveFinding[]    = [];

  const opts: ScanOptions = {
    targets,
    profile: 'standard',
    stealth: 5,
    tools,
    save:    false,
    scanId:  `AGENT-${Date.now()}`,
  };

  // Pre-seed current host state when not running discovery
  if (state.hosts.length > 0 && !tools.includes('host-discovery') && !tools.includes('naabu')) {
    process.env.ADVERSA_REUSED_HOSTS = JSON.stringify(state.hosts);
  }

  const phaseCb: ScanCallbacks = {
    onStageStart(s)            { cb.onStageStart(s); },
    onStageComplete(s, summary){ cb.onStageComplete(s, summary); },
    onHostDiscovered(h)        { newHosts.push(h); cb.onHostDiscovered(h); },
    onFinding(f)               { newFindings.push(f); cb.onFinding(f); },
    onProgress(p, m)           { cb.onProgress(p, m); },
    onError(s, e)              { cb.onError(s, e); },
    onComplete()               { /* no-op */ },
  };

  try {
    await runScan(opts, phaseCb);
  } finally {
    delete process.env.ADVERSA_REUSED_HOSTS;
  }
  return { hosts: newHosts, findings: newFindings };
}

function mergeHosts(prior: DiscoveredHost[], updated: DiscoveredHost[]): DiscoveredHost[] {
  const byIp = new Map(prior.map((h) => [h.ip, h]));
  for (const u of updated) {
    const ex = byIp.get(u.ip);
    if (!ex) { byIp.set(u.ip, u); continue; }
    for (const p of u.ports) if (!ex.ports.includes(p)) ex.ports.push(p);
    for (const s of u.services) {
      const has = ex.services.find((es) => es.port === s.port);
      if (!has) ex.services.push(s);
      else if (s.name && !has.name) Object.assign(has, s);
    }
    ex.ports.sort((a, b) => a - b);
  }
  return [...byIp.values()];
}

// ── The tool catalog ─────────────────────────────────────────────
export const TOOL_REGISTRY: ToolDef[] = [
  {
    name:        'query_state',
    description: 'Get the current engagement state: discovered hosts, open ports, services, and findings so far. Use this any time you want to see what you have.',
    risk:        'READ_ONLY',
    schema: {
      type: 'object',
      properties: {},
      required: [],
    },
    execute: async (_input, state) => {
      const sevCount = (sev: string) => state.findings.filter((f) => f.severity === sev).length;
      const summary = {
        hosts:    state.hosts.map((h) => ({ ip: h.ip, ports: h.ports, services: h.services.filter((s) => s.name).map((s) => `${s.port}/${s.name}${s.version ? '/' + s.version : ''}`) })),
        findings_total:    state.findings.length,
        findings_critical: sevCount('CRITICAL'),
        findings_high:     sevCount('HIGH'),
        findings_medium:   sevCount('MEDIUM'),
        findings_low:      sevCount('LOW'),
        verified:          state.findings.filter((f) => f.status === 'VERIFIED').length,
      };
      return JSON.stringify(summary);
    },
  },

  {
    name:        'host_discovery',
    description: 'Multi-protocol ping sweep to identify live hosts on the given CIDR or range. Use this first when scope is a subnet.',
    risk:        'READ_ONLY',
    schema: {
      type: 'object',
      properties: {
        targets: { type: 'array', items: { type: 'string' }, description: 'List of CIDRs or IP ranges to sweep' },
      },
      required: ['targets'],
    },
    execute: async (input, state, cb) => {
      const targets = (input.targets as string[]) ?? [];
      const result = await runOnePhase(state, cb, ['host-discovery'], targets);
      state.hosts = mergeHosts(state.hosts, result.hosts);
      return JSON.stringify({ discovered: result.hosts.length, total_hosts_known: state.hosts.length });
    },
  },

  {
    name:        'port_scan',
    description: 'TCP port scan against specified hosts (or all known hosts if "hosts" omitted). Discovers open ports.',
    risk:        'ACTIVE',
    schema: {
      type: 'object',
      properties: {
        hosts: { type: 'array', items: { type: 'string' }, description: 'IPs to scan. Omit to scan all known hosts.' },
      },
      required: [],
    },
    execute: async (input, state, cb) => {
      const requested = input.hosts as string[] | undefined;
      const targets = requested && requested.length > 0 ? requested : state.hosts.map((h) => h.ip);
      if (targets.length === 0) return JSON.stringify({ error: 'No hosts to scan. Run host_discovery first.' });
      const result = await runOnePhase(state, cb, ['naabu'], targets);
      state.hosts = mergeHosts(state.hosts, result.hosts);
      const portCounts = result.hosts.map((h) => ({ ip: h.ip, open_ports: h.ports }));
      return JSON.stringify({ hosts_with_ports: portCounts });
    },
  },

  {
    name:        'service_detect',
    description: 'Fingerprint services on open ports (nmap -sV + NSE). Identifies what each service is and its version.',
    risk:        'ACTIVE',
    schema: {
      type: 'object',
      properties: {
        hosts: { type: 'array', items: { type: 'string' }, description: 'IPs to fingerprint. Omit for all known hosts with open ports.' },
      },
      required: [],
    },
    execute: async (input, state, cb) => {
      const requested = input.hosts as string[] | undefined;
      const hostsToScan = requested && requested.length > 0
        ? state.hosts.filter((h) => requested.includes(h.ip))
        : state.hosts.filter((h) => h.ports.length > 0);
      if (hostsToScan.length === 0) return JSON.stringify({ error: 'No hosts with ports. Run port_scan first.' });
      const result = await runOnePhase(state, cb, ['nmap'], hostsToScan.map((h) => h.ip));
      state.hosts = mergeHosts(state.hosts, result.hosts);
      const services = result.hosts.flatMap((h) =>
        h.services.filter((s) => s.name).map((s) => ({ host: h.ip, port: s.port, name: s.name, version: s.version })),
      );
      return JSON.stringify({ services });
    },
  },

  {
    name:        'enumerate_service',
    description: 'Run service-specific enumeration. Provide the service you want to enumerate. Auto-skips if the relevant port is not open on any host.',
    risk:        'ACTIVE',
    schema: {
      type: 'object',
      properties: {
        service: {
          type: 'string',
          description: 'Which service to enumerate.',
          enum: ['smb', 'netbios', 'snmp', 'ldap', 'rpc', 'nfs', 'rdp', 'database', 'http'],
        },
      },
      required: ['service'],
    },
    execute: async (input, state, cb) => {
      const svc = input.service as string;
      const map: Record<string, ScanOptions['tools'][number]> = {
        smb:      'smb-enum',
        netbios:  'netbios-enum',
        snmp:     'snmp-enum',
        ldap:     'ldap-enum',
        rpc:      'rpc-enum',
        nfs:      'nfs-enum',
        rdp:      'rdp-fingerprint',
        database: 'db-enum',
        http:     'httpx',
      };
      const tool = map[svc];
      if (!tool) return JSON.stringify({ error: `Unknown service: ${svc}` });
      const result = await runOnePhase(state, cb, [tool], state.hosts.map((h) => h.ip));
      state.findings.push(...result.findings);
      return JSON.stringify({ findings_added: result.findings.length, recent_findings: result.findings.slice(0, 5).map((f) => ({ id: f.id, severity: f.severity, title: f.title })) });
    },
  },

  {
    name:        'vuln_scan',
    description: 'Run a vulnerability scanner. Pick one: nuclei for CVE templates, testssl for TLS audit, ssh-audit for SSH config audit.',
    risk:        'ACTIVE',
    schema: {
      type: 'object',
      properties: {
        tool: { type: 'string', description: 'Scanner to run.', enum: ['nuclei', 'testssl', 'ssh-audit'] },
      },
      required: ['tool'],
    },
    execute: async (input, state, cb) => {
      const tool = input.tool as ScanOptions['tools'][number];
      if (!['nuclei', 'testssl', 'ssh-audit'].includes(tool)) return JSON.stringify({ error: `Invalid tool: ${tool}` });
      const result = await runOnePhase(state, cb, [tool], state.hosts.map((h) => h.ip));
      state.findings.push(...result.findings);
      return JSON.stringify({ findings_added: result.findings.length, recent_findings: result.findings.slice(0, 5).map((f) => ({ id: f.id, severity: f.severity, title: f.title })) });
    },
  },

  {
    name:        'validate_finding',
    description: 'Mark a finding as VERIFIED with a manual confirmation note. Use this when you have evidence the finding is real.',
    risk:        'STATE_CHANGE',
    schema: {
      type: 'object',
      properties: {
        finding_id: { type: 'string', description: 'ID of the finding to mark verified' },
        note:       { type: 'string', description: 'Short reason / evidence' },
      },
      required: ['finding_id', 'note'],
    },
    execute: async (input, state) => {
      const id = input.finding_id as string;
      const note = input.note as string;
      const f = state.findings.find((x) => x.id === id);
      if (!f) return JSON.stringify({ error: `Finding not found: ${id}` });
      f.status = 'VERIFIED';
      f.evidence.push({ label: 'agent verification', content: note, timestamp: new Date().toISOString() });
      return JSON.stringify({ ok: true });
    },
  },

  {
    name:        'mark_false_positive',
    description: 'Mark a finding as false positive with a reason. Use when evidence shows the finding is not real.',
    risk:        'STATE_CHANGE',
    schema: {
      type: 'object',
      properties: {
        finding_id: { type: 'string', description: 'ID of the finding' },
        reason:     { type: 'string', description: 'Why this is a false positive' },
      },
      required: ['finding_id', 'reason'],
    },
    execute: async (input, state) => {
      const id = input.finding_id as string;
      const reason = input.reason as string;
      const f = state.findings.find((x) => x.id === id);
      if (!f) return JSON.stringify({ error: `Finding not found: ${id}` });
      f.status = 'CLOSED';
      f.falsePositive = true;
      f.falsePositiveReason = reason;
      return JSON.stringify({ ok: true });
    },
  },

  {
    name:        'summarize_and_stop',
    description: 'Stop the engagement and return a final summary. Use this when you have completed enough work, when no further productive action is possible, or when you have hit your action budget.',
    risk:        'READ_ONLY',
    schema: {
      type: 'object',
      properties: {
        reason: { type: 'string', description: 'Why you are stopping' },
      },
      required: ['reason'],
    },
    execute: async (input, state) => {
      state.done = true;
      state.doneReason = input.reason as string;
      return JSON.stringify({ ok: true, finalReason: state.doneReason });
    },
  },
];

/** Persist findings produced by the agent. Called once at the end. */
export function persistAgentFindings(state: AgentState, engagementId?: string): number {
  if (state.findings.length === 0) return 0;
  return saveFindings(state.findings, engagementId);
}
