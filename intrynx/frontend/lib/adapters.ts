/**
 * Contract adapters between the FastAPI backend (snake_case, its enums) and the
 * Adversa UI shapes (camelCase, its enums). All translation lives here so the BFF
 * route handlers stay thin and the UI components don't change.
 */

// ── enums ──────────────────────────────────────────────────────────────────
const ENG_STATUS_TO_UI: Record<string, string> = {
  draft: "PLANNING",
  active: "ACTIVE",
  paused: "PAUSED",
  completed: "COMPLETED",
};
const ENG_STATUS_TO_API: Record<string, string> = {
  PLANNING: "draft",
  ACTIVE: "active",
  PAUSED: "paused",
  COMPLETED: "completed",
  ARCHIVED: "completed",
};

export function engStatusToUi(s?: string): string {
  return ENG_STATUS_TO_UI[s ?? ""] ?? "PLANNING";
}
export function engStatusToApi(s?: string): string {
  return ENG_STATUS_TO_API[s ?? ""] ?? "draft";
}

// ── Engagement ───────────────────────────────────────────────────────────────
// FastAPI EngagementOut / EngagementDetail → UI Engagement
export function toUiEngagement(api: any): any {
  const fs = api.finding_summary ?? {};
  const total = fs.total ?? 0;
  const done = api.status === "completed" ? 100 : Math.min(95, total ? Math.round((fs.remediated ?? 0) / total * 100) : 0);
  const roe = api.rules_of_engagement ?? {};
  return {
    id: api.id,
    name: api.name,
    client: roe.client ?? api.tenant_name ?? "—",
    status: engStatusToUi(api.status),
    startDate: api.start_time ?? "",
    endDate: api.end_time ?? "",
    scopeCidrs: api.scope_cidrs ?? [],
    excludedCidrs: api.excluded_cidrs ?? [],
    assessor: roe.assessor ?? "—",
    assetCount: api.asset_count ?? 0,
    findingCount: total,
    findingsBySeverity: {
      CRITICAL: fs.critical ?? 0,
      HIGH: fs.high ?? 0,
      MEDIUM: fs.medium ?? 0,
      LOW: fs.low ?? 0,
    },
    progress: done,
    tags: roe.tags ?? [],
  };
}

// UI create form → FastAPI EngagementCreate body
export function toApiEngagementCreate(ui: any): any {
  const scope = normalizeList(ui.scopeCidrs);
  return {
    name: ui.name,
    scope_cidrs: scope.length ? scope : ["0.0.0.0/32"],
    excluded_cidrs: normalizeList(ui.excludedCidrs),
    start_time: ui.startDate || null,
    end_time: ui.endDate || null,
    // The UI carries client/assessor/tags that FastAPI doesn't model as columns —
    // park them in rules_of_engagement so nothing is lost.
    rules_of_engagement: {
      client: ui.client ?? null,
      assessor: ui.assessor ?? null,
      description: ui.description ?? null,
      tags: ui.tags ?? [],
      credentials: ui.credentials ?? [],
    },
  };
}

// ── Finding ────────────────────────────────────────────────────────────────
const SEV_TO_UI: Record<string, string> = {
  critical: "CRITICAL", high: "HIGH", medium: "MEDIUM", low: "LOW", info: "INFO",
};
// FastAPI DetectionStatus → UI DetectionCoverage
const DETECTION_TO_UI: Record<string, string> = {
  detected: "COVERED", prevented: "COVERED", missed: "BLIND", unknown: "PARTIAL",
};
function severityToPriority(sev: string): string {
  return sev === "CRITICAL" ? "P0" : sev === "HIGH" ? "P1" : sev === "MEDIUM" ? "P2" : "P3";
}

// FastAPI Finding → the UI's rich Finding shape. Real backend fields are mapped;
// fields the backend doesn't produce yet (kill chain, AI triage narrative, evidence)
// default to safe empty values so the detail view renders without errors.
export function toUiFinding(api: any): any {
  const severity = SEV_TO_UI[api.severity] ?? "INFO";
  const cvss = api.cvss_score != null ? Number(api.cvss_score) : 0;
  const epss = api.epss_score != null ? Number(api.epss_score) : 0;
  const risk = api.risk_score != null ? Number(api.risk_score) : cvss * 10;
  return {
    id: api.id,
    title: api.title ?? "Untitled finding",
    severity,
    cvss: api.cvss_score != null ? String(api.cvss_score) : "—",
    cvssVector: api.cvss_vector ?? "",
    category: api.category ?? api.finding_type ?? "General",
    status: (api.status ?? "open").toUpperCase(),
    affectedHost: api.affected_host ?? api.asset_ip ?? api.asset_id ?? "—",
    discoveredAt: api.created_at ?? api.discovered_at ?? new Date().toISOString(),
    description: api.description ?? "",
    technicalDetails: api.technical_details ?? "",
    attackPath: api.attack_path ?? "",
    evidence: Array.isArray(api.evidence) ? api.evidence : [],
    impact: api.impact ?? "",
    remediation: api.remediation ? [api.remediation] : [],
    compliance: Array.isArray(api.compliance) ? api.compliance : [],
    mitre: (api.mitre_techniques ?? []).map((m: any) =>
      typeof m === "string" ? { id: m, name: m } : m),
    cves: api.cve_ids ?? [],
    riskScore: Math.round(risk),
    riskBreakdown: api.risk_breakdown ?? {
      cvss, epss: Math.round(epss * 100), kev: api.kev_listed ? 100 : 0,
      exploit: 0, asset: 0, lateral: 0,
    },
    epssScore: epss,
    epssPercentile: api.epss_percentile ?? 0,
    kevListed: api.kev_listed ?? false,
    kevDateAdded: api.kev_date_added ?? undefined,
    exploitMaturity: api.exploit_maturity ?? "THEORETICAL",
    pocAvailable: api.poc_available ?? false,
    activelyExploited: api.actively_exploited ?? api.kev_listed ?? false,
    detectionCoverage: DETECTION_TO_UI[api.detection_status] ?? "PARTIAL",
    detectionNote: api.detection_note ?? undefined,
    fpProbability: api.fp_probability ?? 0,
    relatedFindings: api.related_findings ?? [],
    killChain: Array.isArray(api.kill_chain) ? api.kill_chain : [],
    assignee: api.assignee ?? undefined,
    tags: api.tags ?? api.cve_ids ?? [],
    aiTriage: api.ai_triage ?? {
      priority: severityToPriority(severity),
      reasoning: "",
      recommendation: "",
      confidence: 0,
    },
  };
}

// ── Agent / probe ────────────────────────────────────────────────────────────
export function toUiAgent(api: any): any {
  return {
    id: api.id,
    name: api.name,
    location: api.location ?? null,
    status: api.online ? "ONLINE" : "OFFLINE",
    online: !!api.online,
    capabilities: api.capabilities ?? [],
    networkSegments: api.network_segments ?? [],
    lastHeartbeat: api.last_heartbeat ?? null,
    currentJobId: api.current_job_id ?? null,
  };
}

// UI finding-triage patch → FastAPI FindingPatch body
const FIND_STATUS_TO_API: Record<string, string> = {
  OPEN: "open", CONFIRMED: "confirmed", REMEDIATED: "remediated",
  ACCEPTED: "accepted", FP: "fp", FALSE_POSITIVE: "fp", "FALSE-POSITIVE": "fp",
};
export function toApiFindingPatch(ui: any): any {
  const out: any = {};
  if (ui.status) out.status = FIND_STATUS_TO_API[String(ui.status).toUpperCase()] ?? "open";
  if (ui.notes != null) out.notes = ui.notes;
  if (ui.remediation != null) out.remediation = ui.remediation;
  if (typeof ui.exploitable === "boolean") out.exploitable = ui.exploitable;
  return out;
}

// UI engagement-detail patch → FastAPI EngagementUpdate body
export function toApiEngagementPatch(ui: any): any {
  const out: any = {};
  if (ui.name != null) out.name = ui.name;
  if (ui.status != null) out.status = engStatusToApi(ui.status);
  if (ui.scopeCidrs != null) out.scope_cidrs = normalizeList(ui.scopeCidrs);
  if (ui.excludedCidrs != null) out.excluded_cidrs = normalizeList(ui.excludedCidrs);
  return out;
}

function normalizeList(v: unknown): string[] {
  if (Array.isArray(v)) return v.map((x) => String(x).trim()).filter(Boolean);
  if (typeof v === "string") return v.split(/[\n,]/).map((x) => x.trim()).filter(Boolean);
  return [];
}
