// GraphBuilder + PathAnalyzer + demo dataset generator
// Simulates a Neo4j-backed graph engine in-process.

export type NodeType = "Asset" | "Service" | "Finding" | "Credential" | "NetworkSegment";
export type RelationType =
  | "HAS_SERVICE" | "HAS_FINDING" | "EXPLOITS"
  | "CONNECTS_TO" | "SAME_SEGMENT" | "CREDENTIAL_REUSE";
export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
export type PathStatus = "VALIDATED" | "SIMULATING" | "PENDING";

export interface GNode {
  id: string;
  label: string;
  type: NodeType;
  criticality: Severity;
  compromised: boolean;
  internetExposed: boolean;
  zone: string;
  x: number;
  y: number;
  ip?: string;
  cvss?: number;
  cveId?: string;
  properties: Record<string, unknown>;
}

export interface GEdge {
  id: string;
  source: string;
  target: string;
  relation: RelationType;
  technique?: string;
  ttpId?: string;
  weight: number;   // exploit_complexity: lower = easier = higher weight for scoring
  exploited: boolean;
  cvss?: number;
}

export interface AttackPath {
  id: string;
  name: string;
  hops: number;
  riskScore: number;
  highlighted: boolean;
  nodeIds: string[];
  edges: { source: string; target: string; relation: RelationType; technique?: string; ttpId?: string }[];
  severity: Severity;
  status: PathStatus;
  confidence: number;
  cypherQuery: string;
}

export interface Chokepoint {
  nodeId: string;
  label: string;
  type: NodeType;
  zone: string;
  pathCount: number;
  totalPaths: number;
  percentage: number;
  remediationPriority: Severity;
}

export interface BlastRadiusResult {
  sourceNodeId: string;
  reachableNodes: { nodeId: string; label: string; type: NodeType; zone: string; hops: number; criticality: Severity }[];
  totalReachable: number;
  criticalReachable: number;
}

// ── Demo Dataset Generator (GraphBuilder.build_asset_graph) ─────────────────

function buildDemoGraph(): { nodes: GNode[]; edges: GEdge[] } {
  const nodes: GNode[] = [
    // NetworkSegment nodes
    { id: "seg-perimeter", label: "PERIMETER", type: "NetworkSegment", criticality: "MEDIUM", compromised: false, internetExposed: true,  zone: "PERIMETER", x: 60,  y: 200, properties: { cidr: "0.0.0.0/0" } },
    { id: "seg-dmz",       label: "DMZ",       type: "NetworkSegment", criticality: "HIGH",   compromised: false, internetExposed: true,  zone: "DMZ",       x: 170, y: 200, properties: { cidr: "192.168.10.0/24" } },
    { id: "seg-corp",      label: "CORP",      type: "NetworkSegment", criticality: "HIGH",   compromised: true,  internetExposed: false, zone: "CORP",      x: 410, y: 200, properties: { cidr: "10.0.1.0/24" } },
    { id: "seg-mgmt",      label: "MGMT",      type: "NetworkSegment", criticality: "CRITICAL", compromised: false, internetExposed: false, zone: "MGMT",   x: 670, y: 200, properties: { cidr: "10.0.0.0/24" } },

    // Asset nodes
    { id: "fw-ext",    label: "FW-EXT",       type: "Asset", criticality: "HIGH",     compromised: false, internetExposed: true,  zone: "PERIMETER", x: 60,  y: 200, ip: "203.0.113.1",  properties: { os: "PAN-OS 10.1", role: "firewall" } },
    { id: "web-01",   label: "WEB-01",        type: "Asset", criticality: "HIGH",     compromised: false, internetExposed: true,  zone: "DMZ",       x: 170, y: 140, ip: "192.168.10.10", properties: { os: "Ubuntu 20.04", role: "web" } },
    { id: "web-02",   label: "WEB-02",        type: "Asset", criticality: "HIGH",     compromised: false, internetExposed: true,  zone: "DMZ",       x: 170, y: 280, ip: "192.168.10.11", properties: { os: "Ubuntu 20.04", role: "web" } },
    { id: "fw-int",   label: "FW-INT",        type: "Asset", criticality: "HIGH",     compromised: false, internetExposed: false, zone: "PERIMETER", x: 290, y: 200, ip: "10.0.1.1",     properties: { os: "PAN-OS 10.1", role: "firewall" } },
    { id: "ws-042",   label: "WS-042",        type: "Asset", criticality: "MEDIUM",   compromised: true,  internetExposed: false, zone: "CORP",      x: 410, y: 130, ip: "10.0.1.10",    properties: { os: "Windows 10", role: "workstation" } },
    { id: "ws-128",   label: "WS-128",        type: "Asset", criticality: "MEDIUM",   compromised: false, internetExposed: false, zone: "CORP",      x: 410, y: 290, ip: "10.0.1.11",    properties: { os: "Windows 10", role: "workstation" } },
    { id: "svc-sql",  label: "SVC-SQL",       type: "Asset", criticality: "CRITICAL", compromised: true,  internetExposed: false, zone: "CORP",      x: 540, y: 130, ip: "10.0.1.20",    properties: { os: "Windows Server 2019", role: "sql" } },
    { id: "mgmt-srv", label: "MGMT-SRV",      type: "Asset", criticality: "HIGH",     compromised: false, internetExposed: false, zone: "MGMT",      x: 540, y: 290, ip: "10.0.0.20",    properties: { os: "Windows Server 2016", role: "mgmt" } },
    { id: "dc01",     label: "DC01",          type: "Asset", criticality: "CRITICAL", compromised: true,  internetExposed: false, zone: "MGMT",      x: 670, y: 130, ip: "10.0.0.10",    properties: { os: "Windows Server 2019", role: "dc" } },
    { id: "da-target",label: "DOMAIN ADMIN",  type: "Asset", criticality: "CRITICAL", compromised: true,  internetExposed: false, zone: "MGMT",      x: 800, y: 130, ip: "10.0.0.10",    properties: { role: "target" } },

    // Service nodes
    { id: "svc-http-web01", label: "HTTP:80",   type: "Service", criticality: "MEDIUM", compromised: false, internetExposed: true,  zone: "DMZ",  x: 170, y: 110, properties: { port: 80, protocol: "HTTP" } },
    { id: "svc-smb-ws042",  label: "SMB:445",   type: "Service", criticality: "HIGH",   compromised: true,  internetExposed: false, zone: "CORP", x: 410, y: 100, properties: { port: 445, protocol: "SMB" } },
    { id: "svc-sql-port",   label: "MSSQL:1433",type: "Service", criticality: "HIGH",   compromised: true,  internetExposed: false, zone: "CORP", x: 540, y: 100, properties: { port: 1433, protocol: "MSSQL" } },
    { id: "svc-ldap-dc01",  label: "LDAP:389",  type: "Service", criticality: "CRITICAL", compromised: false, internetExposed: false, zone: "MGMT", x: 670, y: 100, properties: { port: 389, protocol: "LDAP" } },

    // Finding nodes
    { id: "f-log4shell", label: "Log4Shell",    type: "Finding", criticality: "CRITICAL", compromised: false, internetExposed: true,  zone: "DMZ",  x: 170, y: 320, cvss: 10.0, cveId: "CVE-2021-44228", properties: { cvss: 10.0, cve: "CVE-2021-44228" } },
    { id: "f-eternalblue",label: "EternalBlue",  type: "Finding", criticality: "CRITICAL", compromised: false, internetExposed: false, zone: "CORP", x: 410, y: 340, cvss: 9.8,  cveId: "CVE-2017-0144",  properties: { cvss: 9.8,  cve: "CVE-2017-0144"  } },
    { id: "f-kerberoast", label: "Kerberoasting", type: "Finding", criticality: "HIGH",    compromised: false, internetExposed: false, zone: "CORP", x: 540, y: 340, cvss: 8.1,  properties: { cvss: 8.1,  technique: "T1558.003" } },
    { id: "f-unconstrained",label: "Unconstrained Deleg.", type: "Finding", criticality: "CRITICAL", compromised: false, internetExposed: false, zone: "MGMT", x: 670, y: 340, cvss: 9.0, properties: { cvss: 9.0, technique: "T1134.001" } },

    // Credential nodes
    { id: "cred-ntlm-ws042",  label: "NTLM Hash (WS-042)", type: "Credential", criticality: "HIGH",     compromised: true,  internetExposed: false, zone: "CORP", x: 460, y: 200, properties: { type: "NTLM", account: "user1" } },
    { id: "cred-tgs-svcbackup",label: "TGS (svc_backup)",  type: "Credential", criticality: "CRITICAL", compromised: true,  internetExposed: false, zone: "CORP", x: 590, y: 200, properties: { type: "TGS",  account: "svc_backup" } },
  ];

  let edgeIdCounter = 0;
  function mkEdge(
    source: string, target: string, relation: RelationType,
    opts: { technique?: string; ttpId?: string; weight?: number; exploited?: boolean; cvss?: number } = {}
  ): GEdge {
    return {
      id: `e${++edgeIdCounter}`,
      source, target, relation,
      technique: opts.technique,
      ttpId: opts.ttpId,
      weight: opts.weight ?? 1,
      exploited: opts.exploited ?? false,
      cvss: opts.cvss,
    };
  }

  const edges: GEdge[] = [
    // SAME_SEGMENT
    mkEdge("fw-ext",  "seg-perimeter", "SAME_SEGMENT"),
    mkEdge("fw-int",  "seg-perimeter", "SAME_SEGMENT"),
    mkEdge("web-01",  "seg-dmz",       "SAME_SEGMENT"),
    mkEdge("web-02",  "seg-dmz",       "SAME_SEGMENT"),
    mkEdge("ws-042",  "seg-corp",      "SAME_SEGMENT"),
    mkEdge("ws-128",  "seg-corp",      "SAME_SEGMENT"),
    mkEdge("svc-sql", "seg-corp",      "SAME_SEGMENT"),
    mkEdge("mgmt-srv","seg-mgmt",      "SAME_SEGMENT"),
    mkEdge("dc01",    "seg-mgmt",      "SAME_SEGMENT"),

    // HAS_SERVICE
    mkEdge("web-01",  "svc-http-web01", "HAS_SERVICE"),
    mkEdge("ws-042",  "svc-smb-ws042",  "HAS_SERVICE"),
    mkEdge("svc-sql", "svc-sql-port",   "HAS_SERVICE"),
    mkEdge("dc01",    "svc-ldap-dc01",  "HAS_SERVICE"),

    // HAS_FINDING
    mkEdge("web-01",  "f-log4shell",    "HAS_FINDING"),
    mkEdge("ws-042",  "f-eternalblue",  "HAS_FINDING"),
    mkEdge("svc-sql", "f-kerberoast",   "HAS_FINDING"),
    mkEdge("dc01",    "f-unconstrained","HAS_FINDING"),

    // CONNECTS_TO (network topology — GraphBuilder.add_network_edges)
    mkEdge("fw-ext",  "web-01",  "CONNECTS_TO", { technique: "Port Traversal",    ttpId: "T1190",     weight: 3, exploited: true  }),
    mkEdge("fw-ext",  "web-02",  "CONNECTS_TO", { technique: "Port Traversal",    ttpId: "T1190",     weight: 3, exploited: true  }),
    mkEdge("web-01",  "fw-int",  "CONNECTS_TO", { technique: "Pivot",             ttpId: "T1572",     weight: 2, exploited: false }),
    mkEdge("web-02",  "fw-int",  "CONNECTS_TO", { technique: "Pivot",             ttpId: "T1572",     weight: 2, exploited: false }),
    mkEdge("fw-int",  "ws-042",  "CONNECTS_TO", { technique: "LLMNR Poisoning",   ttpId: "T1557.001", weight: 1, exploited: true  }),
    mkEdge("fw-int",  "ws-128",  "CONNECTS_TO", { technique: "LLMNR Poisoning",   ttpId: "T1557.001", weight: 2, exploited: false }),
    mkEdge("ws-042",  "ws-128",  "CONNECTS_TO", { technique: "Lateral (WMI)",     ttpId: "T1021.003", weight: 2, exploited: true  }),
    mkEdge("ws-128",  "mgmt-srv","CONNECTS_TO", { technique: "WMI Remote Exec",   ttpId: "T1021.003", weight: 2, exploited: false }),
    mkEdge("mgmt-srv","dc01",    "CONNECTS_TO", { technique: "DCSync Attempt",    ttpId: "T1003.006", weight: 2, exploited: false }),

    // EXPLOITS (GraphBuilder.add_exploit_edges — weight = exploit_complexity)
    mkEdge("f-log4shell",    "web-01",  "EXPLOITS", { technique: "Log4Shell RCE",          ttpId: "T1190",     weight: 1, exploited: true,  cvss: 10.0 }),
    mkEdge("f-eternalblue",  "ws-042",  "EXPLOITS", { technique: "EternalBlue",            ttpId: "T1210",     weight: 2, exploited: true,  cvss: 9.8  }),
    mkEdge("f-kerberoast",   "svc-sql", "EXPLOITS", { technique: "Kerberoasting → SPN",    ttpId: "T1558.003", weight: 2, exploited: true,  cvss: 8.1  }),
    mkEdge("ws-042",  "svc-sql",  "EXPLOITS", { technique: "Kerberoasting",             ttpId: "T1558.003", weight: 2, exploited: true,  cvss: 8.1  }),
    mkEdge("svc-sql", "dc01",     "EXPLOITS", { technique: "Silver Ticket",             ttpId: "T1558.004", weight: 1, exploited: true,  cvss: 9.0  }),
    mkEdge("dc01",    "da-target","EXPLOITS", { technique: "Unconstrained Delegation",  ttpId: "T1134.001", weight: 1, exploited: true,  cvss: 9.0  }),
    mkEdge("f-unconstrained","dc01","EXPLOITS",{ technique: "Unconstrained Deleg.",     ttpId: "T1134.001", weight: 1, exploited: true,  cvss: 9.0  }),

    // CREDENTIAL_REUSE (GraphBuilder.add_exploit_edges)
    mkEdge("cred-ntlm-ws042",   "ws-128",  "CREDENTIAL_REUSE", { technique: "Pass-the-Hash",  ttpId: "T1550.002", weight: 1, exploited: true }),
    mkEdge("cred-tgs-svcbackup","dc01",    "CREDENTIAL_REUSE", { technique: "Pass-the-Ticket", ttpId: "T1550.003", weight: 1, exploited: true }),
    mkEdge("ws-042",  "cred-ntlm-ws042",   "HAS_FINDING"),
    mkEdge("svc-sql", "cred-tgs-svcbackup","HAS_FINDING"),
  ];

  return { nodes, edges };
}

// ── PathAnalyzer ────────────────────────────────────────────────────────────

function adjacency(edges: GEdge[]): Map<string, string[]> {
  const adj = new Map<string, string[]>();
  for (const e of edges) {
    if (e.relation === "CONNECTS_TO" || e.relation === "EXPLOITS" || e.relation === "CREDENTIAL_REUSE") {
      if (!adj.has(e.source)) adj.set(e.source, []);
      adj.get(e.source)!.push(e.target);
    }
  }
  return adj;
}

// BFS shortest path
function bfsPath(adj: Map<string, string[]>, start: string, end: string): string[] | null {
  const visited = new Set<string>();
  const queue: { node: string; path: string[] }[] = [{ node: start, path: [start] }];
  while (queue.length) {
    const { node, path } = queue.shift()!;
    if (node === end) return path;
    if (visited.has(node)) continue;
    visited.add(node);
    for (const next of adj.get(node) ?? []) {
      if (!visited.has(next)) queue.push({ node: next, path: [...path, next] });
    }
  }
  return null;
}

// BFS reachability (blast radius)
function bfsReach(adj: Map<string, string[]>, start: string): Map<string, number> {
  const dist = new Map<string, number>();
  const queue: { node: string; hops: number }[] = [{ node: start, hops: 0 }];
  while (queue.length) {
    const { node, hops } = queue.shift()!;
    if (dist.has(node)) continue;
    dist.set(node, hops);
    for (const next of adj.get(node) ?? []) {
      if (!dist.has(next)) queue.push({ node: next, hops: hops + 1 });
    }
  }
  return dist;
}

// PathAnalyzer.score_path: sum(cvss on path edges) + hop_penalty - credential_reuse_bonus
function scorePath(pathNodeIds: string[], edges: GEdge[]): number {
  let score = 0;
  const edgeMap = new Map(edges.map((e) => [`${e.source}→${e.target}`, e]));
  let hasCredReuse = false;
  for (let i = 0; i < pathNodeIds.length - 1; i++) {
    const e = edgeMap.get(`${pathNodeIds[i]}→${pathNodeIds[i + 1]}`);
    if (e) {
      score += (e.cvss ?? 5) * 10;
      if (e.relation === "CREDENTIAL_REUSE") hasCredReuse = true;
    }
  }
  score -= pathNodeIds.length * 5;  // hop penalty
  if (hasCredReuse) score += 15;    // credential reuse is worse
  return Math.min(100, Math.max(0, Math.round(score)));
}

function edgesForPath(nodeIds: string[], edges: GEdge[]) {
  const result = [];
  const edgeMap = new Map(edges.map((e) => [`${e.source}→${e.target}`, e]));
  for (let i = 0; i < nodeIds.length - 1; i++) {
    const e = edgeMap.get(`${nodeIds[i]}→${nodeIds[i + 1]}`);
    if (e) result.push({ source: e.source, target: e.target, relation: e.relation, technique: e.technique, ttpId: e.ttpId });
  }
  return result;
}

// ── Graph store singleton ────────────────────────────────────────────────────

const { nodes: NODES, edges: EDGES } = buildDemoGraph();
const ADJ = adjacency(EDGES);

// Pre-compute attack paths
const INTERNET_EXPOSED_IDS = NODES.filter((n) => n.internetExposed && n.type === "Asset").map((n) => n.id);
const TARGET_IDS = ["da-target", "dc01"];

function buildAttackPaths(): AttackPath[] {
  const paths: AttackPath[] = [];
  let counter = 0;

  // Hardcoded key paths from the demo topology
  const rawPaths: { nodeIds: string[]; name: string; status: PathStatus; confidence: number }[] = [
    {
      nodeIds: ["fw-ext", "web-01", "fw-int", "ws-042", "svc-sql", "dc01", "da-target"],
      name: "Internet → Log4Shell → LLMNR → Kerberoast → DC01 → DA",
      status: "VALIDATED", confidence: 97,
    },
    {
      nodeIds: ["fw-ext", "web-02", "fw-int", "ws-042", "ws-128", "mgmt-srv", "dc01", "da-target"],
      name: "Internet → WMI Lateral → MGMT → DCSync → DA",
      status: "SIMULATING", confidence: 82,
    },
    {
      nodeIds: ["fw-ext", "web-01", "fw-int", "ws-042", "cred-ntlm-ws042", "ws-128", "mgmt-srv", "dc01"],
      name: "LLMNR Capture → Pass-the-Hash → MGMT → DCSync",
      status: "SIMULATING", confidence: 78,
    },
    {
      nodeIds: ["fw-ext", "web-01", "fw-int", "ws-042", "svc-sql", "cred-tgs-svcbackup", "dc01"],
      name: "Kerberoast → TGS → Silver Ticket → DC01",
      status: "PENDING", confidence: 71,
    },
  ];

  for (const raw of rawPaths) {
    counter++;
    const pathEdges = edgesForPath(raw.nodeIds, EDGES);
    const riskScore = scorePath(raw.nodeIds, EDGES);
    const maxCvss = Math.max(0, ...pathEdges.map((e) => {
      const ge = EDGES.find((x) => x.source === e.source && x.target === e.target);
      return ge?.cvss ?? 0;
    }));
    const severity: Severity =
      maxCvss >= 9 ? "CRITICAL" : maxCvss >= 7 ? "HIGH" : maxCvss >= 4 ? "MEDIUM" : "LOW";

    const startNode = raw.nodeIds[0];
    const endNode = raw.nodeIds[raw.nodeIds.length - 1];

    paths.push({
      id: `AP-${String(counter).padStart(3, "0")}`,
      name: raw.name,
      hops: raw.nodeIds.length - 1,
      riskScore,
      highlighted: false,
      nodeIds: raw.nodeIds,
      edges: pathEdges,
      severity,
      status: raw.status,
      confidence: raw.confidence,
      // Cypher query example (PathAnalyzer.find_paths_to_target)
      cypherQuery: `MATCH p=shortestPath((src:Asset {id:"${startNode}"})-[*..10]->(tgt:Asset {id:"${endNode}"})) RETURN p`,
    });
  }

  return paths.sort((a, b) => b.riskScore - a.riskScore);
}

const ATTACK_PATHS = buildAttackPaths();

// PathAnalyzer.identify_chokepoints — assets appearing in >50% of paths
function buildChokepoints(): Chokepoint[] {
  const nodeCount = new Map<string, number>();
  const total = ATTACK_PATHS.length;
  for (const path of ATTACK_PATHS) {
    for (const nid of path.nodeIds) nodeCount.set(nid, (nodeCount.get(nid) ?? 0) + 1);
  }
  const chokepoints: Chokepoint[] = [];
  for (const [nodeId, count] of nodeCount.entries()) {
    const pct = (count / total) * 100;
    if (pct > 50) {
      const node = NODES.find((n) => n.id === nodeId);
      if (!node || node.type === "NetworkSegment") continue;
      chokepoints.push({
        nodeId, label: node.label, type: node.type, zone: node.zone,
        pathCount: count, totalPaths: total,
        percentage: Math.round(pct),
        remediationPriority: pct === 100 ? "CRITICAL" : pct >= 75 ? "HIGH" : "MEDIUM",
      });
    }
  }
  return chokepoints.sort((a, b) => b.percentage - a.percentage);
}

const CHOKEPOINTS = buildChokepoints();

export const graphStore = {
  // GraphBuilder
  getGraph(): { nodes: GNode[]; edges: GEdge[] } {
    return { nodes: NODES, edges: EDGES };
  },

  // AttackPathService: GET /engagements/{id}/attack-graph (D3-compatible)
  getD3Graph(): {
    nodes: { id: string; label: string; type: NodeType; criticality: Severity; compromised: boolean; internetExposed: boolean; zone: string; x: number; y: number }[];
    edges: { source: string; target: string; relation: RelationType; technique?: string; weight: number; exploited: boolean }[];
    paths: { id: string; hops: number; riskScore: number; highlighted: boolean }[];
    indexingStrategy: string[];
    cypherExamples: string[];
  } {
    return {
      nodes: NODES.map(({ properties: _p, ...n }) => n),
      edges: EDGES.map(({ id: _id, ...e }) => e),
      paths: ATTACK_PATHS.map(({ id, hops, riskScore, highlighted }) => ({ id, hops, riskScore, highlighted })),
      // Cypher indexing strategy for large graphs (>10k nodes)
      indexingStrategy: [
        "CREATE INDEX asset_id IF NOT EXISTS FOR (n:Asset) ON (n.id)",
        "CREATE INDEX asset_internet_exposed IF NOT EXISTS FOR (n:Asset) ON (n.internetExposed)",
        "CREATE INDEX asset_criticality IF NOT EXISTS FOR (n:Asset) ON (n.criticality)",
        "CREATE INDEX finding_cvss IF NOT EXISTS FOR (n:Finding) ON (n.cvss)",
        "CREATE INDEX segment_zone IF NOT EXISTS FOR (n:NetworkSegment) ON (n.zone)",
        "CREATE CONSTRAINT asset_id_unique IF NOT EXISTS FOR (n:Asset) REQUIRE n.id IS UNIQUE",
        "CALL db.awaitIndexes(300)",
      ],
      cypherExamples: [
        `// Shortest path from internet to target\nMATCH p=shortestPath((src:Asset {internetExposed:true})-[*..10]->(tgt:Asset {id:"da-target"})) RETURN p`,
        `// All paths with CREDENTIAL_REUSE\nMATCH p=(a:Asset)-[:CREDENTIAL_REUSE*..5]->(b:Asset) RETURN p ORDER BY length(p)`,
        `// Chokepoints (nodes in >50% of paths)\nMATCH (n:Asset) WHERE n.pathCount > $threshold RETURN n ORDER BY n.pathCount DESC`,
        `// Blast radius from compromised host\nMATCH (start:Asset {id:$assetId})-[*..10]->(reachable) RETURN DISTINCT reachable`,
        `// All EXPLOITS edges sorted by CVSS\nMATCH ()-[r:EXPLOITS]->() RETURN r ORDER BY r.cvss DESC LIMIT 20`,
      ],
    };
  },

  // AttackPathService: GET /engagements/{id}/attack-paths
  listPaths(page = 1, pageSize = 10): { paths: AttackPath[]; total: number; page: number; pageSize: number } {
    const start = (page - 1) * pageSize;
    return { paths: ATTACK_PATHS.slice(start, start + pageSize), total: ATTACK_PATHS.length, page, pageSize };
  },

  // AttackPathService: GET /engagements/{id}/attack-paths/{id}
  getPath(pathId: string): AttackPath | null {
    return ATTACK_PATHS.find((p) => p.id === pathId) ?? null;
  },

  // AttackPathService: GET /engagements/{id}/chokepoints
  getChokepoints(): Chokepoint[] {
    return CHOKEPOINTS;
  },

  // AttackPathService: GET /engagements/{id}/blast-radius/{assetId}
  getBlastRadius(assetId: string): BlastRadiusResult {
    const reachMap = bfsReach(ADJ, assetId);
    reachMap.delete(assetId); // exclude source
    const reachableNodes = [...reachMap.entries()]
      .map(([nodeId, hops]) => {
        const node = NODES.find((n) => n.id === nodeId);
        if (!node) return null;
        return { nodeId, label: node.label, type: node.type, zone: node.zone, hops, criticality: node.criticality };
      })
      .filter(Boolean) as BlastRadiusResult["reachableNodes"];

    return {
      sourceNodeId: assetId,
      reachableNodes: reachableNodes.sort((a, b) => a.hops - b.hops),
      totalReachable: reachableNodes.length,
      criticalReachable: reachableNodes.filter((n) => n.criticality === "CRITICAL").length,
    };
  },
};
