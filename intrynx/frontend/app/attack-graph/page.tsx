"use client";

import React, { useState, useEffect, useCallback } from "react";
import {
  Network, Target, AlertTriangle, Crosshair,
  ChevronDown, ChevronRight, Copy, Check, RefreshCw,
  ZoomIn, ZoomOut, Filter,
} from "lucide-react";
import { PageShell } from "../../components/PageShell";
import { useToast } from "../../hooks/useToast";

/* ─── Types (GraphVisualizer data model) ─── */
type NodeType    = "Asset" | "Service" | "Finding" | "Credential" | "NetworkSegment";
type RelationType = "HAS_SERVICE" | "HAS_FINDING" | "EXPLOITS" | "CONNECTS_TO" | "SAME_SEGMENT" | "CREDENTIAL_REUSE";
type Severity    = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
type PathStatus  = "VALIDATED" | "SIMULATING" | "PENDING";
type TabKey      = "graph" | "paths" | "chokepoints" | "blast-radius";

interface GNode {
  id: string; label: string; type: NodeType;
  criticality: Severity; compromised: boolean;
  internetExposed: boolean; zone: string;
  x: number; y: number;
}

interface GEdge {
  source: string; target: string; relation: RelationType;
  technique?: string; weight: number; exploited: boolean;
}

interface AttackPath {
  id: string; name: string; hops: number; riskScore: number;
  highlighted: boolean; nodeIds: string[];
  edges: { source: string; target: string; relation: RelationType; technique?: string; ttpId?: string }[];
  severity: Severity; status: PathStatus; confidence: number;
  cypherQuery: string;
}

interface Chokepoint {
  nodeId: string; label: string; type: NodeType; zone: string;
  pathCount: number; totalPaths: number; percentage: number;
  remediationPriority: Severity;
}

interface BlastNode {
  nodeId: string; label: string; type: NodeType; zone: string;
  hops: number; criticality: Severity;
}

interface D3Graph {
  nodes: GNode[]; edges: GEdge[];
  paths: { id: string; hops: number; riskScore: number; highlighted: boolean }[];
  indexingStrategy: string[]; cypherExamples: string[];
}

/* ─── Helpers ─── */
function sevColor(s: Severity | string) {
  if (s === "CRITICAL") return "#FF1744";
  if (s === "HIGH")     return "#FF6D00";
  if (s === "MEDIUM")   return "#FFD600";
  return "#00E676";
}

function nodeColor(n: GNode, inPath: boolean) {
  if (n.compromised) return "#FF1744";
  if (inPath)        return "var(--adv-accent)";
  if (n.type === "NetworkSegment") return "#64748B";
  if (n.type === "Finding")        return "#FF6D00";
  if (n.type === "Credential")     return "#FFD600";
  if (n.type === "Service")        return "#00D4FF";
  return sevColor(n.criticality);
}

function nodeSymbol(n: GNode) {
  if (n.label === "DC01")          return "DC";
  if (n.label === "DOMAIN ADMIN")  return "DA";
  if (n.type === "NetworkSegment") return "NET";
  if (n.type === "Service")        return "SVC";
  if (n.type === "Finding")        return "CVE";
  if (n.type === "Credential")     return "KEY";
  if (n.zone === "DMZ")            return "WEB";
  return "HOST";
}

function statusColor(s: PathStatus) {
  if (s === "VALIDATED")  return "#00E676";
  if (s === "SIMULATING") return "#FFD600";
  return "#64748B";
}

function CopyBtn({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button onClick={() => { navigator.clipboard.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 2000); }}
      style={{ background: "none", border: "none", cursor: "pointer", color: copied ? "#00E676" : "#64748B", padding: "2px 4px" }}>
      {copied ? <Check size={11} /> : <Copy size={11} />}
    </button>
  );
}

/* ─── SVG Graph ─── */
const ZONE_X: Record<string, number> = { PERIMETER: 0, DMZ: 120, CORP: 280, MGMT: 600 };
const ZONE_W: Record<string, number> = { PERIMETER: 120, DMZ: 160, CORP: 320, MGMT: 220 };
const ZONE_COLOR: Record<string, string> = { PERIMETER: "#64748B", DMZ: "#FF6D00", CORP: "#2563EB", MGMT: "#FF1744" };

function SVGGraph({
  nodes, edges, selectedPath, hoveredNode, filterZone, filterType,
  onHover, chokepointIds,
}: {
  nodes: GNode[]; edges: GEdge[];
  selectedPath: AttackPath | null;
  hoveredNode: string | null;
  filterZone: string; filterType: string;
  onHover: (id: string | null) => void;
  chokepointIds: Set<string>;
}) {
  const pathNodeSet = new Set(selectedPath?.nodeIds ?? []);
  const pathEdgeSet = new Set(
    (selectedPath?.edges ?? []).map((e) => `${e.source}→${e.target}`)
  );

  const visNodes = nodes.filter((n) =>
    (filterZone === "ALL" || n.zone === filterZone) &&
    (filterType === "ALL" || n.type === filterType) &&
    n.type !== "NetworkSegment"
  );
  const visNodeIds = new Set(visNodes.map((n) => n.id));

  const visEdges = edges.filter(
    (e) =>
      visNodeIds.has(e.source) && visNodeIds.has(e.target) &&
      e.relation !== "SAME_SEGMENT" && e.relation !== "HAS_FINDING" && e.relation !== "HAS_SERVICE"
  );

  return (
    <svg width="100%" height="100%" viewBox="0 0 880 460" style={{ display: "block" }}>
      <defs>
        {["critical","high","medium","muted","cyan","yellow"].map((k) => {
          const color = k === "critical" ? "#FF1744" : k === "high" ? "#FF6D00" : k === "medium" ? "#FFD600" : k === "muted" ? "#64748B" : k === "cyan" ? "#00D4FF" : "#FFD600";
          return (
            <marker key={k} id={`arrow-${k}`} markerWidth="7" markerHeight="7" refX="5" refY="3" orient="auto">
              <path d="M0,0 L0,6 L7,3 z" fill={color} />
            </marker>
          );
        })}
        <filter id="glow-red">
          <feGaussianBlur stdDeviation="3" result="blur" />
          <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
        </filter>
        <filter id="glow-cyan">
          <feGaussianBlur stdDeviation="2" result="blur" />
          <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
        </filter>
      </defs>

      {/* Zone bands */}
      {Object.entries(ZONE_X).map(([zone, x]) => (
        <rect key={zone} x={x} y={0} width={ZONE_W[zone]} height={460}
          fill={`${ZONE_COLOR[zone]}08`} />
      ))}
      {[120, 280, 600].map((x) => (
        <line key={x} x1={x} y1={0} x2={x} y2={460} stroke="var(--adv-border)" strokeWidth={1} strokeDasharray="4,4" />
      ))}
      {Object.entries(ZONE_X).map(([zone, x]) => (
        <text key={zone} x={x + 5} y={16} fill={ZONE_COLOR[zone]} fontSize={8}
          fontFamily="'JetBrains Mono', monospace" opacity={0.6}>{zone}</text>
      ))}

      {/* Edges */}
      {visEdges.map((edge, i) => {
        const from = nodes.find((n) => n.id === edge.source);
        const to   = nodes.find((n) => n.id === edge.target);
        if (!from || !to) return null;

        const inPath = pathEdgeSet.has(`${edge.source}→${edge.target}`);
        const color =
          edge.relation === "CREDENTIAL_REUSE" ? "#FFD600" :
          edge.relation === "EXPLOITS" ? sevColor("CRITICAL") :
          edge.exploited ? sevColor("HIGH") : "#64748B";

        const arrowId =
          edge.relation === "CREDENTIAL_REUSE" ? "arrow-yellow" :
          edge.relation === "EXPLOITS" ? "arrow-critical" :
          edge.exploited ? "arrow-high" : "arrow-muted";

        return (
          <g key={i}>
            <line x1={from.x} y1={from.y} x2={to.x} y2={to.y}
              stroke={color}
              strokeWidth={inPath ? 2.5 : 0.8}
              strokeOpacity={inPath ? 1 : 0.3}
              strokeDasharray={!edge.exploited ? "5,3" : "none"}
              markerEnd={`url(#${arrowId})`} />
            {inPath && edge.technique && (
              <text x={(from.x + to.x) / 2} y={(from.y + to.y) / 2 - 7}
                fill={color} fontSize={7} fontFamily="'JetBrains Mono', monospace" textAnchor="middle">
                {edge.technique}
              </text>
            )}
          </g>
        );
      })}

      {/* Nodes */}
      {visNodes.map((node) => {
        const inPath   = pathNodeSet.has(node.id);
        const isChokepoint = chokepointIds.has(node.id);
        const isHovered = hoveredNode === node.id;
        const color = nodeColor(node, inPath);
        const r = node.label === "DOMAIN ADMIN" ? 18 : node.label === "DC01" ? 16 : 13;

        return (
          <g key={node.id} style={{ cursor: "pointer" }}
            onMouseEnter={() => onHover(node.id)}
            onMouseLeave={() => onHover(null)}>

            {/* Chokepoint pulse ring */}
            {isChokepoint && (
              <circle cx={node.x} cy={node.y} r={r + 10}
                fill="none" stroke="#FF6D00" strokeWidth={1.5}
                strokeOpacity={0.5} className="animate-pulse-dot" />
            )}
            {/* Path glow ring */}
            {inPath && (
              <circle cx={node.x} cy={node.y} r={r + 6}
                fill="none" stroke={color} strokeWidth={1}
                strokeOpacity={0.4} className="animate-pulse-dot" />
            )}

            <circle cx={node.x} cy={node.y} r={r}
              fill={inPath ? `${color}20` : "var(--adv-panel)"}
              stroke={color} strokeWidth={inPath ? 2 : 1}
              filter={node.compromised ? "url(#glow-red)" : inPath ? "url(#glow-cyan)" : "none"} />

            <text x={node.x} y={node.y + 4} fill={color}
              fontSize={node.label === "DOMAIN ADMIN" ? 7 : 7}
              fontFamily="'JetBrains Mono', monospace"
              textAnchor="middle" fontWeight="bold">
              {nodeSymbol(node)}
            </text>

            <text x={node.x} y={node.y + r + 13} fill={inPath ? color : "var(--adv-text-muted)"}
              fontSize={8.5} fontFamily="'JetBrains Mono', monospace" textAnchor="middle">
              {node.label}
            </text>

            {node.compromised && (
              <circle cx={node.x + r - 3} cy={node.y - r + 3} r={4} fill="#FF1744" opacity={0.9} />
            )}
            {isChokepoint && !node.compromised && (
              <circle cx={node.x + r - 3} cy={node.y - r + 3} r={4} fill="#FF6D00" opacity={0.9} />
            )}

            {isHovered && (
              <g>
                <rect x={node.x + 22} y={node.y - 35} width={135} height={52}
                  rx={4} fill="var(--adv-panel)" stroke="var(--adv-border)" strokeWidth={1} />
                <text x={node.x + 30} y={node.y - 20} fill="var(--adv-text)"
                  fontSize={8.5} fontFamily="'JetBrains Mono', monospace">{node.label}</text>
                <text x={node.x + 30} y={node.y - 8} fill={color}
                  fontSize={7.5} fontFamily="'JetBrains Mono', monospace">{node.type} · {node.zone}</text>
                <text x={node.x + 30} y={node.y + 4} fill={node.compromised ? "#FF1744" : "#00E676"}
                  fontSize={7.5} fontFamily="'JetBrains Mono', monospace">
                  {node.compromised ? "COMPROMISED" : "INTACT"}{isChokepoint ? " · CHOKEPOINT" : ""}
                </text>
              </g>
            )}
          </g>
        );
      })}
    </svg>
  );
}

/* ─── Path card ─── */
function PathCard({ path, selected, onClick }: { path: AttackPath; selected: boolean; onClick: () => void }) {
  const [open, setOpen] = useState(false);

  return (
    <div className="card-hover" style={{
      background: selected ? "rgba(37,99,235,0.06)" : "var(--adv-bg)",
      border: `1px solid ${selected ? sevColor(path.severity) + "50" : "var(--adv-border)"}`,
      borderRadius: 6, marginBottom: 8, overflow: "hidden",
    }}>
      <div onClick={() => { onClick(); setOpen(true); }}
        style={{ padding: "10px 14px", cursor: "pointer", display: "flex", alignItems: "center", gap: 10 }}>
        <div style={{ width: 8, height: 8, borderRadius: "50%", background: sevColor(path.severity), flexShrink: 0 }} />
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
            <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: "var(--adv-accent)" }}>{path.id}</span>
            <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: sevColor(path.severity),
              background: `${sevColor(path.severity)}15`, borderRadius: 3, padding: "0 5px" }}>{path.severity}</span>
            <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9,
              color: statusColor(path.status) }}>{path.status}</span>
          </div>
          <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 12, color: "var(--adv-text)", marginTop: 2 }}>{path.name}</div>
          <div style={{ display: "flex", gap: 12, marginTop: 3 }}>
            <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)" }}>
              {path.hops} hops · score {path.riskScore}
            </span>
            <div style={{ display: "flex", alignItems: "center", gap: 4 }}>
              <div style={{ width: 40, height: 3, background: "var(--adv-border)", borderRadius: 2, overflow: "hidden" }}>
                <div style={{ height: "100%", width: `${path.confidence}%`, background: path.confidence >= 90 ? "#00E676" : path.confidence >= 75 ? "var(--adv-accent)" : "#FF6D00" }} />
              </div>
              <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)" }}>{path.confidence}%</span>
            </div>
          </div>
        </div>
        <button onClick={(e) => { e.stopPropagation(); setOpen((p) => !p); }}
          style={{ background: "none", border: "none", cursor: "pointer", color: "#64748B", padding: 4 }}>
          {open ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
        </button>
      </div>

      {open && (
        <div style={{ borderTop: "1px solid var(--adv-border)", padding: "10px 14px", display: "flex", flexDirection: "column", gap: 8 }}>
          {/* Hop chain */}
          <div style={{ display: "flex", alignItems: "center", flexWrap: "wrap", gap: 5 }}>
            {path.nodeIds.map((nid, i) => (
              <React.Fragment key={nid}>
                <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text)", background: "var(--adv-panel)", border: "1px solid var(--adv-border)", borderRadius: 3, padding: "2px 6px" }}>{nid}</span>
                {i < path.nodeIds.length - 1 && <span style={{ color: "var(--adv-text-muted)", fontSize: 10 }}>→</span>}
              </React.Fragment>
            ))}
          </div>
          {/* Edges */}
          <div style={{ display: "flex", flexDirection: "column", gap: 3 }}>
            {path.edges.map((e, i) => (
              <div key={i} style={{ display: "flex", gap: 6, fontFamily: "'JetBrains Mono', monospace", fontSize: 9 }}>
                <span style={{ color: "var(--adv-text-muted)" }}>{e.source}</span>
                <span style={{ color: "#FFD600", background: "rgba(255,214,0,0.08)", borderRadius: 2, padding: "0 4px" }}>{e.technique ?? e.relation}</span>
                <span style={{ color: "var(--adv-text-muted)" }}>{e.target}</span>
                {e.ttpId && <span style={{ color: "#00D4FF" }}>{e.ttpId}</span>}
              </div>
            ))}
          </div>
          {/* Cypher */}
          <div style={{ background: "var(--adv-panel)", border: "1px solid var(--adv-border)", borderRadius: 4 }}>
            <div style={{ padding: "4px 8px", borderBottom: "1px solid var(--adv-border)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 8, color: "var(--adv-text-muted)" }}>CYPHER QUERY</span>
              <CopyBtn text={path.cypherQuery} />
            </div>
            <pre style={{ margin: 0, padding: "6px 10px", fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "#00D4FF", lineHeight: 1.5, overflowX: "auto" }}>{path.cypherQuery}</pre>
          </div>
        </div>
      )}
    </div>
  );
}

/* ─── Main Page ─── */
export default function AttackGraphPage() {
  const { error: toastError } = useToast();
  const [graphData,   setGraphData]   = useState<D3Graph | null>(null);
  const [paths,       setPaths]       = useState<AttackPath[]>([]);
  const [chokepoints, setChokepoints] = useState<Chokepoint[]>([]);
  const [loading,     setLoading]     = useState(true);
  const [activeTab,   setActiveTab]   = useState<TabKey>("graph");

  const [selectedPath, setSelectedPath] = useState<AttackPath | null>(null);
  const [hoveredNode,  setHoveredNode]  = useState<string | null>(null);
  const [filterZone,   setFilterZone]   = useState("ALL");
  const [filterType,   setFilterType]   = useState("ALL");

  const [blastAsset,  setBlastAsset]  = useState("ws-042");
  const [blastResult, setBlastResult] = useState<{ reachableNodes: BlastNode[]; totalReachable: number; criticalReachable: number } | null>(null);
  const [blastLoading, setBlastLoading] = useState(false);

  const engagementId = "ENG-001";

  useEffect(() => {
    Promise.all([
      fetch(`/api/engagements/${engagementId}/attack-graph`).then((r) => r.json()),
      fetch(`/api/engagements/${engagementId}/attack-paths`).then((r) => r.json()),
      fetch(`/api/engagements/${engagementId}/chokepoints`).then((r) => r.json()),
    ])
      .then(([g, p, c]) => {
        setGraphData(g);
        setPaths(p.paths ?? []);
        if (p.paths?.length) setSelectedPath(p.paths[0]);
        setChokepoints(c.chokepoints ?? []);
      })
      .catch(() => toastError("Load Error", "Failed to load attack graph data."))
      .finally(() => setLoading(false));
  }, [toastError]);

  const loadBlastRadius = useCallback(() => {
    if (!blastAsset.trim()) return;
    setBlastLoading(true);
    fetch(`/api/engagements/${engagementId}/blast-radius/${blastAsset}`)
      .then((r) => r.json())
      .then(setBlastResult)
      .catch(() => toastError("Error", "Failed to compute blast radius."))
      .finally(() => setBlastLoading(false));
  }, [blastAsset, toastError]);

  const chokepointIds = new Set(chokepoints.map((c) => c.nodeId));
  const compromisedCount = graphData?.nodes.filter((n) => n.compromised).length ?? 0;
  const criticalCount    = chokepoints.filter((c) => c.remediationPriority === "CRITICAL").length;

  const tabs: { key: TabKey; label: string; icon: React.ReactNode }[] = [
    { key: "graph",        label: "ATTACK GRAPH",   icon: <Network size={12} /> },
    { key: "paths",        label: `PATHS (${paths.length})`, icon: <Target size={12} /> },
    { key: "chokepoints",  label: `CHOKEPOINTS (${chokepoints.length})`, icon: <AlertTriangle size={12} /> },
    { key: "blast-radius", label: "BLAST RADIUS",   icon: <Crosshair size={12} /> },
  ];

  return (
    <PageShell
      title="ATTACK GRAPH"
      subtitle="GRAPHBUILDER · PATHANALYZER · CHOKEPOINTS · BLAST RADIUS"
      statusItems={[
        { label: "COMPROMISED", value: String(compromisedCount), color: compromisedCount > 0 ? "#FF1744" : "var(--adv-text-muted)" },
        { label: "PATHS",       value: String(paths.length),     color: "var(--adv-accent)" },
        { label: "CHOKEPOINTS", value: String(criticalCount),    color: criticalCount > 0 ? "#FF6D00" : "var(--adv-text-muted)" },
      ]}
    >
      {/* Tab bar */}
      <div style={{ display: "flex", borderBottom: "1px solid var(--adv-border)", marginBottom: 0, flexShrink: 0 }}>
        {tabs.map(({ key, label, icon }) => (
          <button key={key} onClick={() => setActiveTab(key)}
            style={{
              padding: "8px 16px", border: "none", background: "none", cursor: "pointer",
              borderBottom: `2px solid ${activeTab === key ? "var(--adv-accent)" : "transparent"}`,
              display: "flex", alignItems: "center", gap: 6, marginBottom: -1,
              fontFamily: "'JetBrains Mono', monospace", fontSize: 10,
              color: activeTab === key ? "var(--adv-accent)" : "var(--adv-text-muted)",
              transition: "color 0.12s", whiteSpace: "nowrap",
            }}>
            {icon}{label}
          </button>
        ))}
      </div>

      {loading ? (
        <div style={{ display: "flex", alignItems: "center", justifyContent: "center", flex: 1, gap: 10 }}>
          <RefreshCw size={16} color="var(--adv-accent)" style={{ animation: "spin 1s linear infinite" }} />
          <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, color: "var(--adv-text-muted)" }}>BUILDING GRAPH…</span>
        </div>
      ) : (
        <div style={{ flex: 1, overflow: "hidden", display: "flex", flexDirection: "column" }}>

          {/* ── GRAPH TAB ─────────────────────────────────────────── */}
          {activeTab === "graph" && graphData && (
            <div style={{ flex: 1, display: "flex", overflow: "hidden" }}>
              {/* Graph + toolbar */}
              <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
                {/* Toolbar */}
                <div style={{ padding: "8px 14px", borderBottom: "1px solid var(--adv-border)", display: "flex", alignItems: "center", gap: 10, flexShrink: 0, flexWrap: "wrap" }}>
                  <Filter size={12} color="#64748B" />
                  <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)" }}>ZONE</span>
                  {["ALL","DMZ","CORP","MGMT","PERIMETER"].map((z) => (
                    <button key={z} onClick={() => setFilterZone(z)}
                      style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, padding: "2px 8px", borderRadius: 3, cursor: "pointer",
                        border: `1px solid ${filterZone === z ? "var(--adv-accent)" : "var(--adv-border)"}`,
                        background: filterZone === z ? "rgba(37,99,235,0.1)" : "transparent",
                        color: filterZone === z ? "var(--adv-accent)" : "var(--adv-text-muted)" }}>
                      {z}
                    </button>
                  ))}
                  <span style={{ color: "var(--adv-border)" }}>|</span>
                  <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)" }}>TYPE</span>
                  {["ALL","Asset","Service","Finding","Credential"].map((t) => (
                    <button key={t} onClick={() => setFilterType(t)}
                      style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, padding: "2px 8px", borderRadius: 3, cursor: "pointer",
                        border: `1px solid ${filterType === t ? "#00D4FF" : "var(--adv-border)"}`,
                        background: filterType === t ? "rgba(0,212,255,0.08)" : "transparent",
                        color: filterType === t ? "#00D4FF" : "var(--adv-text-muted)" }}>
                      {t}
                    </button>
                  ))}
                  <div style={{ flex: 1 }} />
                  {/* Legend */}
                  {[
                    { label: "EXPLOITED",  color: "#FF1744" },
                    { label: "CREDENTIAL REUSE", color: "#FFD600" },
                    { label: "POTENTIAL",  color: "#64748B" },
                    { label: "CHOKEPOINT", color: "#FF6D00" },
                  ].map((l) => (
                    <div key={l.label} style={{ display: "flex", alignItems: "center", gap: 4 }}>
                      <div style={{ width: 16, height: 2, background: l.color }} />
                      <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 8, color: "var(--adv-text-muted)" }}>{l.label}</span>
                    </div>
                  ))}
                </div>
                <div style={{ flex: 1, overflow: "hidden" }}>
                  <SVGGraph nodes={graphData.nodes} edges={graphData.edges}
                    selectedPath={selectedPath} hoveredNode={hoveredNode}
                    filterZone={filterZone} filterType={filterType}
                    onHover={setHoveredNode} chokepointIds={chokepointIds} />
                </div>
              </div>

              {/* Right panel */}
              <div style={{ width: 300, borderLeft: "1px solid var(--adv-border)", display: "flex", flexDirection: "column", flexShrink: 0, overflow: "hidden" }}>
                <div style={{ padding: "10px 14px", borderBottom: "1px solid var(--adv-border)", fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: "var(--adv-text)", letterSpacing: 1 }}>
                  ATTACK PATHS
                </div>
                <div style={{ flex: 1, overflowY: "auto", padding: "8px 10px" }}>
                  {paths.map((path) => (
                    <div key={path.id}
                      onClick={() => setSelectedPath(selectedPath?.id === path.id ? null : path)}
                      className="card-hover"
                      style={{
                        padding: "10px 12px", marginBottom: 6, borderRadius: 5, cursor: "pointer",
                        background: selectedPath?.id === path.id ? "rgba(37,99,235,0.06)" : "transparent",
                        border: `1px solid ${selectedPath?.id === path.id ? sevColor(path.severity) + "40" : "var(--adv-border)"}`,
                        borderLeft: `3px solid ${selectedPath?.id === path.id ? sevColor(path.severity) : "transparent"}`,
                      }}>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4 }}>
                        <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-accent)" }}>{path.id}</span>
                        <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 8, color: sevColor(path.severity), background: `${sevColor(path.severity)}15`, borderRadius: 2, padding: "0 4px" }}>{path.severity}</span>
                      </div>
                      <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 12, color: "var(--adv-text)", marginBottom: 4 }}>{path.name}</div>
                      <div style={{ display: "flex", gap: 10, fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)" }}>
                        <span>{path.hops} hops</span>
                        <span>score {path.riskScore}</span>
                        <span style={{ color: statusColor(path.status) }}>{path.status}</span>
                      </div>
                    </div>
                  ))}
                </div>
                {selectedPath && (
                  <div style={{ borderTop: "1px solid var(--adv-border)", padding: "10px 14px", background: "var(--adv-panel)" }}>
                    <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", marginBottom: 6 }}>SELECTED PATH</div>
                    <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 13, color: "var(--adv-text)", fontWeight: 600, marginBottom: 4 }}>{selectedPath.name}</div>
                    {selectedPath.edges.map((e, i) => (
                      <div key={i} style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", marginBottom: 2 }}>
                        {e.source} <span style={{ color: "#FFD600" }}>→{e.technique ?? e.relation}→</span> {e.target}
                      </div>
                    ))}
                    <div style={{ marginTop: 8, display: "flex", gap: 8 }}>
                      <CopyBtn text={selectedPath.cypherQuery} />
                      <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)" }}>Copy Cypher</span>
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* ── PATHS TAB ─────────────────────────────────────────── */}
          {activeTab === "paths" && (
            <div style={{ flex: 1, overflowY: "auto", padding: "12px 0" }}>
              <div style={{ marginBottom: 12, fontFamily: "'Inter', sans-serif", fontSize: 13, color: "var(--adv-text-muted)" }}>
                {paths.length} attack paths found · sorted by risk score · each includes Cypher query for Neo4j import
              </div>
              {paths.map((p) => (
                <PathCard key={p.id} path={p}
                  selected={selectedPath?.id === p.id}
                  onClick={() => setSelectedPath(p)} />
              ))}
              {graphData && (
                <div style={{ marginTop: 16, background: "var(--adv-bg)", border: "1px solid var(--adv-border)", borderRadius: 6, overflow: "hidden" }}>
                  <div style={{ padding: "10px 14px", borderBottom: "1px solid var(--adv-border)", fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: "var(--adv-text)" }}>
                    INDEXING STRATEGY (Neo4j &gt;10k nodes)
                  </div>
                  <div style={{ position: "relative" }}>
                    <div style={{ position: "absolute", top: 6, right: 8 }}>
                      <CopyBtn text={graphData.indexingStrategy.join("\n")} />
                    </div>
                    <pre style={{ margin: 0, padding: "10px 12px", fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "#00D4FF", lineHeight: 1.7, overflowX: "auto" }}>
                      {graphData.indexingStrategy.join("\n")}
                    </pre>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* ── CHOKEPOINTS TAB ───────────────────────────────────── */}
          {activeTab === "chokepoints" && (
            <div style={{ flex: 1, overflowY: "auto", padding: "12px 0" }}>
              <div style={{ marginBottom: 12, fontFamily: "'Inter', sans-serif", fontSize: 13, color: "var(--adv-text-muted)" }}>
                Chokepoints appear in &gt;50% of all paths to critical targets. Remediating these blocks the most attack paths.
              </div>
              <div style={{ background: "var(--adv-bg)", border: "1px solid var(--adv-border)", borderRadius: 6, overflow: "hidden" }}>
                <table style={{ width: "100%", borderCollapse: "collapse" }}>
                  <thead>
                    <tr>
                      {["NODE", "TYPE", "ZONE", "PATH COVERAGE", "APPEARS IN", "PRIORITY"].map((h) => (
                        <th key={h} style={{ padding: "9px 14px", textAlign: "left", fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", borderBottom: "1px solid var(--adv-border)" }}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {chokepoints.map((cp, i) => (
                      <tr key={cp.nodeId}>
                        <td style={{ padding: "10px 14px", fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: sevColor(cp.remediationPriority), borderBottom: "1px solid var(--adv-border)" }}>
                          {cp.label}
                          {cp.remediationPriority === "CRITICAL" && (
                            <span className="animate-pulse-dot" style={{ display: "inline-block", width: 6, height: 6, borderRadius: "50%", background: "#FF6D00", marginLeft: 6, verticalAlign: "middle" }} />
                          )}
                        </td>
                        <td style={{ padding: "10px 14px", fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-text-muted)", borderBottom: "1px solid var(--adv-border)" }}>{cp.type}</td>
                        <td style={{ padding: "10px 14px", fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: ZONE_COLOR[cp.zone] ?? "var(--adv-text-muted)", borderBottom: "1px solid var(--adv-border)" }}>{cp.zone}</td>
                        <td style={{ padding: "10px 14px", borderBottom: "1px solid var(--adv-border)" }}>
                          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                            <div style={{ width: 80, height: 6, background: "var(--adv-panel)", borderRadius: 3, overflow: "hidden" }}>
                              <div style={{ height: "100%", width: `${cp.percentage}%`, background: sevColor(cp.remediationPriority), borderRadius: 3 }} />
                            </div>
                            <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: sevColor(cp.remediationPriority) }}>{cp.percentage}%</span>
                          </div>
                        </td>
                        <td style={{ padding: "10px 14px", fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-text-muted)", borderBottom: "1px solid var(--adv-border)" }}>
                          {cp.pathCount} / {cp.totalPaths} paths
                        </td>
                        <td style={{ padding: "10px 14px", borderBottom: "1px solid var(--adv-border)" }}>
                          <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: sevColor(cp.remediationPriority), background: `${sevColor(cp.remediationPriority)}15`, borderRadius: 3, padding: "1px 6px" }}>
                            {cp.remediationPriority}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <div style={{ marginTop: 12, background: "rgba(255,107,0,0.04)", border: "1px solid rgba(255,107,0,0.2)", borderRadius: 6, padding: "12px 14px" }}>
                <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", marginBottom: 6 }}>CHOKEPOINT CYPHER QUERY</div>
                <div style={{ position: "relative" }}>
                  <div style={{ position: "absolute", top: 0, right: 0 }}>
                    <CopyBtn text={graphData?.cypherExamples[2] ?? ""} />
                  </div>
                  <pre style={{ margin: 0, fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "#00D4FF", lineHeight: 1.6, overflowX: "auto" }}>
                    {graphData?.cypherExamples[2]}
                  </pre>
                </div>
              </div>
            </div>
          )}

          {/* ── BLAST RADIUS TAB ──────────────────────────────────── */}
          {activeTab === "blast-radius" && (
            <div style={{ flex: 1, overflowY: "auto", padding: "12px 0" }}>
              <div style={{ display: "flex", gap: 10, marginBottom: 16, alignItems: "center" }}>
                <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-text-muted)" }}>ASSET ID</div>
                <input value={blastAsset} onChange={(e) => setBlastAsset(e.target.value)}
                  placeholder="e.g. ws-042"
                  style={{ background: "var(--adv-panel)", border: "1px solid var(--adv-border)", borderRadius: 5, padding: "6px 10px", color: "var(--adv-text)", fontFamily: "'JetBrains Mono', monospace", fontSize: 12, outline: "none", width: 180 }} />
                <button onClick={loadBlastRadius} disabled={blastLoading}
                  style={{ padding: "6px 16px", borderRadius: 5, border: "1px solid rgba(37,99,235,0.3)", background: "rgba(37,99,235,0.1)", color: "var(--adv-accent)", fontFamily: "'JetBrains Mono', monospace", fontSize: 10, cursor: "pointer", display: "flex", alignItems: "center", gap: 6 }}>
                  {blastLoading ? <RefreshCw size={11} style={{ animation: "spin 1s linear infinite" }} /> : <Crosshair size={11} />}
                  COMPUTE
                </button>
                <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 12, color: "var(--adv-text-muted)" }}>
                  Available node IDs: fw-ext, web-01, ws-042, svc-sql, dc01, mgmt-srv
                </div>
              </div>

              {blastResult ? (
                <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
                  <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 10 }}>
                    {[
                      { label: "TOTAL REACHABLE",   value: blastResult.totalReachable,   color: "var(--adv-accent)" },
                      { label: "CRITICAL ASSETS",   value: blastResult.criticalReachable, color: blastResult.criticalReachable > 0 ? "#FF1744" : "var(--adv-text-muted)" },
                      { label: "SOURCE NODE",        value: blastAsset,                   color: "#FF6D00" },
                    ].map((m) => (
                      <div key={m.label} style={{ background: "var(--adv-panel)", border: "1px solid var(--adv-border)", borderRadius: 6, padding: "12px 14px" }}>
                        <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", marginBottom: 4 }}>{m.label}</div>
                        <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 22, fontWeight: 700, color: m.color }}>{m.value}</div>
                      </div>
                    ))}
                  </div>

                  <div style={{ background: "var(--adv-bg)", border: "1px solid var(--adv-border)", borderRadius: 6, overflow: "hidden" }}>
                    <div style={{ padding: "10px 14px", borderBottom: "1px solid var(--adv-border)", fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: "var(--adv-text)" }}>
                      REACHABLE ASSETS FROM {blastAsset.toUpperCase()} — sorted by hop distance
                    </div>
                    <table style={{ width: "100%", borderCollapse: "collapse" }}>
                      <thead>
                        <tr>
                          {["HOPS", "NODE", "TYPE", "ZONE", "CRITICALITY"].map((h) => (
                            <th key={h} style={{ padding: "8px 14px", textAlign: "left", fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", borderBottom: "1px solid var(--adv-border)" }}>{h}</th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {blastResult.reachableNodes.map((n) => (
                          <tr key={n.nodeId}>
                            <td style={{ padding: "9px 14px", fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: n.hops <= 2 ? "#FF1744" : "var(--adv-accent)", borderBottom: "1px solid var(--adv-border)" }}>{n.hops}</td>
                            <td style={{ padding: "9px 14px", fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: "var(--adv-text)", borderBottom: "1px solid var(--adv-border)" }}>{n.label}</td>
                            <td style={{ padding: "9px 14px", fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-text-muted)", borderBottom: "1px solid var(--adv-border)" }}>{n.type}</td>
                            <td style={{ padding: "9px 14px", fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: ZONE_COLOR[n.zone] ?? "var(--adv-text-muted)", borderBottom: "1px solid var(--adv-border)" }}>{n.zone}</td>
                            <td style={{ padding: "9px 14px", borderBottom: "1px solid var(--adv-border)" }}>
                              <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: sevColor(n.criticality), background: `${sevColor(n.criticality)}15`, borderRadius: 3, padding: "1px 5px" }}>{n.criticality}</span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              ) : (
                <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", padding: "60px 0", gap: 12 }}>
                  <Crosshair size={40} color="var(--adv-border)" />
                  <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 13, color: "var(--adv-text-muted)" }}>
                    Enter an asset ID and click COMPUTE to see the blast radius.
                  </div>
                </div>
              )}

              {graphData && (
                <div style={{ marginTop: 12, background: "var(--adv-bg)", border: "1px solid var(--adv-border)", borderRadius: 6, overflow: "hidden" }}>
                  <div style={{ padding: "9px 14px", borderBottom: "1px solid var(--adv-border)", fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-text-muted)" }}>BLAST RADIUS CYPHER</div>
                  <div style={{ position: "relative" }}>
                    <div style={{ position: "absolute", top: 6, right: 8 }}><CopyBtn text={graphData.cypherExamples[3]} /></div>
                    <pre style={{ margin: 0, padding: "10px 12px", fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "#00D4FF", lineHeight: 1.6, overflowX: "auto" }}>{graphData.cypherExamples[3]}</pre>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </PageShell>
  );
}
