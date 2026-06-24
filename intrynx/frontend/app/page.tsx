"use client";

import React, { useState, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Network, Activity, Shield, Cpu, ArrowRight, ChevronRight, Clock,
} from "lucide-react";
import { PageShell } from "../components/PageShell";
import { DashboardCharts } from "../components/DashboardCharts";
import { DataState, SkeletonRows, EmptyState } from "../components/states/DataState";
import { SlaRow } from "../components/dashboard/SlaRow";
import { SlaSummaryCell } from "../components/dashboard/SlaSummaryCell";
import { ProtocolRow } from "../components/dashboard/ProtocolRow";
import { ZoneRow } from "../components/dashboard/ZoneRow";
import { fetchJson } from "../lib/fetcher";
import { useMouseGradient } from "../hooks/useMouseGradient";
import {
  ATTACK_PATHS, SLA_FINDINGS, PROTOCOLS, ZONES,
  type Severity, type PathStatus, type AgentStatus,
} from "../data/mock-dashboard";

/* ─── Agent type ─── */
interface Agent { name: string; status: AgentStatus; activity: string; }

const PATH_STATUS: Record<PathStatus, { color: string; bg: string }> = {
  VALIDATED:  { color: "var(--accent)",           bg: "var(--accent-ghost)"    },
  SIMULATING: { color: "var(--sev-high-color)",   bg: "var(--sev-high-bg)"     },
  PENDING:    { color: "var(--text-muted)",       bg: "var(--bg-hover)"        },
};

const SEV_LABEL: Record<Severity, { color: string; bg: string }> = {
  CRITICAL: { color: "var(--sev-critical-color)", bg: "var(--sev-critical-bg)" },
  HIGH:     { color: "var(--sev-high-color)",     bg: "var(--sev-high-bg)"     },
  MEDIUM:   { color: "var(--sev-medium-color)",   bg: "var(--sev-medium-bg)"   },
};

const AGENT_STATUS: Record<AgentStatus, { color: string; glow: string; pulse: boolean }> = {
  ACTIVE:   { color: "var(--accent)",           glow: "var(--accent-glow)",         pulse: true  },
  THINKING: { color: "var(--sev-high-color)",   glow: "var(--sev-high-glow)",       pulse: true  },
  IDLE:     { color: "var(--text-muted)",       glow: "transparent",                pulse: false },
};

/* ─── Sub-components ─── */
function SectionHeader({ icon, title, action, delay = 0 }: { icon: React.ReactNode; title: string; action?: React.ReactNode; delay?: number }) {
  return (
    <div className="stagger-item" style={{ animationDelay: `${delay}ms`, display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 12 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
        <div style={{ color: "var(--accent)", display: "flex", transition: "transform 0.2s var(--ease-spring)" }}
          onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.transform = "scale(1.2) rotate(-5deg)"; }}
          onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.transform = "scale(1) rotate(0deg)"; }}
        >
          {icon}
        </div>
        <span style={{ fontFamily: "'Inter', sans-serif", fontSize: 13, fontWeight: 600, color: "var(--text-primary)" }}>
          {title}
        </span>
      </div>
      {action}
    </div>
  );
}

function ConfidenceBar({ value }: { value: number }) {
  const color = value >= 90 ? "var(--sev-critical-color)" : value >= 75 ? "var(--sev-high-color)" : "var(--sev-medium-color)";
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
      <div className="progress-track" style={{ width: 60, height: 4 }}>
        <div className="progress-fill" style={{ width: `${value}%`, background: color }} />
      </div>
      <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, fontWeight: 700, color, minWidth: 32 }}>
        {value}%
      </span>
    </div>
  );
}

/* ─── Animated card wrapper with mouse glow ─── */
function GlowCard({ children, delay = 0, style }: { children: React.ReactNode; delay?: number; style?: React.CSSProperties }) {
  const { ref, onMouseMove, onMouseLeave } = useMouseGradient<HTMLDivElement>();
  const [hovered, setHovered] = useState(false);

  return (
    <div
      ref={ref}
      onMouseMove={onMouseMove}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => { onMouseLeave(); setHovered(false); }}
      className="stagger-item"
      style={{
        animationDelay: `${delay}ms`,
        background: "var(--bg-panel)",
        border: `0.5px solid ${hovered ? "var(--border-strong)" : "var(--border-subtle)"}`,
        borderRadius: 14,
        overflow: "hidden",
        position: "relative",
        transition: "border-color 0.18s ease, transform 0.18s var(--ease-out), box-shadow 0.2s ease",
        transform: hovered ? "translateY(-2px)" : "translateY(0)",
        boxShadow: hovered ? "var(--shadow-md)" : "none",
        ...style,
      }}
    >
      {/* Mouse-follow glow overlay */}
      <div style={{
        position: "absolute", inset: 0, borderRadius: "inherit",
        pointerEvents: "none", zIndex: 0,
        opacity: hovered ? 1 : 0,
        transition: "opacity 0.2s ease",
        background: "radial-gradient(circle at var(--glow-x, 50%) var(--glow-y, 50%), var(--accent-glow) 0%, transparent 65%)",
      } as React.CSSProperties} />
      <div style={{ position: "relative", zIndex: 1, height: "100%" }}>
        {children}
      </div>
    </div>
  );
}

/* ─── Dashboard ─── */
/* One agent/probe row — extracted so its hover state is a proper top-level hook
   (calling useState inside .map breaks when the live agent count changes). */
function AgentRow({ agent, index, isLast }: { agent: Agent; index: number; isLast: boolean }) {
  const as_ = AGENT_STATUS[agent.status];
  const [rowHovered, setRowHovered] = useState(false);
  return (
    <div className="stagger-item"
      style={{
        animationDelay: `${300 + index * 40}ms`,
        display: "flex", alignItems: "center", gap: 12,
        padding: "13px 20px",
        borderBottom: isLast ? "none" : "0.5px solid var(--border-subtle)",
        transition: "background 0.12s ease",
        background: rowHovered ? "var(--bg-surface)" : "transparent",
        cursor: "default",
      }}
      onMouseEnter={() => setRowHovered(true)}
      onMouseLeave={() => setRowHovered(false)}
    >
      <div className="status-dot">
        {as_.pulse && (
          <span className="status-dot-ring" style={{ background: as_.glow, opacity: rowHovered ? 1 : 0.6, transition: "opacity 0.2s ease" }} />
        )}
        <span className={`status-dot-core ${as_.pulse ? "animate-pulse-dot" : ""}`} style={{ background: as_.color, width: 7, height: 7 }} />
      </div>
      <div style={{ minWidth: 0, flex: 1 }}>
        <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 13, fontWeight: 500, color: "var(--text-primary)", marginBottom: 2 }}>{agent.name}</div>
        <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 11, color: "var(--text-muted)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{agent.activity}</div>
      </div>
      <span style={{
        fontFamily: "'Inter', sans-serif", fontSize: 10, fontWeight: 700, color: as_.color,
        background: as_.pulse ? `color-mix(in srgb, ${as_.color} 12%, transparent)` : "var(--bg-hover)",
        borderRadius: 5, padding: "2px 7px", flexShrink: 0,
        transition: "transform 0.18s var(--ease-spring)", transform: rowHovered ? "scale(1.06)" : "scale(1)",
      }}>{agent.status}</span>
    </div>
  );
}

export default function Dashboard() {
  // Simple SLA helper — computes deadline status
  const slaStatus = (deadline: string, hoursTotal: number) => {
    const due = new Date(deadline).getTime(), now = Date.now();
    const pct = Math.max(0, Math.min(100, ((due - now) / (hoursTotal * 3_600_000)) * 100));
    return { breached: now > due, pct };
  };

  const breachedCount = SLA_FINDINGS.filter((f) => slaStatus(f.deadline, f.hoursTotal).breached).length;

  // Live probe/agent data (replaces the previous simulated count + mock list).
  const agentsQuery = useQuery({
    queryKey: ["agents"],
    queryFn: () => fetchJson<{ agents?: any[] }>("/api/agents/register"),
    refetchInterval: 15_000,
  });
  const agents: Agent[] = useMemo(
    () => (agentsQuery.data?.agents ?? []).map((a: any) => ({
      name: a.name ?? "probe",
      status: a.status === "BUSY" ? "THINKING" : a.status === "ONLINE" ? "ACTIVE" : "IDLE",
      activity: a.currentJobId
        ? `Running job ${String(a.currentJobId).slice(0, 8)}`
        : a.status === "ONLINE" ? "Online — ready"
        : a.status === "BUSY" ? "Working…"
        : "Offline",
    })),
    [agentsQuery.data],
  );
  const agentsOnline = agents.filter((a) => a.status !== "IDLE").length;

  return (
    <PageShell
      title="Dashboard"
      subtitle="Security Overview"
      statusItems={[
        { label: "AGENTS",  value: `${agentsOnline}/${agents.length}`, color: "var(--accent)"             },
        { label: "SLA",     value: breachedCount > 0 ? `${breachedCount} BREACHED` : "ON TRACK", color: breachedCount > 0 ? "var(--sev-critical-color)" : "var(--accent)" },
        { label: "OPS",     value: "3 ACTIVE",                   color: "var(--sev-high-color)"     },
      ]}
    >
      <div style={{ display: "flex", flexDirection: "column", gap: 28 }}>

        {/* KPIs + Charts */}
        <DashboardCharts />

        {/* Separator */}
        <div style={{ height: "0.5px", background: "var(--border-subtle)" }} />

        {/* ── Attack Paths + Agent Monitor ── */}
        <div style={{ display: "grid", gridTemplateColumns: "1fr 300px", gap: 16 }}>

          {/* Attack Paths */}
          <div>
            <SectionHeader delay={200} icon={<Network size={15} />} title="Attack Paths"
              action={
                <a href="/attack-graph" style={{ display: "flex", alignItems: "center", gap: 4, fontFamily: "'Inter', sans-serif", fontSize: 12, fontWeight: 500, color: "var(--accent)", textDecoration: "none", transition: "opacity 0.15s ease" }}
                  onMouseEnter={(e) => (e.currentTarget.style.opacity = "0.7")}
                  onMouseLeave={(e) => (e.currentTarget.style.opacity = "1")}
                >
                  View graph <ChevronRight size={13} />
                </a>
              }
            />
            <GlowCard delay={240}>
              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <thead>
                  <tr style={{ background: "var(--bg-sidebar)" }}>
                    {["Path", "Route", "Severity", "Confidence", "Status"].map((h) => (
                      <th key={h} style={{
                        padding: "9px 20px", textAlign: "left",
                        fontFamily: "'Inter', sans-serif", fontSize: 11, fontWeight: 600,
                        color: "var(--text-muted)", letterSpacing: 0.3,
                        borderBottom: "0.5px solid var(--border-subtle)", whiteSpace: "nowrap",
                      }}>
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {ATTACK_PATHS.map((p, i) => {
                    const ss  = PATH_STATUS[p.status];
                    const sev = SEV_LABEL[p.severity];
                    return (
                      <tr key={p.id} className="table-row-hover stagger-item" style={{
                        animationDelay: `${280 + i * 40}ms`,
                        borderBottom: i < ATTACK_PATHS.length - 1 ? "0.5px solid var(--border-subtle)" : "none",
                        cursor: "pointer",
                      }}>
                        <td style={{ padding: "11px 20px" }}>
                          <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, fontWeight: 600, color: "var(--accent)" }}>
                            {p.id}
                          </span>
                        </td>
                        <td style={{ padding: "11px 20px", whiteSpace: "nowrap" }}>
                          <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, color: "var(--text-secondary)" }}>{p.origin}</span>
                          <ArrowRight size={11} style={{ margin: "0 6px", color: "var(--text-muted)", verticalAlign: "middle" }} />
                          <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, color: "var(--text-primary)", fontWeight: 600 }}>{p.target}</span>
                        </td>
                        <td style={{ padding: "11px 20px" }}>
                          <span style={{
                            fontFamily: "'Inter', sans-serif", fontSize: 10, fontWeight: 700, letterSpacing: 0.5,
                            color: sev.color, background: sev.bg, borderRadius: 5, padding: "2px 8px",
                            textTransform: "uppercase",
                          }}>
                            {p.severity}
                          </span>
                        </td>
                        <td style={{ padding: "11px 20px" }}>
                          <ConfidenceBar value={p.confidence} />
                        </td>
                        <td style={{ padding: "11px 20px" }}>
                          <span style={{
                            fontFamily: "'Inter', sans-serif", fontSize: 11, fontWeight: 600,
                            color: ss.color, background: ss.bg, borderRadius: 6, padding: "3px 9px",
                          }}>
                            {p.status}
                          </span>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </GlowCard>
          </div>

          {/* Agent Monitor */}
          <div>
            <SectionHeader delay={220} icon={<Cpu size={15} />} title="Agent Monitor" />
            <GlowCard delay={260} style={{ height: "auto" }}>
              <DataState
                loading={agentsQuery.isLoading}
                error={agentsQuery.error}
                isEmpty={agents.length === 0}
                onRetry={() => agentsQuery.refetch()}
                skeleton={<div style={{ padding: 16 }}><SkeletonRows rows={4} height={44} /></div>}
                empty={<div style={{ padding: 24 }}><EmptyState icon={Cpu} title="No probes connected" hint="Deploy a probe to see live agent activity here." /></div>}
              >
                {agents.map((agent, i) => (
                  <AgentRow key={`${agent.name}-${i}`} agent={agent} index={i} isLast={i === agents.length - 1} />
                ))}
              </DataState>
            </GlowCard>
          </div>
        </div>

        {/* ── SLA + Protocol + Zone ── */}
        <div style={{ display: "grid", gridTemplateColumns: "1fr 240px 240px", gap: 16 }}>

          {/* SLA Tracker */}
          <div>
            <SectionHeader delay={360} icon={<Clock size={15} />} title="SLA Status" />
            <GlowCard delay={400}>
              {/* Summary strip */}
              <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", borderBottom: "0.5px solid var(--border-subtle)" }}>
                {[
                  { label: "Breached",  value: breachedCount, color: "var(--sev-critical-color)" },
                  { label: "At risk",   value: SLA_FINDINGS.filter((f) => { const s = slaStatus(f.deadline, f.hoursTotal); return !s.breached && s.pct < 25; }).length, color: "var(--sev-high-color)" },
                  { label: "Due <48h",  value: SLA_FINDINGS.filter((f) => { const s = slaStatus(f.deadline, f.hoursTotal); return !s.breached && s.pct < 50 && s.pct >= 25; }).length, color: "var(--sev-medium-color)" },
                  { label: "On track",  value: SLA_FINDINGS.filter((f) => { const s = slaStatus(f.deadline, f.hoursTotal); return !s.breached && s.pct >= 50; }).length, color: "var(--accent)" },
                ].map((m, i) => (
                  <SlaSummaryCell key={m.label} metric={m} isLast={i === 3} />
                ))}
              </div>

              {/* SLA rows */}
              {SLA_FINDINGS.map((f, i) => (
                <SlaRow key={f.id} finding={f} isLast={i === SLA_FINDINGS.length - 1} />
              ))}
            </GlowCard>
          </div>

          {/* Protocol Risk */}
          <div>
            <SectionHeader delay={380} icon={<Activity size={15} />} title="Protocol Risk" />
            <GlowCard delay={420}>
              {PROTOCOLS.map((p, i) => (
                <ProtocolRow key={p.name} protocol={p} isLast={i === PROTOCOLS.length - 1} />
              ))}
            </GlowCard>
          </div>

          {/* Zone Health */}
          <div>
            <SectionHeader delay={400} icon={<Shield size={15} />} title="Zone Health" />
            <GlowCard delay={440}>
              {ZONES.map((z, i) => (
                <ZoneRow key={z.name} zone={z} isLast={i === ZONES.length - 1} />
              ))}
              <div style={{
                padding: "12px 20px",
                borderTop: "0.5px solid var(--border-subtle)",
                display: "flex", alignItems: "center", justifyContent: "space-between",
              }}>
                <span style={{ fontFamily: "'Inter', sans-serif", fontSize: 11, color: "var(--text-muted)" }}>Avg confidence</span>
                <span style={{ fontFamily: "'Inter', sans-serif", fontSize: 24, fontWeight: 700, color: "var(--accent)", lineHeight: 1 }}>87%</span>
              </div>
            </GlowCard>
          </div>
        </div>

      </div>
    </PageShell>
  );
}
