"use client";

import React, { useRef, useCallback } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  AreaChart, Area, PieChart, Pie, Cell,
  XAxis, YAxis, Tooltip, ResponsiveContainer,
} from "recharts";
import { AlertTriangle, TrendingUp, Users, ShieldAlert, ArrowUpRight, ArrowDownRight, Minus } from "lucide-react";
import Link from "next/link";
import { useCountUp } from "../hooks/useCountUp";

/* ─── Types ─── */
interface TimelinePoint { date: string; CRITICAL: number; HIGH: number; MEDIUM: number; LOW: number; }
interface Engagement {
  id: string; name: string;
  findingsBySeverity: { CRITICAL: number; HIGH: number; MEDIUM: number; LOW: number };
  findingCount: number; assetCount: number; status: string;
}
interface ActivityItem { id: string; timestamp: string; actor: string; action: string; detail: string; engagementId: string; }

const SEV = {
  CRITICAL: { color: "var(--sev-critical-color)", bg: "var(--sev-critical-bg)", glow: "var(--sev-critical-glow)" },
  HIGH:     { color: "var(--sev-high-color)",     bg: "var(--sev-high-bg)",     glow: "var(--sev-high-glow)"     },
  MEDIUM:   { color: "var(--sev-medium-color)",   bg: "var(--sev-medium-bg)",   glow: "var(--sev-medium-glow)"   },
  LOW:      { color: "var(--sev-low-color)",       bg: "var(--sev-low-bg)",      glow: "var(--sev-low-bg)"        },
};

/* ─── Skeleton ─── */
function Bone({ w, h, radius = 6 }: { w: number | string; h: number; radius?: number }) {
  return <div className="shimmer" style={{ width: w, height: h, borderRadius: radius }} />;
}

/* ─── Custom tooltip ─── */
function ChartTooltip({ active, payload, label }: { active?: boolean; payload?: { name: string; value: number; color: string }[]; label?: string }) {
  if (!active || !payload?.length) return null;
  return (
    <div style={{
      background: "var(--bg-sidebar)", border: "0.5px solid var(--border-strong)",
      borderRadius: 10, padding: "10px 14px",
      boxShadow: "0 8px 32px rgba(0,0,0,0.4)",
      backdropFilter: "blur(8px)",
    }}>
      <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--text-muted)", marginBottom: 7 }}>{label}</div>
      {payload.map((p) => (
        <div key={p.name} style={{ display: "flex", justifyContent: "space-between", gap: 16, fontFamily: "'JetBrains Mono', monospace", fontSize: 11, marginBottom: 3 }}>
          <span style={{ color: p.color }}>{p.name}</span>
          <span style={{ color: "var(--text-primary)", fontWeight: 700 }}>{p.value}</span>
        </div>
      ))}
    </div>
  );
}

/* ─── KPI Card with mouse-follow gradient ─── */
function KpiCard({
  label, value, icon, accentColor, accentGlow, trend, loading, delay = 0,
}: {
  label: string; value: number; icon: React.ReactNode;
  accentColor: string; accentGlow: string; trend?: number; loading?: boolean; delay?: number;
}) {
  const cardRef = useRef<HTMLDivElement>(null);
  const displayValue = useCountUp(loading ? 0 : value, 900, delay);
  const [hovered, setHovered] = React.useState(false);

  const onMouseMove = useCallback((e: React.MouseEvent<HTMLDivElement>) => {
    const el = cardRef.current;
    if (!el) return;
    const r = el.getBoundingClientRect();
    el.style.setProperty("--glow-x", `${((e.clientX - r.left) / r.width)  * 100}%`);
    el.style.setProperty("--glow-y", `${((e.clientY - r.top)  / r.height) * 100}%`);
  }, []);

  return (
    <div
      ref={cardRef}
      className="stagger-item"
      onMouseMove={onMouseMove}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => { setHovered(false); cardRef.current?.style.setProperty("--glow-x", "50%"); cardRef.current?.style.setProperty("--glow-y", "50%"); }}
      style={{
        "--glow-x": "50%", "--glow-y": "50%",
        animationDelay: `${delay}ms`,
        background: "var(--bg-panel)",
        border: `0.5px solid ${hovered ? "var(--border-strong)" : "var(--border-subtle)"}`,
        borderRadius: 14,
        padding: "20px 22px 18px",
        position: "relative",
        overflow: "hidden",
        cursor: "default",
        transition: "transform 0.18s var(--ease-out), border-color 0.18s ease, box-shadow 0.2s ease",
        transform: hovered ? "translateY(-3px)" : "translateY(0)",
        boxShadow: hovered ? `0 8px 32px ${accentGlow}, var(--shadow-md)` : "none",
      } as React.CSSProperties}
    >
      {/* Mouse-follow glow */}
      <div style={{
        position: "absolute", inset: 0, borderRadius: "inherit", pointerEvents: "none", zIndex: 0,
        opacity: hovered ? 1 : 0,
        transition: "opacity 0.2s ease",
        background: `radial-gradient(circle at var(--glow-x, 50%) var(--glow-y, 50%), ${accentGlow} 0%, transparent 65%)`,
      } as React.CSSProperties} />

      {/* Left accent edge */}
      <div style={{
        position: "absolute", left: 0, top: 16, bottom: 16, width: 3,
        borderRadius: "0 2px 2px 0", background: accentColor,
        opacity: hovered ? 1 : 0.6,
        transition: "opacity 0.2s ease, box-shadow 0.2s ease",
        boxShadow: hovered ? `0 0 8px ${accentGlow}` : "none",
      }} />

      <div style={{ position: "relative", zIndex: 1 }}>
        {loading ? (
          <>
            <Bone w={90} h={10} /><div style={{ marginTop: 12 }}><Bone w={56} h={28} /></div>
          </>
        ) : (
          <>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 14 }}>
              <span style={{ fontFamily: "'Inter', sans-serif", fontSize: 12, fontWeight: 500, color: "var(--text-secondary)" }}>
                {label}
              </span>
              <div style={{
                opacity: hovered ? 1 : 0.5,
                transition: "opacity 0.18s ease, transform 0.18s var(--ease-spring)",
                transform: hovered ? "scale(1.15)" : "scale(1)",
                color: accentColor,
              }}>
                {icon}
              </div>
            </div>
            <div style={{ display: "flex", alignItems: "flex-end", gap: 10 }}>
              <span className="animate-count-up" style={{
                fontFamily: "'Inter', sans-serif", fontSize: 36, fontWeight: 700,
                color: "var(--text-primary)", lineHeight: 1,
                letterSpacing: "-1px",
                animationDelay: `${delay + 100}ms`,
              }}>
                {displayValue}
              </span>
              {trend !== undefined && (
                <div style={{
                  display: "flex", alignItems: "center", gap: 2, marginBottom: 5,
                  fontFamily: "'Inter', sans-serif", fontSize: 12, fontWeight: 600,
                  color: trend > 0 ? "var(--sev-critical-color)" : trend < 0 ? "var(--accent)" : "var(--text-muted)",
                  background: trend > 0 ? "var(--sev-critical-bg)" : trend < 0 ? "var(--accent-ghost)" : "var(--bg-surface)",
                  borderRadius: 6, padding: "2px 6px",
                }}>
                  {trend > 0 ? <ArrowUpRight size={11} /> : trend < 0 ? <ArrowDownRight size={11} /> : <Minus size={11} />}
                  {Math.abs(trend)}%
                </div>
              )}
            </div>
          </>
        )}
      </div>
    </div>
  );
}

/* ─── Severity badge ─── */
function SevBadge({ sev }: { sev: keyof typeof SEV }) {
  const s = SEV[sev];
  return (
    <span style={{
      fontFamily: "'Inter', sans-serif", fontSize: 10, fontWeight: 700, letterSpacing: 0.5,
      color: s.color, background: s.bg, borderRadius: 5, padding: "2px 8px",
      textTransform: "uppercase" as const,
      transition: "transform 0.15s var(--ease-spring)",
    }}>
      {sev}
    </span>
  );
}

/* ─── Score bar ─── */
function ScoreBar({ score }: { score: number }) {
  const pct   = score / 10;
  const color = score >= 900 ? "var(--sev-critical-color)" : score >= 700 ? "var(--sev-high-color)" : "var(--sev-medium-color)";
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
      <div className="progress-track" style={{ width: 64, height: 4 }}>
        <div className="progress-fill" style={{ width: `${pct}%`, background: color }} />
      </div>
      <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, fontWeight: 700, color, minWidth: 36 }}>
        {score}
      </span>
    </div>
  );
}

const TOP_FINDINGS = [
  { id: "VAPT-CRIT-001", title: "Unconstrained Delegation — DC01",      host: "DC01",    score: 970, severity: "CRITICAL" as const, status: "OPEN"          },
  { id: "VAPT-CRIT-002", title: "Kerberoastable svc_backup → DA",       host: "SVC-SQL", score: 920, severity: "CRITICAL" as const, status: "IN_REMEDIATION"},
  { id: "VAPT-CRIT-003", title: "Log4Shell (CVE-2021-44228)",            host: "WEB-01",  score: 910, severity: "CRITICAL" as const, status: "VERIFIED"      },
  { id: "VAPT-HIGH-001", title: "SMB Signing Not Required — 4 Hosts",   host: "WS-042",  score: 730, severity: "HIGH"     as const, status: "OPEN"          },
  { id: "VAPT-HIGH-003", title: "AD CS ESC1 — UserAuthentication Tmpl", host: "corp-CA", score: 720, severity: "HIGH"     as const, status: "OPEN"          },
];

const STATUS_STYLE: Record<string, { color: string; bg: string }> = {
  OPEN:           { color: "var(--sev-critical-color)", bg: "var(--sev-critical-bg)" },
  IN_REVIEW:      { color: "var(--sev-high-color)",     bg: "var(--sev-high-bg)"     },
  IN_REMEDIATION: { color: "var(--accent)",             bg: "var(--accent-ghost)"    },
  VERIFIED:       { color: "var(--accent)",             bg: "var(--accent-ghost)"    },
  CLOSED:         { color: "var(--text-muted)",         bg: "var(--bg-surface)"      },
};

/* ─── Main component ─── */
export function DashboardCharts() {
  const { data, isLoading } = useQuery({
    queryKey: ["engagements"],
    queryFn: () => fetch("/api/engagements").then((r) => r.json()),
  });

  const engagements: Engagement[] = data?.engagements ?? [];
  const timeline: TimelinePoint[]  = data?.timeline ?? [];
  const activity: ActivityItem[]   = data?.activity ?? [];
  const stats = data?.stats ?? {};

  const sevTotals = engagements.reduce(
    (acc, e) => ({
      CRITICAL: acc.CRITICAL + e.findingsBySeverity.CRITICAL,
      HIGH:     acc.HIGH     + e.findingsBySeverity.HIGH,
      MEDIUM:   acc.MEDIUM   + e.findingsBySeverity.MEDIUM,
      LOW:      acc.LOW      + e.findingsBySeverity.LOW,
    }),
    { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 },
  );

  const pieData = (Object.entries(sevTotals) as [keyof typeof SEV, number][])
    .filter(([, v]) => v > 0)
    .map(([name, value]) => ({ name, value, color: SEV[name].color }));

  const activeEngagements = stats.activeEngagements ?? engagements.filter((e) => e.status === "ACTIVE").length;
  const totalFindings     = stats.totalFindings ?? engagements.reduce((s, e) => s + e.findingCount, 0);
  const totalAssets       = stats.totalAssets   ?? engagements.reduce((s, e) => s + e.assetCount, 0);

  const slimTimeline = timeline.map((t, i) => ({
    ...t, displayDate: i % 5 === 0 ? t.date.slice(5) : "",
  }));

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>

      {/* ── KPI Row ── */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 12 }}>
        <KpiCard label="Total Findings"     value={isLoading ? 0 : totalFindings}    icon={<AlertTriangle size={15} />} accentColor="var(--sev-critical-color)" accentGlow="var(--sev-critical-glow)" trend={12}  delay={0}   loading={isLoading} />
        <KpiCard label="Active Engagements" value={isLoading ? 0 : activeEngagements} icon={<TrendingUp    size={15} />} accentColor="var(--accent)"             accentGlow="var(--accent-glow)"       trend={0}   delay={60}  loading={isLoading} />
        <KpiCard label="Assets Discovered"  value={isLoading ? 0 : totalAssets}       icon={<Users         size={15} />} accentColor="var(--sev-medium-color)"   accentGlow="var(--sev-medium-glow)"   trend={8}   delay={120} loading={isLoading} />
        <KpiCard label="KEV Findings"        value={isLoading ? 0 : (stats.kevFindings ?? 3)} icon={<ShieldAlert size={15} />} accentColor="var(--sev-high-color)" accentGlow="var(--sev-high-glow)" trend={2} delay={180} loading={isLoading} />
      </div>

      {/* ── Charts Row ── */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 228px", gap: 12 }}>

        {/* Area chart */}
        <div className="stagger-item" style={{
          animationDelay: "120ms",
          background: "var(--bg-panel)", border: "0.5px solid var(--border-subtle)",
          borderRadius: 14, padding: "20px 20px 14px",
          transition: "border-color 0.18s ease",
        }}
          onMouseEnter={(e) => (e.currentTarget.style.borderColor = "var(--border-strong)")}
          onMouseLeave={(e) => (e.currentTarget.style.borderColor = "var(--border-subtle)")}
        >
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 16 }}>
            <span style={{ fontFamily: "'Inter', sans-serif", fontSize: 13, fontWeight: 600, color: "var(--text-primary)" }}>
              Findings trend
            </span>
            <span style={{ fontFamily: "'Inter', sans-serif", fontSize: 11, color: "var(--text-muted)", background: "var(--bg-surface)", borderRadius: 6, padding: "3px 9px" }}>
              Last 30 days
            </span>
          </div>
          {isLoading ? (
            <Bone w="100%" h={160} />
          ) : (
            <ResponsiveContainer width="100%" height={160}>
              <AreaChart data={slimTimeline} margin={{ top: 4, right: 0, bottom: 0, left: -24 }}>
                <defs>
                  {(["CRITICAL", "HIGH", "MEDIUM"] as const).map((s) => (
                    <linearGradient key={s} id={`grad-${s}`} x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%"  stopColor={SEV[s].color} stopOpacity={0.18} />
                      <stop offset="95%" stopColor={SEV[s].color} stopOpacity={0}   />
                    </linearGradient>
                  ))}
                </defs>
                <XAxis dataKey="displayDate" tick={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, fill: "var(--text-muted)" }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, fill: "var(--text-muted)" }} axisLine={false} tickLine={false} allowDecimals={false} />
                <Tooltip content={<ChartTooltip />} />
                {(["CRITICAL", "HIGH", "MEDIUM"] as const).map((s) => (
                  <Area key={s} type="monotone" dataKey={s} stroke={SEV[s].color} fill={`url(#grad-${s})`} strokeWidth={2} dot={false} animationDuration={800} />
                ))}
              </AreaChart>
            </ResponsiveContainer>
          )}
        </div>

        {/* Donut */}
        <div className="stagger-item" style={{
          animationDelay: "160ms",
          background: "var(--bg-panel)", border: "0.5px solid var(--border-subtle)",
          borderRadius: 14, padding: "20px 16px 16px",
          display: "flex", flexDirection: "column",
          transition: "border-color 0.18s ease",
        }}
          onMouseEnter={(e) => (e.currentTarget.style.borderColor = "var(--border-strong)")}
          onMouseLeave={(e) => (e.currentTarget.style.borderColor = "var(--border-subtle)")}
        >
          <span style={{ fontFamily: "'Inter', sans-serif", fontSize: 13, fontWeight: 600, color: "var(--text-primary)", marginBottom: 8 }}>
            By severity
          </span>
          {isLoading ? (
            <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center" }}>
              <Bone w={96} h={96} radius={48} />
            </div>
          ) : pieData.length === 0 ? (
            <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center", fontFamily: "'Inter', sans-serif", fontSize: 13, color: "var(--text-muted)" }}>
              No data
            </div>
          ) : (
            <>
              <ResponsiveContainer width="100%" height={110}>
                <PieChart>
                  <Pie data={pieData} cx="50%" cy="50%" innerRadius={26} outerRadius={48}
                    dataKey="value" strokeWidth={0} animationBegin={200} animationDuration={800}>
                    {pieData.map((e, i) => <Cell key={i} fill={e.color} />)}
                  </Pie>
                  <Tooltip formatter={(v: number, name: string) => [v, name]}
                    contentStyle={{ background: "var(--bg-sidebar)", border: "0.5px solid var(--border-strong)", fontFamily: "'JetBrains Mono', monospace", fontSize: 10, borderRadius: 10 }} />
                </PieChart>
              </ResponsiveContainer>
              <div style={{ display: "flex", flexDirection: "column", gap: 7, marginTop: 4 }}>
                {pieData.map((d) => (
                  <div key={d.name} style={{ display: "flex", alignItems: "center", gap: 8, padding: "3px 4px", borderRadius: 6, transition: "background 0.15s ease", cursor: "default" }}
                    onMouseEnter={(e) => (e.currentTarget.style.background = "var(--bg-surface)")}
                    onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
                  >
                    <div style={{ width: 8, height: 8, borderRadius: 2, background: d.color, flexShrink: 0 }} />
                    <span style={{ fontFamily: "'Inter', sans-serif", fontSize: 11, color: "var(--text-secondary)", flex: 1 }}>{d.name}</span>
                    <span style={{ fontFamily: "'Inter', sans-serif", fontSize: 13, fontWeight: 700, color: d.color }}>{d.value}</span>
                  </div>
                ))}
              </div>
            </>
          )}
        </div>
      </div>

      {/* ── Findings + Activity ── */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 280px", gap: 12 }}>

        {/* Top findings table */}
        <div className="stagger-item" style={{
          animationDelay: "200ms",
          background: "var(--bg-panel)", border: "0.5px solid var(--border-subtle)",
          borderRadius: 14, overflow: "hidden",
          transition: "border-color 0.18s ease",
        }}
          onMouseEnter={(e) => (e.currentTarget.style.borderColor = "var(--border-strong)")}
          onMouseLeave={(e) => (e.currentTarget.style.borderColor = "var(--border-subtle)")}
        >
          <div style={{ padding: "14px 20px", borderBottom: "0.5px solid var(--border-subtle)", display: "flex", alignItems: "center", justifyContent: "space-between" }}>
            <span style={{ fontFamily: "'Inter', sans-serif", fontSize: 13, fontWeight: 600, color: "var(--text-primary)" }}>
              Critical findings
            </span>
            <Link href="/findings" style={{
              display: "flex", alignItems: "center", gap: 4,
              fontFamily: "'Inter', sans-serif", fontSize: 12, fontWeight: 500,
              color: "var(--accent)", textDecoration: "none",
              transition: "opacity 0.15s ease",
            }}
              onMouseEnter={(e) => (e.currentTarget.style.opacity = "0.7")}
              onMouseLeave={(e) => (e.currentTarget.style.opacity = "1")}
            >
              View all <ArrowUpRight size={12} />
            </Link>
          </div>

          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr style={{ background: "var(--bg-sidebar)" }}>
                {["Title", "Host", "Risk Score", "Status"].map((h) => (
                  <th key={h} style={{
                    padding: "8px 20px", textAlign: "left",
                    fontFamily: "'Inter', sans-serif", fontSize: 11, fontWeight: 600,
                    color: "var(--text-muted)", letterSpacing: 0.3,
                    borderBottom: "0.5px solid var(--border-subtle)",
                  }}>
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {TOP_FINDINGS.map((f, i) => {
                const ss = STATUS_STYLE[f.status] ?? STATUS_STYLE.OPEN;
                return (
                  <tr key={f.id} className="table-row-hover stagger-item" style={{
                    animationDelay: `${240 + i * 40}ms`,
                    borderBottom: i < TOP_FINDINGS.length - 1 ? "0.5px solid var(--border-subtle)" : "none",
                    cursor: "pointer",
                  }}>
                    <td style={{ padding: "11px 20px", maxWidth: 280 }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 9 }}>
                        <SevBadge sev={f.severity} />
                        <span style={{ fontFamily: "'Inter', sans-serif", fontSize: 13, color: "var(--text-primary)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                          {f.title}
                        </span>
                      </div>
                    </td>
                    <td style={{ padding: "11px 20px" }}>
                      <span style={{
                        fontFamily: "'JetBrains Mono', monospace", fontSize: 11,
                        color: "var(--accent)", background: "var(--accent-ghost)",
                        borderRadius: 5, padding: "2px 7px",
                      }}>
                        {f.host}
                      </span>
                    </td>
                    <td style={{ padding: "11px 20px" }}>
                      <ScoreBar score={f.score} />
                    </td>
                    <td style={{ padding: "11px 20px" }}>
                      <span style={{
                        fontFamily: "'Inter', sans-serif", fontSize: 11, fontWeight: 600,
                        color: ss.color, background: ss.bg, borderRadius: 5, padding: "3px 8px",
                      }}>
                        {f.status.replace(/_/g, " ")}
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        {/* Activity feed */}
        <div className="stagger-item" style={{
          animationDelay: "240ms",
          background: "var(--bg-panel)", border: "0.5px solid var(--border-subtle)",
          borderRadius: 14, overflow: "hidden", display: "flex", flexDirection: "column",
          transition: "border-color 0.18s ease",
        }}
          onMouseEnter={(e) => (e.currentTarget.style.borderColor = "var(--border-strong)")}
          onMouseLeave={(e) => (e.currentTarget.style.borderColor = "var(--border-subtle)")}
        >
          <div style={{ padding: "14px 16px", borderBottom: "0.5px solid var(--border-subtle)", display: "flex", alignItems: "center", justifyContent: "space-between", flexShrink: 0 }}>
            <span style={{ fontFamily: "'Inter', sans-serif", fontSize: 13, fontWeight: 600, color: "var(--text-primary)" }}>
              Recent activity
            </span>
            <Link href="/engagements" style={{ fontFamily: "'Inter', sans-serif", fontSize: 12, fontWeight: 500, color: "var(--accent)", textDecoration: "none" }}>
              All →
            </Link>
          </div>
          <div style={{ overflowY: "auto", flex: 1 }}>
            {isLoading ? (
              [1, 2, 3, 4].map((i) => (
                <div key={i} style={{ padding: "12px 16px", borderBottom: "0.5px solid var(--border-subtle)" }}>
                  <Bone w="75%" h={10} /><div style={{ marginTop: 5 }}><Bone w="55%" h={8} /></div>
                </div>
              ))
            ) : activity.length === 0 ? (
              <div style={{ padding: "36px 16px", textAlign: "center", fontFamily: "'Inter', sans-serif", fontSize: 13, color: "var(--text-muted)" }}>
                No recent activity
              </div>
            ) : (
              activity.slice(0, 8).map((a, i) => (
                <div key={a.id} className="stagger-item"
                  style={{
                    animationDelay: `${280 + i * 35}ms`,
                    padding: "11px 16px",
                    borderBottom: i < Math.min(activity.length, 8) - 1 ? "0.5px solid var(--border-subtle)" : "none",
                    display: "flex", gap: 10, cursor: "default",
                    transition: "background 0.12s ease",
                  }}
                  onMouseEnter={(e) => (e.currentTarget.style.background = "var(--bg-surface)")}
                  onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
                >
                  <div style={{ width: 6, height: 6, borderRadius: "50%", background: "var(--accent)", marginTop: 4, flexShrink: 0 }} />
                  <div style={{ minWidth: 0 }}>
                    <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 11, fontWeight: 600, color: "var(--accent)", marginBottom: 2 }}>{a.action}</div>
                    <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 12, color: "var(--text-primary)", lineHeight: 1.4, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{a.detail}</div>
                    <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--text-muted)", marginTop: 2 }}>
                      {new Date(a.timestamp).toLocaleString()}
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

    </div>
  );
}
