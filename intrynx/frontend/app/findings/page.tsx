"use client";

import React, { useState, useMemo, useCallback } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Copy, Check, Search, CheckCircle, Shield,
  ArrowUpDown, Link2, Brain, Tag,
} from "lucide-react";
import { PageShell } from "../../components/PageShell";
import { useToast } from "../../hooks/useToast";
import { fetchJson, isUnauthorized } from "../../lib/fetcher";
import { DataState, SkeletonRows, EmptyState } from "../../components/states/DataState";

/* ─── Types ─── */
type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
type FindingStatus = "OPEN" | "IN_REVIEW" | "IN_REMEDIATION" | "VERIFIED" | "CLOSED" | "ACCEPTED" | "FALSE_POSITIVE";
type ExploitMaturity = "WEAPONIZED" | "POC" | "THEORETICAL";
type DetectionCoverage = "COVERED" | "PARTIAL" | "BLIND";

interface RemStep {
  step: number; title: string; command?: string;
  description: string; estimatedHours: number;
  verification?: string; completed: boolean; completedBy?: string;
}
interface ComplianceRef { framework: string; refs: string[]; }
interface RiskBreakdown {
  cvss: number; epss: number; kev: number;
  exploit: number; asset: number; lateral: number;
}
interface KillChainStep {
  phase: string; technique: string; description: string; mitre?: string;
}
interface Finding {
  id: string; title: string; severity: Severity; cvss: string; cvssVector: string;
  category: string; status: FindingStatus; affectedHost: string; discoveredAt: string;
  description: string; technicalDetails: string; attackPath: string;
  evidence: { label: string; content: string }[];
  impact: string; businessImpact?: string;
  exploitability?: "EASY" | "MODERATE" | "DIFFICULT";
  remediation: (string | RemStep)[];
  compliance: ComplianceRef[];
  mitre: { id: string; name: string }[];
  riskScore: number;
  riskBreakdown: RiskBreakdown;
  epssScore: number;
  epssPercentile: number;
  kevListed: boolean;
  kevDateAdded?: string;
  exploitMaturity: ExploitMaturity;
  pocAvailable: boolean;
  activelyExploited: boolean;
  detectionCoverage: DetectionCoverage;
  detectionNote?: string;
  fpProbability: number;
  relatedFindings?: string[];
  killChain: KillChainStep[];
  assignee?: string;
  tags?: string[];
  aiTriage: { priority: "P0" | "P1" | "P2" | "P3"; reasoning: string; recommendation: string; confidence: number };
}

/* ─── Color Maps ─── */
const SEV_COLOR: Record<Severity, string> = {
  CRITICAL: "#FF1744", HIGH: "#FF6D00", MEDIUM: "#FFD600", LOW: "#00E676", INFO: "#0284C7",
};
const STATUS_COLOR: Record<FindingStatus, string> = {
  OPEN: "#FF1744", IN_REVIEW: "#FF9900", IN_REMEDIATION: "#2563EB",
  VERIFIED: "#059669", CLOSED: "#64748B", ACCEPTED: "#9C27B0", FALSE_POSITIVE: "#64748B",
};
const STATUS_LABEL: Record<FindingStatus, string> = {
  OPEN: "OPEN", IN_REVIEW: "IN REVIEW", IN_REMEDIATION: "REMEDIATING",
  VERIFIED: "VERIFIED", CLOSED: "CLOSED", ACCEPTED: "ACCEPTED", FALSE_POSITIVE: "FALSE POS.",
};
const MATURITY_COLOR: Record<ExploitMaturity, string> = {
  WEAPONIZED: "#FF1744", POC: "#FF6D00", THEORETICAL: "#64748B",
};
const COVERAGE_COLOR: Record<DetectionCoverage, string> = {
  COVERED: "#059669", PARTIAL: "#FFD600", BLIND: "#FF1744",
};
const PRIORITY_COLOR: Record<string, string> = {
  P0: "#FF1744", P1: "#FF6D00", P2: "#FFD600", P3: "#64748B",
};
const KILL_CHAIN_PHASE_COLOR: Record<string, string> = {
  "Reconnaissance": "#64748B", "Initial Access": "#FF6D00", "Execution": "#FF1744",
  "Persistence": "#9C27B0", "Privilege Escalation": "#FF1744", "Defense Evasion": "#FFD600",
  "Credential Access": "#FF6D00", "Discovery": "#2563EB", "Lateral Movement": "#FF6D00",
  "Collection": "#2563EB", "Exfiltration": "#FF1744", "Impact": "#FF1744",
};

/* ─── SLA helpers ─── */
const SLA_HOURS: Partial<Record<Severity, number>> = { CRITICAL: 24, HIGH: 72, MEDIUM: 168, LOW: 720 };

function getSlaColor(discoveredAt: string, severity: Severity) {
  const slaH = SLA_HOURS[severity];
  if (!slaH) return { color: "var(--adv-text-muted)", label: "N/A", pct: 100 };
  const due = new Date(discoveredAt).getTime() + slaH * 3_600_000;
  const now = Date.now();
  const leftMs = due - now;
  const pct = Math.max(0, Math.min(100, (leftMs / (slaH * 3_600_000)) * 100));
  if (now > due) return { color: "#FF1744", label: "BREACHED", pct: 0 };
  const h = Math.round(leftMs / 3_600_000);
  const label = h < 24 ? `${h}h` : `${Math.round(h / 24)}d`;
  const color = pct < 10 ? "#FF1744" : pct < 25 ? "#FF6D00" : pct < 50 ? "#FFD600" : "#00E676";
  return { color, label, pct };
}

function riskScoreColor(score: number): string {
  if (score >= 800) return "#FF1744";
  if (score >= 600) return "#FF6D00";
  if (score >= 400) return "#FFD600";
  return "#00E676";
}


/* ─── Copy Button ─── */
function CopyBtn({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button onClick={() => { navigator.clipboard.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 2000); }}
      style={{ background: "none", border: "none", cursor: "pointer", color: copied ? "#059669" : "#64748B", padding: "2px 4px" }}>
      {copied ? <Check size={12} /> : <Copy size={12} />}
    </button>
  );
}

/* ─── Severity Badge ─── */
function SevBadge({ s }: { s: Severity }) {
  return (
    <span style={{
      fontFamily: "'JetBrains Mono', monospace", fontSize: 10, padding: "2px 8px", borderRadius: 4,
      background: `${SEV_COLOR[s]}15`, color: SEV_COLOR[s], border: `1px solid ${SEV_COLOR[s]}30`,
    }}>{s}</span>
  );
}

/* ─── Risk Score Badge ─── */
function RiskBadge({ score }: { score: number }) {
  const c = riskScoreColor(score);
  return (
    <span style={{
      fontFamily: "'JetBrains Mono', monospace", fontSize: 10, padding: "2px 8px", borderRadius: 4,
      background: `${c}15`, color: c, border: `1px solid ${c}30`, fontWeight: 700,
    }}>
      RISK {score}
    </span>
  );
}

/* ─── KEV Badge ─── */
function KevBadge() {
  return (
    <span style={{
      fontFamily: "'JetBrains Mono', monospace", fontSize: 9, padding: "2px 6px", borderRadius: 4,
      background: "rgba(255,23,68,0.15)", color: "#FF1744", border: "1px solid rgba(255,23,68,0.35)",
      fontWeight: 700, letterSpacing: 0.5,
    }}>
      ⚠ KEV
    </span>
  );
}

/* ─── Status Badge ─── */
function StatusBadge({ s, onClick }: { s: FindingStatus; onClick?: () => void }) {
  return (
    <span onClick={onClick} style={{
      fontFamily: "'JetBrains Mono', monospace", fontSize: 10, padding: "2px 8px", borderRadius: 4,
      background: `${STATUS_COLOR[s]}12`, color: STATUS_COLOR[s], border: `1px solid ${STATUS_COLOR[s]}30`,
      cursor: onClick ? "pointer" : "default",
    }}>
      {STATUS_LABEL[s]}
    </span>
  );
}

/* ─── Detection Coverage Pill ─── */
function DetectionPill({ cov }: { cov: DetectionCoverage }) {
  const c = COVERAGE_COLOR[cov];
  const icon = cov === "COVERED" ? "◉" : cov === "PARTIAL" ? "◑" : "○";
  return (
    <span style={{
      fontFamily: "'JetBrains Mono', monospace", fontSize: 9, padding: "2px 6px", borderRadius: 4,
      background: `${c}12`, color: c, border: `1px solid ${c}30`,
    }}>
      {icon} {cov}
    </span>
  );
}

/* ─── EPSS Bar ─── */
function EpssBar({ score, percentile }: { score: number; percentile: number }) {
  const pct = Math.round(score * 100);
  const color = score > 0.7 ? "#FF1744" : score > 0.4 ? "#FF6D00" : score > 0.1 ? "#FFD600" : "#64748B";
  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 3 }}>
        <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color }}>
          EPSS {(score * 100).toFixed(1)}%
        </span>
        <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)" }}>
          {Math.round(percentile * 100)}th pct
        </span>
      </div>
      <div style={{ height: 4, background: "rgba(100,116,139,0.2)", borderRadius: 2, overflow: "hidden" }}>
        <div style={{ height: "100%", width: `${pct}%`, background: color, borderRadius: 2, transition: "width 0.4s ease" }} />
      </div>
    </div>
  );
}

/* ─── Risk Score Breakdown ─── */
function RiskBreakdownBar({ breakdown, total }: { breakdown: RiskBreakdown; total: number }) {
  const segments = [
    { key: "cvss",    label: "CVSS",    color: "#FF6D00", value: breakdown.cvss },
    { key: "epss",    label: "EPSS",    color: "#2563EB", value: breakdown.epss },
    { key: "kev",     label: "KEV",     color: "#FF1744", value: breakdown.kev },
    { key: "exploit", label: "EXPLOIT", color: "#9C27B0", value: breakdown.exploit },
    { key: "asset",   label: "ASSET",   color: "#FFD600", value: breakdown.asset },
    { key: "lateral", label: "LATERAL", color: "#00E676", value: breakdown.lateral },
  ];
  return (
    <div>
      <div style={{ height: 8, display: "flex", borderRadius: 4, overflow: "hidden", marginBottom: 6 }}>
        {segments.map((s) => (
          <div key={s.key} style={{ width: `${(s.value / 1000) * 100}%`, background: s.color }} title={`${s.label}: ${s.value}`} />
        ))}
      </div>
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
        {segments.map((s) => (
          <div key={s.key} style={{ display: "flex", alignItems: "center", gap: 4 }}>
            <div style={{ width: 6, height: 6, borderRadius: 1, background: s.color }} />
            <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)" }}>
              {s.label} {s.value}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ─── Kill Chain Visualization ─── */
function KillChainViz({ steps }: { steps: KillChainStep[] }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 0 }}>
      {steps.map((step, i) => {
        const color = KILL_CHAIN_PHASE_COLOR[step.phase] ?? "#64748B";
        return (
          <div key={i} style={{ display: "flex", gap: 0, alignItems: "stretch" }}>
            {/* Timeline line */}
            <div style={{ display: "flex", flexDirection: "column", alignItems: "center", width: 24, flexShrink: 0 }}>
              <div style={{
                width: 10, height: 10, borderRadius: "50%", background: color,
                border: `2px solid ${color}40`, flexShrink: 0, marginTop: 4, zIndex: 1,
                boxShadow: `0 0 6px ${color}60`,
              }} />
              {i < steps.length - 1 && (
                <div style={{ width: 1, flex: 1, background: `${color}30`, minHeight: 16 }} />
              )}
            </div>
            {/* Step content */}
            <div style={{ flex: 1, paddingBottom: i < steps.length - 1 ? 10 : 0, paddingLeft: 8 }}>
              <div style={{ display: "flex", gap: 6, alignItems: "center", marginBottom: 2 }}>
                <span style={{
                  fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color,
                  background: `${color}12`, border: `1px solid ${color}25`,
                  padding: "1px 5px", borderRadius: 3,
                }}>{step.phase}</span>
                {step.mitre && (
                  <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-accent)" }}>
                    {step.mitre}
                  </span>
                )}
              </div>
              <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 12, fontWeight: 600, color: "var(--adv-text)", marginBottom: 1 }}>
                {step.technique}
              </div>
              <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 11, color: "var(--adv-text-muted)", lineHeight: 1.4 }}>
                {step.description}
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}

/* ─── Remediation Checklist ─── */
function RemediationChecklist({ steps, findingId }: { steps: (string | RemStep)[]; findingId: string }) {
  const [checks, setChecks] = useState<Record<string, boolean>>(() => {
    const init: Record<string, boolean> = {};
    steps.forEach((s, i) => { if (typeof s !== "string") init[`${findingId}-${i}`] = s.completed; });
    return init;
  });
  const toggle = (key: string) => setChecks((p) => ({ ...p, [key]: !p[key] }));

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
      {steps.map((s, i) => {
        if (typeof s === "string") {
          const key = `${findingId}-${i}`;
          return (
            <div key={i} style={{ display: "flex", gap: 10, alignItems: "flex-start" }}>
              <div onClick={() => toggle(key)} style={{
                width: 16, height: 16, borderRadius: 4, flexShrink: 0, marginTop: 2, cursor: "pointer",
                background: checks[key] ? "rgba(5,150,105,0.2)" : "transparent",
                border: `1.5px solid ${checks[key] ? "#059669" : "#E2E8F0"}`,
                display: "flex", alignItems: "center", justifyContent: "center",
              }}>
                {checks[key] && <Check size={10} color="#059669" />}
              </div>
              <span style={{ fontFamily: "'Inter', sans-serif", fontSize: 13, color: checks[key] ? "#64748B" : "var(--adv-text)", textDecoration: checks[key] ? "line-through" : "none", lineHeight: 1.5 }}>{s}</span>
            </div>
          );
        }
        const key = `${findingId}-${i}`;
        const done = checks[key] ?? s.completed;
        return (
          <div key={i} style={{ background: "var(--adv-bg)", border: `1px solid ${done ? "rgba(5,150,105,0.2)" : "var(--adv-border)"}`, borderRadius: 6, padding: "10px 12px" }}>
            <div style={{ display: "flex", gap: 10, alignItems: "flex-start", marginBottom: s.command ? 8 : 0 }}>
              <div onClick={() => toggle(key)} style={{
                width: 16, height: 16, borderRadius: 4, flexShrink: 0, marginTop: 2, cursor: "pointer",
                background: done ? "rgba(5,150,105,0.2)" : "transparent",
                border: `1.5px solid ${done ? "#059669" : "#E2E8F0"}`,
                display: "flex", alignItems: "center", justifyContent: "center",
              }}>
                {done && <Check size={10} color="#059669" />}
              </div>
              <div style={{ flex: 1 }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <span style={{ fontFamily: "'Inter', sans-serif", fontSize: 13, fontWeight: 600, color: done ? "#64748B" : "var(--adv-text)", textDecoration: done ? "line-through" : "none" }}>
                    Step {s.step}: {s.title}
                  </span>
                  <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)" }}>~{s.estimatedHours}h</span>
                </div>
                <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 12, color: "var(--adv-text-muted)", marginTop: 2 }}>{s.description}</div>
              </div>
            </div>
            {s.command && (
              <div style={{ background: "var(--adv-panel)", borderRadius: 4, padding: "6px 10px", display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: 4 }}>
                <code style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-accent)", flex: 1, whiteSpace: "pre-wrap", wordBreak: "break-all" }}>{s.command}</code>
                <CopyBtn text={s.command} />
              </div>
            )}
            {s.verification && (
              <div style={{ marginTop: 4, display: "flex", gap: 6, alignItems: "center" }}>
                <CheckCircle size={10} color="#059669" />
                <code style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "#059669" }}>Verify: {s.verification}</code>
              </div>
            )}
            {s.completedBy && (
              <div style={{ marginTop: 4, fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "#059669" }}>
                ✓ Completed by {s.completedBy}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

/* ─── Finding Detail ─── */
function FindingDetail({ f, allFindings, onStatusChange }: {
  f: Finding; allFindings: Finding[]; onStatusChange: (id: string, s: FindingStatus) => void;
}) {
  const [tab, setTab] = useState<"overview" | "intel" | "evidence" | "remediation" | "compliance">("overview");
  const sla = getSlaColor(f.discoveredAt, f.severity);

  const WORKFLOW: { status: FindingStatus; label: string; color: string }[] = [
    { status: "IN_REVIEW",      label: "In Review",    color: "#FF9900" },
    { status: "IN_REMEDIATION", label: "Remediation",  color: "var(--adv-accent)" },
    { status: "VERIFIED",       label: "Verified",     color: "#059669" },
    { status: "ACCEPTED",       label: "Accept Risk",  color: "#9C27B0" },
    { status: "FALSE_POSITIVE", label: "False Pos.",   color: "var(--adv-text-muted)" },
  ];

  const related = allFindings.filter((r) => r.id !== f.id && (f.relatedFindings ?? []).includes(r.id));
  const pc = PRIORITY_COLOR[f.aiTriage.priority];

  return (
    <div className="animate-scale-in" style={{ background: "var(--adv-bg)", border: "1px solid var(--adv-border)", borderRadius: 8, overflow: "hidden" }}>

      {/* ── Header ── */}
      <div style={{ padding: "14px 18px", borderBottom: "1px solid var(--adv-border)", background: `linear-gradient(135deg, ${SEV_COLOR[f.severity]}08 0%, transparent 60%)` }}>
        <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 8, alignItems: "center" }}>
          <SevBadge s={f.severity} />
          <StatusBadge s={f.status} />
          <RiskBadge score={f.riskScore} />
          {f.kevListed && <KevBadge />}
          <span style={{
            fontFamily: "'JetBrains Mono', monospace", fontSize: 9,
            color: pc, background: `${pc}15`, border: `1px solid ${pc}30`,
            borderRadius: 4, padding: "2px 6px", fontWeight: 700,
          }}>
            {f.aiTriage.priority}
          </span>
          <DetectionPill cov={f.detectionCoverage} />
          <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: MATURITY_COLOR[f.exploitMaturity], background: `${MATURITY_COLOR[f.exploitMaturity]}12`, border: `1px solid ${MATURITY_COLOR[f.exploitMaturity]}25`, borderRadius: 4, padding: "2px 6px" }}>
            {f.exploitMaturity}
          </span>
          <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: sla.color, background: `${sla.color}10`, border: `1px solid ${sla.color}25`, borderRadius: 4, padding: "2px 6px" }}>
            SLA {sla.label}
          </span>
        </div>
        <h2 style={{ fontFamily: "'Inter', sans-serif", fontSize: 17, fontWeight: 700, color: "var(--adv-text)", margin: 0, lineHeight: 1.3 }}>{f.title}</h2>
        <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-text-muted)", marginTop: 5 }}>
          {f.id} · {f.category} · {f.affectedHost}
          {f.assignee && <span style={{ color: "var(--adv-accent)", marginLeft: 8 }}>@{f.assignee}</span>}
        </div>

        {/* Risk breakdown bar */}
        <div style={{ marginTop: 10 }}>
          <RiskBreakdownBar breakdown={f.riskBreakdown} total={f.riskScore} />
        </div>

        {/* Business impact */}
        {f.businessImpact && (
          <div style={{ marginTop: 10, padding: "7px 10px", background: `${SEV_COLOR[f.severity]}08`, border: `1px solid ${SEV_COLOR[f.severity]}18`, borderRadius: 5 }}>
            <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: SEV_COLOR[f.severity] }}>BUSINESS IMPACT</span>
            <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 12, color: "var(--adv-text)", marginTop: 3 }}>{f.businessImpact}</div>
          </div>
        )}
      </div>

      {/* ── AI Triage Panel ── */}
      <div style={{ padding: "10px 18px", borderBottom: "1px solid var(--adv-border)", background: "rgba(37,99,235,0.03)" }}>
        <div style={{ display: "flex", gap: 6, alignItems: "flex-start" }}>
          <Brain size={13} color="var(--adv-accent)" style={{ flexShrink: 0, marginTop: 1 }} />
          <div style={{ flex: 1 }}>
            <div style={{ display: "flex", gap: 6, alignItems: "center", marginBottom: 4 }}>
              <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-accent)" }}>AI TRIAGE</span>
              <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)" }}>
                {Math.round(f.aiTriage.confidence * 100)}% confidence
              </span>
            </div>
            <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 12, color: "var(--adv-text)", lineHeight: 1.5, marginBottom: 5 }}>{f.aiTriage.reasoning}</div>
            <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 12, color: "#059669", lineHeight: 1.5 }}>
              <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "#059669" }}>RECOMMEND: </span>
              {f.aiTriage.recommendation}
            </div>
          </div>
        </div>
      </div>

      {/* ── Workflow ── */}
      <div style={{ padding: "8px 18px", borderBottom: "1px solid var(--adv-border)", display: "flex", gap: 5, flexWrap: "wrap", alignItems: "center" }}>
        <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)" }}>ADVANCE:</span>
        {WORKFLOW.map((w) => (
          <button key={w.status} onClick={() => onStatusChange(f.id, w.status)} disabled={f.status === w.status} style={{
            padding: "3px 9px", borderRadius: 4, cursor: f.status === w.status ? "default" : "pointer",
            border: `1px solid ${f.status === w.status ? "var(--adv-border)" : `${w.color}45`}`,
            background: f.status === w.status ? "transparent" : `${w.color}10`,
            color: f.status === w.status ? "var(--adv-text-muted)" : w.color,
            fontFamily: "'JetBrains Mono', monospace", fontSize: 9, opacity: f.status === w.status ? 0.5 : 1,
          }}>{w.label}</button>
        ))}
      </div>

      {/* ── Tabs ── */}
      <div style={{ display: "flex", borderBottom: "1px solid var(--adv-border)", overflowX: "auto" }}>
        {(["overview", "intel", "evidence", "remediation", "compliance"] as const).map((t) => (
          <button key={t} onClick={() => setTab(t)} style={{
            padding: "8px 14px", background: tab === t ? "rgba(37,99,235,0.04)" : "transparent",
            border: "none", borderBottom: tab === t ? "2px solid #2563EB" : "2px solid transparent",
            color: tab === t ? "var(--adv-text)" : "var(--adv-text-muted)",
            fontFamily: "'JetBrains Mono', monospace", fontSize: 10, letterSpacing: 0.8,
            cursor: "pointer", textTransform: "uppercase", whiteSpace: "nowrap",
          }}>
            {t === "remediation" ? `Remediaton (${f.remediation.length})` : t === "intel" ? "Threat Intel" : t}
          </button>
        ))}
      </div>

      <div style={{ padding: "16px 18px" }}>

        {/* Overview tab */}
        {tab === "overview" && (
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
            <div>
              <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", marginBottom: 5 }}>DESCRIPTION</div>
              <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 13, color: "var(--adv-text)", lineHeight: 1.6, marginBottom: 14 }}>{f.description}</div>

              <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", marginBottom: 8 }}>KILL CHAIN</div>
              <KillChainViz steps={f.killChain} />

              {related.length > 0 && (
                <div style={{ marginTop: 14 }}>
                  <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", marginBottom: 6 }}>
                    <Link2 size={10} style={{ display: "inline", marginRight: 4 }} />CORRELATED FINDINGS
                  </div>
                  {related.map((r) => (
                    <div key={r.id} style={{ display: "flex", gap: 6, alignItems: "center", padding: "5px 8px", background: "var(--adv-panel)", borderRadius: 4, marginBottom: 4 }}>
                      <div style={{ width: 6, height: 6, borderRadius: "50%", background: SEV_COLOR[r.severity], flexShrink: 0 }} />
                      <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-accent)" }}>{r.id}</span>
                      <span style={{ fontFamily: "'Inter', sans-serif", fontSize: 11, color: "var(--adv-text)", flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{r.title}</span>
                      <RiskBadge score={r.riskScore} />
                    </div>
                  ))}
                </div>
              )}
            </div>
            <div>
              <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", marginBottom: 5 }}>TECHNICAL DETAILS</div>
              <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 13, color: "var(--adv-text)", lineHeight: 1.6, marginBottom: 12 }}>{f.technicalDetails}</div>

              <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", marginBottom: 6 }}>MITRE ATT&CK</div>
              {f.mitre.map((m) => (
                <div key={m.id} style={{ display: "flex", gap: 8, marginBottom: 4, alignItems: "center" }}>
                  <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-accent)", flexShrink: 0 }}>{m.id}</span>
                  <span style={{ fontFamily: "'Inter', sans-serif", fontSize: 12, color: "var(--adv-text-muted)" }}>{m.name}</span>
                </div>
              ))}

              <div style={{ marginTop: 12 }}>
                <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", marginBottom: 5 }}>CVSS VECTOR</div>
                <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text)", background: "var(--adv-panel)", padding: "6px 10px", borderRadius: 4, wordBreak: "break-all", lineHeight: 1.5 }}>
                  {f.cvssVector}
                </div>
              </div>

              {f.tags && f.tags.length > 0 && (
                <div style={{ marginTop: 12 }}>
                  <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", marginBottom: 5 }}>
                    <Tag size={9} style={{ display: "inline", marginRight: 4 }} />TAGS
                  </div>
                  <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                    {f.tags.map((t) => (
                      <span key={t} style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", background: "var(--adv-panel)", border: "1px solid var(--adv-border)", borderRadius: 3, padding: "1px 5px" }}>{t}</span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Threat Intel tab */}
        {tab === "intel" && (
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
            {/* Left: scores */}
            <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
              {/* EPSS */}
              <div style={{ background: "var(--adv-panel)", border: "1px solid var(--adv-border)", borderRadius: 6, padding: "12px 14px" }}>
                <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", marginBottom: 8 }}>
                  EPSS · EXPLOIT PREDICTION SCORING
                </div>
                <EpssBar score={f.epssScore} percentile={f.epssPercentile} />
                <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 11, color: "var(--adv-text-muted)", marginTop: 8, lineHeight: 1.4 }}>
                  {f.epssScore > 0.5
                    ? `Top ${(100 - f.epssPercentile * 100).toFixed(1)}% most likely to be exploited in the next 30 days (FIRST.org model).`
                    : `Moderate exploitation probability. Monitor EPSS trend weekly.`}
                </div>
              </div>

              {/* CISA KEV */}
              <div style={{ background: "var(--adv-panel)", border: `1px solid ${f.kevListed ? "rgba(255,23,68,0.2)" : "var(--adv-border)"}`, borderRadius: 6, padding: "12px 14px" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4 }}>
                  <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)" }}>CISA KEV STATUS</div>
                  {f.kevListed ? <KevBadge /> : (
                    <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "#64748B", background: "rgba(100,116,139,0.1)", border: "1px solid rgba(100,116,139,0.2)", borderRadius: 3, padding: "1px 5px" }}>NOT LISTED</span>
                  )}
                </div>
                {f.kevListed && f.kevDateAdded && (
                  <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "#FF1744" }}>Added {f.kevDateAdded}</div>
                )}
                <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 11, color: "var(--adv-text-muted)", marginTop: 6, lineHeight: 1.4 }}>
                  {f.kevListed
                    ? "Actively exploited in the wild per CISA. Mandatory patching deadline applies to federal agencies. Treat as highest priority."
                    : "Not in CISA KEV catalog. Monitor for future addition if CVSS ≥ 7.0 and exploitation observed."}
                </div>
              </div>

              {/* FP probability */}
              <div style={{ background: "var(--adv-panel)", border: "1px solid var(--adv-border)", borderRadius: 6, padding: "12px 14px" }}>
                <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", marginBottom: 6 }}>FALSE POSITIVE PROBABILITY</div>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <div style={{ height: 4, flex: 1, background: "rgba(100,116,139,0.2)", borderRadius: 2, overflow: "hidden", marginRight: 10 }}>
                    <div style={{ height: "100%", width: `${f.fpProbability * 100}%`, background: f.fpProbability < 0.1 ? "#059669" : f.fpProbability < 0.3 ? "#FFD600" : "#FF1744", borderRadius: 2 }} />
                  </div>
                  <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: f.fpProbability < 0.1 ? "#059669" : "#FFD600", fontWeight: 700, flexShrink: 0 }}>
                    {Math.round(f.fpProbability * 100)}%
                  </span>
                </div>
                <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 11, color: "var(--adv-text-muted)", marginTop: 5 }}>
                  {f.fpProbability < 0.1 ? "Very low FP probability — finding confirmed via exploitation evidence." : f.fpProbability < 0.3 ? "Moderate — correlate with additional evidence before closing." : "Elevated — validate before remediation investment."}
                </div>
              </div>
            </div>

            {/* Right: exploit intel + detection */}
            <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
              {/* Exploit maturity */}
              <div style={{ background: "var(--adv-panel)", border: `1px solid ${MATURITY_COLOR[f.exploitMaturity]}22`, borderRadius: 6, padding: "12px 14px" }}>
                <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", marginBottom: 8 }}>EXPLOIT INTELLIGENCE</div>
                <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginBottom: 8 }}>
                  <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
                    <div style={{ width: 8, height: 8, borderRadius: "50%", background: MATURITY_COLOR[f.exploitMaturity], boxShadow: `0 0 6px ${MATURITY_COLOR[f.exploitMaturity]}` }} />
                    <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: MATURITY_COLOR[f.exploitMaturity] }}>{f.exploitMaturity}</span>
                  </div>
                  {f.pocAvailable && (
                    <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "#FF6D00", background: "rgba(255,109,0,0.1)", border: "1px solid rgba(255,109,0,0.2)", borderRadius: 3, padding: "1px 5px" }}>
                      PoC PUBLIC
                    </span>
                  )}
                  {f.activelyExploited && (
                    <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "#FF1744", background: "rgba(255,23,68,0.12)", border: "1px solid rgba(255,23,68,0.25)", borderRadius: 3, padding: "1px 5px" }}>
                      ACTIVE EXPLOITATION
                    </span>
                  )}
                </div>
                <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 11, color: "var(--adv-text-muted)", lineHeight: 1.4 }}>
                  {f.exploitMaturity === "WEAPONIZED"
                    ? "Weaponized exploit available in public toolchains (Metasploit/Sliver/Cobalt Strike). Exploitation is trivial for any attacker."
                    : f.exploitMaturity === "POC"
                    ? "Proof-of-concept code publicly available. Requires adaptation for production exploit but significantly lowers attacker barrier."
                    : "No public exploit code. Theoretical attack path — requires custom exploit development."}
                </div>
              </div>

              {/* Detection coverage */}
              <div style={{ background: "var(--adv-panel)", border: `1px solid ${COVERAGE_COLOR[f.detectionCoverage]}22`, borderRadius: 6, padding: "12px 14px" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
                  <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)" }}>DETECTION COVERAGE</div>
                  <DetectionPill cov={f.detectionCoverage} />
                </div>
                {f.detectionNote && (
                  <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 11, color: "var(--adv-text-muted)", lineHeight: 1.4, marginBottom: 8 }}>{f.detectionNote}</div>
                )}
                <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                  {f.mitre.map((m) => (
                    <div key={m.id} style={{ display: "flex", gap: 6, alignItems: "center", padding: "3px 6px", background: "var(--adv-bg)", borderRadius: 3 }}>
                      <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-accent)", flexShrink: 0 }}>{m.id}</span>
                      <span style={{ fontFamily: "'Inter', sans-serif", fontSize: 10, color: "var(--adv-text-muted)", flex: 1 }}>{m.name}</span>
                      <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 8, color: COVERAGE_COLOR[f.detectionCoverage] }}>
                        {f.detectionCoverage}
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Risk score context */}
              <div style={{ background: "var(--adv-panel)", border: "1px solid var(--adv-border)", borderRadius: 6, padding: "12px 14px" }}>
                <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", marginBottom: 6 }}>COMPOSITE RISK SCORE</div>
                <div style={{ display: "flex", alignItems: "baseline", gap: 8, marginBottom: 8 }}>
                  <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 28, fontWeight: 800, color: riskScoreColor(f.riskScore) }}>{f.riskScore}</span>
                  <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: "var(--adv-text-muted)" }}>/ 1000</span>
                </div>
                <div style={{ height: 6, background: "rgba(100,116,139,0.2)", borderRadius: 3, overflow: "hidden" }}>
                  <div style={{ height: "100%", width: `${f.riskScore / 10}%`, background: riskScoreColor(f.riskScore), borderRadius: 3 }} />
                </div>
                <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 11, color: "var(--adv-text-muted)", marginTop: 6 }}>
                  Composite: CVSS × 0.25 + EPSS × 0.20 + KEV × 0.20 + Exploit × 0.15 + Asset Criticality × 0.10 + Lateral Impact × 0.05
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Evidence tab */}
        {tab === "evidence" && (
          <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
            {f.evidence.map((e, i) => (
              <div key={i} style={{ background: "var(--adv-bg)", border: "1px solid var(--adv-border)", borderRadius: 6, overflow: "hidden" }}>
                <div style={{ padding: "7px 12px", borderBottom: "1px solid var(--adv-border)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-text-muted)" }}>{e.label}</span>
                  <CopyBtn text={e.content} />
                </div>
                <pre style={{ margin: 0, padding: "12px", fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: "var(--adv-text)", whiteSpace: "pre-wrap", wordBreak: "break-word", lineHeight: 1.6, maxHeight: 250, overflow: "auto" }}>
                  {e.content}
                </pre>
              </div>
            ))}
          </div>
        )}

        {/* Remediation tab */}
        {tab === "remediation" && (
          <div>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
              <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-text-muted)" }}>
                {f.remediation.filter((s) => typeof s !== "string" && s.completed).length} / {f.remediation.length} steps completed
              </span>
              <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "#FFD600" }}>
                ~{f.remediation.reduce((a, s) => a + (typeof s !== "string" ? s.estimatedHours : 1), 0)}h estimated
              </span>
            </div>
            <RemediationChecklist steps={f.remediation} findingId={f.id} />
          </div>
        )}

        {/* Compliance tab */}
        {tab === "compliance" && (
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            {f.compliance.map((c, i) => (
              <div key={i} style={{ background: "var(--adv-bg)", border: "1px solid var(--adv-border)", borderRadius: 6, padding: "10px 14px" }}>
                <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: "var(--adv-accent)", marginBottom: 7 }}>{c.framework}</div>
                <div style={{ display: "flex", flexDirection: "column", gap: 3 }}>
                  {c.refs.map((r, j) => (
                    <div key={j} style={{ fontFamily: "'Inter', sans-serif", fontSize: 13, color: "var(--adv-text)", lineHeight: 1.4 }}>· {r}</div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

/* ─── Main Page ─── */
export default function FindingsPage() {
  const { success } = useToast();
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["findings"],
    queryFn: () => fetchJson<Finding[]>("/api/findings"),
    refetchInterval: 30_000,
    retry: (count, err) => !isUnauthorized(err) && count < 2,
  });
  // Local, optimistic status changes layered over the live data (no backend persist yet).
  const [statusOverrides, setStatusOverrides] = useState<Record<string, FindingStatus>>({});
  const findings = useMemo<Finding[]>(
    () => (data ?? []).map((f) => (statusOverrides[f.id] ? { ...f, status: statusOverrides[f.id] } : f)),
    [data, statusOverrides],
  );
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [filterSev, setFilterSev] = useState<Severity | "ALL">("ALL");
  const [filterStatus, setFilterStatus] = useState<FindingStatus | "ALL">("ALL");
  const [filterCat, setFilterCat] = useState<string>("ALL");
  const [sortBy, setSortBy] = useState<"risk" | "cvss" | "epss" | "date">("risk");
  const [filterKev, setFilterKev] = useState(false);
  const [filterBlind, setFilterBlind] = useState(false);

  const categories = useMemo(() => ["ALL", ...Array.from(new Set(findings.map((f) => f.category)))], [findings]);

  const filtered = useMemo(() => {
    let list = [...findings];
    if (filterSev !== "ALL") list = list.filter((f) => f.severity === filterSev);
    if (filterStatus !== "ALL") list = list.filter((f) => f.status === filterStatus);
    if (filterCat !== "ALL") list = list.filter((f) => f.category === filterCat);
    if (filterKev) list = list.filter((f) => f.kevListed);
    if (filterBlind) list = list.filter((f) => f.detectionCoverage === "BLIND");
    if (search) list = list.filter((f) =>
      f.title.toLowerCase().includes(search.toLowerCase()) ||
      f.id.includes(search) ||
      f.affectedHost.toLowerCase().includes(search.toLowerCase()) ||
      (f.tags ?? []).some((t) => t.toLowerCase().includes(search.toLowerCase()))
    );
    list.sort((a, b) => {
      if (sortBy === "risk")  return b.riskScore - a.riskScore;
      if (sortBy === "cvss")  return Number(b.cvss) - Number(a.cvss);
      if (sortBy === "epss")  return b.epssScore - a.epssScore;
      if (sortBy === "date")  return new Date(b.discoveredAt).getTime() - new Date(a.discoveredAt).getTime();
      return 0;
    });
    return list;
  }, [findings, filterSev, filterStatus, filterCat, filterKev, filterBlind, search, sortBy]);

  const stats = useMemo(() => ({
    critical:   findings.filter((f) => f.severity === "CRITICAL" && f.status === "OPEN").length,
    high:       findings.filter((f) => f.severity === "HIGH" && f.status === "OPEN").length,
    kev:        findings.filter((f) => f.kevListed).length,
    blind:      findings.filter((f) => f.detectionCoverage === "BLIND").length,
    weaponized: findings.filter((f) => f.exploitMaturity === "WEAPONIZED").length,
    open:       findings.filter((f) => f.status === "OPEN" || f.status === "IN_REVIEW").length,
    avgRisk:    findings.length ? Math.round(findings.reduce((s, f) => s + f.riskScore, 0) / findings.length) : 0,
  }), [findings]);

  const handleStatusChange = useCallback((id: string, newStatus: FindingStatus) => {
    setStatusOverrides((prev) => ({ ...prev, [id]: newStatus }));
    success("Status updated", `${id} → ${STATUS_LABEL[newStatus]}`);
  }, [success]);

  const selected = findings.find((f) => f.id === selectedId) ?? null;

  return (
    <PageShell
      title="FINDINGS"
      subtitle="VAPT · THREAT INTEL · TRIAGE · REMEDIATION"
      statusItems={[
        { label: "CRITICAL OPEN", value: String(stats.critical),   color: "#FF1744" },
        { label: "KEV LISTED",    value: String(stats.kev),        color: "#FF6D00" },
        { label: "BLIND DETECT",  value: String(stats.blind),      color: "#FFD600" },
        { label: "AVG RISK",      value: String(stats.avgRisk),    color: riskScoreColor(stats.avgRisk) },
      ]}
    >
      <div style={{ display: "grid", gridTemplateColumns: selectedId ? "380px 1fr" : "1fr", gap: 16 }}>

        {/* ── Left: List ── */}
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>

          {/* KPI stats */}
          <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 8 }}>
            {[
              { label: "CRITICAL",   value: findings.filter((f) => f.severity === "CRITICAL").length,  color: "#FF1744" },
              { label: "WEAPONIZED", value: stats.weaponized,  color: "#9C27B0" },
              { label: "KEV",        value: stats.kev,         color: "#FF6D00" },
              { label: "BLIND",      value: stats.blind,       color: "#FFD600" },
            ].map((m) => (
              <div key={m.label} className="animate-fade-up" style={{ background: "var(--adv-bg)", border: "1px solid var(--adv-border)", borderRadius: 6, padding: "10px 12px", textAlign: "center" }}>
                <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 22, fontWeight: 700, color: m.color }}>{m.value}</div>
                <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", marginTop: 2 }}>{m.label}</div>
              </div>
            ))}
          </div>

          {/* Filters */}
          <div style={{ background: "var(--adv-bg)", border: "1px solid var(--adv-border)", borderRadius: 6, padding: "10px 12px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 8, background: "var(--adv-panel)", border: "1px solid var(--adv-border)", borderRadius: 4, padding: "5px 10px" }}>
              <Search size={11} color="#64748B" />
              <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search findings, tags..."
                style={{ background: "none", border: "none", outline: "none", color: "var(--adv-text)", fontFamily: "'JetBrains Mono', monospace", fontSize: 11, width: "100%" }}
              />
            </div>

            {/* Severity filter */}
            <div style={{ display: "flex", gap: 4, flexWrap: "wrap", marginBottom: 6 }}>
              {(["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).map((s) => (
                <button key={s} onClick={() => setFilterSev(s)} style={{
                  padding: "3px 8px", borderRadius: 3, cursor: "pointer", fontFamily: "'JetBrains Mono', monospace", fontSize: 9,
                  border: `1px solid ${filterSev === s ? (s === "ALL" ? "#2563EB" : SEV_COLOR[s as Severity]) : "var(--adv-border)"}`,
                  background: filterSev === s ? (s === "ALL" ? "rgba(37,99,235,0.1)" : `${SEV_COLOR[s as Severity]}15`) : "transparent",
                  color: filterSev === s ? (s === "ALL" ? "#2563EB" : SEV_COLOR[s as Severity]) : "var(--adv-text-muted)",
                }}>{s}</button>
              ))}
            </div>

            {/* Quick filters row */}
            <div style={{ display: "flex", gap: 6, alignItems: "center", flexWrap: "wrap" }}>
              <select value={filterStatus} onChange={(e) => setFilterStatus(e.target.value as FindingStatus | "ALL")}
                style={{ background: "var(--adv-panel)", border: "1px solid var(--adv-border)", borderRadius: 4, color: "var(--adv-text-muted)", fontFamily: "'JetBrains Mono', monospace", fontSize: 10, padding: "3px 6px", outline: "none" }}>
                {["ALL", "OPEN", "IN_REVIEW", "IN_REMEDIATION", "VERIFIED", "CLOSED", "ACCEPTED", "FALSE_POSITIVE"].map((s) => <option key={s} value={s}>{s}</option>)}
              </select>
              <select value={filterCat} onChange={(e) => setFilterCat(e.target.value)}
                style={{ background: "var(--adv-panel)", border: "1px solid var(--adv-border)", borderRadius: 4, color: "var(--adv-text-muted)", fontFamily: "'JetBrains Mono', monospace", fontSize: 10, padding: "3px 6px", outline: "none" }}>
                {categories.map((c) => <option key={c} value={c}>{c}</option>)}
              </select>
              <button onClick={() => setFilterKev((p) => !p)} style={{
                padding: "3px 8px", borderRadius: 3, cursor: "pointer", fontFamily: "'JetBrains Mono', monospace", fontSize: 9,
                border: `1px solid ${filterKev ? "rgba(255,23,68,0.4)" : "var(--adv-border)"}`,
                background: filterKev ? "rgba(255,23,68,0.1)" : "transparent",
                color: filterKev ? "#FF1744" : "var(--adv-text-muted)",
              }}>⚠ KEV</button>
              <button onClick={() => setFilterBlind((p) => !p)} style={{
                padding: "3px 8px", borderRadius: 3, cursor: "pointer", fontFamily: "'JetBrains Mono', monospace", fontSize: 9,
                border: `1px solid ${filterBlind ? "rgba(255,23,68,0.4)" : "var(--adv-border)"}`,
                background: filterBlind ? "rgba(255,23,68,0.1)" : "transparent",
                color: filterBlind ? "#FF1744" : "var(--adv-text-muted)",
              }}>○ BLIND</button>
              <button onClick={() => setSortBy(sortBy === "risk" ? "cvss" : sortBy === "cvss" ? "epss" : sortBy === "epss" ? "date" : "risk")}
                style={{ display: "flex", alignItems: "center", gap: 4, padding: "3px 8px", background: "transparent", border: "1px solid var(--adv-border)", borderRadius: 4, color: "var(--adv-text-muted)", cursor: "pointer", fontFamily: "'JetBrains Mono', monospace", fontSize: 9 }}>
                <ArrowUpDown size={9} /> {sortBy.toUpperCase()}
              </button>
            </div>
          </div>

          {/* Finding list */}
          <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            <DataState
              loading={isLoading}
              error={error}
              isEmpty={findings.length === 0}
              onRetry={() => refetch()}
              skeleton={<SkeletonRows rows={6} height={92} />}
              empty={
                <EmptyState
                  icon={Shield}
                  title="No findings yet"
                  hint="Run a vulnerability scan on an in-scope target — findings appear here, ranked by risk."
                />
              }
            >
            {filtered.map((f) => {
              const sla = getSlaColor(f.discoveredAt, f.severity);
              const isSelected = selectedId === f.id;
              const pc = PRIORITY_COLOR[f.aiTriage.priority];
              return (
                <div
                  key={f.id}
                  className="card-hover stagger-item"
                  onClick={() => setSelectedId(isSelected ? null : f.id)}
                  style={{
                    background: isSelected ? "rgba(37,99,235,0.03)" : "var(--adv-bg)",
                    border: `1px solid ${isSelected ? "#2563EB" : "var(--adv-border)"}`,
                    borderLeft: `3px solid ${SEV_COLOR[f.severity]}`,
                    borderRadius: 6, padding: "10px 12px", cursor: "pointer",
                  }}
                >
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 5 }}>
                    <div style={{ display: "flex", gap: 5, flexWrap: "wrap", flex: 1, alignItems: "center" }}>
                      <SevBadge s={f.severity} />
                      <StatusBadge s={f.status} />
                      {f.kevListed && <KevBadge />}
                      <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: pc, background: `${pc}12`, border: `1px solid ${pc}25`, borderRadius: 3, padding: "1px 4px" }}>{f.aiTriage.priority}</span>
                    </div>
                    <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", gap: 2, flexShrink: 0 }}>
                      <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, fontWeight: 700, color: riskScoreColor(f.riskScore) }}>{f.riskScore}</span>
                      <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 8, color: "var(--adv-text-muted)" }}>RISK</span>
                    </div>
                  </div>

                  <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 13, fontWeight: 600, color: "var(--adv-text)", lineHeight: 1.3, marginBottom: 5 }}>
                    {f.title}
                  </div>

                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 5 }}>
                    <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)" }}>{f.affectedHost}</span>
                    <div style={{ display: "flex", gap: 5, alignItems: "center" }}>
                      <DetectionPill cov={f.detectionCoverage} />
                      <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: MATURITY_COLOR[f.exploitMaturity] }}>{f.exploitMaturity}</span>
                    </div>
                  </div>

                  {/* EPSS mini */}
                  <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 4 }}>
                    <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)" }}>EPSS</span>
                    <div style={{ flex: 1, height: 3, background: "rgba(100,116,139,0.15)", borderRadius: 2, overflow: "hidden" }}>
                      <div style={{ height: "100%", width: `${f.epssScore * 100}%`, background: f.epssScore > 0.7 ? "#FF1744" : f.epssScore > 0.4 ? "#FF6D00" : "#FFD600", borderRadius: 2 }} />
                    </div>
                    <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)" }}>{(f.epssScore * 100).toFixed(0)}%</span>
                    <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "#FF6D00" }}>CVSS {f.cvss}</span>
                    <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: sla.color }}>{sla.label}</span>
                  </div>

                  {/* Risk bar */}
                  <div style={{ height: 2, background: "rgba(100,116,139,0.15)", borderRadius: 1, overflow: "hidden" }}>
                    <div style={{ height: "100%", width: `${f.riskScore / 10}%`, background: riskScoreColor(f.riskScore), borderRadius: 1 }} />
                  </div>
                </div>
              );
            })}

            {filtered.length === 0 && (
              <div style={{ textAlign: "center", padding: 32, color: "var(--adv-text-muted)", fontFamily: "'JetBrains Mono', monospace", fontSize: 11 }}>
                No findings match the current filters.
              </div>
            )}
            </DataState>
          </div>
        </div>

        {/* ── Right: Detail ── */}
        {selected && (
          <div style={{ minWidth: 0 }}>
            <FindingDetail f={selected} allFindings={findings} onStatusChange={handleStatusChange} />
          </div>
        )}
      </div>
    </PageShell>
  );
}
