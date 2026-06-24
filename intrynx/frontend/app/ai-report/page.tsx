"use client";

import React, { useState, useEffect, useCallback } from "react";
import {
  Brain, BarChart2, ShieldCheck, FileText, RefreshCw,
  Play, CheckCircle2, XCircle, AlertTriangle, Copy, Check, ChevronDown, ChevronRight,
} from "lucide-react";
import { PageShell } from "../../components/PageShell";
import { useToast } from "../../hooks/useToast";

/* ─── Types ─── */
type TabKey = "prioritizer" | "generator" | "guard" | "review";
type ReviewStatus = "pending" | "approved" | "rejected";
type ReportSection = "executive_summary" | "technical_finding" | "remediation" | "sigma_explanation";

interface ShapFeature { name: string; value: number; contribution: number; pct: number; }
interface ShapExplanation { score: number; features: ShapFeature[]; modelType: string; }

interface ScoredFinding {
  finding: { id: string; title: string; severity: string; cvss: number; cveId?: string; affectedHost: string; exploitValidated: boolean; mitreTechnique?: string };
  asset: { label: string; criticality: string; zone: string; lateralReachableCount?: number; daysSinceLastPatch?: number };
  score: number;
  shap: ShapExplanation;
}

interface LLMOutput {
  id: string; section: ReportSection; model: string;
  output: string; generatedAt: string; reviewStatus: ReviewStatus;
  reviewedBy?: string; rejectionFeedback?: string;
  hallucinationCheck?: { valid: boolean; issues: string[]; confidence: number };
}

/* ─── Helpers ─── */
function sevColor(s: string) {
  if (s === "CRITICAL") return "#FF1744";
  if (s === "HIGH")     return "#FF6D00";
  if (s === "MEDIUM")   return "#FFD600";
  return "#00E676";
}

function scoreColor(n: number) {
  if (n >= 800) return "#FF1744";
  if (n >= 600) return "#FF6D00";
  if (n >= 400) return "#FFD600";
  return "#00E676";
}

function statusColor(s: ReviewStatus) {
  if (s === "approved") return "#00E676";
  if (s === "rejected") return "#FF1744";
  return "#FFD600";
}

const SECTION_LABELS: Record<ReportSection, string> = {
  executive_summary: "Executive Summary",
  technical_finding: "Technical Finding",
  remediation:       "Remediation Steps",
  sigma_explanation: "Sigma Explanation",
};

function CopyBtn({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button onClick={() => { navigator.clipboard.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 2000); }}
      style={{ background: "none", border: "none", cursor: "pointer", color: copied ? "#00E676" : "#64748B", padding: "2px 4px" }}>
      {copied ? <Check size={11} /> : <Copy size={11} />}
    </button>
  );
}

const ENG = "ENG-001";

/* ─── Main Page ─── */
export default function AIReportPage() {
  const { success, error: toastError, info, warning } = useToast();
  const [activeTab, setActiveTab] = useState<TabKey>("prioritizer");

  // Prioritizer state
  const [findings,    setFindings]    = useState<ScoredFinding[]>([]);
  const [expandedF,   setExpandedF]   = useState<string | null>(null);
  const [loadingPri,  setLoadingPri]  = useState(true);

  // Generator state
  const [selectedSections, setSelectedSections] = useState<ReportSection[]>(["executive_summary", "technical_finding", "remediation"]);
  const [generating,  setGenerating]  = useState(false);
  const [jobId,       setJobId]       = useState<string | null>(null);

  // Draft review state
  const [drafts,      setDrafts]      = useState<LLMOutput[]>([]);
  const [expandedOut, setExpandedOut] = useState<string | null>(null);
  const [feedback,    setFeedback]    = useState<Record<string, string>>({});
  const [processing,  setProcessing]  = useState<string | null>(null);

  useEffect(() => {
    fetch(`/api/engagements/${ENG}/vuln-prioritizer`)
      .then((r) => r.json())
      .then((d) => setFindings(d.findings ?? []))
      .catch(() => toastError("Load Error", "Failed to load risk scores."))
      .finally(() => setLoadingPri(false));
  }, [toastError]);

  const loadDrafts = useCallback(() => {
    fetch(`/api/engagements/${ENG}/ai-report/draft`)
      .then((r) => r.json())
      .then((d) => setDrafts(d.all ?? []))
      .catch(() => null);
  }, []);

  useEffect(() => { loadDrafts(); }, [loadDrafts]);

  const generate = useCallback(async () => {
    if (generating) return;
    setGenerating(true);
    info("Generating", `Running LLMReportGenerator for ${selectedSections.length} sections…`);
    try {
      const res = await fetch(`/api/engagements/${ENG}/ai-report/generate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ sections: selectedSections }),
      });
      const data = await res.json();
      setJobId(data.jobId);
      success("Complete", `Report sections generated (job ${data.jobId}). Review in the DRAFT REVIEW tab.`);
      loadDrafts();
      setActiveTab("review");
    } catch {
      toastError("Error", "Report generation failed.");
    } finally {
      setGenerating(false);
    }
  }, [generating, selectedSections, info, success, toastError, loadDrafts]);

  const approveOutput = useCallback(async (outputId: string) => {
    setProcessing(outputId);
    try {
      await fetch(`/api/engagements/${ENG}/ai-report/approve`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ outputId, reviewedBy: "manager@adversa.io" }),
      });
      success("Approved", "Output marked as final.");
      loadDrafts();
    } catch {
      toastError("Error", "Approval failed.");
    } finally {
      setProcessing(null);
    }
  }, [success, toastError, loadDrafts]);

  const rejectOutput = useCallback(async (outputId: string) => {
    const fb = feedback[outputId]?.trim();
    if (!fb) { warning("Validation", "Provide rejection feedback first."); return; }
    setProcessing(outputId);
    try {
      await fetch(`/api/engagements/${ENG}/ai-report/reject`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ outputId, feedback: fb, reviewedBy: "manager@adversa.io" }),
      });
      warning("Rejected", "Output rejected and flagged for regeneration.");
      setFeedback((p) => { const n = { ...p }; delete n[outputId]; return n; });
      loadDrafts();
    } catch {
      toastError("Error", "Rejection failed.");
    } finally {
      setProcessing(null);
    }
  }, [feedback, warning, toastError, loadDrafts]);

  const pendingCount  = drafts.filter((d) => d.reviewStatus === "pending").length;
  const approvedCount = drafts.filter((d) => d.reviewStatus === "approved").length;

  const tabs: { key: TabKey; label: string; icon: React.ReactNode }[] = [
    { key: "prioritizer", label: "RISK SCORING",    icon: <BarChart2 size={12} /> },
    { key: "generator",   label: "REPORT GENERATOR",icon: <Brain size={12} /> },
    { key: "guard",       label: "HALLUCINATION GUARD", icon: <ShieldCheck size={12} /> },
    { key: "review",      label: `DRAFT REVIEW (${pendingCount})`, icon: <FileText size={12} /> },
  ];

  return (
    <PageShell
      title="AI ENGINE"
      subtitle="VULN PRIORITIZER · LLM REPORT GENERATOR · HALLUCINATION GUARD"
      statusItems={[
        { label: "MODEL",    value: "claude-sonnet-4-20250514", color: "var(--adv-accent)" },
        { label: "PENDING",  value: String(pendingCount),  color: pendingCount > 0 ? "#FFD600" : "var(--adv-text-muted)" },
        { label: "APPROVED", value: String(approvedCount), color: approvedCount > 0 ? "#00E676" : "var(--adv-text-muted)" },
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
              whiteSpace: "nowrap",
            }}>
            {icon}{label}
          </button>
        ))}
      </div>

      <div style={{ flex: 1, overflowY: "auto", paddingTop: 14 }}>

        {/* ── RISK SCORING (VulnPrioritizer) ─────────────────── */}
        {activeTab === "prioritizer" && (
          <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
            <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 13, color: "var(--adv-text-muted)" }}>
              VulnPrioritizer: composite risk score 0–1000 using weighted formula (CVSS·0.25 + EPSS·0.20 + KEV·0.20 + ExploitValidated·0.15 + AssetCrit·0.10 + LateralReach·0.05 + PatchAge·0.05). SHAP breakdown per finding.
            </div>

            {loadingPri ? (
              <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "40px 0" }}>
                <RefreshCw size={16} color="var(--adv-accent)" style={{ animation: "spin 1s linear infinite" }} />
                <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, color: "var(--adv-text-muted)" }}>Computing priority scores…</span>
              </div>
            ) : findings.map((item) => (
              <div key={item.finding.id} style={{ background: "var(--adv-bg)", border: `1px solid ${scoreColor(item.score)}20`, borderLeft: `3px solid ${scoreColor(item.score)}`, borderRadius: 6, overflow: "hidden" }}>
                <div onClick={() => setExpandedF(expandedF === item.finding.id ? null : item.finding.id)}
                  style={{ padding: "12px 14px", cursor: "pointer", display: "flex", alignItems: "center", gap: 12 }}>
                  {/* Score ring */}
                  <div style={{ width: 52, height: 52, borderRadius: "50%", border: `3px solid ${scoreColor(item.score)}`, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0, background: `${scoreColor(item.score)}10` }}>
                    <span style={{ fontFamily: "'Inter', sans-serif", fontSize: 15, fontWeight: 700, color: scoreColor(item.score) }}>{item.score}</span>
                  </div>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                      <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-text-muted)" }}>{item.finding.id}</span>
                      <span style={{ fontFamily: "'Inter', sans-serif", fontSize: 13, color: "var(--adv-text)", fontWeight: 600 }}>{item.finding.title}</span>
                      {item.finding.cveId && <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "#FF6D00" }}>{item.finding.cveId}</span>}
                    </div>
                    <div style={{ display: "flex", gap: 12, marginTop: 3 }}>
                      <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: sevColor(item.finding.severity) }}>{item.finding.severity}</span>
                      <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)" }}>CVSS {item.finding.cvss}</span>
                      <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)" }}>{item.asset.label} · {item.asset.zone}</span>
                      <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: item.finding.exploitValidated ? "#FF1744" : "var(--adv-text-muted)" }}>{item.finding.exploitValidated ? "VALIDATED" : "UNVALIDATED"}</span>
                    </div>
                  </div>
                  {expandedF === item.finding.id ? <ChevronDown size={13} color="#64748B" /> : <ChevronRight size={13} color="#64748B" />}
                </div>

                {expandedF === item.finding.id && (
                  <div style={{ borderTop: "1px solid var(--adv-border)", padding: "14px 16px" }}>
                    <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", marginBottom: 10 }}>
                      SHAP FEATURE IMPORTANCE — {item.shap.modelType === "fallback_formula" ? "Weighted Formula (XGBoost model not trained)" : "XGBoost"}
                    </div>
                    <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                      {item.shap.features.map((f) => (
                        <div key={f.name} style={{ display: "flex", alignItems: "center", gap: 10 }}>
                          <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-text-muted)", width: 160, flexShrink: 0 }}>{f.name}</span>
                          <div style={{ flex: 1, height: 8, background: "var(--adv-panel)", borderRadius: 4, overflow: "hidden" }}>
                            <div style={{ height: "100%", width: `${f.pct}%`, background: scoreColor(item.score), borderRadius: 4 }} />
                          </div>
                          <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: scoreColor(item.score), width: 36, textAlign: "right" }}>{f.pct}%</span>
                          <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", width: 60 }}>val: {typeof f.value === "number" ? f.value.toFixed(f.value < 1 ? 3 : 0) : f.value}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}

        {/* ── REPORT GENERATOR ───────────────────────────────── */}
        {activeTab === "generator" && (
          <div style={{ display: "flex", flexDirection: "column", gap: 16, maxWidth: 640 }}>
            <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 13, color: "var(--adv-text-muted)" }}>
              LLMReportGenerator calls claude-sonnet-4-20250514 at temperature=0.3 with retry logic. Set ANTHROPIC_API_KEY for live generation — falls back to simulated output otherwise.
            </div>

            <div style={{ background: "var(--adv-panel)", border: "1px solid var(--adv-border)", borderRadius: 6, padding: 16 }}>
              <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-text-muted)", marginBottom: 10 }}>SELECT REPORT SECTIONS</div>
              <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                {(["executive_summary", "technical_finding", "remediation", "sigma_explanation"] as ReportSection[]).map((sec) => {
                  const checked = selectedSections.includes(sec);
                  return (
                    <label key={sec} style={{ display: "flex", alignItems: "center", gap: 10, cursor: "pointer" }}>
                      <input type="checkbox" checked={checked}
                        onChange={() => setSelectedSections((prev) => checked ? prev.filter((s) => s !== sec) : [...prev, sec])}
                        style={{ accentColor: "var(--adv-accent)", width: 14, height: 14 }} />
                      <div>
                        <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: "var(--adv-text)" }}>{SECTION_LABELS[sec]}</div>
                        <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 11, color: "var(--adv-text-muted)" }}>
                          {sec === "executive_summary" && "400-600 words for CISO/Board — business impact, top risks, urgency"}
                          {sec === "technical_finding" && "Full finding write-up with reproduction steps and evidence"}
                          {sec === "remediation" && "Numbered step-by-step fix guide with CLI commands and verification"}
                          {sec === "sigma_explanation" && "Plain-language explanation of the generated Sigma YAML rule"}
                        </div>
                      </div>
                    </label>
                  );
                })}
              </div>
            </div>

            <div style={{ background: "rgba(37,99,235,0.04)", border: "1px solid rgba(37,99,235,0.15)", borderRadius: 6, padding: "10px 14px" }}>
              <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", marginBottom: 5 }}>SYSTEM CONSTRAINTS (always enforced)</div>
              {[
                "temperature=0.3 for consistency",
                "Only reference CVE IDs and CVSS scores from engagement data",
                "Never invent asset names, IPs, or vulnerability details",
                "Destructive remediation commands are blocked by HallucinationGuard",
                "Exponential backoff on API failures (3 retries: 1s, 2s, 4s)",
                "All outputs saved with prompt_hash, model, review_status=pending",
              ].map((c) => (
                <div key={c} style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 3 }}>
                  <ShieldCheck size={10} color="#00E676" />
                  <span style={{ fontFamily: "'Inter', sans-serif", fontSize: 11, color: "var(--adv-text-muted)" }}>{c}</span>
                </div>
              ))}
            </div>

            <button onClick={generate} disabled={generating || selectedSections.length === 0}
              style={{
                padding: "10px 24px", borderRadius: 6, cursor: generating ? "not-allowed" : "pointer",
                border: "1px solid rgba(0,230,118,0.3)", background: "rgba(0,230,118,0.08)",
                color: "#00E676", fontFamily: "'JetBrains Mono', monospace", fontSize: 12,
                display: "flex", alignItems: "center", gap: 8, alignSelf: "flex-start",
              }}>
              {generating ? <RefreshCw size={13} style={{ animation: "spin 1s linear infinite" }} /> : <Play size={13} />}
              {generating ? "GENERATING…" : `GENERATE ${selectedSections.length} SECTION${selectedSections.length !== 1 ? "S" : ""}`}
            </button>

            {jobId && (
              <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-text-muted)" }}>
                Last job: <span style={{ color: "var(--adv-accent)" }}>{jobId}</span> · Check DRAFT REVIEW tab
              </div>
            )}
          </div>
        )}

        {/* ── HALLUCINATION GUARD ────────────────────────────── */}
        {activeTab === "guard" && (
          <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
            <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 13, color: "var(--adv-text-muted)", marginBottom: 4 }}>
              HallucinationGuard validation results for all generated outputs. Each check runs automatically after generation.
            </div>

            {drafts.length === 0 ? (
              <div style={{ padding: "60px 0", textAlign: "center", fontFamily: "'JetBrains Mono', monospace", fontSize: 13, color: "var(--adv-text-muted)" }}>
                Generate report sections first — hallucination check results appear here.
              </div>
            ) : (
              <div style={{ background: "var(--adv-bg)", border: "1px solid var(--adv-border)", borderRadius: 6, overflow: "hidden" }}>
                <table style={{ width: "100%", borderCollapse: "collapse" }}>
                  <thead>
                    <tr>
                      {["SECTION", "MODEL", "CVE CHECK", "CVSS CHECK", "DESTRUCTIVE CMD CHECK", "CONFIDENCE", "VALID"].map((h) => (
                        <th key={h} style={{ padding: "8px 12px", textAlign: "left", fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", borderBottom: "1px solid var(--adv-border)", whiteSpace: "nowrap" }}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {drafts.map((d, i) => {
                      const g = d.hallucinationCheck;
                      return (
                        <tr key={d.id}>
                          <td style={{ padding: "9px 12px", fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-text)", borderBottom: "1px solid var(--adv-border)" }}>{SECTION_LABELS[d.section]}</td>
                          <td style={{ padding: "9px 12px", fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", borderBottom: "1px solid var(--adv-border)" }}>{d.model}</td>
                          {["cve", "cvss", "cmd"].map((check) => (
                            <td key={check} style={{ padding: "9px 12px", borderBottom: "1px solid var(--adv-border)" }}>
                              {g ? (
                                g.valid
                                  ? <CheckCircle2 size={14} color="#00E676" />
                                  : g.issues.some((issue) => issue.toLowerCase().includes(check === "cve" ? "cve" : check === "cvss" ? "cvss" : "command"))
                                    ? <XCircle size={14} color="#FF1744" />
                                    : <CheckCircle2 size={14} color="#00E676" />
                              ) : <span style={{ color: "var(--adv-text-muted)", fontSize: 10 }}>—</span>}
                            </td>
                          ))}
                          <td style={{ padding: "9px 12px", fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: g?.valid ? "#00E676" : "#FF1744", borderBottom: "1px solid var(--adv-border)" }}>
                            {g ? `${Math.round(g.confidence * 100)}%` : "—"}
                          </td>
                          <td style={{ padding: "9px 12px", borderBottom: "1px solid var(--adv-border)" }}>
                            {g ? (g.valid ? <CheckCircle2 size={14} color="#00E676" /> : <XCircle size={14} color="#FF1744" />) : "—"}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}

            {/* Guard explanation */}
            <div style={{ background: "var(--adv-panel)", border: "1px solid var(--adv-border)", borderRadius: 6, padding: 14 }}>
              <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-text-muted)", marginBottom: 8 }}>GUARD CHECKS EXPLAINED</div>
              {[
                { label: "CVE CHECK",          desc: "Scans output for CVE-XXXX-XXXXX patterns not present in engagement data — prevents hallucinated vulnerability IDs." },
                { label: "CVSS CHECK",         desc: "Validates any CVSS score mentioned in output against known scores from the engagement findings (±0.1 tolerance)." },
                { label: "DESTRUCTIVE CMD",    desc: "Blocks outputs containing rm -rf, DROP TABLE, format, shutdown, wipefs, dd if=/dev/zero — prevents dangerous remediation guidance." },
              ].map((g) => (
                <div key={g.label} style={{ display: "flex", gap: 8, marginBottom: 6 }}>
                  <ShieldCheck size={12} color="var(--adv-accent)" style={{ marginTop: 2, flexShrink: 0 }} />
                  <div>
                    <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-text)" }}>{g.label}: </span>
                    <span style={{ fontFamily: "'Inter', sans-serif", fontSize: 12, color: "var(--adv-text-muted)" }}>{g.desc}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ── DRAFT REVIEW ───────────────────────────────────── */}
        {activeTab === "review" && (
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 10, marginBottom: 4 }}>
              {[
                { label: "TOTAL",    value: drafts.length,   color: "var(--adv-accent)" },
                { label: "PENDING",  value: pendingCount,    color: pendingCount > 0 ? "#FFD600" : "var(--adv-text-muted)" },
                { label: "APPROVED", value: approvedCount,   color: approvedCount > 0 ? "#00E676" : "var(--adv-text-muted)" },
              ].map((s) => (
                <div key={s.label} style={{ background: "var(--adv-panel)", border: "1px solid var(--adv-border)", borderRadius: 6, padding: "10px 14px" }}>
                  <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", marginBottom: 4 }}>{s.label}</div>
                  <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 22, fontWeight: 700, color: s.color }}>{s.value}</div>
                </div>
              ))}
            </div>

            {drafts.length === 0 ? (
              <div style={{ padding: "60px 0", textAlign: "center", fontFamily: "'JetBrains Mono', monospace", fontSize: 13, color: "var(--adv-text-muted)" }}>
                No generated outputs yet. Use the REPORT GENERATOR tab.
              </div>
            ) : drafts.map((output) => (
              <div key={output.id} style={{
                background: "var(--adv-bg)",
                border: `1px solid ${statusColor(output.reviewStatus)}25`,
                borderLeft: `3px solid ${statusColor(output.reviewStatus)}`,
                borderRadius: 6, overflow: "hidden",
              }}>
                <div onClick={() => setExpandedOut(expandedOut === output.id ? null : output.id)}
                  style={{ padding: "12px 14px", cursor: "pointer", display: "flex", alignItems: "center", gap: 10 }}>
                  <div style={{ flex: 1 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                      <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-accent)" }}>{output.id}</span>
                      <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: "var(--adv-text)", fontWeight: 600 }}>{SECTION_LABELS[output.section]}</span>
                      <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: statusColor(output.reviewStatus), background: `${statusColor(output.reviewStatus)}15`, borderRadius: 3, padding: "0 5px" }}>{output.reviewStatus.toUpperCase()}</span>
                      {output.hallucinationCheck && !output.hallucinationCheck.valid && (
                        <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "#FF1744", background: "rgba(255,23,68,0.1)", borderRadius: 3, padding: "0 5px", display: "flex", alignItems: "center", gap: 3 }}>
                          <AlertTriangle size={9} /> HALLUCINATION ISSUES
                        </span>
                      )}
                    </div>
                    <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", marginTop: 2 }}>
                      {output.model} · {new Date(output.generatedAt).toLocaleString()}
                      {output.reviewedBy && ` · Reviewed by ${output.reviewedBy}`}
                    </div>
                  </div>
                  {expandedOut === output.id ? <ChevronDown size={13} color="#64748B" /> : <ChevronRight size={13} color="#64748B" />}
                </div>

                {expandedOut === output.id && (
                  <div style={{ borderTop: "1px solid var(--adv-border)", padding: "12px 14px", display: "flex", flexDirection: "column", gap: 12 }}>
                    {/* Hallucination check issues */}
                    {output.hallucinationCheck && !output.hallucinationCheck.valid && (
                      <div style={{ background: "rgba(255,23,68,0.04)", border: "1px solid rgba(255,23,68,0.2)", borderRadius: 5, padding: "10px 12px" }}>
                        <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "#FF1744", marginBottom: 5 }}>HALLUCINATION GUARD ISSUES</div>
                        {output.hallucinationCheck.issues.map((issue, i) => (
                          <div key={i} style={{ fontFamily: "'Inter', sans-serif", fontSize: 12, color: "#FF6D00", marginBottom: 2 }}>• {issue}</div>
                        ))}
                      </div>
                    )}

                    {/* Output content */}
                    <div style={{ background: "var(--adv-panel)", border: "1px solid var(--adv-border)", borderRadius: 5, overflow: "hidden" }}>
                      <div style={{ padding: "5px 10px", borderBottom: "1px solid var(--adv-border)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                        <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)" }}>GENERATED OUTPUT</span>
                        <CopyBtn text={output.output} />
                      </div>
                      <div style={{ padding: "10px 14px", fontFamily: "'Inter', sans-serif", fontSize: 13, color: "var(--adv-text)", lineHeight: 1.6, whiteSpace: "pre-wrap", maxHeight: 320, overflowY: "auto" }}>
                        {output.output}
                      </div>
                    </div>

                    {/* Rejection feedback */}
                    {output.rejectionFeedback && (
                      <div style={{ background: "rgba(255,107,0,0.04)", border: "1px solid rgba(255,107,0,0.2)", borderRadius: 5, padding: "8px 12px" }}>
                        <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "#FF6D00", marginBottom: 3 }}>REJECTION FEEDBACK</div>
                        <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 12, color: "var(--adv-text-muted)" }}>{output.rejectionFeedback}</div>
                      </div>
                    )}

                    {/* Approval controls */}
                    {output.reviewStatus === "pending" && (
                      <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                        <input
                          value={feedback[output.id] ?? ""}
                          onChange={(e) => setFeedback((p) => ({ ...p, [output.id]: e.target.value }))}
                          placeholder="Rejection reason (required if rejecting)…"
                          style={{ width: "100%", boxSizing: "border-box", background: "var(--adv-panel)", border: "1px solid var(--adv-border)", borderRadius: 5, padding: "7px 10px", color: "var(--adv-text)", fontFamily: "'Inter', sans-serif", fontSize: 12, outline: "none" }}
                        />
                        <div style={{ display: "flex", gap: 8 }}>
                          <button onClick={() => approveOutput(output.id)} disabled={processing === output.id}
                            style={{ padding: "6px 18px", borderRadius: 5, border: "1px solid rgba(0,230,118,0.3)", background: "rgba(0,230,118,0.08)", color: "#00E676", fontFamily: "'JetBrains Mono', monospace", fontSize: 10, cursor: "pointer", display: "flex", alignItems: "center", gap: 5 }}>
                            <CheckCircle2 size={11} /> APPROVE & MARK FINAL
                          </button>
                          <button onClick={() => rejectOutput(output.id)} disabled={processing === output.id}
                            style={{ padding: "6px 18px", borderRadius: 5, border: "1px solid rgba(255,23,68,0.3)", background: "rgba(255,23,68,0.08)", color: "#FF4444", fontFamily: "'JetBrains Mono', monospace", fontSize: 10, cursor: "pointer", display: "flex", alignItems: "center", gap: 5 }}>
                            <XCircle size={11} /> REJECT & FLAG
                          </button>
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </PageShell>
  );
}
