"use client";

import React, { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import {
  Plus, Briefcase, ChevronRight, X, Check,
  RefreshCw, AlertTriangle, Users, Calendar,
} from "lucide-react";
import { PageShell } from "../../components/PageShell";
import { useToast } from "../../hooks/useToast";

/* ─── Types ─── */
type EngagementStatus = "PLANNING" | "ACTIVE" | "PAUSED" | "COMPLETED" | "ARCHIVED";

interface Engagement {
  id: string; name: string; client: string; status: EngagementStatus;
  startDate: string; endDate: string; scopeCidrs: string[];
  assessor: string; assetCount: number; findingCount: number;
  findingsBySeverity: { CRITICAL: number; HIGH: number; MEDIUM: number; LOW: number };
  progress: number; tags: string[];
}

/* ─── Multi-step form state ─── */
interface FormState {
  name: string; client: string; description: string;
  startDate: string; endDate: string; assessor: string;
  scopeCidrs: string; excludedCidrs: string;
  credType: "ssh" | "winrm" | "domain" | "api"; credLabel: string; credUser: string;
}

const EMPTY_FORM: FormState = {
  name: "", client: "", description: "",
  startDate: "", endDate: "", assessor: "analyst@adversa.io",
  scopeCidrs: "", excludedCidrs: "",
  credType: "domain", credLabel: "", credUser: "",
};

/* ─── Helpers ─── */
function statusColor(s: EngagementStatus) {
  if (s === "ACTIVE")    return "#00E676";
  if (s === "PLANNING")  return "#FFD600";
  if (s === "PAUSED")    return "#FF6D00";
  if (s === "COMPLETED") return "#00D4FF";
  return "#64748B";
}

function sevColor(s: string) {
  if (s === "CRITICAL") return "#FF1744";
  if (s === "HIGH")     return "#FF6D00";
  if (s === "MEDIUM")   return "#FFD600";
  return "#00E676";
}

/* ─── Skeleton ─── */
function RowSkeleton() {
  return (
    <tr>
      {[200, 100, 80, 80, 120, 80].map((w, i) => (
        <td key={i} style={{ padding: "12px 14px" }}>
          <div className="shimmer" style={{ width: w, height: 14, borderRadius: 4 }} />
        </td>
      ))}
    </tr>
  );
}

/* ─── Step labels ─── */
const STEPS = ["Name & Dates", "Scope CIDRs", "Credentials", "Review"];

/* ─── Main Page ─── */
export default function EngagementsPage() {
  const { success, error: toastError } = useToast();
  const qc = useQueryClient();

  const { data, isLoading, isError } = useQuery({
    queryKey: ["engagements"],
    queryFn: () => fetch("/api/engagements").then((r) => r.json()),
  });

  const createMutation = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      fetch("/api/engagements", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      }).then((r) => r.json()),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["engagements"] });
      success("Created", "Engagement created successfully.");
      setShowModal(false);
      setStep(0);
      setForm(EMPTY_FORM);
    },
    onError: () => toastError("Error", "Failed to create engagement."),
  });

  const [showModal, setShowModal] = useState(false);
  const [step, setStep] = useState(0);
  const [form, setForm] = useState<FormState>(EMPTY_FORM);

  const engagements: Engagement[] = data?.engagements ?? [];

  function patchForm(patch: Partial<FormState>) {
    setForm((p) => ({ ...p, ...patch }));
  }

  function canProceed() {
    if (step === 0) return form.name.trim() && form.client.trim() && form.startDate && form.endDate;
    if (step === 1) return form.scopeCidrs.trim().length > 0;
    return true;
  }

  function submit() {
    createMutation.mutate({
      name: form.name.trim(),
      client: form.client.trim(),
      description: form.description.trim(),
      startDate: form.startDate,
      endDate: form.endDate,
      assessor: form.assessor,
      scopeCidrs: form.scopeCidrs.split(",").map((s) => s.trim()).filter(Boolean),
      excludedCidrs: form.excludedCidrs.split(",").map((s) => s.trim()).filter(Boolean),
      credentials: form.credLabel.trim()
        ? [{ type: form.credType, label: form.credLabel, username: form.credUser, vaultRef: `vault/${Date.now()}` }]
        : [],
    });
  }

  const inputStyle: React.CSSProperties = {
    width: "100%", boxSizing: "border-box",
    background: "var(--adv-bg)", border: "1px solid var(--adv-border)",
    borderRadius: 5, padding: "8px 10px", color: "var(--adv-text)",
    fontFamily: "'JetBrains Mono', monospace", fontSize: 12, outline: "none",
  };

  const labelStyle: React.CSSProperties = {
    fontFamily: "'JetBrains Mono', monospace", fontSize: 9,
    color: "var(--adv-text-muted)", marginBottom: 5, display: "block",
  };

  return (
    <PageShell
      title="ENGAGEMENTS"
      subtitle="MANAGE · SCOPE · TRACK · REPORT"
      statusItems={[
        { label: "ACTIVE",    value: String(engagements.filter((e) => e.status === "ACTIVE").length),    color: "#00E676" },
        { label: "PLANNING",  value: String(engagements.filter((e) => e.status === "PLANNING").length),  color: "#FFD600" },
        { label: "COMPLETED", value: String(engagements.filter((e) => e.status === "COMPLETED").length), color: "#00D4FF" },
      ]}
    >
      {/* Toolbar */}
      <div style={{ display: "flex", justifyContent: "flex-end", marginBottom: 14 }}>
        <button onClick={() => setShowModal(true)}
          style={{ display: "flex", alignItems: "center", gap: 6, padding: "8px 18px", borderRadius: 6, border: "1px solid rgba(37,99,235,0.3)", background: "rgba(37,99,235,0.1)", color: "var(--adv-accent)", fontFamily: "'JetBrains Mono', monospace", fontSize: 11, cursor: "pointer" }}>
          <Plus size={13} /> NEW ENGAGEMENT
        </button>
      </div>

      {/* Table */}
      <div style={{ background: "var(--adv-bg)", border: "1px solid var(--adv-border)", borderRadius: 6, overflow: "hidden" }}>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr>
              {["ENGAGEMENT", "CLIENT", "STATUS", "SCOPE", "FINDINGS", "ASSETS", "PROGRESS", "DATES", ""].map((h) => (
                <th key={h} style={{ padding: "9px 14px", textAlign: "left", fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", borderBottom: "1px solid var(--adv-border)", whiteSpace: "nowrap" }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {isLoading && [1, 2, 3].map((i) => <RowSkeleton key={i} />)}
            {isError && (
              <tr>
                <td colSpan={9} style={{ padding: "40px 0", textAlign: "center" }}>
                  <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 8 }}>
                    <AlertTriangle size={28} color="#FF1744" />
                    <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, color: "#FF1744" }}>Failed to load engagements</span>
                  </div>
                </td>
              </tr>
            )}
            {!isLoading && !isError && engagements.length === 0 && (
              <tr>
                <td colSpan={9} style={{ padding: "60px 0", textAlign: "center" }}>
                  <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 10 }}>
                    <Briefcase size={36} color="var(--adv-border)" />
                    <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 13, color: "var(--adv-text-muted)" }}>No engagements yet</span>
                    <button onClick={() => setShowModal(true)} style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-accent)", background: "none", border: "1px solid rgba(37,99,235,0.3)", borderRadius: 4, padding: "5px 14px", cursor: "pointer" }}>
                      Create first engagement
                    </button>
                  </div>
                </td>
              </tr>
            )}
            {engagements.map((eng) => (
              <tr key={eng.id} className="card-hover" style={{ borderBottom: "1px solid var(--adv-border)" }}>
                <td style={{ padding: "12px 14px" }}>
                  <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: "var(--adv-text)", fontWeight: 600 }}>{eng.name}</div>
                  <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", marginTop: 2 }}>
                    {eng.tags.map((t) => (
                      <span key={t} style={{ marginRight: 4, background: "rgba(37,99,235,0.1)", borderRadius: 2, padding: "0 4px", color: "var(--adv-accent)" }}>{t}</span>
                    ))}
                  </div>
                </td>
                <td style={{ padding: "12px 14px", fontFamily: "'Inter', sans-serif", fontSize: 13, color: "var(--adv-text-muted)" }}>{eng.client}</td>
                <td style={{ padding: "12px 14px" }}>
                  <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: statusColor(eng.status), background: `${statusColor(eng.status)}15`, border: `1px solid ${statusColor(eng.status)}30`, borderRadius: 3, padding: "1px 7px" }}>{eng.status}</span>
                </td>
                <td style={{ padding: "12px 14px", fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-text-muted)" }}>{eng.scopeCidrs.length} CIDR{eng.scopeCidrs.length !== 1 ? "s" : ""}</td>
                <td style={{ padding: "12px 14px" }}>
                  <div style={{ display: "flex", gap: 5 }}>
                    {(["CRITICAL","HIGH","MEDIUM","LOW"] as const).map((s) => eng.findingsBySeverity[s] > 0 ? (
                      <span key={s} style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: sevColor(s) }}>{eng.findingsBySeverity[s]}</span>
                    ) : null)}
                    {eng.findingCount === 0 && <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)" }}>—</span>}
                  </div>
                </td>
                <td style={{ padding: "12px 14px", fontFamily: "'Inter', sans-serif", fontSize: 14, fontWeight: 700, color: "var(--adv-accent)" }}>{eng.assetCount}</td>
                <td style={{ padding: "12px 14px", minWidth: 100 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <div style={{ flex: 1, height: 5, background: "var(--adv-panel)", borderRadius: 3, overflow: "hidden" }}>
                      <div style={{ height: "100%", width: `${eng.progress}%`, background: eng.progress === 100 ? "#00E676" : "var(--adv-accent)", borderRadius: 3, transition: "width 0.4s ease" }} />
                    </div>
                    <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", flexShrink: 0 }}>{eng.progress}%</span>
                  </div>
                </td>
                <td style={{ padding: "12px 14px", fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", whiteSpace: "nowrap" }}>
                  {eng.startDate} → {eng.endDate}
                </td>
                <td style={{ padding: "12px 14px" }}>
                  <Link href={`/engagements/${eng.id}`}
                    style={{ display: "flex", alignItems: "center", gap: 4, fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-accent)", textDecoration: "none" }}>
                    OPEN <ChevronRight size={11} />
                  </Link>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* ── Multi-step Create Modal ── */}
      {showModal && (
        <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.7)", zIndex: 100, display: "flex", alignItems: "center", justifyContent: "center" }}>
          <div className="animate-scale-in" style={{ background: "var(--adv-panel)", border: "1px solid var(--adv-border)", borderRadius: 10, width: 520, maxHeight: "90vh", overflow: "hidden", display: "flex", flexDirection: "column" }}>
            {/* Modal header */}
            <div style={{ padding: "16px 20px", borderBottom: "1px solid var(--adv-border)", display: "flex", alignItems: "center", justifyContent: "space-between" }}>
              <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 13, color: "var(--adv-text)", letterSpacing: 1 }}>NEW ENGAGEMENT</span>
              <button onClick={() => { setShowModal(false); setStep(0); setForm(EMPTY_FORM); }}
                style={{ background: "none", border: "none", cursor: "pointer", color: "var(--adv-text-muted)" }}>
                <X size={16} />
              </button>
            </div>

            {/* Step indicators */}
            <div style={{ padding: "12px 20px", borderBottom: "1px solid var(--adv-border)", display: "flex", gap: 0 }}>
              {STEPS.map((s, i) => (
                <div key={s} style={{ display: "flex", alignItems: "center" }}>
                  <div style={{
                    width: 22, height: 22, borderRadius: "50%", display: "flex", alignItems: "center", justifyContent: "center",
                    background: i < step ? "var(--adv-accent)" : i === step ? "rgba(37,99,235,0.15)" : "var(--adv-bg)",
                    border: `1.5px solid ${i <= step ? "var(--adv-accent)" : "var(--adv-border)"}`,
                    fontFamily: "'JetBrains Mono', monospace", fontSize: 9,
                    color: i <= step ? (i < step ? "#fff" : "var(--adv-accent)") : "var(--adv-text-muted)",
                  }}>
                    {i < step ? <Check size={11} /> : i + 1}
                  </div>
                  <span style={{ fontFamily: "'Inter', sans-serif", fontSize: 11, color: i === step ? "var(--adv-text)" : "var(--adv-text-muted)", marginLeft: 6, marginRight: i < STEPS.length - 1 ? 12 : 0 }}>{s}</span>
                  {i < STEPS.length - 1 && <div style={{ width: 24, height: 1, background: "var(--adv-border)", marginRight: 8 }} />}
                </div>
              ))}
            </div>

            {/* Step content */}
            <div style={{ padding: "20px 24px", flex: 1, overflowY: "auto" }}>
              {step === 0 && (
                <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
                  {[
                    { label: "ENGAGEMENT NAME *", key: "name" as const, placeholder: "ACME Corp — Q2 VAPT" },
                    { label: "CLIENT NAME *",     key: "client" as const, placeholder: "ACME Corporation" },
                    { label: "DESCRIPTION",       key: "description" as const, placeholder: "Scope and objectives…" },
                    { label: "ASSESSOR",          key: "assessor" as const, placeholder: "analyst@adversa.io" },
                  ].map(({ label, key, placeholder }) => (
                    <div key={key}>
                      <label style={labelStyle}>{label}</label>
                      <input value={form[key]} onChange={(e) => patchForm({ [key]: e.target.value })}
                        placeholder={placeholder} style={inputStyle} />
                    </div>
                  ))}
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
                    <div>
                      <label style={labelStyle}>START DATE *</label>
                      <input type="date" value={form.startDate} onChange={(e) => patchForm({ startDate: e.target.value })} style={inputStyle} />
                    </div>
                    <div>
                      <label style={labelStyle}>END DATE *</label>
                      <input type="date" value={form.endDate} onChange={(e) => patchForm({ endDate: e.target.value })} style={inputStyle} />
                    </div>
                  </div>
                </div>
              )}

              {step === 1 && (
                <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
                  <div>
                    <label style={labelStyle}>SCOPE CIDRs * (comma-separated)</label>
                    <textarea value={form.scopeCidrs} onChange={(e) => patchForm({ scopeCidrs: e.target.value })}
                      placeholder="10.0.0.0/8, 192.168.1.0/24" rows={3}
                      style={{ ...inputStyle, resize: "vertical", lineHeight: 1.5 }} />
                    <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 11, color: "var(--adv-text-muted)", marginTop: 4 }}>
                      {form.scopeCidrs.split(",").filter((s) => s.trim()).length} CIDR{form.scopeCidrs.split(",").filter((s) => s.trim()).length !== 1 ? "s" : ""} entered
                    </div>
                  </div>
                  <div>
                    <label style={labelStyle}>EXCLUDED IPs / CIDRs (comma-separated)</label>
                    <textarea value={form.excludedCidrs} onChange={(e) => patchForm({ excludedCidrs: e.target.value })}
                      placeholder="10.0.0.1, 192.168.1.1" rows={2}
                      style={{ ...inputStyle, resize: "vertical", lineHeight: 1.5 }} />
                  </div>
                  <div style={{ background: "rgba(255,214,0,0.04)", border: "1px solid rgba(255,214,0,0.2)", borderRadius: 5, padding: "10px 12px", fontFamily: "'Inter', sans-serif", fontSize: 12, color: "var(--adv-text-muted)" }}>
                    Scope is enforced server-side by the exploit engine. Out-of-scope targets are blocked automatically.
                  </div>
                </div>
              )}

              {step === 2 && (
                <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
                  <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 13, color: "var(--adv-text-muted)" }}>
                    Optional: add a credential set. Credentials are stored in HashiCorp Vault — only a vault reference is saved here.
                  </div>
                  <div>
                    <label style={labelStyle}>CREDENTIAL TYPE</label>
                    <div style={{ display: "flex", gap: 6 }}>
                      {(["domain", "ssh", "winrm", "api"] as const).map((t) => (
                        <button key={t} onClick={() => patchForm({ credType: t })}
                          style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, padding: "5px 12px", borderRadius: 4, cursor: "pointer",
                            border: `1px solid ${form.credType === t ? "var(--adv-accent)" : "var(--adv-border)"}`,
                            background: form.credType === t ? "rgba(37,99,235,0.1)" : "transparent",
                            color: form.credType === t ? "var(--adv-accent)" : "var(--adv-text-muted)" }}>
                          {t.toUpperCase()}
                        </button>
                      ))}
                    </div>
                  </div>
                  <div>
                    <label style={labelStyle}>LABEL</label>
                    <input value={form.credLabel} onChange={(e) => patchForm({ credLabel: e.target.value })}
                      placeholder="e.g. corp.local standard user" style={inputStyle} />
                  </div>
                  <div>
                    <label style={labelStyle}>USERNAME</label>
                    <input value={form.credUser} onChange={(e) => patchForm({ credUser: e.target.value })}
                      placeholder="e.g. pentest@corp.local" style={inputStyle} />
                  </div>
                  <div style={{ background: "rgba(37,99,235,0.04)", border: "1px solid rgba(37,99,235,0.12)", borderRadius: 5, padding: "8px 12px", fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)" }}>
                    Actual credentials are stored in Vault at vault/eng-{"{id}"}/cred. Never saved in plaintext.
                  </div>
                </div>
              )}

              {step === 3 && (
                <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
                  <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-text-muted)", marginBottom: 4 }}>REVIEW BEFORE CREATING</div>
                  {[
                    { label: "NAME",       value: form.name },
                    { label: "CLIENT",     value: form.client },
                    { label: "DATES",      value: `${form.startDate} → ${form.endDate}` },
                    { label: "ASSESSOR",   value: form.assessor },
                    { label: "SCOPE",      value: `${form.scopeCidrs.split(",").filter((s) => s.trim()).length} CIDR(s): ${form.scopeCidrs}` },
                    { label: "EXCLUDED",   value: form.excludedCidrs || "—" },
                    { label: "CREDENTIAL", value: form.credLabel || "None added" },
                  ].map(({ label, value }) => (
                    <div key={label} style={{ display: "flex", padding: "6px 0", borderBottom: "1px solid var(--adv-border)" }}>
                      <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", width: 110, flexShrink: 0 }}>{label}</span>
                      <span style={{ fontFamily: "'Inter', sans-serif", fontSize: 13, color: "var(--adv-text)" }}>{value}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Footer */}
            <div style={{ padding: "14px 20px", borderTop: "1px solid var(--adv-border)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <button disabled={step === 0} onClick={() => setStep((p) => p - 1)}
                style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-text-muted)", background: "none", border: "1px solid var(--adv-border)", borderRadius: 4, padding: "6px 16px", cursor: step === 0 ? "not-allowed" : "pointer" }}>
                BACK
              </button>
              {step < STEPS.length - 1 ? (
                <button onClick={() => setStep((p) => p + 1)} disabled={!canProceed()}
                  style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: canProceed() ? "var(--adv-accent)" : "#64748B", background: canProceed() ? "rgba(37,99,235,0.08)" : "transparent", border: `1px solid ${canProceed() ? "rgba(37,99,235,0.3)" : "var(--adv-border)"}`, borderRadius: 4, padding: "6px 20px", cursor: canProceed() ? "pointer" : "not-allowed" }}>
                  NEXT
                </button>
              ) : (
                <button onClick={submit} disabled={createMutation.isPending}
                  style={{ display: "flex", alignItems: "center", gap: 6, fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "#00E676", background: "rgba(0,230,118,0.08)", border: "1px solid rgba(0,230,118,0.3)", borderRadius: 4, padding: "6px 20px", cursor: "pointer" }}>
                  {createMutation.isPending ? <RefreshCw size={11} style={{ animation: "spin 1s linear infinite" }} /> : <Check size={11} />}
                  CREATE ENGAGEMENT
                </button>
              )}
            </div>
          </div>
        </div>
      )}
    </PageShell>
  );
}
