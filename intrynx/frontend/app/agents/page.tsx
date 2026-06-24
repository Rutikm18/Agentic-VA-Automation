"use client";

import React, { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Cpu, Wifi, WifiOff, Activity, Clock, AlertTriangle,
  ChevronDown, ChevronRight, Play, RefreshCw, Plus,
  CheckCircle2, XCircle, Circle,
} from "lucide-react";
import { PageShell } from "../../components/PageShell";
import { useToast } from "../../hooks/useToast";
import { fetchJson, isUnauthorized, errorMessage } from "../../lib/fetcher";
import {
  SkeletonRows, ErrorState, Unauthorized, EmptyState,
} from "../../components/states/DataState";

/* ─── Types ─── */
type AgentStatus = "ONLINE" | "OFFLINE" | "BUSY" | "ERROR";
type JobStatus   = "PENDING" | "RUNNING" | "COMPLETED" | "FAILED" | "CANCELLED";
type JobType     = "discovery" | "vuln_scan" | "ad_enum" | "lateral_movement" | "cloud_scan";
type TabKey      = "agents" | "jobs" | "kafka";

interface Agent {
  id: string; name: string; location: string; status: AgentStatus;
  capabilities: { type: JobType; enabled: boolean }[];
  networkSegments: string[]; lastHeartbeat: string; version: string; ip: string;
  currentJobId?: string; tlsCertExpiry: string;
}

interface ScanJob {
  id: string; agentId?: string; engagementId: string; type: JobType;
  status: JobStatus; targetCidrs: string[]; profile: string;
  progress: number; createdAt: string; startedAt?: string;
  completedAt?: string; result?: Record<string, unknown>; errorMessage?: string;
}

interface KafkaTopic {
  name: string; partitions: number; replicationFactor: number;
  retentionMs: number; messageCount: number; lag: number;
  consumers: string[]; producers: string[]; description: string;
}

/* ─── Helpers ─── */
function agentStatusColor(s: AgentStatus) {
  if (s === "ONLINE")  return "#00E676";
  if (s === "BUSY")    return "#FFD600";
  if (s === "ERROR")   return "#FF1744";
  return "#64748B";
}

function jobStatusColor(s: JobStatus) {
  if (s === "COMPLETED") return "#00E676";
  if (s === "RUNNING")   return "var(--adv-accent)";
  if (s === "PENDING")   return "#FFD600";
  if (s === "FAILED")    return "#FF1744";
  return "#64748B";
}

function jobTypeIcon(t: JobType) {
  const icons: Record<JobType, string> = {
    discovery: "DISC", vuln_scan: "VULN", ad_enum: "AD",
    lateral_movement: "LAT", cloud_scan: "CLOUD",
  };
  return icons[t] ?? t;
}

function secsTillOffline(lastHeartbeat: string) {
  const secs = Math.floor((Date.now() - new Date(lastHeartbeat).getTime()) / 1000);
  return secs;
}

function AgentStatusDot({ status }: { status: AgentStatus }) {
  return (
    <span className={status === "ONLINE" || status === "BUSY" ? "animate-pulse-dot" : ""}
      style={{ display: "inline-block", width: 8, height: 8, borderRadius: "50%", background: agentStatusColor(status), flexShrink: 0 }} />
  );
}

/* ─── Kafka lag badge ─── */
function LagBadge({ lag }: { lag: number }) {
  const color = lag === 0 ? "#00E676" : lag < 10 ? "#FFD600" : "#FF1744";
  return (
    <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color, background: `${color}15`, border: `1px solid ${color}30`, borderRadius: 3, padding: "1px 6px" }}>
      LAG {lag}
    </span>
  );
}

/* ─── Main Page ─── */
export default function AgentsPage() {
  const { success, error: toastError, info } = useToast();
  const qc = useQueryClient();
  const [activeTab, setActiveTab] = useState<TabKey>("agents");
  const [expandedAgent, setExpandedAgent] = useState<string | null>(null);
  const [expandedTopic, setExpandedTopic] = useState<string | null>(null);
  const [showRegisterForm, setShowRegisterForm] = useState(false);

  const [regName,     setRegName]     = useState("");
  const [regLocation, setRegLocation] = useState("");
  const [regSegments, setRegSegments] = useState("");
  const [regCaps,     setRegCaps]     = useState<JobType[]>(["discovery", "vuln_scan"]);

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["agents"],
    queryFn: () =>
      fetchJson<{ agents?: Agent[]; jobs?: ScanJob[]; stats?: Record<string, number> }>(
        "/api/agents/register",
      ),
    refetchInterval: 15_000,
    retry: (count, err) => !isUnauthorized(err) && count < 2,
  });

  const { data: kafkaData } = useQuery({
    queryKey: ["kafka-topics"],
    queryFn: () => fetch("/api/kafka/topics").then((r) => r.json()),
    refetchInterval: 30_000,
  });

  const registerMutation = useMutation({
    mutationFn: (body: object) =>
      fetch("/api/agents/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      }).then((r) => r.json()),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["agents"] });
      success("Registered", "Agent registered successfully. Store the TLS cert and Vault token.");
      setShowRegisterForm(false);
      setRegName(""); setRegLocation(""); setRegSegments("");
    },
    onError: () => toastError("Error", "Agent registration failed."),
  });

  const agents: Agent[]    = data?.agents    ?? [];
  const jobs: ScanJob[]    = data?.jobs       ?? [];
  const stats              = data?.stats      ?? {};
  const topics: KafkaTopic[] = kafkaData?.topics ?? [];

  const ALL_JOB_TYPES: JobType[] = ["discovery", "vuln_scan", "ad_enum", "lateral_movement", "cloud_scan"];

  const tabs: { key: TabKey; label: string; count?: number }[] = [
    { key: "agents", label: "SCANNING AGENTS", count: agents.length },
    { key: "jobs",   label: "SCAN JOBS",        count: jobs.length },
    { key: "kafka",  label: "KAFKA TOPICS",     count: topics.length },
  ];

  return (
    <PageShell
      title="AGENT MANAGER"
      subtitle="SCANNING AGENTS · JOBS · KAFKA TOPICS · mTLS · VAULT"
      statusItems={[
        { label: "ONLINE", value: String(stats.online ?? 0),  color: "#00E676" },
        { label: "BUSY",   value: String(stats.busy ?? 0),    color: "#FFD600" },
        { label: "PENDING JOBS", value: String(stats.pending ?? 0), color: stats.pending > 0 ? "#FF6D00" : "var(--adv-text-muted)" },
      ]}
    >
      {/* Tab bar + actions */}
      <div style={{ display: "flex", alignItems: "center", borderBottom: "1px solid var(--adv-border)", marginBottom: 0, flexShrink: 0 }}>
        {tabs.map(({ key, label, count }) => (
          <button key={key} onClick={() => setActiveTab(key)}
            style={{
              padding: "8px 16px", border: "none", background: "none", cursor: "pointer",
              borderBottom: `2px solid ${activeTab === key ? "var(--adv-accent)" : "transparent"}`,
              display: "flex", alignItems: "center", gap: 6, marginBottom: -1,
              fontFamily: "'JetBrains Mono', monospace", fontSize: 10,
              color: activeTab === key ? "var(--adv-accent)" : "var(--adv-text-muted)",
            }}>
            {label}
            {count !== undefined && <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 8, color: activeTab === key ? "var(--adv-accent)" : "var(--adv-text-muted)", background: "var(--adv-panel)", borderRadius: 8, padding: "0 5px" }}>{count}</span>}
          </button>
        ))}
        <div style={{ flex: 1 }} />
        {activeTab === "agents" && (
          <button onClick={() => setShowRegisterForm(true)}
            style={{ display: "flex", alignItems: "center", gap: 5, padding: "6px 14px", marginRight: 4, borderRadius: 5, border: "1px solid rgba(37,99,235,0.3)", background: "rgba(37,99,235,0.08)", color: "var(--adv-accent)", fontFamily: "'JetBrains Mono', monospace", fontSize: 10, cursor: "pointer" }}>
            <Plus size={11} /> REGISTER AGENT
          </button>
        )}
      </div>

      <div style={{ flex: 1, overflowY: "auto", paddingTop: 14 }}>

        {/* ── AGENTS TAB ─────────────────────────────────────── */}
        {activeTab === "agents" && (
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            {/* Stats bar */}
            <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 10, marginBottom: 4 }}>
              {[
                { label: "TOTAL AGENTS",  value: stats.total   ?? 0, color: "var(--adv-accent)" },
                { label: "ONLINE",         value: stats.online  ?? 0, color: "#00E676" },
                { label: "BUSY",           value: stats.busy    ?? 0, color: "#FFD600" },
                { label: "RUNNING JOBS",   value: stats.running ?? 0, color: "var(--adv-accent)" },
              ].map((s) => (
                <div key={s.label} style={{ background: "var(--adv-panel)", border: "1px solid var(--adv-border)", borderRadius: 6, padding: "10px 14px" }}>
                  <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", marginBottom: 4 }}>{s.label}</div>
                  <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 24, fontWeight: 700, color: s.color }}>{s.value}</div>
                </div>
              ))}
            </div>

            {isLoading && <SkeletonRows rows={3} />}

            {!isLoading && error && isUnauthorized(error) && <Unauthorized />}

            {!isLoading && error && !isUnauthorized(error) && (
              <ErrorState title="Failed to load probes" detail={errorMessage(error)} onRetry={() => refetch()} />
            )}

            {!isLoading && !error && agents.length === 0 && (
              <EmptyState
                icon={Cpu}
                title="No probes registered yet"
                hint="Deploy a probe inside a target network — once it dials in and registers, it appears here."
                action={
                  <button onClick={() => setShowRegisterForm(true)}
                    style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: "var(--adv-accent)", background: "var(--adv-accent-bg)", border: "1px solid var(--adv-accent-border)", borderRadius: 6, padding: "6px 14px", cursor: "pointer" }}>
                    Register a probe
                  </button>
                }
              />
            )}

            {agents.map((agent) => {
              const heartbeatAge = secsTillOffline(agent.lastHeartbeat);
              const stale = heartbeatAge > 60;

              return (
                <div key={agent.id} style={{ background: "var(--adv-bg)", border: `1px solid ${agentStatusColor(agent.status)}20`, borderLeft: `3px solid ${agentStatusColor(agent.status)}`, borderRadius: 6, overflow: "hidden" }}>
                  <div onClick={() => setExpandedAgent(expandedAgent === agent.id ? null : agent.id)}
                    style={{ padding: "12px 14px", cursor: "pointer", display: "flex", alignItems: "center", gap: 12 }}>
                    <AgentStatusDot status={agent.status} />
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
                        <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, color: "var(--adv-text)", fontWeight: 600 }}>{agent.name}</span>
                        <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: agentStatusColor(agent.status), background: `${agentStatusColor(agent.status)}15`, borderRadius: 3, padding: "0 6px" }}>{agent.status}</span>
                        {agent.currentJobId && <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "#FFD600" }}>JOB: {agent.currentJobId}</span>}
                        {stale && <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "#FF1744" }}>HEARTBEAT STALE ({heartbeatAge}s)</span>}
                      </div>
                      <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", marginTop: 3 }}>
                        {agent.location} · {agent.ip} · v{agent.version} · Last heartbeat: {heartbeatAge}s ago
                      </div>
                    </div>
                    {expandedAgent === agent.id ? <ChevronDown size={13} color="#64748B" /> : <ChevronRight size={13} color="#64748B" />}
                  </div>

                  {expandedAgent === agent.id && (
                    <div style={{ borderTop: "1px solid var(--adv-border)", padding: "14px 16px", display: "flex", flexDirection: "column", gap: 12 }}>
                      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
                        {/* Capabilities */}
                        <div style={{ background: "var(--adv-panel)", border: "1px solid var(--adv-border)", borderRadius: 5, padding: "10px 12px" }}>
                          <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", marginBottom: 8 }}>CAPABILITIES</div>
                          {agent.capabilities.map((c) => (
                            <div key={c.type} style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 4 }}>
                              {c.enabled ? <CheckCircle2 size={11} color="#00E676" /> : <XCircle size={11} color="#64748B" />}
                              <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: c.enabled ? "var(--adv-text)" : "var(--adv-text-muted)" }}>{c.type}</span>
                            </div>
                          ))}
                        </div>

                        {/* Network + mTLS info */}
                        <div style={{ background: "var(--adv-panel)", border: "1px solid var(--adv-border)", borderRadius: 5, padding: "10px 12px" }}>
                          <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", marginBottom: 8 }}>NETWORK & SECURITY</div>
                          {[
                            { label: "Segments",  value: agent.networkSegments.join(", ") || "—" },
                            { label: "TLS Expiry", value: new Date(agent.tlsCertExpiry).toLocaleDateString() },
                            { label: "Vault Token",value: "••••••••" },
                            { label: "Agent ID",   value: agent.id },
                          ].map((r) => (
                            <div key={r.label} style={{ display: "flex", gap: 8, marginBottom: 4 }}>
                              <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", width: 80, flexShrink: 0 }}>{r.label}</span>
                              <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text)" }}>{r.value}</span>
                            </div>
                          ))}
                        </div>
                      </div>

                      {/* Agent registration curl example */}
                      <div style={{ background: "var(--adv-panel)", border: "1px solid var(--adv-border)", borderRadius: 5, overflow: "hidden" }}>
                        <div style={{ padding: "5px 10px", borderBottom: "1px solid var(--adv-border)", fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)" }}>
                          HEARTBEAT COMMAND (runs every 30s)
                        </div>
                        <pre style={{ margin: 0, padding: "8px 12px", fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "#00D4FF", lineHeight: 1.6 }}>
{`curl -X POST https://adversa.internal/api/agents/${agent.id}/heartbeat \\
  --cert /etc/adversa/certs/client.pem \\
  --key  /etc/adversa/certs/client.key \\
  --cacert /etc/adversa/certs/ca.pem`}
                        </pre>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}

        {/* ── JOBS TAB ───────────────────────────────────────── */}
        {activeTab === "jobs" && (
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {jobs.length === 0 ? (
              <div style={{ padding: "60px 0", textAlign: "center", fontFamily: "'JetBrains Mono', monospace", fontSize: 13, color: "var(--adv-text-muted)" }}>No scan jobs</div>
            ) : (
              <div style={{ background: "var(--adv-bg)", border: "1px solid var(--adv-border)", borderRadius: 6, overflow: "hidden" }}>
                <table style={{ width: "100%", borderCollapse: "collapse" }}>
                  <thead>
                    <tr>
                      {["JOB ID", "TYPE", "AGENT", "ENGAGEMENT", "STATUS", "PROGRESS", "PROFILE", "TARGETS", "CREATED"].map((h) => (
                        <th key={h} style={{ padding: "8px 12px", textAlign: "left", fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", borderBottom: "1px solid var(--adv-border)", whiteSpace: "nowrap" }}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {jobs.map((job, i) => (
                      <tr key={job.id} style={{ borderBottom: i < jobs.length - 1 ? "1px solid var(--adv-border)" : "none" }}>
                        <td style={{ padding: "9px 12px", fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-accent)" }}>{job.id}</td>
                        <td style={{ padding: "9px 12px", fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "#00D4FF", background: "rgba(0,212,255,0.04)" }}>{jobTypeIcon(job.type)}</td>
                        <td style={{ padding: "9px 12px", fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-text-muted)" }}>{job.agentId ?? "—"}</td>
                        <td style={{ padding: "9px 12px", fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-text)" }}>{job.engagementId}</td>
                        <td style={{ padding: "9px 12px" }}>
                          <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: jobStatusColor(job.status), background: `${jobStatusColor(job.status)}15`, borderRadius: 3, padding: "1px 6px" }}>{job.status}</span>
                        </td>
                        <td style={{ padding: "9px 12px", minWidth: 100 }}>
                          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                            <div style={{ flex: 1, height: 5, background: "var(--adv-panel)", borderRadius: 3, overflow: "hidden" }}>
                              <div style={{ height: "100%", width: `${job.progress}%`, background: jobStatusColor(job.status), borderRadius: 3 }} />
                            </div>
                            <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", flexShrink: 0 }}>{job.progress}%</span>
                          </div>
                        </td>
                        <td style={{ padding: "9px 12px", fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)" }}>{job.profile}</td>
                        <td style={{ padding: "9px 12px", fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)" }}>{job.targetCidrs.join(", ")}</td>
                        <td style={{ padding: "9px 12px", fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", whiteSpace: "nowrap" }}>{new Date(job.createdAt).toLocaleTimeString()}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {/* Kafka topic reference */}
            <div style={{ marginTop: 8, background: "rgba(37,99,235,0.04)", border: "1px solid rgba(37,99,235,0.15)", borderRadius: 6, padding: "10px 14px", fontFamily: "'Inter', sans-serif", fontSize: 12, color: "var(--adv-text-muted)" }}>
              Jobs are distributed via Kafka topic <code style={{ fontFamily: "'JetBrains Mono', monospace", color: "var(--adv-accent)" }}>scan-jobs</code>. Results are published to <code style={{ fontFamily: "'JetBrains Mono', monospace", color: "var(--adv-accent)" }}>scan-results</code>. View topic health in the KAFKA TOPICS tab.
            </div>
          </div>
        )}

        {/* ── KAFKA TOPICS TAB ───────────────────────────────── */}
        {activeTab === "kafka" && (
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 13, color: "var(--adv-text-muted)", marginBottom: 4 }}>
              5 topics · 3× replication · Partitioned for engagement-level ordering
            </div>
            {topics.map((topic) => (
              <div key={topic.name} style={{ background: "var(--adv-bg)", border: "1px solid var(--adv-border)", borderRadius: 6, overflow: "hidden" }}>
                <div onClick={() => setExpandedTopic(expandedTopic === topic.name ? null : topic.name)}
                  style={{ padding: "12px 14px", cursor: "pointer", display: "flex", alignItems: "center", gap: 12 }}>
                  <Activity size={13} color={topic.lag === 0 ? "#00E676" : "#FFD600"} />
                  <div style={{ flex: 1 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
                      <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, color: "var(--adv-accent)", fontWeight: 600 }}>{topic.name}</span>
                      <LagBadge lag={topic.lag} />
                      <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)" }}>
                        {topic.partitions}p · {topic.replicationFactor}r · {(topic.messageCount).toLocaleString()} msgs
                      </span>
                    </div>
                    <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 11, color: "var(--adv-text-muted)", marginTop: 2 }}>{topic.description}</div>
                  </div>
                  {expandedTopic === topic.name ? <ChevronDown size={13} color="#64748B" /> : <ChevronRight size={13} color="#64748B" />}
                </div>
                {expandedTopic === topic.name && (
                  <div style={{ borderTop: "1px solid var(--adv-border)", padding: "12px 14px", display: "flex", flexDirection: "column", gap: 10 }}>
                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
                      <div>
                        <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", marginBottom: 6 }}>PRODUCERS</div>
                        {topic.producers.map((p) => (
                          <div key={p} style={{ display: "flex", alignItems: "center", gap: 5, marginBottom: 3 }}>
                            <Play size={9} color="#00E676" />
                            <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-text)" }}>{p}</span>
                          </div>
                        ))}
                      </div>
                      <div>
                        <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", marginBottom: 6 }}>CONSUMERS</div>
                        {topic.consumers.map((c) => (
                          <div key={c} style={{ display: "flex", alignItems: "center", gap: 5, marginBottom: 3 }}>
                            <Circle size={9} color="var(--adv-accent)" />
                            <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-text)" }}>{c}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                    <div style={{ display: "flex", gap: 20, flexWrap: "wrap", fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)" }}>
                      <span>Partitions: <span style={{ color: "var(--adv-text)" }}>{topic.partitions}</span></span>
                      <span>Replication: <span style={{ color: "var(--adv-text)" }}>{topic.replicationFactor}</span></span>
                      <span>Retention: <span style={{ color: "var(--adv-text)" }}>{topic.retentionMs / 86400000}d</span></span>
                      <span>Messages: <span style={{ color: "var(--adv-text)" }}>{topic.messageCount.toLocaleString()}</span></span>
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* ── Register Modal ── */}
      {showRegisterForm && (
        <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.7)", zIndex: 100, display: "flex", alignItems: "center", justifyContent: "center" }}>
          <div className="animate-scale-in" style={{ background: "var(--adv-panel)", border: "1px solid var(--adv-border)", borderRadius: 10, width: 480, overflow: "hidden" }}>
            <div style={{ padding: "16px 20px", borderBottom: "1px solid var(--adv-border)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 13, color: "var(--adv-text)" }}>REGISTER AGENT</span>
              <button onClick={() => setShowRegisterForm(false)} style={{ background: "none", border: "none", cursor: "pointer", color: "var(--adv-text-muted)" }}>✕</button>
            </div>
            <div style={{ padding: 20, display: "flex", flexDirection: "column", gap: 14 }}>
              {[
                { label: "AGENT NAME", value: regName, setter: setRegName, placeholder: "corp-agent-02" },
                { label: "LOCATION",   value: regLocation, setter: setRegLocation, placeholder: "On-Premise / CORP" },
                { label: "NETWORK SEGMENTS (comma-separated)", value: regSegments, setter: setRegSegments, placeholder: "10.0.0.0/8, 192.168.1.0/24" },
              ].map(({ label, value, setter, placeholder }) => (
                <div key={label}>
                  <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", marginBottom: 5 }}>{label}</div>
                  <input value={value} onChange={(e) => setter(e.target.value)} placeholder={placeholder}
                    style={{ width: "100%", boxSizing: "border-box", background: "var(--adv-bg)", border: "1px solid var(--adv-border)", borderRadius: 5, padding: "8px 10px", color: "var(--adv-text)", fontFamily: "'JetBrains Mono', monospace", fontSize: 12, outline: "none" }} />
                </div>
              ))}
              <div>
                <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", marginBottom: 6 }}>CAPABILITIES</div>
                <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                  {ALL_JOB_TYPES.map((t) => {
                    const on = regCaps.includes(t);
                    return (
                      <button key={t} onClick={() => setRegCaps((p) => on ? p.filter((x) => x !== t) : [...p, t])}
                        style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, padding: "4px 10px", borderRadius: 3, cursor: "pointer",
                          border: `1px solid ${on ? "var(--adv-accent)" : "var(--adv-border)"}`,
                          background: on ? "rgba(37,99,235,0.1)" : "transparent",
                          color: on ? "var(--adv-accent)" : "var(--adv-text-muted)" }}>
                        {t}
                      </button>
                    );
                  })}
                </div>
              </div>
            </div>
            <div style={{ padding: "12px 20px", borderTop: "1px solid var(--adv-border)", display: "flex", justifyContent: "flex-end", gap: 8 }}>
              <button onClick={() => setShowRegisterForm(false)} style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, padding: "6px 16px", borderRadius: 4, border: "1px solid var(--adv-border)", background: "transparent", color: "var(--adv-text-muted)", cursor: "pointer" }}>
                CANCEL
              </button>
              <button onClick={() => registerMutation.mutate({ agentName: regName, location: regLocation, networkSegments: regSegments.split(",").map((s) => s.trim()).filter(Boolean), capabilities: regCaps })}
                disabled={!regName || !regLocation || registerMutation.isPending}
                style={{ display: "flex", alignItems: "center", gap: 5, fontFamily: "'JetBrains Mono', monospace", fontSize: 10, padding: "6px 20px", borderRadius: 4, border: "1px solid rgba(0,230,118,0.3)", background: "rgba(0,230,118,0.08)", color: "#00E676", cursor: "pointer" }}>
                {registerMutation.isPending ? <RefreshCw size={11} style={{ animation: "spin 1s linear infinite" }} /> : <Plus size={11} />}
                REGISTER & ISSUE CERT
              </button>
            </div>
          </div>
        </div>
      )}
    </PageShell>
  );
}
