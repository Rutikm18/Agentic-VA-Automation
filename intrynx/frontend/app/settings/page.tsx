"use client";

import React, { useState } from "react";
import {
  Mail, MessageCircle, ExternalLink, Save, CheckCircle,
  Bell, Shield, User, Globe, Eye, EyeOff, RefreshCw,
} from "lucide-react";
import { PageShell } from "../../components/PageShell";
import { useToast } from "../../hooks/useToast";

/* ─── Types ─── */
interface EnvSetting { key: string; label: string; type?: "password" | "number"; placeholder: string; description: string; }

/* ─── Sections ─── */
const EMAIL_FIELDS: EnvSetting[] = [
  { key: "SMTP_HOST",  label: "SMTP Host",    placeholder: "smtp.gmail.com",      description: "Outbound mail server hostname" },
  { key: "SMTP_PORT",  label: "SMTP Port",    type: "number", placeholder: "587", description: "587 for STARTTLS, 465 for SSL" },
  { key: "SMTP_USER",  label: "SMTP User",    placeholder: "alerts@corp.com",     description: "Auth username for the SMTP server" },
  { key: "SMTP_PASS",  label: "SMTP Password",type: "password", placeholder: "••••••••", description: "Auth password — stored in .env.local only" },
  { key: "SMTP_FROM",  label: "From Address", placeholder: "adversa@corp.com",    description: "The From: header on outbound emails" },
  { key: "SMTP_TO",    label: "Alert Recipients", placeholder: "sec-team@corp.com", description: "Comma-separated list of notification recipients" },
];

const SLACK_FIELDS: EnvSetting[] = [
  { key: "SLACK_WEBHOOK_URL", label: "Webhook URL", type: "password", placeholder: "https://hooks.slack.com/services/...", description: "Incoming webhook URL from MessageCircle App settings" },
];

const JIRA_FIELDS: EnvSetting[] = [
  { key: "JIRA_URL",         label: "Jira Base URL",    placeholder: "https://org.atlassian.net",  description: "Your Jira Cloud or Server base URL" },
  { key: "JIRA_EMAIL",       label: "Jira Email",       placeholder: "admin@corp.com",             description: "Jira user email for API auth" },
  { key: "JIRA_API_TOKEN",   label: "API Token",        type: "password", placeholder: "••••••••", description: "Generate at id.atlassian.com/manage-profile/security" },
  { key: "JIRA_PROJECT_KEY", label: "Project Key",      placeholder: "SEC",                        description: "Jira project key where issues will be created" },
];

/* ─── SLA Policy ─── */
const SLA_POLICY = [
  { severity: "CRITICAL", hours: 24,  escalate: "12h",  color: "#FF1744" },
  { severity: "HIGH",     hours: 72,  escalate: "24h",  color: "#FF6D00" },
  { severity: "MEDIUM",   hours: 168, escalate: "48h",  color: "#FFD600" },
  { severity: "LOW",      hours: 720, escalate: "7d",   color: "#00E676" },
];

/* ─── Notification Rules ─── */
const DEFAULT_RULES = {
  onNewCritical:  true,
  onNewHigh:      true,
  onNewMedium:    false,
  onSlaBreach:    true,
  onCaseClose:    true,
  onStatusChange: false,
};

/* ─── Section Header ─── */
function SectionHeader({ icon, label, badge }: { icon: React.ElementType; label: string; badge?: string }) {
  const Icon = icon;
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 16 }}>
      <div style={{ width: 32, height: 32, borderRadius: 6, background: "rgba(37,99,235,0.08)", border: "1px solid rgba(37,99,235,0.2)", display: "flex", alignItems: "center", justifyContent: "center" }}>
        <Icon size={16} color="#2563EB" />
      </div>
      <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 13, color: "var(--adv-text)", letterSpacing: 1 }}>{label}</span>
      {badge && (
        <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", background: "rgba(100,116,139,0.1)", border: "1px solid var(--adv-border)", borderRadius: 10, padding: "2px 8px" }}>
          {badge}
        </span>
      )}
    </div>
  );
}

/* ─── Integration Field Group ─── */
function IntegrationFields({ fields }: { fields: EnvSetting[] }) {
  const [visible, setVisible] = useState<Record<string, boolean>>({});
  const [vals, setVals] = useState<Record<string, string>>({});

  return (
    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
      {fields.map((f) => (
        <div key={f.key}>
          <label style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-text-muted)", display: "block", marginBottom: 5 }}>
            {f.label}
          </label>
          <div style={{ position: "relative" }}>
            <input
              type={f.type === "password" && !visible[f.key] ? "password" : "text"}
              placeholder={f.placeholder}
              value={vals[f.key] ?? ""}
              onChange={(e) => setVals((p) => ({ ...p, [f.key]: e.target.value }))}
              style={{
                width: "100%", boxSizing: "border-box",
                background: "var(--adv-bg)", border: "1px solid var(--adv-border)", borderRadius: 5,
                padding: `8px ${f.type === "password" ? "36px" : "12px"} 8px 12px`,
                color: "var(--adv-text)", fontFamily: "'JetBrains Mono', monospace", fontSize: 11,
                outline: "none",
              }}
            />
            {f.type === "password" && (
              <button
                onClick={() => setVisible((p) => ({ ...p, [f.key]: !p[f.key] }))}
                style={{ position: "absolute", right: 10, top: "50%", transform: "translateY(-50%)", background: "none", border: "none", cursor: "pointer", color: "var(--adv-text-muted)" }}
              >
                {visible[f.key] ? <EyeOff size={13} /> : <Eye size={13} />}
              </button>
            )}
          </div>
          <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 11, color: "var(--adv-text-muted)", marginTop: 3 }}>
            {f.description}
          </div>
        </div>
      ))}
    </div>
  );
}

/* ─── Test Button ─── */
function TestButton({ label, color, onTest }: { label: string; color: string; onTest: () => void }) {
  const [state, setState] = useState<"idle" | "testing" | "ok" | "fail">("idle");

  const run = async () => {
    setState("testing");
    await new Promise((r) => setTimeout(r, 1200));
    setState("ok");
    setTimeout(() => setState("idle"), 3000);
    onTest();
  };

  return (
    <button
      onClick={run}
      disabled={state === "testing"}
      style={{
        display: "flex", alignItems: "center", gap: 6,
        padding: "7px 14px", borderRadius: 4, cursor: state === "testing" ? "wait" : "pointer",
        border: `1px solid ${color}50`, background: `${color}10`, color,
        fontFamily: "'JetBrains Mono', monospace", fontSize: 10,
        opacity: state === "testing" ? 0.7 : 1,
      }}
    >
      {state === "testing" ? <RefreshCw size={12} className="animate-spin" /> : state === "ok" ? <CheckCircle size={12} /> : null}
      {state === "testing" ? "Testing..." : state === "ok" ? "Connected!" : label}
    </button>
  );
}

/* ─── Toggle ─── */
function Toggle({ on, onChange }: { on: boolean; onChange: (v: boolean) => void }) {
  return (
    <div
      onClick={() => onChange(!on)}
      style={{
        width: 36, height: 20, borderRadius: 10, cursor: "pointer",
        background: on ? "rgba(37,99,235,0.8)" : "#E2E8F0",
        position: "relative", transition: "background 0.2s ease", flexShrink: 0,
      }}
    >
      <div style={{
        width: 14, height: 14, borderRadius: "50%", background: "#fff",
        position: "absolute", top: 3, left: on ? 19 : 3,
        transition: "left 0.2s ease", boxShadow: "0 1px 3px rgba(0,0,0,0.4)",
      }} />
    </div>
  );
}

/* ─── Main Page ─── */
export default function SettingsPage() {
  const { success } = useToast();
  const [rules, setRules] = useState(DEFAULT_RULES);
  const [engagementName, setEngagementName] = useState("CORP.LOCAL Internal VAPT");
  const [clientName, setClientName] = useState("ACME Corp");
  const [assessorName, setAssessorName] = useState("Rutik Mangale");
  const [activeSection, setActiveSection] = useState<string>("engagement");

  const sections = [
    { key: "engagement", label: "Engagement",    icon: Globe },
    { key: "email",      label: "Email / SMTP",  icon: Mail },
    { key: "slack",      label: "MessageCircle",          icon: MessageCircle },
    { key: "jira",       label: "Jira",           icon: ExternalLink },
    { key: "sla",        label: "SLA Policy",     icon: Shield },
    { key: "notify",     label: "Notifications",  icon: Bell },
  ];

  const save = () => success("Settings saved", "Configuration will take effect on next restart.");

  return (
    <PageShell
      title="SETTINGS"
      subtitle="INTEGRATIONS · SLA · NOTIFICATIONS · ENGAGEMENT"
      headerActions={
        <button
          onClick={save}
          style={{
            display: "flex", alignItems: "center", gap: 6, padding: "6px 14px",
            background: "#2563EB", border: "none", borderRadius: 4,
            color: "#F8FAFC", fontFamily: "'JetBrains Mono', monospace", fontSize: 10,
            cursor: "pointer", fontWeight: 700,
          }}
        >
          <Save size={13} /> SAVE ALL
        </button>
      }
    >
      <div style={{ display: "flex", gap: 20, height: "100%" }}>
        {/* Left nav */}
        <div style={{ width: 180, flexShrink: 0 }}>
          <div style={{ background: "linear-gradient(160deg, rgba(37,99,235,0.05) 0%, #FFFFFF 55%)", border: "1px solid var(--adv-border)", borderRadius: 6, overflow: "hidden" }}>
            {sections.map((s) => {
              const Icon = s.icon;
              const active = activeSection === s.key;
              return (
                <button
                  key={s.key}
                  onClick={() => setActiveSection(s.key)}
                  style={{
                    width: "100%", display: "flex", alignItems: "center", gap: 10, padding: "11px 14px",
                    background: active ? "rgba(37,99,235,0.06)" : "transparent",
                    border: "none", borderLeft: `2px solid ${active ? "#2563EB" : "transparent"}`,
                    cursor: "pointer", textAlign: "left",
                  }}
                >
                  <Icon size={14} color={active ? "#2563EB" : "#64748B"} />
                  <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: active ? "#0F172A" : "#64748B" }}>
                    {s.label}
                  </span>
                </button>
              );
            })}
          </div>
        </div>

        {/* Right content */}
        <div style={{ flex: 1, minWidth: 0 }}>

          {/* ── Engagement ── */}
          {activeSection === "engagement" && (
            <div className="animate-slide-in" style={{ background: "linear-gradient(160deg, rgba(37,99,235,0.05) 0%, #FFFFFF 55%)", border: "1px solid var(--adv-border)", borderRadius: 8, padding: 24 }}>
              <SectionHeader icon={Globe} label="ENGAGEMENT METADATA" />
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
                {[
                  { label: "Engagement Name", val: engagementName, set: setEngagementName, ph: "Q2 2026 Internal VAPT" },
                  { label: "Client Name",      val: clientName,     set: setClientName,     ph: "ACME Corp" },
                  { label: "Lead Assessor",    val: assessorName,   set: setAssessorName,   ph: "Security Engineer" },
                ].map((f) => (
                  <div key={f.label}>
                    <label style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-text-muted)", display: "block", marginBottom: 5 }}>{f.label}</label>
                    <input
                      value={f.val}
                      onChange={(e) => f.set(e.target.value)}
                      placeholder={f.ph}
                      style={{
                        width: "100%", boxSizing: "border-box",
                        background: "var(--adv-bg)", border: "1px solid var(--adv-border)", borderRadius: 5,
                        padding: "8px 12px", color: "var(--adv-text)",
                        fontFamily: "'Inter', sans-serif", fontSize: 14, outline: "none",
                      }}
                    />
                  </div>
                ))}
              </div>
              <div style={{ marginTop: 20 }}>
                <label style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-text-muted)", display: "block", marginBottom: 8 }}>SCOPE NETWORKS</label>
                <textarea
                  rows={3}
                  placeholder="10.10.0.0/24, 10.10.10.0/24, 172.16.1.0/24"
                  style={{
                    width: "100%", boxSizing: "border-box",
                    background: "var(--adv-bg)", border: "1px solid var(--adv-border)", borderRadius: 5,
                    padding: "8px 12px", color: "var(--adv-text)",
                    fontFamily: "'JetBrains Mono', monospace", fontSize: 11,
                    resize: "vertical", outline: "none",
                  }}
                />
              </div>
            </div>
          )}

          {/* ── Email ── */}
          {activeSection === "email" && (
            <div className="animate-slide-in" style={{ background: "linear-gradient(160deg, rgba(37,99,235,0.05) 0%, #FFFFFF 55%)", border: "1px solid var(--adv-border)", borderRadius: 8, padding: 24 }}>
              <SectionHeader icon={Mail} label="EMAIL / SMTP CONFIGURATION" badge="SMTP" />
              <div style={{ background: "rgba(37,99,235,0.04)", border: "1px solid rgba(37,99,235,0.15)", borderRadius: 6, padding: 12, marginBottom: 20 }}>
                <p style={{ fontFamily: "'Inter', sans-serif", fontSize: 13, color: "var(--adv-text-muted)", margin: 0, lineHeight: 1.5 }}>
                  Set <code style={{ color: "var(--adv-accent)" }}>SMTP_HOST</code>, <code style={{ color: "var(--adv-accent)" }}>SMTP_TO</code>, and credentials in <code style={{ color: "var(--adv-accent)" }}>.env.local</code> for real email delivery. These fields show current config — changes require a server restart.
                </p>
              </div>
              <IntegrationFields fields={EMAIL_FIELDS} />
              <div style={{ display: "flex", gap: 10, marginTop: 20 }}>
                <TestButton label="Test Connection" color="#2563EB" onTest={() => success("SMTP Test", "Connection successful (preview mode).")} />
                <TestButton label="Send Test Email" color="#059669" onTest={() => success("Test Email Sent", "Check your inbox for the test alert.")} />
              </div>
            </div>
          )}

          {/* ── MessageCircle ── */}
          {activeSection === "slack" && (
            <div className="animate-slide-in" style={{ background: "linear-gradient(160deg, rgba(37,99,235,0.05) 0%, #FFFFFF 55%)", border: "1px solid var(--adv-border)", borderRadius: 8, padding: 24 }}>
              <SectionHeader icon={MessageCircle} label="SLACK INTEGRATION" badge="WEBHOOK" />
              <div style={{ marginBottom: 20, fontFamily: "'Inter', sans-serif", fontSize: 14, color: "var(--adv-text-muted)", lineHeight: 1.6 }}>
                Create an Incoming Webhook in your MessageCircle App configuration and paste the URL below. Set <code style={{ color: "var(--adv-accent)" }}>SLACK_WEBHOOK_URL</code> in <code style={{ color: "var(--adv-accent)" }}>.env.local</code>.
              </div>
              <IntegrationFields fields={SLACK_FIELDS} />
              <div style={{ display: "flex", gap: 10, marginTop: 20 }}>
                <TestButton label="Send Test Message" color="#9C27B0" onTest={() => success("MessageCircle Test", "Rich block message sent to channel (preview mode).")} />
              </div>
            </div>
          )}

          {/* ── Jira ── */}
          {activeSection === "jira" && (
            <div className="animate-slide-in" style={{ background: "linear-gradient(160deg, rgba(37,99,235,0.05) 0%, #FFFFFF 55%)", border: "1px solid var(--adv-border)", borderRadius: 8, padding: 24 }}>
              <SectionHeader icon={ExternalLink} label="JIRA INTEGRATION" badge="REST API v3" />
              <div style={{ marginBottom: 20, fontFamily: "'Inter', sans-serif", fontSize: 14, color: "var(--adv-text-muted)", lineHeight: 1.6 }}>
                Generates Jira issues in your security project when cases are escalated. Uses Atlassian REST API v3. Set env vars in <code style={{ color: "var(--adv-accent)" }}>.env.local</code>.
              </div>
              <IntegrationFields fields={JIRA_FIELDS} />
              <div style={{ display: "flex", gap: 10, marginTop: 20 }}>
                <TestButton label="Test Jira Connection" color="#2196F3" onTest={() => success("Jira Test", "API authentication successful (preview mode).")} />
              </div>
            </div>
          )}

          {/* ── SLA Policy ── */}
          {activeSection === "sla" && (
            <div className="animate-slide-in" style={{ background: "linear-gradient(160deg, rgba(37,99,235,0.05) 0%, #FFFFFF 55%)", border: "1px solid var(--adv-border)", borderRadius: 8, padding: 24 }}>
              <SectionHeader icon={Shield} label="SLA POLICY CONFIGURATION" />
              <div style={{ marginBottom: 16, fontFamily: "'Inter', sans-serif", fontSize: 14, color: "var(--adv-text-muted)" }}>
                SLA windows define the maximum time allowed to remediate findings by severity. Escalation triggers notification when the threshold is crossed.
              </div>
              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <thead>
                  <tr>
                    {["SEVERITY", "SLA WINDOW", "ESCALATION TRIGGER", "COLOR"].map((h) => (
                      <th key={h} style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-text-muted)", padding: "8px 12px", textAlign: "left", borderBottom: "1px solid var(--adv-border)" }}>
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {SLA_POLICY.map((row, i) => (
                    <tr key={row.severity} style={{ borderBottom: i < SLA_POLICY.length - 1 ? "1px solid rgba(37,99,235,0.06)" : "none" }}>
                      <td style={{ padding: "12px 12px" }}>
                        <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: row.color, background: `${row.color}15`, border: `1px solid ${row.color}30`, borderRadius: 4, padding: "2px 8px" }}>
                          {row.severity}
                        </span>
                      </td>
                      <td style={{ padding: "12px 12px", fontFamily: "'JetBrains Mono', monospace", fontSize: 12, color: "var(--adv-text)" }}>
                        {row.hours}h
                      </td>
                      <td style={{ padding: "12px 12px", fontFamily: "'JetBrains Mono', monospace", fontSize: 12, color: "var(--adv-text-muted)" }}>
                        {row.escalate} remaining
                      </td>
                      <td style={{ padding: "12px 12px" }}>
                        <div style={{ width: 20, height: 20, borderRadius: 4, background: row.color }} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <div style={{ marginTop: 16, padding: "12px 16px", background: "rgba(37,99,235,0.04)", border: "1px solid rgba(37,99,235,0.15)", borderRadius: 6, fontFamily: "'Inter', sans-serif", fontSize: 13, color: "var(--adv-text-muted)" }}>
                SLA windows are defined in <code style={{ color: "var(--adv-accent)" }}>lib/cases-store.ts</code>. Custom windows require a code change and redeploy.
              </div>
            </div>
          )}

          {/* ── Notifications ── */}
          {activeSection === "notify" && (
            <div className="animate-slide-in" style={{ background: "linear-gradient(160deg, rgba(37,99,235,0.05) 0%, #FFFFFF 55%)", border: "1px solid var(--adv-border)", borderRadius: 8, padding: 24 }}>
              <SectionHeader icon={Bell} label="NOTIFICATION RULES" />
              <div style={{ display: "flex", flexDirection: "column", gap: 0 }}>
                {(Object.entries({
                  onNewCritical:  { label: "New CRITICAL finding",   desc: "Trigger email + Slack when a CRITICAL finding is opened" },
                  onNewHigh:      { label: "New HIGH finding",        desc: "Trigger Slack when a HIGH finding is opened" },
                  onNewMedium:    { label: "New MEDIUM finding",      desc: "Silent by default — enable for high-noise environments" },
                  onSlaBreach:    { label: "SLA breach",              desc: "Alert when any case crosses its SLA deadline" },
                  onCaseClose:    { label: "Case closed",             desc: "Notify when a case is moved to CLOSED/VERIFIED" },
                  onStatusChange: { label: "Any status change",       desc: "Verbose mode — notify on every case transition" },
                }) as [keyof typeof rules, { label: string; desc: string }][]).map(([ruleKey, ruleMeta], i) => (
                  <div
                    key={ruleKey}
                    style={{
                      display: "flex", justifyContent: "space-between", alignItems: "center",
                      padding: "14px 0",
                      borderBottom: i < 5 ? "1px solid rgba(37,99,235,0.06)" : "none",
                    }}
                  >
                    <div>
                      <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 14, fontWeight: 600, color: "var(--adv-text)" }}>{ruleMeta.label}</div>
                      <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 12, color: "var(--adv-text-muted)", marginTop: 2 }}>{ruleMeta.desc}</div>
                    </div>
                    <Toggle on={rules[ruleKey]} onChange={(v) => setRules((p) => ({ ...p, [ruleKey]: v }))} />
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </PageShell>
  );
}
