"use client";

import { useState } from "react";
import type { SlaFinding, Severity } from "@/data/mock-dashboard";

function getSla(deadline: string, hoursTotal: number) {
  const due = new Date(deadline).getTime(), now = Date.now();
  const pct = Math.max(0, Math.min(100, ((due - now) / (hoursTotal * 3_600_000)) * 100));
  const hrs = Math.max(0, (due - now) / 3_600_000);
  const breached = now > due;
  const color = breached || pct < 10 ? "var(--sev-critical-color)"
    : pct < 25 ? "var(--sev-high-color)"
    : pct < 50 ? "var(--sev-medium-color)"
    : "var(--accent)";
  const label = breached ? "BREACHED" : hrs < 24 ? `${Math.round(hrs)}h` : `${Math.round(hrs / 24)}d`;
  return { pct, breached, color, label };
}

const SEV_BG: Record<Severity, string> = {
  CRITICAL: "var(--sev-critical-bg)",
  HIGH: "var(--sev-high-bg)",
  MEDIUM: "var(--sev-medium-bg)",
};

const SEV_COLOR: Record<Severity, string> = {
  CRITICAL: "var(--sev-critical-color)",
  HIGH: "var(--sev-high-color)",
  MEDIUM: "var(--sev-medium-color)",
};

export function SlaRow({ finding, isLast }: { finding: SlaFinding; isLast: boolean }) {
  const s = getSla(finding.deadline, finding.hoursTotal);
  const [hovered, setHovered] = useState(false);

  return (
    <div
      style={{
        display: "flex", alignItems: "center", gap: 12, padding: "10px 20px",
        borderBottom: isLast ? "none" : "0.5px solid var(--border-subtle)",
        transition: "background 0.12s ease",
        background: hovered ? "var(--bg-surface)" : "transparent",
        cursor: "default",
      }}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
    >
      <span style={{
        fontFamily: "'Inter', sans-serif", fontSize: 10, fontWeight: 700, letterSpacing: 0.5,
        color: SEV_COLOR[finding.severity],
        background: SEV_BG[finding.severity],
        borderRadius: 5, padding: "2px 7px", flexShrink: 0, textTransform: "uppercase" as const,
      }}>
        {finding.severity}
      </span>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 12, color: "var(--text-primary)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", marginBottom: 5 }}>
          {finding.title}
        </div>
        <div className="progress-track" style={{ height: 3 }}>
          <div className={`progress-fill ${s.breached ? "sla-pulse" : ""}`}
            style={{ width: `${s.pct}%`, background: s.color }} />
        </div>
      </div>
      <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, fontWeight: 700, color: s.color, flexShrink: 0, minWidth: 56, textAlign: "right" }}>
        {s.label}
      </span>
    </div>
  );
}
