"use client";

import { useState } from "react";
import type { ProtocolRisk } from "@/data/mock-dashboard";

function riskColor(v: number) {
  return v >= 85 ? "var(--sev-critical-color)" : v >= 65 ? "var(--sev-high-color)" : v >= 45 ? "var(--sev-medium-color)" : "var(--accent)";
}

export function ProtocolRow({ protocol, isLast }: { protocol: ProtocolRisk; isLast: boolean }) {
  const [hovered, setHovered] = useState(false);

  return (
    <div
      style={{
        padding: "13px 20px", display: "flex", flexDirection: "column", gap: 8,
        borderBottom: isLast ? "none" : "0.5px solid var(--border-subtle)",
        transition: "background 0.12s ease",
        background: hovered ? "var(--bg-surface)" : "transparent",
        cursor: "default",
      }}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
    >
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, fontWeight: 600, color: "var(--text-primary)" }}>{protocol.name}</span>
        <span style={{
          fontFamily: "'JetBrains Mono', monospace", fontSize: 12, fontWeight: 700,
          color: riskColor(protocol.value),
          transition: "transform 0.18s var(--ease-spring)",
          transform: hovered ? "scale(1.1)" : "scale(1)",
          display: "inline-block",
        }}>
          {protocol.value}%
        </span>
      </div>
      <div className="progress-track" style={{ height: 5 }}>
        <div className="progress-fill" style={{ width: `${protocol.value}%`, background: riskColor(protocol.value) }} />
      </div>
    </div>
  );
}
