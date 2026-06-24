"use client";

import { useState } from "react";
import type { ZoneHealth } from "@/data/mock-dashboard";

export function ZoneRow({ zone, isLast }: { zone: ZoneHealth; isLast: boolean }) {
  const [hovered, setHovered] = useState(false);
  const health = zone.score >= 90 ? "var(--accent)" : zone.score >= 75 ? "var(--sev-medium-color)" : "var(--sev-critical-color)";

  return (
    <div
      style={{
        padding: "13px 20px", display: "flex", alignItems: "center", gap: 12,
        borderBottom: isLast ? "none" : "0.5px solid var(--border-subtle)",
        transition: "background 0.12s ease",
        background: hovered ? "var(--bg-surface)" : "transparent",
        cursor: "default",
      }}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
    >
      <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, fontWeight: 600, color: "var(--text-primary)", width: 42, flexShrink: 0 }}>
        {zone.name}
      </span>
      <div className="progress-track" style={{ flex: 1, height: 5 }}>
        <div className="progress-fill" style={{ width: `${zone.score}%`, background: health }} />
      </div>
      <span style={{
        fontFamily: "'JetBrains Mono', monospace", fontSize: 12, fontWeight: 700,
        color: health, minWidth: 32, textAlign: "right",
        transition: "transform 0.18s var(--ease-spring)",
        transform: hovered ? "scale(1.1)" : "scale(1)",
        display: "inline-block",
      }}>
        {zone.score}
      </span>
    </div>
  );
}
