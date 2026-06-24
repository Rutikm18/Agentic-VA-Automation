"use client";

import { useState } from "react";

interface SlaSummaryMetric {
  label: string;
  value: number;
  color: string;
}

export function SlaSummaryCell({ metric, isLast }: { metric: SlaSummaryMetric; isLast: boolean }) {
  const [hovered, setHovered] = useState(false);
  return (
    <div
      style={{
        padding: "14px 16px", textAlign: "center", cursor: "default",
        borderRight: isLast ? "none" : "0.5px solid var(--border-subtle)",
        background: hovered ? "var(--bg-surface)" : "transparent",
        transition: "background 0.12s ease",
      }}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
    >
      <div style={{
        fontFamily: "'Inter', sans-serif", fontSize: 24, fontWeight: 700, color: metric.color, lineHeight: 1, marginBottom: 4,
        transition: "transform 0.18s var(--ease-spring)",
        transform: hovered ? "scale(1.08)" : "scale(1)",
      }}>
        {metric.value}
      </div>
      <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 10, color: "var(--text-muted)", fontWeight: 500 }}>
        {metric.label}
      </div>
    </div>
  );
}
