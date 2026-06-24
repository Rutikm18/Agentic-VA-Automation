"use client";

import React, { useState, useEffect, useCallback, useRef } from "react";
import { Menu, Sun, Moon } from "lucide-react";
import { Sidebar } from "./Sidebar";
import { useTheme } from "./ThemeProvider";

interface PageShellProps {
  title: string;
  subtitle?: string;
  headerActions?: React.ReactNode;
  statusItems?: Array<{ label: string; value: string; color?: string }>;
  children: React.ReactNode;
  noPadding?: boolean;
}

export function PageShell({
  title, subtitle, headerActions, statusItems, children, noPadding,
}: PageShellProps) {
  const [sidebarOpen, setSidebarOpen]   = useState(false);
  const [utcTime, setUtcTime]           = useState("");
  const [sessionTime, setSessionTime]   = useState(0);
  const [themeHovered, setThemeHovered] = useState(false);
  const sessionStart = useRef(Date.now());
  const { theme, toggleTheme } = useTheme();

  useEffect(() => {
    const tick = () =>
      setUtcTime(new Date().toISOString().replace("T", " ").slice(0, 19) + " UTC");
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, []);

  useEffect(() => {
    const id = setInterval(
      () => setSessionTime(Math.floor((Date.now() - sessionStart.current) / 1000)),
      1000,
    );
    return () => clearInterval(id);
  }, []);

  const fmtSession = useCallback((s: number) => {
    const m = Math.floor(s / 60), sec = s % 60;
    return `${String(m).padStart(2, "0")}:${String(sec).padStart(2, "0")}`;
  }, []);

  return (
    <div style={{
      display: "flex", height: "100vh",
      background: "var(--bg-app)", fontFamily: "'Inter', sans-serif",
      overflow: "hidden", transition: "background 0.25s ease, color 0.25s ease",
    }}>
      {/* Mobile overlay */}
      {sidebarOpen && (
        <div className="md:hidden" onClick={() => setSidebarOpen(false)} style={{
          position: "fixed", inset: 0,
          background: "var(--modal-backdrop)",
          zIndex: 40, backdropFilter: "blur(4px)",
          animation: "fadeIn 0.15s ease",
        }} />
      )}

      <Sidebar open={sidebarOpen} onClose={() => setSidebarOpen(false)} />

      <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden", minWidth: 0 }}>

        {/* ── Header ── */}
        <header style={{
          height: 52, flexShrink: 0,
          background: "var(--bg-sidebar)",
          borderBottom: "0.5px solid var(--border-subtle)",
          backdropFilter: "blur(12px)",
          display: "flex", alignItems: "center",
          justifyContent: "space-between",
          padding: "0 20px", gap: 16,
          transition: "background 0.25s ease, border-color 0.25s ease",
        }}>
          {/* Left */}
          <div style={{ display: "flex", alignItems: "center", gap: 10, minWidth: 0 }}>
            <button className="md:hidden" onClick={() => setSidebarOpen(true)} style={{
              background: "none", border: "none", cursor: "pointer",
              padding: "6px", borderRadius: 6, flexShrink: 0,
              color: "var(--accent)",
              transition: "background 0.15s ease, transform 0.15s var(--ease-spring)",
            }}
              onMouseEnter={(e) => { e.currentTarget.style.background = "var(--accent-ghost)"; e.currentTarget.style.transform = "scale(1.1)"; }}
              onMouseLeave={(e) => { e.currentTarget.style.background = "none"; e.currentTarget.style.transform = "scale(1)"; }}
            >
              <Menu size={18} />
            </button>

            <div style={{ display: "flex", alignItems: "center", gap: 6, minWidth: 0 }}>
              <span style={{
                fontFamily: "'Inter', sans-serif", fontSize: 14, fontWeight: 600,
                color: "var(--text-primary)", flexShrink: 0,
              }}>
                {title}
              </span>
              {subtitle && (
                <>
                  <span style={{ color: "var(--text-faint)", flexShrink: 0, fontSize: 15, fontWeight: 300 }}>/</span>
                  <span style={{
                    fontFamily: "'Inter', sans-serif", fontSize: 13,
                    color: "var(--text-secondary)", whiteSpace: "nowrap",
                    overflow: "hidden", textOverflow: "ellipsis",
                  }}>
                    {subtitle}
                  </span>
                </>
              )}
            </div>

            {/* Live pulse */}
            <div className="status-dot" style={{ marginLeft: 2 }}>
              <span className="status-dot-ring" style={{ background: "var(--accent-pulse)" }} />
              <span className="status-dot-core animate-pulse-dot" style={{ background: "var(--accent)", width: 6, height: 6 }} />
            </div>
          </div>

          {/* Right */}
          <div style={{ display: "flex", alignItems: "center", gap: 12, flexShrink: 0 }}>
            {headerActions && (
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                {headerActions}
              </div>
            )}

            {statusItems?.map((item, i) => (
              <React.Fragment key={i}>
                <div style={{ width: "0.5px", height: 16, background: "var(--border-subtle)" }} />
                <div style={{ display: "flex", alignItems: "center", gap: 5 }}>
                  <span style={{
                    fontFamily: "'JetBrains Mono', monospace", fontSize: 10,
                    color: "var(--text-muted)", letterSpacing: 0.6, textTransform: "uppercase",
                  }}>
                    {item.label}
                  </span>
                  <span style={{
                    fontFamily: "'JetBrains Mono', monospace", fontSize: 11,
                    fontWeight: 600, color: item.color ?? "var(--text-primary)",
                  }}>
                    {item.value}
                  </span>
                </div>
              </React.Fragment>
            ))}

            <div style={{ width: "0.5px", height: 16, background: "var(--border-subtle)" }} />

            <span style={{
              fontFamily: "'JetBrains Mono', monospace", fontSize: 11,
              color: "var(--text-muted)", letterSpacing: 0.3,
            }}>
              {fmtSession(sessionTime)}
            </span>

            <div style={{ width: "0.5px", height: 16, background: "var(--border-subtle)" }} />

            {/* Theme toggle */}
            <button
              onClick={toggleTheme}
              onMouseEnter={() => setThemeHovered(true)}
              onMouseLeave={() => setThemeHovered(false)}
              title={theme === "dark" ? "Light mode" : "Dark mode"}
              style={{
                display: "flex", alignItems: "center", justifyContent: "center",
                width: 30, height: 30, borderRadius: 7, flexShrink: 0,
                border: `0.5px solid ${themeHovered ? "var(--accent)" : "var(--border-subtle)"}`,
                background: themeHovered ? "var(--accent-ghost)" : "var(--bg-surface)",
                cursor: "pointer",
                color: themeHovered ? "var(--accent)" : "var(--text-muted)",
                transition: "all 0.18s var(--ease-spring)",
                transform: themeHovered ? "scale(1.1) rotate(12deg)" : "scale(1) rotate(0deg)",
                boxShadow: themeHovered ? "0 0 10px var(--accent-glow)" : "none",
              }}
            >
              <div style={{
                transition: "transform 0.3s var(--ease-spring), opacity 0.2s ease",
                transform: `rotate(${themeHovered ? 180 : 0}deg)`,
              }}>
                {theme === "dark" ? <Sun size={13} /> : <Moon size={13} />}
              </div>
            </button>
          </div>
        </header>

        {/* ── Content ── */}
        <main style={{
          flex: 1, overflowY: "auto",
          padding: noPadding ? 0 : 20,
          background: "var(--bg-app)",
          transition: "background 0.25s ease",
        }}>
          {children}
        </main>

        {/* ── Footer ── */}
        <footer style={{
          height: 28, flexShrink: 0,
          background: "var(--bg-panel)",
          borderTop: "0.5px solid var(--border-subtle)",
          display: "flex", alignItems: "center",
          justifyContent: "space-between",
          padding: "0 20px", gap: 16,
          transition: "background 0.25s ease",
        }}>
          <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
            {[
              { label: "ENGINE", color: "var(--accent)" },
              { label: "API",    color: "var(--accent)" },
              { label: "DB",     color: "var(--accent)" },
            ].map((s, i) => (
              <React.Fragment key={i}>
                {i > 0 && <div style={{ width: "0.5px", height: 10, background: "var(--border-subtle)" }} />}
                <div style={{ display: "flex", alignItems: "center", gap: 5 }}>
                  <span style={{
                    width: 5, height: 5, borderRadius: "50%",
                    background: s.color, display: "inline-block",
                    boxShadow: `0 0 4px ${s.color}`,
                  }} />
                  <span style={{ fontFamily: "'Inter', sans-serif", fontSize: 10, color: "var(--text-muted)", fontWeight: 500 }}>
                    {s.label}
                  </span>
                </div>
              </React.Fragment>
            ))}
          </div>

          <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--text-muted)" }}>
            {utcTime} · ADVERSA v1.0
          </div>
        </footer>
      </div>
    </div>
  );
}
