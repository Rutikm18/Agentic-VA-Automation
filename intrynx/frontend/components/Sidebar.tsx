"use client";

import React, { useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Shield, Brain, Network, Users, Grid,
  AlertTriangle, FileText, X,
  Terminal, Briefcase, Settings, Zap, Cpu,
} from "lucide-react";

const NAV_SECTIONS = [
  {
    label: "OPERATIONS",
    items: [
      { icon: Shield,        label: "Dashboard",        href: "/"              },
      { icon: Briefcase,     label: "Engagements",      href: "/engagements"   },
      { icon: Brain,         label: "AI Brain",         href: "/aibrain"       },
      { icon: Terminal,      label: "Scanner",          href: "/scan"          },
      { icon: Zap,           label: "Exploit Engine",   href: "/exploit"       },
      { icon: Cpu,           label: "AI Engine",        href: "/ai-report"     },
      { icon: Network,       label: "Agents",           href: "/agents"        },
    ],
  },
  {
    label: "ANALYSIS",
    items: [
      { icon: Network,       label: "Attack Graph",     href: "/attack-graph"     },
      { icon: Users,         label: "Active Directory", href: "/active-directory" },
      { icon: Grid,          label: "Segmentation",     href: "/segmentation"     },
    ],
  },
  {
    label: "MANAGEMENT",
    items: [
      { icon: AlertTriangle, label: "Findings",         href: "/findings"  },
      { icon: Briefcase,     label: "Cases",            href: "/cases"     },
      { icon: FileText,      label: "Reports",          href: "/reports"   },
      { icon: Settings,      label: "Settings",         href: "/settings"  },
    ],
  },
];

interface SidebarProps { open: boolean; onClose: () => void; }

export function Sidebar({ open, onClose }: SidebarProps) {
  const pathname = usePathname();
  const [hoveredHref, setHoveredHref] = useState<string | null>(null);

  return (
    <aside
      className={[
        "fixed md:static",
        "transition-transform duration-200 ease-in-out",
        open ? "translate-x-0" : "-translate-x-full md:translate-x-0",
        "z-50",
      ].join(" ")}
      style={{
        width: 220,
        background: "var(--bg-sidebar)",
        borderRight: "0.5px solid var(--border-subtle)",
        display: "flex", flexDirection: "column",
        height: "100vh", flexShrink: 0, overflowY: "auto",
        transition: "background 0.2s ease",
      }}
    >
      {/* ── Logo ─── */}
      <div style={{
        padding: "20px 16px 16px",
        borderBottom: "0.5px solid var(--border-subtle)",
        display: "flex", alignItems: "center", justifyContent: "space-between",
        flexShrink: 0,
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          {/* Animated logo mark */}
          <div style={{
            width: 34, height: 34, borderRadius: 9,
            background: "var(--accent-ghost)",
            border: "0.5px solid var(--border-accent)",
            display: "flex", alignItems: "center", justifyContent: "center",
            flexShrink: 0, position: "relative",
            transition: "box-shadow 0.25s ease, transform 0.2s var(--ease-spring)",
          }}
            onMouseEnter={(e) => {
              e.currentTarget.style.boxShadow = "0 0 14px var(--accent-glow)";
              e.currentTarget.style.transform = "scale(1.06)";
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.boxShadow = "none";
              e.currentTarget.style.transform = "scale(1)";
            }}
          >
            <Shield size={16} color="var(--accent)" />
          </div>
          <div>
            <div style={{
              fontFamily: "'Sora', sans-serif", fontSize: 14, fontWeight: 700,
              color: "var(--text-primary)", letterSpacing: 2, lineHeight: 1,
            }}>
              ADVERSA
            </div>
            <div style={{
              display: "flex", alignItems: "center", gap: 5, marginTop: 4,
            }}>
              <span style={{
                width: 5, height: 5, borderRadius: "50%",
                background: "var(--accent)", display: "inline-block",
                animation: "pulse 2s ease-in-out infinite",
              }} />
              <span style={{
                fontFamily: "'Inter', sans-serif", fontSize: 10,
                color: "var(--text-muted)", fontWeight: 500,
              }}>
                v1.0 Enterprise
              </span>
            </div>
          </div>
        </div>

        <button className="md:hidden" onClick={onClose} style={{
          background: "none", border: "none", cursor: "pointer",
          padding: "4px", borderRadius: 6, color: "var(--text-muted)",
          transition: "color 0.15s ease, background 0.15s ease",
        }}
          onMouseEnter={(e) => { e.currentTarget.style.background = "var(--bg-surface)"; e.currentTarget.style.color = "var(--text-primary)"; }}
          onMouseLeave={(e) => { e.currentTarget.style.background = "none"; e.currentTarget.style.color = "var(--text-muted)"; }}
        >
          <X size={15} />
        </button>
      </div>

      {/* ── Navigation ─── */}
      <nav style={{ paddingTop: 12, flex: 1 }}>
        {NAV_SECTIONS.map((section, si) => (
          <div key={section.label} style={{ marginBottom: 8 }}>
            {/* Section label */}
            <div style={{
              display: "flex", alignItems: "center", gap: 8,
              padding: "6px 16px 5px",
            }}>
              <div style={{ flex: 1, height: "0.5px", background: "var(--border-subtle)" }} />
              <span style={{
                fontFamily: "'Inter', sans-serif", fontSize: 9, fontWeight: 700,
                color: "var(--text-faint)", letterSpacing: 1.4, textTransform: "uppercase",
              }}>
                {section.label}
              </span>
              <div style={{ flex: 1, height: "0.5px", background: "var(--border-subtle)" }} />
            </div>

            {section.items.map((item, ii) => {
              const Icon = item.icon;
              const isActive  = pathname === item.href;
              const isHovered = hoveredHref === item.href;

              return (
                <Link
                  key={item.label}
                  href={item.href}
                  onClick={onClose}
                  className="stagger-item"
                  style={{
                    animationDelay: `${(si * 4 + ii) * 30}ms`,
                    display: "flex", alignItems: "center", gap: 9,
                    padding: "7px 10px 7px 14px",
                    margin: "1px 8px",
                    borderRadius: 7, textDecoration: "none",
                    background: isActive
                      ? "var(--accent-ghost)"
                      : isHovered ? "var(--bg-surface)" : "transparent",
                    borderLeft: isActive ? "2px solid var(--accent)" : "2px solid transparent",
                    transition: "background 0.12s ease, border-color 0.12s ease, transform 0.12s var(--ease-spring)",
                    transform: isHovered && !isActive ? "translateX(2px)" : "translateX(0)",
                  }}
                  onMouseEnter={() => setHoveredHref(item.href)}
                  onMouseLeave={() => setHoveredHref(null)}
                >
                  {/* Icon with micro-animation */}
                  <div style={{
                    transition: "transform 0.18s var(--ease-spring)",
                    transform: isHovered ? "scale(1.15) rotate(-4deg)" : "scale(1) rotate(0deg)",
                    flexShrink: 0,
                  }}>
                    <Icon
                      size={14}
                      color={isActive ? "var(--accent)" : isHovered ? "var(--text-primary)" : "var(--text-secondary)"}
                    />
                  </div>

                  <span style={{
                    fontFamily: "'Inter', sans-serif", fontSize: 13,
                    fontWeight: isActive ? 600 : 400,
                    color: isActive ? "var(--text-primary)" : isHovered ? "var(--text-primary)" : "var(--text-secondary)",
                    transition: "color 0.12s ease, font-weight 0.12s ease",
                    flex: 1,
                  }}>
                    {item.label}
                  </span>

                  {/* Cases badge */}
                  {item.href === "/cases" && (
                    <span style={{
                      background: "var(--sev-critical-bg)",
                      color: "var(--sev-critical-color)",
                      fontSize: 10, fontFamily: "'Inter', sans-serif", fontWeight: 700,
                      borderRadius: 10, padding: "1px 6px", lineHeight: 1.5,
                      transition: "transform 0.18s var(--ease-spring)",
                      transform: isHovered ? "scale(1.08)" : "scale(1)",
                    }}>
                      12
                    </span>
                  )}

                  {/* Active dot */}
                  {isActive && (
                    <span style={{
                      width: 4, height: 4, borderRadius: "50%",
                      background: "var(--accent)", flexShrink: 0,
                      boxShadow: "0 0 6px var(--accent-glow)",
                    }} />
                  )}
                </Link>
              );
            })}
          </div>
        ))}
      </nav>

      {/* ── Footer ─── */}
      <div style={{
        padding: "14px 16px",
        borderTop: "0.5px solid var(--border-subtle)",
        background: "var(--bg-sidebar)", flexShrink: 0,
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
          {/* Status dot with ping ring */}
          <div className="status-dot">
            <span className="status-dot-ring" style={{ background: "var(--accent-pulse)" }} />
            <span className="status-dot-core" style={{ background: "var(--accent)" }} />
          </div>
          <span style={{
            fontFamily: "'Inter', sans-serif", fontSize: 11, fontWeight: 600,
            color: "var(--accent)",
          }}>
            System Nominal
          </span>
        </div>
        <div style={{
          fontFamily: "'JetBrains Mono', monospace", fontSize: 10,
          color: "var(--text-muted)",
        }}>
          ADVERSA v1.0.0 · Enterprise
        </div>
      </div>
    </aside>
  );
}
