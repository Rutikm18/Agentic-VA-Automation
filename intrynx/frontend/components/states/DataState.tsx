"use client";

/**
 * DataState — one place that handles every async edge factor for a screen:
 *   loading → skeleton · error → message + retry · unauthorized → sign-in ·
 *   empty → guidance + action · offline → banner.
 *
 * Usage:
 *   <DataState loading={isLoading} error={error} isEmpty={rows.length===0}
 *              onRetry={refetch} empty={<EmptyState .../>}>
 *     {rows.map(...)}
 *   </DataState>
 *
 * Design: dark SOC tokens (--adv-*, --sev-*), Lucide icons (no emoji), tabular
 * mono type, accessible roles (status/alert), reduced-motion friendly.
 */
import React from "react";
import { AlertTriangle, Inbox, Lock, RefreshCw, WifiOff, type LucideIcon } from "lucide-react";
import { errorMessage, isUnauthorized } from "../../lib/fetcher";

const MONO = "'JetBrains Mono', monospace";

/* ── Loading: skeleton rows (reserves layout to avoid CLS) ── */
export function SkeletonRows({ rows = 3, height = 46 }: { rows?: number; height?: number }) {
  return (
    <div role="status" aria-busy="true" aria-label="Loading" style={{ display: "grid", gap: 8 }}>
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="shimmer"
          style={{ height, borderRadius: 6, border: "1px solid var(--adv-border)", background: "var(--adv-panel)" }} />
      ))}
    </div>
  );
}

/* ── Empty: helpful, with an optional primary action ── */
export function EmptyState({
  icon: Icon = Inbox, title, hint, action,
}: { icon?: LucideIcon; title: string; hint?: string; action?: React.ReactNode }) {
  return (
    <div style={center}>
      <Icon size={36} color="var(--adv-border)" strokeWidth={1.5} />
      <div style={{ fontFamily: MONO, fontSize: 13, color: "var(--adv-text)", marginTop: 12 }}>{title}</div>
      {hint && <div style={{ fontFamily: MONO, fontSize: 11, color: "var(--adv-text-muted)", marginTop: 4, maxWidth: 360, textAlign: "center" }}>{hint}</div>}
      {action && <div style={{ marginTop: 14 }}>{action}</div>}
    </div>
  );
}

/* ── Error: states the problem AND offers a recovery path (retry) ── */
export function ErrorState({
  title = "Couldn't load this", detail, onRetry,
}: { title?: string; detail?: string; onRetry?: () => void }) {
  return (
    <div role="alert" aria-live="assertive" style={center}>
      <AlertTriangle size={32} color="var(--sev-critical-color)" strokeWidth={1.75} />
      <div style={{ fontFamily: MONO, fontSize: 13, color: "var(--adv-text)", marginTop: 12 }}>{title}</div>
      {detail && <div style={{ fontFamily: MONO, fontSize: 11, color: "var(--sev-critical-color)", marginTop: 4, maxWidth: 420, textAlign: "center" }}>{detail}</div>}
      {onRetry && (
        <button onClick={onRetry} style={btn} aria-label="Retry">
          <RefreshCw size={12} /> Try again
        </button>
      )}
    </div>
  );
}

/* ── Unauthorized: expired session → sign in again ── */
export function Unauthorized({ onLogin }: { onLogin?: () => void }) {
  const go = onLogin ?? (() => { window.location.href = "/login"; });
  return (
    <div role="alert" style={center}>
      <Lock size={32} color="var(--sev-high-color)" strokeWidth={1.75} />
      <div style={{ fontFamily: MONO, fontSize: 13, color: "var(--adv-text)", marginTop: 12 }}>Your session has expired</div>
      <div style={{ fontFamily: MONO, fontSize: 11, color: "var(--adv-text-muted)", marginTop: 4 }}>Sign in again to continue.</div>
      <button onClick={go} style={btn}>Sign in</button>
    </div>
  );
}

/* ── Offline: a non-blocking banner (e.g. a probe stopped heartbeating) ── */
export function OfflineBanner({ label = "Offline — showing last known data" }: { label?: string }) {
  return (
    <div role="status" style={{
      display: "flex", alignItems: "center", gap: 8, padding: "8px 12px", marginBottom: 10,
      fontFamily: MONO, fontSize: 11, color: "var(--sev-high-color)",
      background: "var(--sev-high-bg)", border: "1px solid var(--sev-high-color)33", borderRadius: 6,
    }}>
      <WifiOff size={13} /> {label}
    </div>
  );
}

/* ── Orchestrator: pick the right state, in priority order ── */
export interface DataStateProps {
  loading?: boolean;
  error?: unknown;
  isEmpty?: boolean;
  onRetry?: () => void;
  onLogin?: () => void;
  /** Override the default loading/empty UI per screen. */
  skeleton?: React.ReactNode;
  empty?: React.ReactNode;
  children: React.ReactNode;
}

export function DataState({
  loading, error, isEmpty, onRetry, onLogin, skeleton, empty, children,
}: DataStateProps) {
  if (error && isUnauthorized(error)) return <Unauthorized onLogin={onLogin} />;
  if (loading) return <>{skeleton ?? <SkeletonRows />}</>;
  if (error) return <ErrorState detail={errorMessage(error)} onRetry={onRetry} />;
  if (isEmpty) return <>{empty ?? <EmptyState title="Nothing here yet" />}</>;
  return <>{children}</>;
}

/* ── shared styles ── */
const center: React.CSSProperties = {
  display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center",
  padding: "56px 16px", textAlign: "center",
};
const btn: React.CSSProperties = {
  display: "inline-flex", alignItems: "center", gap: 6, marginTop: 16,
  fontFamily: MONO, fontSize: 11, color: "var(--adv-accent)",
  background: "var(--adv-accent-bg)", border: "1px solid var(--adv-accent-border)",
  borderRadius: 6, padding: "6px 14px", cursor: "pointer",
};
