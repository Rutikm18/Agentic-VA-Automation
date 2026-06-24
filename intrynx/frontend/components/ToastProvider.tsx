"use client";

import React, { createContext, useState, useCallback, useRef } from "react";
import { CheckCircle, AlertTriangle, XCircle, Info, X } from "lucide-react";

export type ToastType = "success" | "error" | "warning" | "info";

export interface Toast {
  id: string;
  type: ToastType;
  title: string;
  message?: string;
  duration?: number;
  dismissing?: boolean;
}

interface ToastContextValue {
  toast: (opts: Omit<Toast, "id">) => void;
  success: (title: string, message?: string) => void;
  error:   (title: string, message?: string) => void;
  warning: (title: string, message?: string) => void;
  info:    (title: string, message?: string) => void;
  dismiss: (id: string) => void;
}

export const ToastContext = createContext<ToastContextValue | null>(null);

/*
 * Toast colour system — light theme with semantic psychology:
 *   success  → Emerald (completion, reward, safety)
 *   error    → Red     (danger, critical, stop)
 *   warning  → Amber   (caution, attention needed)
 *   info     → Blue    (neutral information, trust)
 */
const TOAST_STYLES: Record<
  ToastType,
  { icon: React.ElementType; accent: string; bg: string; border: string; iconBg: string }
> = {
  success: {
    icon:   CheckCircle,
    accent: "#059669",
    bg:     "var(--adv-panel)",
    border: "#A7F3D0",
    iconBg: "#D1FAE5",
  },
  error: {
    icon:   XCircle,
    accent: "#DC2626",
    bg:     "var(--adv-panel)",
    border: "#FECACA",
    iconBg: "#FEE2E2",
  },
  warning: {
    icon:   AlertTriangle,
    accent: "#D97706",
    bg:     "var(--adv-panel)",
    border: "#FDE68A",
    iconBg: "#FEF3C7",
  },
  info: {
    icon:   Info,
    accent: "#2563EB",
    bg:     "var(--adv-panel)",
    border: "#BFDBFE",
    iconBg: "#DBEAFE",
  },
};

function ToastItem({ toast, onDismiss }: { toast: Toast; onDismiss: (id: string) => void }) {
  const style = TOAST_STYLES[toast.type];
  const Icon = style.icon;

  return (
    <div
      className={toast.dismissing ? "animate-slide-out-right" : "animate-slide-in-right"}
      style={{
        background: style.bg,
        border: `1px solid ${style.border}`,
        borderLeft: `4px solid ${style.accent}`,
        borderRadius: 10,
        padding: "12px 14px",
        display: "flex",
        gap: 12,
        alignItems: "flex-start",
        minWidth: 300,
        maxWidth: 380,
        boxShadow: "0 8px 24px rgba(15,23,42,0.10), 0 2px 8px rgba(15,23,42,0.06)",
        cursor: "default",
      }}
    >
      {/* Icon with coloured background pill */}
      <div
        style={{
          width: 30,
          height: 30,
          borderRadius: 8,
          background: style.iconBg,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          flexShrink: 0,
        }}
      >
        <Icon size={15} color={style.accent} />
      </div>

      {/* Content */}
      <div style={{ flex: 1, minWidth: 0 }}>
        <div
          style={{
            fontFamily: "'Inter', 'Inter', sans-serif",
            fontSize: 13,
            fontWeight: 600,
            color: "var(--adv-text)",
            lineHeight: 1.3,
          }}
        >
          {toast.title}
        </div>
        {toast.message && (
          <div
            style={{
              fontFamily: "'Inter', sans-serif",
              fontSize: 12,
              color: "var(--adv-text-muted)",
              marginTop: 3,
              lineHeight: 1.5,
            }}
          >
            {toast.message}
          </div>
        )}
      </div>

      {/* Dismiss */}
      <button
        onClick={() => onDismiss(toast.id)}
        style={{
          background: "none",
          border: "none",
          cursor: "pointer",
          padding: 2,
          color: "var(--adv-text-dim)",
          flexShrink: 0,
          display: "flex",
          alignItems: "center",
          borderRadius: 4,
          transition: "color 0.1s ease",
        }}
        onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.color = "var(--adv-text-sub)"; }}
        onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.color = "var(--adv-text-dim)"; }}
      >
        <X size={14} />
      </button>
    </div>
  );
}

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const timersRef = useRef<Map<string, ReturnType<typeof setTimeout>>>(new Map());

  const dismiss = useCallback((id: string) => {
    setToasts((prev) => prev.map((t) => (t.id === id ? { ...t, dismissing: true } : t)));
    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, 280);
    const timer = timersRef.current.get(id);
    if (timer) clearTimeout(timer);
    timersRef.current.delete(id);
  }, []);

  const toast = useCallback(
    (opts: Omit<Toast, "id">) => {
      const id = `toast-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
      setToasts((prev) => {
        const next = [...prev, { ...opts, id }];
        return next.length > 3 ? next.slice(next.length - 3) : next;
      });
      const duration = opts.duration ?? 4000;
      const timer = setTimeout(() => dismiss(id), duration);
      timersRef.current.set(id, timer);
    },
    [dismiss]
  );

  const success = useCallback((title: string, message?: string) => toast({ type: "success", title, message }), [toast]);
  const error   = useCallback((title: string, message?: string) => toast({ type: "error",   title, message }), [toast]);
  const warning = useCallback((title: string, message?: string) => toast({ type: "warning", title, message }), [toast]);
  const info    = useCallback((title: string, message?: string) => toast({ type: "info",    title, message }), [toast]);

  return (
    <ToastContext.Provider value={{ toast, success, error, warning, info, dismiss }}>
      {children}

      {/* Toast container — top right */}
      <div
        style={{
          position: "fixed",
          top: 16,
          right: 16,
          zIndex: 9999,
          display: "flex",
          flexDirection: "column",
          gap: 8,
          pointerEvents: "none",
        }}
      >
        {toasts.map((t) => (
          <div key={t.id} style={{ pointerEvents: "auto" }}>
            <ToastItem toast={t} onDismiss={dismiss} />
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}
