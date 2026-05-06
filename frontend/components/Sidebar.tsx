"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import {
  BarChart3,
  BotMessageSquare,
  FileSearch,
  FileText,
  LayoutDashboard,
  LogOut,
  Radar,
  Settings,
  ShieldAlert,
  Split,
  Wifi,
} from "lucide-react";

import { getHealth, logout } from "@/lib/api";

const navItems = [
  { href: "/dashboard", label: "DASHBOARD", icon: LayoutDashboard },
  { href: "/scan-console", label: "SCAN ORCHESTRATION", icon: Radar },
  { href: "/scan-reports", label: "REPORTS", icon: FileText },
  { href: "/cve-explorer", label: "CVE EXPLORER", icon: FileSearch },
  { href: "/attack-paths", label: "ATTACK PATHS", icon: Split },
  { href: "/rag-chat", label: "RAG CHAT", icon: BotMessageSquare },
  { href: "/evaluation", label: "EVALUATION", icon: BarChart3 },
  { href: "/audit-logs", label: "AUDIT LOGS", icon: ShieldAlert },
  { href: "/settings", label: "SETTINGS", icon: Settings },
];

export function Sidebar() {
  const pathname = usePathname();
  const router = useRouter();
  const [backendOnline, setBackendOnline] = useState(true);
  const [queueDepth, setQueueDepth] = useState<number | null>(null);

  useEffect(() => {
    let cancelled = false;

    const poll = async () => {
      try {
        const health = await getHealth();
        if (!cancelled) {
          setBackendOnline(true);
          setQueueDepth(health.queue_depth);
        }
      } catch {
        if (!cancelled) {
          setBackendOnline(false);
          setQueueDepth(null);
        }
      }
    };

    void poll();
    const interval = window.setInterval(() => {
      void poll();
    }, 10000);

    return () => {
      cancelled = true;
      window.clearInterval(interval);
    };
  }, []);

  return (
    <aside
      style={{
        width: "240px",
        minHeight: "100vh",
        position: "fixed",
        left: 0,
        top: 0,
        zIndex: 2000,
        background: "var(--bg-dark)",
        color: "var(--text-inverse)",
        borderRight: "3px solid var(--accent-yellow)",
        display: "flex",
        flexDirection: "column",
        justifyContent: "space-between",
      }}
    >
      <div>
        <div style={{ padding: 18, borderBottom: "3px solid #1f1f1f" }}>
          <h1 style={{ color: "var(--accent-yellow)", fontSize: 56, lineHeight: 1 }}>EMET</h1>
          <p style={{ margin: 0, color: "#8f8f8f", fontSize: 11, letterSpacing: "0.12em" }}>v3.0 // DEFENSIVE PLATFORM</p>
        </div>

        <nav style={{ padding: 10, display: "grid", gap: 8 }}>
          {navItems.map((item) => {
            const active = pathname === item.href || pathname.startsWith(`${item.href}/`);
            const Icon = item.icon;
            return (
              <Link
                key={item.href}
                href={item.href}
                className="sidebar-nav-item"
                style={{
                  border: "2px solid #000",
                  borderLeft: active ? "4px solid var(--accent-yellow)" : "2px solid #000",
                  padding: "12px 10px",
                  display: "flex",
                  gap: 8,
                  alignItems: "center",
                  fontWeight: 700,
                  letterSpacing: "0.06em",
                  background: active ? "#1A1A1A" : "#111",
                  color: active ? "var(--accent-yellow)" : "#c4c4c4",
                  textTransform: "uppercase",
                  transition: "none",
                }}
              >
                <Icon size={18} />
                <span style={{ fontSize: 11 }}>{item.label}</span>
              </Link>
            );
          })}
        </nav>
      </div>

      <div style={{ padding: 14, borderTop: "3px solid #1f1f1f", display: "grid", gap: 10 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 11, letterSpacing: "0.08em" }}>
          <span className="status-square" style={{ background: backendOnline ? "var(--accent-green)" : "var(--accent-red)" }} />
          <span>{backendOnline ? "BACKEND ONLINE" : "BACKEND OFFLINE"}</span>
          <Wifi size={14} color={backendOnline ? "#00ff6a" : "#ff2d2d"} />
        </div>
        <div style={{ border: "2px solid #333", padding: 8, display: "grid", gap: 6 }}>
          <div style={{ fontWeight: 700, fontSize: 12 }}>QUEUE DEPTH // {queueDepth === null ? "N/A" : queueDepth}</div>
          <button
            className="neo-btn"
            style={{ width: "100%", marginTop: 4, background: "#fff", color: "#000", padding: "8px 10px", display: "flex", alignItems: "center", gap: 8, justifyContent: "center" }}
            onClick={async () => {
              try {
                await logout();
              } finally {
                router.push("/login");
              }
            }}
          >
            <LogOut size={14} />
            LOGOUT
          </button>
        </div>
      </div>
    </aside>
  );
}
