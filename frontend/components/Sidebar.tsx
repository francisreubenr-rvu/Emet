"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import {
  BarChart3,
  BotMessageSquare,
  CheckCircle,
  FileSearch,
  FileText,
  LayoutDashboard,
  LogOut,
  Radar,
  Settings,
  ShieldAlert,
  Split,
  Ticket,
  Users,
  Wifi,
  Server,
} from "lucide-react";

import { getHealth, logout } from "@/lib/api";

const navItems = [
  { href: "/dashboard", label: "DASHBOARD", icon: LayoutDashboard },
  { href: "/scan-console", label: "SCAN ORCHESTRATION", icon: Radar },
  { href: "/scan-reports", label: "REPORTS", icon: FileText },
  { href: "/agents", label: "AGENTS", icon: Server },
  { href: "/remediation", label: "REMEDIATION", icon: Ticket },
  { href: "/compliance", label: "COMPLIANCE", icon: CheckCircle },
  { href: "/tenants", label: "TENANTS", icon: Users },
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
        width: "260px",
        minHeight: "100vh",
        position: "fixed",
        left: 0,
        top: 0,
        zIndex: 2000,
        background: "var(--bg-dark)",
        color: "var(--text-inverse)",
        borderRight: "4px solid var(--accent-yellow)",
        display: "flex",
        flexDirection: "column",
        justifyContent: "space-between",
        boxShadow: "10px 0px 0px rgba(0,0,0,0.1)"
      }}
    >
      <div>
        <div style={{ padding: 24, borderBottom: "4px solid #1f1f1f", position: "relative" }}>
          <h1 style={{ color: "var(--accent-yellow)", fontSize: 62, lineHeight: 0.8, marginBottom: 8 }}>EMET</h1>
          <div style={{ 
            fontSize: 9, 
            background: "var(--accent-yellow)", 
            color: "#000", 
            display: "inline-block", 
            padding: "2px 6px", 
            fontWeight: 900,
            letterSpacing: "0.15em"
          }}>
            SYSTEM v4.0 // PRO
          </div>
          <div style={{ position: "absolute", bottom: -2, right: 0, width: 40, height: 4, background: "var(--accent-yellow)" }} />
        </div>

        <nav style={{ padding: 12, display: "grid", gap: 6 }}>
          {navItems.map((item) => {
            const active = pathname === item.href || pathname.startsWith(`${item.href}/`);
            const Icon = item.icon;
            return (
              <Link
                key={item.href}
                href={item.href}
                className="sidebar-nav-item"
                style={{
                  border: "2px solid transparent",
                  borderLeft: active ? "6px solid var(--accent-yellow)" : "2px solid transparent",
                  padding: "14px 12px",
                  display: "flex",
                  gap: 12,
                  alignItems: "center",
                  fontWeight: 800,
                  letterSpacing: "0.08em",
                  background: active ? "#111" : "transparent",
                  color: active ? "var(--accent-yellow)" : "#888",
                  textTransform: "uppercase",
                  fontSize: 10,
                }}
              >
                <Icon size={16} strokeWidth={active ? 3 : 2} />
                <span>{item.label}</span>
              </Link>
            );
          })}
        </nav>
      </div>

      <div style={{ padding: 16, borderTop: "4px solid #1f1f1f", display: "grid", gap: 12, background: "#080808" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10, fontSize: 10, fontWeight: 900, letterSpacing: "0.1em" }}>
          <div style={{ 
            width: 10, 
            height: 10, 
            background: backendOnline ? "var(--accent-green)" : "var(--accent-red)",
            boxShadow: backendOnline ? "0 0 10px var(--accent-green)" : "0 0 10px var(--accent-red)"
          }} />
          <span style={{ color: backendOnline ? "var(--accent-green)" : "var(--accent-red)" }}>
            {backendOnline ? "CORE ONLINE" : "SYSTEM OFFLINE"}
          </span>
        </div>
        
        <div style={{ border: "2px solid #222", padding: 12, position: "relative" }}>
          <div style={{ position: "absolute", top: -8, left: 8, background: "#080808", padding: "0 4px", fontSize: 8, color: "#444", fontWeight: 800 }}>QUEUE_METRICS</div>
          <div style={{ fontWeight: 900, fontSize: 14, color: "#fff" }}>
            DEPTH: <span style={{ color: "var(--accent-yellow)" }}>{queueDepth === null ? "ERR" : queueDepth}</span>
          </div>
          <button
            style={{ 
              width: "100%", 
              marginTop: 12, 
              background: "var(--accent-yellow)", 
              color: "#000", 
              padding: "10px", 
              border: "none",
              fontWeight: 900,
              fontSize: 10,
              cursor: "pointer",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              gap: 8
            }}
            onClick={async () => {
              try {
                await logout();
              } finally {
                router.push("/login");
              }
            }}
          >
            <LogOut size={14} strokeWidth={3} />
            INIT_LOGOUT
          </button>
        </div>
      </div>
    </aside>
  );
}
