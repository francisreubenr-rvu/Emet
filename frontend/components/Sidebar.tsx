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
        borderRight: "3px solid var(--accent-strong)",
        display: "flex",
        flexDirection: "column",
        justifyContent: "space-between",
      }}
    >
      <div>
        <div style={{ padding: 24, borderBottom: "2px solid #2a2a30", position: "relative" }}>
          <h1 style={{ color: "var(--accent)", fontSize: 48, lineHeight: 0.9, marginBottom: 10 }}>EMET</h1>
          <div style={{
            fontSize: 9,
            background: "var(--accent)",
            color: "#000",
            display: "inline-block",
            padding: "3px 7px",
            fontWeight: 700,
            letterSpacing: "0.12em",
            borderRadius: 3,
          }}>
            VULNERABILITY SCANNER + INTEL
          </div>
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
                  borderLeft: active ? "5px solid var(--accent)" : "2px solid transparent",
                  borderRadius: 4,
                  padding: "12px 12px",
                  display: "flex",
                  gap: 12,
                  alignItems: "center",
                  fontWeight: 600,
                  letterSpacing: "0.06em",
                  background: active ? "#24242a" : "transparent",
                  color: active ? "var(--accent)" : "#a1a1aa",
                  textTransform: "uppercase",
                  fontSize: 10.5,
                }}
                aria-current={active ? "page" : undefined}
              >
                <Icon size={16} strokeWidth={active ? 3 : 2} />
                <span>{item.label}</span>
              </Link>
            );
          })}
        </nav>
      </div>

      <div style={{ padding: 16, borderTop: "2px solid #2a2a30", display: "grid", gap: 12, background: "#101013" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10, fontSize: 10, fontWeight: 700, letterSpacing: "0.08em" }}>
          <div style={{
            width: 9,
            height: 9,
            borderRadius: "50%",
            background: backendOnline ? "var(--ok)" : "var(--danger)",
          }} />
          <span style={{ color: backendOnline ? "var(--ok)" : "var(--danger)" }}>
            {backendOnline ? "BACKEND ONLINE" : "BACKEND OFFLINE"}
          </span>
        </div>

        <div style={{ border: "2px solid #2a2a30", borderRadius: 4, padding: 12, position: "relative" }}>
          <div style={{ position: "absolute", top: -8, left: 8, background: "#101013", padding: "0 4px", fontSize: 8, color: "#6b7280", fontWeight: 700, letterSpacing: "0.08em" }}>QUEUE DEPTH</div>
          <div style={{ fontWeight: 700, fontSize: 14, color: "#fff", fontFamily: "var(--font-code)" }}>
            {queueDepth === null ? "—" : queueDepth}
          </div>
          <button
            style={{
              width: "100%",
              marginTop: 12,
              background: "var(--accent)",
              color: "#000",
              padding: "10px",
              border: "2px solid #000",
              borderRadius: 4,
              fontWeight: 700,
              fontSize: 10,
              letterSpacing: "0.06em",
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
            <LogOut size={14} strokeWidth={2.5} />
            LOG OUT
          </button>
        </div>
      </div>
    </aside>
  );
}
