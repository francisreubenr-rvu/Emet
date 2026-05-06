"use client";

import { useEffect, useState } from "react";

import { Panel, SectionTitle } from "@/components/ui/primitives";

type AuditLog = {
  id: number;
  created_at: string;
  event_type: string;
  actor: string;
  scan_id: string;
  details: Record<string, unknown>;
};

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

async function authed<T>(path: string): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    cache: "no-store",
  });
  if (!response.ok) throw new Error(`API ${response.status}: ${await response.text()}`);
  return response.json() as Promise<T>;
}

export default function AuditLogsPage() {
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void authed<AuditLog[]>("/api/audit/logs?limit=200")
      .then((items) => setLogs(items))
      .catch((err) => setError(err instanceof Error ? err.message : "Failed to load audit logs"));
  }, []);

  return (
    <div style={{ display: "grid", gap: 12 }}>
      <SectionTitle>Audit Logs</SectionTitle>
      <Panel>
        <div className="code-log" style={{ minHeight: 420, maxHeight: 580, overflowY: "auto", border: "2px solid #000", padding: 10 }}>
          {logs.length === 0 ? "No audit logs yet." : null}
          {logs.map((log) => (
            <div key={log.id} style={{ borderTop: "1px solid #2e2e2e", paddingTop: 8, marginTop: 8 }}>
              [{new Date(log.created_at).toLocaleString()}] {log.event_type} actor={log.actor} scan_id={log.scan_id || "-"}
            </div>
          ))}
        </div>
      </Panel>
      {error ? <p style={{ color: "var(--accent-red)", margin: 0 }}>{error}</p> : null}
    </div>
  );
}
