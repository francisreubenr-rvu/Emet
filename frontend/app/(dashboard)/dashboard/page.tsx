"use client";

import { useEffect, useMemo, useState } from "react";

import { NeoButton, Panel, SectionTitle } from "@/components/ui/primitives";
import { DashboardStats, OperationsQueueHealth, ScanReport, ScannerAvailability, WorkerHeartbeatRow, WorkerMetricRow } from "@/lib/types";
import { getDashboardStats, getHealth, getOperationsQueue, getOperationsWorkerMetrics, getOperationsWorkers, getReports, replayDeadLetter } from "@/lib/api";

const emptyStats: DashboardStats = {
  total_scans: 0,
  active_scans: 0,
  critical_findings: 0,
  verified_findings: 0,
  severity_distribution: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
  last_scan_time: new Date(0).toISOString(),
  queue_health: "unknown",
  rag_availability: "unknown",
  evaluation_summary: { latest_f1: 0, latest_accuracy: 0 },
};

import { LayoutDashboard } from "lucide-react";

export default function DashboardPage() {
  const [stats, setStats] = useState<DashboardStats>(emptyStats);
  const [recentScans, setRecentScans] = useState<ScanReport[]>([]);
  const [scannerHealth, setScannerHealth] = useState<ScannerAvailability[]>([]);
  const [queueHealth, setQueueHealth] = useState<OperationsQueueHealth | null>(null);
  const [workers, setWorkers] = useState<WorkerHeartbeatRow[]>([]);
  const [workerMetrics, setWorkerMetrics] = useState<WorkerMetricRow[]>([]);
  const [opsActionText, setOpsActionText] = useState("Ready");

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const [dashboard, health, reports, queue, workerRows, metricRows] = await Promise.all([
          getDashboardStats(),
          getHealth(),
          getReports(),
          getOperationsQueue(),
          getOperationsWorkers(),
          getOperationsWorkerMetrics(),
        ]);
        if (cancelled) return;
        setStats(dashboard);
        setScannerHealth(health.scanners || []);
        setRecentScans(reports.slice(0, 5));
        setQueueHealth(queue);
        setWorkers(workerRows);
        setWorkerMetrics(metricRows);
      } catch {
        if (!cancelled) {
          setStats(emptyStats);
          setRecentScans([]);
          setScannerHealth([]);
          setQueueHealth(null);
          setWorkers([]);
          setWorkerMetrics([]);
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const severityBars = useMemo(() => {
    const total = Object.values(stats.severity_distribution).reduce((sum, value) => sum + value, 0) || 1;
    return [
      { label: "Critical", value: Math.round((stats.severity_distribution.CRITICAL / total) * 100), color: "var(--accent-red)" },
      { label: "High", value: Math.round((stats.severity_distribution.HIGH / total) * 100), color: "#FF6B00" },
      { label: "Medium", value: Math.round((stats.severity_distribution.MEDIUM / total) * 100), color: "var(--accent-yellow)" },
      { label: "Low", value: Math.round((stats.severity_distribution.LOW / total) * 100), color: "var(--accent-green)" },
      { label: "Info", value: Math.round((stats.severity_distribution.INFO / total) * 100), color: "var(--accent-blue)" },
    ];
  }, [stats]);

  const topStats = [
    { label: "TOTAL SCANS", value: String(stats.total_scans), ref: "SC-01" },
    { label: "ACTIVE SCANS", value: String(stats.active_scans), ref: "SC-02" },
    { label: "CRITICAL FINDINGS", value: String(stats.critical_findings), ref: "VF-01" },
    { label: "VERIFIED FINDINGS", value: String(stats.verified_findings), ref: "VF-02" },
  ];

  return (
    <div style={{ display: "grid", gap: 24 }}>
      <SectionTitle 
        subtitle="Operational Intelligence & Threat Vector Surface" 
        icon={LayoutDashboard}
      >
        Dashboard
      </SectionTitle>

      <section style={{ display: "grid", gridTemplateColumns: "repeat(4, minmax(0, 1fr))", gap: 16 }}>
        {topStats.map((item) => (
          <Panel key={item.label} refId={item.ref}>
            <div style={{ minHeight: 120, display: "flex", flexDirection: "column", justifyContent: "space-between" }}>
              <p style={{ margin: 0, fontSize: 10, fontWeight: 900, textTransform: "uppercase", color: "#888" }}>{item.label}</p>
              <p style={{ margin: "8px 0 0", fontSize: 56, fontFamily: "var(--font-display)", fontWeight: 900, lineHeight: 1 }}>{item.value}</p>
            </div>
          </Panel>
        ))}
      </section>

      <Panel refId="AUTH-NOTICE" style={{ background: "var(--accent-yellow)", color: "#000" }}>
        <div style={{ fontWeight: 900, fontSize: 13, letterSpacing: "0.05em" }}>
          🚨 AUTHORIZATION NOTICE: RUN SCANS ONLY AGAINST ASSETS YOU ARE EXPLICITLY AUTHORIZED TO ASSESS.
        </div>
      </Panel>

      <section style={{ display: "grid", gridTemplateColumns: "3fr 2fr", gap: 24 }}>
        <Panel refId="SCAN-LOG">
          <h3 style={{ fontSize: 28, marginBottom: 16 }}>Recent Scans</h3>
          {recentScans.length === 0 ? <p style={{ marginTop: 12 }}>No scans yet. Launch your first authorized scan from Scan Orchestration.</p> : null}
          <div style={{ display: "grid", gap: 0 }}>
            {recentScans.map((row) => (
              <div key={row.id} style={{ display: "grid", gridTemplateColumns: "2fr 1fr 120px", padding: "14px 0", borderTop: "2px solid #eee" }}>
                <strong>{row.target}</strong>
                <span style={{ fontSize: 11, color: "#666" }}>{new Date(row.date).toLocaleString()}</span>
                <span className={`severity-badge severity-${row.severity}`} style={{ width: "fit-content", background: severityBars.find(b => b.label.toUpperCase() === row.severity)?.color || "#eee" }}>{row.severity}</span>
              </div>
            ))}
          </div>
        </Panel>

        <Panel refId="DIST-01">
          <h3 style={{ fontSize: 28, marginBottom: 16 }}>Severity Distribution</h3>
          <div style={{ display: "grid", gap: 12 }}>
            {severityBars.map((item) => (
              <div key={item.label}>
                <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, fontWeight: 900, marginBottom: 4 }}>
                  <span>{item.label.toUpperCase()}</span>
                  <span>{item.value}%</span>
                </div>
                <div style={{ border: "3px solid #000", height: 28, background: "#f0f0f0", position: "relative" }}>
                  <div style={{ width: `${item.value}%`, height: "100%", background: item.color, borderRight: "3px solid #000" }} />
                </div>
              </div>
            ))}
          </div>
        </Panel>
      </section>

      <section style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 24 }}>
        <Panel refId="OPS-01">
          <h3 style={{ fontSize: 28, marginBottom: 16 }}>Operational Snapshot</h3>
          <div style={{ display: "grid", gap: 0 }}>
            {[
              ["Queue health", stats.queue_health.toUpperCase(), "var(--accent-yellow)"],
              ["RAG availability", stats.rag_availability.toUpperCase(), "var(--accent-blue)"],
              ["Latest eval F1", String(stats.evaluation_summary.latest_f1), "var(--accent-green)"],
              ["Latest eval accuracy", String(stats.evaluation_summary.latest_accuracy), "var(--accent-green)"],
            ].map((item) => (
              <div key={item[0]} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "12px 0", borderTop: "2px solid #eee" }}>
                <span style={{ fontWeight: 800, fontSize: 12 }}>{item[0].toUpperCase()}</span>
                <span style={{ border: "2px solid #000", padding: "4px 10px", background: item[2] as string, fontWeight: 900, fontSize: 10 }}>{item[1]}</span>
              </div>
            ))}
          </div>
        </Panel>

        <Panel refId="HEALTH-01">
          <h3 style={{ fontSize: 28, marginBottom: 16 }}>Scanner Health</h3>
          {scannerHealth.length === 0 ? <p style={{ marginTop: 12 }}>No scanner health data available.</p> : null}
          <div style={{ display: "grid", gap: 0 }}>
            {scannerHealth.map((item) => (
              <div key={item.scanner} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "12px 0", borderTop: "2px solid #eee" }}>
                <span style={{ fontWeight: 800, fontSize: 12 }}>{item.scanner.toUpperCase()}</span>
                <span style={{ border: "2px solid #000", padding: "4px 10px", background: item.available ? "var(--accent-green)" : "var(--accent-red)", fontWeight: 900, fontSize: 10 }}>
                  {item.available ? "ACTIVE" : "OFFLINE"}
                </span>
              </div>
            ))}
          </div>
        </Panel>
      </section>
    </div>
  );
}
