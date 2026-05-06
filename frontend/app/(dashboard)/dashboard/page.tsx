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
    { label: "TOTAL SCANS", value: String(stats.total_scans) },
    { label: "ACTIVE SCANS", value: String(stats.active_scans) },
    { label: "CRITICAL FINDINGS", value: String(stats.critical_findings) },
    { label: "VERIFIED FINDINGS", value: String(stats.verified_findings) },
  ];

  return (
    <div style={{ display: "grid", gap: 18 }}>
      <SectionTitle>Dashboard</SectionTitle>

      <section style={{ display: "grid", gridTemplateColumns: "repeat(4, minmax(0, 1fr))", gap: 12 }}>
        {topStats.map((item) => (
          <Panel key={item.label}>
            <div style={{ padding: 14, minHeight: 150, display: "flex", flexDirection: "column", justifyContent: "space-between" }}>
              <p style={{ margin: 0, fontSize: 11, fontWeight: 700, textTransform: "uppercase", fontFamily: "var(--font-body)" }}>{item.label}</p>
              <p style={{ margin: "8px 0 0", fontSize: 64, fontFamily: "var(--font-display)", fontWeight: 700, lineHeight: 1 }}>{item.value}</p>
            </div>
          </Panel>
        ))}
      </section>

      <Panel>
        <div style={{ padding: 12, background: "#fff4a3", borderBottom: "2px solid #000", fontWeight: 800 }}>
          AUTHORIZATION NOTICE: Run scans only against assets you are explicitly authorized to assess.
        </div>
      </Panel>

      <section style={{ display: "grid", gridTemplateColumns: "3fr 2fr", gap: 12 }}>
        <Panel>
          <div style={{ padding: 14 }}>
            <h3 style={{ fontSize: 28 }}>Recent Scans</h3>
            {recentScans.length === 0 ? <p style={{ marginTop: 12 }}>No scans yet. Launch your first authorized scan from Scan Orchestration.</p> : null}
            {recentScans.map((row) => (
              <div key={row.id} style={{ display: "grid", gridTemplateColumns: "2fr 1fr 120px", padding: "10px 0", borderTop: "2px solid #000" }}>
                <strong>{row.target}</strong>
                <span>{new Date(row.date).toLocaleString()}</span>
                <span className={`severity-badge severity-${row.severity}`} style={{ width: "fit-content" }}>{row.severity}</span>
              </div>
            ))}
          </div>
        </Panel>

        <Panel>
          <div style={{ padding: 14 }}>
            <h3 style={{ fontSize: 28 }}>Severity Distribution</h3>
            <div style={{ display: "grid", gap: 10, marginTop: 10 }}>
              {severityBars.map((item) => (
                <div key={item.label}>
                  <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12, fontWeight: 700 }}>
                    <span>{item.label.toUpperCase()}</span>
                    <span>{item.value}%</span>
                  </div>
                  <div style={{ border: "2px solid #000", height: 24, background: "#fff" }}>
                    <div style={{ width: `${item.value}%`, height: "100%", background: item.color, borderRight: "2px solid #000" }} />
                  </div>
                </div>
              ))}
            </div>
          </div>
        </Panel>
      </section>

      <section style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
        <Panel>
          <div style={{ padding: 14 }}>
            <h3 style={{ fontSize: 28 }}>Operational Snapshot</h3>
            {[
              ["Queue health", stats.queue_health.toUpperCase(), "var(--accent-yellow)"],
              ["RAG availability", stats.rag_availability.toUpperCase(), "var(--accent-blue)"],
              ["Latest eval F1", String(stats.evaluation_summary.latest_f1), "var(--accent-green)"],
              ["Latest eval accuracy", String(stats.evaluation_summary.latest_accuracy), "var(--accent-green)"],
            ].map((item) => (
              <div key={item[0]} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "10px 0", borderTop: "2px solid #000" }}>
                <span style={{ fontWeight: 700 }}>{item[0]}</span>
                <span style={{ border: "2px solid #000", padding: "2px 8px", background: item[2] as string, fontWeight: 800 }}>{item[1]}</span>
              </div>
            ))}
          </div>
        </Panel>

        <Panel>
          <div style={{ padding: 14 }}>
            <h3 style={{ fontSize: 28 }}>Scanner Health</h3>
            {scannerHealth.length === 0 ? <p style={{ marginTop: 12 }}>No scanner health data available.</p> : null}
            {scannerHealth.map((item) => (
              <div key={item.scanner} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "10px 0", borderTop: "2px solid #000" }}>
                <span style={{ fontWeight: 700 }}>{item.scanner.toUpperCase()}</span>
                <span style={{ border: "2px solid #000", padding: "2px 8px", background: item.available ? "var(--accent-green)" : "var(--accent-red)", fontWeight: 800 }}>
                  {item.available ? "AVAILABLE" : "UNAVAILABLE"}
                </span>
              </div>
            ))}
          </div>
        </Panel>
      </section>

      <section style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
        <Panel>
          <div style={{ padding: 14 }}>
            <h3 style={{ fontSize: 28 }}>Queue Partitions</h3>
            {queueHealth ? (
              <>
                {Object.entries(queueHealth.queues).map(([name, depth]) => (
                  <div key={name} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "10px 0", borderTop: "2px solid #000" }}>
                    <span style={{ fontWeight: 700 }}>{name.toUpperCase()}</span>
                    <span style={{ border: "2px solid #000", padding: "2px 8px", fontWeight: 800 }}>
                      {depth} • oldest {queueHealth.queue_oldest_age_seconds[name] || 0}s
                    </span>
                  </div>
                ))}
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "10px 0", borderTop: "2px solid #000" }}>
                  <span style={{ fontWeight: 700 }}>TOTAL DEPTH</span>
                  <span style={{ border: "2px solid #000", padding: "2px 8px", fontWeight: 800 }}>{queueHealth.total_depth}</span>
                </div>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "10px 0", borderTop: "2px solid #000" }}>
                  <span style={{ fontWeight: 700 }}>DEAD LETTER</span>
                  <span style={{ border: "2px solid #000", padding: "2px 8px", fontWeight: 800, background: queueHealth.dead_letter_depth > 0 ? "var(--accent-red)" : "var(--accent-green)" }}>
                    {queueHealth.dead_letter_depth}
                  </span>
                </div>
                <div style={{ marginTop: 10, display: "flex", gap: 8, alignItems: "center" }}>
                  <NeoButton
                    style={{ background: "#000", color: "var(--accent-yellow)", padding: "6px 10px" }}
                    onClick={() => {
                      void replayDeadLetter()
                        .then((res) => {
                          setOpsActionText(`Replayed to ${res.target_queue}`);
                          return getOperationsQueue().then(setQueueHealth);
                        })
                        .catch(() => setOpsActionText("Replay failed or requires admin"));
                    }}
                  >
                    REPLAY DEAD LETTER
                  </NeoButton>
                  <span style={{ fontSize: 12, fontWeight: 700 }}>{opsActionText}</span>
                </div>
              </>
            ) : (
              <p style={{ marginTop: 12 }}>Queue health unavailable.</p>
            )}
          </div>
        </Panel>

        <Panel>
          <div style={{ padding: 14 }}>
            <h3 style={{ fontSize: 28 }}>Workers</h3>
            {workers.length === 0 ? <p style={{ marginTop: 12 }}>No worker heartbeat signals.</p> : null}
            {workers.map((item) => (
              <div key={item.worker_id} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "10px 0", borderTop: "2px solid #000" }}>
                <span style={{ fontWeight: 700 }}>{item.worker_id}</span>
                <span style={{ fontSize: 12 }}>{new Date(item.heartbeat).toLocaleTimeString()}</span>
              </div>
            ))}
            <div style={{ marginTop: 10, borderTop: "2px solid #000", paddingTop: 10 }}>
              <strong style={{ fontSize: 12 }}>Worker throughput</strong>
              {workerMetrics.map((row) => (
                <div key={row.worker_id} style={{ marginTop: 8, fontSize: 12, border: "2px solid #000", padding: 8 }}>
                  <div style={{ fontWeight: 700 }}>{row.worker_id}</div>
                  <div>picked: {row.metrics.picked || 0} | completed: {row.metrics.completed || 0} | failed: {row.metrics.failed || 0}</div>
                  <div>
                    per-scanner proxy: nmap {row.metrics["scanner:nmap"] || 0} | nuclei {row.metrics["scanner:nuclei"] || 0} | rustscan {row.metrics["scanner:rustscan"] || 0}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </Panel>
      </section>
    </div>
  );
}
