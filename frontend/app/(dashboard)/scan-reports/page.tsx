"use client";

import { useEffect, useMemo, useState } from "react";

import { Panel, SectionTitle } from "@/components/ui/primitives";
import { fetchOsint, getReportDetail, getReports, updateVulnerabilityStatus } from "@/lib/api";
import { getIndexedReportById, getIndexedReports } from "@/lib/storage";
import { OsintIntel, ScanReport } from "@/lib/types";

function severityColor(severity: string): string {
  if (severity === "CRITICAL") return "#FF2D2D";
  if (severity === "HIGH") return "#FF6B00";
  if (severity === "MEDIUM") return "#FFE500";
  if (severity === "LOW") return "#00FF6A";
  return "#0057FF";
}

export default function ScanReportsPage() {
  const [reports, setReports] = useState<ScanReport[]>([]);
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState("ALL");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<any | null>(null);
  const [osint, setOsint] = useState<OsintIntel | null>(null);
  const [loadingOsint, setLoadingOsint] = useState(false);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const remote = await getReports();
        const local = await getIndexedReports();
        const merged = [...remote, ...local.filter((localItem) => !remote.find((r) => r.id === localItem.id))];
        if (!cancelled) setReports(merged);
      } catch {
        const local = await getIndexedReports();
        if (!cancelled) setReports(local);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const filtered = useMemo(() => {
    return reports.filter((report) => {
      const matchQuery = `${report.target} ${report.date}`.toLowerCase().includes(query.toLowerCase());
      const matchFilter = filter === "ALL" || report.severity === filter;
      return matchQuery && matchFilter;
    });
  }, [reports, query, filter]);

  const openDetail = async (report: ScanReport) => {
    setSelectedId(report.id);
    setLoadingOsint(true);
    setOsint(null);
    try {
      const remoteDetail = await getReportDetail(report.id);
      setDetail(remoteDetail);
    } catch {
      const local = await getIndexedReportById(report.id);
      setDetail(local?.full || null);
    }

    try {
      const intel = await fetchOsint(report.target);
      setOsint(intel);
    } finally {
      setLoadingOsint(false);
    }
  };

  return (
    <div style={{ display: "grid", gap: 12 }}>
      <SectionTitle>Reports</SectionTitle>

      <Panel>
        <div style={{ padding: 14, display: "grid", gridTemplateColumns: "1fr 220px", gap: 10, borderBottom: "3px solid #000" }}>
          <input
            placeholder="Search target, CVE, date..."
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            style={{ border: "3px solid #000", boxShadow: "var(--shadow)", padding: 10, fontFamily: "inherit" }}
          />
          <select value={filter} onChange={(event) => setFilter(event.target.value)} style={{ border: "3px solid #000", boxShadow: "var(--shadow)", padding: 10, fontFamily: "inherit" }}>
            <option value="ALL">Filter by Severity</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
            <option value="INFO">Info</option>
          </select>
        </div>

        <div style={{ padding: 0, display: "grid", gap: 0 }}>
          {filtered.map((report) => (
            <article key={report.id} style={{ borderTop: "2px solid #000", padding: 10, background: "#fff", width: "100%" }}>
              <div style={{ display: "grid", gridTemplateColumns: "1.4fr 0.9fr 0.8fr 1fr 110px 120px", gap: 8, alignItems: "center" }}>
                <strong>{report.target}</strong>
                <span>{new Date(report.date).toLocaleString()}</span>
                <span>{report.duration}</span>
                <span>{report.tools.join(", ")}</span>
                <span style={{ border: "2px solid #000", background: severityColor(report.severity), padding: "2px 8px", textAlign: "center", fontWeight: 800 }}>{report.severity}</span>
                <button
                  onClick={() => {
                    void openDetail(report);
                  }}
                  className="neo-btn"
                  style={{ padding: "6px 8px", background: "#fff" }}
                >
                  EXPAND
                </button>
              </div>
            </article>
          ))}
        </div>
      </Panel>

      {selectedId && detail ? (
        <Panel>
          <div style={{ padding: 14, display: "grid", gap: 12 }}>
            <h3 style={{ fontSize: 30 }}>REPORT DETAIL: {detail.target}</h3>

            <div style={{ border: "2px solid #000", padding: 10 }}>
              <strong>ALL PREVIOUS SCANS FOR THIS TARGET</strong>
              <div style={{ marginTop: 8, borderTop: "2px solid #000", paddingTop: 8 }}>
                {reports
                  .filter((item) => item.target === detail.target)
                  .slice(0, 8)
                  .map((item) => (
                    <div key={item.id} style={{ display: "grid", gridTemplateColumns: "1fr 1fr 80px", padding: "4px 0" }}>
                      <span>{new Date(item.date).toLocaleDateString()}</span>
                      <span>{item.findings_count} findings</span>
                      <span>{item.severity}</span>
                    </div>
                  ))}
              </div>
            </div>

            <div style={{ border: "2px solid #000", padding: 10 }}>
              <strong>FULL SCAN DETAILS</strong>
              <p style={{ marginBottom: 6 }}>{detail.unified_report?.executive_summary || "No unified summary."}</p>
              <div style={{ borderTop: "2px solid #000", paddingTop: 8 }}>
                {(detail.findings || []).map((item: any) => (
                  <div key={`${item.finding_id || item.cve_id || item.title}-${item.port || 0}`} style={{ border: "2px solid #000", marginBottom: 8, padding: 8 }}>
                    <div style={{ fontWeight: 800 }}>{item.cve_id || "UNCLASSIFIED"} - {item.title}</div>
                    <div style={{ fontSize: 13 }}>{item.description}</div>
                    <div style={{ fontSize: 12, marginTop: 6, display: "flex", flexWrap: "wrap", gap: 12 }}>
                      <span>Component: {item.affected_component}</span>
                      <span>Severity: {item.severity}</span>
                      <span style={{ fontWeight: 800, color: "var(--accent-red)" }}>Risk Score: {item.dynamic_risk_score?.toFixed(1) || '0.0'}</span>
                      <span>Verification: {item.verification_status || "unverified"}</span>
                    </div>
                    {item.compliance_violations?.length > 0 && (
                      <div style={{ marginTop: 6, fontSize: 11, background: "#000", padding: "4px 8px", color: "var(--accent-yellow)" }}>
                        COMPLIANCE VIOLATIONS: {item.compliance_violations.join(", ")}
                      </div>
                    )}
                    <div style={{ display: "flex", gap: 8, marginTop: 8 }}>
                      <button
                        className="neo-btn"
                        style={{ background: "#fff", padding: "6px 10px" }}
                        onClick={() => {
                          if (!item.finding_id) return;
                          void updateVulnerabilityStatus(item.finding_id, "in_progress");
                        }}
                      >
                        MARK IN PROGRESS
                      </button>
                      <button
                        className="neo-btn"
                        style={{ background: "#fff", padding: "6px 10px" }}
                        onClick={() => {
                          if (!item.finding_id) return;
                          void updateVulnerabilityStatus(item.finding_id, "resolved");
                        }}
                      >
                        MARK RESOLVED
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div style={{ border: "2px solid #000", padding: 10 }}>
              <strong>OSINT INTELLIGENCE</strong>
              {loadingOsint ? (
                <p style={{ fontWeight: 700 }}>FETCHING LIVE INTEL...</p>
              ) : osint ? (
                <div style={{ marginTop: 8, display: "grid", gap: 8 }}>
                  <div>Shodan ports: {osint.shodan.open_ports.join(", ")}</div>
                  <div>Whois registrar: {osint.whois.registrar}</div>
                  <div>SSL grade: {osint.ssl.grade} ({osint.ssl.issuer})</div>
                  <div>Breach count: {osint.breaches.count}</div>
                  <div>
                    News:
                    <ul>
                      {osint.news.map((item) => (
                        <li key={item.title}>{item.source}: {item.title}</li>
                      ))}
                    </ul>
                  </div>
                </div>
              ) : (
                <p>No OSINT data available.</p>
              )}
            </div>
          </div>
        </Panel>
      ) : null}
    </div>
  );
}
