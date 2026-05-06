"use client";

import { useEffect, useState } from "react";

import { Panel, SectionTitle } from "@/components/ui/primitives";
import { getAttackPaths, getReports } from "@/lib/api";
import { AttackPathRow, ScanReport } from "@/lib/types";

export default function AttackPathsPage() {
  const [reports, setReports] = useState<ScanReport[]>([]);
  const [selectedScanId, setSelectedScanId] = useState("");
  const [paths, setPaths] = useState<AttackPathRow[]>([]);

  useEffect(() => {
    void getReports()
      .then((items) => {
        setReports(items);
        if (items.length) {
          setSelectedScanId(items[0].id);
        }
      })
      .catch(() => {
        setReports([]);
      });
  }, []);

  useEffect(() => {
    if (!selectedScanId) return;
    void getAttackPaths(selectedScanId)
      .then(setPaths)
      .catch(() => setPaths([]));
  }, [selectedScanId]);

  return (
    <div style={{ display: "grid", gap: 12 }}>
      <SectionTitle>Attack Paths</SectionTitle>

      <Panel>
        <div style={{ padding: 12, borderBottom: "2px solid #000", background: "#fff4a3", fontWeight: 800 }}>
          DEFENSIVE EXPOSURE GRAPH ONLY - NO OFFENSIVE INSTRUCTIONAL CONTENT
        </div>
        <div style={{ padding: 12 }}>
          <p style={{ marginTop: 0 }}>
            This page maps exposure relationships between assets, services, and vulnerabilities to prioritize remediation leverage.
          </p>
          <div style={{ display: "grid", gap: 8, marginBottom: 10 }}>
            <label style={{ fontWeight: 700, fontSize: 12 }}>SCAN</label>
            <select
              value={selectedScanId}
              onChange={(event) => setSelectedScanId(event.target.value)}
              style={{ border: "2px solid #000", padding: 10, fontFamily: "inherit" }}
            >
              {reports.map((item) => (
                <option key={item.id} value={item.id}>
                  {item.id} • {item.target} • {item.date}
                </option>
              ))}
            </select>
          </div>
          <div style={{ border: "2px solid #000", minHeight: 220, padding: 10, display: "grid", gap: 8 }}>
            {paths.length === 0 ? <div style={{ fontWeight: 700 }}>No attack paths available for selected scan.</div> : null}
            {paths.map((path, idx) => (
              <div key={path.id} style={{ border: "2px solid #000", background: idx % 2 ? "#f6f6f6" : "#fff", padding: 8, fontWeight: 700 }}>
                PATH {idx + 1} ({Math.round(path.confidence_score * 100)}%): {path.path_summary}
              </div>
            ))}
          </div>
        </div>
      </Panel>

      <Panel>
        <div style={{ padding: 12 }}>
          <h3 style={{ fontSize: 28 }}>Remediation Leverage</h3>
          <ul>
            <li>Patch internet-exposed services with verified CVEs first.</li>
            <li>Reduce blast radius by segmenting legacy systems.</li>
            <li>Track path confidence and provenance before prioritizing work items.</li>
          </ul>
        </div>
      </Panel>
    </div>
  );
}
