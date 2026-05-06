"use client";

import { useEffect, useState } from "react";
import { Panel, SectionTitle } from "@/components/ui/primitives";
import { getComplianceReport } from "@/lib/api";
import { CheckCircle, ShieldAlert, FileText } from "lucide-react";

const frameworks = ["SOC2", "ISO27001", "HIPAA", "PCI-DSS"];

export default function CompliancePage() {
  const [selectedFramework, setSelectedFramework] = useState("SOC2");
  const [findings, setFindings] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    getComplianceReport(selectedFramework).then((data) => {
      setFindings(data);
      setLoading(false);
    }).catch(console.error);
  }, [selectedFramework]);

  return (
    <div style={{ display: "grid", gap: 24 }}>
      <SectionTitle
        title="COMPLIANCE MAPPING"
        subtitle="Automated mapping of vulnerabilities to regulatory frameworks"
        icon={CheckCircle}
      />

      <div style={{ display: "flex", gap: 12 }}>
        {frameworks.map((fw) => (
          <button
            key={fw}
            onClick={() => setSelectedFramework(fw)}
            style={{
              padding: "10px 20px",
              background: selectedFramework === fw ? "var(--accent-yellow)" : "#111",
              color: selectedFramework === fw ? "#000" : "#8f8f8f",
              border: "2px solid #000",
              fontWeight: 700,
              cursor: "pointer",
              transition: "0.2s"
            }}
          >
            {fw}
          </button>
        ))}
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 24 }}>
        <Panel>
          <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 16 }}>
            <ShieldAlert color="var(--accent-red)" />
            <div style={{ fontWeight: 700 }}>CRITICAL VIOLATIONS</div>
          </div>
          <div style={{ fontSize: 48, fontWeight: 900 }}>
            {findings.filter(f => f.severity === 'CRITICAL').length}
          </div>
        </Panel>
        <Panel>
          <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 16 }}>
            <FileText color="var(--accent-yellow)" />
            <div style={{ fontWeight: 700 }}>TOTAL FINDINGS</div>
          </div>
          <div style={{ fontSize: 48, fontWeight: 900 }}>{findings.length}</div>
        </Panel>
      </div>

      <Panel>
        <div style={{ overflowX: "auto" }}>
          <table className="neo-table">
            <thead>
              <tr>
                <th>FINDING</th>
                <th>SEVERITY</th>
                <th>CONTROLS VIOLATED</th>
                <th>TARGET</th>
                <th>STATUS</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={5}>MAPPING COMPLIANCE DATA...</td></tr>
              ) : findings.length === 0 ? (
                <tr><td colSpan={5}>NO VIOLATIONS FOUND FOR {selectedFramework}</td></tr>
              ) : findings.map((finding) => (
                <tr key={finding.finding_id}>
                  <td style={{ fontWeight: 700 }}>{finding.title}</td>
                  <td>
                    <span style={{ 
                      padding: "2px 6px", 
                      background: finding.severity === 'CRITICAL' ? "var(--accent-red)" : "var(--accent-yellow)",
                      color: "#000",
                      fontSize: 10,
                      fontWeight: 700
                    }}>
                      {finding.severity}
                    </span>
                  </td>
                  <td>
                    {finding.compliance_violations.filter((v: string) => v.startsWith(selectedFramework)).join(", ") || "N/A"}
                  </td>
                  <td>{finding.target}</td>
                  <td>{finding.status.toUpperCase()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>
    </div>
  );
}
