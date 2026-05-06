"use client";

import { useEffect, useState } from "react";
import { Panel, SectionTitle } from "@/components/ui/primitives";
import { getAgents } from "@/lib/api";
import { Server, Activity, ShieldCheck } from "lucide-react";

export default function AgentsPage() {
  const [agents, setAgents] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getAgents().then((data) => {
      setAgents(data);
      setLoading(false);
    }).catch(console.error);
  }, []);

  return (
    <div style={{ display: "grid", gap: 24 }}>
      <SectionTitle
        title="AGENT-BASED ORCHESTRATION"
        subtitle="Manage persistent agents for deep internal inspection"
        icon={Server}
      />

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))", gap: 16 }}>
        <Panel style={{ display: "flex", gap: 16, alignItems: "center" }}>
          <div style={{ background: "var(--accent-yellow)", padding: 12, color: "#000" }}>
            <Activity size={24} />
          </div>
          <div>
            <div style={{ fontSize: 10, color: "#8f8f8f", fontWeight: 700 }}>ACTIVE AGENTS</div>
            <div style={{ fontSize: 24, fontWeight: 900 }}>{agents.filter(a => a.status === 'online').length}</div>
          </div>
        </Panel>
        <Panel style={{ display: "flex", gap: 16, alignItems: "center" }}>
          <div style={{ background: "#222", padding: 12, color: "var(--accent-yellow)" }}>
            <ShieldCheck size={24} />
          </div>
          <div>
            <div style={{ fontSize: 10, color: "#8f8f8f", fontWeight: 700 }}>TOTAL REGISTERED</div>
            <div style={{ fontSize: 24, fontWeight: 900 }}>{agents.length}</div>
          </div>
        </Panel>
      </div>

      <Panel>
        <div style={{ overflowX: "auto" }}>
          <table className="neo-table">
            <thead>
              <tr>
                <th>AGENT ID</th>
                <th>NAME</th>
                <th>IP ADDRESS</th>
                <th>STATUS</th>
                <th>LAST HEARTBEAT</th>
                <th>VERSION</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={6}>LOADING AGENTS...</td></tr>
              ) : agents.length === 0 ? (
                <tr><td colSpan={6}>NO AGENTS REGISTERED</td></tr>
              ) : agents.map((agent) => (
                <tr key={agent.id}>
                  <td style={{ fontWeight: 700, fontSize: 11 }}>{agent.id}</td>
                  <td>{agent.name}</td>
                  <td>{agent.ip_address}</td>
                  <td>
                    <span style={{ 
                      padding: "2px 6px", 
                      background: agent.status === 'online' ? "var(--accent-green)" : "#333",
                      color: agent.status === 'online' ? "#000" : "#8f8f8f",
                      fontSize: 10,
                      fontWeight: 700
                    }}>
                      {agent.status.toUpperCase()}
                    </span>
                  </td>
                  <td>{new Date(agent.last_heartbeat).toLocaleString()}</td>
                  <td>{agent.version}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>
    </div>
  );
}
