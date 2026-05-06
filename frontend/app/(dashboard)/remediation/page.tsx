"use client";

import { useEffect, useState } from "react";
import { Panel, SectionTitle, NeoButton } from "@/components/ui/primitives";
import { getTickets, syncTicket } from "@/lib/api";
import { Ticket, RefreshCw, ExternalLink } from "lucide-react";

export default function RemediationPage() {
  const [tickets, setTickets] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  const loadTickets = () => {
    setLoading(true);
    getTickets().then((data) => {
      setTickets(data);
      setLoading(false);
    }).catch(console.error);
  };

  useEffect(() => {
    loadTickets();
  }, []);

  const handleSync = async (id: number) => {
    try {
      await syncTicket(id);
      loadTickets();
    } catch (err) {
      console.error(err);
    }
  };

  return (
    <div style={{ display: "grid", gap: 24 }}>
      <SectionTitle
        title="REMEDIATION ORCHESTRATION"
        subtitle="Bidirectional sync with enterprise ticketing systems"
        icon={Ticket}
      />

      <Panel>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
          <div style={{ fontWeight: 700, fontSize: 14 }}>ACTIVE REMEDIATION TICKETS</div>
          <NeoButton onClick={loadTickets} size="sm">
            <RefreshCw size={14} style={{ marginRight: 6 }} />
            REFRESH
          </NeoButton>
        </div>

        <div style={{ overflowX: "auto" }}>
          <table className="neo-table">
            <thead>
              <tr>
                <th>TICKET ID</th>
                <th>EXTERNAL ID</th>
                <th>SYSTEM</th>
                <th>SUMMARY</th>
                <th>STATUS</th>
                <th>LAST SYNC</th>
                <th>ACTIONS</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={7}>LOADING TICKETS...</td></tr>
              ) : tickets.length === 0 ? (
                <tr><td colSpan={7}>NO ACTIVE TICKETS</td></tr>
              ) : tickets.map((ticket) => (
                <tr key={ticket.id}>
                  <td style={{ fontWeight: 700 }}>#{ticket.id}</td>
                  <td style={{ color: "var(--accent-yellow)", fontWeight: 700 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 4 }}>
                      {ticket.external_id}
                      <ExternalLink size={12} />
                    </div>
                  </td>
                  <td>{ticket.external_system.toUpperCase()}</td>
                  <td style={{ maxWidth: 300, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {ticket.summary}
                  </td>
                  <td>
                    <span style={{ 
                      padding: "2px 6px", 
                      background: ticket.status === 'closed' ? "var(--accent-green)" : "#333",
                      color: ticket.status === 'closed' ? "#000" : "#fff",
                      fontSize: 10,
                      fontWeight: 700
                    }}>
                      {ticket.status.toUpperCase()}
                    </span>
                  </td>
                  <td>{ticket.last_sync_at ? new Date(ticket.last_sync_at).toLocaleString() : 'NEVER'}</td>
                  <td>
                    <NeoButton onClick={() => handleSync(ticket.id)} size="sm" variant="outline">
                      SYNC
                    </NeoButton>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>
    </div>
  );
}
