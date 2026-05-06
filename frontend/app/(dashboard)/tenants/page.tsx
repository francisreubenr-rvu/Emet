"use client";

import { useEffect, useState } from "react";
import { Panel, SectionTitle, NeoButton } from "@/components/ui/primitives";
import { listTenants, createTenant } from "@/lib/api";
import { Users, Plus, Globe } from "lucide-react";

export default function TenantsPage() {
  const [tenants, setTenants] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [showAdd, setShowAdd] = useState(false);
  const [name, setName] = useState("");
  const [domain, setDomain] = useState("");

  const loadTenants = () => {
    setLoading(true);
    listTenants().then((data) => {
      setTenants(data);
      setLoading(false);
    }).catch(console.error);
  };

  useEffect(() => {
    loadTenants();
  }, []);

  const handleCreate = async () => {
    if (!name) return;
    try {
      await createTenant(name, domain);
      setName("");
      setDomain("");
      setShowAdd(false);
      loadTenants();
    } catch (err) {
      console.error(err);
    }
  };

  return (
    <div style={{ display: "grid", gap: 24 }}>
      <SectionTitle
        title="TENANT MANAGEMENT"
        subtitle="Manage multi-tenant isolation and organizational units"
        icon={Users}
      />

      <Panel>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 24 }}>
          <div style={{ fontWeight: 700, fontSize: 14 }}>ACTIVE TENANTS / ORGANIZATIONS</div>
          <NeoButton onClick={() => setShowAdd(!showAdd)}>
            <Plus size={16} style={{ marginRight: 6 }} />
            NEW TENANT
          </NeoButton>
        </div>

        {showAdd && (
          <div style={{ border: "2px solid var(--accent-yellow)", padding: 16, marginBottom: 24, background: "#111", display: "grid", gap: 12 }}>
            <div style={{ fontWeight: 700, fontSize: 12 }}>CREATE NEW TENANT</div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
              <input 
                placeholder="TENANT NAME (e.g. Acme Corp)" 
                value={name}
                onChange={e => setName(e.target.value)}
                style={{ background: "#000", border: "1px solid #333", color: "#fff", padding: 8 }}
              />
              <input 
                placeholder="DOMAIN (e.g. acme.com)" 
                value={domain}
                onChange={e => setDomain(e.target.value)}
                style={{ background: "#000", border: "1px solid #333", color: "#fff", padding: 8 }}
              />
            </div>
            <div style={{ display: "flex", gap: 8 }}>
              <NeoButton onClick={handleCreate} size="sm">CREATE</NeoButton>
              <NeoButton onClick={() => setShowAdd(false)} size="sm" variant="outline">CANCEL</NeoButton>
            </div>
          </div>
        )}

        <div style={{ overflowX: "auto" }}>
          <table className="neo-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>NAME</th>
                <th>DOMAIN</th>
                <th>STATUS</th>
                <th>CREATED AT</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={5}>FETCHING TENANT LIST...</td></tr>
              ) : tenants.length === 0 ? (
                <tr><td colSpan={5}>NO TENANTS CONFIGURED</td></tr>
              ) : tenants.map((tenant) => (
                <tr key={tenant.id}>
                  <td style={{ fontWeight: 700 }}>#{tenant.id}</td>
                  <td style={{ fontWeight: 700 }}>{tenant.name}</td>
                  <td>
                    <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                      <Globe size={14} color="#8f8f8f" />
                      {tenant.domain || 'N/A'}
                    </div>
                  </td>
                  <td>
                    <span style={{ 
                      padding: "2px 6px", 
                      background: tenant.active ? "var(--accent-green)" : "var(--accent-red)",
                      color: "#000",
                      fontSize: 10,
                      fontWeight: 700
                    }}>
                      {tenant.active ? "ACTIVE" : "INACTIVE"}
                    </span>
                  </td>
                  <td>{new Date(tenant.created_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>
    </div>
  );
}
