"use client";

import { useEffect, useState } from "react";

import { NeoButton, Panel, SectionTitle } from "@/components/ui/primitives";
import {
  createGithubIssue,
  createJiraIssue,
  createSchedule,
  deleteSchedule,
  getDatasetHistory,
  getDatasetStatus,
  getSchedules,
  listAlerts,
  runScheduleNow,
  updateSchedule,
} from "@/lib/api";
import { AlertEventRecord, DatasetHistoryRow, DatasetStatusRow, ScheduledScan } from "@/lib/types";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

async function authed<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    ...init,
    credentials: "include",
    headers: { "Content-Type": "application/json", ...(init?.headers || {}) },
    cache: "no-store",
  });
  if (!response.ok) throw new Error(`API ${response.status}: ${await response.text()}`);
  return response.json() as Promise<T>;
}

export default function SettingsPage() {
  const [allowInternal, setAllowInternal] = useState(false);
  const [statusText, setStatusText] = useState<string>("Not saved");
  const [datasetStatus, setDatasetStatus] = useState<DatasetStatusRow[]>([]);
  const [datasetHistory, setDatasetHistory] = useState<DatasetHistoryRow[]>([]);
  const [schedules, setSchedules] = useState<ScheduledScan[]>([]);
  const [alerts, setAlerts] = useState<AlertEventRecord[]>([]);

  useEffect(() => {
    void authed<Record<string, unknown>>("/api/settings")
      .then((settings) => setAllowInternal(Boolean(settings["allow_internal_scanning"])))
      .catch(() => {
        setAllowInternal(false);
      });

    void getDatasetStatus().then(setDatasetStatus).catch(() => setDatasetStatus([]));
    void getDatasetHistory().then(setDatasetHistory).catch(() => setDatasetHistory([]));
    void getSchedules().then(setSchedules).catch(() => setSchedules([]));
    void listAlerts().then(setAlerts).catch(() => setAlerts([]));
  }, []);

  return (
    <div style={{ display: "grid", gap: 12 }}>
      <SectionTitle>Settings</SectionTitle>

      <Panel>
        <div style={{ padding: 12, display: "grid", gap: 10 }}>
          <h3 style={{ fontSize: 28 }}>Scan Safety</h3>
          <label style={{ display: "flex", alignItems: "center", gap: 8, fontWeight: 700 }}>
            <input type="checkbox" checked={allowInternal} onChange={(event) => setAllowInternal(event.target.checked)} />
            ALLOW CONTROLLED INTERNAL SCANNING
          </label>
          <p style={{ margin: 0, fontSize: 12 }}>
            Default should stay disabled. Enabling this requires explicit authorization for internal/private ranges.
          </p>
          <NeoButton
            style={{ width: 220, background: "#000", color: "var(--accent-yellow)" }}
            onClick={() => {
              void authed("/api/settings", {
                method: "PUT",
                body: JSON.stringify({ allow_internal_scanning: allowInternal }),
              })
                .then(() => setStatusText("Saved"))
                .catch(() => setStatusText("Save failed"));
            }}
          >
            SAVE SETTINGS
          </NeoButton>
          <p style={{ margin: 0, fontWeight: 700 }}>{statusText.toUpperCase()}</p>
        </div>
      </Panel>

      <Panel>
        <div style={{ padding: 12, display: "grid", gap: 10 }}>
          <h3 style={{ fontSize: 28 }}>Scheduled Scans</h3>
          <NeoButton
            style={{ width: 240, background: "#000", color: "var(--accent-yellow)" }}
            onClick={() => {
              void createSchedule({
                name: "Daily perimeter check",
                target: "example.com",
                profile: "quick",
                scanners: ["nmap"],
                recurrence: "daily",
              })
                .then(() => getSchedules().then(setSchedules))
                .catch(() => setStatusText("Schedule create failed"));
            }}
          >
            CREATE SAMPLE SCHEDULE
          </NeoButton>
          {schedules.slice(0, 6).map((item) => (
            <div key={item.id} style={{ border: "2px solid #000", padding: 8, fontSize: 12 }}>
              <strong>{item.name}</strong> • {item.recurrence} • next: {new Date(item.next_run_at).toLocaleString()}
              <div style={{ marginTop: 6, display: "flex", gap: 6, flexWrap: "wrap" }}>
                <NeoButton
                  style={{ background: "#fff", color: "#000", padding: "4px 8px" }}
                  onClick={() => {
                    void runScheduleNow(item.id)
                      .then(() => setStatusText("Schedule queued"))
                      .catch(() => setStatusText("Run now failed"));
                  }}
                >
                  RUN NOW
                </NeoButton>
                <NeoButton
                  style={{ background: "#fff", color: "#000", padding: "4px 8px" }}
                  onClick={() => {
                    void updateSchedule(item.id, {
                      name: item.name,
                      profile: item.profile,
                      scanners: item.scanners,
                      recurrence: item.recurrence,
                      cron_expr: item.cron_expr,
                      enabled: !item.enabled,
                    })
                      .then(() => getSchedules().then(setSchedules))
                      .catch(() => setStatusText("Toggle failed"));
                  }}
                >
                  {item.enabled ? "DISABLE" : "ENABLE"}
                </NeoButton>
                <NeoButton
                  style={{ background: "#fff", color: "#000", padding: "4px 8px" }}
                  onClick={() => {
                    void deleteSchedule(item.id)
                      .then(() => getSchedules().then(setSchedules))
                      .catch(() => setStatusText("Delete failed"));
                  }}
                >
                  DELETE
                </NeoButton>
              </div>
            </div>
          ))}
        </div>
      </Panel>

      <Panel>
        <div style={{ padding: 12, display: "grid", gap: 10 }}>
          <h3 style={{ fontSize: 28 }}>Alerts</h3>
          {alerts.slice(0, 8).map((item) => (
            <div key={item.id} style={{ border: "2px solid #000", padding: 8, fontSize: 12 }}>
              <strong>{item.event_type}</strong> [{item.severity}] • {new Date(item.created_at).toLocaleString()}
            </div>
          ))}
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            <NeoButton
              style={{ background: "#000", color: "var(--accent-yellow)", padding: "6px 10px" }}
              onClick={() => {
                void createGithubIssue("[EMET] Defensive finding", "Create GitHub issue from settings panel")
                  .then((res) => setStatusText(res.ok ? "GitHub issue created" : `GitHub not configured: ${res.reference}`))
                  .catch(() => setStatusText("GitHub issue failed"));
              }}
            >
              CREATE GITHUB ISSUE
            </NeoButton>
            <NeoButton
              style={{ background: "#000", color: "var(--accent-yellow)", padding: "6px 10px" }}
              onClick={() => {
                void createJiraIssue("EMET Defensive finding", "Create Jira issue from settings panel")
                  .then((res) => setStatusText(res.ok ? "Jira issue created" : `Jira not configured: ${res.reference}`))
                  .catch(() => setStatusText("Jira issue failed"));
              }}
            >
              CREATE JIRA ISSUE
            </NeoButton>
          </div>
          {alerts.length === 0 ? <p style={{ margin: 0, fontSize: 12 }}>No alerts yet.</p> : null}
        </div>
      </Panel>

      <Panel>
        <div style={{ padding: 12 }}>
          <h3 style={{ fontSize: 28 }}>RAG Pipeline</h3>
          <p>Knowledge ingestion and provider configuration are available through backend APIs.</p>
          <div style={{ marginTop: 12, display: "grid", gap: 8 }}>
            <h4 style={{ margin: 0 }}>Dataset Status</h4>
            {datasetStatus.map((item) => (
              <div key={item.name} style={{ display: "flex", justifyContent: "space-between", border: "2px solid #000", padding: 8 }}>
                <span>{item.name}</span>
                <span>{item.status} ({item.size})</span>
              </div>
            ))}
          </div>
          <div style={{ marginTop: 12, display: "grid", gap: 8 }}>
            <h4 style={{ margin: 0 }}>Ingest History</h4>
            {datasetHistory.slice(0, 8).map((item) => (
              <div key={item.id} style={{ border: "2px solid #000", padding: 8, fontSize: 12 }}>
                <div><strong>{item.event_type}</strong> • {new Date(item.created_at).toLocaleString()}</div>
                <div>actor: {item.actor}</div>
                <div>details: {JSON.stringify(item.details)}</div>
              </div>
            ))}
          </div>
        </div>
      </Panel>
    </div>
  );
}
