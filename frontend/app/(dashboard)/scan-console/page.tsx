"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";

import { NeoButton, Panel, SectionTitle } from "@/components/ui/primitives";
import { buildScanProgressSseUrl, cancelScan, getScanResult, getScannerAvailability, parseScanProgress, runScan } from "@/lib/api";
import { saveScanResult } from "@/lib/storage";
import { ScanProgressEvent, ScanRunResponse, ScannerAvailability, UnifiedFinding } from "@/lib/types";
import { useSse } from "@/lib/useSse";

const tools = [
  { key: "nmap", name: "Nmap", eta: "2m", updated: "native" },
  { key: "rustscan", name: "Rustscan", eta: "1m", updated: "adapter" },
  { key: "nuclei", name: "Nuclei", eta: "3m", updated: "adapter" },
  { key: "openvas", name: "OpenVAS", eta: "8m", updated: "phase2" },
  { key: "nessus", name: "Nessus", eta: "8m", updated: "phase2" },
  { key: "trivy", name: "Trivy", eta: "4m", updated: "phase2" },
  { key: "semgrep", name: "Semgrep", eta: "4m", updated: "phase2" },
  { key: "gitleaks", name: "Gitleaks", eta: "3m", updated: "phase2" },
  { key: "zap", name: "OWASP ZAP", eta: "10m", updated: "phase2" },
];

function severityColor(severity: string): string {
  if (severity === "CRITICAL") return "#FF2D2D";
  if (severity === "HIGH") return "#FF6B00";
  if (severity === "MEDIUM") return "#FFE500";
  if (severity === "LOW") return "#00FF6A";
  return "#0057FF";
}

function formatProgress(event: ScanProgressEvent | null, running: boolean): number {
  if (!event) return running ? 5 : 0;
  const total = event.scanner_total || 0;
  const index = event.scanner_index || 0;
  if (event.phase === "SCANNER_RUNNING" && total > 0) {
    return Math.min(95, Math.max(10, Math.round(((index - 1) / total) * 80 + 10)));
  }
  if (event.phase === "SCANNER_COMPLETE" && total > 0) {
    return Math.min(95, Math.max(10, Math.round((index / total) * 85)));
  }
  if (event.phase === "NORMALIZING") return 90;
  if (event.phase === "COMPLETE" || event.phase === "FAILED" || event.phase === "CANCELLED") return 100;
  return running ? 10 : 0;
}

export default function ScanConsolePage() {
  const router = useRouter();
  const [target, setTarget] = useState("");
  const [selected, setSelected] = useState<string[]>(["nmap"]);
  const [availability, setAvailability] = useState<Record<string, ScannerAvailability>>({});
  const [profile, setProfile] = useState("standard");
  const [tab, setTab] = useState<"progress" | "unified" | "detailed">("progress");
  const [running, setRunning] = useState(false);
  const [scanId, setScanId] = useState("");
  const [result, setResult] = useState<ScanRunResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [queued, setQueued] = useState(false);
  const [startedAt, setStartedAt] = useState<number | null>(null);
  const [pollAttempts, setPollAttempts] = useState(0);
  const [statusHint, setStatusHint] = useState<string>("Idle");
  const [nowTick, setNowTick] = useState(Date.now());

  const ACTIVE_SCAN_KEY = "emet.activeScan";

  const valid = useMemo(
    () => 
      /^(https?:\/\/)?([\w.-]+)(:\d+)?(\/.*)?$/.test(target) || 
      /^(\d{1,3}\.){3}\d{1,3}$/.test(target) ||
      target.startsWith("repo:") ||
      target.startsWith("file://"),
    [target],
  );

  const isRepoToolSelected = useMemo(
    () => selected.some(s => ["trivy", "semgrep", "gitleaks"].includes(s)),
    [selected]
  );

  const sseUrl = scanId ? buildScanProgressSseUrl(scanId) : "";
  const { connected, messages } = useSse(sseUrl);
  const progressEvents = useMemo(
    () => messages.map(parseScanProgress).filter((item): item is ScanProgressEvent => Boolean(item)),
    [messages],
  );
  const latestEvent = progressEvents.length ? progressEvents[progressEvents.length - 1] : null;
  const progressValue = formatProgress(latestEvent, running || queued);
  const active = running || queued;

  useEffect(() => {
    if (!active) return;
    const timer = window.setInterval(() => setNowTick(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [active]);

  const elapsedSeconds = startedAt ? Math.max(0, Math.floor((nowTick - startedAt) / 1000)) : 0;
  const lastUpdateAgeSeconds = latestEvent?.timestamp
    ? Math.max(0, Math.floor((nowTick - new Date(latestEvent.timestamp).getTime()) / 1000))
    : null;

  const scannerState = useMemo(() => {
    const map = new Map<string, { status: string; detail: string }>();
    for (const scanner of selected) {
      map.set(scanner, { status: "PENDING", detail: "waiting" });
    }
    for (const row of result?.scanner_runs || []) {
      if (row.scanner === "pipeline") continue;
      map.set(row.scanner, {
        status: row.status.toUpperCase(),
        detail: row.error || `${row.findings_count || 0} findings`,
      });
    }
    if (latestEvent?.scanner && map.has(latestEvent.scanner) && latestEvent.phase === "SCANNER_RUNNING") {
      map.set(latestEvent.scanner, { status: "RUNNING", detail: latestEvent.message || "scanner active" });
    }
    return Array.from(map.entries());
  }, [selected, result?.scanner_runs, latestEvent]);

  const lifecycle = useMemo(() => {
    if (result?.status) return result.status.toUpperCase();
    if (latestEvent?.phase) return latestEvent.phase;
    if (queued) return "QUEUED";
    if (running) return "INITIALIZING";
    return "IDLE";
  }, [result?.status, latestEvent?.phase, queued, running]);

  const fetchFinalResult = useCallback(async (id: string) => {
    try {
      for (let attempt = 0; attempt < 120; attempt += 1) {
        setPollAttempts(attempt + 1);
        const data = await getScanResult(id);
        setStatusHint(`Job status: ${data.status.toUpperCase()}`);
        if (data.status === "complete") {
          setResult(data);
          await saveScanResult(data);
          localStorage.removeItem(ACTIVE_SCAN_KEY);
          setTab("unified");
          setQueued(false);
          setRunning(false);
          return;
        }
        if (data.status === "failed") {
          setError("Scan job failed. Check scanner run details in progress logs.");
          setResult(data);
          localStorage.removeItem(ACTIVE_SCAN_KEY);
          setQueued(false);
          setRunning(false);
          return;
        }
        if (data.status === "cancelled") {
          setError("Scan was cancelled.");
          setResult(data);
          localStorage.removeItem(ACTIVE_SCAN_KEY);
          setQueued(false);
          setRunning(false);
          return;
        }
        await new Promise((resolve) => setTimeout(resolve, connected ? 1000 : 2000));
      }
      setError("Timed out waiting for scan completion.");
      localStorage.removeItem(ACTIVE_SCAN_KEY);
      setQueued(false);
      setRunning(false);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to fetch scan result");
      localStorage.removeItem(ACTIVE_SCAN_KEY);
      setQueued(false);
      setRunning(false);
    }
  }, [connected]);

  const startScan = async () => {
    if (!valid || selected.length === 0 || running || queued) {
      return;
    }
    setError(null);
    setResult(null);
    setRunning(true);
    setQueued(false);
    setStartedAt(Date.now());
    setPollAttempts(0);
    setStatusHint("Submitting job to queue");
    setTab("progress");

    try {
      const response = await runScan(target, selected, profile);
      setScanId(response.scan_id);
      setQueued(true);
      localStorage.setItem(
        ACTIVE_SCAN_KEY,
        JSON.stringify({
          scanId: response.scan_id,
          target,
          selected,
          profile,
          startedAt: Date.now(),
          tab: "progress",
        }),
      );
      setStatusHint(`Queued as ${response.scan_id}`);
      void fetchFinalResult(response.scan_id);
    } catch (err) {
      const message = err instanceof Error ? err.message : "Scan execution failed";
      if (message.includes("401") && message.includes("Missing access token")) {
        setError("Session missing. Please login first.");
        setQueued(false);
        setRunning(false);
        router.push("/login");
        return;
      }
      if (message.includes("403") && message.includes("Insufficient scope")) {
        setError("Guest mode is read-only. Login as analyst@emet.local to run scans.");
        setQueued(false);
        setRunning(false);
        return;
      }
      setError(message);
      setQueued(false);
      setRunning(false);
    }
  };

  const findings: UnifiedFinding[] = result?.findings || [];

  useEffect(() => {
    let cancelled = false;
    void getScannerAvailability()
      .then((items) => {
        if (cancelled) return;
        const mapped: Record<string, ScannerAvailability> = {};
        for (const item of items) {
          mapped[item.scanner] = item;
        }
        setAvailability(mapped);
        if (!mapped["nmap"]?.available) {
          setSelected([]);
        }
      })
      .catch(() => {
        if (!cancelled) setAvailability({});
      });
    return () => {
      cancelled = true;
    };
  }, [fetchFinalResult]);

  useEffect(() => {
    if (!scanId || !active) return;
    localStorage.setItem(
      ACTIVE_SCAN_KEY,
      JSON.stringify({
        scanId,
        target,
        selected,
        profile,
        startedAt,
        tab,
      }),
    );
  }, [scanId, active, target, selected, profile, startedAt, tab]);

  useEffect(() => {
    const raw = localStorage.getItem(ACTIVE_SCAN_KEY);
    if (!raw) return;
    try {
      const parsed = JSON.parse(raw) as {
        scanId: string;
        target: string;
        selected: string[];
        profile: string;
        startedAt: number;
        tab?: "progress" | "unified" | "detailed";
      };
      if (!parsed.scanId) return;
      setScanId(parsed.scanId);
      setTarget(parsed.target || "");
      setSelected(Array.isArray(parsed.selected) && parsed.selected.length ? parsed.selected : ["nmap"]);
      setProfile(parsed.profile || "standard");
      setStartedAt(parsed.startedAt || Date.now());
      setTab(parsed.tab || "progress");
      setRunning(true);
      setQueued(true);
      setStatusHint(`Resumed active scan ${parsed.scanId}`);
      void fetchFinalResult(parsed.scanId);
    } catch {
      localStorage.removeItem(ACTIVE_SCAN_KEY);
    }
  }, [fetchFinalResult]);

  return (
    <div style={{ display: "grid", gap: 14 }}>
      <SectionTitle>Scan Orchestration</SectionTitle>
      <div style={{ display: "grid", gridTemplateColumns: "55% 45%", gap: 12, minWidth: 0 }}>
        <Panel>
          <div style={{ padding: 16 }}>
            <h3 className="page-title">NEW SCAN JOB</h3>

            <div style={{ marginTop: 12 }}>
              <p style={{ margin: "0 0 6px", fontWeight: 800, letterSpacing: "0.06em" }}>TARGET URL / IP ADDRESS / REPO PATH</p>
              <div style={{ display: "grid", gridTemplateColumns: "1fr auto", gap: 10 }}>
                <input
                  value={target}
                  placeholder={isRepoToolSelected ? "repo:/path/to/project" : "https://example.com or 1.2.3.4"}
                  onChange={(event) => setTarget(event.target.value)}
                  style={{ border: "3px solid #000", boxShadow: "var(--shadow)", padding: 12, fontFamily: "inherit", fontSize: 16 }}
                />
                <div style={{ border: "3px solid #000", boxShadow: "var(--shadow)", width: 52, display: "grid", placeItems: "center", fontWeight: 800 }}>
                  {target ? (valid ? "OK" : "NO") : "--"}
                </div>
              </div>
              {isRepoToolSelected && (
                <p style={{ margin: "8px 0 0", fontSize: 11, fontWeight: 900, color: "var(--accent-blue)" }}>
                  💡 REPOSITORY SCANNING ACTIVE: Target must start with 'repo:' or 'file://' (e.g. repo:/app)
                </p>
              )}
              <p style={{ margin: "8px 0 0", fontSize: 11, fontWeight: 700 }}>
                AUTHORIZATION REQUIRED: Scan only approved assets. Private/internal ranges are blocked by default.
              </p>
            </div>

            <div style={{ marginTop: 14 }}>
              <p style={{ margin: "0 0 8px", fontWeight: 800, letterSpacing: "0.06em" }}>SELECT SCANNERS</p>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
                {tools.map((tool) => {
                  const active = selected.includes(tool.key);
                  const info = availability[tool.key];
                  const disabled = info ? !info.available : false;
                  return (
                    <label key={tool.key} style={{ border: "2px solid #000", padding: 8, display: "grid", gap: 6, background: disabled ? "#f3f3f3" : active ? "#fff4a3" : "#fff", opacity: disabled ? 0.65 : 1 }}>
                      <span style={{ display: "flex", alignItems: "center", gap: 8, fontWeight: 700 }}>
                        <input
                          type="checkbox"
                          style={{ width: 16, height: 16, border: "2px solid #000", borderRadius: 0, appearance: "none", background: active ? "#FFE500" : "#FFFFFF", margin: 0 }}
                          checked={active}
                          disabled={disabled}
                          onChange={() => {
                            if (disabled) return;
                            setSelected((prev) => (prev.includes(tool.key) ? prev.filter((x) => x !== tool.key) : [...prev, tool.key]));
                          }}
                        />
                        {tool.name}
                      </span>
                      <span style={{ fontSize: 11 }}>
                        ETA {tool.eta} | {tool.updated.toUpperCase()} {disabled && info?.reason ? `| ${info.reason.toUpperCase()}` : ""}
                      </span>
                    </label>
                  );
                })}
              </div>
            </div>

            <div style={{ marginTop: 14 }}>
              <p style={{ margin: "0 0 8px", fontWeight: 800, letterSpacing: "0.06em" }}>SCAN PROFILE</p>
              <div style={{ display: "flex", gap: 12 }}>
                {[
                  ["quick", "QUICK"],
                  ["standard", "STANDARD"],
                  ["deep", "DEEP"],
                ].map((item) => (
                  <label key={item[0]} style={{ border: "2px solid #000", padding: "8px 10px", background: profile === item[0] ? "var(--accent-yellow)" : "#fff", fontWeight: 700 }}>
                    <input type="radio" name="profile" checked={profile === item[0]} onChange={() => setProfile(item[0])} /> {item[1]}
                  </label>
                ))}
              </div>
            </div>

            <div style={{ display: "grid", gap: 8, marginTop: 16 }}>
              <NeoButton
                onClick={() => {
                  void startScan();
                }}
                disabled={!valid || selected.length === 0 || running || queued}
                style={{ width: "100%", background: running || queued ? "#FF2D2D" : "#000", color: running || queued ? "#FFFFFF" : "var(--accent-yellow)", padding: "14px 16px", transition: "none" }}
              >
                {queued ? "QUEUED..." : running ? "RUNNING..." : "START SCAN"}
              </NeoButton>
              {active ? (
                <div style={{ border: "2px solid #000", padding: 8, fontSize: 12, fontWeight: 700, background: "#f9f9f9" }}>
                  STATE: {lifecycle} | ELAPSED: {elapsedSeconds}s | POLL: {pollAttempts}
                  <br />
                  {statusHint}
                </div>
              ) : null}
              {scanId && (running || queued) ? (
                <NeoButton
                  onClick={() => {
                    void cancelScan(scanId).catch(() => {
                      setError("Failed to cancel scan job.");
                    });
                    localStorage.removeItem(ACTIVE_SCAN_KEY);
                  }}
                  style={{ width: "100%", background: "#fff", color: "#000", padding: "12px 16px" }}
                >
                  CANCEL JOB
                </NeoButton>
              ) : null}
            </div>

            {error ? <p style={{ color: "var(--accent-red)", fontWeight: 700, marginTop: 10 }}>{error}</p> : null}
          </div>
        </Panel>

        <Panel>
          <div style={{ display: "flex", borderBottom: "2px solid #000", margin: 0 }}>
            {[
              ["progress", "LIVE PROGRESS"],
              ["unified", "UNIFIED REPORT"],
              ["detailed", "DETAILED FINDINGS"],
            ].map((entry) => (
              <button
                key={entry[0]}
                onClick={() => setTab(entry[0] as typeof tab)}
                className={`tab-trigger ${tab === entry[0] ? "tab-trigger-active" : ""}`}
                style={{ flex: 1, cursor: "pointer" }}
              >
                {entry[1]}
              </button>
            ))}
          </div>

          <div style={{ padding: 14, minHeight: 600 }}>
            {tab === "progress" && (
              <div>
                <div style={{ marginBottom: 10, border: "2px solid #000", padding: 8 }}>
                  <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 6, fontWeight: 700 }}>
                    <span>PIPELINE ({lifecycle})</span>
                    <span>{progressValue}%</span>
                  </div>
                  <div style={{ height: 14, border: "2px solid #000", background: "#fff" }}>
                    <div style={{ width: `${Math.max(0, Math.min(100, progressValue))}%`, background: "var(--accent-yellow)", height: "100%" }} />
                  </div>
                  <div style={{ fontSize: 11, marginTop: 6, fontWeight: 700 }}>
                    STATUS: {latestEvent?.phase || (running ? "INITIALIZING" : "IDLE")}
                  </div>
                  <div style={{ fontSize: 11, marginTop: 6, fontWeight: 700 }}>
                    STREAM: {scanId ? (connected ? "LIVE" : "RECONNECTING (POLL FALLBACK ACTIVE)") : "NOT STARTED"}
                    {lastUpdateAgeSeconds !== null ? ` | LAST UPDATE ${lastUpdateAgeSeconds}s AGO` : ""}
                  </div>
                  {latestEvent?.scanner ? (
                    <div style={{ fontSize: 11, marginTop: 6, fontWeight: 700 }}>
                      CURRENT SCANNER: {latestEvent.scanner.toUpperCase()} {latestEvent.status ? `(${latestEvent.status})` : ""}
                    </div>
                  ) : null}
                  {latestEvent?.phase === "SCANNER_COMPLETE" && latestEvent.status && latestEvent.status !== "success" ? (
                    <div style={{ fontSize: 11, marginTop: 6, fontWeight: 700, color: "var(--accent-red)" }}>
                      FAILURE STATE: {latestEvent.message || "Scanner run did not succeed."}
                    </div>
                  ) : null}
                </div>
                <div style={{ marginBottom: 10, border: "2px solid #000", padding: 8 }}>
                  <strong>SCANNER EXECUTION BOARD</strong>
                  <div style={{ display: "grid", gridTemplateColumns: "repeat(2, minmax(0, 1fr))", gap: 8, marginTop: 8 }}>
                    {scannerState.map(([scanner, meta]) => (
                      <div key={scanner} style={{ border: "2px solid #000", padding: 8, background: meta.status === "FAILED" ? "#ffd7d7" : meta.status === "RUNNING" ? "#fff4a3" : meta.status === "SUCCESS" ? "#d8ffd8" : "#fff" }}>
                        <div style={{ fontWeight: 800 }}>{scanner.toUpperCase()}</div>
                        <div style={{ fontSize: 11 }}>{meta.status}</div>
                        <div style={{ fontSize: 11 }}>{meta.detail}</div>
                      </div>
                    ))}
                  </div>
                </div>
                <div className="code-log" style={{ border: "2px solid #000", minHeight: 220, padding: 10 }}>
                  [SSE] {scanId ? (connected ? "CONNECTED" : "DISCONNECTED") : "NOT STARTED"}
                  <br />
                  {progressEvents.slice(-20).map((event, idx) => (
                    <span key={`${idx}-${event.phase}`}>
                      [LOG] {event.phase} :: {event.message || "update"}
                      <br />
                    </span>
                  ))}
                </div>
                {result?.scanner_runs?.length ? (
                  <div style={{ marginTop: 10, border: "2px solid #000", padding: 8 }}>
                    <strong>SCANNER RUN SUMMARY</strong>
                    {result.scanner_runs
                      .filter((item) => item.scanner !== "pipeline")
                      .map((item) => (
                        <div key={`${item.scanner}-${item.status}`} style={{ borderTop: "2px solid #000", padding: "8px 0", fontSize: 12 }}>
                          {item.scanner.toUpperCase()} :: {item.status.toUpperCase()} {item.error ? `- ${item.error}` : ""}
                        </div>
                      ))}
                  </div>
                ) : null}
              </div>
            )}

            {tab === "unified" && (
              <div style={{ display: "grid", gap: 10 }}>
                <h4 style={{ fontSize: 26 }}>Executive Summary</h4>
                <p style={{ margin: 0 }}>{result?.unified_report?.executive_summary || "No report available yet."}</p>
                <h4 style={{ fontSize: 26 }}>Key Findings</h4>
                <ul>
                  {(result?.unified_report?.key_findings || []).map((item) => (
                    <li key={item}>{item}</li>
                  ))}
                </ul>
                <h4 style={{ fontSize: 26 }}>Defensive Exposure Assessment</h4>
                <p style={{ margin: 0 }}>{result?.zero_day?.narrative || "No exposure assessment yet."}</p>
                <h4 style={{ fontSize: 26 }}>Recommended Actions</h4>
                <ol>
                  {(result?.unified_report?.recommended_actions || []).map((item) => (
                    <li key={item}>{item}</li>
                  ))}
                </ol>
              </div>
            )}

            {tab === "detailed" && (
              <div style={{ border: "2px solid #000" }}>
                <div style={{ display: "grid", gridTemplateColumns: "130px 110px 120px 1fr 160px", fontWeight: 800, borderBottom: "2px solid #000", background: "#f2f2f2" }}>
                  {["CVE ID", "SEVERITY", "TOOL", "DESCRIPTION", "COMPONENT"].map((head) => (
                    <div key={head} style={{ padding: 8, borderRight: "2px solid #000", fontSize: 11 }}>{head}</div>
                  ))}
                </div>
                {findings.map((row) => (
                  <div key={`${row.finding_id || row.cve_id || row.title}-${row.port || 0}`} style={{ display: "grid", gridTemplateColumns: "130px 110px 120px 1fr 160px", borderBottom: "2px solid #000" }}>
                    {[row.cve_id || "UNCLASSIFIED", row.severity, row.scanner_source.toUpperCase(), row.description, row.affected_component].map((cell, idx) => (
                      <div
                        key={`${cell}-${idx}`}
                        style={{
                          padding: 8,
                          borderRight: "2px solid #000",
                          fontSize: 12,
                          background: idx === 1 ? severityColor(String(cell)) : "#FFFFFF",
                        }}
                      >
                        {cell}
                      </div>
                    ))}
                  </div>
                ))}
              </div>
            )}
          </div>
        </Panel>
      </div>
    </div>
  );
}
