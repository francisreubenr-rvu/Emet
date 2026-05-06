"use client";

import { useEffect, useState } from "react";
import {
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import { NeoButton, Panel, SectionTitle } from "@/components/ui/primitives";

type EvalRun = {
  run_id: string;
  run_type: string;
  model_name: string;
  metrics: { f1: number; bleu4: number; rougeL: number; accuracy: number };
  metadata: Record<string, unknown>;
  created_at: string;
};

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

export default function EvaluationPage() {
  const [runs, setRuns] = useState<EvalRun[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true);
    try {
      setRuns(await authed<EvalRun[]>("/api/eval/runs"));
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load evaluation runs");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void load();
  }, []);

  return (
    <div style={{ display: "grid", gap: 12 }}>
      <SectionTitle>Evaluation</SectionTitle>
      <Panel>
        <div style={{ padding: 12, display: "flex", gap: 8 }}>
          <NeoButton
            onClick={() => {
              void authed<{ run_id: string; metrics: EvalRun["metrics"] }>("/api/eval/runs", {
                method: "POST",
                body: JSON.stringify({ run_type: "retrieval-grounding", model_name: "fallback-template" }),
              }).then(() => load()).catch((err) => setError(err instanceof Error ? err.message : "Evaluation run failed"));
            }}
            style={{ background: "#000", color: "var(--accent-yellow)" }}
          >
            RUN EVALUATION
          </NeoButton>
        </div>
      </Panel>

      <Panel>
        <div style={{ padding: 12, height: 260 }}>
          <h3 style={{ marginTop: 0, marginBottom: 10 }}>Evaluation Trends</h3>
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={[...runs].reverse()}>
              <CartesianGrid strokeDasharray="4 4" stroke="#111" />
              <XAxis dataKey="created_at" tickFormatter={(value) => new Date(value).toLocaleTimeString()} />
              <YAxis domain={[0, 1]} />
              <Tooltip labelFormatter={(value) => new Date(String(value)).toLocaleString()} />
              <Line type="monotone" dataKey="metrics.f1" stroke="#111" strokeWidth={2} dot={false} />
              <Line type="monotone" dataKey="metrics.accuracy" stroke="#FF2D2D" strokeWidth={2} dot={false} />
              <Line type="monotone" dataKey="metrics.bleu4" stroke="#0057FF" strokeWidth={2} dot={false} />
              <Line type="monotone" dataKey="metrics.rougeL" stroke="#00A84F" strokeWidth={2} dot={false} />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </Panel>

      <Panel>
        <div style={{ padding: 0 }}>
          <div style={{ display: "grid", gridTemplateColumns: "1.2fr 1fr 1fr 1fr 1fr", borderBottom: "2px solid #000", background: "#f2f2f2", fontWeight: 800 }}>
            {["RUN", "F1", "BLEU-4", "ROUGE-L", "ACCURACY"].map((head) => (
              <div key={head} style={{ padding: 8, borderRight: "2px solid #000", fontSize: 11 }}>{head}</div>
            ))}
          </div>
          {loading ? <p style={{ padding: 12 }}>Loading evaluation runs...</p> : null}
          {!loading && runs.length === 0 ? <p style={{ padding: 12 }}>No evaluation runs yet.</p> : null}
          {runs.map((run) => (
            <div key={run.run_id} style={{ display: "grid", gridTemplateColumns: "1.2fr 1fr 1fr 1fr 1fr", borderBottom: "2px solid #000" }}>
              <div style={{ padding: 8, borderRight: "2px solid #000", fontSize: 12 }}>
                <strong>{run.run_type}</strong>
                <div>{new Date(run.created_at).toLocaleString()}</div>
                <div>{run.model_name}</div>
              </div>
              <div style={{ padding: 8, borderRight: "2px solid #000", fontSize: 12 }}>{run.metrics.f1}</div>
              <div style={{ padding: 8, borderRight: "2px solid #000", fontSize: 12 }}>{run.metrics.bleu4}</div>
              <div style={{ padding: 8, borderRight: "2px solid #000", fontSize: 12 }}>{run.metrics.rougeL}</div>
              <div style={{ padding: 8, fontSize: 12 }}>{run.metrics.accuracy}</div>
            </div>
          ))}
        </div>
      </Panel>

      {error ? <p style={{ color: "var(--accent-red)", margin: 0 }}>{error}</p> : null}
    </div>
  );
}
