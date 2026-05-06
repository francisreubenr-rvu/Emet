"use client";

import { FormEvent, useCallback, useEffect, useState } from "react";

import { NeoButton, Panel, SectionTitle } from "@/components/ui/primitives";

type ChatSession = { session_id: string; title: string; updated_at?: string };
type ChatMessage = { id: number; role: string; content: string; citations?: { source: string }[] };

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

async function authed<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    ...init,
    credentials: "include",
    headers: { "Content-Type": "application/json", ...(init?.headers || {}) },
    cache: "no-store",
  });
  if (!response.ok) {
    throw new Error(`API ${response.status}: ${await response.text()}`);
  }
  return response.json() as Promise<T>;
}

export default function RagChatPage() {
  const [sessions, setSessions] = useState<ChatSession[]>([]);
  const [current, setCurrent] = useState<string>("");
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [draft, setDraft] = useState("");
  const [error, setError] = useState<string | null>(null);

  const refreshSessions = useCallback(async () => {
    const items = await authed<ChatSession[]>("/api/rag/sessions");
    setSessions(items);
    if (!current && items[0]) {
      setCurrent(items[0].session_id);
    }
  }, [current]);

  const refreshMessages = async (sessionId: string) => {
    const items = await authed<ChatMessage[]>(`/api/rag/sessions/${sessionId}`);
    setMessages(items);
  };

  useEffect(() => {
    void refreshSessions().catch((err) => {
      setError(err instanceof Error ? err.message : "Failed to load sessions");
    });
  }, [refreshSessions]);

  useEffect(() => {
    if (!current) return;
    void refreshMessages(current).catch((err) => {
      setError(err instanceof Error ? err.message : "Failed to load messages");
    });
  }, [current]);

  const createSession = async () => {
    const result = await authed<{ session_id: string }>("/api/rag/sessions", {
      method: "POST",
      body: JSON.stringify({ title: "Analyst Session" }),
    });
    setCurrent(result.session_id);
    await refreshSessions();
    await refreshMessages(result.session_id);
  };

  const send = async (event: FormEvent) => {
    event.preventDefault();
    if (!current || !draft.trim()) return;
    const content = draft.trim();
    setDraft("");
    setMessages((prev) => [...prev, { id: Date.now(), role: "user", content }]);

    const reply = await authed<{ reply: string; citations: { source: string }[] }>(`/api/rag/sessions/${current}/messages`, {
      method: "POST",
      body: JSON.stringify({ content }),
    });

    setMessages((prev) => [
      ...prev,
      { id: Date.now() + 1, role: "assistant", content: reply.reply, citations: reply.citations },
    ]);
  };

  return (
    <div style={{ display: "grid", gap: 12 }}>
      <SectionTitle>RAG Chat</SectionTitle>
      <div style={{ display: "grid", gridTemplateColumns: "280px 1fr", gap: 12 }}>
        <Panel>
          <div style={{ padding: 12, display: "grid", gap: 10 }}>
            <NeoButton onClick={() => void createSession()} style={{ background: "#fff" }}>NEW SESSION</NeoButton>
            <div style={{ display: "grid", gap: 8 }}>
              {sessions.map((session) => (
                <button
                  key={session.session_id}
                  onClick={() => setCurrent(session.session_id)}
                  style={{
                    border: "2px solid #000",
                    padding: 8,
                    textAlign: "left",
                    background: current === session.session_id ? "#FFE500" : "#fff",
                    cursor: "pointer",
                    fontWeight: 700,
                  }}
                >
                  {session.title}
                </button>
              ))}
            </div>
          </div>
        </Panel>

        <Panel>
          <div style={{ padding: 12, minHeight: 480, display: "grid", gridTemplateRows: "1fr auto", gap: 10 }}>
            <div style={{ border: "2px solid #000", padding: 10, background: "#fff", overflowY: "auto", maxHeight: 420 }}>
              {messages.length === 0 ? <p>No messages yet. Ask about a finding and EMET will return grounded fallback guidance.</p> : null}
              {messages.map((message) => (
                <div key={message.id} style={{ borderTop: "2px solid #000", paddingTop: 8, marginTop: 8 }}>
                  <strong>{message.role.toUpperCase()}</strong>
                  <p style={{ marginBottom: 6 }}>{message.content}</p>
                  {message.citations?.length ? <p style={{ fontSize: 12, margin: 0 }}>Sources: {message.citations.map((item) => item.source).join(", ")}</p> : null}
                </div>
              ))}
            </div>

            <form onSubmit={(event) => void send(event)} style={{ display: "grid", gridTemplateColumns: "1fr 130px", gap: 8 }}>
              <input
                value={draft}
                onChange={(event) => setDraft(event.target.value)}
                placeholder="Ask a grounded defensive question"
                style={{ border: "2px solid #000", boxShadow: "var(--shadow)", padding: 10, fontFamily: "inherit" }}
              />
              <NeoButton type="submit" style={{ background: "#000", color: "var(--accent-yellow)" }}>SEND</NeoButton>
            </form>

            {error ? <p style={{ color: "var(--accent-red)", margin: 0 }}>{error}</p> : null}
          </div>
        </Panel>
      </div>
    </div>
  );
}
