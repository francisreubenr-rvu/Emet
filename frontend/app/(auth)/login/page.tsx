"use client";

import { FormEvent, useState } from "react";
import { useRouter } from "next/navigation";
import { NeoButton } from "@/components/ui/primitives";
import { login } from "@/lib/api";

export default function LoginPage() {
  const router = useRouter();
  const [identifier, setIdentifier] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setError(null);
    if (!identifier || !password) {
      setError("Identifier and password are required.");
      return;
    }
    try {
      setSubmitting(true);
      await login(identifier, password);
      router.push("/scan-console");
    } catch {
      setError("Authentication failed. Try analyst@emet.local / emet for demo backend login.");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div style={{ minHeight: "100vh", display: "grid", gridTemplateColumns: "40% 60%" }}>
      <section style={{ height: "100vh", background: "#0D0D0D", color: "var(--text-inverse)", padding: 44, display: "grid", alignContent: "center" }}>
        <h1 style={{ fontSize: 96, lineHeight: 0.9, marginBottom: 8, fontFamily: "var(--font-display)", letterSpacing: "-0.02em", fontWeight: 700 }}>EMET</h1>
        <div style={{ width: 220, borderTop: "4px solid #FFE500" }} />
        <p style={{ marginTop: 20, maxWidth: 380, letterSpacing: "0.08em", fontWeight: 700 }}>
          THREAT INTELLIGENCE. ZERO COMPROMISE.
        </p>
      </section>

      <section style={{ padding: "8vw 10vw", display: "grid", alignContent: "center", background: "#F5F0E8" }}>
        <form className="neo-panel" onSubmit={submit} style={{ maxWidth: 520, padding: 28, background: "#fff" }}>
          <h2 className="page-title" style={{ marginBottom: 18 }}>ACCESS NODE</h2>
          <label style={{ display: "grid", gap: 8, marginBottom: 14 }}>
            <span style={{ fontWeight: 800, letterSpacing: "0.06em" }}>USERNAME / EMAIL</span>
            <input
              value={identifier}
              onChange={(event) => setIdentifier(event.target.value)}
              className="input-brutal"
              style={{ padding: "12px" }}
            />
          </label>
          <label style={{ display: "grid", gap: 8, marginBottom: 18 }}>
            <span style={{ fontWeight: 800, letterSpacing: "0.06em" }}>PASSWORD</span>
            <input
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              className="input-brutal"
              style={{ padding: "12px" }}
            />
          </label>
          <NeoButton type="submit" disabled={submitting} style={{ width: "100%", background: "#000", color: "var(--accent-yellow)", padding: "14px 16px" }}>
            {submitting ? "AUTHENTICATING..." : "LOGIN"}
          </NeoButton>
          {error ? <p style={{ color: "var(--accent-red)", fontWeight: 700, marginBottom: 0 }}>{error}</p> : null}
          <button
            type="button"
            onClick={async () => {
              setError(null);
              try {
                setSubmitting(true);
                await login("guest", "emet");
                router.push("/scan-console");
              } catch {
                setError("Guest login failed. Try analyst@emet.local / emet.");
              } finally {
                setSubmitting(false);
              }
            }}
            style={{ marginTop: 12, border: "none", background: "transparent", textDecoration: "underline", fontWeight: 700, cursor: "pointer" }}
          >
            ENTER AS GUEST
          </button>
        </form>
      </section>
    </div>
  );
}
