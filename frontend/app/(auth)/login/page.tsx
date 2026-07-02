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
    <div style={{ minHeight: "100vh", display: "grid", gridTemplateColumns: "1fr 1fr", background: "#f2f2f2" }}>
      <section style={{ height: "100vh", background: "#000", color: "#fff", padding: 64, display: "grid", alignContent: "center", borderRight: "6px solid var(--accent-yellow)", position: "relative", overflow: "hidden" }}>
        <div style={{ position: "absolute", top: 0, left: 0, width: "100%", height: "100%", opacity: 0.1, backgroundImage: "linear-gradient(#fff 1px, transparent 1px), linear-gradient(90deg, #fff 1px, transparent 1px)", backgroundSize: "40px 40px" }} />
        <h1 style={{ fontSize: 84, lineHeight: 0.85, marginBottom: 14, fontFamily: "var(--font-display)", color: "var(--accent)" }}>EMET</h1>
        <div style={{ display: "inline-block", background: "var(--accent)", color: "#000", padding: "4px 12px", fontWeight: 700, fontSize: 12, letterSpacing: "0.12em", width: "fit-content", borderRadius: 3 }}>
          DEFENSIVE VULNERABILITY SCANNER
        </div>
        <p style={{ marginTop: 28, maxWidth: 440, letterSpacing: "0.01em", fontWeight: 500, fontSize: 15, lineHeight: 1.6, color: "#d4d4d8" }}>
          Orchestrated scanning, real threat-intelligence enrichment (NVD, EPSS, CISA KEV),
          and AI-assisted analysis — with transparent provenance for every finding.
        </p>
      </section>

      <section style={{ padding: "8vw", display: "grid", alignContent: "center", position: "relative" }}>
        <form className="neo-panel" onSubmit={submit} style={{ maxWidth: 480, width: "100%", background: "#fff" }}>
          <h2 className="page-title" style={{ marginBottom: 28, fontSize: 32 }}>Sign in</h2>

          <div style={{ display: "grid", gap: 18 }}>
            <label htmlFor="identifier" style={{ display: "grid", gap: 8 }}>
              <span style={{ fontWeight: 700, fontSize: 11, letterSpacing: "0.06em", color: "var(--text-muted)", textTransform: "uppercase" }}>Identifier</span>
              <input
                id="identifier"
                name="identifier"
                autoComplete="username"
                value={identifier}
                onChange={(event) => setIdentifier(event.target.value)}
                className="input-brutal"
                placeholder="email or handle"
              />
            </label>

            <label htmlFor="password" style={{ display: "grid", gap: 8 }}>
              <span style={{ fontWeight: 700, fontSize: 11, letterSpacing: "0.06em", color: "var(--text-muted)", textTransform: "uppercase" }}>Password</span>
              <input
                id="password"
                name="password"
                type="password"
                autoComplete="current-password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                className="input-brutal"
                placeholder="••••••••"
              />
            </label>

            <div style={{ marginTop: 8 }}>
              <NeoButton type="submit" variant="accent" disabled={submitting} style={{ width: "100%", fontSize: 14 }}>
                {submitting ? "Verifying…" : "Log in"}
              </NeoButton>
            </div>

            {error ? (
              <div role="alert" style={{ border: "2px solid var(--danger)", borderRadius: 4, padding: 12, background: "#fdeef0", color: "var(--danger)", fontWeight: 600, fontSize: 12 }}>
                {error}
              </div>
            ) : null}

            <button
              type="button"
              onClick={async () => {
                setError(null);
                try {
                  setSubmitting(true);
                  await login("guest", "emet");
                  router.push("/scan-console");
                } catch {
                  setError("Guest login failed.");
                } finally {
                  setSubmitting(false);
                }
              }}
              style={{
                marginTop: 4,
                border: "none",
                background: "transparent",
                color: "var(--text-muted)",
                fontWeight: 600,
                fontSize: 11,
                cursor: "pointer",
                textAlign: "center",
                letterSpacing: "0.04em",
                textDecoration: "underline",
              }}
            >
              Continue as guest (read-only)
            </button>
          </div>
        </form>
      </section>
    </div>
  );
}
