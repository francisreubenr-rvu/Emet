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
        <h1 style={{ fontSize: 120, lineHeight: 0.7, marginBottom: 12, fontFamily: "var(--font-display)", fontWeight: 900, color: "var(--accent-yellow)" }}>EMET</h1>
        <div style={{ display: "inline-block", background: "var(--accent-yellow)", color: "#000", padding: "4px 12px", fontWeight: 900, fontSize: 12, letterSpacing: "0.2em", width: "fit-content" }}>
          DEFENSIVE ORCHESTRATOR v4.0
        </div>
        <p style={{ marginTop: 32, maxWidth: 440, letterSpacing: "0.04em", fontWeight: 800, fontSize: 18, lineHeight: 1.4 }}>
          "THE BONES OF THE SYSTEM ARE VISIBLE. TRUST IS BUILT THROUGH TRANSPARENCY."
        </p>
        <div style={{ marginTop: 64, display: "flex", gap: 24, opacity: 0.4 }}>
          <div style={{ border: "2px solid #fff", padding: "8px 12px", fontSize: 10, fontWeight: 900 }}>NODE: US-EAST-01</div>
          <div style={{ border: "2px solid #fff", padding: "8px 12px", fontSize: 10, fontWeight: 900 }}>PROTO: SECURE_V4</div>
        </div>
      </section>

      <section style={{ padding: "8vw", display: "grid", alignContent: "center", position: "relative" }}>
        <form className="neo-panel" onSubmit={submit} style={{ maxWidth: 480, width: "100%", background: "#fff" }} data-ref="AUTH-NODE-77">
          <h2 className="page-title" style={{ marginBottom: 32, fontSize: 42 }}>INIT_ACCESS</h2>
          
          <div style={{ display: "grid", gap: 20 }}>
            <label style={{ display: "grid", gap: 8 }}>
              <span style={{ fontWeight: 900, fontSize: 11, letterSpacing: "0.1em", color: "#444" }}>USER_IDENTIFIER</span>
              <input
                value={identifier}
                onChange={(event) => setIdentifier(event.target.value)}
                className="input-brutal"
                placeholder="EMAIL_OR_HANDLE"
              />
            </label>

            <label style={{ display: "grid", gap: 8 }}>
              <span style={{ fontWeight: 900, fontSize: 11, letterSpacing: "0.1em", color: "#444" }}>ACCESS_KEY</span>
              <input
                type="password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                className="input-brutal"
                placeholder="********"
              />
            </label>

            <div style={{ marginTop: 12 }}>
              <NeoButton type="submit" disabled={submitting} style={{ width: "100%", background: "#000", color: "var(--accent-yellow)", fontSize: 14 }}>
                {submitting ? "VERIFYING_CREDENTIALS..." : "EXECUTE_LOGIN"}
              </NeoButton>
            </div>
            
            {error ? (
              <div style={{ border: "2px solid var(--accent-red)", padding: 12, background: "#fff0f0", color: "var(--accent-red)", fontWeight: 800, fontSize: 11 }}>
                ERROR: {error.toUpperCase()}
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
                marginTop: 8, 
                border: "none", 
                background: "transparent", 
                color: "#888",
                fontWeight: 900, 
                fontSize: 10,
                cursor: "pointer",
                textAlign: "center",
                letterSpacing: "0.1em"
              }}
            >
              [ BYPASS_WITH_GUEST_MODE ]
            </button>
          </div>
        </form>
      </section>
    </div>
  );
}
