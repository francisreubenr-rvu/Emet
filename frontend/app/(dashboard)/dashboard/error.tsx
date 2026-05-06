"use client";

export default function DashboardError({ reset }: { reset: () => void }) {
  return (
    <div style={{ border: "3px solid #000", background: "var(--accent-red)", color: "#fff", padding: 14, fontWeight: 800 }}>
      DASHBOARD RENDER FAILURE
      <button
        onClick={reset}
        style={{ marginLeft: 12, border: "2px solid #000", boxShadow: "var(--shadow)", background: "#fff", color: "#000", padding: "6px 10px", cursor: "pointer" }}
      >
        RETRY
      </button>
    </div>
  );
}
