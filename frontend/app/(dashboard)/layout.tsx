import { Sidebar } from "@/components/Sidebar";

const STATIC_DEMO = process.env.NEXT_PUBLIC_STATIC_DEMO === "true";

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="page-shell" style={{ display: "flex" }}>
      <Sidebar />
      <main style={{ marginLeft: 260, width: "calc(100% - 260px)", padding: 20, minHeight: "100vh" }}>
        {STATIC_DEMO ? (
          <div
            role="note"
            style={{
              border: "2px solid var(--accent-strong)",
              borderRadius: 4,
              background: "#fff7d9",
              padding: "10px 14px",
              marginBottom: 20,
              fontSize: 13,
              fontWeight: 500,
            }}
          >
            Static preview — no backend is connected on GitHub Pages, so data will not load.
            Run the EMET backend locally and this UI will talk to it at{" "}
            <code>http://localhost:8000</code>.
          </div>
        ) : null}
        {children}
      </main>
    </div>
  );
}
