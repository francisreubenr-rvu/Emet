import { Sidebar } from "@/components/Sidebar";

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="page-shell" style={{ display: "flex" }}>
      <Sidebar />
      <main style={{ marginLeft: "240px", width: "calc(100% - 240px)", padding: 20, minHeight: "100vh" }}>
        {children}
      </main>
    </div>
  );
}
