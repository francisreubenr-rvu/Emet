import { ReactNode } from "react";

export function Panel({ children, className = "" }: { children: ReactNode; className?: string }) {
  return <section className={`neo-panel ${className}`.trim()}>{children}</section>;
}

export function SectionTitle({ children }: { children: ReactNode }) {
  return <h2 className="page-title" style={{ marginBottom: 14 }}>{children}</h2>;
}

export function NeoButton({
  children,
  className = "",
  type = "button",
  ...rest
}: React.ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button
      type={type}
      className={`neo-btn ${className}`.trim()}
      style={{ padding: "12px 18px", cursor: "pointer" }}
      {...rest}
    >
      {children}
    </button>
  );
}

export function Label({ children }: { children: ReactNode }) {
  return (
    <label style={{ display: "block", fontWeight: 800, letterSpacing: "0.06em", textTransform: "uppercase", marginBottom: 8 }}>
      {children}
    </label>
  );
}
