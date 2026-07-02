import { ReactNode } from "react";

export function Panel({
  children,
  className = "",
  style = {},
}: {
  children: ReactNode;
  className?: string;
  style?: React.CSSProperties;
  /** @deprecated retained for call-site compatibility; no longer rendered */
  refId?: string;
}) {
  return (
    <section className={`neo-panel ${className}`.trim()} style={style}>
      {children}
    </section>
  );
}

export function SectionTitle({
  children,
  title,
  subtitle,
  icon: Icon,
}: {
  children?: ReactNode;
  title?: ReactNode;
  subtitle?: string;
  icon?: any;
}) {
  return (
    <div style={{ marginBottom: 28 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
        {Icon && <Icon size={26} strokeWidth={2.25} aria-hidden />}
        <h1 className="page-title">{title ?? children}</h1>
      </div>
      {subtitle && (
        <p style={{ margin: "10px 0 0", color: "var(--text-muted)", fontSize: 13, maxWidth: "70ch" }}>
          {subtitle}
        </p>
      )}
    </div>
  );
}

export function NeoButton({
  children,
  className = "",
  type = "button",
  variant = "primary",
  size = "md",
  style = {},
  ...rest
}: React.ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "primary" | "outline" | "accent";
  size?: "sm" | "md" | "lg";
}) {
  const variants: Record<string, React.CSSProperties> = {
    primary: { background: "#fff", color: "var(--text-primary)" },
    outline: { background: "transparent", color: "var(--text-primary)" },
    accent: { background: "var(--accent)", color: "var(--text-primary)" },
  };
  const sizes: Record<string, React.CSSProperties> = {
    sm: { padding: "6px 12px", fontSize: 10 },
    md: { padding: "10px 16px", fontSize: 12 },
    lg: { padding: "14px 22px", fontSize: 14 },
  };

  return (
    <button
      type={type}
      className={`neo-btn ${className}`.trim()}
      style={{ cursor: "pointer", ...variants[variant], ...sizes[size], ...style }}
      {...rest}
    >
      {children}
    </button>
  );
}

export function Label({ children, htmlFor }: { children: ReactNode; htmlFor?: string }) {
  return (
    <label
      htmlFor={htmlFor}
      style={{
        display: "block",
        fontWeight: 700,
        letterSpacing: "0.06em",
        textTransform: "uppercase",
        marginBottom: 8,
        fontSize: 11,
        color: "var(--text-muted)",
      }}
    >
      {children}
    </label>
  );
}

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: "var(--sev-critical)",
  HIGH: "var(--sev-high)",
  MEDIUM: "var(--sev-medium)",
  LOW: "var(--sev-low)",
  INFO: "var(--sev-info)",
};

export function severityColor(severity?: string): string {
  return SEVERITY_COLORS[(severity || "INFO").toUpperCase()] || "var(--sev-info)";
}

export function Badge({ children, color }: { children: ReactNode; color?: string }) {
  const resolved = color || severityColor(typeof children === "string" ? children : undefined);
  return (
    <span className="severity-badge" style={{ background: resolved }}>
      {children}
    </span>
  );
}
