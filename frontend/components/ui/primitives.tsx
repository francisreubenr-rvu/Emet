import { ReactNode } from "react";

export function Panel({ 
  children, 
  className = "", 
  style = {}, 
  refId = "0X-00" 
}: { 
  children: ReactNode; 
  className?: string; 
  style?: React.CSSProperties;
  refId?: string;
}) {
  return (
    <section 
      className={`neo-panel ${className}`.trim()} 
      style={style}
      data-ref={refId}
    >
      {children}
    </section>
  );
}

export function SectionTitle({ 
  children, 
  subtitle, 
  icon: Icon 
}: { 
  children: ReactNode; 
  subtitle?: string;
  icon?: any;
}) {
  return (
    <div style={{ marginBottom: 32 }}>
      <div style={{ display: "flex", alignItems: "flex-end", gap: 16 }}>
        <h2 className="page-title">{children}</h2>
        {Icon && <Icon size={48} strokeWidth={3} style={{ marginBottom: 24 }} />}
      </div>
      {subtitle && (
        <div style={{ 
          background: "#000", 
          color: "#fff", 
          display: "inline-block", 
          padding: "4px 12px", 
          fontSize: 12, 
          fontWeight: 800, 
          letterSpacing: "0.1em",
          marginTop: -16,
          marginLeft: 24,
          border: "2px solid #000"
        }}>
          {subtitle.toUpperCase()}
        </div>
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
}: React.ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "primary" | "outline", size?: "sm" | "md" | "lg" }) {
  const getVariantStyle = () => {
    if (variant === "outline") return { background: "transparent", color: "#000" };
    return { background: "#fff", color: "#000" };
  };

  const getSizeStyle = () => {
    if (size === "sm") return { padding: "6px 12px", fontSize: 10 };
    if (size === "lg") return { padding: "16px 24px", fontSize: 14 };
    return { padding: "12px 18px", fontSize: 12 };
  };

  return (
    <button
      type={type}
      className={`neo-btn ${className}`.trim()}
      style={{ 
        cursor: "pointer", 
        ...getVariantStyle(), 
        ...getSizeStyle(),
        ...style 
      }}
      {...rest}
    >
      {children}
    </button>
  );
}

export function Label({ children }: { children: ReactNode }) {
  return (
    <label style={{ display: "block", fontWeight: 900, letterSpacing: "0.1em", textTransform: "uppercase", marginBottom: 8, fontSize: 11 }}>
      {children}
    </label>
  );
}

export function Badge({ children, color = "var(--accent-yellow)" }: { children: ReactNode, color?: string }) {
  return (
    <span className="severity-badge" style={{ background: color }}>
      {children}
    </span>
  );
}
