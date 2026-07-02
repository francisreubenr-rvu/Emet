"use client";

import { useEffect } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";

// GitHub Pages hosts a static export with no backend, so the demo build shows an
// honest landing page. Every other build keeps the original behavior: send the
// user straight into the console.
const STATIC_DEMO = process.env.NEXT_PUBLIC_STATIC_DEMO === "true";

export default function Home() {
  const router = useRouter();

  useEffect(() => {
    if (!STATIC_DEMO) {
      router.replace("/scan-console");
    }
  }, [router]);

  if (!STATIC_DEMO) {
    return null;
  }

  return (
    <main
      style={{
        minHeight: "100vh",
        display: "grid",
        placeItems: "center",
        padding: "6vw 24px",
        background: "var(--bg-dark)",
        color: "#fff",
      }}
    >
      <div style={{ maxWidth: 720, width: "100%" }}>
        <h1 style={{ fontSize: 96, lineHeight: 0.85, color: "var(--accent)", fontFamily: "var(--font-display)" }}>
          EMET
        </h1>
        <p
          style={{
            display: "inline-block",
            background: "var(--accent)",
            color: "#000",
            padding: "4px 12px",
            fontWeight: 700,
            fontSize: 12,
            letterSpacing: "0.12em",
            borderRadius: 3,
            marginTop: 4,
          }}
        >
          DEFENSIVE VULNERABILITY SCANNER
        </p>

        <div
          role="note"
          style={{
            marginTop: 28,
            border: "2px solid var(--accent)",
            borderRadius: 4,
            padding: 16,
            background: "#1f1f24",
            fontSize: 14,
            lineHeight: 1.6,
          }}
        >
          <strong>Static preview.</strong> This is the EMET console UI hosted on GitHub Pages.
          It is a front end only — GitHub Pages cannot run the FastAPI backend, Redis, or the
          scanners, so login and live data will not work here. To use EMET for real, run the
          backend (see the{" "}
          <a
            href="https://github.com/francisreubenr-rvu/Emet#quick-start-docker"
            style={{ color: "var(--accent)", textDecoration: "underline" }}
          >
            README
          </a>
          ) and point the frontend at it via <code>NEXT_PUBLIC_API_URL</code>.
        </div>

        <div style={{ marginTop: 28, display: "flex", gap: 14, flexWrap: "wrap" }}>
          <Link
            href="/scan-console"
            className="neo-btn"
            style={{
              background: "var(--accent)",
              color: "#000",
              padding: "12px 20px",
              textDecoration: "none",
              display: "inline-block",
            }}
          >
            Explore the console UI
          </Link>
          <a
            href="https://github.com/francisreubenr-rvu/Emet"
            className="neo-btn"
            style={{
              background: "transparent",
              color: "#fff",
              padding: "12px 20px",
              textDecoration: "none",
              display: "inline-block",
            }}
          >
            View source
          </a>
        </div>
      </div>
    </main>
  );
}
