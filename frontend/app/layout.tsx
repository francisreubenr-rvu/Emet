import type { Metadata } from "next";
import { Bebas_Neue, IBM_Plex_Mono, JetBrains_Mono } from "next/font/google";
import "./globals.css";

const display = Bebas_Neue({ subsets: ["latin"], weight: "400", variable: "--font-display" });
const body = IBM_Plex_Mono({ subsets: ["latin"], weight: ["400", "500", "700"], variable: "--font-body" });
const code = JetBrains_Mono({ subsets: ["latin"], weight: ["400", "600", "700"], variable: "--font-code" });

export const metadata: Metadata = {
  title: "EMET - Threat Intelligence. Zero Compromise.",
  description: "Centralized vulnerability detection and zero-day intelligence platform.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className={`${display.variable} ${body.variable} ${code.variable} grain`}>{children}</body>
    </html>
  );
}
