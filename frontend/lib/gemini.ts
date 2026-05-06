import { UnifiedFinding } from "@/lib/types";

export async function analyzeFindingsWithBackend(findings: UnifiedFinding[]) {
  const response = await fetch("/api/scan/analyze", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ findings }),
  });
  if (!response.ok) {
    throw new Error("Failed to analyze findings");
  }
  return response.json();
}
