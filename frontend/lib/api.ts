import {
  AttackPathRow,
  AlertEventRecord,
  DashboardStats,
  DatasetHistoryRow,
  DatasetStatusRow,
  OsintIntel,
  QueuedScanResponse,
  ScanProgressEvent,
  ScanReport,
  ScanRunResponse,
  ScheduledScan,
  ScannerAvailability,
  OperationsQueueHealth,
  WorkerHeartbeatRow,
  WorkerMetricRow,
  VulnerabilityRecord,
} from "@/lib/types";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers || {}),
    },
    credentials: "include",
    cache: "no-store",
  });

  if (!response.ok) {
    const body = await response.text();
    throw new Error(`API ${response.status}: ${body}`);
  }

  if (response.status === 204) {
    return undefined as T;
  }

  return response.json() as Promise<T>;
}

export async function getHealth() {
  return request<{ status: string; app: string; queue_depth: number; scanners: ScannerAvailability[] }>("/api/health");
}

export async function getScannerAvailability() {
  return request<ScannerAvailability[]>("/api/scan/availability");
}

export async function login(identifier: string, password: string) {
  return request<{ access_token: string; token_type: string }>("/api/auth/login", {
    method: "POST",
    body: JSON.stringify({ identifier, password }),
  });
}

export async function logout() {
  return request<{ status: string }>("/api/auth/logout", { method: "POST" });
}

export async function getDashboardStats() {
  return request<DashboardStats>("/api/reports/dashboard-stats");
}

export async function runScan(target: string, scanners: string[], profile: string) {
  return request<QueuedScanResponse>("/api/scan/run", {
    method: "POST",
    body: JSON.stringify({ target, scanners, profile }),
  });
}

export async function cancelScan(scanId: string) {
  return request<{ scan_id: string; status: string }>(`/api/scan/${scanId}`, {
    method: "DELETE",
  });
}

export async function getScanResult(scanId: string) {
  return request<ScanRunResponse>(`/api/scan/${scanId}`);
}

export async function getReports() {
  return request<ScanReport[]>("/api/reports");
}

export async function getReportDetail(reportId: string) {
  return request<ScanRunResponse & { id: string; date: string }>(`/api/reports/${reportId}`);
}

export async function fetchOsint(target: string) {
  return request<OsintIntel>("/api/reports/osint", {
    method: "POST",
    body: JSON.stringify({ target }),
  });
}

export async function listVulnerabilities(filters?: {
  severity?: string;
  scanner?: string;
  target?: string;
  status?: string;
  cve?: string;
}) {
  const params = new URLSearchParams();
  if (filters?.severity) params.set("severity", filters.severity);
  if (filters?.scanner) params.set("scanner", filters.scanner);
  if (filters?.target) params.set("target", filters.target);
  if (filters?.status) params.set("status", filters.status);
  if (filters?.cve) params.set("cve", filters.cve);
  const suffix = params.toString() ? `?${params.toString()}` : "";
  return request<VulnerabilityRecord[]>(`/api/vulnerabilities${suffix}`);
}

export async function updateVulnerabilityStatus(findingId: string, status: string) {
  return request<{ finding_id: string; status: string }>(`/api/vulnerabilities/${findingId}/status`, {
    method: "PATCH",
    body: JSON.stringify({ status }),
  });
}

export async function getAttackPaths(scanId: string) {
  return request<AttackPathRow[]>(`/api/vulnerabilities/attack-paths/${scanId}`);
}

export async function getSchedules() {
  return request<ScheduledScan[]>("/api/schedules");
}

export async function createSchedule(payload: {
  name: string;
  target: string;
  profile: string;
  scanners: string[];
  recurrence: string;
  cron_expr?: string;
}) {
  return request<{ id: number; status: string; next_run_at: string }>("/api/schedules", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function updateSchedule(
  scheduleId: number,
  payload: {
    name: string;
    profile: string;
    scanners: string[];
    recurrence: string;
    cron_expr?: string;
    enabled: boolean;
  },
) {
  return request<{ id: number; status: string; next_run_at: string }>(`/api/schedules/${scheduleId}`, {
    method: "PUT",
    body: JSON.stringify(payload),
  });
}

export async function deleteSchedule(scheduleId: number) {
  return request<{ id: number; status: string }>(`/api/schedules/${scheduleId}`, {
    method: "DELETE",
  });
}

export async function runScheduleNow(scheduleId: number) {
  return request<{ schedule_id: number; scan_id: string; status: string }>(`/api/schedules/${scheduleId}/run-now`, {
    method: "POST",
  });
}

export async function listAlerts() {
  return request<AlertEventRecord[]>("/api/alerts");
}

export async function getOperationsQueue() {
  return request<OperationsQueueHealth>("/api/operations/queue");
}

export async function getOperationsWorkers() {
  return request<WorkerHeartbeatRow[]>("/api/operations/workers");
}

export async function getOperationsWorkerMetrics() {
  return request<WorkerMetricRow[]>("/api/operations/metrics/workers");
}

export async function replayDeadLetter() {
  return request<{ status: string; target_queue: string }>("/api/operations/queue/dead-letter/replay", {
    method: "POST",
  });
}

export async function createGithubIssue(title: string, body: string, labels: string[] = []) {
  return request<{ ok: boolean; reference: string }>("/api/alerts/integrations/github/issue", {
    method: "POST",
    body: JSON.stringify({ title, body, labels }),
  });
}

export async function createJiraIssue(title: string, body: string) {
  return request<{ ok: boolean; reference: string }>("/api/alerts/integrations/jira/issue", {
    method: "POST",
    body: JSON.stringify({ title, body, labels: [] }),
  });
}

export async function getDatasetStatus() {
  return request<DatasetStatusRow[]>("/api/settings/dataset-status");
}

export async function getDatasetHistory() {
  return request<DatasetHistoryRow[]>("/api/settings/dataset-history");
}

export async function getAgents() {
  return request<any[]>("/api/v1/agents");
}

export async function getTickets() {
  return request<any[]>("/api/v1/remediation/tickets");
}

export async function syncTicket(ticketId: number) {
  return request<any>("/api/v1/remediation/sync", {
    method: "POST",
    params: { ticket_id: ticketId },
  });
}

export async function deployPatch(vulnerabilityId: string) {
  return request<any>("/api/v1/patching/deploy", {
    method: "POST",
    body: JSON.stringify({ vulnerability_id: vulnerabilityId }),
  });
}

export async function getPatchJob(jobId: number) {
  return request<any>(`/api/v1/patching/jobs/${jobId}`);
}

export async function getComplianceReport(framework: string) {
  return request<any[]>(`/api/v1/compliance/${framework}`);
}

export async function listTenants() {
  return request<any[]>("/api/tenants");
}

export async function createTenant(name: string, domain: string = "") {
  return request<any>("/api/tenants", {
    method: "POST",
    body: JSON.stringify({ name, domain }),
  });
}

export function buildScanProgressSseUrl(scanId: string): string {
  const base = API_BASE.replace(/\/$/, "");
  return `${base}/api/scan/${scanId}/events`;
}

export function parseScanProgress(input: string): ScanProgressEvent | null {
  try {
    return JSON.parse(input) as ScanProgressEvent;
  } catch {
    return null;
  }
}
