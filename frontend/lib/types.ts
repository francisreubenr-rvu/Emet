export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export interface UnifiedFinding {
  finding_id?: string;
  scan_id: string;
  target: string;
  scanner_source: string;
  detected_at?: string;
  timestamp: string;
  cve_id?: string;
  cwe_id?: string;
  cvss_score: number;
  cvss_vector: string;
  severity: Severity;
  title: string;
  description: string;
  affected_component: string;
  affected_version?: string;
  port?: number;
  protocol?: string;
  service?: string;
  evidence?: Record<string, unknown>;
  remediation?: string;
  references: string[];
  verification_status?: "verified" | "partially_verified" | "unverified" | "rejected";
  verified: boolean;
  confidence_score?: number;
  false_positive_probability: number;
  tags?: string[];
  status?: string;
  source_artifact_path?: string;
}

export interface ScanReport {
  id: string;
  target: string;
  date: string;
  duration: string;
  tools: string[];
  severity: Severity;
  findings_count: number;
  status?: string;
}

export interface ScanRunResponse {
  scan_id: string;
  target: string;
  status: string;
  duration_seconds: number;
  findings: UnifiedFinding[];
  scanner_runs?: {
    scanner: string;
    status: string;
    findings_count?: number;
    error?: string;
    artifact_path?: string;
  }[];
  unified_report: {
    executive_summary?: string;
    key_findings?: string[];
    zero_day_risk_assessment?: string;
    recommended_actions?: string[];
    confidence?: number;
  };
  zero_day: {
    zero_day_risk_score?: number;
    narrative?: string;
    recommended_monitoring?: string[];
  };
  self_audit: {
    sample_size?: number;
    checked?: number;
    issues?: string[];
    status?: string;
  };
}

export interface QueuedScanResponse {
  scan_id: string;
  target: string;
  status: string;
  duration_seconds: number;
  findings: UnifiedFinding[];
  unified_report: Record<string, unknown>;
  zero_day: Record<string, unknown>;
  self_audit: Record<string, unknown>;
}

export interface ScanProgressEvent {
  scan_id: string;
  phase: string;
  progress?: number;
  sequence?: number;
  scanner?: string;
  scanner_index?: number;
  scanner_total?: number;
  status?: string;
  message?: string;
  timestamp?: string;
}

export interface OsintIntel {
  target: string;
  shodan: { open_ports: number[]; org: string; hostnames: string[] };
  whois: { registrar: string; created: string; expires: string };
  ssl: { issuer: string; valid_until: string; grade: string };
  breaches: { count: number; recent: string[] };
  cve_entries: { cve_id: string; summary: string }[];
  news: { source: string; title: string; published_at: string }[];
}

export interface ScannerAvailability {
  scanner: string;
  available: boolean;
  reason?: string;
}

export interface DashboardStats {
  total_scans: number;
  active_scans: number;
  critical_findings: number;
  verified_findings: number;
  severity_distribution: Record<string, number>;
  last_scan_time: string;
  queue_health: string;
  rag_availability: string;
  evaluation_summary: { latest_f1: number; latest_accuracy: number };
}

export interface VulnerabilityRecord {
  finding_id: string;
  scan_id: string;
  target: string;
  scanner_source: string;
  detected_at: string;
  title: string;
  description: string;
  severity: Severity;
  cvss_score: number;
  cvss_vector: string;
  cve_id?: string;
  cwe_id?: string;
  affected_component: string;
  affected_version?: string;
  port?: number;
  protocol?: string;
  service?: string;
  evidence: Record<string, unknown>;
  remediation?: string;
  references: string[];
  verification_status: "verified" | "partially_verified" | "unverified" | "rejected";
  confidence_score: number;
  false_positive_probability: number;
  tags: string[];
  status: string;
  source_artifact_path: string;
}

export interface DatasetStatusRow {
  name: string;
  source: string;
  status: string;
  size: number;
}

export interface DatasetHistoryRow {
  id: number;
  created_at: string;
  event_type: string;
  actor: string;
  details: Record<string, unknown>;
}

export interface AttackPathRow {
  id: number;
  scan_id: string;
  target: string;
  path_summary: string;
  confidence_score: number;
  provenance: Record<string, unknown>;
  created_at: string;
}

export interface ScheduledScan {
  id: number;
  name: string;
  target: string;
  profile: string;
  scanners: string[];
  recurrence: string;
  cron_expr: string;
  enabled: boolean;
  next_run_at: string;
  last_run_at?: string | null;
  created_by: string;
  updated_at: string;
}

export interface AlertEventRecord {
  id: number;
  event_type: string;
  severity: string;
  payload: Record<string, unknown>;
  created_at: string;
}

export interface OperationsQueueHealth {
  queues: Record<string, number>;
  queue_oldest_age_seconds: Record<string, number>;
  total_depth: number;
  dead_letter_depth: number;
}

export interface WorkerMetricRow {
  worker_id: string;
  metrics: Record<string, number>;
}

export interface WorkerHeartbeatRow {
  worker_id: string;
  heartbeat: string;
}
