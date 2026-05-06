import { ScanReport, ScanRunResponse } from "@/lib/types";

const DB_NAME = "emet-db";
const DB_VERSION = 1;
const STORE_REPORTS = "scanReports";

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(STORE_REPORTS)) {
        db.createObjectStore(STORE_REPORTS, { keyPath: "id" });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

export async function saveScanResult(scan: ScanRunResponse) {
  const db = await openDb();
  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction(STORE_REPORTS, "readwrite");
    const tools = Array.from(new Set((scan.scanner_runs || []).map((item) => item.scanner).filter((value) => value && value !== "pipeline")));
    tx.objectStore(STORE_REPORTS).put({
      id: scan.scan_id,
      target: scan.target,
      date: new Date().toISOString(),
      duration: `${Math.floor(scan.duration_seconds / 60)}m ${String(scan.duration_seconds % 60).padStart(2, "0")}s`,
      tools: tools.length ? tools : ["nmap"],
      severity: scan.findings[0]?.severity || "INFO",
      findings_count: scan.findings.length,
      status: scan.status,
      full: scan,
    });
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

export async function getIndexedReports(): Promise<ScanReport[]> {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_REPORTS, "readonly");
    const request = tx.objectStore(STORE_REPORTS).getAll();
    request.onsuccess = () => resolve((request.result as ScanReport[]) || []);
    request.onerror = () => reject(request.error);
  });
}

export async function getIndexedReportById(id: string): Promise<any | null> {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_REPORTS, "readonly");
    const request = tx.objectStore(STORE_REPORTS).get(id);
    request.onsuccess = () => resolve(request.result || null);
    request.onerror = () => reject(request.error);
  });
}

export async function clearIndexedReports() {
  const db = await openDb();
  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction(STORE_REPORTS, "readwrite");
    tx.objectStore(STORE_REPORTS).clear();
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}
