/**
 * Thin client for the Vigía API. Every call goes straight to the FastAPI backend
 * (NEXT_PUBLIC_API_URL) — there's no Next.js API-route proxy layer, since the
 * browser needs a plain URL for EventSource (SSE) anyway and CORS is already
 * configured on the API for this origin (see vigia.config.Settings.cors_origins).
 */

export const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export type ScanStatus = "pending" | "running" | "completed" | "failed" | "stopped";
export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface ScanSummary {
  id: string;
  domain: string;
  mode: string;
  status: ScanStatus;
  started_at: string | null;
  finished_at: string | null;
  findings_count: number;
  max_severity: Severity | null;
}

export interface FindingOut {
  id: string;
  asset_id: string | null;
  type: string;
  severity: Severity;
  score: number;
  title: string;
  explanation: string;
  remediation: string;
  kev: boolean;
  known_ransomware: boolean;
  epss: number | null;
  cve: string | null;
}

export interface EthicsStatus {
  accepted: boolean;
  notice: string;
}

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_URL}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...init?.headers },
  });
  if (!response.ok) {
    const body = await response.text().catch(() => "");
    throw new Error(`${response.status} ${response.statusText}: ${body}`);
  }
  if (response.status === 204) {
    return undefined as T;
  }
  return response.json() as Promise<T>;
}

export function listScans(): Promise<ScanSummary[]> {
  return apiFetch("/scans");
}

export function getScan(id: string): Promise<ScanSummary> {
  return apiFetch(`/scans/${id}`);
}

export function listFindings(scanId: string): Promise<FindingOut[]> {
  return apiFetch(`/scans/${scanId}/findings`);
}

export function createScan(
  domain: string,
  model?: string,
): Promise<{ id: string; domain: string; status: string }> {
  return apiFetch("/scans", {
    method: "POST",
    body: JSON.stringify({ domain, model: model || null }),
  });
}

export function stopScan(id: string): Promise<void> {
  return apiFetch(`/scans/${id}`, { method: "DELETE" });
}

export function getEthicsStatus(): Promise<EthicsStatus> {
  return apiFetch("/ethics");
}

export function acceptEthicsNotice(): Promise<EthicsStatus> {
  return apiFetch("/ethics/accept", { method: "POST" });
}

export function scanStreamUrl(id: string): string {
  return `${API_URL}/scans/${id}/stream`;
}

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export const SEVERITY_COLORS: Record<Severity, string> = {
  critical: "bg-red-500/20 text-red-400 border-red-500/40",
  high: "bg-orange-500/20 text-orange-400 border-orange-500/40",
  medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/40",
  low: "bg-blue-500/20 text-blue-400 border-blue-500/40",
  info: "bg-zinc-500/20 text-zinc-400 border-zinc-500/40",
};
