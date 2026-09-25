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

export interface AssetOut {
  id: string;
  type: string;
  value: string;
  parent_id: string | null;
  first_seen: string;
  last_seen: string;
}

export interface ToolCallOut {
  id: string;
  scan_id: string;
  phase: string;
  tool: string;
  args: Record<string, unknown>;
  reason: string;
  status: string;
  duration_ms: number | null;
  result_sha256: string | null;
  created_at: string;
}

export interface TopRiskOut {
  title: string;
  reason: string;
}

export interface ReportFindingOut {
  title: string;
  explanation: string;
  impact: string;
  remediation: string;
}

export interface ReportOut {
  executive_summary: string;
  top_risks: TopRiskOut[];
  findings: ReportFindingOut[];
  positive_observations: string[];
  dropped_items: string[];
  attempts_used: number;
}

export const API_KEY_SOURCES = [
  "censys_api_id",
  "censys_api_secret",
  "github_token",
  "hibp_api_key",
] as const;
export type ApiKeySource = (typeof API_KEY_SOURCES)[number];

export interface SettingsOut {
  planner_model: string;
  extractor_model: string;
  scan_max_steps: number;
  scan_max_minutes: number;
  scan_max_deep_dives: number;
  configured_api_keys: Record<ApiKeySource, boolean>;
}

export interface SettingsUpdate {
  planner_model?: string;
  extractor_model?: string;
  scan_max_steps?: number;
  scan_max_minutes?: number;
  scan_max_deep_dives?: number;
  api_keys?: Partial<Record<ApiKeySource, string>>;
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

export function listAssets(scanId: string): Promise<AssetOut[]> {
  return apiFetch(`/scans/${scanId}/assets`);
}

export function listAudit(scanId: string): Promise<ToolCallOut[]> {
  return apiFetch(`/scans/${scanId}/audit`);
}

export function generateReport(scanId: string, model?: string): Promise<ReportOut> {
  return apiFetch(`/scans/${scanId}/report`, {
    method: "POST",
    body: JSON.stringify({ model: model || null }),
  });
}

export async function exportReport(
  scanId: string,
  format: "md" | "json" | "pdf",
  model?: string,
): Promise<Blob> {
  const response = await fetch(`${API_URL}/scans/${scanId}/report/export?format=${format}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ model: model || null }),
  });
  if (!response.ok) {
    const body = await response.text().catch(() => "");
    throw new Error(`${response.status} ${response.statusText}: ${body}`);
  }
  return response.blob();
}

export function getSettings(): Promise<SettingsOut> {
  return apiFetch("/settings");
}

export function updateSettings(update: SettingsUpdate): Promise<SettingsOut> {
  return apiFetch("/settings", { method: "PUT", body: JSON.stringify(update) });
}

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export const SEVERITY_COLORS: Record<Severity, string> = {
  critical: "bg-red-500/20 text-red-400 border-red-500/40",
  high: "bg-orange-500/20 text-orange-400 border-orange-500/40",
  medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/40",
  low: "bg-blue-500/20 text-blue-400 border-blue-500/40",
  info: "bg-zinc-500/20 text-zinc-400 border-zinc-500/40",
};
