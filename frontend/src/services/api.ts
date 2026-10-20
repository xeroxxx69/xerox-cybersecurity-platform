import {
  ThreatReport,
  ScanHistoryItem,
  StatsSummary,
} from "@/types";
import { getStoredToken } from "@/features/auth/tokenStorage";
import { getApiBaseUrl } from "./apiConfig";
import {
  safeFetchWithDiagnostics,
  parseJsonSafely,
  extractCorrelationId,
} from "./apiError";


export { ApiError } from "./apiError";
export type { ApiErrorKind, ApiErrorContext } from "./apiError";

function getAuthHeaders(extraHeaders: Record<string, string> = {}): Record<string, string> {
  const headers: Record<string, string> = { ...extraHeaders };
  const token = getStoredToken();
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }
  return headers;
}

export interface BackendHealthResult {
  status: string;
  service: string;
  version: string;
  database?: string;
  cache?: string;
  redis?: Record<string, string>;
  checks?: Record<string, string>;
  baseUrl: string;
  latencyMs: number;
  correlationId?: string;
}

export async function checkBackendHealth(): Promise<BackendHealthResult> {
  const baseUrl = getApiBaseUrl();
  const startTime = Date.now();

  const res = await safeFetchWithDiagnostics(
    `${baseUrl}/health`,
    {
      headers: getAuthHeaders(),
      credentials: "include",
      cache: "no-store",
    },
    10000
  );

  const latencyMs = Date.now() - startTime;
  const correlationId = extractCorrelationId(res.headers);
  const data = await parseJsonSafely<Record<string, any>>(res, `${baseUrl}/health`);

  return {
    status: data.status || "healthy",
    service: data.service || "XEROX API",
    version: data.version || "1.0.0",
    database: data.database,
    cache: data.cache,
    redis: data.redis,
    checks: data.checks,
    baseUrl,
    latencyMs,
    correlationId,
  };
}

export async function scanUrl(url: string): Promise<ThreatReport> {
  const targetUrl = `${getApiBaseUrl()}/analyze/url`;
  const res = await safeFetchWithDiagnostics(
    targetUrl,
    {
      method: "POST",
      headers: getAuthHeaders({ "Content-Type": "application/json" }),
      credentials: "include",
      body: JSON.stringify({ url, deep_scan: true }),
    },
    30000
  );
  return parseJsonSafely<ThreatReport>(res, targetUrl);
}

export async function scanMessage(
  content: string,
  senderMetadata?: string,
  subject?: string,
  sender?: string
): Promise<ThreatReport> {
  const targetUrl = `${getApiBaseUrl()}/analyze/message`;
  const res = await safeFetchWithDiagnostics(
    targetUrl,
    {
      method: "POST",
      headers: getAuthHeaders({ "Content-Type": "application/json" }),
      credentials: "include",
      body: JSON.stringify({
        content,
        sender_metadata: senderMetadata,
        subject,
        sender,
      }),
    },
    30000
  );
  return parseJsonSafely<ThreatReport>(res, targetUrl);
}

export async function scanScreenshot(file: File): Promise<ThreatReport> {
  const targetUrl = `${getApiBaseUrl()}/analyze/screenshot`;
  const formData = new FormData();
  formData.append("file", file);

  const res = await safeFetchWithDiagnostics(
    targetUrl,
    {
      method: "POST",
      headers: getAuthHeaders(),
      credentials: "include",
      body: formData,
    },
    45000
  );
  return parseJsonSafely<ThreatReport>(res, targetUrl);
}

export async function scanFile(file: File): Promise<ThreatReport> {
  const targetUrl = `${getApiBaseUrl()}/analyze/file`;
  const formData = new FormData();
  formData.append("file", file);

  const res = await safeFetchWithDiagnostics(
    targetUrl,
    {
      method: "POST",
      headers: getAuthHeaders(),
      credentials: "include",
      body: formData,
    },
    45000
  );
  return parseJsonSafely<ThreatReport>(res, targetUrl);
}

export async function getHistory(limit: number = 50): Promise<ScanHistoryItem[]> {
  const targetUrl = `${getApiBaseUrl()}/analyze/history?limit=${limit}`;
  const res = await safeFetchWithDiagnostics(
    targetUrl,
    {
      headers: getAuthHeaders(),
      credentials: "include",
      cache: "no-store",
    },
    15000
  );
  return parseJsonSafely<ScanHistoryItem[]>(res, targetUrl);
}

export async function getReport(scanId: string): Promise<ThreatReport> {
  const targetUrl = `${getApiBaseUrl()}/analyze/${encodeURIComponent(scanId)}`;
  const res = await safeFetchWithDiagnostics(
    targetUrl,
    {
      headers: getAuthHeaders(),
      credentials: "include",
      cache: "no-store",
    },
    15000
  );
  return parseJsonSafely<ThreatReport>(res, targetUrl);
}

export async function getStats(): Promise<StatsSummary> {
  const targetUrl = `${getApiBaseUrl()}/analyze/stats/summary`;
  const res = await safeFetchWithDiagnostics(
    targetUrl,
    {
      headers: getAuthHeaders(),
      credentials: "include",
      cache: "no-store",
    },
    15000
  );
  return parseJsonSafely<StatsSummary>(res, targetUrl);
}

export interface FeedbackSubmission {
  scan_id: string;
  is_accurate: boolean;
  user_notes?: string;
  suggested_label?: string;
}

export async function submitFeedback(feedback: FeedbackSubmission): Promise<{
  id: string;
  scan_id: string;
  is_accurate: boolean;
  user_notes?: string;
  suggested_label?: string;
  submitted_at: string;
}> {
  const targetUrl = `${getApiBaseUrl()}/feedback`;
  const res = await safeFetchWithDiagnostics(
    targetUrl,
    {
      method: "POST",
      headers: getAuthHeaders({ "Content-Type": "application/json" }),
      credentials: "include",
      body: JSON.stringify(feedback),
    },
    15000
  );
  return parseJsonSafely<{
    id: string;
    scan_id: string;
    is_accurate: boolean;
    user_notes?: string;
    suggested_label?: string;
    submitted_at: string;
  }>(res, targetUrl);
}
