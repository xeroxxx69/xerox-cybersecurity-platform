import {
  ThreatReport,
  ScanHistoryItem,
  StatsSummary,
} from "@/types";
import { getStoredToken } from "@/features/auth/tokenStorage";
import { getApiBaseUrl, isBackendConfigured } from "./apiConfig";
import {
  safeFetchWithDiagnostics,
  parseJsonSafely,
  extractCorrelationId,
} from "./apiError";
import {
  analyzeUrlClientSide,
  analyzeMessageClientSide,
  analyzeFileClientSide,
  analyzeScreenshotClientSide,
} from "./clientEngine";
import {
  saveGuestScan,
  getGuestHistory,
  getGuestReport,
  getGuestStats,
} from "./guestStorage";

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
  // If backend is not configured, operate in Edge Standalone Mode with zero failed network calls
  if (!isBackendConfigured()) {
    return {
      status: "standalone",
      service: "XEROX Autonomous Edge Engine",
      version: "1.0.0",
      database: "IndexedDB / Local Storage",
      cache: "Active",
      checks: {
        engine: "active",
        storage: "connected",
        mode: "standalone_edge",
      },
      baseUrl: "Client-Side Standalone Engine",
      latencyMs: 0,
    };
  }

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
  // Edge Standalone Mode (Zero external dependencies)
  if (!isBackendConfigured()) {
    const report = analyzeUrlClientSide(url);
    saveGuestScan(report);
    return report;
  }

  const targetUrl = `${getApiBaseUrl()}/analyze/url`;
  try {
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
    const report = await parseJsonSafely<ThreatReport>(res, targetUrl);
    saveGuestScan(report);
    return report;
  } catch (err) {
    console.warn("Backend enclave analysis failed, executing Edge Sandbox fallback:", err);
    const fallbackReport = analyzeUrlClientSide(url);
    saveGuestScan(fallbackReport);
    return fallbackReport;
  }
}

export async function scanMessage(
  content: string,
  senderMetadata?: string,
  subject?: string,
  sender?: string
): Promise<ThreatReport> {
  if (!isBackendConfigured()) {
    const report = analyzeMessageClientSide(content);
    saveGuestScan(report);
    return report;
  }

  const targetUrl = `${getApiBaseUrl()}/analyze/message`;
  try {
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
    const report = await parseJsonSafely<ThreatReport>(res, targetUrl);
    saveGuestScan(report);
    return report;
  } catch (err) {
    console.warn("Backend enclave analysis failed, executing Edge Sandbox fallback:", err);
    const fallbackReport = analyzeMessageClientSide(content);
    saveGuestScan(fallbackReport);
    return fallbackReport;
  }
}

export async function scanScreenshot(file: File): Promise<ThreatReport> {
  if (!isBackendConfigured()) {
    const report = await analyzeScreenshotClientSide(file);
    saveGuestScan(report);
    return report;
  }

  const targetUrl = `${getApiBaseUrl()}/analyze/screenshot`;
  const formData = new FormData();
  formData.append("file", file);

  try {
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
    const report = await parseJsonSafely<ThreatReport>(res, targetUrl);
    saveGuestScan(report);
    return report;
  } catch (err) {
    console.warn("Backend enclave screenshot scan failed, executing Edge Sandbox fallback:", err);
    const fallbackReport = await analyzeScreenshotClientSide(file);
    saveGuestScan(fallbackReport);
    return fallbackReport;
  }
}

export async function scanFile(file: File): Promise<ThreatReport> {
  if (!isBackendConfigured()) {
    const report = await analyzeFileClientSide(file);
    saveGuestScan(report);
    return report;
  }

  const targetUrl = `${getApiBaseUrl()}/analyze/file`;
  const formData = new FormData();
  formData.append("file", file);

  try {
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
    const report = await parseJsonSafely<ThreatReport>(res, targetUrl);
    saveGuestScan(report);
    return report;
  } catch (err) {
    console.warn("Backend enclave file scan failed, executing Edge Sandbox fallback:", err);
    const fallbackReport = await analyzeFileClientSide(file);
    saveGuestScan(fallbackReport);
    return fallbackReport;
  }
}

export async function getHistory(limit: number = 50): Promise<ScanHistoryItem[]> {
  if (!isBackendConfigured()) {
    return getGuestHistory().slice(0, limit);
  }

  const targetUrl = `${getApiBaseUrl()}/analyze/history?limit=${limit}`;
  try {
    const res = await safeFetchWithDiagnostics(
      targetUrl,
      {
        headers: getAuthHeaders(),
        credentials: "include",
        cache: "no-store",
      },
      15000
    );
    return await parseJsonSafely<ScanHistoryItem[]>(res, targetUrl);
  } catch {
    return getGuestHistory().slice(0, limit);
  }
}

export async function getReport(scanId: string): Promise<ThreatReport> {
  // First check local guest storage
  const localReport = getGuestReport(scanId);
  if (localReport) {
    return localReport;
  }

  if (!isBackendConfigured()) {
    throw new Error(`Security investigation report '${scanId}' not found in local browser storage.`);
  }

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
  if (!isBackendConfigured()) {
    return getGuestStats();
  }

  const targetUrl = `${getApiBaseUrl()}/analyze/stats/summary`;
  try {
    const res = await safeFetchWithDiagnostics(
      targetUrl,
      {
        headers: getAuthHeaders(),
        credentials: "include",
        cache: "no-store",
      },
      15000
    );
    return await parseJsonSafely<StatsSummary>(res, targetUrl);
  } catch {
    return getGuestStats();
  }
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
  if (!isBackendConfigured()) {
    return {
      id: "local_feedback_" + Date.now(),
      scan_id: feedback.scan_id,
      is_accurate: feedback.is_accurate,
      user_notes: feedback.user_notes,
      suggested_label: feedback.suggested_label,
      submitted_at: new Date().toISOString(),
    };
  }

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
