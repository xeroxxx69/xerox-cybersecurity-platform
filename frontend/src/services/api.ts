import {
  ThreatReport,
  ScanHistoryItem,
  StatsSummary,
} from "@/types";
import { getStoredToken } from "@/features/auth/tokenStorage";

import { getApiBaseUrl } from "./apiConfig";

function getAuthHeaders(extraHeaders: Record<string, string> = {}): Record<string, string> {
  const headers: Record<string, string> = { ...extraHeaders };
  const token = getStoredToken();
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }
  return headers;
}

export async function checkBackendHealth(): Promise<{
  status: string;
  service: string;
  version: string;
  database?: string;
  redis?: Record<string, string>;
  baseUrl?: string;
}> {
  const baseUrl = getApiBaseUrl();
  try {
    const res = await fetch(`${baseUrl}/health`, {
      headers: getAuthHeaders(),
      credentials: "include",
    });
    if (!res.ok) {
      throw new Error(`Health check returned HTTP ${res.status}: ${res.statusText}`);
    }
    const data = await res.json();
    return { ...data, baseUrl };
  } catch (err: any) {
    throw new Error(`Backend unavailable at ${baseUrl}: ${err.message || "Connection failed"}`);
  }
}

export async function scanUrl(url: string): Promise<ThreatReport> {
  const res = await fetch(`${getApiBaseUrl()}/analyze/url`, {
    method: "POST",
    headers: getAuthHeaders({ "Content-Type": "application/json" }),
    credentials: "include",
    body: JSON.stringify({ url, deep_scan: true }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: "Scan failed" }));
    throw new Error(err.detail || "URL scan failed");
  }
  return res.json();
}

export async function scanMessage(
  content: string,
  senderMetadata?: string,
  subject?: string,
  sender?: string
): Promise<ThreatReport> {
  const res = await fetch(`${getApiBaseUrl()}/analyze/message`, {
    method: "POST",
    headers: getAuthHeaders({ "Content-Type": "application/json" }),
    credentials: "include",
    body: JSON.stringify({
      content,
      sender_metadata: senderMetadata,
      subject,
      sender,
    }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: "Scan failed" }));
    throw new Error(err.detail || "Message scan failed");
  }
  return res.json();
}

export async function scanScreenshot(file: File): Promise<ThreatReport> {
  const formData = new FormData();
  formData.append("file", file);

  const res = await fetch(`${getApiBaseUrl()}/analyze/screenshot`, {
    method: "POST",
    headers: getAuthHeaders(),
    credentials: "include",
    body: formData,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: "Screenshot scan failed" }));
    throw new Error(err.detail || "Screenshot scan failed");
  }
  return res.json();
}

export async function scanFile(file: File): Promise<ThreatReport> {
  const formData = new FormData();
  formData.append("file", file);

  const res = await fetch(`${getApiBaseUrl()}/analyze/file`, {
    method: "POST",
    headers: getAuthHeaders(),
    credentials: "include",
    body: formData,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: "File scan failed" }));
    throw new Error(err.detail || "File scan failed");
  }
  return res.json();
}

export async function getHistory(limit: number = 50): Promise<ScanHistoryItem[]> {
  const res = await fetch(`${getApiBaseUrl()}/analyze/history?limit=${limit}`, {
    headers: getAuthHeaders(),
    credentials: "include",
  });
  if (!res.ok) {
    throw new Error("Failed to load scan history");
  }
  return res.json();
}

export async function getReport(scanId: string): Promise<ThreatReport> {
  const res = await fetch(`${getApiBaseUrl()}/analyze/${scanId}`, {
    headers: getAuthHeaders(),
    credentials: "include",
  });
  if (!res.ok) {
    throw new Error("Report not found");
  }
  return res.json();
}

export async function getStats(): Promise<StatsSummary> {
  const res = await fetch(`${getApiBaseUrl()}/analyze/stats/summary`, {
    headers: getAuthHeaders(),
    credentials: "include",
  });
  if (!res.ok) {
    throw new Error("Failed to load telemetry stats");
  }
  return res.json();
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
  const res = await fetch(`${getApiBaseUrl()}/feedback`, {
    method: "POST",
    headers: getAuthHeaders({ "Content-Type": "application/json" }),
    credentials: "include",
    body: JSON.stringify(feedback),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: "Feedback submission failed" }));
    throw new Error(err.detail || "Feedback submission failed");
  }
  return res.json();
}
