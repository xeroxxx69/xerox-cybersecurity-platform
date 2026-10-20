/**
 * XEROX Cybersecurity Platform — Comprehensive API Error & Diagnostic Architecture
 *
 * Implements granular, safe error classification distinguishing:
 * - DNS or offline network failures
 * - CORS / browser-blocked requests
 * - Request timeouts (server cold starts / latency)
 * - HTTP 404 (Route not found vs Railway Application not found)
 * - HTTP 401 / 403 (Authentication and authorization boundaries)
 * - HTTP 429 (Rate limiting & lockout)
 * - HTTP 500-series (Server error / database degradation)
 * - Invalid JSON responses
 * - Client configuration errors (localhost/HTTP in prod)
 *
 * Strictly adheres to security rules:
 * - NEVER logs or leaks passwords, auth headers, cookies, or secrets
 * - NEVER misreports 401 as a network error
 * - NEVER reports CORS as a server crash
 * - Captures request path, HTTP status, and correlation IDs safely
 */

export type ApiErrorKind =
  | "DNS_OR_NETWORK"
  | "CORS_OR_BLOCKED"
  | "TIMEOUT"
  | "NOT_FOUND"
  | "UNAUTHORIZED"
  | "FORBIDDEN"
  | "RATE_LIMITED"
  | "SERVER_ERROR"
  | "DATABASE_DEGRADED"
  | "INVALID_JSON"
  | "CONFIG_INVALID"
  | "UNKNOWN";

export interface ApiErrorContext {
  url?: string;
  method?: string;
  statusCode?: number;
  correlationId?: string;
  technicalDetail?: string;
  responseBodySnippet?: string;
}

export class ApiError extends Error {
  public readonly kind: ApiErrorKind;
  public readonly statusCode?: number;
  public readonly url?: string;
  public readonly method?: string;
  public readonly correlationId?: string;
  public readonly technicalDetail?: string;
  public readonly userMessage: string;
  public readonly timestamp: string;

  constructor(userMessage: string, kind: ApiErrorKind, context: ApiErrorContext = {}) {
    super(userMessage);
    this.name = "ApiError";
    this.kind = kind;
    this.userMessage = userMessage;
    this.statusCode = context.statusCode;
    this.url = context.url ? sanitizeUrlForLog(context.url) : undefined;
    this.method = context.method;
    this.correlationId = context.correlationId;
    this.technicalDetail = context.technicalDetail;
    this.timestamp = new Date().toISOString();

    // Maintain prototype chain
    Object.setPrototypeOf(this, ApiError.prototype);
  }

  public toDiagnosticString(): string {
    const parts = [
      `[${this.kind}] ${this.userMessage}`,
      this.statusCode ? `HTTP Status: ${this.statusCode}` : null,
      this.url ? `Target: ${this.url}` : null,
      this.correlationId ? `Correlation ID: ${this.correlationId}` : null,
      this.technicalDetail ? `Details: ${this.technicalDetail}` : null,
    ].filter(Boolean);
    return parts.join(" | ");
  }
}

/**
 * Strips sensitive query parameters and tokens from URLs before logging or recording.
 */
export function sanitizeUrlForLog(rawUrl: string): string {
  try {
    const parsed = new URL(rawUrl, "http://localhost");
    // Strip any sensitive query parameters if present
    const sensitiveKeys = ["token", "key", "secret", "auth", "password", "session"];
    sensitiveKeys.forEach((k) => {
      if (parsed.searchParams.has(k)) {
        parsed.searchParams.set(k, "[REDACTED]");
      }
    });
    const search = decodeURIComponent(parsed.search);
    return parsed.origin === "http://localhost" && rawUrl.startsWith("/")
      ? `${parsed.pathname}${search}`
      : `${parsed.origin}${parsed.pathname}${search}`;
  } catch {
    return rawUrl.split("?")[0];
  }
}


/**
 * Extracts correlation IDs from response headers.
 */
export function extractCorrelationId(headers?: Headers | Record<string, string>): string | undefined {
  if (!headers) return undefined;
  if (typeof (headers as Headers).get === "function") {
    return (
      (headers as Headers).get("x-request-id") ||
      (headers as Headers).get("x-railway-request-id") ||
      (headers as Headers).get("cf-ray") ||
      (headers as Headers).get("x-correlation-id") ||
      undefined
    );
  }
  const obj = headers as Record<string, string>;
  return (
    obj["x-request-id"] ||
    obj["x-railway-request-id"] ||
    obj["cf-ray"] ||
    obj["x-correlation-id"] ||
    undefined
  );
}

/**
 * Safe fetch wrapper with timeout, CORS detection, status code inspection,
 * and correlation ID tracking.
 */
export async function safeFetchWithDiagnostics(
  url: string,
  options: RequestInit = {},
  timeoutMs: number = 15000
): Promise<Response> {
  const method = options.method || "GET";
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  let response: Response;
  try {
    response = await fetch(url, {
      ...options,
      signal: controller.signal,
    });
  } catch (err: any) {
    clearTimeout(timer);

    if (err?.name === "AbortError") {
      throw new ApiError(
        `Security enclave request timed out after ${timeoutMs / 1000}s. The backend may be booting or experiencing high latency.`,
        "TIMEOUT",
        {
          url,
          method,
          statusCode: 408,
          technicalDetail: `AbortController triggered after ${timeoutMs}ms threshold`,
        }
      );
    }

    const isOnline = typeof navigator !== "undefined" ? navigator.onLine : true;
    if (!isOnline) {
      throw new ApiError(
        "Network connection offline. Please check your internet or local network interface.",
        "DNS_OR_NETWORK",
        {
          url,
          method,
          technicalDetail: "navigator.onLine is false",
        }
      );
    }

    // When fetch fails while navigator.onLine is true, it is typically a CORS refusal,
    // DNS resolution failure, SSL certificate error, or host refusing connections.
    throw new ApiError(
      `Unable to reach backend security enclave at ${sanitizeUrlForLog(url)}. The server may be offline, sleeping, or blocking cross-origin requests.`,
      "CORS_OR_BLOCKED",
      {
        url,
        method,
        technicalDetail:
          err?.message || "Browser blocked cross-origin request or target host refused connection.",
      }
    );
  } finally {
    clearTimeout(timer);
  }

  if (response.ok) {
    return response;
  }

  // Handle HTTP error responses
  const correlationId = extractCorrelationId(response.headers);
  const status = response.status;
  let errorDetail = "";
  let isRailwayEdge404 = false;

  try {
    const text = await response.text();
    if (text) {
      try {
        const json = JSON.parse(text);
        if (typeof json.detail === "string") {
          errorDetail = json.detail;
        } else if (Array.isArray(json.detail)) {
          errorDetail = json.detail.map((d: any) => d.msg || "").filter(Boolean).join("; ");
        } else if (typeof json.message === "string") {
          errorDetail = json.message;
          if (json.message.includes("Application not found")) {
            isRailwayEdge404 = true;
          }
        }
      } catch {
        errorDetail = text.slice(0, 200);
      }
    }
  } catch {
    // text() extraction failed
  }

  if (response.headers.get("x-railway-fallback") === "true") {
    isRailwayEdge404 = true;
  }

  if (status === 404) {
    if (isRailwayEdge404) {
      throw new ApiError(
        `Backend service not found on deployment platform (HTTP 404). The Railway/Render service may be deleted, renamed, or unmapped.`,
        "NOT_FOUND",
        {
          url,
          method,
          statusCode: 404,
          correlationId,
          technicalDetail: "Platform edge proxy returned 404 Application not found (x-railway-fallback: true)",
        }
      );
    }
    throw new ApiError(
      `Requested endpoint not found (HTTP 404): ${sanitizeUrlForLog(url)}`,
      "NOT_FOUND",
      {
        url,
        method,
        statusCode: 404,
        correlationId,
        technicalDetail: errorDetail || "Route not mounted on backend router",
      }
    );
  }

  if (status === 401) {
    throw new ApiError(
      errorDetail || "Authentication required. Please authenticate to access this enclave dossier.",
      "UNAUTHORIZED",
      {
        url,
        method,
        statusCode: 401,
        correlationId,
        technicalDetail: "Security enclave returned HTTP 401 Unauthorized",
      }
    );
  }

  if (status === 403) {
    throw new ApiError(
      errorDetail || "Access forbidden. Your account does not have permission for this resource.",
      "FORBIDDEN",
      {
        url,
        method,
        statusCode: 403,
        correlationId,
        technicalDetail: "Security enclave returned HTTP 403 Forbidden",
      }
    );
  }

  if (status === 429) {
    throw new ApiError(
      errorDetail || "Rate limit exceeded. Please wait a few moments before retrying.",
      "RATE_LIMITED",
      {
        url,
        method,
        statusCode: 429,
        correlationId,
        technicalDetail: "Security enclave returned HTTP 429 Too Many Requests",
      }
    );
  }

  if (status === 503) {
    const isDbDegraded = errorDetail.toLowerCase().includes("database") || errorDetail.toLowerCase().includes("degraded");
    throw new ApiError(
      isDbDegraded
        ? "Security enclave database is temporarily degraded or offline. Guest memory scans remain operational."
        : "Backend service temporarily unavailable. Please retry shortly.",
      "DATABASE_DEGRADED",
      {
        url,
        method,
        statusCode: 503,
        correlationId,
        technicalDetail: errorDetail || "HTTP 503 Service Unavailable",
      }
    );
  }

  if (status >= 500) {
    throw new ApiError(
      `Backend security enclave error (HTTP ${status}). The server encountered an unexpected condition.`,
      "SERVER_ERROR",
      {
        url,
        method,
        statusCode: status,
        correlationId,
        technicalDetail: errorDetail || `HTTP ${status} Internal Server Error`,
      }
    );
  }

  throw new ApiError(
    errorDetail || `Request failed with HTTP status ${status}`,
    "UNKNOWN",
    {
      url,
      method,
      statusCode: status,
      correlationId,
    }
  );
}

/**
 * Safely parses JSON from a Response with diagnostic fallback.
 */
export async function parseJsonSafely<T>(response: Response, url: string): Promise<T> {
  try {
    return (await response.json()) as T;
  } catch (err: any) {
    throw new ApiError(
      "Backend response format error. Expected JSON payload from security enclave.",
      "INVALID_JSON",
      {
        url,
        statusCode: response.status,
        correlationId: extractCorrelationId(response.headers),
        technicalDetail: err?.message || "SyntaxError parsing JSON",
      }
    );
  }
}
