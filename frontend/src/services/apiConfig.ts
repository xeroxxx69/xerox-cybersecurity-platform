/**
 * XEROX Cybersecurity Platform — Centralized API Configuration & Validation
 *
 * Ensures a single, validated API endpoint across the entire application.
 * Prevents accidental localhost targeting in production, normalizes URL formats,
 * and allows dynamic runtime fallback/override for hosted environments.
 */

export interface ApiValidationResult {
  isValid: boolean;
  error?: string;
  isLocalhostInProd?: boolean;
}

export interface ApiDiagnostics {
  baseUrl: string;
  source: "runtime_override" | "env_var" | "github_pages_default" | "local_dev_proxy";
  environment: string;
  isProduction: boolean;
  isValid: boolean;
  validationError?: string;
}

const STORAGE_KEY_CUSTOM_API = "xerox_custom_api_url";

// Default production backend endpoint (deployed Railway API)
export const DEFAULT_PRODUCTION_API = "https://web-production-69de4.up.railway.app/api/v1";

/**
 * Safely retrieves an environment variable across Vite and Node.js environments.
 */
export function getEnvVar(key: string): string | undefined {
  try {
    if (typeof import.meta !== "undefined" && (import.meta as any).env) {
      const val = (import.meta as any).env[key];
      if (typeof val === "string") return val;
    }
  } catch {
    // import.meta.env not available
  }

  try {
    if (typeof process !== "undefined" && process.env) {
      const val = process.env[key];
      if (typeof val === "string") return val;
    }
  } catch {
    // process.env not available
  }

  return undefined;
}

/**
 * Safely determines if running in production mode.
 */
export function isProductionMode(): boolean {
  try {
    if (typeof import.meta !== "undefined" && (import.meta as any).env?.PROD !== undefined) {
      return Boolean((import.meta as any).env.PROD);
    }
  } catch {
    // fallback
  }

  try {
    if (typeof process !== "undefined" && process.env?.NODE_ENV) {
      return process.env.NODE_ENV === "production";
    }
  } catch {
    // fallback
  }

  return false;
}

/**
 * Validates a candidate API Base URL.
 * Enforces valid URL scheme, format, and forbids localhost in production.
 */
export function validateApiUrl(
  url: string,
  isProd: boolean = isProductionMode()
): ApiValidationResult {
  if (!url || typeof url !== "string") {
    return { isValid: false, error: "API URL must be a non-empty string." };
  }

  const trimmed = url.trim();

  // Allow relative paths only in development/preview
  if (trimmed.startsWith("/")) {
    if (isProd && typeof window !== "undefined" && window.location.hostname.endsWith("github.io")) {
      return {
        isValid: false,
        error: "Relative API paths are not supported on static GitHub Pages hosting. A full HTTPS URL is required.",
      };
    }
    return { isValid: true };
  }

  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    return { isValid: false, error: `Malformed API URL: "${trimmed}". Must be a valid HTTP or HTTPS URL.` };
  }

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return {
      isValid: false,
      error: `Invalid protocol "${parsed.protocol}". API URL must use HTTP or HTTPS.`,
    };
  }

  const isLocalhost =
    parsed.hostname === "localhost" ||
    parsed.hostname === "127.0.0.1" ||
    parsed.hostname === "0.0.0.0" ||
    parsed.hostname.endsWith(".local");

  if (isProd && isLocalhost) {
    return {
      isValid: false,
      isLocalhostInProd: true,
      error: `Localhost API URL ("${trimmed}") is not accessible from a public production deployment. Please configure an HTTPS backend URL.`,
    };
  }

  if (isProd && parsed.protocol === "http:" && !isLocalhost) {
    return {
      isValid: false,
      error: `Insecure HTTP API URL ("${trimmed}") blocked in production. Modern browsers require HTTPS for cross-origin APIs to prevent Mixed Content security blocks.`,
    };
  }

  return { isValid: true };
}

/**
 * Normalizes an API base URL (strips trailing slashes).
 */
export function normalizeApiUrl(url: string): string {
  return url.trim().replace(/\/+$/, "");
}

/**
 * Resolves the active API Base URL using prioritized sources:
 * 1. Runtime override from localStorage (analyst-configured via UI)
 * 2. Window global override (window.__XEROX_API_URL__)
 * 3. Build-time environment variable (VITE_API_URL)
 * 4. GitHub Pages production fallback (DEFAULT_PRODUCTION_API)
 * 5. Local development fallback ("/api/v1")
 */
export function getApiBaseUrl(): string {
  // 1. Runtime override in localStorage
  if (typeof window !== "undefined") {
    try {
      const stored = localStorage.getItem(STORAGE_KEY_CUSTOM_API);
      if (stored && stored.trim()) {
        const validated = validateApiUrl(stored);
        if (validated.isValid) {
          return normalizeApiUrl(stored);
        }
      }
    } catch {
      // localStorage may be inaccessible in restrictive sandboxes
    }

    // 2. Window global override
    const windowOverride = (window as any).__XEROX_API_URL__;
    if (typeof windowOverride === "string" && windowOverride.trim()) {
      const validated = validateApiUrl(windowOverride);
      if (validated.isValid) {
        return normalizeApiUrl(windowOverride);
      }
    }
  }

  // 3. Build-time environment variable
  const envUrl = getEnvVar("VITE_API_URL");
  if (envUrl && envUrl.trim()) {
    const validated = validateApiUrl(envUrl);
    if (validated.isValid) {
      return normalizeApiUrl(envUrl);
    }
  }

  // 4. GitHub Pages production default
  if (typeof window !== "undefined" && window.location.hostname.endsWith("github.io")) {
    return DEFAULT_PRODUCTION_API;
  }

  // 5. Local development Vite proxy
  return "/api/v1";
}

/**
 * Updates or clears the analyst's custom runtime API base URL.
 */
export function setCustomApiUrl(url: string | null): ApiValidationResult {
  if (url === null || url.trim() === "") {
    if (typeof window !== "undefined") {
      try {
        localStorage.removeItem(STORAGE_KEY_CUSTOM_API);
      } catch {
        // ignore
      }
    }
    return { isValid: true };
  }

  const validation = validateApiUrl(url);
  if (!validation.isValid) {
    return validation;
  }

  if (typeof window !== "undefined") {
    try {
      localStorage.setItem(STORAGE_KEY_CUSTOM_API, normalizeApiUrl(url));
    } catch {
      // ignore
    }
  }
  return { isValid: true };
}

/**
 * Returns diagnostic metadata about the current API configuration.
 */
export function getApiDiagnostics(): ApiDiagnostics {
  let source: ApiDiagnostics["source"] = "local_dev_proxy";
  let rawUrl = "/api/v1";

  if (typeof window !== "undefined") {
    try {
      const stored = localStorage.getItem(STORAGE_KEY_CUSTOM_API);
      if (stored && stored.trim()) {
        rawUrl = stored;
        source = "runtime_override";
      }
    } catch {
      // ignore
    }
  }

  if (source === "local_dev_proxy") {
    const envUrl = getEnvVar("VITE_API_URL");
    if (envUrl && envUrl.trim()) {
      rawUrl = envUrl;
      source = "env_var";
    } else if (typeof window !== "undefined" && window.location.hostname.endsWith("github.io")) {
      rawUrl = DEFAULT_PRODUCTION_API;
      source = "github_pages_default";
    }
  }

  const isProd = isProductionMode();
  const validation = validateApiUrl(rawUrl, isProd);

  return {
    baseUrl: getApiBaseUrl(),
    source,
    environment: isProd ? "production" : "development",
    isProduction: isProd,
    isValid: validation.isValid,
    validationError: validation.error,
  };
}

export const API_BASE = getApiBaseUrl();
