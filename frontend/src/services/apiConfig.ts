/**
 * XEROX Cybersecurity Platform — Centralized API Configuration & Validation
 *
 * Ensures a single, validated API endpoint across the entire application.
 * Prevents accidental localhost targeting in production, normalizes URL formats,
 * rejects obsolete/placeholder hosts, and guarantees zero-dependency Edge Standalone Mode.
 */

export interface ApiValidationResult {
  isValid: boolean;
  error?: string;
  isEmpty?: boolean;
  isPlaceholder?: boolean;
  isLocalhostInProd?: boolean;
}

export type ApiConfigSource =
  | "runtime_override"
  | "window_override"
  | "env_var"
  | "standalone_default"
  | "local_dev_proxy";

export interface ApiDiagnostics {
  baseUrl: string;
  source: ApiConfigSource;
  sourceLabel: string;
  isConfigured: boolean;
  isStandalone: boolean;
  environment: "production" | "development";
  isProduction: boolean;
  isValid: boolean;
  validationError?: string;
}

const STORAGE_KEY_CUSTOM_API = "xerox_custom_api_url";

// Default production backend endpoint: empty by default (enables zero-latency Edge Standalone Mode)
// When an analyst configures a custom backend or sets VITE_API_URL, it automatically connects.
export const DEFAULT_PRODUCTION_API = "";

const PLACEHOLDER_PATTERNS = [
  "your-backend",
  "yourdomain.com",
  "example.com",
  "your-api",
  "my-backend",
  "<your-",
  "{backend}",
  "placeholder",
  "web-production-69de4.up.railway.app",
];

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
 * Enforces valid URL scheme, format, and rejects placeholders, obsolete hosts, and localhost in production.
 */
export function validateApiUrl(
  url: string,
  isProd: boolean = isProductionMode()
): ApiValidationResult {
  if (!url || typeof url !== "string" || !url.trim()) {
    return {
      isValid: false,
      isEmpty: true,
      error: "API URL cannot be empty when configuring a backend enclave.",
    };
  }

  const trimmed = url.trim();
  const lower = trimmed.toLowerCase();

  // 1. Placeholder & obsolete pattern detection
  for (const placeholder of PLACEHOLDER_PATTERNS) {
    if (lower.includes(placeholder)) {
      return {
        isValid: false,
        isPlaceholder: true,
        error: `Placeholder or obsolete URL detected ("${trimmed}"). Please configure a live HTTPS backend or leave empty for Standalone Edge Mode.`,
      };
    }
  }

  if (lower.includes(".up.railway.app")) {
    return {
      isValid: false,
      isPlaceholder: true,
      error: `Railway backend hosting has been decommissioned. Please configure a live HTTPS backend or leave empty for Standalone Edge Mode.`,
    };
  }

  // 2. Allow relative paths only in development/preview
  if (trimmed.startsWith("/")) {
    if (isProd && typeof window !== "undefined" && window.location.hostname.endsWith("github.io")) {
      return {
        isValid: false,
        error: "Relative API paths are not supported on static GitHub Pages hosting. A full HTTPS URL is required.",
      };
    }
    return { isValid: true };
  }

  // 3. Full URL Parsing
  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    return {
      isValid: false,
      error: `Malformed API URL: "${trimmed}". Must be a valid HTTP or HTTPS URL.`,
    };
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
 * Normalizes an API base URL (strips trailing slashes, ensures /api/v1 suffix).
 */
export function normalizeApiUrl(url: string): string {
  if (!url || typeof url !== "string") return "";
  const trimmed = url.trim().replace(/\/+$/, "");
  if (!trimmed) return "";

  if (trimmed.startsWith("/")) {
    if (trimmed === "/" || trimmed === "/api") return "/api/v1";
    return trimmed;
  }

  try {
    const parsed = new URL(trimmed);
    let pathname = parsed.pathname.replace(/\/+$/, "");

    if (pathname === "" || pathname === "/") {
      pathname = "/api/v1";
    } else if (pathname === "/api") {
      pathname = "/api/v1";
    }

    parsed.pathname = pathname;
    return parsed.toString().replace(/\/+$/, "");
  } catch {
    return trimmed;
  }
}

/**
 * Resolves the active API Base URL using prioritized sources:
 * 1. Runtime override from localStorage (analyst-configured via UI)
 * 2. Window global override (window.__XEROX_API_URL__)
 * 3. Build-time environment variable (VITE_API_URL)
 * 4. GitHub Pages production default (DEFAULT_PRODUCTION_API = "")
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
        } else {
          // Stale, malformed, or placeholder stored URL — clean it up automatically
          localStorage.removeItem(STORAGE_KEY_CUSTOM_API);
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

  // 4. GitHub Pages / static production default (Edge Standalone Mode)
  if (typeof window !== "undefined" && (window.location.hostname.endsWith("github.io") || isProductionMode())) {
    return DEFAULT_PRODUCTION_API;
  }

  // 5. Local development Vite proxy
  return "/api/v1";
}

/**
 * Determines whether an active external backend API is configured.
 * Returns false when operating in Edge Standalone Mode or if pointing to an obsolete/placeholder host.
 */
export function isBackendConfigured(): boolean {
  const url = getApiBaseUrl();
  if (!url || typeof url !== "string" || !url.trim()) return false;
  const validation = validateApiUrl(url);
  return validation.isValid;
}

/**
 * Updates or clears the analyst's custom runtime API base URL.
 * Passing null or empty string resets to Edge Standalone Mode.
 */
export function setCustomApiUrl(url: string | null): ApiValidationResult {
  if (url === null || url === undefined || url.trim() === "") {
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
  let source: ApiConfigSource = "local_dev_proxy";
  let sourceLabel = "Local Dev Proxy (/api/v1)";
  let rawUrl = "/api/v1";

  if (typeof window !== "undefined") {
    try {
      const stored = localStorage.getItem(STORAGE_KEY_CUSTOM_API);
      if (stored && stored.trim()) {
        const validation = validateApiUrl(stored);
        if (validation.isValid) {
          rawUrl = stored;
          source = "runtime_override";
          sourceLabel = "Analyst Custom Enclave (Saved in Browser Storage)";
        } else {
          localStorage.removeItem(STORAGE_KEY_CUSTOM_API);
        }
      }
    } catch {
      // ignore
    }

    if (source === "local_dev_proxy") {
      const windowOverride = (window as any).__XEROX_API_URL__;
      if (typeof windowOverride === "string" && windowOverride.trim()) {
        const validation = validateApiUrl(windowOverride);
        if (validation.isValid) {
          rawUrl = windowOverride;
          source = "window_override";
          sourceLabel = "Window Global Override";
        }
      }
    }
  }

  if (source === "local_dev_proxy") {
    const envUrl = getEnvVar("VITE_API_URL");
    if (envUrl && envUrl.trim()) {
      const validation = validateApiUrl(envUrl);
      if (validation.isValid) {
        rawUrl = envUrl;
        source = "env_var";
        sourceLabel = "Build Environment Variable (VITE_API_URL)";
      }
    } else if (typeof window !== "undefined" && (window.location.hostname.endsWith("github.io") || isProductionMode())) {
      rawUrl = DEFAULT_PRODUCTION_API;
      source = "standalone_default";
      sourceLabel = "Standalone Edge Mode (GitHub Pages Default)";
    }
  }

  const isProd = isProductionMode();
  const configured = isBackendConfigured();
  const isStandalone = !configured;

  const isValid = isStandalone ? true : validateApiUrl(rawUrl, isProd).isValid;
  const validationError = isStandalone ? undefined : validateApiUrl(rawUrl, isProd).error;

  return {
    baseUrl: getApiBaseUrl(),
    source,
    sourceLabel,
    isConfigured: configured,
    isStandalone,
    environment: isProd ? "production" : "development",
    isProduction: isProd,
    isValid,
    validationError,
  };
}

export const API_BASE = getApiBaseUrl();
