import React, { createContext, useContext, useEffect, useRef, useState } from "react";
import { clearStoredToken, getStoredToken, setStoredToken } from "./tokenStorage";
import { getApiBaseUrl, validateApiUrl, isBackendConfigured } from "@/services/apiConfig";

export interface User {
  id: string;
  email: string;
  created_at: string;
}

export type AuthErrorKind =
  | "BACKEND_UNREACHABLE"
  | "NETWORK_ERROR"
  | "CONFIG_INVALID"
  | "INVALID_CREDENTIALS"
  | "RATE_LIMITED"
  | "SESSION_EXPIRED"
  | "REQUEST_TIMEOUT"
  | "SERVER_ERROR"
  | "REGISTRATION_DUPLICATE"
  | "VALIDATION_ERROR"
  | "UNKNOWN";

export class AuthError extends Error {
  kind: AuthErrorKind;
  statusCode?: number;
  targetUrl?: string;

  constructor(message: string, kind: AuthErrorKind, statusCode?: number, targetUrl?: string) {
    super(message);
    this.name = "AuthError";
    this.kind = kind;
    this.statusCode = statusCode;
    this.targetUrl = targetUrl;
  }
}

interface AuthContextType {
  user: User | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<void>;
  register: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  refreshUser: () => Promise<void>;
  apiBaseUrl: string;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

async function fetchAuthWithDiagnostics(
  endpoint: string,
  options: RequestInit,
  timeoutMs: number = 15000
): Promise<Response> {
  if (!isBackendConfigured()) {
    throw new AuthError(
      "No backend security enclave configured. Cloud authentication is optional and requires an HTTPS backend enclave. You can use all security analysis features as a Guest.",
      "CONFIG_INVALID",
      undefined,
      ""
    );
  }

  const baseUrl = getApiBaseUrl();
  const validation = validateApiUrl(baseUrl);
  if (!validation.isValid) {
    throw new AuthError(
      validation.error || "Invalid API configuration detected.",
      "CONFIG_INVALID",
      undefined,
      baseUrl
    );
  }

  const cleanEndpoint = endpoint.startsWith("/") ? endpoint : `/${endpoint}`;
  const fullUrl = `${baseUrl}${cleanEndpoint}`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetch(fullUrl, {
      ...options,
      signal: controller.signal,
    });
    return res;
  } catch (err: any) {
    if (err.name === "AbortError") {
      throw new AuthError(
        `Security enclave request timed out after ${timeoutMs / 1000}s. Server may be starting or experiencing high load.`,
        "REQUEST_TIMEOUT",
        408,
        fullUrl
      );
    }

    const isOnline = typeof navigator !== "undefined" ? navigator.onLine : true;
    if (!isOnline) {
      throw new AuthError(
        "Network connection lost. Please verify your internet connection.",
        "NETWORK_ERROR",
        undefined,
        fullUrl
      );
    }

    throw new AuthError(
      `Unable to reach the backend security enclave at ${baseUrl}. The server may be stopped, offline, or inaccessible.`,
      "BACKEND_UNREACHABLE",
      undefined,
      fullUrl
    );
  } finally {
    clearTimeout(timer);
  }
}

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const reqSeq = useRef(0);

  const refreshUser = async () => {
    const seq = ++reqSeq.current;

    // In Standalone Edge mode (no backend configured), skip network auth checks silently
    if (!isBackendConfigured()) {
      if (seq === reqSeq.current) {
        setUser(null);
        setLoading(false);
      }
      return;
    }

    try {
      const token = getStoredToken();
      if (!token) {
        if (seq === reqSeq.current) {
          setUser(null);
          setLoading(false);
        }
        return;
      }

      const headers: Record<string, string> = {
        Authorization: `Bearer ${token}`,
      };

      const res = await fetchAuthWithDiagnostics(
        "/auth/me",
        {
          method: "GET",
          credentials: "include",
          headers,
          cache: "no-store",
        },
        8000
      );

      if (seq !== reqSeq.current) return;

      if (res.ok) {
        const data = await res.json();
        setUser(data);
      } else {
        clearStoredToken();
        setUser(null);
      }
    } catch {
      if (seq === reqSeq.current) {
        setUser(null);
      }
    } finally {
      if (seq === reqSeq.current) {
        setLoading(false);
      }
    }
  };

  useEffect(() => {
    refreshUser();
  }, []);

  const login = async (email: string, password: string) => {
    reqSeq.current++;
    const res = await fetchAuthWithDiagnostics("/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      cache: "no-store",
      body: JSON.stringify({ email, password }),
    });

    if (!res.ok) {
      let detail = "";
      try {
        const errJson = await res.json();
        if (typeof errJson?.detail === "string") {
          detail = errJson.detail;
        } else if (Array.isArray(errJson?.detail)) {
          detail = errJson.detail.map((d: any) => d.msg || "").filter(Boolean).join("; ");
        }
      } catch {
        detail = "";
      }

      if (res.status === 401) {
        throw new AuthError(
          "Incorrect operational email or security key.",
          "INVALID_CREDENTIALS",
          401,
          getApiBaseUrl()
        );
      }
      if (res.status === 429) {
        throw new AuthError(
          detail || "Too many authentication attempts. Please wait 5 minutes before retrying.",
          "RATE_LIMITED",
          429,
          getApiBaseUrl()
        );
      }
      if (res.status >= 500) {
        throw new AuthError(
          `Security enclave server error (HTTP ${res.status}). Please check backend logs or retry.`,
          "SERVER_ERROR",
          res.status,
          getApiBaseUrl()
        );
      }
      throw new AuthError(
        detail || "Authentication failed. Please verify credentials.",
        "UNKNOWN",
        res.status,
        getApiBaseUrl()
      );
    }

    const userData = await res.json();
    if (userData.session_token) {
      setStoredToken(userData.session_token);
    }
    setUser(userData);
  };

  const register = async (email: string, password: string) => {
    reqSeq.current++;
    const res = await fetchAuthWithDiagnostics("/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      cache: "no-store",
      body: JSON.stringify({ email, password }),
    });

    if (!res.ok) {
      let detail = "";
      try {
        const errJson = await res.json();
        if (typeof errJson?.detail === "string") {
          detail = errJson.detail;
        } else if (Array.isArray(errJson?.detail)) {
          detail = errJson.detail.map((d: any) => d.msg || "").filter(Boolean).join("; ");
        }
      } catch {
        detail = "";
      }

      if (
        res.status === 400 &&
        (detail.toLowerCase().includes("already exists") ||
          detail.toLowerCase().includes("already registered"))
      ) {
        throw new AuthError(
          "An account with this email address already exists. Please sign in instead.",
          "REGISTRATION_DUPLICATE",
          400,
          getApiBaseUrl()
        );
      }
      if (res.status === 422) {
        throw new AuthError(
          detail || "Invalid registration information. Please check requirements.",
          "VALIDATION_ERROR",
          422,
          getApiBaseUrl()
        );
      }
      if (res.status >= 500) {
        throw new AuthError(
          `Security enclave server error during registration (HTTP ${res.status}).`,
          "SERVER_ERROR",
          res.status,
          getApiBaseUrl()
        );
      }
      throw new AuthError(
        detail || "Registration failed. Please try again.",
        "UNKNOWN",
        res.status,
        getApiBaseUrl()
      );
    }

    // Automatically establish session via login
    await login(email, password);
  };

  const logout = async () => {
    reqSeq.current++;
    const token = getStoredToken();
    const headers: Record<string, string> = {};
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }

    try {
      await fetchAuthWithDiagnostics(
        "/auth/logout",
        {
          method: "POST",
          credentials: "include",
          headers,
          cache: "no-store",
        },
        5000
      );
    } catch {
      // Clean up locally regardless of network outcome
    } finally {
      clearStoredToken();
      setUser(null);
    }
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        loading,
        login,
        register,
        logout,
        refreshUser,
        apiBaseUrl: getApiBaseUrl(),
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}
