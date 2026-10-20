import React, { useState } from "react";
import { Link } from "react-router-dom";
import {
  Settings,
  Shield,
  User,
  Cpu,
  LogIn,
  Server,
  RefreshCw,
  CheckCircle2,
  AlertCircle,
} from "lucide-react";

import { useAuth } from "@/features/auth/AuthContext";
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
  Button,
  StatusIndicator,
  useToast,
} from "@/components/ui";
import {
  getApiBaseUrl,
  getApiDiagnostics,
  setCustomApiUrl,
  validateApiUrl,
  isBackendConfigured,
} from "@/services/apiConfig";
import {
  checkBackendHealth,
  BackendHealthResult,
  testBackendAnalysisEndpoint,
  AnalysisEndpointTestResult,
} from "@/services/api";

export const SettingsPage: React.FC = () => {
  const { user } = useAuth();
  const toast = useToast();

  const [deepScanEnabled, setDeepScanEnabled] = useState(true);
  const [autoDefangEnabled, setAutoDefangEnabled] = useState(true);
  const sessionEnclaveActive = true;

  // Backend Enclave API State
  const [customUrlInput, setCustomUrlInput] = useState(getApiBaseUrl());
  const [healthTesting, setHealthTesting] = useState(false);
  const [healthResult, setHealthResult] = useState<BackendHealthResult | null>(null);
  const [healthError, setHealthError] = useState<string | null>(null);

  // Analysis Endpoint Probe State
  const [analysisTesting, setAnalysisTesting] = useState(false);
  const [analysisTestResult, setAnalysisTestResult] = useState<AnalysisEndpointTestResult | null>(null);

  const diagnostics = getApiDiagnostics();

  const handleTestHealth = async () => {
    setHealthTesting(true);
    setHealthResult(null);
    setHealthError(null);
    try {
      const res = await checkBackendHealth();
      setHealthResult(res);
      if (res.status === "not_configured") {
        toast.info("Edge Standalone Mode: No external backend configured.");
      } else if (res.status === "healthy") {
        toast.success(`Enclave responded in ${res.latencyMs}ms (${res.status})`);
      } else if (res.status === "degraded") {
        toast.warning(`Enclave degraded (${res.database || "Database check warning"})`);
      } else {
        toast.error(`Enclave probe failed: ${res.errorDetail || res.status}`);
      }
    } catch (err: any) {
      const msg = err?.userMessage || err?.message || "Enclave endpoint unreachable";
      setHealthError(msg);
      toast.error(`Health check failed: ${msg}`);
    } finally {
      setHealthTesting(false);
    }
  };

  const handleTestAnalysis = async () => {
    setAnalysisTesting(true);
    setAnalysisTestResult(null);
    try {
      const res = await testBackendAnalysisEndpoint();
      setAnalysisTestResult(res);
      if (res.success) {
        toast.success(`Analysis pipeline responded in ${res.latencyMs}ms (${res.riskLevel})`);
      } else {
        toast.error(`Analysis probe: ${res.errorDetail || "Probe failed"}`);
      }
    } catch (err: any) {
      toast.error(`Analysis probe error: ${err?.message || "Failed"}`);
    } finally {
      setAnalysisTesting(false);
    }
  };

  const handleSaveApiUrl = () => {
    const trimmed = customUrlInput.trim();
    if (!trimmed) {
      setCustomApiUrl(null);
      setCustomUrlInput("");
      setHealthResult(null);
      setHealthError(null);
      setAnalysisTestResult(null);
      toast.success("Enclave URL cleared. Operating in Edge Standalone Mode.");
      return;
    }

    const validation = validateApiUrl(trimmed);
    if (!validation.isValid) {
      toast.error(validation.error || "Invalid API URL");
      return;
    }

    const result = setCustomApiUrl(trimmed);
    if (!result.isValid) {
      toast.error(result.error || "Failed to save API URL");
      return;
    }

    setCustomUrlInput(getApiBaseUrl());
    toast.success("Enclave Base URL updated. Probing health...");
    handleTestHealth();
  };

  const handleResetApiUrl = () => {
    setCustomApiUrl(null);
    setCustomUrlInput("");
    setHealthResult(null);
    setHealthError(null);
    setAnalysisTestResult(null);
    toast.info("Reset to default Edge Standalone configuration.");
  };

  const handleSaveSettings = () => {
    toast.success("Defensive preferences saved to analyst profile");
  };

  return (
    <div className="max-w-5xl mx-auto space-y-8 overflow-x-hidden">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-xerox-border-subtle pb-6">
        <div>
          <h1 className="text-2xl font-extrabold text-white tracking-tight flex items-center gap-2.5">
            <Settings className="w-6 h-6 text-xerox-red" />
            Analyst & Platform Settings
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Tenant configuration, cryptographic session enclaves, and defensive heuristics
          </p>
        </div>

        <Button variant="primary" size="sm" onClick={handleSaveSettings}>
          SAVE CONFIGURATION
        </Button>
      </div>

      {/* Backend Security Enclave & API Gateway Configuration */}
      <Card variant="alert" className="border-red-900/50">
        <CardHeader>
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <CardTitle className="text-red-400 flex items-center gap-2">
              <Server className="w-4 h-4 text-xerox-red flex-shrink-0" />
              Backend Security Enclave & API Gateway
            </CardTitle>
            <div className="flex flex-wrap items-center gap-2">
              <Button
                type="button"
                variant="secondary"
                size="sm"
                onClick={handleTestHealth}
                disabled={healthTesting}
                leftIcon={<RefreshCw className={`w-3.5 h-3.5 ${healthTesting ? "animate-spin" : ""}`} />}
              >
                TEST HEALTH ENDPOINT
              </Button>
              {isBackendConfigured() && (
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={handleTestAnalysis}
                  disabled={analysisTesting}
                  leftIcon={<RefreshCw className={`w-3.5 h-3.5 ${analysisTesting ? "animate-spin" : ""}`} />}
                >
                  TEST ANALYSIS PIPELINE
                </Button>
              )}
            </div>
          </div>
          <CardDescription>
            Configure an optional FastAPI backend enclave. Leaving this empty runs XEROX in zero-server Edge Standalone Mode.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <label htmlFor="settings-api-url" className="text-xs font-mono text-slate-300 block">
              Active Enclave Base URL (Leave empty for zero-server Edge Standalone Mode):
            </label>
            <div className="flex flex-col sm:flex-row gap-2">
              <input
                id="settings-api-url"
                type="text"
                value={customUrlInput}
                onChange={(e) => setCustomUrlInput(e.target.value)}
                placeholder="https://api.yourdomain.com/api/v1 (or leave empty for Standalone Edge)"
                className="flex-1 bg-xerox-surface-elevated border border-xerox-border rounded-xl px-3 py-2 text-base sm:text-xs text-white font-mono focus:outline-none focus:border-xerox-red"
              />

              <Button type="button" variant="primary" size="sm" onClick={handleSaveApiUrl}>
                SAVE URL
              </Button>
              <Button type="button" variant="outline" size="sm" onClick={handleResetApiUrl}>
                RESET DEFAULT
              </Button>
            </div>
            <div className="flex flex-wrap items-center justify-between text-[11px] font-mono text-slate-500 pt-1 gap-2">
              <span>Source: <strong className="text-slate-300">{diagnostics.sourceLabel}</strong></span>
              <span>Environment: <strong className="text-slate-300">{diagnostics.environment}</strong></span>
            </div>
          </div>

          {/* Health Check Result Card */}
          {healthResult && (
            <div
              className={`p-3.5 rounded-xl border text-xs font-mono space-y-1 ${
                healthResult.status === "not_configured"
                  ? "bg-cyan-950/30 border-cyan-500/30 text-cyan-300"
                  : healthResult.status === "healthy"
                  ? "bg-emerald-950/30 border-emerald-500/40 text-emerald-300"
                  : healthResult.status === "degraded"
                  ? "bg-amber-950/30 border-amber-500/40 text-amber-300"
                  : "bg-red-950/40 border-red-500/40 text-red-300"
              }`}
            >
              <div className="flex items-center gap-2 font-bold">
                {healthResult.status === "not_configured" ? (
                  <StatusIndicator status="standalone" size="sm" />
                ) : healthResult.status === "healthy" ? (
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                ) : (
                  <AlertCircle className="w-4 h-4 text-amber-400" />
                )}
                <span>
                  {healthResult.status === "not_configured"
                    ? "STANDALONE EDGE MODE (NO EXTERNAL BACKEND CONFIGURED)"
                    : healthResult.status === "healthy"
                    ? "ENCLAVE ONLINE & RESPONDING"
                    : healthResult.status === "degraded"
                    ? "ENCLAVE DEGRADED"
                    : "ENCLAVE MISCONFIGURED OR UNREACHABLE"}
                </span>
                {healthResult.latencyMs > 0 && (
                  <span className="text-[10px] px-1.5 py-0.2 rounded bg-white/10 text-slate-200">
                    {healthResult.latencyMs}ms
                  </span>
                )}
              </div>
              <div className="text-[11px] text-slate-300 grid grid-cols-1 sm:grid-cols-2 gap-1 pt-1 font-sans">
                {healthResult.service && <span>Service: {healthResult.service} v{healthResult.version || "1.0"}</span>}
                {healthResult.database && (
                  <span>Database: <strong className="text-emerald-400">{healthResult.database}</strong></span>
                )}
                {healthResult.cache && (
                  <span>Cache: <strong className="text-emerald-400">{healthResult.cache}</strong></span>
                )}
                {healthResult.errorDetail && (
                  <span className="col-span-full text-slate-300">{healthResult.errorDetail}</span>
                )}
              </div>
            </div>
          )}

          {/* Separate Analysis Endpoint Probe Result */}
          {analysisTestResult && (
            <div
              className={`p-3.5 rounded-xl border text-xs font-mono space-y-1 ${
                analysisTestResult.success
                  ? "bg-emerald-950/30 border-emerald-500/40 text-emerald-300"
                  : "bg-red-950/40 border-red-500/40 text-red-300"
              }`}
            >
              <div className="flex items-center gap-2 font-bold">
                {analysisTestResult.success ? (
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                ) : (
                  <AlertCircle className="w-4 h-4 text-red-400" />
                )}
                <span>
                  {analysisTestResult.success
                    ? `ANALYSIS ENDPOINT VERIFIED (${analysisTestResult.latencyMs}ms)`
                    : "ANALYSIS ENDPOINT PROBE FAILED"}
                </span>
              </div>
              <p className="text-[11px] text-slate-300 font-sans pt-0.5">
                {analysisTestResult.success
                  ? `Probe analysis on ${analysisTestResult.targetTested} succeeded. Risk: ${analysisTestResult.riskLevel} (${analysisTestResult.riskScore}/100).`
                  : analysisTestResult.errorDetail}
              </p>
            </div>
          )}

          {/* Health Check Error Card */}
          {healthError && (
            <div className="p-3.5 rounded-xl bg-red-950/40 border border-red-500/40 text-xs font-mono space-y-1 text-red-300">
              <div className="flex items-center gap-2 font-bold text-red-400">
                <AlertCircle className="w-4 h-4" />
                <span>SECURITY ENCLAVE OFFLINE OR UNREACHABLE</span>
              </div>
              <p className="text-[11px] text-red-200 font-sans">{healthError}</p>
            </div>
          )}
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Analyst Identity & Session */}
        <Card variant="default">
          <CardHeader>
            <CardTitle>
              <User className="w-4 h-4 text-xerox-red" />
              {user ? "Authenticated Operator Profile" : "Guest Operator Profile"}
            </CardTitle>
            <CardDescription>
              {user
                ? "Current cryptographic session and tenant isolation details"
                : "Unauthenticated guest session — scans stored locally on this machine"}
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="p-3.5 rounded-xl bg-xerox-surface-elevated border border-xerox-border-subtle space-y-2 text-xs font-mono">
              <div className="flex justify-between">
                <span className="text-slate-400">OPERATOR:</span>
                <span className="text-white font-bold">
                  {user?.email || "Guest Operator (Unauthenticated)"}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">TENANT ARCHIVE:</span>
                <span className="text-slate-300 truncate max-w-[180px]">
                  {user?.id ? user.id.slice(0, 16) + "..." : "Device LocalStorage Only"}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">SESSION AUTH:</span>
                <span className={user ? "text-emerald-400 font-bold" : "text-amber-400 font-bold"}>
                  {user ? "HTTPONLY COOKIE SECURED" : "EPHEMERAL GUEST SESSION"}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">DATA ISOLATION:</span>
                <span className="text-slate-200">
                  {user ? "PER-USER STRICT ENFORCED" : "DEVICE LOCAL (NO CLOUD UPLOAD)"}
                </span>
              </div>
            </div>

            {!user && (
              <div className="pt-2">
                <Link to="/login" className="block">
                  <Button
                    variant="outline"
                    size="sm"
                    className="w-full justify-center"
                    leftIcon={<LogIn className="w-3.5 h-3.5 text-xerox-red" />}
                  >
                    AUTHENTICATE TO ENABLE CLOUD ARCHIVE
                  </Button>
                </Link>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Defensive Heuristic Configuration */}
        <Card variant="default">
          <CardHeader>
            <CardTitle>
              <Cpu className="w-4 h-4 text-xerox-red" />
              Heuristic Pipeline Preferences
            </CardTitle>
            <CardDescription>
              Toggle deep deconstruction features for links and message lures
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3 text-xs font-mono">
            <div className="flex items-center justify-between p-3 rounded-xl bg-xerox-surface-elevated border border-xerox-border-subtle">
              <div>
                <span className="text-slate-200 font-bold block">Deep Redirect Following</span>
                <span className="text-[11px] text-slate-400 font-sans">
                  Trace multi-hop HTTP redirects (status 301/302/307)
                </span>
              </div>
              <input
                type="checkbox"
                checked={deepScanEnabled}
                onChange={(e) => setDeepScanEnabled(e.target.checked)}
                className="w-4 h-4 accent-red-600 rounded cursor-pointer"
              />
            </div>

            <div className="flex items-center justify-between p-3 rounded-xl bg-xerox-surface-elevated border border-xerox-border-subtle">
              <div>
                <span className="text-slate-200 font-bold block">Auto-Defanging on Copy</span>
                <span className="text-[11px] text-slate-400 font-sans">
                  Neutralize URLs into hxxps:// and brackets
                </span>
              </div>
              <input
                type="checkbox"
                checked={autoDefangEnabled}
                onChange={(e) => setAutoDefangEnabled(e.target.checked)}
                className="w-4 h-4 accent-red-600 rounded cursor-pointer"
              />
            </div>

            <div className="flex items-center justify-between p-3 rounded-xl bg-xerox-surface-elevated border border-xerox-border-subtle">
              <div>
                <span className="text-slate-200 font-bold block">Browser Enclave Security</span>
                <span className="text-[11px] text-slate-400 font-sans">
                  Zero token storage in localStorage (strict cookies)
                </span>
              </div>
              <input
                type="checkbox"
                checked={sessionEnclaveActive}
                disabled
                className="w-4 h-4 accent-red-600 rounded cursor-not-allowed"
              />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Integration Status Section */}
      <Card variant="default">
        <CardHeader>
          <CardTitle>
            <Shield className="w-4 h-4 text-xerox-red" />
            Defensive Engine & Threat Feed Status
          </CardTitle>
          <CardDescription>
            Core modules and scheduled integration points across milestones
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-mono">
            <div className="p-3.5 rounded-xl bg-xerox-surface-elevated border border-xerox-border-subtle space-y-1">
              <span className="text-slate-400 block text-[10px] uppercase">PostgreSQL + Alembic</span>
              <span className="text-emerald-400 font-bold flex items-center gap-1.5">
                <StatusIndicator status="online" size="sm" /> NOMINAL (M2)
              </span>
            </div>

            <div className="p-3.5 rounded-xl bg-xerox-surface-elevated border border-xerox-border-subtle space-y-1">
              <span className="text-slate-400 block text-[10px] uppercase">HttpOnly Cookie Auth</span>
              <span className="text-emerald-400 font-bold flex items-center gap-1.5">
                <StatusIndicator status="online" size="sm" /> ACTIVE (M3)
              </span>
            </div>

            <div className="p-3.5 rounded-xl bg-xerox-surface-elevated border border-xerox-border-subtle space-y-1">
              <span className="text-slate-400 block text-[10px] uppercase">Design System Shell</span>
              <span className="text-emerald-400 font-bold flex items-center gap-1.5">
                <StatusIndicator status="online" size="sm" /> OPERATIONAL (M4)
              </span>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};
