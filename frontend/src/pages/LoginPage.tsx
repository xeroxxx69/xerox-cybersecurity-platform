import React, { useState, useEffect } from "react";
import { Link, useNavigate, useLocation } from "react-router-dom";
import {
  ShieldAlert,
  Lock,
  Mail,
  AlertCircle,
  X,
  ArrowRight,
  ShieldCheck,
  Server,
  RefreshCw,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
} from "lucide-react";
import { useAuth, validateEmail, validateLoginPassword, AuthError } from "@/features/auth";
import { Input, Button } from "@/components/ui";
import {
  getApiBaseUrl,
  setCustomApiUrl,
  getApiDiagnostics,
  isBackendConfigured,
} from "@/services/apiConfig";
import { checkBackendHealth } from "@/services/api";

export const LoginPage: React.FC = () => {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [rememberMe, setRememberMe] = useState(false);
  const [showForgotNotice, setShowForgotNotice] = useState(false);
  const [showBackendConfig, setShowBackendConfig] = useState(false);
  const [fieldErrors, setFieldErrors] = useState<{ email?: string; password?: string }>({});
  const [serverError, setServerError] = useState<string | null>(null);
  const [serverErrorKind, setServerErrorKind] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  // Backend connection diagnostic state
  const [customUrlInput, setCustomUrlInput] = useState(getApiBaseUrl());
  const [pingStatus, setPingStatus] = useState<"idle" | "testing" | "online" | "offline">("idle");
  const [pingDetail, setPingDetail] = useState<string | null>(null);

  const { login, apiBaseUrl } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  const from = (location.state as any)?.from?.pathname || "/dashboard";
  const isStandalone = !isBackendConfigured();

  useEffect(() => {
    const saved = localStorage.getItem("xerox_remember_me");
    if (saved === "true") {
      setRememberMe(true);
    }
    setCustomUrlInput(getApiBaseUrl());
  }, [apiBaseUrl]);

  const handleEmailChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setEmail(e.target.value);
    if (fieldErrors.email) {
      setFieldErrors((prev) => ({ ...prev, email: undefined }));
    }
    if (serverError) {
      setServerError(null);
      setServerErrorKind(null);
    }
  };

  const handlePasswordChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setPassword(e.target.value);
    if (fieldErrors.password) {
      setFieldErrors((prev) => ({ ...prev, password: undefined }));
    }
    if (serverError) {
      setServerError(null);
      setServerErrorKind(null);
    }
  };

  const handleLogin = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setServerError(null);
    setServerErrorKind(null);

    if (!isBackendConfigured()) {
      setServerErrorKind("CONFIG_INVALID");
      setServerError(
        "No backend security enclave configured. To authenticate with a cloud account, configure an HTTPS backend URL below, or continue as a guest without signing in."
      );
      setShowBackendConfig(true);
      return;
    }

    const emailError = validateEmail(email);
    const passwordError = validateLoginPassword(password);

    if (emailError || passwordError) {
      setFieldErrors({
        email: emailError || undefined,
        password: passwordError || undefined,
      });
      return;
    }

    setFieldErrors({});
    setLoading(true);

    try {
      await login(email.trim(), password);
      if (rememberMe) {
        localStorage.setItem("xerox_remember_me", "true");
      } else {
        localStorage.removeItem("xerox_remember_me");
      }
      navigate(from, { replace: true });
    } catch (err: any) {
      if (err instanceof AuthError) {
        setServerErrorKind(err.kind);
        setServerError(err.message);
        if (err.kind === "BACKEND_UNREACHABLE" || err.kind === "CONFIG_INVALID") {
          setShowBackendConfig(true);
        }
      } else {
        const rawMsg = String(err?.message || "").toLowerCase();
        if (
          rawMsg.includes("network") ||
          rawMsg.includes("connect") ||
          rawMsg.includes("fetch") ||
          rawMsg.includes("cors")
        ) {
          setServerErrorKind("BACKEND_UNREACHABLE");
          setServerError(
            `Unable to connect to XEROX backend at ${getApiBaseUrl()}. Please verify your backend server is deployed and online.`
          );
          setShowBackendConfig(true);
        } else if (rawMsg.includes("attempt") || rawMsg.includes("too many") || rawMsg.includes("429")) {
          setServerErrorKind("RATE_LIMITED");
          setServerError("Too many authentication attempts. Please wait 5 minutes before retrying.");
        } else {
          setServerErrorKind("INVALID_CREDENTIALS");
          setServerError("Incorrect operational email or security key. Please verify credentials.");
        }
      }
    } finally {
      setLoading(false);
    }
  };

  const handleTestBackend = async () => {
    setPingStatus("testing");
    setPingDetail(null);
    try {
      const res = await checkBackendHealth();
      if (res.status === "not_configured") {
        setPingStatus("idle");
        setPingDetail("Edge Standalone Mode active (no external backend configured).");
      } else if (res.status === "healthy") {
        setPingStatus("online");
        setPingDetail(`Healthy (${res.service || "XEROX API"} v${res.version || "1.0"}) - ${res.latencyMs}ms`);
      } else if (res.status === "degraded") {
        setPingStatus("offline");
        setPingDetail(`Degraded (${res.errorDetail || "Database or cache degraded"})`);
      } else {
        setPingStatus("offline");
        setPingDetail(res.errorDetail || "Endpoint unreachable or misconfigured");
      }
    } catch (err: any) {
      setPingStatus("offline");
      setPingDetail(err?.userMessage || err?.message || "Endpoint unreachable");
    }
  };

  const handleSaveBackendUrl = () => {
    const trimmed = customUrlInput.trim();
    if (!trimmed) {
      setCustomApiUrl(null);
      setCustomUrlInput("");
      setPingStatus("idle");
      setPingDetail("Reset to default Edge Standalone Mode (no external server).");
      return;
    }
    const result = setCustomApiUrl(trimmed);
    if (!result.isValid) {
      setPingStatus("offline");
      setPingDetail(result.error || "Invalid URL");
      return;
    }
    setPingDetail("Backend URL updated. Testing...");
    handleTestBackend();
  };

  const handleResetBackendUrl = () => {
    setCustomApiUrl(null);
    setCustomUrlInput("");
    setPingDetail("Reset to default Edge Standalone Mode.");
    setPingStatus("idle");
  };

  const diagnostics = getApiDiagnostics();

  return (
    <div className="relative min-h-[calc(100vh-12rem)] flex items-center justify-center px-4 py-8 sm:py-12 overflow-x-hidden">
      {/* Subtle Ambient Red Glow Background Effect */}
      <div
        aria-hidden="true"
        className="pointer-events-none absolute inset-0 flex items-center justify-center overflow-hidden"
      >
        <div className="w-[500px] h-[500px] rounded-full bg-red-600/[0.04] blur-[120px]" />
      </div>

      {/* Main Centered Login Card */}
      <div className="relative w-full max-w-[460px] rounded-2xl bg-[#12141c] border border-[#222735] shadow-[0_16px_50px_-10px_rgba(0,0,0,0.85)] p-5 sm:p-9 transition-all">
        {/* Subtle Top Red Accent Line */}
        <div
          aria-hidden="true"
          className="absolute top-0 left-1/2 -translate-x-1/2 w-40 h-[2px] bg-gradient-to-r from-transparent via-red-500/60 to-transparent"
        />

        {/* Brand Header */}
        <div className="flex flex-col items-center text-center">
          <div className="mb-3.5 inline-flex items-center justify-center w-12 h-12 rounded-xl bg-gradient-to-b from-[#1c202d] to-[#12151e] border border-[#2e3549] shadow-[0_4px_16px_rgba(0,0,0,0.5),0_0_16px_rgba(239,68,68,0.12)]">
            <ShieldAlert className="w-6 h-6 text-xerox-red" />
          </div>

          <div className="flex items-center justify-center">
            <span className="text-xl font-extrabold tracking-wider text-white">
              XE<span className="text-xerox-red">R</span>OX
            </span>
          </div>
          <p className="text-[10px] sm:text-[11px] font-mono tracking-[0.2em] text-slate-400 uppercase mt-1">
            CYBER DEFENSE INTELLIGENCE
          </p>

          <h1 className="text-2xl sm:text-[26px] font-bold text-white tracking-tight mt-5">
            Authenticate to XEROX
          </h1>
          <p className="text-xs sm:text-sm text-slate-400 mt-1">
            Enter analyst credentials to access protected defensive telemetry
          </p>
        </div>

        {/* Standalone Edge Mode Notice for Guests */}
        {isStandalone && (
          <div className="mt-5 p-3.5 rounded-xl bg-cyan-950/30 border border-cyan-500/30 text-cyan-200 text-xs space-y-2">
            <div className="flex items-center gap-2 font-mono font-semibold text-cyan-300">
              <ShieldCheck className="w-4 h-4 text-cyan-400 flex-shrink-0" />
              <span>STANDALONE EDGE MODE ACTIVE</span>
            </div>
            <p className="text-[11px] text-slate-300 leading-relaxed">
              XEROX runs autonomous, client-side threat analysis directly in your browser without requiring a backend server or login.
            </p>
            <div className="pt-1">
              <Link
                to="/analyze"
                className="inline-flex items-center justify-center gap-1.5 w-full py-2 px-3 rounded-lg bg-cyan-500/20 hover:bg-cyan-500/30 border border-cyan-400/40 text-cyan-200 text-xs font-mono font-medium transition-colors"
              >
                <span>CONTINUE AS GUEST OPERATOR</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </Link>
            </div>
          </div>
        )}

        {/* Forgot Password Information Notice */}
        {showForgotNotice && (
          <div
            role="dialog"
            aria-modal="true"
            className="mt-6 p-4 rounded-xl bg-[#171b26] border border-[#2e354a] text-slate-300 text-xs sm:text-sm relative animate-fadeIn"
          >
            <button
              type="button"
              onClick={() => setShowForgotNotice(false)}
              aria-label="Close notice"
              className="absolute top-2.5 right-2.5 text-slate-400 hover:text-white p-1 rounded-lg transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
            <p className="font-semibold text-white mb-1">Security Credential Recovery</p>
            <p className="text-slate-400 leading-relaxed text-xs">
              To rotate or reset analyst operational keys, contact your system administrator or verify your backend cryptographic session enclave.
            </p>
          </div>
        )}

        {/* Categorized Server Error Alert Banner */}
        {serverError && (
          <div
            role="alert"
            aria-live="polite"
            className="mt-6 p-3.5 rounded-xl bg-red-500/10 border border-red-500/30 text-red-300 text-xs sm:text-sm flex flex-col gap-2"
          >
            <div className="flex items-start gap-2.5">
              <AlertCircle className="w-4 h-4 text-xerox-red flex-shrink-0 mt-0.5" aria-hidden="true" />
              <span className="leading-relaxed font-sans">{serverError}</span>
            </div>
            {serverErrorKind === "BACKEND_UNREACHABLE" && (
              <div className="pt-2 border-t border-red-500/20 flex items-center justify-between text-[11px] text-red-300/80">
                <span>Destination: {getApiBaseUrl()}</span>
                <button
                  type="button"
                  onClick={() => setShowBackendConfig((prev) => !prev)}
                  className="text-white underline hover:text-red-200 transition-colors font-medium"
                >
                  {showBackendConfig ? "Hide Settings" : "Configure Backend"}
                </button>
              </div>
            )}
          </div>
        )}

        {/* Collapsible Backend Server Diagnostic & Configuration Enclave */}
        {showBackendConfig && (
          <div className="mt-5 p-4 rounded-xl bg-[#0b0d13] border border-[#242b3d] text-slate-300 text-xs space-y-3">
            <div className="flex items-center justify-between">
              <span className="font-mono text-slate-200 font-medium flex items-center gap-1.5">
                <Server className="w-3.5 h-3.5 text-xerox-red" />
                SECURITY ENCLAVE BACKEND
              </span>
              <button
                type="button"
                onClick={handleTestBackend}
                disabled={pingStatus === "testing"}
                className="inline-flex items-center gap-1 px-2 py-1 rounded bg-[#1c2233] hover:bg-[#283149] text-slate-200 text-[11px] transition-colors"
              >
                <RefreshCw className={`w-3 h-3 ${pingStatus === "testing" ? "animate-spin" : ""}`} />
                Test Health
              </button>
            </div>

            <div className="space-y-1.5">
              <label htmlFor="custom-backend-url" className="text-[11px] text-slate-400">
                API Base URL (Leave empty for Edge Standalone Mode):
              </label>
              <div className="flex flex-col sm:flex-row gap-2">
                <input
                  id="custom-backend-url"
                  type="text"
                  value={customUrlInput}
                  onChange={(e) => setCustomUrlInput(e.target.value)}
                  placeholder="https://api.yourdomain.com/api/v1"
                  className="flex-1 bg-[#12151f] border border-[#252c3e] rounded-lg px-2.5 py-2 text-base sm:text-xs text-white focus:outline-none focus:border-xerox-red"
                />
                <button
                  type="button"
                  onClick={handleSaveBackendUrl}
                  className="px-3 py-2 bg-red-600/80 hover:bg-red-600 text-white rounded-lg text-xs font-medium transition-colors"
                >
                  Save
                </button>
              </div>
            </div>

            {pingDetail && (
              <div
                className={`p-2 rounded text-[11px] font-mono flex items-center gap-1.5 ${
                  pingStatus === "online"
                    ? "bg-emerald-500/10 text-emerald-300 border border-emerald-500/30"
                    : "bg-red-500/10 text-red-300 border border-red-500/30"
                }`}
              >
                {pingStatus === "online" ? (
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                ) : (
                  <AlertCircle className="w-3.5 h-3.5 text-red-400" />
                )}
                <span>{pingDetail}</span>
              </div>
            )}

            <div className="flex flex-wrap items-center justify-between text-[10px] text-slate-500 font-mono pt-1 gap-2">
              <span>Source: {diagnostics.sourceLabel || diagnostics.source}</span>
              <button
                type="button"
                onClick={handleResetBackendUrl}
                className="text-slate-400 hover:text-slate-200 underline"
              >
                Reset Default
              </button>
            </div>
          </div>
        )}

        {/* Login Form */}
        <form onSubmit={handleLogin} noValidate className="mt-6 space-y-4">
          <Input
            id="login-email"
            label="OPERATIONAL EMAIL"
            labelClassName="block text-xs font-mono uppercase tracking-wider text-slate-300 mb-1"
            type="email"
            name="email"
            value={email}
            onChange={handleEmailChange}
            error={fieldErrors.email}
            autoComplete="email"
            placeholder="analyst@domain.gov"
            leftIcon={<Mail className="w-4 h-4" />}
            className="bg-[#0e1017] border-[#222736] focus:border-xerox-red focus:ring-xerox-red/30 h-11 text-base sm:text-sm placeholder-slate-500 text-slate-100"
          />

          <Input
            id="login-password"
            label="SECURITY KEY / PASSWORD"
            labelClassName="block text-xs font-mono uppercase tracking-wider text-slate-300 mb-1"
            type="password"
            name="password"
            value={password}
            onChange={handlePasswordChange}
            error={fieldErrors.password}
            showPasswordToggle
            autoComplete="current-password"
            placeholder="••••••••••••"
            leftIcon={<Lock className="w-4 h-4" />}
            className="bg-[#0e1017] border-[#222736] focus:border-xerox-red focus:ring-xerox-red/30 h-11 text-base sm:text-sm placeholder-slate-500 text-slate-100"
          />

          {/* Remember Me & Forgot Password Row */}
          <div className="flex items-center justify-between w-full pt-1 pb-1 text-xs sm:text-sm gap-4">
            <label
              htmlFor="remember-me"
              className="inline-flex items-center gap-2 cursor-pointer select-none group"
            >
              <input
                id="remember-me"
                name="remember-me"
                type="checkbox"
                checked={rememberMe}
                onChange={(e) => setRememberMe(e.target.checked)}
                className="w-4 h-4 rounded border-[#2b3243] bg-[#0e1017] text-xerox-red focus:ring-xerox-red/30 focus:ring-offset-0 focus:ring-offset-transparent cursor-pointer transition-colors accent-red-600"
              />
              <span className="text-slate-400 group-hover:text-slate-300 transition-colors text-xs font-mono">
                Remember analyst key
              </span>
            </label>

            <button
              type="button"
              onClick={() => setShowForgotNotice((prev) => !prev)}
              className="text-slate-400 hover:text-white transition-colors text-xs focus-visible:underline focus-visible:outline-none whitespace-nowrap"
            >
              Key recovery?
            </button>
          </div>

          {/* Primary Action Button */}
          <div className="pt-2">
            <Button
              id="btn-initialize-session"
              type="submit"
              variant="primary"
              fullWidth
              size="lg"
              loading={loading}
              loadingText="AUTHENTICATING..."
              rightIcon={<ArrowRight className="w-4 h-4" />}
              className="h-11 text-sm font-semibold tracking-wider uppercase bg-xerox-red hover:bg-red-600 active:scale-[0.99] transition-all shadow-[0_0_20px_rgba(239,68,68,0.2)] hover:shadow-[0_0_28px_rgba(239,68,68,0.35)] border border-red-500/40 rounded-xl"
            >
              INITIALIZE SESSION
            </Button>
          </div>
        </form>

        {/* Bottom Registration & Enclave Badge Row */}
        <div className="mt-7 pt-5 border-t border-[#1e2332] flex flex-col sm:flex-row items-center justify-between text-xs font-mono text-slate-400 gap-2">
          <Link
            to="/register"
            className="text-slate-400 hover:text-white transition-colors"
          >
            Register new analyst account
          </Link>
          <button
            type="button"
            onClick={() => setShowBackendConfig((prev) => !prev)}
            className="text-[11px] text-slate-500 hover:text-slate-300 flex items-center gap-1 transition-colors"
            title="Inspect backend enclave configuration"
          >
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
            HTTPONLY COOKIE ENCLAVE
            {showBackendConfig ? (
              <ChevronUp className="w-3 h-3 ml-0.5" />
            ) : (
              <ChevronDown className="w-3 h-3 ml-0.5" />
            )}
          </button>
        </div>
      </div>
    </div>
  );
};
