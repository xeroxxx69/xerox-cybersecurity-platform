import React, { useState } from "react";
import { Link, useLocation } from "react-router-dom";
import {
  ShieldAlert,
  Search,
  LayoutDashboard,
  History,
  FileText,
  Settings,
  ShieldCheck,
  Menu,
  X,
  Radio,
  LogOut,
  UserCheck,
  LogIn,
  Globe,
  ChevronLeft,
  ChevronRight,
} from "lucide-react";
import { useAuth } from "@/features/auth/AuthContext";
import { useBackendHealth } from "@/features/health/useBackendHealth";
import { ToastProvider, NavigationItem, StatusIndicator, IconButton } from "@/components/ui";

interface MainLayoutProps {
  children: React.ReactNode;
}

export const MainLayout: React.FC<MainLayoutProps> = ({ children }) => {
  const location = useLocation();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const { user, logout } = useAuth();
  const health = useBackendHealth(20000);

  const navItems = [
    { label: "Dashboard", href: "/dashboard", icon: LayoutDashboard },
    { label: "Analyze", href: "/analyze", icon: Search },
    { label: "History", href: "/history", icon: History },
    { label: "Threat Intelligence", href: "/threat-intel", icon: Globe },
    { label: "Reports", href: "/reports", icon: FileText },
    { label: "Settings", href: "/settings", icon: Settings },
  ];

  const isAuthRoute =
    location.pathname === "/login" ||
    location.pathname === "/register" ||
    location.pathname.endsWith("/login") ||
    location.pathname.endsWith("/register");

  if (isAuthRoute) {
    return (
      <ToastProvider>
        <div className="min-h-screen bg-xerox-bg text-slate-100 flex flex-col justify-center font-sans selection:bg-xerox-red selection:text-white">
          <main className="w-full flex-1 flex items-center justify-center p-4 sm:p-6">
            {children}
          </main>
        </div>
      </ToastProvider>
    );
  }

  return (
    <ToastProvider>
      <div className="min-h-screen bg-xerox-bg text-slate-100 flex flex-col font-sans selection:bg-xerox-red selection:text-white">
        {/* Top Cyber Command Header */}
        <header className="sticky top-0 z-40 border-b border-xerox-border bg-xerox-bg-secondary/90 backdrop-blur-xl">
          <div className="px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
            {/* Left: Mobile Toggle & Brand Logo */}
            <div className="flex items-center gap-3">
              <button
                onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
                aria-label="Toggle navigation menu"
                className="lg:hidden p-2 rounded-xl bg-xerox-surface border border-xerox-border text-slate-400 hover:text-white"
              >
                {mobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
              </button>

              <Link to="/dashboard" className="flex items-center gap-2.5 group">
                <div className="relative w-9 h-9 rounded-xl bg-gradient-to-br from-red-600 to-red-950 p-0.5 shadow-[0_0_20px_rgba(239,68,68,0.35)] transition-transform group-hover:scale-105">
                  <div className="w-full h-full bg-xerox-bg rounded-[10px] flex items-center justify-center border border-red-500/40">
                    <ShieldAlert className="w-5 h-5 text-xerox-red" />
                  </div>
                </div>
                <div className="flex flex-col">
                  <div className="flex items-center gap-1.5">
                    <span className="font-extrabold text-lg tracking-wider text-white">
                      XE<span className="text-xerox-red">R</span>OX
                    </span>
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-500/10 text-red-400 font-mono font-bold border border-red-500/20">
                      SENTINEL 1.0
                    </span>
                  </div>
                  <span className="text-[10px] tracking-wider text-slate-400 font-mono -mt-1 hidden sm:inline">
                    CYBER DEFENSIVE INTELLIGENCE
                  </span>
                </div>
              </Link>
            </div>

            {/* Middle: System Operational Status Beacon (Dynamic Enclave Telemetry) */}
            <Link
              to="/settings"
              title={
                health.status === "online"
                  ? `Backend Enclave Online (${health.latencyMs}ms) at ${health.baseUrl}`
                  : health.status === "degraded"
                  ? `Backend Enclave Degraded: ${health.errorDetail || "Database/Cache check warning"}`
                  : health.status === "offline"
                  ? `Backend Enclave Offline: ${health.errorDetail || "Unreachable"}. Click to configure API endpoint.`
                  : `Connecting to ${health.baseUrl}...`
              }
              className="hidden md:flex items-center gap-3 px-3.5 py-1.5 rounded-full bg-xerox-surface/80 border border-xerox-border-subtle hover:border-xerox-border transition-all cursor-pointer group"
            >
              <StatusIndicator
                status={
                  health.status === "online"
                    ? "online"
                    : health.status === "degraded"
                    ? "degraded"
                    : health.status === "offline"
                    ? "offline"
                    : "scanning"
                }
                label={
                  health.status === "online"
                    ? `ENCLAVE ONLINE ${health.latencyMs !== null ? `(${health.latencyMs}ms)` : ""}`
                    : health.status === "degraded"
                    ? "ENCLAVE DEGRADED"
                    : health.status === "offline"
                    ? "ENCLAVE OFFLINE"
                    : "VERIFYING ENCLAVE..."
                }
                size="sm"
              />
              <span className="text-slate-600 font-mono text-xs">|</span>
              <span className="text-[11px] font-mono text-slate-400 group-hover:text-slate-200 transition-colors">
                HEURISTIC CORE
              </span>
            </Link>


            {/* Right: Quick Action & User Profile */}
            <div className="flex items-center gap-3">
              <Link
                to="/analyze"
                className="hidden sm:inline-flex items-center gap-2 px-3.5 py-2 rounded-xl bg-xerox-red hover:bg-xerox-red-bright text-white text-xs font-mono font-bold tracking-wider transition-all shadow-red-glow"
              >
                <Radio className="w-3.5 h-3.5 animate-pulse" />
                INSPECT TARGET
              </Link>

              {user ? (
                <div className="flex items-center gap-2.5 px-3 py-1.5 rounded-xl bg-xerox-surface border border-xerox-border text-xs font-mono">
                  <UserCheck className="w-3.5 h-3.5 text-emerald-400 flex-shrink-0" />
                  <span className="text-slate-300 max-w-[120px] sm:max-w-[160px] truncate">
                    {user.email}
                  </span>
                  <button
                    onClick={() => logout()}
                    title="Sign out of XEROX"
                    aria-label="Logout"
                    className="ml-1 text-slate-400 hover:text-xerox-red transition-colors p-1 rounded hover:bg-xerox-surface-elevated"
                  >
                    <LogOut className="w-3.5 h-3.5" />
                  </button>
                </div>
              ) : (
                <Link
                  to="/login"
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-xerox-surface hover:bg-xerox-surface-elevated text-xs font-mono text-slate-300 border border-xerox-border transition-colors"
                >
                  <LogIn className="w-3.5 h-3.5 text-red-400" />
                  <span>AUTHENTICATE</span>
                </Link>
              )}
            </div>
          </div>
        </header>

        {/* Core Layout: Sidebar + Main Content */}
        <div className="flex-1 flex overflow-hidden">
          {/* Desktop Left Sidebar */}
          <aside
            className={`hidden lg:flex flex-col border-r border-xerox-border bg-xerox-bg-secondary/60 backdrop-blur-md transition-all duration-300 ${
              sidebarCollapsed ? "w-20" : "w-64"
            }`}
          >
            {/* Navigation links */}
            <div className="flex-1 p-4 space-y-1.5">
              {navItems.map((item) => {
                const isActive =
                  location.pathname === item.href ||
                  (item.href === "/dashboard" && location.pathname === "/");
                return (
                  <NavigationItem
                    key={item.href}
                    href={item.href}
                    icon={item.icon}
                    label={item.label}
                    isActive={isActive}
                    collapsed={sidebarCollapsed}
                  />
                );
              })}
            </div>

            {/* Sidebar Collapse Toggle */}
            <div className="p-4 border-t border-xerox-border-subtle flex items-center justify-between">
              {!sidebarCollapsed && (
                <div className="text-[11px] font-mono text-slate-500 truncate">
                  XEROX ARCHITECTURE
                </div>
              )}
              <IconButton
                icon={sidebarCollapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
                aria-label={sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"}
                size="sm"
                onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
                className="text-slate-400 hover:text-white"
              />
            </div>
          </aside>

          {/* Mobile Navigation Drawer */}
          {mobileMenuOpen && (
            <div className="lg:hidden fixed inset-0 z-50 flex">
              <div
                className="fixed inset-0 bg-black/80 backdrop-blur-sm"
                onClick={() => setMobileMenuOpen(false)}
                aria-hidden="true"
              />
              <div className="relative w-72 max-w-full bg-xerox-bg-secondary border-r border-xerox-border p-5 flex flex-col h-full z-10 space-y-4">
                <div className="flex items-center justify-between border-b border-xerox-border-subtle pb-4">
                  <div className="flex items-center gap-2">
                    <ShieldAlert className="w-5 h-5 text-xerox-red" />
                    <span className="font-extrabold text-sm text-white font-mono">
                      XEROX NAVIGATION
                    </span>
                  </div>
                  <IconButton
                    icon={<X className="w-4 h-4" />}
                    aria-label="Close menu"
                    size="sm"
                    onClick={() => setMobileMenuOpen(false)}
                  />
                </div>

                <nav className="flex-1 space-y-1">
                  {navItems.map((item) => {
                    const isActive =
                      location.pathname === item.href ||
                      (item.href === "/dashboard" && location.pathname === "/");
                    return (
                      <NavigationItem
                        key={item.href}
                        href={item.href}
                        icon={item.icon}
                        label={item.label}
                        isActive={isActive}
                        onClick={() => setMobileMenuOpen(false)}
                      />
                    );
                  })}
                </nav>

                <div className="border-t border-xerox-border-subtle pt-4">
                  {user ? (
                    <div className="space-y-2">
                      <div className="text-xs font-mono text-slate-300 truncate">
                        {user.email}
                      </div>
                      <button
                        onClick={() => {
                          logout();
                          setMobileMenuOpen(false);
                        }}
                        className="w-full flex items-center justify-center gap-2 p-2 rounded-xl bg-red-950/40 text-red-400 text-xs font-mono border border-red-500/30"
                      >
                        <LogOut className="w-3.5 h-3.5" /> Sign Out
                      </button>
                    </div>
                  ) : (
                    <Link
                      to="/login"
                      onClick={() => setMobileMenuOpen(false)}
                      className="w-full flex items-center justify-center gap-2 p-2 rounded-xl bg-xerox-surface text-slate-200 text-xs font-mono border border-xerox-border"
                    >
                      <LogIn className="w-3.5 h-3.5 text-xerox-red" /> Authenticate
                    </Link>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* Main Content Workspace Area */}
          <main className="flex-1 overflow-y-auto px-4 sm:px-6 lg:px-8 py-8">
            {children}
          </main>
        </div>

        {/* Cyber Command Footer */}
        <footer className="border-t border-xerox-border bg-xerox-bg-secondary py-4 text-xs text-slate-500 font-mono">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-slate-400" />
              <span>XEROX DEFENSIVE CYBERSECURITY ARCHITECTURE // PHASE 1</span>
            </div>
            <div className="text-slate-500">
              WEAPONLESS, PURPOSE DRIVEN. A SAFER DIGITAL TOMORROW.
            </div>
          </div>
        </footer>
      </div>
    </ToastProvider>
  );
};
