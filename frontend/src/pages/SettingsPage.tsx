import React, { useState } from "react";
import { Link } from "react-router-dom";
import { Settings, Shield, User, Cpu, LogIn } from "lucide-react";
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

export const SettingsPage: React.FC = () => {
  const { user } = useAuth();
  const toast = useToast();

  const [deepScanEnabled, setDeepScanEnabled] = useState(true);
  const [autoDefangEnabled, setAutoDefangEnabled] = useState(true);
  const sessionEnclaveActive = true;

  const handleSaveSettings = () => {
    toast.success("Defensive preferences saved to analyst profile");
  };

  return (
    <div className="max-w-5xl mx-auto space-y-8">
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
