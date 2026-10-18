import React, { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import {
  ShieldAlert,
  ShieldCheck,
  Radio,
  ExternalLink,
  ChevronRight,
  TrendingUp,
  Cpu,
  Globe,
  Mail,
  Image as ImageIcon,
  FileCode,
  ArrowRight,
  Activity,
  AlertTriangle,
} from "lucide-react";
import { useAuth } from "@/features/auth/AuthContext";
import { getStats, getHistory } from "@/services/api";
import { getGuestStats, getGuestHistory } from "@/services/guestStorage";
import { StatsSummary, ScanHistoryItem } from "@/types";
import {
  Card,
  CardTitle,
  CardDescription,
  Button,
  Badge,
  RiskBadge,
  StatusIndicator,
  Input,
} from "@/components/ui";
import { XeroxThreatGlobe } from "@/components/XeroxThreatGlobe";

const DEFAULT_STATS: StatsSummary = {
  total_scans: 0,
  threats_blocked: 0,
  suspicious_flagged: 0,
  benign_verified: 0,
  scans_by_type: { URL: 0, MESSAGE: 0, SCREENSHOT: 0, FILE: 0 },
};

export const DashboardPage: React.FC = () => {
  const { user } = useAuth();
  const navigate = useNavigate();
  const [stats, setStats] = useState<StatsSummary>(DEFAULT_STATS);
  const [recentScans, setRecentScans] = useState<ScanHistoryItem[]>([]);
  const [quickUrl, setQuickUrl] = useState("");

  useEffect(() => {
    async function loadData() {
      if (user) {
        try {
          const [statsData, historyData] = await Promise.all([
            getStats().catch(() => null),
            getHistory(5).catch(() => null),
          ]);
          if (statsData) {
            setStats(statsData);
          }
          if (historyData) {
            setRecentScans(historyData);
          }
        } catch {
          // preserve current state
        }
      } else {
        // Load guest stats and guest history from local device storage
        const guestStats = getGuestStats();
        const guestHistory = getGuestHistory().slice(0, 5);
        setStats(guestStats);
        setRecentScans(guestHistory);
      }
    }
    loadData();
  }, [user]);

  const handleQuickUrlSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!quickUrl.trim()) return;
    navigate(`/analyze?type=url&target=${encodeURIComponent(quickUrl.trim())}`);
  };

  return (
    <div className="space-y-8 max-w-7xl mx-auto">
      {/* Hero Sentinel Greeting Header */}
      <div className="relative overflow-hidden rounded-3xl bg-gradient-to-r from-xerox-surface via-xerox-surface-card to-xerox-surface border border-xerox-border p-6 sm:p-8 shadow-panel">
        <div className="absolute -right-16 -top-16 w-80 h-80 bg-red-600/10 rounded-full blur-3xl pointer-events-none" />
        <div className="relative z-10 flex flex-col md:flex-row items-start md:items-center justify-between gap-6">
          <div className="space-y-2">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-red-500/10 border border-red-500/20 text-xs font-mono text-red-400">
              <Cpu className="w-3.5 h-3.5 text-xerox-red animate-pulse" />
              <span>DEFENSIVE COMMAND // TELEMETRY HUB</span>
            </div>
            <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
              Good morning. Let's check what's suspicious.
            </h1>
            <p className="text-xs sm:text-sm text-slate-400 max-w-xl font-sans leading-relaxed">
              XEROX heuristic defensive engine is operational for analyst {user?.email ? user.email.split("@")[0] : "Operator"}. Inspect suspect URLs, message lures, screenshots, or files.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <Link to="/analyze">
              <Button
                variant="primary"
                size="lg"
                leftIcon={<Radio className="w-4 h-4 animate-pulse" />}
              >
                NEW SECURITY SCAN
              </Button>
            </Link>
          </div>
        </div>
      </div>

      {/* Guest Mode Telemetry Notice */}
      {!user && (
        <div className="flex flex-col sm:flex-row sm:items-center justify-between p-4 rounded-2xl bg-gradient-to-r from-xerox-surface-elevated to-xerox-surface border border-xerox-border text-xs font-mono gap-3 shadow-panel">
          <div className="flex items-center gap-3 text-slate-300">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse flex-shrink-0" />
            <div>
              <span className="text-white font-bold block sm:inline">GUEST OPERATOR SESSION: </span>
              <span className="text-slate-400">
                Analysis telemetry & recent scan results are stored in local browser memory.
              </span>
            </div>
          </div>
          <Link
            to="/login"
            className="text-red-400 hover:text-red-300 font-bold tracking-wider inline-flex items-center gap-1.5 flex-shrink-0"
          >
            INITIALIZE SESSION TO SYNC ACROSS DEVICES &rarr;
          </Link>
        </div>
      )}

      {/* 4 Key Security Overview Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* 1. Threats Detected */}
        <Card variant="alert" className="p-5">
          <div className="text-xs font-mono text-red-400 uppercase flex items-center justify-between">
            <span>Threats Detected</span>
            <ShieldAlert className="w-4 h-4 text-xerox-red" />
          </div>
          <div className="text-3xl font-extrabold text-red-400 mt-2 font-mono">
            {stats.threats_blocked}
          </div>
          <div className="text-[11px] text-slate-400 mt-1 flex items-center gap-1 font-mono">
            <TrendingUp className="w-3 h-3 text-red-400" /> Active Heuristic Intercepts
          </div>
        </Card>

        {/* 2. Scans Completed */}
        <Card variant="default" className="p-5">
          <div className="text-xs font-mono text-slate-400 uppercase flex items-center justify-between">
            <span>Scans Completed</span>
            <Activity className="w-4 h-4 text-slate-400" />
          </div>
          <div className="text-3xl font-extrabold text-white mt-2 font-mono">
            {stats.total_scans}
          </div>
          <div className="text-[11px] text-slate-500 mt-1 font-mono">
            {stats.scans_by_type?.URL || 0} URLs // {stats.scans_by_type?.MESSAGE || 0} Messages
          </div>
        </Card>

        {/* 3. High-Risk Findings */}
        <Card variant="default" className="p-5">
          <div className="text-xs font-mono text-amber-400 uppercase flex items-center justify-between">
            <span>High-Risk Findings</span>
            <AlertTriangle className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-3xl font-extrabold text-amber-400 mt-2 font-mono">
            {stats.suspicious_flagged}
          </div>
          <div className="text-[11px] text-slate-500 mt-1 font-mono">
            Flagged for containment
          </div>
        </Card>

        {/* 4. Security Status */}
        <Card variant="default" className="p-5">
          <div className="text-xs font-mono text-emerald-400 uppercase flex items-center justify-between">
            <span>Security Status</span>
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-xl font-bold text-white mt-3 flex items-center gap-2">
            <StatusIndicator status="online" label="SHIELD ACTIVE" size="md" />
          </div>
          <div className="text-[11px] text-emerald-400/80 mt-1 font-mono">
            All heuristic modules nominal
          </div>
        </Card>
      </div>

      {/* Central 3D Threat Telemetry Observatory */}
      <div className="rounded-3xl border border-xerox-border bg-xerox-surface overflow-hidden shadow-panel">
        <XeroxThreatGlobe className="w-full" />
      </div>

      {/* 4 Quick Analysis Cards (URL, Message, Screenshot, File) */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Quick URL Card */}
        <Card variant="default" className="flex flex-col justify-between space-y-4">
          <div className="space-y-2">
            <div className="w-9 h-9 rounded-xl bg-blue-500/10 text-blue-400 border border-blue-500/20 flex items-center justify-center">
              <Globe className="w-4 h-4" />
            </div>
            <CardTitle className="text-sm">URL Inspection</CardTitle>
            <CardDescription className="text-xs">
              Deconstruct links, check homograph spoofing & SSL anomalies.
            </CardDescription>
          </div>
          <Button
            variant="secondary"
            size="sm"
            fullWidth
            onClick={() => navigate("/analyze?type=url")}
            rightIcon={<ArrowRight className="w-3.5 h-3.5" />}
          >
            INSPECT URL
          </Button>
        </Card>

        {/* Quick Message Card */}
        <Card variant="default" className="flex flex-col justify-between space-y-4">
          <div className="space-y-2">
            <div className="w-9 h-9 rounded-xl bg-amber-500/10 text-amber-400 border border-amber-500/20 flex items-center justify-center">
              <Mail className="w-4 h-4" />
            </div>
            <CardTitle className="text-sm">Message & Smishing</CardTitle>
            <CardDescription className="text-xs">
              Analyze SMS, email lures, and urgency signals.
            </CardDescription>
          </div>
          <Button
            variant="secondary"
            size="sm"
            fullWidth
            onClick={() => navigate("/analyze?type=message")}
            rightIcon={<ArrowRight className="w-3.5 h-3.5" />}
          >
            TRIAGE MESSAGE
          </Button>
        </Card>

        {/* Quick Screenshot Card */}
        <Card variant="default" className="flex flex-col justify-between space-y-4">
          <div className="space-y-2">
            <div className="w-9 h-9 rounded-xl bg-purple-500/10 text-purple-400 border border-purple-500/20 flex items-center justify-center">
              <ImageIcon className="w-4 h-4" />
            </div>
            <CardTitle className="text-sm">Screenshot Analysis</CardTitle>
            <CardDescription className="text-xs">
              Detect fake login overlays and QR phishing lures.
            </CardDescription>
          </div>
          <Button
            variant="secondary"
            size="sm"
            fullWidth
            onClick={() => navigate("/analyze?type=screenshot")}
            rightIcon={<ArrowRight className="w-3.5 h-3.5" />}
          >
            SCAN IMAGE
          </Button>
        </Card>

        {/* Quick File Card */}
        <Card variant="default" className="flex flex-col justify-between space-y-4">
          <div className="space-y-2">
            <div className="w-9 h-9 rounded-xl bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 flex items-center justify-center">
              <FileCode className="w-4 h-4" />
            </div>
            <CardTitle className="text-sm">File & Macro Scan</CardTitle>
            <CardDescription className="text-xs">
              Static inspection of suspicious attachments & scripts.
            </CardDescription>
          </div>
          <Button
            variant="secondary"
            size="sm"
            fullWidth
            onClick={() => navigate("/analyze?type=file")}
            rightIcon={<ArrowRight className="w-3.5 h-3.5" />}
          >
            CHECK FILE
          </Button>
        </Card>
      </div>

      {/* Rapid URL One-Click Bar */}
      <Card variant="default" className="p-4 sm:p-5">
        <form onSubmit={handleQuickUrlSubmit} className="flex flex-col sm:flex-row items-center gap-3">
          <div className="flex-1 w-full">
            <Input
              value={quickUrl}
              onChange={(e) => setQuickUrl(e.target.value)}
              placeholder="Quick link check: paste suspicious URL (e.g. hxxps://...)"
              className="font-mono text-xs"
              leftIcon={<Globe className="w-4 h-4 text-slate-400" />}
            />
          </div>
          <Button
            type="submit"
            variant="primary"
            size="md"
            rightIcon={<ArrowRight className="w-4 h-4" />}
            className="w-full sm:w-auto flex-shrink-0"
          >
            INSPECT TARGET
          </Button>
        </form>
      </Card>

      {/* Recent Scans Section */}
      <div className="rounded-2xl bg-xerox-surface border border-xerox-border p-6 shadow-panel space-y-5">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-xerox-border-subtle pb-4">
          <div>
            <h3 className="text-base font-bold text-white tracking-tight flex items-center gap-2">
              <Activity className="w-4 h-4 text-xerox-red" />
              Recent Security Scans
            </h3>
            <p className="text-xs text-slate-400 font-sans">
              Latest forensic investigations and indicator deconstructions
            </p>
          </div>

          <Link to="/history">
            <Button variant="ghost" size="sm" rightIcon={<ChevronRight className="w-4 h-4" />}>
              VIEW FULL ARCHIVE
            </Button>
          </Link>
        </div>

        {/* Scans List */}
        {recentScans.length === 0 ? (
          <div className="py-10 text-center space-y-3">
            <div className="w-12 h-12 rounded-full bg-slate-800/50 border border-slate-700 flex items-center justify-center mx-auto text-slate-500">
              <Activity className="w-6 h-6 text-slate-500" />
            </div>
            <p className="font-mono text-xs text-slate-400">
              No recent security investigations recorded.
            </p>
            <p className="text-[11px] text-slate-500 font-sans max-w-sm mx-auto">
              Initiate an inspection above to begin building your forensic audit dossier.
            </p>
          </div>
        ) : (
          <div className="divide-y divide-xerox-border-subtle">
            {recentScans.map((scan) => (
              <div
                key={scan.scan_id}
                className="py-4 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 hover:bg-xerox-surface-elevated/40 p-3 rounded-xl transition-colors"
              >
                <div className="space-y-1.5 flex-1 min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge variant="outline" size="sm">
                      {scan.target_type}
                    </Badge>
                    <RiskBadge level={scan.risk_level} score={scan.risk_score} size="sm" />
                    <span className="text-[11px] font-mono text-slate-500">
                      {new Date(scan.analyzed_at).toLocaleString()}
                    </span>
                  </div>
                  <div className="font-mono text-xs font-bold text-white truncate max-w-xl">
                    {scan.defanged_target}
                  </div>
                  <p className="text-xs text-slate-400 font-sans line-clamp-1">
                    {scan.executive_summary}
                  </p>
                </div>

                <Link to={`/reports?id=${scan.scan_id}`}>
                  <Button
                    variant="outline"
                    size="sm"
                    rightIcon={<ExternalLink className="w-3.5 h-3.5" />}
                  >
                    DOSSIER
                  </Button>
                </Link>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
