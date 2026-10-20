import React, { useEffect, useState, useMemo } from "react";
import { Link } from "react-router-dom";
import { History, ExternalLink, RefreshCw, Search, Trash2, ShieldAlert, Download } from "lucide-react";
import { useAuth } from "@/features/auth/AuthContext";
import { getHistory } from "@/services/api";
import { getGuestHistory, clearGuestHistory, exportGuestHistoryAsJson } from "@/services/guestStorage";
import { ScanHistoryItem } from "@/types";

import {
  Button,
  Badge,
  RiskBadge,
  Input,
  EmptyState,
} from "@/components/ui";

type FilterType = "ALL" | "URL" | "MESSAGE" | "SCREENSHOT" | "FILE" | "HIGH_RISK" | "MEDIUM_RISK" | "LOW_RISK";

export const HistoryPage: React.FC = () => {
  const { user } = useAuth();
  const [history, setHistory] = useState<ScanHistoryItem[]>([]);
  const [activeFilter, setActiveFilter] = useState<FilterType>("ALL");
  const [searchQuery, setSearchQuery] = useState("");
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);

  const fetchHistory = async () => {
    setLoading(true);
    setLoadError(null);
    try {
      if (user) {
        const data = await getHistory(50);
        setHistory(data || []);
      } else {
        const localData = getGuestHistory();
        setHistory(localData);
      }
    } catch (err: any) {
      const msg = err?.userMessage || err?.message || "Failed to load account scan archive from security enclave.";
      setLoadError(msg);
      if (!user) {
        setHistory(getGuestHistory());
      } else {
        setHistory([]);
      }
    } finally {
      setLoading(false);
    }
  };


  const handleClearLocal = () => {
    if (window.confirm("Purge all locally stored guest scan reports from this device?")) {
      clearGuestHistory();
      setHistory([]);
    }
  };

  useEffect(() => {
    fetchHistory();
  }, [user]);

  const filteredHistory = useMemo(() => {
    return history.filter((item) => {
      // Search match
      const queryMatch =
        item.defanged_target.toLowerCase().includes(searchQuery.toLowerCase()) ||
        item.executive_summary.toLowerCase().includes(searchQuery.toLowerCase());

      if (!queryMatch) return false;

      // Filter category match
      switch (activeFilter) {
        case "URL":
          return item.target_type === "URL";
        case "MESSAGE":
          return item.target_type === "MESSAGE";
        case "SCREENSHOT":
          return item.target_type === "SCREENSHOT";
        case "FILE":
          return item.target_type === "FILE";
        case "HIGH_RISK":
          return item.risk_level === "HIGH RISK" || item.risk_level === "CRITICAL";
        case "MEDIUM_RISK":
          return item.risk_level === "SUSPICIOUS";
        case "LOW_RISK":
          return item.risk_level === "LOW RISK" || item.risk_level === "BENIGN";
        case "ALL":
        default:
          return true;
      }
    });
  }, [history, activeFilter, searchQuery]);

  const filterOptions: { id: FilterType; label: string }[] = [
    { id: "ALL", label: "All Scans" },
    { id: "URL", label: "URLs" },
    { id: "MESSAGE", label: "Messages" },
    { id: "SCREENSHOT", label: "Screenshots" },
    { id: "FILE", label: "Files" },
    { id: "HIGH_RISK", label: "High Risk" },
    { id: "MEDIUM_RISK", label: "Medium Risk" },
    { id: "LOW_RISK", label: "Low Risk" },
  ];

  return (
    <div className="space-y-6 max-w-6xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-xerox-border-subtle pb-6">
        <div>
          <h1 className="text-2xl font-extrabold text-white tracking-tight flex items-center gap-2.5">
            <History className="w-6 h-6 text-xerox-red" />
            Security Investigation Archive
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Historical audit log of past forensic scans and deconstructed indicators
          </p>
        </div>

        <div className="flex items-center gap-2">
          {history.length > 0 && (
            <Button
              variant="outline"
              size="sm"
              onClick={exportGuestHistoryAsJson}
              leftIcon={<Download className="w-3.5 h-3.5 text-slate-400" />}
              title="Download local scan history as a JSON file"
            >
              EXPORT JSON
            </Button>
          )}
          {!user && history.length > 0 && (
            <Button
              variant="outline"
              size="sm"
              onClick={handleClearLocal}
              leftIcon={<Trash2 className="w-3.5 h-3.5 text-slate-400" />}
            >
              PURGE LOCAL
            </Button>
          )}
          <Button
            variant="secondary"
            size="sm"
            onClick={fetchHistory}
            disabled={loading}
            leftIcon={<RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />}
          >
            REFRESH ARCHIVE
          </Button>
        </div>
      </div>


      {/* Guest Mode Explanatory Notice */}
      {!user && (
        <div className="p-4 rounded-2xl bg-gradient-to-r from-xerox-surface-elevated to-xerox-surface border border-xerox-border flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs font-mono shadow-panel">
          <div className="space-y-1">
            <div className="flex items-center gap-2 text-white font-bold">
              <ShieldAlert className="w-4 h-4 text-xerox-red" />
              <span>DEVICE-SPECIFIC GUEST ARCHIVE</span>
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                LOCAL ONLY
              </span>
            </div>
            <p className="text-slate-400 font-sans text-xs">
              Investigations below are stored solely in this browser. To preserve history permanently and access it from any machine, initialize a session.
            </p>
          </div>
          <Link
            to="/login"
            className="flex-shrink-0 px-3.5 py-2 rounded-xl bg-xerox-red hover:bg-xerox-red-bright text-white font-bold tracking-wider transition-all text-xs text-center shadow-red-glow-sm"
          >
            SIGN IN TO SYNC &rarr;
          </Link>
        </div>
      )}

      {/* Enclave Synchronization Failure Alert */}
      {loadError && (

        <div className="p-4 rounded-2xl bg-red-950/40 border border-red-800/80 text-xs font-mono shadow-panel space-y-2">
          <div className="flex items-start justify-between gap-3">
            <div className="flex items-center gap-2 text-red-400 font-bold">
              <ShieldAlert className="w-4 h-4 text-xerox-red flex-shrink-0" />
              <span>ENCLAVE ARCHIVE RETRIEVAL FAILED</span>
            </div>
            <Link
              to="/settings"
              className="text-xs text-red-300 hover:text-white underline tracking-wider"
            >
              Verify Endpoint &rarr;
            </Link>
          </div>
          <p className="text-red-200 font-sans text-xs">{loadError}</p>
        </div>
      )}

      {/* Filter and Search Bar */}

      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-4">
        {/* Filter Pills */}
        <div className="flex flex-wrap items-center gap-1.5">
          {filterOptions.map((opt) => (
            <button
              key={opt.id}
              onClick={() => setActiveFilter(opt.id)}
              className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-all ${
                activeFilter === opt.id
                  ? "bg-xerox-red text-white shadow-red-glow-sm"
                  : "bg-xerox-surface hover:bg-xerox-surface-elevated text-slate-400 hover:text-slate-200 border border-xerox-border"
              }`}
            >
              {opt.label}
            </button>
          ))}
        </div>

        {/* Search Input */}
        <div className="w-full sm:w-64">
          <Input
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search target or verdict..."
            leftIcon={<Search className="w-3.5 h-3.5" />}
            className="text-xs"
          />
        </div>
      </div>

      {/* Results Container */}
      <div className="rounded-2xl bg-xerox-surface border border-xerox-border overflow-hidden shadow-panel">
        {filteredHistory.length === 0 ? (
          <EmptyState
            title="No Investigations Found"
            description={
              searchQuery
                ? `No scans matching query "${searchQuery}" in filter "${activeFilter}".`
                : "No telemetry records stored under this filter criteria."
            }
            showSentinel={true}
            action={
              <Link to="/analyze">
                <Button variant="primary" size="sm">
                  INITIALIZE NEW SCAN
                </Button>
              </Link>
            }
          />
        ) : (
          <div className="divide-y divide-xerox-border-subtle">
            {filteredHistory.map((item) => (
              <div
                key={item.scan_id}
                className="p-4 sm:p-5 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 hover:bg-xerox-surface-elevated/40 transition-colors"
              >
                <div className="space-y-1.5 flex-1 min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge variant="outline" size="sm">
                      {item.target_type}
                    </Badge>
                    <RiskBadge level={item.risk_level} score={item.risk_score} size="sm" />
                    <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-xerox-surface border border-xerox-border text-slate-400">
                      {user ? "ENCLAVE" : "LOCAL DEVICE"}
                    </span>
                    <span className="text-[11px] font-mono text-slate-500">
                      {new Date(item.analyzed_at).toLocaleString()}
                    </span>
                    <span className="text-[11px] font-mono text-slate-600">
                      ID: {item.scan_id.slice(0, 8)}
                    </span>
                  </div>

                  <div className="font-mono text-xs sm:text-sm font-bold text-white truncate max-w-xl">
                    {item.defanged_target}
                  </div>

                  <p className="text-xs text-slate-400 font-sans line-clamp-1">
                    {item.executive_summary}
                  </p>
                </div>

                <Link to={`/reports?id=${item.scan_id}`} className="flex-shrink-0">
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
