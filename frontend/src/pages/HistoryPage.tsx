import React, { useEffect, useState, useMemo } from "react";
import { Link } from "react-router-dom";
import { History, ExternalLink, RefreshCw, Search } from "lucide-react";
import { getHistory } from "@/services/api";
import { useAuth } from "@/features/auth/AuthContext";
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

  const fetchHistory = async () => {
    if (!user) {
      setHistory([]);
      setLoading(false);
      return;
    }
    setLoading(true);
    try {
      const data = await getHistory(50);
      setHistory(data || []);
    } catch {
      setHistory([]);
    } finally {
      setLoading(false);
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

      {!user ? (
        <div className="rounded-2xl bg-xerox-surface border border-xerox-border p-8 sm:p-10 text-center space-y-4">
          <History className="w-10 h-10 text-xerox-red mx-auto" />
          <h2 className="text-xl font-bold text-white">History is an account feature</h2>
          <p className="text-sm text-slate-400 max-w-xl mx-auto">
            You can use XEROX without signing in. Sign in or create an account when you want
            scans and previous reports saved to your personal history.
          </p>
          <div className="flex justify-center gap-3">
            <Link to="/login"><Button variant="primary" size="sm">SIGN IN</Button></Link>
            <Link to="/register"><Button variant="secondary" size="sm">CREATE ACCOUNT</Button></Link>
            <Link to="/analyze"><Button variant="outline" size="sm">START A SCAN</Button></Link>
          </div>
        </div>
      ) : (
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
      )}
    </div>
  );
};
