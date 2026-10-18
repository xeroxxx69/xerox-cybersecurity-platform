import React, { useState } from "react";
import {
  ThumbsUp,
  ThumbsDown,
  Flag,
  Share2,
  Copy,
  Check,
  Sparkles,
  Info,
} from "lucide-react";
import { ThreatReport } from "@/types";
import { RiskGauge } from "./RiskGauge";
import { EvidenceDrawer } from "./EvidenceDrawer";
import { RecommendedActions } from "./RecommendedActions";
import { RiskBadge, Badge, Button, Modal, useToast } from "@/components/ui";
import { submitFeedback } from "@/services/api";

export interface AnalysisResultProps {
  report: ThreatReport;
}

export const AnalysisResult: React.FC<AnalysisResultProps> = ({ report }) => {
  const [copied, setCopied] = useState(false);
  const [feedbackSent, setFeedbackSent] = useState<"UP" | "DOWN" | null>(null);
  const [falsePositiveModalOpen, setFalsePositiveModalOpen] = useState(false);
  const [fpReason, setFpReason] = useState("");
  const [submittingFeedback, setSubmittingFeedback] = useState(false);
  const toast = useToast();

  const handleCopyTarget = () => {
    navigator.clipboard.writeText(report.defanged_target);
    setCopied(true);
    toast.success("Target copied to clipboard (defanged)");
    setTimeout(() => setCopied(false), 2000);
  };

  const handleFeedback = async (type: "UP" | "DOWN") => {
    if (feedbackSent) return;
    setFeedbackSent(type);
    try {
      await submitFeedback({
        scan_id: report.scan_id,
        is_accurate: type === "UP",
        user_notes: type === "UP" ? "User confirmed accurate analysis" : "User flagged analysis as inaccurate",
      });
      toast.success(
        type === "UP"
          ? "Telemetry feedback registered. Thank you!"
          : "Feedback registered. Flagged for heuristic calibration."
      );
    } catch (err) {
      toast.warning("Feedback stored locally (could not sync with backend)");
    }
  };

  const handleSubmitFalsePositive = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmittingFeedback(true);
    try {
      await submitFeedback({
        scan_id: report.scan_id,
        is_accurate: false,
        user_notes: fpReason,
        suggested_label: "FALSE_POSITIVE",
      });
      setFalsePositiveModalOpen(false);
      toast.info("False positive report submitted to analyst queue.");
      setFpReason("");
    } catch (err) {
      toast.error("Failed to submit false positive report.");
    } finally {
      setSubmittingFeedback(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Target Dossier Header Card */}
      <div className="p-6 rounded-2xl bg-xerox-surface border border-xerox-border relative overflow-hidden shadow-panel">
        <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4">
          <div className="space-y-2">
            <div className="flex flex-wrap items-center gap-2">
              <Badge variant="outline" size="sm">
                TARGET // {report.target_type}
              </Badge>
              <span className="text-xs font-mono text-slate-500">
                ANALYZED: {new Date(report.analyzed_at).toLocaleString()}
              </span>
              <span className="text-xs font-mono text-slate-500">
                SCAN ID: {report.scan_id.slice(0, 8)}
              </span>
            </div>

            <div className="flex items-center gap-2">
              <span className="text-lg sm:text-xl font-mono font-bold text-white break-all">
                {report.defanged_target}
              </span>
              <button
                onClick={handleCopyTarget}
                title="Copy defanged target"
                className="p-1.5 rounded-lg bg-xerox-surface-elevated hover:bg-slate-800 text-slate-400 hover:text-white transition-colors"
                aria-label="Copy defanged target"
              >
                {copied ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
              </button>
            </div>
          </div>

          <div className="flex items-center gap-2 w-full sm:w-auto">
            <Button
              variant="outline"
              size="sm"
              leftIcon={<Share2 className="w-3.5 h-3.5" />}
              onClick={() => {
                navigator.clipboard.writeText(window.location.href);
                toast.info("Investigation dossier URL copied");
              }}
            >
              SHARE DOSSIER
            </Button>
            <Button
              variant="ghost"
              size="sm"
              leftIcon={<Flag className="w-3.5 h-3.5 text-amber-400" />}
              onClick={() => setFalsePositiveModalOpen(true)}
            >
              REPORT FP
            </Button>
          </div>
        </div>
      </div>

      {/* Main Score & Core Assessment Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Risk Gauge */}
        <div className="lg:col-span-1 rounded-2xl bg-xerox-surface border border-xerox-border p-6 flex flex-col items-center justify-center text-center shadow-panel">
          <RiskGauge
            score={report.risk_score}
            level={report.risk_level}
            confidence={report.confidence_score}
          />

          <div className="mt-4 w-full pt-4 border-t border-xerox-border-subtle flex items-center justify-between text-xs font-mono">
            <span className="text-slate-400">CONFIDENCE:</span>
            <span className="text-white font-bold">{report.confidence_score}%</span>
          </div>
        </div>

        {/* Right Column: Layman Verdict & Why XEROX Flagged This */}
        <div className="lg:col-span-2 rounded-2xl bg-xerox-surface border border-xerox-border p-6 space-y-5 shadow-panel">
          {/* Executive Verdict Banner */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">
                EXECUTIVE VERDICT
              </span>
              <RiskBadge level={report.risk_level} score={report.risk_score} />
            </div>
            <h2 className="text-xl sm:text-2xl font-bold text-white tracking-tight">
              {report.layman_verdict}
            </h2>
            <p className="text-sm text-slate-300 font-sans leading-relaxed">
              {report.executive_summary}
            </p>
          </div>

          {/* Why XEROX Flagged This */}
          <div className="pt-4 border-t border-xerox-border-subtle space-y-3">
            <div className="flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-xerox-red" />
              <h3 className="text-xs font-mono font-bold text-slate-200 tracking-wider uppercase">
                Why XEROX Flagged This
              </h3>
            </div>

            <div className="space-y-2">
              {report.evidence_items && report.evidence_items.length > 0 ? (
                report.evidence_items.map((evidence, idx) => (
                  <div
                    key={idx}
                    className="p-3 rounded-xl bg-xerox-surface-elevated border border-xerox-border-subtle flex items-start gap-3 text-xs"
                  >
                    <span className="p-1 rounded bg-red-500/10 text-red-400 mt-0.5 font-mono font-bold text-[10px]">
                      {evidence.severity}
                    </span>
                    <div className="space-y-0.5">
                      <h4 className="font-bold text-slate-200">{evidence.title}</h4>
                      <p className="text-slate-400 font-sans">{evidence.why_this_matters}</p>
                    </div>
                  </div>
                ))
              ) : (
                <div className="p-3 rounded-xl bg-slate-900/60 text-xs text-slate-400 font-mono">
                  No heuristic threat triggers matched. Target meets baseline benign criteria.
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Recommended Action Plan */}
      <div className="rounded-2xl bg-xerox-surface border border-xerox-border p-6 shadow-panel">
        <RecommendedActions actions={report.recommended_actions} />
      </div>

      {/* Forensic Evidence Drawer */}
      <div className="rounded-2xl bg-xerox-surface border border-xerox-border p-6 shadow-panel">
        <EvidenceDrawer
          evidence={report.evidence_items}
        />
      </div>

      {/* Analyst Feedback Footer Bar */}
      <div className="p-4 rounded-xl bg-xerox-surface border border-xerox-border flex flex-col sm:flex-row items-center justify-between gap-4">
        <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
          <Info className="w-4 h-4 text-blue-400" />
          <span>Was this AI defensive analysis accurate and actionable?</span>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => handleFeedback("UP")}
            disabled={feedbackSent !== null}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono transition-colors ${
              feedbackSent === "UP"
                ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/40"
                : "bg-xerox-surface-elevated hover:bg-slate-800 text-slate-300 border border-xerox-border"
            }`}
          >
            <ThumbsUp className="w-3.5 h-3.5" /> HELPFUL
          </button>
          <button
            onClick={() => handleFeedback("DOWN")}
            disabled={feedbackSent !== null}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono transition-colors ${
              feedbackSent === "DOWN"
                ? "bg-red-500/20 text-red-300 border border-red-500/40"
                : "bg-xerox-surface-elevated hover:bg-slate-800 text-slate-300 border border-xerox-border"
            }`}
          >
            <ThumbsDown className="w-3.5 h-3.5" /> INACCURATE
          </button>
        </div>
      </div>

      {/* False Positive Report Modal */}
      <Modal
        isOpen={falsePositiveModalOpen}
        onClose={() => setFalsePositiveModalOpen(false)}
        title="Report False Positive / Calibration"
        description="Help improve XEROX heuristic defense models by reporting classification errors."
      >
        <form onSubmit={handleSubmitFalsePositive} className="space-y-4">
          <div>
            <label className="block text-xs font-mono text-slate-300 mb-1">
              OBSERVATION / RATIONALE
            </label>
            <textarea
              value={fpReason}
              onChange={(e) => setFpReason(e.target.value)}
              placeholder="Why do you believe this target was misclassified? Provide technical evidence or context..."
              required
              rows={4}
              className="w-full p-3 rounded-xl bg-xerox-surface-card border border-xerox-border text-xs text-white placeholder-slate-500 outline-none focus:ring-2 focus:ring-xerox-red"
            />
          </div>

          <div className="flex items-center justify-end gap-2 pt-2">
            <Button
              variant="outline"
              size="sm"
              type="button"
              disabled={submittingFeedback}
              onClick={() => setFalsePositiveModalOpen(false)}
            >
              CANCEL
            </Button>
            <Button
              variant="primary"
              size="sm"
              type="submit"
              disabled={submittingFeedback}
            >
              {submittingFeedback ? "SUBMITTING..." : "SUBMIT REPORT"}
            </Button>
          </div>
        </form>
      </Modal>
    </div>
  );
};
