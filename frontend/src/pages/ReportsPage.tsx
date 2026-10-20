import React, { useEffect, useState } from "react";
import { useSearchParams, useParams, Link } from "react-router-dom";
import { ArrowLeft } from "lucide-react";
import { getReport } from "@/services/api";
import { getGuestReport } from "@/services/guestStorage";
import { useAuth } from "@/features/auth/AuthContext";
import { ThreatReport } from "@/types";
import { AnalysisResult } from "@/components/threat/AnalysisResult";
import { Button, LoadingState, ErrorState } from "@/components/ui";

export const ReportsPage: React.FC = () => {
  const [searchParams] = useSearchParams();
  const { id: paramId } = useParams();
  const scanId = paramId || searchParams.get("id");
  const { user } = useAuth();
  const [report, setReport] = useState<ThreatReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!scanId) {
      setError("No scan identifier provided. Please select an investigation from the archive or run a new scan.");
      return;
    }

    // Check local guest storage first if unauthenticated
    const localReport = getGuestReport(scanId);
    if (!user && localReport) {
      setReport(localReport);
      setLoading(false);
      setError(null);
      return;
    }

    setLoading(true);
    setError(null);

    getReport(scanId)
      .then((data) => {
        setReport(data);
      })
      .catch((err) => {
        // If server retrieval failed, try local guest storage as fallback
        if (localReport) {
          setReport(localReport);
          setError(null);
        } else {
          setError(err?.userMessage || err?.message || "Dossier could not be located in the cryptographic archive.");
          setReport(null);
        }
      })

      .finally(() => setLoading(false));
  }, [scanId, user]);

  if (loading) {
    return (
      <div className="max-w-4xl mx-auto py-12">
        <LoadingState
          message="RETRIEVING ENCRYPTED SECURITY DOSSIER..."
          subMessage={`Target Scan ID: ${scanId}`}
          size="lg"
        />
      </div>
    );
  }

  if (error || !report) {
    return (
      <div className="max-w-4xl mx-auto py-12">
        <ErrorState
          title="Security Report Retrieval Failed"
          message={error || "Dossier could not be located in the current cryptographic archive."}
          action={
            <Link to="/history">
              <Button variant="outline" size="sm" leftIcon={<ArrowLeft className="w-3.5 h-3.5" />}>
                RETURN TO ARCHIVE
              </Button>
            </Link>
          }
        />
      </div>
    );
  }

  return (
    <div className="max-w-5xl mx-auto space-y-6">
      <div className="flex items-center justify-between border-b border-xerox-border-subtle pb-4">
        <Link to="/history">
          <Button
            variant="ghost"
            size="sm"
            leftIcon={<ArrowLeft className="w-4 h-4" />}
          >
            BACK TO ARCHIVE
          </Button>
        </Link>

        <span className="text-xs font-mono text-slate-500">
          CONFIDENTIAL // FORENSIC DOSSIER
        </span>
      </div>

      <AnalysisResult report={report} />
    </div>
  );
};
