import React, { useState, useEffect, useRef } from "react";
import { useSearchParams } from "react-router-dom";
import {
  Globe,
  Mail,
  Image as ImageIcon,
  FileCode,
  Radio,
  Sparkles,
  UploadCloud,
  FileCheck,
  X as XIcon,
  AlertTriangle,
} from "lucide-react";
import { ThreatReport, SentinelState } from "@/types";
import { SentinelRobotHUD } from "@/components/sentinel/SentinelRobotHUD";
import { ScanProgress } from "@/components/threat/ScanProgress";
import { AnalysisResult } from "@/components/threat/AnalysisResult";
import { Button, Card, Input, Textarea, Badge } from "@/components/ui";
import { scanUrl, scanMessage, scanScreenshot, scanFile } from "@/services/api";

type ActiveTab = "URL" | "MESSAGE" | "SCREENSHOT" | "FILE";

function createSampleScreenshotFile(name: string): File {
  const canvas = document.createElement("canvas");
  canvas.width = 640;
  canvas.height = 400;
  const ctx = canvas.getContext("2d");
  if (ctx) {
    ctx.fillStyle = "#18181b";
    ctx.fillRect(0, 0, 640, 400);
    ctx.fillStyle = "#ffffff";
    ctx.font = "bold 20px sans-serif";
    ctx.fillText("Microsoft Account Sign-in", 40, 60);
    ctx.font = "14px sans-serif";
    ctx.fillStyle = "#94a3b8";
    ctx.fillText("Enter your email, phone, or Skype", 40, 100);
    ctx.fillStyle = "#27272a";
    ctx.fillRect(40, 120, 400, 36);
    ctx.fillStyle = "#ef4444";
    ctx.fillRect(40, 180, 100, 36);
    ctx.fillStyle = "#ffffff";
    ctx.font = "bold 14px sans-serif";
    ctx.fillText("Sign in", 65, 203);
    ctx.fillStyle = "#f87171";
    ctx.font = "12px sans-serif";
    ctx.fillText("Security Notice: Urgent Verification Required", 40, 260);
  }
  const dataUrl = canvas.toDataURL("image/png");
  const byteString = atob(dataUrl.split(",")[1]);
  const ab = new ArrayBuffer(byteString.length);
  const ia = new Uint8Array(ab);
  for (let i = 0; i < byteString.length; i++) {
    ia[i] = byteString.charCodeAt(i);
  }
  return new File([ab], name, { type: "image/png" });
}

function createSampleDocumentFile(name: string): File {
  if (name.endsWith(".pdf")) {
    const pdfContent = "%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>\nendobj\n4 0 obj\n<< /Length 44 >>\nstream\nBT /F1 12 Tf 100 700 Td (Xerox Test Document) Tj ET\nendstream\nendobj\nxref\n0 5\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \n0000000206 00000 n \ntrailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n300\n%%EOF\n";
    return new File([pdfContent], name, { type: "application/pdf" });
  } else if (name.endsWith(".eml")) {
    const emlContent = "From: alert@usps-post-service.xyz\nReply-To: phisher@scam-hub.top\nTo: victim@example.com\nSubject: Urgent Delivery Notice\nDate: Mon, 14 Sep 2026 12:00:00 +0000\nContent-Type: text/plain\n\nYour shipment has an unpaid fee. Please verify: https://usps-redelivery-support.xyz\n";
    return new File([emlContent], name, { type: "message/rfc822" });
  } else {
    const textContent = name.endsWith(".docm")
      ? "Rem Sub Document_Open()\nShell \"powershell.exe -enc aWV4 ...\"\nEnd Sub\n"
      : "XEROX Suspicious Script / Document Test File\nhttps://malicious-test-link.xyz\n";
    return new File([textContent], name, { type: "text/plain" });
  }
}

export const AnalyzePage: React.FC = () => {
  const [searchParams] = useSearchParams();
  const initialType = (searchParams.get("type")?.toUpperCase() as ActiveTab) || "URL";
  const initialTarget = searchParams.get("target") || "";

  const [activeTab, setActiveTab] = useState<ActiveTab>(
    ["URL", "MESSAGE", "SCREENSHOT", "FILE"].includes(initialType) ? initialType : "URL"
  );
  const [inputValue, setInputValue] = useState(initialTarget);
  const [senderMetadata, setSenderMetadata] = useState("");
  const [fileName, setFileName] = useState("");
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [previewUrl, setPreviewUrl] = useState<string | null>(null);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const genericFileInputRef = useRef<HTMLInputElement | null>(null);
  const [scanning, setScanning] = useState(false);
  const [currentStage, setCurrentStage] = useState(0);
  const [report, setReport] = useState<ThreatReport | null>(null);
  const [sentinelState, setSentinelState] = useState<SentinelState>("IDLE");
  const [scanError, setScanError] = useState<string | null>(null);

  // Synchronize when query params change
  useEffect(() => {
    const typeParam = searchParams.get("type")?.toUpperCase() as ActiveTab;
    if (typeParam && ["URL", "MESSAGE", "SCREENSHOT", "FILE"].includes(typeParam)) {
      setActiveTab(typeParam);
    }
    const targetParam = searchParams.get("target");
    if (targetParam) setInputValue(targetParam);
  }, [searchParams]);

  const handleTabSwitch = (tab: ActiveTab) => {
    setActiveTab(tab);
    setReport(null);
    setUploadError(null);
    setScanError(null);
    setInputValue("");
    setSelectedFile(null);
    setFileName("");
    if (previewUrl) {
      URL.revokeObjectURL(previewUrl);
      setPreviewUrl(null);
    }
  };

  const handleFileChange = (file: File | null) => {
    setUploadError(null);
    setScanError(null);
    if (!file) {
      setSelectedFile(null);
      setPreviewUrl(null);
      setFileName("");
      return;
    }

    if (activeTab === "FILE") {
      const allowedExts = [".pdf", ".docx", ".docm", ".eml", ".txt", ".zip", ".csv", ".json", ".ps1", ".bat"];
      const lowerName = file.name.toLowerCase();
      const hasValidExt = allowedExts.some((ext) => lowerName.endsWith(ext));
      if (!hasValidExt) {
        setUploadError("Unsupported format. Please upload PDF, DOCX, DOCM, EML, TXT, or ZIP.");
        return;
      }
      if (file.size > 15 * 1024 * 1024) {
        setUploadError("File size exceeds the 15 MB maximum limit.");
        return;
      }
      setSelectedFile(file);
      setFileName(file.name);
      setPreviewUrl(null);
      return;
    }

    // Screenshot tab
    const validMimes = ["image/png", "image/jpeg", "image/jpg", "image/webp"];
    if (!validMimes.includes(file.type.toLowerCase())) {
      setUploadError("Unsupported format. Please upload a PNG, JPEG, or WEBP image.");
      return;
    }

    if (file.size > 10 * 1024 * 1024) {
      setUploadError("File size exceeds the 10 MB maximum limit.");
      return;
    }

    setSelectedFile(file);
    setFileName(file.name);
    const url = URL.createObjectURL(file);
    setPreviewUrl(url);
  };

  const handleClearFile = (e: React.MouseEvent) => {
    e.stopPropagation();
    setSelectedFile(null);
    setPreviewUrl(null);
    setFileName("");
    setUploadError(null);
    setScanError(null);
    if (fileInputRef.current) {
      fileInputRef.current.value = "";
    }
    if (genericFileInputRef.current) {
      genericFileInputRef.current.value = "";
    }
  };

  // Handle analysis initiation with live multi-stage security pipeline
  const handleAnalyze = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    const effectiveInput = activeTab === "SCREENSHOT" || activeTab === "FILE"
      ? fileName || inputValue || ""
      : inputValue;

    if (!effectiveInput.trim() && !selectedFile) return;

    setReport(null);
    setScanError(null);
    setScanning(true);
    setCurrentStage(0);
    setSentinelState("SCANNING");

    // Stage progression animation interval
    const stageInterval = setInterval(() => {
      setCurrentStage((prev) => (prev < 5 ? prev + 1 : prev));
    }, 280);

    try {
      let finalReport: ThreatReport;

      if (activeTab === "URL") {
        finalReport = await scanUrl(effectiveInput.trim());
      } else if (activeTab === "MESSAGE") {
        finalReport = await scanMessage(effectiveInput.trim(), senderMetadata.trim() || undefined);
      } else if (activeTab === "SCREENSHOT") {
        if (!selectedFile) {
          throw new Error("Please select or drop an image file (PNG, JPEG, WEBP) to inspect.");
        }
        finalReport = await scanScreenshot(selectedFile);
      } else if (activeTab === "FILE") {
        if (!selectedFile) {
          throw new Error("Please select or drop a file (PDF, DOCX, DOCM, EML, ZIP, TXT) to inspect.");
        }
        finalReport = await scanFile(selectedFile);
      } else {
        throw new Error("Unsupported target type.");
      }

      clearInterval(stageInterval);
      setCurrentStage(6);

      if (
        finalReport.risk_level === "CRITICAL" ||
        finalReport.risk_level === "HIGH RISK" ||
        finalReport.risk_level === "SUSPICIOUS"
      ) {
        setSentinelState("ALERT");
      } else {
        setSentinelState("VERIFIED");
      }

      setReport(finalReport);
    } catch (err: any) {
      clearInterval(stageInterval);
      setScanError(err.message || "Security analysis failed. Please verify credentials and connectivity.");
      setSentinelState("IDLE");
    } finally {
      setScanning(false);
    }
  };

  const sampleTargets = {
    URL: [
      {
        label: "Phishing: Fake Apple ID Portal",
        val: "https://apple-id-verify.support-secure.live/auth",
      },
      {
        label: "Verified Safe: GitHub Portal",
        val: "https://github.com",
      },
    ],
    MESSAGE: [
      {
        label: "Smishing: Fake Postal Customs Charge",
        val: "USPS Alert: Your package has an unpaid customs charge of $2.49. Delivery will be cancelled within 12 hours: https://usps-redelivery-support.xyz",
      },
      {
        label: "Benign: Standard Team Meeting Lure",
        val: "Hi team, please review the security telemetry documentation attached to the internal project board.",
      },
    ],
    SCREENSHOT: [
      {
        label: "Fake M365 Login Prompt",
        val: "sample_m365_login_capture.png",
      },
      {
        label: "Suspicious QR Code Overlay",
        val: "parking_meter_qr_sticker.jpg",
      },
    ],
    FILE: [
      {
        label: "Invoice_Overdue_March.docm",
        val: "Invoice_Overdue_March.docm",
      },
      {
        label: "Safe_Project_Roadmap.pdf",
        val: "Safe_Project_Roadmap.pdf",
      },
    ],
  };

  return (
    <div className="space-y-8 max-w-5xl mx-auto">
      {/* Sentinel Robot Diagnostic Visualizer */}
      <SentinelRobotHUD
        state={sentinelState}
        riskLevel={report?.risk_level}
        riskScore={report?.risk_score}
        targetPreview={report?.defanged_target || (inputValue ? inputValue.slice(0, 80) : undefined)}
      />

      {/* Target Submission Workspace Card */}
      <Card variant="default" className="shadow-panel space-y-6">
        {/* Mode Selector Tabs */}
        <div className="flex flex-wrap items-center justify-between border-b border-xerox-border-subtle pb-4 gap-3">
          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={() => handleTabSwitch("URL")}
              className={`flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-mono font-bold tracking-wide transition-all ${
                activeTab === "URL"
                  ? "bg-xerox-red/15 text-red-400 border border-xerox-red/40 shadow-[0_0_15px_rgba(239,68,68,0.2)]"
                  : "text-slate-400 hover:text-slate-200 hover:bg-xerox-surface-elevated border border-transparent"
              }`}
            >
              <Globe className="w-4 h-4" />
              URL
            </button>

            <button
              onClick={() => handleTabSwitch("MESSAGE")}
              className={`flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-mono font-bold tracking-wide transition-all ${
                activeTab === "MESSAGE"
                  ? "bg-xerox-red/15 text-red-400 border border-xerox-red/40 shadow-[0_0_15px_rgba(239,68,68,0.2)]"
                  : "text-slate-400 hover:text-slate-200 hover:bg-xerox-surface-elevated border border-transparent"
              }`}
            >
              <Mail className="w-4 h-4" />
              MESSAGE
            </button>

            <button
              onClick={() => handleTabSwitch("SCREENSHOT")}
              className={`flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-mono font-bold tracking-wide transition-all ${
                activeTab === "SCREENSHOT"
                  ? "bg-xerox-red/15 text-red-400 border border-xerox-red/40 shadow-[0_0_15px_rgba(239,68,68,0.2)]"
                  : "text-slate-400 hover:text-slate-200 hover:bg-xerox-surface-elevated border border-transparent"
              }`}
            >
              <ImageIcon className="w-4 h-4" />
              SCREENSHOT
            </button>

            <button
              onClick={() => handleTabSwitch("FILE")}
              className={`flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-mono font-bold tracking-wide transition-all ${
                activeTab === "FILE"
                  ? "bg-xerox-red/15 text-red-400 border border-xerox-red/40 shadow-[0_0_15px_rgba(239,68,68,0.2)]"
                  : "text-slate-400 hover:text-slate-200 hover:bg-xerox-surface-elevated border border-transparent"
              }`}
            >
              <FileCode className="w-4 h-4" />
              FILE
            </button>
          </div>

          <span className="text-[11px] font-mono text-slate-500">
            WEAPONLESS // NON-DETONATING
          </span>
        </div>

        {/* Input Form */}
        <form onSubmit={handleAnalyze} className="space-y-4">
          {activeTab === "URL" && (
            <Input
              label="TARGET WEB LOCATION / URL"
              type="text"
              value={inputValue}
              onChange={(e) => setInputValue(e.target.value)}
              placeholder="https://suspect-domain.example/login.php"
              required
              className="font-mono text-sm"
              helperText="URLs are safely defanged before transmission. No active scripts will execute."
              leftIcon={<Globe className="w-4 h-4 text-slate-400" />}
            />
          )}

          {activeTab === "MESSAGE" && (
            <div className="space-y-4">
              <Textarea
                label="MESSAGE BODY / EMAIL / SMS LURE"
                value={inputValue}
                onChange={(e) => setInputValue(e.target.value)}
                placeholder="Paste the complete SMS text, email body, or urgent message lure..."
                required
                rows={5}
                className="font-mono text-xs"
                helperText="Evaluates psychological manipulation, urgency indicators, and extracted links."
              />

              <Input
                label="OPTIONAL SENDER METADATA / PHONE / HEADER"
                type="text"
                value={senderMetadata}
                onChange={(e) => setSenderMetadata(e.target.value)}
                placeholder="e.g. +1 (800) 555-0199 or alert@usps-services.com"
                className="font-mono text-xs"
                leftIcon={<Mail className="w-4 h-4 text-slate-400" />}
              />
            </div>
          )}

          {activeTab === "SCREENSHOT" && (
            <div className="space-y-4">
              <input
                type="file"
                ref={fileInputRef}
                className="hidden"
                accept="image/png,image/jpeg,image/webp"
                onChange={(e) => handleFileChange(e.target.files?.[0] || null)}
              />

              <div
                onClick={() => fileInputRef.current?.click()}
                onDragOver={(e) => {
                  e.preventDefault();
                  e.stopPropagation();
                }}
                onDrop={(e) => {
                  e.preventDefault();
                  e.stopPropagation();
                  if (e.dataTransfer.files && e.dataTransfer.files[0]) {
                    handleFileChange(e.dataTransfer.files[0]);
                  }
                }}
                className="p-6 border-2 border-dashed border-xerox-border hover:border-xerox-red/50 rounded-2xl bg-xerox-surface-elevated/40 hover:bg-xerox-surface-elevated/70 text-center space-y-4 cursor-pointer transition-all"
              >
                {previewUrl ? (
                  <div className="space-y-3">
                    <div className="relative inline-block max-w-sm mx-auto">
                      <img
                        src={previewUrl}
                        alt="Screenshot Preview"
                        className="max-h-48 rounded-xl object-contain mx-auto border border-xerox-border shadow-lg"
                      />
                      <button
                        type="button"
                        onClick={handleClearFile}
                        className="absolute -top-2 -right-2 p-1.5 rounded-full bg-red-600 hover:bg-red-700 text-white shadow-md transition-colors"
                        title="Remove screenshot"
                      >
                        <XIcon className="w-3.5 h-3.5" />
                      </button>
                    </div>

                    <div className="flex flex-wrap items-center justify-center gap-2">
                      <Badge variant="safe" size="sm" icon={<FileCheck className="w-3.5 h-3.5" />}>
                        LOADED: {fileName}
                      </Badge>
                      {selectedFile && (
                        <span className="text-[11px] font-mono text-slate-400">
                          ({(selectedFile.size / 1024).toFixed(1)} KB)
                        </span>
                      )}
                    </div>
                    <p className="text-[11px] font-mono text-slate-500">
                      Click or drop another image to replace
                    </p>
                  </div>
                ) : (
                  <div className="space-y-3">
                    <div className="w-12 h-12 rounded-2xl bg-xerox-surface border border-xerox-border mx-auto flex items-center justify-center text-slate-400">
                      <UploadCloud className="w-6 h-6 text-xerox-red" />
                    </div>
                    <div className="space-y-1">
                      <p className="text-sm font-bold text-white">
                        {fileName ? fileName : "Drag & drop screenshot here, or click to browse"}
                      </p>
                      <p className="text-xs text-slate-500 font-mono">
                        Supported: PNG, JPEG, WEBP (Max 10MB). Static OCR & heuristic inspection only.
                      </p>
                    </div>
                    {fileName && !previewUrl && (
                      <Badge variant="safe" size="sm" icon={<FileCheck className="w-3.5 h-3.5" />}>
                        FIXTURE SELECTED: {fileName}
                      </Badge>
                    )}
                  </div>
                )}
              </div>

              {uploadError && (
                <div className="p-3 rounded-xl bg-red-950/40 border border-red-800/60 text-red-400 text-xs font-mono">
                  {uploadError}
                </div>
              )}
            </div>
          )}

          {activeTab === "FILE" && (
            <div className="space-y-4">
              <input
                type="file"
                ref={genericFileInputRef}
                className="hidden"
                accept=".pdf,.docx,.docm,.eml,.txt,.zip,.csv,.json,.ps1,.bat"
                onChange={(e) => handleFileChange(e.target.files?.[0] || null)}
              />

              <div
                onClick={() => genericFileInputRef.current?.click()}
                onDragOver={(e) => {
                  e.preventDefault();
                  e.stopPropagation();
                }}
                onDrop={(e) => {
                  e.preventDefault();
                  e.stopPropagation();
                  if (e.dataTransfer.files && e.dataTransfer.files[0]) {
                    handleFileChange(e.dataTransfer.files[0]);
                  }
                }}
                className="p-8 border-2 border-dashed border-xerox-border rounded-2xl bg-xerox-surface-elevated/40 hover:border-xerox-red/50 hover:bg-xerox-surface-elevated/70 text-center space-y-3 cursor-pointer transition-all"
              >
                <div className="w-12 h-12 rounded-2xl bg-xerox-surface border border-xerox-border mx-auto flex items-center justify-center text-slate-400">
                  <UploadCloud className="w-6 h-6 text-xerox-red" />
                </div>
                <div className="space-y-1">
                  <p className="text-sm font-bold text-white">
                    {fileName ? fileName : "Drag & drop file here, or click to browse"}
                  </p>
                  <p className="text-xs text-slate-500 font-mono">
                    Supported: PDF, DOCX, DOCM, EML, ZIP, TXT (Max 15MB). Safe static inspection only.
                  </p>
                </div>
                {fileName && (
                  <div className="flex flex-wrap items-center justify-center gap-2 pt-1">
                    <Badge variant="safe" size="sm" icon={<FileCheck className="w-3.5 h-3.5" />}>
                      LOADED: {fileName}
                    </Badge>
                    {selectedFile && (
                      <span className="text-[11px] font-mono text-slate-400">
                        ({(selectedFile.size / 1024).toFixed(1)} KB)
                      </span>
                    )}
                    <button
                      type="button"
                      onClick={handleClearFile}
                      className="p-1 rounded bg-red-950 hover:bg-red-900 text-red-300 transition-colors ml-1"
                      title="Clear file"
                    >
                      <XIcon className="w-3 h-3" />
                    </button>
                  </div>
                )}
              </div>

              {uploadError && (
                <div className="p-3 rounded-xl bg-red-950/40 border border-red-800/60 text-red-400 text-xs font-mono">
                  {uploadError}
                </div>
              )}
            </div>
          )}

          {/* Quick Presets / Test Samples */}
          <div className="flex flex-wrap items-center gap-2 pt-2">
            <span className="text-[11px] font-mono text-slate-500 flex items-center gap-1">
              <Sparkles className="w-3 h-3 text-red-400" /> Test Fixtures:
            </span>
            {sampleTargets[activeTab].map((sample, idx) => (
              <button
                key={idx}
                type="button"
                onClick={() => {
                  setReport(null);
                  setUploadError(null);
                  setScanError(null);
                  if (activeTab === "SCREENSHOT") {
                    setFileName(sample.val);
                    setInputValue(sample.val);
                    const fixtureFile = createSampleScreenshotFile(sample.val);
                    setSelectedFile(fixtureFile);
                    setPreviewUrl(URL.createObjectURL(fixtureFile));
                  } else if (activeTab === "FILE") {
                    setFileName(sample.val);
                    setInputValue(sample.val);
                    const fixtureFile = createSampleDocumentFile(sample.val);
                    setSelectedFile(fixtureFile);
                    setPreviewUrl(null);
                  } else {
                    setInputValue(sample.val);
                    setSelectedFile(null);
                    setPreviewUrl(null);
                    setFileName("");
                  }
                }}
                className="px-2.5 py-1 rounded-lg bg-xerox-surface-elevated hover:bg-slate-800 text-[11px] font-mono text-slate-300 border border-xerox-border transition-colors truncate max-w-[280px]"
              >
                {sample.label}
              </button>
            ))}
          </div>

          {/* Submit Button */}
          <div className="pt-4 flex items-center justify-end">
            <Button
              type="submit"
              variant="primary"
              size="lg"
              loading={scanning}
              loadingText="HEURISTIC PIPELINE ACTIVE..."
              rightIcon={<Radio className="w-4 h-4 animate-pulse" />}
              disabled={!(activeTab === "SCREENSHOT" || activeTab === "FILE" ? fileName || inputValue : inputValue.trim())}
            >
              ANALYZE TARGET
            </Button>
          </div>
        </form>
      </Card>

      {/* Interactive Scan Progress Pipeline */}
      {scanning && (
        <ScanProgress
          currentStageIndex={currentStage}
          targetName={inputValue || fileName}
        />
      )}

      {/* Scan Error Presentation */}
      {scanError && !scanning && (
        <Card variant="alert" className="p-5 border-red-800/80 bg-red-950/30 shadow-panel">
          <div className="flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 text-xerox-red flex-shrink-0 mt-0.5" />
            <div className="space-y-1">
              <h4 className="text-sm font-bold text-white font-mono uppercase tracking-wide">
                Security Analysis Failed
              </h4>
              <p className="text-xs text-red-300 font-sans leading-relaxed">
                {scanError}
              </p>
            </div>
          </div>
        </Card>
      )}

      {/* Result Presentation */}
      {report && !scanning && <AnalysisResult report={report} />}
    </div>
  );
};
