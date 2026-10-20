import type {
  ThreatReport,
  EvidenceItem,
  RecommendedAction,
  RiskLevel,
} from "@/types";

const DANGEROUS_EXTENSIONS = new Set([
  ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".iso", ".img",
  ".zip", ".rar", ".7z", ".tar", ".gz", ".apk", ".dmg", ".pkg", ".docm", ".xlsm"
]);

function generateUuid(): string {
  try {
    if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
      return crypto.randomUUID();
    }
  } catch {
    // fallback
  }
  return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === "x" ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

async function computeSha256(file: File): Promise<string> {
  try {
    if (typeof crypto !== "undefined" && crypto.subtle) {
      const buffer = await file.slice(0, 1024 * 1024 * 5).arrayBuffer(); // first 5MB
      const hashBuffer = await crypto.subtle.digest("SHA-256", buffer);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
    }
  } catch (err) {
    console.warn("Failed to compute SHA-256 client-side:", err);
  }
  return "hash_unavailable_in_sandbox";
}

async function readHeaderBytes(file: File, bytesToRead = 16): Promise<Uint8Array> {
  try {
    const slice = file.slice(0, bytesToRead);
    const buffer = await slice.arrayBuffer();
    return new Uint8Array(buffer);
  } catch {
    return new Uint8Array(0);
  }
}

export async function analyzeFileClientSide(file: File): Promise<ThreatReport> {
  const scanId = generateUuid();
  const analyzedAt = new Date().toISOString();
  const fileName = file.name || "unnamed_upload";
  const defangedName = fileName.replace(/\./g, "[.]");
  const fileSize = file.size;
  const mimeType = file.type || "application/octet-stream";

  const findings: EvidenceItem[] = [];
  let score = 0;

  // Compute cryptographic SHA-256
  const sha256 = await computeSha256(file);
  const headerBytes = await readHeaderBytes(file, 16);

  // 1. Magic Bytes Identification
  let detectedType = "unknown";
  let isExecutableHeader = false;

  if (headerBytes.length >= 2 && headerBytes[0] === 0x4D && headerBytes[1] === 0x5A) {
    detectedType = "Windows PE / Executable (MZ)";
    isExecutableHeader = true;
  } else if (headerBytes.length >= 4 && headerBytes[0] === 0x7F && headerBytes[1] === 0x45 && headerBytes[2] === 0x4C && headerBytes[3] === 0x46) {
    detectedType = "Linux ELF Executable";
    isExecutableHeader = true;
  } else if (headerBytes.length >= 4 && headerBytes[0] === 0x25 && headerBytes[1] === 0x50 && headerBytes[2] === 0x44 && headerBytes[3] === 0x46) {
    detectedType = "Adobe Portable Document Format (PDF)";
  } else if (headerBytes.length >= 4 && headerBytes[0] === 0x50 && headerBytes[1] === 0x4B && headerBytes[2] === 0x03 && headerBytes[3] === 0x04) {
    detectedType = "ZIP Compressed Archive / Office OpenXML";
  } else if (headerBytes.length >= 4 && headerBytes[0] === 0xD0 && headerBytes[1] === 0xCF && headerBytes[2] === 0x11 && headerBytes[3] === 0xE0) {
    detectedType = "Microsoft Compound Document / OLE";
  }

  // 2. Double Extension Trickery
  const nameParts = fileName.split(".");
  if (nameParts.length > 2) {
    const trailingExt = `.${nameParts[nameParts.length - 1].toLowerCase()}`;
    const precedingExt = `.${nameParts[nameParts.length - 2].toLowerCase()}`;
    if (DANGEROUS_EXTENSIONS.has(trailingExt)) {
      score += 60;
      findings.push({
        category: "CONTENT",
        severity: "CRITICAL",
        title: "Deceptive Double File Extension Detected",
        description: `File disguises an executable (${trailingExt}) behind an innocent preceding extension (${precedingExt}).`,
        technical_proof: `Filename: ${fileName} -> [${precedingExt}][${trailingExt}]`,
        why_this_matters: "Attackers use double extensions (e.g. invoice.pdf.exe) hoping victims and file managers will only notice the PDF icon.",
      });
    }
  }

  // 3. Executable Header Mismatch
  const lowerName = fileName.toLowerCase();
  const reportedExtMatch = lowerName.match(/\.[a-z0-9]+$/);
  const reportedExt = reportedExtMatch ? reportedExtMatch[0] : "";

  if (isExecutableHeader && (reportedExt === ".pdf" || reportedExt === ".docx" || reportedExt === ".jpg" || reportedExt === ".png")) {
    score += 80;
    findings.push({
      category: "CONTENT",
      severity: "CRITICAL",
      title: "File Extension / Header Signature Mismatch",
      description: `File claims to be ${reportedExt} but binary header contains executable magic bytes (${detectedType}).`,
      technical_proof: `Header bytes: 0x4D 0x5A ('MZ') vs Reported extension '${reportedExt}'`,
      why_this_matters: "Disguising executables as images or office documents is a definitive indicator of targeted malware delivery.",
    });
  } else if (isExecutableHeader) {
    score += 65;
    findings.push({
      category: "CONTENT",
      severity: "HIGH",
      title: `Executable Binary Detected (${detectedType})`,
      description: "File contains native binary executable instructions.",
      technical_proof: `Magic header: ${detectedType}`,
      why_this_matters: "Unsolicited executable binaries pose immediate remote code execution risks.",
    });
  }

  // 4. Macro-Enabled Document Extension
  if (reportedExt === ".docm" || reportedExt === ".xlsm" || reportedExt === ".pptm") {
    score += 45;
    findings.push({
      category: "CONTENT",
      severity: "HIGH",
      title: "Macro-Enabled Office Document Format",
      description: `File uses a macro-enabled extension (${reportedExt}) capable of executing Visual Basic for Applications (VBA) code.`,
      technical_proof: `Format extension: ${reportedExt}`,
      why_this_matters: "Macro-enabled office files are the single most prolific vehicle for initial ransomware and banking trojan deployment.",
    });
  }

  // 5. Client Sandbox Attribution
  findings.push({
    category: "CONTENT",
    severity: "INFO",
    title: "Client-Side Isolated Structural Inspection",
    description: "Evaluated in browser using cryptographic hashing and binary header parsing with zero execution.",
    technical_proof: `SHA-256: ${sha256} | Size: ${(fileSize / 1024).toFixed(1)} KB`,
    why_this_matters: "Ensures dangerous binaries are analyzed safely without detonation or uploading sensitive files to cloud servers.",
  });

  const finalScore = Math.min(100, Math.max(0, score));

  let riskLevel: RiskLevel = "BENIGN";
  if (finalScore >= 80) riskLevel = "CRITICAL";
  else if (finalScore >= 60) riskLevel = "HIGH RISK";
  else if (finalScore >= 35) riskLevel = "SUSPICIOUS";
  else if (finalScore >= 15) riskLevel = "LOW RISK";

  let verdict = "File structure conforms to expected file format specifications without obvious executable camouflage.";
  if (riskLevel === "CRITICAL" || riskLevel === "HIGH RISK") {
    verdict = "DANGER: This file exhibits dangerous executable camouflage or macro execution capabilities. DO NOT OPEN.";
  } else if (riskLevel === "SUSPICIOUS") {
    verdict = "CAUTION: File has unusual structural or extension attributes. Inspect in a sandbox environment before opening.";
  }

  const recommendedActions: RecommendedAction[] = [];
  if (finalScore >= 60) {
    recommendedActions.push({
      priority: "IMMEDIATE",
      action: "Do not open, mount, or execute this file.",
      rationale: "Executable or camouflaged payload signature detected.",
      action_type: "DO_NOT_CLICK",
    });
  } else {
    recommendedActions.push({
      priority: "PREVENTATIVE",
      action: "Standard file structure verified.",
      rationale: "No disguised executable headers detected.",
      action_type: "SAFE_TO_PROCEED",
    });
  }

  return {
    scan_id: scanId,
    target_type: "FILE",
    raw_target: fileName,
    defanged_target: defangedName,
    risk_score: finalScore,
    risk_level: riskLevel,
    confidence_score: 95,
    executive_summary: `Static file inspection classified file as ${riskLevel} (score: ${finalScore}/100). Header format: ${detectedType}.`,
    layman_verdict: verdict,
    evidence_items: findings,
    recommended_actions: recommendedActions,
    technical_metadata: {
      domain: "",
      subdomain: "",
      registered_domain: "",
      tld: "",
      ip_addresses: [],
      redirect_hops: [],
      entropy: 0,
      detected_brands: [],
      extracted_urls: [],
      social_engineering_flags: [],
      file_name: fileName,
      file_size_bytes: fileSize,
      file_hash_sha256: sha256,
      mime_type: mimeType,
      is_executable: isExecutableHeader,
    },
    analyzed_at: analyzedAt,
  };
}
