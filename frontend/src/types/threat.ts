export type RiskLevel =
  | "BENIGN"
  | "LOW RISK"
  | "SUSPICIOUS"
  | "HIGH RISK"
  | "CRITICAL";

export type TargetType = "URL" | "MESSAGE" | "EMAIL" | "SCREENSHOT" | "FILE";

export type EvidenceCategory =
  | "INFRASTRUCTURE"
  | "IDENTITY"
  | "CONTENT"
  | "REPUTATION"
  | "CRYPTOGRAPHY";

export type EvidenceSeverity = "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export interface EvidenceItem {
  category: EvidenceCategory;
  severity: EvidenceSeverity;
  title: string;
  description: string;
  technical_proof: string;
  why_this_matters: string;
}

export interface RedirectHop {
  hop_number: number;
  from_url: string;
  to_url: string;
  status_code: number;
  ip_address?: string;
  response_time_ms?: number;
}

export interface RecommendedAction {
  priority: "IMMEDIATE" | "PREVENTATIVE" | "REPORTING";
  action: string;
  rationale: string;
  action_type:
    | "DO_NOT_CLICK"
    | "CHANGE_PASSWORD"
    | "REPORT_PHISHING"
    | "VERIFY_SENDER"
    | "SAFE_TO_PROCEED";
}

export interface DNSRecords {
  a: string[];
  aaaa: string[];
  mx: string[];
  ns: string[];
  txt: string[];
}

export interface SSLCertInfo {
  issuer?: string;
  subject?: string;
  valid_from?: string;
  valid_until?: string;
  is_valid: boolean;
  is_self_signed: boolean;
  days_remaining?: number;
}

export interface TechnicalMetadata {
  domain: string;
  subdomain: string;
  registered_domain: string;
  tld: string;
  ip_addresses: string[];
  dns?: DNSRecords;
  ssl?: SSLCertInfo;
  redirect_hops: RedirectHop[];
  entropy: number;
  detected_brands: string[];
  extracted_urls: string[];
  social_engineering_flags: string[];
  file_name?: string;
  file_size_bytes?: number;
  file_hash_sha256?: string;
  file_hash_md5?: string;
  mime_type?: string;
  is_executable?: boolean;
  threat_intel_summary?: string;
  threat_intel_permalink?: string;
}

export interface ThreatReport {
  scan_id: string;
  target_type: TargetType;
  raw_target: string;
  defanged_target: string;
  risk_score: number;
  risk_level: RiskLevel;
  confidence_score: number;
  executive_summary: string;
  layman_verdict: string;
  evidence_items: EvidenceItem[];
  recommended_actions: RecommendedAction[];
  technical_metadata: TechnicalMetadata;
  analyzed_at: string;
}

export interface ScanHistoryItem {
  scan_id: string;
  target_type: TargetType;
  defanged_target: string;
  risk_level: RiskLevel;
  risk_score: number;
  analyzed_at: string;
  executive_summary: string;
}

export interface StatsSummary {
  total_scans: number;
  threats_blocked: number;
  benign_verified: number;
  suspicious_flagged: number;
  scans_by_type: Record<string, number>;
}

export type SentinelState =
  | "STANDBY"
  | "IDLE"
  | "INGESTING"
  | "SCANNING"
  | "CORRELATING"
  | "VERIFIED"
  | "ALERT";
