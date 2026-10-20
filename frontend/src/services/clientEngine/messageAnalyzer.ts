import type {
  ThreatReport,
  EvidenceItem,
  RecommendedAction,
  RiskLevel,
} from "@/types";
import { defangUrl, calculateShannonEntropy } from "./urlAnalyzer";

const INSTITUTIONAL_BRANDS: Record<string, { name: string; keywords: string[] }> = {
  usps: {
    name: "United States Postal Service (USPS)",
    keywords: ["usps", "postal service", "post office", "priority mail", "package delivery"],
  },
  fedex: {
    name: "FedEx",
    keywords: ["fedex", "federal express", "delivery attempt"],
  },
  dhl: {
    name: "DHL Express",
    keywords: ["dhl", "dhl express", "customs duty"],
  },
  chase: {
    name: "JPMorgan Chase Bank",
    keywords: ["chase bank", "chase account", "jpmorgan"],
  },
  bofa: {
    name: "Bank of America",
    keywords: ["bank of america", "bofa", "zelle transfer"],
  },
  wellsfargo: {
    name: "Wells Fargo",
    keywords: ["wells fargo", "online banking alert"],
  },
  paypal: {
    name: "PayPal",
    keywords: ["paypal", "paypal account", "unauthorized payment"],
  },
  apple: {
    name: "Apple Inc.",
    keywords: ["apple id", "icloud storage", "apple support", "find my iphone"],
  },
  microsoft: {
    name: "Microsoft 365",
    keywords: ["microsoft 365", "m365", "outlook password", "office 365 session"],
  },
  netflix: {
    name: "Netflix",
    keywords: ["netflix subscription", "netflix payment", "membership suspended"],
  },
};

const URGENCY_PATTERNS = [
  /urgent/i,
  /immediately/i,
  /within 24 hours/i,
  /account suspended/i,
  /account terminated/i,
  /unauthorized transaction/i,
  /action required/i,
  /security alert/i,
  /final notice/i,
  /compromised/i,
  /unusual activity/i,
];

const CREDENTIAL_HARVESTING_PATTERNS = [
  /verify your (identity|account|password|pin)/i,
  /click here to (login|sign in|confirm|verify|unlock)/i,
  /update your (billing|payment|security|credentials)/i,
  /reset your password/i,
  /enter your (ssn|social security|card number|credentials)/i,
];

const SECRET_PATTERNS: Array<{ name: string; regex: RegExp; severity: "HIGH" | "CRITICAL" }> = [
  { name: "AWS Access Key ID", regex: /\b(AKIA[0-9A-Z]{16})\b/, severity: "CRITICAL" },
  { name: "GitHub Personal Access Token", regex: /\b(ghp_[0-9a-zA-Z]{36})\b/, severity: "CRITICAL" },
  { name: "RSA / SSH Private Key Header", regex: /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/, severity: "CRITICAL" },
  { name: "JSON Web Token (JWT)", regex: /\beyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*\b/, severity: "HIGH" },
  { name: "Generic API Key or Secret Token", regex: /\b(api[_-]?key|secret[_-]?token|bearer)\s*[:=]\s*['"][a-zA-Z0-9_\-]{16,}['"]/i, severity: "HIGH" },
];

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

export function analyzeMessageClientSide(rawMessage: string): ThreatReport {
  const cleaned = rawMessage.trim();
  const scanId = generateUuid();
  const analyzedAt = new Date().toISOString();
  const findings: EvidenceItem[] = [];
  const detectedBrands: string[] = [];
  const socialFlags: string[] = [];
  let score = 0;

  // Extract URLs
  const urlRegex = /(https?:\/\/[^\s<>"'{}|\\^`]+)/gi;
  const extractedUrls = cleaned.match(urlRegex) || [];

  // 1. Psychological Urgency Cues
  const matchedUrgency: string[] = [];
  for (const pattern of URGENCY_PATTERNS) {
    if (pattern.test(cleaned)) {
      matchedUrgency.push(pattern.source.replace(/[\\^$i/]/g, ""));
    }
  }
  if (matchedUrgency.length > 0) {
    score += Math.min(35, matchedUrgency.length * 15);
    findings.push({
      category: "CONTENT",
      severity: matchedUrgency.length >= 2 ? "HIGH" : "MEDIUM",
      title: "Psychological Coercion & Urgency Language",
      description: `Message deploys artificial urgency or panic cues (${matchedUrgency.slice(0, 3).join(", ")}).`,
      technical_proof: `Urgency matches: ${matchedUrgency.join(", ")}`,
      why_this_matters: "Social engineers use fear and artificial time pressure to rush victims into bypassing their critical thinking.",
    });
    socialFlags.push("urgency_pressure");
  }

  // 2. Credential Harvesting Cues
  const matchedHarvesting: string[] = [];
  for (const pattern of CREDENTIAL_HARVESTING_PATTERNS) {
    if (pattern.test(cleaned)) {
      matchedHarvesting.push(pattern.source.replace(/[\\^$i/]/g, ""));
    }
  }
  if (matchedHarvesting.length > 0) {
    score += 40;
    findings.push({
      category: "IDENTITY",
      severity: "HIGH",
      title: "Credential Harvesting Solicitations",
      description: "Message requests that the recipient verify passwords, security credentials, or billing data.",
      technical_proof: `Solicitation matches: ${matchedHarvesting.join(", ")}`,
      why_this_matters: "Reputable institutions will never ask users to verify passwords or enter payment details via unauthenticated messages.",
    });
    socialFlags.push("credential_solicitation");
  }

  // 3. Institutional Brand Spoofing
  const lowerMessage = cleaned.toLowerCase();
  for (const [brandKey, brandInfo] of Object.entries(INSTITUTIONAL_BRANDS)) {
    const brandMentioned = brandInfo.keywords.some((kw) => lowerMessage.includes(kw));
    if (brandMentioned) {
      detectedBrands.push(brandInfo.name);
      score += 25;
      findings.push({
        category: "IDENTITY",
        severity: "MEDIUM",
        title: `Impersonation of ${brandInfo.name}`,
        description: `Message explicitly references brand and service markers associated with ${brandInfo.name}.`,
        technical_proof: `Institutional markers identified: ${brandKey}`,
        why_this_matters: "Attackers mimic recognizable brands to exploit brand trust and trick users into clicking phishing links.",
      });
      socialFlags.push(`brand_${brandKey}`);
    }
  }

  // 4. Secret & Token Leak Detection (Safety Audit)
  for (const sec of SECRET_PATTERNS) {
    const match = cleaned.match(sec.regex);
    if (match) {
      score += 50;
      findings.push({
        category: "CRYPTOGRAPHY",
        severity: sec.severity,
        title: `Exposed Secret / Credential Pattern (${sec.name})`,
        description: `Detected plaintext cryptographic credential or authentication token in user content.`,
        technical_proof: `Matched pattern: ${sec.name} (masked: ${match[0].slice(0, 4)}...[REDACTED])`,
        why_this_matters: "Pasting secrets or API keys into untrusted channels risks total account takeover and cloud resource abuse.",
      });
      socialFlags.push("secret_exposure");
    }
  }

  // 5. Embedded Links with Urgency
  if (extractedUrls.length > 0 && (matchedUrgency.length > 0 || matchedHarvesting.length > 0)) {
    score += 20;
    findings.push({
      category: "CONTENT",
      severity: "HIGH",
      title: "High-Risk Call-to-Action Link Combination",
      description: `Message pairs ${extractedUrls.length} external link(s) with high-pressure call-to-action language.`,
      technical_proof: `Links detected: ${extractedUrls.slice(0, 3).map((u) => defangUrl(u)).join(", ")}`,
      why_this_matters: "The combination of high urgency and an embedded link is the definitive signature of phishing and smishing delivery.",
    });
  }

  // 6. Transparent Sandbox Attribution
  findings.push({
    category: "CONTENT",
    severity: "INFO",
    title: "Client-Side Autonomous Message Heuristics",
    description: "Evaluated using deterministic social engineering lexical dictionaries and regex pattern matchers in local browser sandbox.",
    technical_proof: "Execution completed in client sandbox with zero telemetry egress.",
    why_this_matters: "Provides instantaneous threat analysis while keeping message contents private on your device.",
  });

  const finalScore = Math.min(100, Math.max(0, score));

  let riskLevel: RiskLevel = "BENIGN";
  if (finalScore >= 80) riskLevel = "CRITICAL";
  else if (finalScore >= 60) riskLevel = "HIGH RISK";
  else if (finalScore >= 35) riskLevel = "SUSPICIOUS";
  else if (finalScore >= 15) riskLevel = "LOW RISK";

  let verdict = "This message does not exhibit obvious phishing or social engineering patterns.";
  if (riskLevel === "CRITICAL" || riskLevel === "HIGH RISK") {
    verdict = "DANGER: This message exhibits classic phishing, credential harvesting, or secret leak indicators. Do NOT respond or click links.";
  } else if (riskLevel === "SUSPICIOUS") {
    verdict = "CAUTION: Message displays psychological urgency or unverified brand references. Verify through an independent channel.";
  }

  const recommendedActions: RecommendedAction[] = [];
  if (finalScore >= 60) {
    recommendedActions.push({
      priority: "IMMEDIATE",
      action: "Do not click any links or provide credentials.",
      rationale: "High confidence social engineering indicators detected.",
      action_type: "DO_NOT_CLICK",
    });
    recommendedActions.push({
      priority: "REPORTING",
      action: "Forward message to your security team or spam reporting inbox.",
      rationale: "Helps update defensive email gateway filters.",
      action_type: "REPORT_PHISHING",
    });
  } else {
    recommendedActions.push({
      priority: "PREVENTATIVE",
      action: "Always verify unexpected messages with the alleged sender directly.",
      rationale: "General defensive operational security practice.",
      action_type: "SAFE_TO_PROCEED",
    });
  }

  return {
    scan_id: scanId,
    target_type: "MESSAGE",
    raw_target: cleaned.slice(0, 100) + (cleaned.length > 100 ? "..." : ""),
    defanged_target: cleaned.slice(0, 100).replace(/\./g, "[.]") + (cleaned.length > 100 ? "..." : ""),
    risk_score: finalScore,
    risk_level: riskLevel,
    confidence_score: 90,
    executive_summary: `Social engineering analysis determined risk level ${riskLevel} (score: ${finalScore}/100) based on ${findings.length - 1} behavioral indicators.`,
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
      entropy: calculateShannonEntropy(cleaned.slice(0, 200)),
      detected_brands: detectedBrands,
      extracted_urls: extractedUrls,
      social_engineering_flags: socialFlags,
    },
    analyzed_at: analyzedAt,
  };
}
