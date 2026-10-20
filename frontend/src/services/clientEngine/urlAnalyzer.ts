import type {
  ThreatReport,
  EvidenceItem,
  RecommendedAction,
  RiskLevel,
} from "@/types";

const HIGH_RISK_TLDS = new Set([
  "xyz", "top", "work", "live", "click", "link", "loan", "buzz", "surf",
  "monster", "fit", "rest", "cam", "quest", "cfd", "sbs", "icu", "gq",
  "ml", "tk", "ga", "cf", "pw", "cc", "ws"
]);

const SUSPICIOUS_SUBDOMAINS_OR_SERVICES = [
  "workers.dev", "pages.dev", "vercel.app", "glitch.me", "netlify.app",
  "web.app", "firebaseapp.com", "duckdns.org", "ngrok-free.app", "ngrok.io",
];

const TARGETED_BRANDS: Record<string, string[]> = {
  apple: ["apple.com", "icloud.com"],
  paypal: ["paypal.com"],
  google: ["google.com", "accounts.google.com"],
  microsoft: ["microsoft.com", "live.com", "office.com", "office365.com", "outlook.com"],
  netflix: ["netflix.com"],
  amazon: ["amazon.com", "primevideo.com"],
  chase: ["chase.com"],
  wellsfargo: ["wellsfargo.com"],
  bankofamerica: ["bankofamerica.com"],
  binance: ["binance.com"],
  coinbase: ["coinbase.com"],
  facebook: ["facebook.com", "meta.com"],
  instagram: ["instagram.com"],
  whatsapp: ["whatsapp.com"],
  usps: ["usps.com"],
  dhl: ["dhl.com"],
  fedex: ["fedex.com"],
  ups: ["ups.com"],
  steam: ["steampowered.com", "steamcommunity.com"],
};

const PHISHING_LEXICAL_KEYWORDS = [
  "login", "verify", "verification", "secure", "account", "update",
  "password", "wallet", "banking", "payment", "authentication", "recovery",
  "signin", "confirm", "support", "security", "billing", "invoice",
  "authenticate", "credential", "suspend", "unlock", "alert", "validate"
];

const OPEN_REDIRECT_PARAMS = new Set([
  "url", "redirect", "redirect_url", "redirect_uri", "next", "dest",
  "destination", "return", "return_to", "r", "goto", "out"
]);

const DANGEROUS_EXTENSIONS = new Set([
  ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".iso", ".img",
  ".zip", ".rar", ".7z", ".tar", ".gz", ".apk", ".dmg", ".pkg", ".docm", ".xlsm"
]);

export function calculateShannonEntropy(text: string): number {
  if (!text) return 0;
  const lower = text.toLowerCase();
  const freq: Record<string, number> = {};
  for (let i = 0; i < lower.length; i++) {
    const c = lower[i];
    freq[c] = (freq[c] || 0) + 1;
  }
  let entropy = 0;
  for (const count of Object.values(freq)) {
    const p = count / lower.length;
    entropy -= p * Math.log2(p);
  }
  return Math.round(entropy * 100) / 100;
}

export function defangUrl(url: string): string {
  return url
    .replace(/^https?:\/\//i, (match) => match.toLowerCase().startsWith("https") ? "hxxps[://]" : "hxxp[://]")
    .replace(/\./g, "[.]");
}

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

function isIpAddress(hostname: string): boolean {
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (ipv4Regex.test(hostname)) {
    const parts = hostname.split(".").map(Number);
    return parts.every((p) => p >= 0 && p <= 255);
  }
  return false;
}

function isPrivateIp(hostname: string): boolean {
  if (!isIpAddress(hostname)) {
    return hostname === "localhost" || hostname.endsWith(".local") || hostname.endsWith(".internal");
  }
  const parts = hostname.split(".").map(Number);
  if (parts[0] === 127 || parts[0] === 10 || parts[0] === 0) return true;
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
  if (parts[0] === 192 && parts[1] === 168) return true;
  if (parts[0] === 169 && parts[1] === 254) return true;
  return false;
}

export function analyzeUrlClientSide(rawUrl: string): ThreatReport {
  const cleaned = rawUrl.trim();
  const defanged = defangUrl(cleaned);
  const scanId = generateUuid();
  const analyzedAt = new Date().toISOString();

  let parsed: URL;
  try {
    const candidate = cleaned.startsWith("http://") || cleaned.startsWith("https://")
      ? cleaned
      : `http://${cleaned}`;
    parsed = new URL(candidate);
  } catch {
    return {
      scan_id: scanId,
      target_type: "URL",
      raw_target: cleaned,
      defanged_target: defanged,
      risk_score: 85,
      risk_level: "HIGH RISK",
      confidence_score: 95,
      executive_summary: "Target URL failed RFC-3986 lexical syntax validation. Malformed or obfuscated URI structure detected.",
      layman_verdict: "This URL is broken, malformed, or intentionally deceptive.",
      evidence_items: [
        {
          category: "CONTENT",
          severity: "HIGH",
          title: "Malformed URL Structure",
          description: "The supplied target does not conform to standard URI structural specifications.",
          technical_proof: `Failed parser validation: ${cleaned}`,
          why_this_matters: "Deceptive attacks often use malformed or illegal characters to bypass security filters.",
        },
      ],
      recommended_actions: [
        {
          priority: "IMMEDIATE",
          action: "Do not open or route traffic to this destination.",
          rationale: "Malformed URI structures frequently mask exploit payloads.",
          action_type: "DO_NOT_CLICK",
        },
      ],
      technical_metadata: {
        domain: cleaned,
        subdomain: "",
        registered_domain: cleaned,
        tld: "",
        ip_addresses: [],
        redirect_hops: [],
        entropy: calculateShannonEntropy(cleaned),
        detected_brands: [],
        extracted_urls: [],
        social_engineering_flags: ["malformed_syntax"],
      },
      analyzed_at: analyzedAt,
    };
  }

  const hostname = parsed.hostname.toLowerCase();
  const pathname = parsed.pathname.toLowerCase();
  const findings: EvidenceItem[] = [];
  const detectedBrands: string[] = [];
  const socialFlags: string[] = [];
  let score = 0;

  // 1. IP as Hostname
  if (isIpAddress(hostname)) {
    if (isPrivateIp(hostname)) {
      score += 55;
      findings.push({
        category: "INFRASTRUCTURE",
        severity: "HIGH",
        title: "Internal / Private Network Destination",
        description: "The URL resolves to a loopback, RFC-1918 private, or link-local address.",
        technical_proof: `Destination host: ${hostname}`,
        why_this_matters: "Targeting internal addresses from external links is a hallmark of Server-Side Request Forgery (SSRF) and local reconnaissance.",
      });
      socialFlags.push("private_ip_target");
    } else {
      score += 45;
      findings.push({
        category: "INFRASTRUCTURE",
        severity: "HIGH",
        title: "Raw IP Address Hostname",
        description: "The URL targets a direct numeric IP address rather than a registered domain name.",
        technical_proof: `Host: ${hostname}`,
        why_this_matters: "Legitimate institutional services use branded domain names. Attackers use raw IPs to bypass domain reputation blocklists.",
      });
      socialFlags.push("raw_ip_host");
    }
  }

  // 2. Punycode / IDN Homograph
  if (hostname.includes("xn--")) {
    score += 40;
    findings.push({
      category: "IDENTITY",
      severity: "HIGH",
      title: "Punycode / Internationalized Domain Detected",
      description: "Hostname contains 'xn--' prefix representing ASCII-compatible encoding of non-ASCII characters.",
      technical_proof: `Host: ${hostname}`,
      why_this_matters: "Homograph attacks replace Latin letters with identical-looking Cyrillic or Greek glyphs to trick users into trusting a spoofed domain.",
    });
    socialFlags.push("punycode_homograph");
  }

  // 3. TLD Analysis
  const hostParts = hostname.split(".");
  const tld = hostParts.length > 1 ? hostParts[hostParts.length - 1] : "";
  if (HIGH_RISK_TLDS.has(tld)) {
    score += 25;
    findings.push({
      category: "REPUTATION",
      severity: "MEDIUM",
      title: `High-Risk Top-Level Domain (.${tld})`,
      description: `Domain uses a TLD with statistically elevated phishing and disposable registration volume.`,
      technical_proof: `TLD: .${tld}`,
      why_this_matters: "Discount and free TLDs are heavily favored by threat actors for short-lived phishing campaigns.",
    });
    socialFlags.push("high_risk_tld");
  }

  // 4. Subdomain Abuse
  for (const svc of SUSPICIOUS_SUBDOMAINS_OR_SERVICES) {
    if (hostname.endsWith(svc)) {
      score += 20;
      findings.push({
        category: "INFRASTRUCTURE",
        severity: "MEDIUM",
        title: "Free Cloud/Subdomain Platform Hosting",
        description: `URL is hosted on a free cloud deployment or tunneling service (${svc}).`,
        technical_proof: `Subdomain host on: ${svc}`,
        why_this_matters: "Phishing kits frequently abuse free developer platforms to inherit trusted domain reputations and bypass basic filters.",
      });
      socialFlags.push("free_hosting_abuse");
      break;
    }
  }

  // 5. Brand Impersonation
  for (const [brand, legitDomains] of Object.entries(TARGETED_BRANDS)) {
    const isLegit = legitDomains.some((d) => hostname === d || hostname.endsWith(`.${d}`));
    if (!isLegit) {
      if (hostname.includes(brand) || pathname.includes(brand)) {
        detectedBrands.push(brand);
        score += 50;
        findings.push({
          category: "IDENTITY",
          severity: "CRITICAL",
          title: `Brand Impersonation Detected (${brand.toUpperCase()})`,
          description: `The URL references high-profile brand '${brand}' but is NOT hosted on official infrastructure.`,
          technical_proof: `Reference '${brand}' on unverified host '${hostname}' (official: ${legitDomains.join(", ")})`,
          why_this_matters: "Impersonating recognizable institutions is the primary tactic used to harvest banking and account credentials.",
        });
        socialFlags.push(`brand_spoof_${brand}`);
      }
    }
  }

  // 6. Phishing Lexical Keywords
  const matchedKeywords: string[] = [];
  for (const kw of PHISHING_LEXICAL_KEYWORDS) {
    if (pathname.includes(kw) || hostname.includes(kw) || parsed.search.includes(kw)) {
      matchedKeywords.push(kw);
    }
  }
  if (matchedKeywords.length >= 2) {
    score += Math.min(30, matchedKeywords.length * 10);
    findings.push({
      category: "CONTENT",
      severity: "MEDIUM",
      title: "Credential Harvesting Keywords in URI",
      description: `Path or query contains multiple sensitive authentication terms: ${matchedKeywords.slice(0, 5).join(", ")}.`,
      technical_proof: `Matched tokens: ${matchedKeywords.join(", ")}`,
      why_this_matters: "Legitimate websites rarely string together multiple urgency/authentication keywords in unauthenticated deep links.",
    });
    socialFlags.push("phishing_keywords");
  }

  // 7. Shannon Entropy (DGA Detection)
  const domainEntropy = calculateShannonEntropy(hostname);
  if (domainEntropy > 3.8 && hostname.length > 14) {
    score += 25;
    findings.push({
      category: "CRYPTOGRAPHY",
      severity: "MEDIUM",
      title: "High Hostname Entropy (Algorithmic DGA Pattern)",
      description: `Shannon entropy score of ${domainEntropy} indicates an unusually high degree of character randomness.`,
      technical_proof: `Entropy: ${domainEntropy} (threshold: 3.80, length: ${hostname.length})`,
      why_this_matters: "Domain Generation Algorithms (DGA) generate pseudo-random domain names to evade static reputation blocklists.",
    });
    socialFlags.push("high_entropy_dga");
  }

  // 8. Embedded Credentials in URL
  if (parsed.username || parsed.password) {
    score += 40;
    findings.push({
      category: "CONTENT",
      severity: "HIGH",
      title: "Embedded Credentials in URL",
      description: "URL contains basic-auth username or password structure before the hostname.",
      technical_proof: `Embedded user: ${parsed.username}`,
      why_this_matters: "Attackers embed credentials in URLs to mislead users about the true destination domain (e.g. http://paypal.com@attacker.com).",
    });
    socialFlags.push("embedded_credentials");
  }

  // 9. Dangerous File Extensions
  for (const ext of DANGEROUS_EXTENSIONS) {
    if (pathname.endsWith(ext) || pathname.includes(`${ext}?`)) {
      score += 45;
      findings.push({
        category: "CONTENT",
        severity: "HIGH",
        title: `Dangerous Direct Download Target (${ext})`,
        description: `URL path targets an executable, script, or container archive file directly.`,
        technical_proof: `Target extension: ${ext}`,
        why_this_matters: "Direct links to executables or macro-enabled documents frequently deliver initial access trojans and malware droppers.",
      });
      socialFlags.push("executable_download");
      break;
    }
  }

  // 10. Open Redirects
  parsed.searchParams.forEach((val, key) => {
    if (OPEN_REDIRECT_PARAMS.has(key.toLowerCase()) && (val.startsWith("http://") || val.startsWith("https://") || val.startsWith("//"))) {
      score += 30;
      findings.push({
        category: "INFRASTRUCTURE",
        severity: "MEDIUM",
        title: "Potential Open Redirect Parameter",
        description: `Query parameter '${key}' contains an external URL destination.`,
        technical_proof: `${key}=${val}`,
        why_this_matters: "Open redirects allow attackers to leverage trusted domains to bounce victims to malicious landing pages.",
      });
      socialFlags.push("open_redirect");
    }
  });

  // 11. Transparent Browser Sandbox Observation
  findings.push({
    category: "INFRASTRUCTURE",
    severity: "INFO",
    title: "Client-Side Edge Sandbox Execution",
    description: "Deterministic static lexical, structural, and brand verification completed in local browser sandbox.",
    technical_proof: `W3C CORS Security Isolation active; raw cross-origin HTTP response headers intentionally uninspected without server proxy.`,
    why_this_matters: "Ensures instantaneous, private analysis with zero data egress or dependency on external servers.",
  });

  const finalScore = Math.min(100, Math.max(0, score));

  let riskLevel: RiskLevel = "BENIGN";
  if (finalScore >= 80) riskLevel = "CRITICAL";
  else if (finalScore >= 60) riskLevel = "HIGH RISK";
  else if (finalScore >= 35) riskLevel = "SUSPICIOUS";
  else if (finalScore >= 15) riskLevel = "LOW RISK";

  let verdict = "This destination exhibits standard structural patterns and does not trigger suspicious indicators.";
  let summary = `Client-side static inspection determined risk level ${riskLevel} (score: ${finalScore}/100) based on ${findings.length - 1} structural observations.`;

  if (riskLevel === "CRITICAL" || riskLevel === "HIGH RISK") {
    verdict = "DANGER: This link shows critical signs of phishing, brand deception, or malicious intent. Do not visit.";
    summary = `High-confidence malicious indicators identified: ${detectedBrands.length > 0 ? `Brand spoofing (${detectedBrands.join(', ')})` : 'Deceptive URI patterns'}. Total risk score: ${finalScore}/100.`;
  } else if (riskLevel === "SUSPICIOUS") {
    verdict = "CAUTION: This destination displays suspicious attributes (e.g. high-risk TLD or credential keywords). Proceed with caution.";
  }

  const recommendedActions: RecommendedAction[] = [];
  if (finalScore >= 60) {
    recommendedActions.push({
      priority: "IMMEDIATE",
      action: "Do not visit this URL or submit credentials.",
      rationale: "Deceptive brand impersonation or malicious executable target detected.",
      action_type: "DO_NOT_CLICK",
    });
    recommendedActions.push({
      priority: "REPORTING",
      action: "Report this link to your security team or anti-phishing provider.",
      rationale: "Reporting helps block the infrastructure across global threat networks.",
      action_type: "REPORT_PHISHING",
    });
  } else if (finalScore >= 35) {
    recommendedActions.push({
      priority: "PREVENTATIVE",
      action: "Inspect the domain carefully before entering sensitive information.",
      rationale: "Suspicious structural attributes observed.",
      action_type: "VERIFY_SENDER",
    });
  } else {
    recommendedActions.push({
      priority: "PREVENTATIVE",
      action: "Destination shows no obvious static threat indicators.",
      rationale: "Static lexical and structural heuristics passed cleanly.",
      action_type: "SAFE_TO_PROCEED",
    });
  }

  const domain = hostname;
  const subParts = hostParts.length > 2 ? hostParts.slice(0, hostParts.length - 2).join(".") : "";
  const regDomain = hostParts.length > 1 ? hostParts.slice(-2).join(".") : hostname;

  return {
    scan_id: scanId,
    target_type: "URL",
    raw_target: cleaned,
    defanged_target: defanged,
    risk_score: finalScore,
    risk_level: riskLevel,
    confidence_score: 90,
    executive_summary: summary,
    layman_verdict: verdict,
    evidence_items: findings,
    recommended_actions: recommendedActions,
    technical_metadata: {
      domain,
      subdomain: subParts,
      registered_domain: regDomain,
      tld,
      ip_addresses: isIpAddress(hostname) ? [hostname] : [],
      redirect_hops: [],
      entropy: domainEntropy,
      detected_brands: detectedBrands,
      extracted_urls: [cleaned],
      social_engineering_flags: socialFlags,
    },
    analyzed_at: analyzedAt,
  };
}
