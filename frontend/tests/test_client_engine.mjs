import assert from "node:assert/strict";
import {
  analyzeUrlClientSide,
  analyzeMessageClientSide,
  defangUrl,
  calculateShannonEntropy,
} from "../src/services/clientEngine/index.ts";

console.log("=== RUNNING FRONTEND CLIENT-SIDE THREAT ENGINE TESTS ===");

// 1. Defanging Test
console.log("Testing URL defanging...");
assert.equal(defangUrl("https://malicious.example.com/path"), "hxxps[://]malicious[.]example[.]com/path");
assert.equal(defangUrl("http://phishing.site/login"), "hxxp[://]phishing[.]site/login");
console.log("✓ Defanging logic verified");

// 2. Shannon Entropy Test
console.log("Testing Shannon entropy calculation...");
const lowEntropy = calculateShannonEntropy("google");
const highEntropy = calculateShannonEntropy("qkx7z9p0w1m4v8y2r6");
assert.ok(highEntropy > lowEntropy, "Randomized DGA string should have higher entropy than simple dictionary word");
console.log(`✓ Entropy calculation verified (normal: ${lowEntropy}, DGA: ${highEntropy})`);

// 3. Benign URL Static Analysis
console.log("Testing benign URL analysis...");
const benignReport = analyzeUrlClientSide("https://example.com/about-us");
assert.equal(benignReport.target_type, "URL");
assert.equal(benignReport.risk_level, "BENIGN");
assert.ok(benignReport.risk_score < 30, "Benign URL score should be low");
assert.ok(benignReport.scan_id, "Scan ID must be generated");
assert.ok(benignReport.evidence_items.length >= 1, "Should include sandbox attribution finding");
console.log("✓ Benign URL analyzed correctly");

// 4. Phishing & Brand Impersonation URL Analysis
console.log("Testing brand impersonation & high-risk TLD analysis...");
const phishingReport = analyzeUrlClientSide("http://paypal-security-verification.xyz/login/verify-account");
assert.equal(phishingReport.target_type, "URL");
assert.ok(
  phishingReport.risk_level === "CRITICAL" || phishingReport.risk_level === "HIGH RISK",
  `Expected critical/high risk but got ${phishingReport.risk_level}`
);
assert.ok(phishingReport.risk_score >= 60, "Phishing score should be >= 60");
assert.ok(
  phishingReport.technical_metadata.detected_brands.includes("paypal"),
  "Should detect PayPal brand impersonation"
);
assert.equal(phishingReport.technical_metadata.tld, "xyz", "Should extract TLD");
console.log(`✓ Phishing URL classified as ${phishingReport.risk_level} (Score: ${phishingReport.risk_score})`);

// 5. IP Address & Private Network Target
console.log("Testing private IP / SSRF target analysis...");
const privateIpReport = analyzeUrlClientSide("http://192.168.1.100/admin");
assert.ok(
  privateIpReport.evidence_items.some((e) => e.title.includes("Private Network") || e.title.includes("IP Address")),
  "Should flag internal/private network IP"
);
console.log("✓ Private IP target identified");

// 6. Dangerous Executable Target
console.log("Testing dangerous executable download link...");
const exeReport = analyzeUrlClientSide("https://cdn.updates-server.net/payload.exe");
assert.ok(
  exeReport.evidence_items.some((e) => e.title.includes("Dangerous Direct Download")),
  "Should flag direct executable download"
);
console.log("✓ Dangerous executable link flagged");

// 7. Message Social Engineering & Urgency Analysis
console.log("Testing phishing message analysis...");
const phishingMessage = "URGENT: Your Chase Bank account has been suspended due to unusual activity. Click here to verify your password immediately: https://chase-secure-reactivate.xyz";
const msgReport = analyzeMessageClientSide(phishingMessage);
assert.equal(msgReport.target_type, "MESSAGE");
assert.ok(
  msgReport.risk_level === "CRITICAL" || msgReport.risk_level === "HIGH RISK",
  `Expected critical or high risk message but got ${msgReport.risk_level}`
);
assert.ok(
  msgReport.evidence_items.some((e) => e.title.includes("Psychological Coercion") || e.title.includes("Credential Harvesting")),
  "Should detect social engineering and credential harvesting indicators"
);
console.log(`✓ Phishing message classified as ${msgReport.risk_level} (Score: ${msgReport.risk_score})`);

// 8. Secret & Credential Leak Detection in Content
console.log("Testing secret pattern leak detection...");
const secretMessage = "Deploying app with AWS credentials: AKIAIOSFODNN7EXAMPLE and secret token";
const secretReport = analyzeMessageClientSide(secretMessage);
assert.ok(
  secretReport.evidence_items.some((e) => e.title.includes("AWS Access Key")),
  "Should detect exposed AWS Access Key pattern"
);
console.log("✓ Secret credential pattern detected and flagged");

// 9. Malformed Input Handling
console.log("Testing malformed URL handling...");
const malformedReport = analyzeUrlClientSide("http://::broken-url::");
assert.ok(malformedReport.scan_id, "Malformed input must return valid report without throwing");
assert.equal(malformedReport.risk_level, "HIGH RISK");
console.log("✓ Malformed inputs handled safely");

console.log("\n=======================================================");
console.log("🎉 ALL CLIENT-SIDE THREAT ENGINE TESTS PASSED WITH 100% SUCCESS!");
console.log("=======================================================");
