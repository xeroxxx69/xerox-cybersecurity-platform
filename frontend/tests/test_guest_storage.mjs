import assert from "node:assert/strict";

// Setup mock window and localStorage for node/tsx test environment
const store = new Map();
global.window = {
  localStorage: {
    getItem: (key) => store.get(key) || null,
    setItem: (key, val) => store.set(key, String(val)),
    removeItem: (key) => store.delete(key),
    clear: () => store.clear(),
  },
};

const {
  saveGuestScan,
  getGuestReports,
  getGuestHistory,
  getGuestReport,
  getGuestStats,
  clearGuestHistory,
} = await import("../src/services/guestStorage.ts");

console.log("=== RUNNING FRONTEND GUEST STORAGE UNIT TESTS ===");

// 1. Initial empty state
console.log("Testing initial guest storage state...");
clearGuestHistory();
assert.deepEqual(getGuestReports(), [], "Initial guest reports should be empty");
assert.deepEqual(getGuestHistory(), [], "Initial guest history should be empty");
const initialStats = getGuestStats();
assert.equal(initialStats.total_scans, 0);
assert.equal(initialStats.threats_blocked, 0);
console.log("✓ Initial empty state verified");

// 2. Saving a scan report
console.log("Testing saveGuestScan and retrieval...");
const sampleReport1 = {
  scan_id: "scan-001",
  target_type: "URL",
  raw_target: "https://paypal-security-update.serveo.net/login",
  defanged_target: "hxxps[://]paypal-security-update[.]serveo[.]net/login",
  risk_score: 95,
  risk_level: "CRITICAL",
  confidence_score: 98,
  executive_summary: "Critical phishing threat mimicking PayPal.",
  layman_verdict: "Extremely dangerous. Do not open.",
  evidence_items: [],
  recommended_actions: [],
  technical_metadata: {
    domain: "serveo.net",
    subdomain: "paypal-security-update",
    registered_domain: "serveo.net",
    tld: "net",
    ip_addresses: ["127.0.0.1"],
    redirect_hops: [],
    entropy: 4.5,
    detected_brands: ["PayPal"],
    extracted_urls: [],
    social_engineering_flags: ["Urgent Account Suspension"],
  },
  analyzed_at: new Date().toISOString(),
};

saveGuestScan(sampleReport1);
assert.equal(getGuestReports().length, 1);
const history = getGuestHistory();
assert.equal(history.length, 1);
assert.equal(history[0].scan_id, "scan-001");
assert.equal(history[0].risk_level, "CRITICAL");
assert.equal(history[0].risk_score, 95);

const retrieved = getGuestReport("scan-001");
assert.notEqual(retrieved, null);
assert.equal(retrieved.scan_id, "scan-001");
assert.equal(retrieved.defanged_target, sampleReport1.defanged_target);
console.log("✓ Scan save and retrieval passed");

// 3. Saving second report and computing statistics
console.log("Testing stats aggregation across multiple scan types...");
const sampleReport2 = {
  scan_id: "scan-002",
  target_type: "FILE",
  raw_target: "roadmap.pdf",
  defanged_target: "roadmap.pdf",
  risk_score: 10,
  risk_level: "BENIGN",
  confidence_score: 90,
  executive_summary: "Clean document without suspicious macros or URLs.",
  layman_verdict: "Safe to open.",
  evidence_items: [],
  recommended_actions: [],
  technical_metadata: {
    domain: "",
    subdomain: "",
    registered_domain: "",
    tld: "",
    ip_addresses: [],
    redirect_hops: [],
    entropy: 3.2,
    detected_brands: [],
    extracted_urls: [],
    social_engineering_flags: [],
  },
  analyzed_at: new Date().toISOString(),
};

saveGuestScan(sampleReport2);
const stats = getGuestStats();
assert.equal(stats.total_scans, 2);
assert.equal(stats.threats_blocked, 1);
assert.equal(stats.benign_verified, 1);
assert.equal(stats.suspicious_flagged, 0);
assert.equal(stats.scans_by_type["URL"], 1);
assert.equal(stats.scans_by_type["FILE"], 1);
console.log("✓ Stats aggregation passed");

// 4. Deduplication
console.log("Testing deduplication when saving duplicate scan ID...");
saveGuestScan(sampleReport1);
assert.equal(getGuestReports().length, 2, "Duplicate scan_id must update rather than duplicate");
console.log("✓ Deduplication verified");

// 5. Purging local storage
console.log("Testing clearGuestHistory...");
clearGuestHistory();
assert.equal(getGuestReports().length, 0);
assert.equal(getGuestHistory().length, 0);
console.log("✓ Purge local storage verified");

console.log("=== ALL GUEST STORAGE UNIT TESTS PASSED SUCCESSFULLY ===");
