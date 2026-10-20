import assert from "node:assert/strict";
import {
  validateApiUrl,
  normalizeApiUrl,
  setCustomApiUrl,
  getApiBaseUrl,
  isBackendConfigured,
  getApiDiagnostics,
  DEFAULT_PRODUCTION_API,
} from "../src/services/apiConfig.ts";

console.log("=== RUNNING FRONTEND API CONFIG & VALIDATION REGRESSION TESTS ===");

// 1. Missing & Empty API URLs
console.log("Testing missing and empty API URL handling...");
const emptyResult1 = validateApiUrl("", true);
assert.equal(emptyResult1.isValid, false, "Empty URL must be marked invalid");
assert.equal(emptyResult1.isEmpty, true, "Empty URL must set isEmpty flag");
assert.match(emptyResult1.error, /cannot be empty/i);

const emptyResult2 = validateApiUrl("   ", true);
assert.equal(emptyResult2.isValid, false, "Whitespace-only URL must be marked invalid");
assert.equal(emptyResult2.isEmpty, true);

// 2. Placeholder Rejection
console.log("Testing placeholder URL rejection...");
const placeholderTests = [
  "https://your-backend.up.railway.app/api/v1",
  "https://your-backend.onrender.com/api/v1",
  "https://api.example.com/api/v1",
  "https://yourdomain.com/api/v1",
  "https://web-production-69de4.up.railway.app/api/v1",
  "https://custom-app.up.railway.app/api/v1",
  "https://<your-backend>/api/v1",
];

for (const placeholderUrl of placeholderTests) {
  const result = validateApiUrl(placeholderUrl, true);
  assert.equal(result.isValid, false, `Placeholder "${placeholderUrl}" must be rejected`);
  assert.equal(result.isPlaceholder, true, `Placeholder "${placeholderUrl}" must set isPlaceholder flag`);
  assert.ok(result.error && result.error.length > 0);
}
console.log("✓ Placeholder rejection passed (7/7 placeholder patterns rejected)");

// 3. Valid Configurations
console.log("Testing valid production URLs...");
const validProd1 = validateApiUrl("https://api.xerox-defense.com/api/v1", true);
assert.equal(validProd1.isValid, true, "Valid HTTPS URL should pass validation in production");

const validProd2 = validateApiUrl("https://defense-enclave.org/api/v1", true);
assert.equal(validProd2.isValid, true, "Valid custom enclave HTTPS URL should pass validation in production");

assert.equal(DEFAULT_PRODUCTION_API, "", "Default production API must be empty string for zero-server Edge Standalone Mode");
console.log("✓ Valid production URLs and standalone default passed");

// 4. Reject Localhost in Production
console.log("Testing localhost rejection in production mode...");
const testLocalhost1 = validateApiUrl("http://localhost:8000/api/v1", true);
assert.equal(testLocalhost1.isValid, false, "Localhost must be rejected in production");
assert.equal(testLocalhost1.isLocalhostInProd, true);
assert.match(testLocalhost1.error, /localhost/i);

const testLocalhost2 = validateApiUrl("http://127.0.0.1:8000", true);
assert.equal(testLocalhost2.isValid, false, "127.0.0.1 must be rejected in production");
assert.equal(testLocalhost2.isLocalhostInProd, true);

const testLocalhost3 = validateApiUrl("https://localhost:8443/api/v1", true);
assert.equal(testLocalhost3.isValid, false, "HTTPS localhost must still be rejected in production");
assert.equal(testLocalhost3.isLocalhostInProd, true);
console.log("✓ Localhost rejection in production passed");

// 5. Localhost Allowed in Development Mode
console.log("Testing localhost permitted in development mode...");
const testDevLocalhost = validateApiUrl("http://localhost:8000/api/v1", false);
assert.equal(testDevLocalhost.isValid, true, "Localhost should be permitted in development mode");
console.log("✓ Development mode localhost check passed");

// 6. Reject Insecure Plain HTTP in Production
console.log("Testing plain HTTP rejection in production mode...");
const testInsecureHttp = validateApiUrl("http://remote-api.security-corp.net/api/v1", true);
assert.equal(testInsecureHttp.isValid, false, "Insecure HTTP must be rejected for remote production hosts");
assert.match(testInsecureHttp.error, /HTTPS/i);
console.log("✓ Insecure HTTP rejection passed");

// 7. Malformed URLs and Non-HTTP Protocols
console.log("Testing malformed URL handling...");
assert.equal(validateApiUrl("not-a-url", true).isValid, false);
assert.equal(validateApiUrl("ftp://api.security-enclave.org", true).isValid, false);
assert.match(validateApiUrl("ftp://api.security-enclave.org", true).error, /protocol/i);
console.log("✓ Malformed URL handling passed");

// 8. URL Normalization and Automatic Path Handling
console.log("Testing URL normalization...");
assert.equal(normalizeApiUrl(""), "");
assert.equal(normalizeApiUrl("   "), "");
assert.equal(normalizeApiUrl("https://api.security.org/api/v1/"), "https://api.security.org/api/v1");
assert.equal(normalizeApiUrl("https://api.security.org/api/v1"), "https://api.security.org/api/v1");
assert.equal(normalizeApiUrl("https://api.security.org/"), "https://api.security.org/api/v1");
assert.equal(normalizeApiUrl("https://api.security.org"), "https://api.security.org/api/v1");
assert.equal(normalizeApiUrl("  https://api.security.org/api/v1  "), "https://api.security.org/api/v1");
console.log("✓ URL normalization passed");

// 9. Saved Settings & Reset Behavior
console.log("Testing custom API settings persistence and reset...");
// Mock localStorage in Node
const mockStorage = new Map();
globalThis.localStorage = {
  getItem: (k) => mockStorage.get(k) || null,
  setItem: (k, v) => mockStorage.set(k, String(v)),
  removeItem: (k) => mockStorage.delete(k),
  clear: () => mockStorage.clear(),
};
globalThis.window = {
  location: { hostname: "xeroxxx69.github.io" },
};

// Setting a placeholder should be rejected and NOT saved
const savePlaceholderResult = setCustomApiUrl("https://your-backend.up.railway.app/api/v1");
assert.equal(savePlaceholderResult.isValid, false, "Saving placeholder must be rejected");
assert.equal(mockStorage.has("xerox_custom_api_url"), false, "Placeholder must not be written to storage");

// Setting a valid HTTPS URL
const saveValidResult = setCustomApiUrl("https://defense.mycompany.org");
assert.equal(saveValidResult.isValid, true, "Saving valid custom URL should succeed");
assert.equal(getApiBaseUrl(), "https://defense.mycompany.org/api/v1", "Base URL should normalize and include /api/v1");
assert.equal(isBackendConfigured(), true, "Backend should be marked as configured");

const diagOverride = getApiDiagnostics();
assert.equal(diagOverride.source, "runtime_override");
assert.equal(diagOverride.isConfigured, true);
assert.equal(diagOverride.isStandalone, false);

// Resetting configuration (passing null or empty string)
const resetResult = setCustomApiUrl(null);
assert.equal(resetResult.isValid, true);
assert.equal(getApiBaseUrl(), "", "Resetting should revert baseUrl to empty (Standalone Edge Mode)");
assert.equal(isBackendConfigured(), false, "Backend should not be marked as configured in standalone mode");

const diagStandalone = getApiDiagnostics();
assert.equal(diagStandalone.source, "standalone_default");
assert.equal(diagStandalone.isConfigured, false);
assert.equal(diagStandalone.isStandalone, true);
assert.equal(diagStandalone.isValid, true, "Standalone mode is always valid");
assert.equal(diagStandalone.validationError, undefined, "Standalone mode must have NO validation error");
console.log("✓ Settings persistence and reset behavior verified");

console.log("\nALL API CONFIG REGRESSION TESTS PASSED SUCCESSFULLY!");
