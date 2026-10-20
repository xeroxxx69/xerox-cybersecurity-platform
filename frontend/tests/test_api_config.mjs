import assert from "node:assert/strict";
import {
  validateApiUrl,
  normalizeApiUrl,
  DEFAULT_PRODUCTION_API,
} from "../src/services/apiConfig.ts";

console.log("=== RUNNING FRONTEND API CONFIG & VALIDATION REGRESSION TESTS ===");

// 1. Valid URLs in Production
console.log("Testing valid production URLs...");
const validProd1 = validateApiUrl("https://web-production-69de4.up.railway.app/api/v1", true);
assert.equal(validProd1.isValid, true, "Valid HTTPS URL should pass validation in production");

const validProd2 = validateApiUrl("https://xerox-api.onrender.com/api/v1", true);
assert.equal(validProd2.isValid, true, "Valid Render HTTPS URL should pass validation in production");

const validProd3 = validateApiUrl("https://my-backend-enclave.org/api/v1", true);
assert.equal(validProd3.isValid, true, "Valid custom enclave HTTPS URL should pass validation in production");
assert.equal(DEFAULT_PRODUCTION_API, "", "Default production API must be empty string for zero-server Edge Standalone Mode");
console.log("✓ Valid production URLs and standalone default passed");


// 2. Reject Localhost in Production
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

// 3. Localhost Allowed in Development Mode
console.log("Testing localhost permitted in development mode...");
const testDevLocalhost = validateApiUrl("http://localhost:8000/api/v1", false);
assert.equal(testDevLocalhost.isValid, true, "Localhost should be permitted in development mode");
console.log("✓ Development mode localhost check passed");

// 4. Reject Insecure Plain HTTP in Production
console.log("Testing plain HTTP rejection in production mode...");
const testInsecureHttp = validateApiUrl("http://remote-api.example.com/api/v1", true);
assert.equal(testInsecureHttp.isValid, false, "Insecure HTTP must be rejected for remote production hosts");
assert.match(testInsecureHttp.error, /HTTPS/i);
console.log("✓ Insecure HTTP rejection passed");

// 5. Malformed URLs and Non-String Inputs
console.log("Testing malformed URL handling...");
assert.equal(validateApiUrl("", true).isValid, false);
assert.equal(validateApiUrl("not-a-url", true).isValid, false);
assert.equal(validateApiUrl("ftp://api.example.com", true).isValid, false);
assert.match(validateApiUrl("ftp://api.example.com", true).error, /protocol/i);
console.log("✓ Malformed URL handling passed");

// 6. URL Normalization
console.log("Testing URL normalization...");
assert.equal(normalizeApiUrl("https://api.example.com/api/v1/"), "https://api.example.com/api/v1");
assert.equal(normalizeApiUrl("https://api.example.com///"), "https://api.example.com");
assert.equal(normalizeApiUrl("  https://api.example.com/api/v1  "), "https://api.example.com/api/v1");
console.log("✓ URL normalization passed");

console.log("\nALL API CONFIG REGRESSION TESTS PASSED SUCCESSFULLY!");
