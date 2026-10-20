import assert from "node:assert/strict";
import {
  ApiError,
  sanitizeUrlForLog,
  extractCorrelationId,
} from "../src/services/apiError.ts";

console.log("=== RUNNING FRONTEND API ERROR HANDLING & DIAGNOSTIC TESTS ===");

// 1. URL Sanitization: Strips sensitive query parameters
console.log("Testing URL sanitization for diagnostic logging...");
const rawUrlWithSecret = "https://api.xerox.sec/v1/auth?token=supersecret123&password=hunter2&user=admin";
const sanitized = sanitizeUrlForLog(rawUrlWithSecret);
assert.ok(!sanitized.includes("supersecret123"), "Token must be redacted from diagnostic URLs");
assert.ok(!sanitized.includes("hunter2"), "Password must be redacted from diagnostic URLs");
assert.ok(sanitized.includes("[REDACTED]"), "Sensitive parameter should be replaced with [REDACTED]");
console.log("✓ URL sanitization passed");

// 2. Correlation ID Extraction from diverse headers
console.log("Testing correlation ID extraction...");
const mockPlatformHeaders = {
  "x-correlation-id": "corr-req-998877",
};
assert.equal(extractCorrelationId(mockPlatformHeaders), "corr-req-998877");

const mockStandardHeaders = {
  "x-request-id": "req-uuid-112233",
};
assert.equal(extractCorrelationId(mockStandardHeaders), "req-uuid-112233");

const mockCfHeaders = {
  "cf-ray": "887766554433-BOM",
};
assert.equal(extractCorrelationId(mockCfHeaders), "887766554433-BOM");

assert.equal(extractCorrelationId({}), undefined);
console.log("✓ Correlation ID extraction passed");

// 3. ApiError instantiation and classification
console.log("Testing ApiError structure and diagnostic formatting...");
const err404 = new ApiError("Application not found on hosting platform", "NOT_FOUND", {
  statusCode: 404,
  url: "https://api.xerox-defense.com/api/v1/health",
  correlationId: "sZsagdhoTLaj67gD2prcFg",
  technicalDetail: "Platform edge proxy returned 404 Application not found",
});

assert.equal(err404.name, "ApiError");
assert.equal(err404.kind, "NOT_FOUND");
assert.equal(err404.statusCode, 404);
assert.equal(err404.correlationId, "sZsagdhoTLaj67gD2prcFg");
assert.ok(err404.toDiagnosticString().includes("404"));
assert.ok(err404.toDiagnosticString().includes("sZsagdhoTLaj67gD2prcFg"));
console.log("✓ ApiError classification passed");

// 4. Distinction: 401 is NEVER reported as network failure
console.log("Testing 401 Unauthorized distinction...");
const err401 = new ApiError("Invalid operational security credentials", "UNAUTHORIZED", {
  statusCode: 401,
  url: "https://api.xerox.sec/v1/analyze/history",
});
assert.notEqual(err401.kind, "DNS_OR_NETWORK");
assert.notEqual(err401.kind, "CORS_OR_BLOCKED");
assert.equal(err401.kind, "UNAUTHORIZED");
assert.equal(err401.statusCode, 401);
console.log("✓ 401 Unauthorized distinction verified");

// 5. Distinction: CORS refusal is NEVER reported as server crash (500)
console.log("Testing CORS / blocked distinction...");
const errCors = new ApiError("Browser blocked cross-origin request", "CORS_OR_BLOCKED", {
  url: "https://api.xerox-defense.com/api/v1",
  technicalDetail: "Failed to fetch - Access-Control-Allow-Origin header absent",
});
assert.equal(errCors.kind, "CORS_OR_BLOCKED");
assert.notEqual(errCors.kind, "SERVER_ERROR");
assert.equal(errCors.statusCode, undefined);
console.log("✓ CORS refusal distinction verified");

// 6. Database degradation distinction (503)
console.log("Testing 503 Database degradation distinction...");
const err503 = new ApiError("Security enclave database degraded", "DATABASE_DEGRADED", {
  statusCode: 503,
  technicalDetail: "PostgreSQL connection pool exhausted",
});
assert.equal(err503.kind, "DATABASE_DEGRADED");
assert.equal(err503.statusCode, 503);
console.log("✓ Database degradation distinction verified");

console.log("\nALL API ERROR HANDLING & DIAGNOSTIC TESTS PASSED SUCCESSFULLY!");
