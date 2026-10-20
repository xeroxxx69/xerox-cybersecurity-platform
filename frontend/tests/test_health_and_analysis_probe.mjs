import assert from "node:assert/strict";
import {
  checkBackendHealth,
  testBackendAnalysisEndpoint,
} from "../src/services/api.ts";
import { setCustomApiUrl } from "../src/services/apiConfig.ts";

console.log("=== RUNNING HEALTH CHECK & ANALYSIS PROBE AUTOMATED TESTS ===");

// Setup mock window & localStorage
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

// 1. Standalone Mode Health Check (No backend configured)
console.log("Testing health check when no backend is configured...");
setCustomApiUrl(null); // Ensure standalone mode

const standaloneHealth = await checkBackendHealth();
assert.equal(standaloneHealth.status, "not_configured", "Status must be 'not_configured', never 'healthy'");
assert.equal(standaloneHealth.isOnline, false, "isOnline must be false when no backend is configured");
assert.equal(standaloneHealth.baseUrl, "");
assert.ok(standaloneHealth.errorDetail && standaloneHealth.errorDetail.includes("Standalone"));
console.log("✓ Standalone mode correctly reports 'not_configured' and never simulates healthy");

// 2. Mocking Fetch for Configured Backend Scenarios
const originalFetch = globalThis.fetch;

try {
  // Scenario A: Healthy Backend (200 OK)
  console.log("Testing healthy backend response...");
  setCustomApiUrl("https://defense-api.mycompany.org/api/v1");

  globalThis.fetch = async (url) => {
    if (String(url).endsWith("/health")) {
      return new Response(
        JSON.stringify({
          status: "healthy",
          service: "XEROX API Core",
          version: "1.2.0",
          database: "connected",
          cache: "connected",
        }),
        {
          status: 200,
          headers: {
            "Content-Type": "application/json",
            "x-correlation-id": "test-corr-123",
          },
        }
      );
    }
    throw new Error(`Unexpected URL: ${url}`);
  };

  const healthyRes = await checkBackendHealth();
  assert.equal(healthyRes.status, "healthy");
  assert.equal(healthyRes.isOnline, true);
  assert.equal(healthyRes.service, "XEROX API Core");
  assert.equal(healthyRes.version, "1.2.0");
  assert.equal(healthyRes.database, "connected");
  assert.equal(healthyRes.correlationId, "test-corr-123");
  console.log("✓ Reachable healthy backend correctly detected");

  // Scenario B: Degraded Backend (200 OK with degraded database)
  console.log("Testing degraded backend response...");
  globalThis.fetch = async (url) => {
    if (String(url).endsWith("/health")) {
      return new Response(
        JSON.stringify({
          status: "degraded",
          service: "XEROX API Core",
          version: "1.2.0",
          database: "disconnected",
          cache: "connected",
        }),
        {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }
      );
    }
    throw new Error(`Unexpected URL: ${url}`);
  };

  const degradedRes = await checkBackendHealth();
  assert.equal(degradedRes.status, "degraded");
  assert.equal(degradedRes.isOnline, true);
  assert.equal(degradedRes.database, "disconnected");
  console.log("✓ Degraded database state correctly identified");

  // Scenario C: Unavailable Backend (Network error / Connection refused)
  console.log("Testing unavailable backend handling...");
  globalThis.fetch = async () => {
    throw new TypeError("Failed to fetch");
  };

  const unavailableRes = await checkBackendHealth();
  assert.equal(unavailableRes.status, "unavailable");
  assert.equal(unavailableRes.isOnline, false);
  assert.ok(unavailableRes.errorDetail && unavailableRes.errorDetail.length > 0);
  console.log("✓ Network connection failure correctly classified as 'unavailable'");

  // Scenario D: Misconfigured Endpoint (404 Not Found)
  console.log("Testing misconfigured route / 404 response...");
  globalThis.fetch = async () => {
    return new Response(
      JSON.stringify({ detail: "Not Found" }),
      {
        status: 404,
        headers: { "Content-Type": "application/json" },
      }
    );
  };

  const misconfiguredRes = await checkBackendHealth();
  assert.equal(misconfiguredRes.status, "misconfigured");
  assert.equal(misconfiguredRes.isOnline, false);
  console.log("✓ 404 Route failure correctly classified as 'misconfigured'");

  // Scenario E: Critical Case — Health endpoint succeeds, but Analysis endpoint fails!
  console.log("Testing scenario: Health endpoint succeeds but Analysis endpoint fails...");
  globalThis.fetch = async (url) => {
    if (String(url).endsWith("/health")) {
      return new Response(
        JSON.stringify({
          status: "healthy",
          service: "XEROX API Core",
          version: "1.2.0",
        }),
        {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }
      );
    }
    if (String(url).endsWith("/analyze/url")) {
      return new Response(
        JSON.stringify({ detail: "Analysis engine worker failed" }),
        {
          status: 500,
          headers: { "Content-Type": "application/json" },
        }
      );
    }
    throw new Error(`Unexpected URL: ${url}`);
  };

  // 1. Health check reports healthy
  const healthCheck = await checkBackendHealth();
  assert.equal(healthCheck.status, "healthy", "Health endpoint returned 200 OK");

  // 2. Separate Analysis probe detects the failure!
  const analysisProbe = await testBackendAnalysisEndpoint("https://example.com");
  assert.equal(analysisProbe.success, false, "Analysis probe must detect worker failure");
  assert.equal(analysisProbe.status, "failed");
  assert.ok(analysisProbe.errorDetail && analysisProbe.errorDetail.includes("500"));
  console.log("✓ Successfully distinguished working health endpoint from failing analysis endpoint!");

} finally {
  globalThis.fetch = originalFetch;
  setCustomApiUrl(null);
}

console.log("\nALL HEALTH CHECK & ANALYSIS PROBE TESTS PASSED SUCCESSFULLY!");
