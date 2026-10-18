import assert from "node:assert/strict";

const BASE_URL = "http://127.0.0.1:8000";

async function run() {
  console.log("=== RUNNING FULL LIVE END-TO-END AUTH INTEGRATION TEST ===");

  // 1. Health check
  console.log("\n1. Verifying /health and /api/v1/health...");
  const h1 = await fetch(`${BASE_URL}/health`);
  assert.equal(h1.status, 200, "/health must return 200");
  const h1Data = await h1.json();
  assert.equal(h1Data.status, "healthy");
  assert.equal(h1Data.database, "connected");

  const h2 = await fetch(`${BASE_URL}/api/v1/health`);
  assert.equal(h2.status, 200, "/api/v1/health must return 200");
  console.log("✓ Health checks passed. Backend is healthy and database is connected.");

  // 2. CORS Preflight check from production origin
  console.log("\n2. Verifying CORS Preflight from https://xeroxxx69.github.io...");
  const corsRes = await fetch(`${BASE_URL}/api/v1/auth/login`, {
    method: "OPTIONS",
    headers: {
      Origin: "https://xeroxxx69.github.io",
      "Access-Control-Request-Method": "POST",
      "Access-Control-Request-Headers": "Content-Type",
    },
  });
  assert.equal(corsRes.status, 200, "CORS OPTIONS preflight must return 200");
  assert.equal(
    corsRes.headers.get("access-control-allow-origin"),
    "https://xeroxxx69.github.io",
    "CORS header must allow https://xeroxxx69.github.io"
  );
  assert.equal(
    corsRes.headers.get("access-control-allow-credentials"),
    "true",
    "Credentials must be allowed for cross-origin authentication"
  );
  console.log("✓ CORS preflight for production origin passed.");

  // 3. User Registration
  const testEmail = `analyst_test_${Date.now()}@xerox.sec`;
  const testPassword = "StrongPassword2026!";
  console.log(`\n3. Registering test analyst account: ${testEmail}...`);
  const regRes = await fetch(`${BASE_URL}/api/v1/auth/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: testEmail, password: testPassword }),
  });
  assert.equal(regRes.status, 201, "Registration must succeed with HTTP 201");
  const regData = await regRes.json();
  assert.equal(regData.email, testEmail.toLowerCase());
  assert.ok(regData.id, "User ID must be returned");
  console.log("✓ Registration succeeded. Account securely created.");

  // 4. Duplicate registration rejection
  console.log("\n4. Verifying duplicate email rejection...");
  const dupRes = await fetch(`${BASE_URL}/api/v1/auth/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: testEmail, password: testPassword }),
  });
  assert.equal(dupRes.status, 400, "Duplicate email must be rejected with 400");
  console.log("✓ Duplicate registration rejected correctly.");

  // 5. Invalid credentials rejection
  console.log("\n5. Verifying rejection of invalid login credentials...");
  const invalidLoginRes = await fetch(`${BASE_URL}/api/v1/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: testEmail, password: "WrongPassword999!" }),
  });
  assert.equal(invalidLoginRes.status, 401, "Invalid password must return HTTP 401");
  const invalidData = await invalidLoginRes.json();
  assert.equal(invalidData.detail, "Incorrect email or password.");
  console.log("✓ Invalid credentials rejected with 401.");

  // 6. Valid Authentication & Session Token Issuance
  console.log("\n6. Authenticating with valid credentials...");
  const loginRes = await fetch(`${BASE_URL}/api/v1/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: testEmail, password: testPassword }),
  });
  assert.equal(loginRes.status, 200, "Valid login must return HTTP 200");
  const loginData = await loginRes.json();
  assert.ok(loginData.session_token, "Session token must be issued");
  assert.ok(loginData.session_token.length > 20, "Session token must have sufficient entropy");
  console.log("✓ Login succeeded. Session established and session_token issued.");

  // 7. Access Protected Endpoint with Session Token
  console.log("\n7. Accessing protected /api/v1/auth/me with Bearer token...");
  const meRes = await fetch(`${BASE_URL}/api/v1/auth/me`, {
    headers: { Authorization: `Bearer ${loginData.session_token}` },
  });
  assert.equal(meRes.status, 200, "Protected endpoint must accept valid session token");
  const meData = await meRes.json();
  assert.equal(meData.email, testEmail.toLowerCase());
  console.log("✓ Protected endpoint accessed successfully via Bearer token.");

  // 8. Access Protected Endpoint WITHOUT Token
  console.log("\n8. Accessing protected endpoint without credentials (should fail)...");
  const unauthRes = await fetch(`${BASE_URL}/api/v1/auth/me`);
  assert.equal(unauthRes.status, 401, "Protected endpoint without token must return HTTP 401");
  console.log("✓ Unauthenticated access correctly blocked with 401.");

  console.log("\n=======================================================");
  console.log("🎉 ALL LIVE INTEGRATION & CONTRACT TESTS PASSED WITH 100% SUCCESS!");
  console.log("=======================================================");
}

run().catch((err) => {
  console.error("Test failed:", err);
  process.exit(1);
});
