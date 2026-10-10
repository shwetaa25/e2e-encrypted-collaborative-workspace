// scripts/load_test.js
// ─────────────────────────────────────────────────────────
// k6 load test for the evaluation dossier.
// Tests: API under 50 concurrent users, measures latency
// and error rate for all endpoints.
//
// Run: k6 run scripts/load_test.js
// Install k6: https://k6.io/docs/getting-started/installation/
//
// Acceptance criteria (from evaluation plan):
//   - p95 latency < 2s for all endpoints under load
//   - Error rate < 1%
//   - Encryption overhead < 500ms at p95
// ─────────────────────────────────────────────────────────

import http from "k6/http";
import { check, sleep } from "k6";
import { Trend, Rate, Counter } from "k6/metrics";

// ── Custom metrics ────────────────────────────────────────

const encryptedUploadDuration = new Trend("encrypted_upload_ms");
const searchDuration = new Trend("sse_search_ms");
const loginDuration = new Trend("login_ms");
const errorRate = new Rate("errors");
const requestCount = new Counter("requests_total");

// ── Test config ───────────────────────────────────────────

export const options = {
  stages: [
    { duration: "30s", target: 10 },   // Ramp up to 10 users
    { duration: "60s", target: 50 },   // Ramp up to 50 users (peak)
    { duration: "60s", target: 50 },   // Hold at 50 users
    { duration: "30s", target: 0 },    // Ramp down
  ],
  thresholds: {
    // ── Acceptance thresholds (go/no-go criteria) ──────
    http_req_duration: ["p(95)<2000"],       // p95 < 2s overall
    encrypted_upload_ms: ["p(95)<500"],      // Encryption overhead < 500ms
    sse_search_ms: ["p(95)<2000"],           // SSE search < 2s
    errors: ["rate<0.01"],                   // Error rate < 1%
    http_req_failed: ["rate<0.01"],
  },
};

const BASE_URL = __ENV.API_URL || "http://localhost:8080";

// Pre-computed fake crypto material (simulates what the browser generates)
// In a real evaluation run, use actual WebCrypto-generated values
const FAKE_KEYS = {
  public_key_spki: "A".repeat(200),
  wrapped_private_key: "B".repeat(200),
  wrap_iv: "A".repeat(16),
  pbkdf2_salt: "A".repeat(16),
  wrapped_doc_key: "C".repeat(200),
  doc_iv: "A".repeat(16),
  sse_token: "a".repeat(64),
};

// ── Setup: create a test user before the load test ────────

export function setup() {
  const email = `loadtest-${Date.now()}@test.com`;
  const regResp = http.post(
    `${BASE_URL}/api/v1/auth/register`,
    JSON.stringify({
      email,
      password: "LoadTest123!",
      ...FAKE_KEYS,
    }),
    { headers: { "Content-Type": "application/json" } }
  );

  if (regResp.status !== 201) {
    throw new Error(`Setup failed: ${regResp.body}`);
  }

  return { email, token: regResp.json("access_token") };
}

// ── Main test function (runs for each VU on each iteration) ─

export default function (data) {
  const { email, token } = data;
  const headers = {
    "Content-Type": "application/json",
    Authorization: `Bearer ${token}`,
  };

  requestCount.add(1);

  // ── Test 1: Login (measures key derivation overhead) ──
  const loginStart = Date.now();
  const loginResp = http.post(
    `${BASE_URL}/api/v1/auth/login`,
    JSON.stringify({ email, password: "LoadTest123!" }),
    { headers: { "Content-Type": "application/json" } }
  );
  loginDuration.add(Date.now() - loginStart);

  const loginOk = check(loginResp, {
    "login 200": (r) => r.status === 200,
    "login has token": (r) => r.json("access_token") !== undefined,
  });
  errorRate.add(!loginOk);

  // ── Test 2: Upload encrypted document ─────────────────
  const uploadStart = Date.now();
  const uploadResp = http.post(
    `${BASE_URL}/api/v1/documents`,
    JSON.stringify({
      title_ciphertext: "ENCRYPTED_TITLE_" + Math.random().toString(36),
      title_iv: FAKE_KEYS.doc_iv,
      content_ciphertext: "ENCRYPTED_CONTENT_" + "X".repeat(500), // ~500 byte doc
      content_iv: FAKE_KEYS.doc_iv,
      wrapped_key_for_owner: FAKE_KEYS.wrapped_doc_key,
      search_index: [{ keyword_token: FAKE_KEYS.sse_token }],
    }),
    { headers }
  );
  encryptedUploadDuration.add(Date.now() - uploadStart);

  const uploadOk = check(uploadResp, {
    "upload 201": (r) => r.status === 201,
    "upload has id": (r) => r.json("id") !== undefined,
    "upload no plaintext": (r) => {
      const body = r.body;
      // Verify server never echoes back plaintext-looking content
      return !body.includes("secret") && !body.includes("password");
    },
  });
  errorRate.add(!uploadOk);

  // ── Test 3: List documents ─────────────────────────────
  const listResp = http.get(`${BASE_URL}/api/v1/documents`, { headers });
  check(listResp, { "list 200": (r) => r.status === 200 });

  // ── Test 4: SSE search ────────────────────────────────
  const searchStart = Date.now();
  const searchResp = http.post(
    `${BASE_URL}/api/v1/search`,
    JSON.stringify({
      tokens: [FAKE_KEYS.sse_token],
      mode: "or",
    }),
    { headers }
  );
  searchDuration.add(Date.now() - searchStart);

  check(searchResp, {
    "search 200": (r) => r.status === 200,
    "search is array": (r) => Array.isArray(r.json()),
  });

  sleep(1); // 1s between iterations per VU
}

// ── Teardown: print summary ───────────────────────────────

export function handleSummary(data) {
  const p95Upload = data.metrics.encrypted_upload_ms?.values?.["p(95)"] ?? "N/A";
  const p95Search = data.metrics.sse_search_ms?.values?.["p(95)"] ?? "N/A";
  const p95Overall = data.metrics.http_req_duration?.values?.["p(95)"] ?? "N/A";
  const errRate = (data.metrics.errors?.values?.rate * 100 ?? 0).toFixed(2);

  const summary = `
══════════════════════════════════════════════════════
  LOAD TEST RESULTS — E2E Encrypted Workspace
══════════════════════════════════════════════════════

  Virtual users (peak):   50
  Duration:               ~3 minutes

  ── Latency ─────────────────────────────────────────
  Overall p95:            ${p95Overall}ms       (target: < 2000ms)
  Encrypted upload p95:   ${p95Upload}ms   (target: < 500ms)
  SSE search p95:         ${p95Search}ms   (target: < 2000ms)

  ── Reliability ─────────────────────────────────────
  Error rate:             ${errRate}%           (target: < 1%)
  Total requests:         ${data.metrics.requests_total?.values?.count ?? "N/A"}

  ── Acceptance ──────────────────────────────────────
  Upload overhead:        ${p95Upload <= 500 ? "✅ PASS" : "❌ FAIL"}
  Search latency:         ${p95Search <= 2000 ? "✅ PASS" : "❌ FAIL"}
  Overall latency:        ${p95Overall <= 2000 ? "✅ PASS" : "❌ FAIL"}
  Error rate:             ${parseFloat(errRate) < 1 ? "✅ PASS" : "❌ FAIL"}

══════════════════════════════════════════════════════
`;

  console.log(summary);

  return {
    "load-test-results.txt": summary,
    stdout: summary,
  };
}
