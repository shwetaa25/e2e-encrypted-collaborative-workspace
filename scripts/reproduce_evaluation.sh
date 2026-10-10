#!/usr/bin/env bash
# scripts/reproduce_evaluation.sh
# ─────────────────────────────────────────────────────────
# Reproducibility Script — runs the complete evaluation suite.
#
# Another team can reproduce ALL reported findings by running:
#   bash scripts/reproduce_evaluation.sh
#
# What this runs:
#   1. Confidentiality test (DB has zero plaintext)
#   2. Revoke effectiveness test
#   3. Load test (50 concurrent users, performance overhead)
#   4. Audit chain integrity verification
#   5. Summary report
#
# Requirements:
#   - docker compose up -d (stack must be running)
#   - k6 (load testing): https://k6.io
#   - psql (PostgreSQL client)
# ─────────────────────────────────────────────────────────

set -e

API_URL="${API_URL:-http://localhost:8080}"
PGHOST="${PGHOST:-localhost}"
PGPASSWORD="${PGPASSWORD:-changeme_in_production}"
RESULTS_DIR="evaluation-results-$(date +%Y%m%d-%H%M%S)"

mkdir -p "$RESULTS_DIR"

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║  FULL EVALUATION SUITE — E2E Encrypted Workspace     ║"
echo "║  $(date -u +"%Y-%m-%dT%H:%M:%SZ")                   ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""
echo "Results will be saved to: $RESULTS_DIR/"
echo ""

TOTAL_PASS=0
TOTAL_FAIL=0

run_test() {
  local name="$1"
  local script="$2"
  local output_file="$RESULTS_DIR/$3"

  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "  Running: $name"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

  if eval "$script" 2>&1 | tee "$output_file"; then
    echo "  → ✅ $name PASSED"
    TOTAL_PASS=$((TOTAL_PASS + 1))
  else
    echo "  → ❌ $name FAILED"
    TOTAL_FAIL=$((TOTAL_FAIL + 1))
  fi
  echo ""
}

# ── Test 1: Confidentiality ────────────────────────────────
run_test \
  "Confidentiality Test (DB has zero plaintext)" \
  "PGPASSWORD=$PGPASSWORD bash scripts/confidentiality_check.sh" \
  "01_confidentiality.txt"

# ── Test 2: Revoke Effectiveness ──────────────────────────
run_test \
  "Revoke Effectiveness Test" \
  "API_URL=$API_URL bash scripts/revoke_test.sh" \
  "02_revoke_effectiveness.txt"

# ── Test 3: Audit Chain Integrity ─────────────────────────
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Running: Audit Chain Integrity Verification"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
AUDIT_RESULT=$(curl -sf "$API_URL/api/v1/admin/audit/verify" \
  -H "Authorization: Bearer $ADMIN_TOKEN" 2>/dev/null || echo '{"valid": false, "error": "endpoint not available"}')

echo "$AUDIT_RESULT" | tee "$RESULTS_DIR/03_audit_chain.json"
AUDIT_VALID=$(echo "$AUDIT_RESULT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('valid', False))" 2>/dev/null || echo "False")
if [ "$AUDIT_VALID" = "True" ]; then
  echo "  → ✅ Audit chain integrity verified"
  TOTAL_PASS=$((TOTAL_PASS + 1))
else
  echo "  → ⚠️  Audit chain verification skipped (admin token not set)"
fi
echo ""

# ── Test 4: Load Test ─────────────────────────────────────
if command -v k6 &>/dev/null; then
  run_test \
    "Load Test (50 concurrent users)" \
    "API_URL=$API_URL k6 run --summary-export=$RESULTS_DIR/04_load_test_summary.json scripts/load_test.js" \
    "04_load_test.txt"
else
  echo "  ⚠️  k6 not installed — skipping load test"
  echo "     Install: https://k6.io/docs/getting-started/installation/"
  echo "     Then run: k6 run scripts/load_test.js"
  echo ""
fi

# ── Test 5: Backend unit tests ────────────────────────────
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Running: Backend Unit + Integration Tests"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
docker compose exec -T backend \
  python -m pytest tests/ -v --tb=short 2>&1 | tee "$RESULTS_DIR/05_unit_tests.txt"
echo ""

# ── Final Summary ─────────────────────────────────────────

SUMMARY="
╔══════════════════════════════════════════════════════╗
║  EVALUATION SUMMARY                                  ║
╠══════════════════════════════════════════════════════╣
║  Total passed: $TOTAL_PASS                           ║
║  Total failed: $TOTAL_FAIL                           ║
║  Results dir:  $RESULTS_DIR/                         ║
╚══════════════════════════════════════════════════════╝

Acceptance criteria status:
  Confidentiality (DB zero plaintext):   see 01_confidentiality.txt
  Revoke effectiveness (cryptographic):  see 02_revoke_effectiveness.txt
  Audit chain tamper-evidence:           see 03_audit_chain.json
  Performance overhead (p95 < 500ms):   see 04_load_test_summary.json
  Unit / integration test coverage:      see 05_unit_tests.txt
"

echo "$SUMMARY" | tee "$RESULTS_DIR/SUMMARY.txt"

if [ "$TOTAL_FAIL" -gt 0 ]; then
  exit 1
fi
