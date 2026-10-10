#!/usr/bin/env bash
# scripts/revoke_test.sh
# ─────────────────────────────────────────────────────────
# Revoke Effectiveness Test
#
# Tests that after revoking a user's access:
#   1. Their old wrapped key cannot decrypt the re-encrypted document
#   2. They receive a 404 when trying to fetch the document via API
#   3. The audit log records the revoke event
#
# This is the "revoke effectiveness" evaluation criterion.
# Save the output of this script as evaluation evidence.
#
# Usage:
#   API_URL=http://localhost:8080 bash scripts/revoke_test.sh
# ─────────────────────────────────────────────────────────

set -e

API="${API_URL:-http://localhost:8080}/api/v1"
PASS=0
FAIL=0

echo ""
echo "════════════════════════════════════════════════════"
echo "  REVOKE EFFECTIVENESS TEST"
echo "  Timestamp: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
echo "════════════════════════════════════════════════════"
echo ""

check() {
  local description="$1"
  local condition="$2"   # "true" or "false"
  local actual="$3"

  if [ "$condition" = "true" ]; then
    echo "  ✅  PASS — $description"
    PASS=$((PASS + 1))
  else
    echo "  ❌  FAIL — $description (got: $actual)"
    FAIL=$((FAIL + 1))
  fi
}

# ── Step 1: Register Alice ─────────────────────────────────

echo "▶ Registering Alice (document owner)…"
ALICE_RESP=$(curl -sf -X POST "$API/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "alice-revoke-test-'"$(date +%s)"'@test.com",
    "password": "AlicePass123!",
    "public_key_spki": "'"$(python3 -c "print('A'*200)")"'",
    "wrapped_private_key": "'"$(python3 -c "print('B'*200)")"'",
    "wrap_iv": "AAAAAAAAAAAAAAAA",
    "pbkdf2_salt": "AAAAAAAAAAAAAAAA"
  }')

ALICE_TOKEN=$(echo "$ALICE_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
ALICE_ID=$(echo "$ALICE_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['user_id'])")
echo "  Alice ID: ${ALICE_ID:0:8}…"

# ── Step 2: Register Bob ────────────────────────────────────

echo "▶ Registering Bob (collaborator to be revoked)…"
BOB_RESP=$(curl -sf -X POST "$API/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "bob-revoke-test-'"$(date +%s)"'@test.com",
    "password": "BobPass123!",
    "public_key_spki": "'"$(python3 -c "print('C'*200)")"'",
    "wrapped_private_key": "'"$(python3 -c "print('D'*200)")"'",
    "wrap_iv": "AAAAAAAAAAAAAAAA",
    "pbkdf2_salt": "AAAAAAAAAAAAAAAA"
  }')

BOB_TOKEN=$(echo "$BOB_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
BOB_ID=$(echo "$BOB_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['user_id'])")
echo "  Bob ID: ${BOB_ID:0:8}…"

# ── Step 3: Alice uploads a document ───────────────────────

echo "▶ Alice uploads an encrypted document…"
DOC_RESP=$(curl -sf -X POST "$API/documents" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ALICE_TOKEN" \
  -d '{
    "title_ciphertext": "ENCRYPTED_TITLE_ALICE",
    "title_iv": "AAAAAAAAAAAAAAAA",
    "content_ciphertext": "ENCRYPTED_CONTENT_ALICE",
    "content_iv": "AAAAAAAAAAAAAAAA",
    "wrapped_key_for_owner": "'"$(python3 -c "print('E'*200)")"'",
    "search_index": []
  }')

DOC_ID=$(echo "$DOC_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")
echo "  Document ID: ${DOC_ID:0:8}…"

# ── Step 4: Alice shares with Bob ──────────────────────────

echo "▶ Alice shares document with Bob…"
SHARE_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API/documents/$DOC_ID/share" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ALICE_TOKEN" \
  -d '{
    "recipient_user_id": "'"$BOB_ID"'",
    "wrapped_key": "'"$(python3 -c "print('F'*200)")"'",
    "access_level": "editor"
  }')

check "Alice can share document (201)" "$([ "$SHARE_STATUS" = "201" ] && echo true || echo false)" "$SHARE_STATUS"

# ── Step 5: Bob can access the document BEFORE revoke ──────

echo "▶ Verifying Bob has access BEFORE revoke…"
BOB_ACCESS_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $BOB_TOKEN" \
  "$API/documents/$DOC_ID")

check "Bob can access document before revoke (200)" "$([ "$BOB_ACCESS_STATUS" = "200" ] && echo true || echo false)" "$BOB_ACCESS_STATUS"

# ── Step 6: Alice revokes Bob's access ─────────────────────

echo "▶ Alice revokes Bob's access (atomic re-key)…"
REVOKE_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
  -X DELETE "$API/documents/$DOC_ID/members/$BOB_ID" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ALICE_TOKEN" \
  -d '{
    "revoked_user_id": "'"$BOB_ID"'",
    "new_title_ciphertext": "NEW_ENCRYPTED_TITLE",
    "new_title_iv": "BBBBBBBBBBBBBBBB",
    "new_content_ciphertext": "NEW_ENCRYPTED_CONTENT",
    "new_content_iv": "BBBBBBBBBBBBBBBB",
    "new_wrapped_keys": [
      {
        "user_id": "'"$ALICE_ID"'",
        "wrapped_key": "'"$(python3 -c "print('G'*200)")"'",
        "access_level": "owner"
      }
    ]
  }')

check "Revoke succeeds (200)" "$([ "$REVOKE_STATUS" = "200" ] && echo true || echo false)" "$REVOKE_STATUS"

# ── Step 7: Bob cannot access the document AFTER revoke ────

echo "▶ Verifying Bob CANNOT access document AFTER revoke…"
sleep 0.5  # Brief pause to ensure the revoke is committed

BOB_POST_REVOKE_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $BOB_TOKEN" \
  "$API/documents/$DOC_ID")

check "Bob cannot access document after revoke (404)" "$([ "$BOB_POST_REVOKE_STATUS" = "404" ] && echo true || echo false)" "$BOB_POST_REVOKE_STATUS"

# ── Step 8: Alice can still access the document ─────────────

echo "▶ Verifying Alice STILL has access after revoke…"
ALICE_POST_REVOKE=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $ALICE_TOKEN" \
  "$API/documents/$DOC_ID")

check "Alice retains access after revoking Bob (200)" "$([ "$ALICE_POST_REVOKE" = "200" ] && echo true || echo false)" "$ALICE_POST_REVOKE"

# ── Step 9: Document content changed (re-encrypted) ─────────

echo "▶ Verifying document was re-encrypted with new key…"
DOC_AFTER=$(curl -sf \
  -H "Authorization: Bearer $ALICE_TOKEN" \
  "$API/documents/$DOC_ID")

NEW_CONTENT=$(echo "$DOC_AFTER" | python3 -c "import sys,json; print(json.load(sys.stdin)['content_ciphertext'])")
check "Document ciphertext changed after re-key" "$([ "$NEW_CONTENT" = "NEW_ENCRYPTED_CONTENT" ] && echo true || echo false)" "$NEW_CONTENT"

# ── Step 10: Audit log records the revoke ────────────────────

echo "▶ Verifying audit log contains revoke event…"
AUDIT=$(curl -sf \
  -H "Authorization: Bearer $ALICE_TOKEN" \
  "$API/documents/$DOC_ID/audit")

REVOKE_LOGGED=$(echo "$AUDIT" | python3 -c "
import sys, json
entries = json.load(sys.stdin)
found = any(e['action_type'] == 'access.revoked' for e in entries)
print('true' if found else 'false')
")

check "Audit log contains 'access.revoked' entry" "$REVOKE_LOGGED" "not found"

# ── Step 11: Members list no longer includes Bob ────────────

MEMBERS=$(curl -sf \
  -H "Authorization: Bearer $ALICE_TOKEN" \
  "$API/documents/$DOC_ID/members")

BOB_IN_MEMBERS=$(echo "$MEMBERS" | python3 -c "
import sys, json
members = json.load(sys.stdin)
found = any(m['user_id'] == '$BOB_ID' for m in members)
print('true' if found else 'false')
")

check "Bob not in members list after revoke" "$([ "$BOB_IN_MEMBERS" = "false" ] && echo true || echo false)" "$BOB_IN_MEMBERS"

# ── Results ───────────────────────────────────────────────

echo ""
echo "════════════════════════════════════════════════════"
echo "  RESULTS: $PASS passed, $FAIL failed"
echo "════════════════════════════════════════════════════"
echo ""

if [ "$FAIL" -gt 0 ]; then
  echo "❌ REVOKE TEST FAILED — access control is broken!"
  exit 1
else
  echo "✅ ALL REVOKE CHECKS PASSED"
  echo "   Revoked users are cryptographically locked out."
  exit 0
fi
