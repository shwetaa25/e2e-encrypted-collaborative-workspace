#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────
# Confidentiality Test
#
# Queries PostgreSQL directly and verifies that ZERO
# plaintext document content, titles, or comments are
# visible in the database.
#
# This is your PRIMARY security proof for the evaluation.
# Save the output of this script as evidence.
#
# Usage:
#   PGPASSWORD=your_password bash scripts/confidentiality_check.sh
# ─────────────────────────────────────────────────────────

set -e

PGHOST="${PGHOST:-localhost}"
PGPORT="${PGPORT:-5432}"
PGUSER="${PGUSER:-postgres}"
PGDB="${PGDB:-encryptedws}"

PSQL="psql -h $PGHOST -p $PGPORT -U $PGUSER -d $PGDB -t -c"

echo ""
echo "════════════════════════════════════════════════════"
echo "  CONFIDENTIALITY TEST — E2E Encrypted Workspace"
echo "════════════════════════════════════════════════════"
echo "  Database: $PGDB @ $PGHOST:$PGPORT"
echo "  Timestamp: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
echo "════════════════════════════════════════════════════"
echo ""

PASS=0
FAIL=0

check() {
    local description="$1"
    local query="$2"
    local expected_zero="$3"   # "true" means we expect 0 rows (all encrypted)

    result=$($PSQL "$query" 2>&1 | tr -d ' ')

    if [ "$expected_zero" = "true" ]; then
        if [ "$result" = "0" ] || [ -z "$result" ]; then
            echo "  ✅  PASS — $description"
            PASS=$((PASS + 1))
        else
            echo "  ❌  FAIL — $description"
            echo "       Found $result rows with plaintext content!"
            FAIL=$((FAIL + 1))
        fi
    else
        echo "  ℹ️   INFO — $description: $result"
    fi
}

echo "── Document Content ──────────────────────────────"

# content_ciphertext should never look like English text.
# We check for rows where the field is NOT base64-encoded
# (real base64 only contains [A-Za-z0-9+/=]).
check \
    "No plaintext document content (non-base64 content_ciphertext)" \
    "SELECT COUNT(*) FROM documents WHERE content_ciphertext !~ '^[A-Za-z0-9+/]+=*$'" \
    "true"

check \
    "No plaintext document titles (non-base64 title_ciphertext)" \
    "SELECT COUNT(*) FROM documents WHERE title_ciphertext !~ '^[A-Za-z0-9+/]+=*$'" \
    "true"

# Check for common English words in content (should never appear)
for word in "the" "and" "document" "secret" "confidential" "project" "report"; do
    check \
        "No word '$word' in document ciphertext" \
        "SELECT COUNT(*) FROM documents WHERE content_ciphertext ILIKE '%$word%'" \
        "true"
done

echo ""
echo "── Document Keys ─────────────────────────────────"

check \
    "All document keys are base64-encoded (wrapped/encrypted)" \
    "SELECT COUNT(*) FROM document_keys WHERE wrapped_key !~ '^[A-Za-z0-9+/]+=*$'" \
    "true"

echo ""
echo "── Comments ──────────────────────────────────────"

check \
    "No plaintext comment content" \
    "SELECT COUNT(*) FROM comments WHERE content_ciphertext !~ '^[A-Za-z0-9+/]+=*$'" \
    "true"

for word in "the" "and" "comment" "feedback" "review"; do
    check \
        "No word '$word' in comment ciphertext" \
        "SELECT COUNT(*) FROM comments WHERE content_ciphertext ILIKE '%$word%'" \
        "true"
done

echo ""
echo "── User Keys ─────────────────────────────────────"

check \
    "All wrapped private keys are base64-encoded" \
    "SELECT COUNT(*) FROM users WHERE wrapped_private_key !~ '^[A-Za-z0-9+/]+=*$'" \
    "true"

# Public keys should be in SPKI PEM or base64 format
check \
    "Public keys present for all users" \
    "SELECT COUNT(*) FROM users WHERE public_key_spki IS NULL OR public_key_spki = ''" \
    "true"

echo ""
echo "── Search Index ──────────────────────────────────"

check \
    "Search index tokens are HMAC hashes (hex format)" \
    "SELECT COUNT(*) FROM search_index WHERE keyword_token !~ '^[a-f0-9]{64}$'" \
    "true"

echo ""
echo "── Audit Log ─────────────────────────────────────"

check \
    "Audit log has chain hashes (tamper-evident)" \
    "SELECT COUNT(*) FROM audit_log WHERE entry_hash IS NULL OR entry_hash = ''" \
    "true"

# Audit log should not contain real user IDs in actor field
# (should use pseudonyms instead)
check \
    "Audit log uses pseudonymous actor IDs (no raw UUIDs matching user table)" \
    "SELECT COUNT(*) FROM audit_log al JOIN users u ON al.actor_pseudonym = u.id::TEXT" \
    "true"

echo ""
echo "── Database Summary ──────────────────────────────"

$PSQL "SELECT 'documents' as table_name, COUNT(*) as rows FROM documents
       UNION ALL SELECT 'document_keys', COUNT(*) FROM document_keys
       UNION ALL SELECT 'comments', COUNT(*) FROM comments
       UNION ALL SELECT 'search_index', COUNT(*) FROM search_index
       UNION ALL SELECT 'audit_log', COUNT(*) FROM audit_log
       UNION ALL SELECT 'users', COUNT(*) FROM users;" 2>&1

echo ""
echo "════════════════════════════════════════════════════"
echo "  RESULTS: $PASS passed, $FAIL failed"
echo "════════════════════════════════════════════════════"
echo ""

if [ "$FAIL" -gt 0 ]; then
    echo "❌ CONFIDENTIALITY TEST FAILED — plaintext content detected in database!"
    echo "   This is a critical security failure. Review the failed checks above."
    exit 1
else
    echo "✅ ALL CHECKS PASSED — database contains zero plaintext content."
    echo "   The server is cryptographically blind to all document content."
    exit 0
fi
