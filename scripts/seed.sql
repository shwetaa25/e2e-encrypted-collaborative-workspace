-- ─────────────────────────────────────────────────────────
-- Seed data for testing and evaluation.
-- All "content" is synthetic — no real sensitive data.
--
-- Test users (passwords are TestPass123!):
--   alice@test.com  — Document owner
--   bob@test.com    — Collaborator
--   carol@test.com  — Reviewer
--   admin@test.com  — Admin
--
-- NOTE: In a real deployment, users register via the UI
-- and their keys are generated client-side. These seed
-- users have placeholder key values — replace with real
-- key-generated values when running evaluation tests.
-- Use scripts/generate_test_keys.js to generate real keys.
-- ─────────────────────────────────────────────────────────

-- Test users
-- Passwords hashed with bcrypt cost=12 for "TestPass123!"
INSERT INTO users (id, email, username, password_hash, public_key_spki, wrapped_private_key, pbkdf2_salt)
VALUES
(
    'a0000000-0000-0000-0000-000000000001',
    'alice@test.com',
    'alice_demo',
    '$2a$12$PLACEHOLDER_BCRYPT_HASH_ALICE',
    'PLACEHOLDER_RSA_PUBLIC_KEY_ALICE_SPKI_BASE64',
    'PLACEHOLDER_WRAPPED_PRIVATE_KEY_ALICE_BASE64',
    'PLACEHOLDER_PBKDF2_SALT_ALICE_BASE64'
),
(
    'b0000000-0000-0000-0000-000000000002',
    'bob@test.com',
    'bob_demo',
    '$2a$12$PLACEHOLDER_BCRYPT_HASH_BOB',
    'PLACEHOLDER_RSA_PUBLIC_KEY_BOB_SPKI_BASE64',
    'PLACEHOLDER_WRAPPED_PRIVATE_KEY_BOB_BASE64',
    'PLACEHOLDER_PBKDF2_SALT_BOB_BASE64'
),
(
    'c0000000-0000-0000-0000-000000000003',
    'carol@test.com',
    'carol_demo',
    '$2a$12$PLACEHOLDER_BCRYPT_HASH_CAROL',
    'PLACEHOLDER_RSA_PUBLIC_KEY_CAROL_SPKI_BASE64',
    'PLACEHOLDER_WRAPPED_PRIVATE_KEY_CAROL_BASE64',
    'PLACEHOLDER_PBKDF2_SALT_CAROL_BASE64'
),
(
    'd0000000-0000-0000-0000-000000000004',
    'admin@test.com',
    'admin_demo',
    '$2a$12$PLACEHOLDER_BCRYPT_HASH_ADMIN',
    'PLACEHOLDER_RSA_PUBLIC_KEY_ADMIN_SPKI_BASE64',
    'PLACEHOLDER_WRAPPED_PRIVATE_KEY_ADMIN_BASE64',
    'PLACEHOLDER_PBKDF2_SALT_ADMIN_BASE64'
)
ON CONFLICT (email) DO NOTHING;

-- NOTE: Document records with real ciphertext are generated
-- by running: node scripts/generate_test_documents.js
-- This creates 20 test documents encrypted with the test
-- users' actual WebCrypto keys.
