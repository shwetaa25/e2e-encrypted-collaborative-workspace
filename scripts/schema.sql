-- ─────────────────────────────────────────────────────────
-- E2E Encrypted Workspace — Database Schema
--
-- IMPORTANT: This schema stores ZERO plaintext content.
-- All document content, titles, and comments are stored
-- as ciphertext blobs. The database is blind to content.
-- ─────────────────────────────────────────────────────────

-- Enable UUID generation
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ── Users ────────────────────────────────────────────────
-- Stores auth credentials and public crypto keys only.
-- Private keys are NEVER stored here — they are stored
-- client-side, wrapped with the user's master key.
CREATE TABLE IF NOT EXISTS users (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email               TEXT NOT NULL UNIQUE,
    password_hash       TEXT NOT NULL,           -- bcrypt hash of password
    public_key_spki     TEXT NOT NULL,           -- RSA public key (SPKI format, base64)
    wrapped_private_key TEXT NOT NULL,           -- RSA private key, AES-wrapped with user's master key
    pbkdf2_salt         TEXT NOT NULL,           -- Salt for PBKDF2 key derivation (base64)
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at        TIMESTAMPTZ
);

-- ── Documents ────────────────────────────────────────────
-- Stores ONLY ciphertext. No plaintext titles or content.
CREATE TABLE IF NOT EXISTS documents (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id            UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- Encrypted title: AES-GCM ciphertext (base64) — server cannot read it
    title_ciphertext    TEXT NOT NULL,
    title_iv            TEXT NOT NULL,           -- AES-GCM initialization vector (base64)
    -- Encrypted content: AES-GCM ciphertext (base64)
    content_ciphertext  TEXT NOT NULL,
    content_iv          TEXT NOT NULL,           -- AES-GCM initialization vector (base64)
    -- Version tracking
    current_version     INTEGER NOT NULL DEFAULT 1,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Document Keys ─────────────────────────────────────────
-- Each row = one user's access to one document.
-- The AES document key is wrapped with the user's RSA public key.
-- Server cannot unwrap it — only the user's private key can.
CREATE TABLE IF NOT EXISTS document_keys (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    document_id         UUID NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- RSA-OAEP encrypted AES key (base64)
    wrapped_key         TEXT NOT NULL,
    -- Access level: 'owner' | 'editor' | 'commenter' | 'viewer'
    access_level        TEXT NOT NULL DEFAULT 'viewer',
    granted_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    granted_by          UUID REFERENCES users(id),
    UNIQUE(document_id, user_id)
);

-- ── Document Versions ────────────────────────────────────
-- Full version history. All versions are encrypted.
CREATE TABLE IF NOT EXISTS document_versions (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    document_id         UUID NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    version_number      INTEGER NOT NULL,
    content_ciphertext  TEXT NOT NULL,           -- Encrypted content snapshot
    content_iv          TEXT NOT NULL,
    created_by          UUID NOT NULL REFERENCES users(id),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Optional: short encrypted note about this version
    note_ciphertext     TEXT,
    note_iv             TEXT,
    UNIQUE(document_id, version_number)
);

-- ── Comments ─────────────────────────────────────────────
-- Comments are encrypted with the document's AES key.
-- Server cannot read comment content.
CREATE TABLE IF NOT EXISTS comments (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    document_id         UUID NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    parent_comment_id   UUID REFERENCES comments(id),   -- for threading
    -- Encrypted comment text
    content_ciphertext  TEXT NOT NULL,
    content_iv          TEXT NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_deleted          BOOLEAN NOT NULL DEFAULT FALSE
);

-- ── SSE Search Index ─────────────────────────────────────
-- Searchable Symmetric Encryption index.
-- Stores HMAC(search_key, keyword) → encrypted doc ID list.
-- Server sees only HMAC tokens — never actual keywords.
CREATE TABLE IF NOT EXISTS search_index (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    document_id         UUID NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    -- HMAC-SHA256(search_key, keyword) — the token for this keyword
    keyword_token       TEXT NOT NULL,
    -- AES-GCM encrypted list of matching positions/metadata
    encrypted_metadata  TEXT,
    metadata_iv         TEXT,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(document_id, keyword_token)
);

-- ── Audit Log ─────────────────────────────────────────────
-- Tamper-evident chain of all actions in the system.
-- Each entry includes hash of the previous entry (chain integrity).
-- Uses pseudonymous user IDs — minimal personal data exposure.
CREATE TABLE IF NOT EXISTS audit_log (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Action type: 'document.created' | 'document.opened' | 'document.updated'
    --              | 'access.granted' | 'access.revoked' | 'comment.added'
    --              | 'search.performed' | 'key.rotated'
    action_type         TEXT NOT NULL,
    -- Pseudonymous ID — NOT the real user UUID (data minimization)
    -- Derived as: HMAC(audit_secret, user_id) — reversible by admin only
    actor_pseudonym     TEXT NOT NULL,
    -- Document ID (nullable — some actions are user-level)
    document_id         UUID REFERENCES documents(id) ON DELETE SET NULL,
    -- Additional context (non-sensitive metadata only)
    metadata            JSONB,
    -- Tamper-evidence chain: SHA-256 hash of (prev_hash || this entry data)
    entry_hash          TEXT NOT NULL,
    prev_entry_hash     TEXT,                    -- NULL for the first entry
    -- Timestamp truncated to hour (data minimization — not exact time)
    created_at_hour     TIMESTAMPTZ NOT NULL DEFAULT date_trunc('hour', NOW())
);

-- ─────────────────────────────────────────────
-- Indexes for query performance
-- ─────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_documents_owner ON documents(owner_id);
CREATE INDEX IF NOT EXISTS idx_doc_keys_doc ON document_keys(document_id);
CREATE INDEX IF NOT EXISTS idx_doc_keys_user ON document_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_versions_doc ON document_versions(document_id);
CREATE INDEX IF NOT EXISTS idx_comments_doc ON comments(document_id);
CREATE INDEX IF NOT EXISTS idx_search_token ON search_index(keyword_token);
CREATE INDEX IF NOT EXISTS idx_search_doc ON search_index(document_id);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor_pseudonym);
CREATE INDEX IF NOT EXISTS idx_audit_doc ON audit_log(document_id);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action_type);

-- ─────────────────────────────────────────────
-- Trigger: auto-update updated_at timestamps
-- ─────────────────────────────────────────────
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_documents_updated_at
    BEFORE UPDATE ON documents
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER trg_comments_updated_at
    BEFORE UPDATE ON comments
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ─────────────────────────────────────────────
-- v2: workspaces, per-file permissions, canonical emails
-- (idempotent — safe to run on an existing database)
-- ─────────────────────────────────────────────

ALTER TABLE users ADD COLUMN IF NOT EXISTS wrap_iv VARCHAR(64);
ALTER TABLE users ADD COLUMN IF NOT EXISTS email_canonical VARCHAR(255);

-- Canonical email = trimmed, lower-case, without "+tag".
-- UNIQUE, so tweaking the address can't create a second account.
UPDATE users
   SET email_canonical = regexp_replace(lower(trim(email)), '[+][^@]*@', '@')
 WHERE email_canonical IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS ix_users_email_canonical ON users(email_canonical);

-- A workspace groups documents and members. Its NAME is ciphertext.
CREATE TABLE IF NOT EXISTS workspaces (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name_ciphertext  TEXT NOT NULL,
    name_iv          VARCHAR(64) NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- One row per member; the AES workspace key is RSA-wrapped for that member.
-- Membership does NOT grant access to files — see document_keys.
CREATE TABLE IF NOT EXISTS workspace_members (
    id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id           UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    user_id                UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role                   VARCHAR(20) NOT NULL DEFAULT 'member',   -- 'owner' | 'member'
    wrapped_workspace_key  TEXT NOT NULL,
    added_by               UUID REFERENCES users(id),
    added_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_workspace_member UNIQUE (workspace_id, user_id)
);
CREATE INDEX IF NOT EXISTS ix_workspace_members_workspace ON workspace_members(workspace_id);
CREATE INDEX IF NOT EXISTS ix_workspace_members_user ON workspace_members(user_id);

-- NULL workspace_id = personal document
ALTER TABLE documents
    ADD COLUMN IF NOT EXISTS workspace_id UUID REFERENCES workspaces(id) ON DELETE CASCADE;
CREATE INDEX IF NOT EXISTS ix_documents_workspace_id ON documents(workspace_id);

-- ─────────────────────────────────────────────
-- v3: usernames (public handle; emails stay private)
-- ─────────────────────────────────────────────
ALTER TABLE users ADD COLUMN IF NOT EXISTS username VARCHAR(32);

-- Back-fill legacy rows from the email local part (de-duplicated with a numeric suffix)
WITH base AS (
    SELECT id, created_at,
           left(regexp_replace(regexp_replace(lower(split_part(email, '@', 1)),
                '[^a-z0-9_]', '_', 'g'), '^([^a-z])', 'u_\1'), 16) AS b
      FROM users WHERE username IS NULL
), ranked AS (
    SELECT id, b, row_number() OVER (PARTITION BY b ORDER BY created_at) AS rn FROM base
)
UPDATE users u
   SET username = CASE WHEN r.rn = 1 THEN r.b ELSE r.b || r.rn END
  FROM ranked r
 WHERE u.id = r.id
   AND NOT EXISTS (SELECT 1 FROM users x WHERE x.username = CASE WHEN r.rn = 1 THEN r.b ELSE r.b || r.rn END);

CREATE UNIQUE INDEX IF NOT EXISTS ix_users_username ON users(username);
