# tests/integration/test_api.py
# ─────────────────────────────────────────────────────────
# Integration tests covering the full API flow:
#   - Register + Login
#   - Upload encrypted document
#   - Share with another user
#   - Revoke access + verify lockout
#   - Comments
#   - SSE search
#   - Audit log
#
# Requires a running PostgreSQL (set TEST_DATABASE_URL env var).
# In CI, the postgres service container provides this.
# ─────────────────────────────────────────────────────────

import os

# The test-suite registers dozens of users from one address — turn the
# per-IP registration limit off BEFORE the app (and its settings) is imported.
os.environ.setdefault("REGISTER_MAX_PER_WINDOW", "0")

import pytest
import pytest_asyncio
import uuid
from httpx import AsyncClient, ASGITransport

from app.main import app
from app.db.database import engine, Base


# ── Test fixtures ─────────────────────────────────────────

@pytest_asyncio.fixture(scope="session", autouse=True)
async def setup_database():
    """Create all tables before tests, drop after."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture
async def client() -> AsyncClient:
    """HTTP test client using ASGI transport (no real HTTP needed)."""
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        yield client


# Fake crypto material (base64-encoded random data that passes validation)
# In real tests, use the actual WebCrypto-generated values from generate_test_keys.js
FAKE_PUBLIC_KEY = "A" * 200         # Fake SPKI base64
FAKE_WRAPPED_KEY = "B" * 200        # Fake wrapped private key
FAKE_WRAP_IV = "AAAAAAAAAAAAAAAA"   # 16-char base64 (12 bytes)
FAKE_SALT = "AAAAAAAAAAAAAAAA"      # 16-char base64
FAKE_DOC_KEY = "C" * 200           # Fake wrapped document key
FAKE_TOKEN = "a" * 64              # Valid 64-char hex token
STRONG_PASSWORD = "Str0ng!Test#Pw42"  # satisfies the password policy


def make_user_payload(email: str) -> dict:
    return {
        "email": email,
        "username": "u" + uuid.uuid4().hex[:12],
        "password": STRONG_PASSWORD,
        "public_key_spki": FAKE_PUBLIC_KEY,
        "wrapped_private_key": FAKE_WRAPPED_KEY,
        "wrap_iv": FAKE_WRAP_IV,
        "pbkdf2_salt": FAKE_SALT,
    }


def make_doc_payload() -> dict:
    return {
        "title_ciphertext": "ENCRYPTED_TITLE_BASE64==",
        "title_iv": FAKE_WRAP_IV,
        "content_ciphertext": "ENCRYPTED_CONTENT_BASE64==",
        "content_iv": FAKE_WRAP_IV,
        "wrapped_key_for_owner": FAKE_DOC_KEY,
        "search_index": [{"keyword_token": FAKE_TOKEN}],
    }


# ── Auth Tests ────────────────────────────────────────────

class TestAuth:
    @pytest.mark.asyncio
    async def test_register_new_user(self, client: AsyncClient):
        email = f"test-{uuid.uuid4()}@example.com"
        resp = await client.post("/api/v1/auth/register", json=make_user_payload(email))

        assert resp.status_code == 201
        data = resp.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert "user_id" in data
        assert "wrapped_private_key" in data
        assert "pbkdf2_salt" in data

    @pytest.mark.asyncio
    async def test_register_duplicate_email_fails(self, client: AsyncClient):
        email = f"dup-{uuid.uuid4()}@example.com"
        await client.post("/api/v1/auth/register", json=make_user_payload(email))

        resp = await client.post("/api/v1/auth/register", json=make_user_payload(email))
        assert resp.status_code == 409

    @pytest.mark.asyncio
    async def test_login_correct_credentials(self, client: AsyncClient):
        email = f"login-{uuid.uuid4()}@example.com"
        await client.post("/api/v1/auth/register", json=make_user_payload(email))

        resp = await client.post("/api/v1/auth/login", json={
            "email": email, "password": STRONG_PASSWORD
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        # Returns crypto material for key re-derivation
        assert "wrapped_private_key" in data
        assert "pbkdf2_salt" in data
        assert "wrap_iv" in data

    @pytest.mark.asyncio
    async def test_login_wrong_password_fails(self, client: AsyncClient):
        email = f"wrong-{uuid.uuid4()}@example.com"
        await client.post("/api/v1/auth/register", json=make_user_payload(email))

        resp = await client.post("/api/v1/auth/login", json={
            "email": email, "password": "WrongPassword123!"
        })
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_get_me_requires_auth(self, client: AsyncClient):
        resp = await client.get("/api/v1/auth/me")
        assert resp.status_code == 403  # No token


# ── Document Tests ────────────────────────────────────────

class TestDocuments:
    @pytest_asyncio.fixture
    async def alice_token(self, client: AsyncClient) -> str:
        email = f"alice-{uuid.uuid4()}@example.com"
        resp = await client.post("/api/v1/auth/register", json=make_user_payload(email))
        return resp.json()["access_token"]

    @pytest_asyncio.fixture
    async def bob(self, client: AsyncClient) -> dict:
        email = f"bob-{uuid.uuid4()}@example.com"
        resp = await client.post("/api/v1/auth/register", json=make_user_payload(email))
        return resp.json()

    @pytest.mark.asyncio
    async def test_upload_document(self, client: AsyncClient, alice_token: str):
        resp = await client.post(
            "/api/v1/documents",
            json=make_doc_payload(),
            headers={"Authorization": f"Bearer {alice_token}"},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert "id" in data
        assert data["current_version"] == 1

        # Critical: response must not contain plaintext
        assert "title_ciphertext" in data       # encrypted title, not plaintext
        assert "ENCRYPTED" not in data.get("id", "")  # ID is just a UUID

    @pytest.mark.asyncio
    async def test_list_documents(self, client: AsyncClient, alice_token: str):
        # Upload two docs
        for _ in range(2):
            await client.post(
                "/api/v1/documents", json=make_doc_payload(),
                headers={"Authorization": f"Bearer {alice_token}"},
            )

        resp = await client.get(
            "/api/v1/documents",
            headers={"Authorization": f"Bearer {alice_token}"},
        )
        assert resp.status_code == 200
        assert len(resp.json()) >= 2

    @pytest.mark.asyncio
    async def test_share_document(
        self, client: AsyncClient, alice_token: str, bob: dict
    ):
        # Alice uploads a doc
        doc_resp = await client.post(
            "/api/v1/documents", json=make_doc_payload(),
            headers={"Authorization": f"Bearer {alice_token}"},
        )
        doc_id = doc_resp.json()["id"]

        # Alice shares with Bob
        share_resp = await client.post(
            f"/api/v1/documents/{doc_id}/share",
            json={
                "recipient_user_id": bob["user_id"],
                "wrapped_key": FAKE_DOC_KEY,
                "access_level": "editor",
            },
            headers={"Authorization": f"Bearer {alice_token}"},
        )
        assert share_resp.status_code == 201

        # Bob can now see the document in his list
        bob_docs = await client.get(
            "/api/v1/documents",
            headers={"Authorization": f"Bearer {bob['access_token']}"},
        )
        doc_ids = [d["id"] for d in bob_docs.json()]
        assert doc_id in doc_ids

    @pytest.mark.asyncio
    async def test_revoke_access(
        self, client: AsyncClient, alice_token: str, bob: dict
    ):
        # Alice uploads and shares with Bob
        doc_resp = await client.post(
            "/api/v1/documents", json=make_doc_payload(),
            headers={"Authorization": f"Bearer {alice_token}"},
        )
        doc_id = doc_resp.json()["id"]

        # Get Alice's user_id (needed for revoke wrapped keys)
        me = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {alice_token}"}
        )
        alice_id = me.json()["id"]

        await client.post(
            f"/api/v1/documents/{doc_id}/share",
            json={
                "recipient_user_id": bob["user_id"],
                "wrapped_key": FAKE_DOC_KEY,
                "access_level": "editor",
            },
            headers={"Authorization": f"Bearer {alice_token}"},
        )

        # Alice revokes Bob's access + re-keys
        revoke_resp = await client.delete(
            f"/api/v1/documents/{doc_id}/members/{bob['user_id']}",
            json={
                "revoked_user_id": bob["user_id"],
                "new_title_ciphertext": "NEW_TITLE_CIPHER",
                "new_title_iv": FAKE_WRAP_IV,
                "new_content_ciphertext": "NEW_CONTENT_CIPHER",
                "new_content_iv": FAKE_WRAP_IV,
                # Only Alice gets a new wrapped key
                "new_wrapped_keys": [{
                    "user_id": alice_id,
                    "wrapped_key": FAKE_DOC_KEY + "NEW",
                    "access_level": "owner",
                }],
            },
            headers={"Authorization": f"Bearer {alice_token}"},
        )
        assert revoke_resp.status_code == 200

        # Bob can no longer access the document
        bob_doc = await client.get(
            f"/api/v1/documents/{doc_id}",
            headers={"Authorization": f"Bearer {bob['access_token']}"},
        )
        assert bob_doc.status_code == 404  # Not found / no access

    @pytest.mark.asyncio
    async def test_unauthenticated_cannot_access_documents(self, client: AsyncClient):
        resp = await client.get("/api/v1/documents")
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_version_history_created_on_update(
        self, client: AsyncClient, alice_token: str
    ):
        doc_resp = await client.post(
            "/api/v1/documents", json=make_doc_payload(),
            headers={"Authorization": f"Bearer {alice_token}"},
        )
        doc_id = doc_resp.json()["id"]

        # Save an update
        await client.put(
            f"/api/v1/documents/{doc_id}",
            json={
                "title_ciphertext": "NEW_TITLE",
                "title_iv": FAKE_WRAP_IV,
                "content_ciphertext": "NEW_CONTENT",
                "content_iv": FAKE_WRAP_IV,
            },
            headers={"Authorization": f"Bearer {alice_token}"},
        )

        # Version history should have 2 entries
        versions = await client.get(
            f"/api/v1/documents/{doc_id}/versions",
            headers={"Authorization": f"Bearer {alice_token}"},
        )
        assert len(versions.json()) == 2
        assert versions.json()[0]["version_number"] == 2  # Latest first

    @pytest.mark.asyncio
    async def test_add_encrypted_comment(self, client: AsyncClient, alice_token: str):
        doc_resp = await client.post(
            "/api/v1/documents", json=make_doc_payload(),
            headers={"Authorization": f"Bearer {alice_token}"},
        )
        doc_id = doc_resp.json()["id"]

        comment_resp = await client.post(
            f"/api/v1/documents/{doc_id}/comments",
            json={
                "content_ciphertext": "ENCRYPTED_COMMENT",
                "content_iv": FAKE_WRAP_IV,
            },
            headers={"Authorization": f"Bearer {alice_token}"},
        )
        assert comment_resp.status_code == 201

        comments = await client.get(
            f"/api/v1/documents/{doc_id}/comments",
            headers={"Authorization": f"Bearer {alice_token}"},
        )
        assert len(comments.json()) == 1
        # Server returns ciphertext — never plaintext
        assert comments.json()[0]["content_ciphertext"] == "ENCRYPTED_COMMENT"


# ── Search Tests ──────────────────────────────────────────

class TestSearch:
    @pytest.mark.asyncio
    async def test_sse_search_returns_matching_docs(self, client: AsyncClient):
        email = f"searcher-{uuid.uuid4()}@example.com"
        reg = await client.post("/api/v1/auth/register", json=make_user_payload(email))
        token = reg.json()["access_token"]

        # Upload doc with a known token in search index
        unique_token = "d" * 64  # unique 64-char hex token
        await client.post(
            "/api/v1/documents",
            json={**make_doc_payload(), "search_index": [{"keyword_token": unique_token}]},
            headers={"Authorization": f"Bearer {token}"},
        )

        # Search with that token
        results = await client.post(
            "/api/v1/search",
            json={"tokens": [unique_token], "mode": "or"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert results.status_code == 200
        assert len(results.json()) == 1

    @pytest.mark.asyncio
    async def test_search_with_no_match_returns_empty(self, client: AsyncClient):
        email = f"searcher2-{uuid.uuid4()}@example.com"
        reg = await client.post("/api/v1/auth/register", json=make_user_payload(email))
        token = reg.json()["access_token"]

        no_match_token = "f" * 64  # a token not in any document
        results = await client.post(
            "/api/v1/search",
            json={"tokens": [no_match_token], "mode": "or"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert results.status_code == 200
        assert results.json() == []

    @pytest.mark.asyncio
    async def test_search_invalid_token_format_rejected(self, client: AsyncClient):
        email = f"searcher3-{uuid.uuid4()}@example.com"
        reg = await client.post("/api/v1/auth/register", json=make_user_payload(email))
        token = reg.json()["access_token"]

        # Non-hex token should fail validation
        results = await client.post(
            "/api/v1/search",
            json={"tokens": ["not-a-valid-token"], "mode": "or"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert results.status_code == 422  # Validation error


# ── Audit Log Tests ───────────────────────────────────────

class TestAuditLog:
    @pytest.mark.asyncio
    async def test_audit_entries_created_for_document_actions(self, client: AsyncClient):
        email = f"auditor-{uuid.uuid4()}@example.com"
        reg = await client.post("/api/v1/auth/register", json=make_user_payload(email))
        token = reg.json()["access_token"]

        # Upload a doc
        doc_resp = await client.post(
            "/api/v1/documents", json=make_doc_payload(),
            headers={"Authorization": f"Bearer {token}"},
        )
        doc_id = doc_resp.json()["id"]

        # Fetch the doc (creates 'document.opened' entry)
        await client.get(
            f"/api/v1/documents/{doc_id}",
            headers={"Authorization": f"Bearer {token}"},
        )

        # Check audit log
        audit = await client.get(
            f"/api/v1/documents/{doc_id}/audit",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert audit.status_code == 200
        entries = audit.json()
        assert len(entries) >= 2

        action_types = [e["action_type"] for e in entries]
        assert "document.created" in action_types
        assert "document.opened" in action_types

    @pytest.mark.asyncio
    async def test_audit_entries_use_pseudonyms(self, client: AsyncClient):
        email = f"pseudo-{uuid.uuid4()}@example.com"
        reg = await client.post("/api/v1/auth/register", json=make_user_payload(email))
        token = reg.json()["access_token"]
        real_user_id = reg.json()["user_id"]

        doc_resp = await client.post(
            "/api/v1/documents", json=make_doc_payload(),
            headers={"Authorization": f"Bearer {token}"},
        )
        doc_id = doc_resp.json()["id"]

        audit = await client.get(
            f"/api/v1/documents/{doc_id}/audit",
            headers={"Authorization": f"Bearer {token}"},
        )
        entries = audit.json()

        for entry in entries:
            # Actor pseudonym should NOT be the real user ID
            assert entry["actor_pseudonym"] != real_user_id
            # Should be a 64-char hex string
            assert len(entry["actor_pseudonym"]) == 64

    @pytest.mark.asyncio
    async def test_audit_chain_has_hashes(self, client: AsyncClient):
        email = f"chain-{uuid.uuid4()}@example.com"
        reg = await client.post("/api/v1/auth/register", json=make_user_payload(email))
        token = reg.json()["access_token"]

        doc_resp = await client.post(
            "/api/v1/documents", json=make_doc_payload(),
            headers={"Authorization": f"Bearer {token}"},
        )
        doc_id = doc_resp.json()["id"]

        audit = await client.get(
            f"/api/v1/documents/{doc_id}/audit",
            headers={"Authorization": f"Bearer {token}"},
        )
        for entry in audit.json():
            # Every entry must have a hash
            assert entry["entry_hash"]
            assert len(entry["entry_hash"]) == 64
