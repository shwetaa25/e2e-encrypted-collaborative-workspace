# tests/unit/test_auth_service.py
# ─────────────────────────────────────────────────────────
# Unit tests for auth service functions.
# These tests don't need a database — pure function tests.
# ─────────────────────────────────────────────────────────

import pytest
import uuid

from app.services.auth_service import (
    hash_password,
    verify_password,
    create_access_token,
    decode_token,
    pseudonymise_user_id,
)
from app.core.config import Settings


# ── Password hashing ──────────────────────────────────────

class TestPasswordHashing:
    def test_hash_password_produces_bcrypt_hash(self):
        hashed = hash_password("TestPass123!")
        assert hashed.startswith("$2b$") or hashed.startswith("$2a$")

    def test_verify_correct_password(self):
        hashed = hash_password("TestPass123!")
        assert verify_password("TestPass123!", hashed) is True

    def test_reject_wrong_password(self):
        hashed = hash_password("TestPass123!")
        assert verify_password("WrongPassword!", hashed) is False

    def test_same_password_different_hashes(self):
        # bcrypt uses a random salt — same password → different hash each time
        hash1 = hash_password("TestPass123!")
        hash2 = hash_password("TestPass123!")
        assert hash1 != hash2

    def test_both_hashes_verify_correctly(self):
        hash1 = hash_password("TestPass123!")
        hash2 = hash_password("TestPass123!")
        assert verify_password("TestPass123!", hash1) is True
        assert verify_password("TestPass123!", hash2) is True


# ── JWT ───────────────────────────────────────────────────

class TestJWT:
    def setup_method(self):
        self.settings = Settings(
            JWT_SECRET="test-secret-that-is-at-least-32-chars-long",
            DATABASE_URL="postgresql+asyncpg://test:test@localhost/test",
        )
        self.user_id = uuid.uuid4()

    def test_create_and_decode_token(self):
        token, expires_in = create_access_token(self.user_id, self.settings)
        assert token
        assert expires_in > 0

        payload = decode_token(token, self.settings)
        assert payload["sub"] == str(self.user_id)
        assert payload["type"] == "access"

    def test_reject_tampered_token(self):
        from fastapi import HTTPException
        token, _ = create_access_token(self.user_id, self.settings)

        # Tamper with the signature
        parts = token.split(".")
        tampered = parts[0] + "." + parts[1] + ".invalidsignature"

        with pytest.raises(HTTPException) as exc_info:
            decode_token(tampered, self.settings)
        assert exc_info.value.status_code == 401

    def test_reject_token_signed_with_different_secret(self):
        from fastapi import HTTPException

        other_settings = Settings(
            JWT_SECRET="completely-different-secret-also-32-chars",
            DATABASE_URL="postgresql+asyncpg://test:test@localhost/test",
        )
        token, _ = create_access_token(self.user_id, other_settings)

        with pytest.raises(HTTPException):
            decode_token(token, self.settings)

    def test_token_contains_correct_user_id(self):
        user_id = uuid.uuid4()
        token, _ = create_access_token(user_id, self.settings)
        payload = decode_token(token, self.settings)
        assert payload["sub"] == str(user_id)


# ── Audit pseudonymisation ────────────────────────────────

class TestAuditPseudonymisation:
    def test_produces_64_char_hex_string(self):
        user_id = uuid.uuid4()
        pseudonym = pseudonymise_user_id(user_id, "test-audit-secret")
        assert len(pseudonym) == 64
        assert all(c in "0123456789abcdef" for c in pseudonym)

    def test_deterministic_same_input_same_output(self):
        user_id = uuid.uuid4()
        p1 = pseudonymise_user_id(user_id, "test-secret")
        p2 = pseudonymise_user_id(user_id, "test-secret")
        assert p1 == p2

    def test_different_users_different_pseudonyms(self):
        user1 = uuid.uuid4()
        user2 = uuid.uuid4()
        p1 = pseudonymise_user_id(user1, "test-secret")
        p2 = pseudonymise_user_id(user2, "test-secret")
        assert p1 != p2

    def test_pseudonym_is_not_the_real_user_id(self):
        user_id = uuid.uuid4()
        pseudonym = pseudonymise_user_id(user_id, "test-secret")
        assert pseudonym != str(user_id)
        assert pseudonym != str(user_id).replace("-", "")

    def test_different_secrets_different_pseudonyms(self):
        # Same user, different audit secret → different pseudonym
        user_id = uuid.uuid4()
        p1 = pseudonymise_user_id(user_id, "secret-one")
        p2 = pseudonymise_user_id(user_id, "secret-two")
        assert p1 != p2
