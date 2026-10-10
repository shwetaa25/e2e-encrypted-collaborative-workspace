# app/schemas/schemas.py
# ─────────────────────────────────────────────────────────
# Pydantic v2 schemas for request validation and response
# serialization. These define the API contract.
#
# IMPORTANT: Response schemas never include plaintext content.
# All content fields in responses are ciphertext + IV pairs.
# ─────────────────────────────────────────────────────────

from datetime import datetime
from uuid import UUID
from pydantic import BaseModel, EmailStr, Field, field_validator, model_validator
import re

from app.security.password_policy import password_problems, MAX_LENGTH
from app.security.username_policy import normalize_username, username_problems


# ── Auth Schemas ──────────────────────────────────────────

class RegisterRequest(BaseModel):
    """
    Registration payload from the browser.
    All crypto material is generated client-side before this is sent.
    """
    email: EmailStr
    # Public handle other users type to add/share with you (emails stay private)
    username: str = Field(min_length=1, max_length=40)
    password: str = Field(min_length=1, max_length=MAX_LENGTH)

    # RSA public key (SPKI base64) — safe to store, used for key sharing
    public_key_spki: str = Field(min_length=100)

    # RSA private key wrapped with user's master AES key
    wrapped_private_key: str = Field(min_length=100)

    # IV used to wrap the private key (base64, 16 chars = 12 bytes)
    wrap_iv: str = Field(min_length=16, max_length=32)

    # PBKDF2 salt (base64, ~24 chars = 16 bytes)
    pbkdf2_salt: str = Field(min_length=16, max_length=32)

    @field_validator("email")
    @classmethod
    def normalise_email(cls, v: str) -> str:
        return v.strip().lower()

    @field_validator("username")
    @classmethod
    def valid_username(cls, v: str) -> str:
        problems = username_problems(v)
        if problems:
            raise ValueError("Invalid username: " + "; ".join(problems))
        return normalize_username(v)

    @model_validator(mode="after")
    def password_strength(self) -> "RegisterRequest":
        problems = password_problems(self.password, self.email, self.username)
        if problems:
            # Shown to the user as-is (422 detail) — one sentence per problem
            raise ValueError("Weak password: " + "; ".join(problems))
        return self


class LoginRequest(BaseModel):
    # Email OR username (field name kept as `email` for compatibility)
    email: str = Field(min_length=1, max_length=255)
    password: str

    @field_validator("email")
    @classmethod
    def normalise_identifier(cls, v: str) -> str:
        return v.strip().lower()


class TokenResponse(BaseModel):
    """JWT access token returned after successful login."""
    access_token: str
    token_type: str = "bearer"
    expires_in: int          # seconds until expiry

    # Crypto material the browser needs to re-derive keys on login
    user_id: UUID
    public_key_spki: str
    wrapped_private_key: str
    wrap_iv: str
    pbkdf2_salt: str

    # True when this account may open the Admin Console (see ADMIN_EMAILS)
    is_admin: bool = False
    username: str | None = None


class UserResponse(BaseModel):
    """Safe user representation — no password hash, no private key."""
    id: UUID
    email: str
    username: str | None = None
    public_key_spki: str
    created_at: datetime

    model_config = {"from_attributes": True}


# ── Document Schemas ──────────────────────────────────────

class CreateDocumentRequest(BaseModel):
    """
    Upload a new encrypted document.
    Server receives ONLY ciphertext — never plaintext title or content.
    """
    # Encrypted title
    title_ciphertext: str = Field(min_length=1)
    title_iv: str = Field(min_length=16, max_length=32)

    # Encrypted content
    content_ciphertext: str = Field(min_length=1)
    content_iv: str = Field(min_length=16, max_length=32)

    # AES doc key wrapped with the owner's own RSA public key
    # (Owner needs this to read their own document)
    wrapped_key_for_owner: str = Field(min_length=100)

    # SSE search index entries (optional — can be built separately)
    search_index: list["SearchIndexEntry"] = Field(default_factory=list)

    # Put the document inside a shared workspace (None = personal document)
    workspace_id: UUID | None = None


class UpdateDocumentRequest(BaseModel):
    """
    Save a new version of a document.
    Same structure — server only ever sees ciphertext.
    """
    title_ciphertext: str
    title_iv: str
    content_ciphertext: str
    content_iv: str

    # Optional encrypted note for this version
    note_ciphertext: str | None = None
    note_iv: str | None = None

    # Updated search index
    search_index: list["SearchIndexEntry"] = Field(default_factory=list)


class DocumentResponse(BaseModel):
    """
    Document as returned by the server.
    Contains ONLY ciphertext — client decrypts this.
    """
    id: UUID
    owner_id: UUID
    workspace_id: UUID | None = None
    title_ciphertext: str
    title_iv: str
    content_ciphertext: str
    content_iv: str
    current_version: int
    created_at: datetime
    updated_at: datetime

    # The current user's wrapped document key
    # (Needed to decrypt — unique per user)
    wrapped_key: str
    access_level: str

    model_config = {"from_attributes": True}


class DocumentListItem(BaseModel):
    """Lightweight document list item — no content ciphertext (saves bandwidth)."""
    id: UUID
    owner_id: UUID
    workspace_id: UUID | None = None
    title_ciphertext: str
    title_iv: str
    current_version: int
    created_at: datetime
    updated_at: datetime
    wrapped_key: str
    access_level: str

    model_config = {"from_attributes": True}


# ── Sharing / Access Schemas ──────────────────────────────

class ShareDocumentRequest(BaseModel):
    """
    Share a document with another user.
    The AES doc key is wrapped with the recipient's RSA public key client-side.
    """
    recipient_user_id: UUID
    wrapped_key: str = Field(min_length=100)   # AES key wrapped for recipient
    access_level: str = Field(default="viewer")

    @field_validator("access_level")
    @classmethod
    def valid_access_level(cls, v: str) -> str:
        allowed = {"owner", "editor", "commenter", "viewer"}
        if v not in allowed:
            raise ValueError(f"access_level must be one of {allowed}")
        return v


class UpdateAccessLevelRequest(BaseModel):
    """Change what an existing member may do (no re-keying needed)."""
    access_level: str

    @field_validator("access_level")
    @classmethod
    def valid_access_level(cls, v: str) -> str:
        allowed = {"editor", "commenter", "viewer"}
        if v not in allowed:
            raise ValueError(f"access_level must be one of {allowed}")
        return v


class RevokeAccessRequest(BaseModel):
    """
    Revoke a user's access + re-key the document.
    All remaining members get new wrapped keys.
    The document is re-encrypted client-side and sent here.
    """
    # The user being revoked
    revoked_user_id: UUID

    # Re-encrypted document (new AES key was used)
    new_title_ciphertext: str
    new_title_iv: str
    new_content_ciphertext: str
    new_content_iv: str

    # New wrapped keys for all remaining members
    new_wrapped_keys: list["WrappedKeyForUser"]


class WrappedKeyForUser(BaseModel):
    user_id: UUID
    wrapped_key: str
    access_level: str = "viewer"


class MemberResponse(BaseModel):
    """A member of a document's access list."""
    user_id: UUID
    username: str
    access_level: str
    granted_at: datetime
    public_key_spki: str   # Needed by owner to wrap new keys for sharing


# ── Workspace Schemas ─────────────────────────────────────

class CreateWorkspaceRequest(BaseModel):
    """
    The name is AES-GCM encrypted in the browser with a fresh workspace key,
    and that key is wrapped for the creator. The server sees only blobs.
    """
    name_ciphertext: str = Field(min_length=1)
    name_iv: str = Field(min_length=16, max_length=32)
    wrapped_workspace_key: str = Field(min_length=100)


class WorkspaceResponse(BaseModel):
    id: UUID
    owner_id: UUID
    name_ciphertext: str
    name_iv: str
    role: str                       # caller's role: 'owner' | 'member'
    wrapped_workspace_key: str      # caller's copy of the workspace key
    member_count: int
    created_at: datetime


class AddWorkspaceMemberRequest(BaseModel):
    user_id: UUID
    # Workspace key wrapped with the invitee's RSA public key (client-side)
    wrapped_workspace_key: str = Field(min_length=100)


class WorkspaceMemberResponse(BaseModel):
    user_id: UUID
    username: str
    role: str
    added_at: datetime
    public_key_spki: str


# ── Comment Schemas ───────────────────────────────────────

class CreateCommentRequest(BaseModel):
    """Add an encrypted comment to a document."""
    content_ciphertext: str = Field(min_length=1)
    content_iv: str = Field(min_length=16, max_length=32)
    parent_comment_id: UUID | None = None


class CommentResponse(BaseModel):
    id: UUID
    document_id: UUID
    user_id: UUID
    parent_comment_id: UUID | None
    content_ciphertext: str
    content_iv: str
    created_at: datetime
    updated_at: datetime
    is_deleted: bool

    model_config = {"from_attributes": True}


# ── Version Schemas ───────────────────────────────────────

class VersionResponse(BaseModel):
    id: UUID
    document_id: UUID
    version_number: int
    content_ciphertext: str
    content_iv: str
    created_by: UUID
    created_at: datetime
    note_ciphertext: str | None
    note_iv: str | None

    model_config = {"from_attributes": True}


# ── Search Schemas ────────────────────────────────────────

class SearchIndexEntry(BaseModel):
    """One entry in the SSE keyword index."""
    keyword_token: str = Field(
        min_length=64, max_length=64,
        description="HMAC-SHA256(search_key, keyword) — a 64-char hex string"
    )

    @field_validator("keyword_token")
    @classmethod
    def must_be_hex(cls, v: str) -> str:
        if not re.match(r"^[a-f0-9]{64}$", v):
            raise ValueError("keyword_token must be a 64-character lowercase hex string")
        return v


class SearchRequest(BaseModel):
    """
    Privacy-preserving search query.
    Client sends HMAC tokens — never the actual keywords.
    """
    tokens: list[str] = Field(min_length=1, max_length=10)
    mode: str = Field(default="and", description="'and' = all tokens match, 'or' = any token matches")

    @field_validator("tokens")
    @classmethod
    def validate_tokens(cls, v: list[str]) -> list[str]:
        for token in v:
            if not re.match(r"^[a-f0-9]{64}$", token):
                raise ValueError("Each token must be a 64-character hex string")
        return v


class SearchResultItem(BaseModel):
    """A document that matched the search query."""
    document_id: UUID
    title_ciphertext: str
    title_iv: str
    wrapped_key: str
    updated_at: datetime


# ── Audit Schemas ─────────────────────────────────────────

class AuditLogEntry(BaseModel):
    id: UUID
    action_type: str
    actor_pseudonym: str
    document_id: UUID | None
    metadata: dict | None
    entry_hash: str
    prev_entry_hash: str | None
    created_at_hour: datetime

    model_config = {"from_attributes": True}


# Update forward references
CreateDocumentRequest.model_rebuild()
UpdateDocumentRequest.model_rebuild()
RevokeAccessRequest.model_rebuild()
