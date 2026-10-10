# app/models/models.py
# ─────────────────────────────────────────────────────────
# SQLAlchemy ORM models — mirror of scripts/schema.sql.
#
# KEY DESIGN PRINCIPLE:
# Every content field (title, content, comment text) stores
# ONLY ciphertext. The server is blind to all document content.
# ─────────────────────────────────────────────────────────

import uuid
from datetime import datetime
from sqlalchemy import (
    String, Text, Integer, Boolean, DateTime,
    ForeignKey, JSON, UniqueConstraint, func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID

from app.db.database import Base


def new_uuid() -> uuid.UUID:
    return uuid.uuid4()


# ── Users ─────────────────────────────────────────────────
class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=new_uuid
    )
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    # Public handle used to find/add people (lower-case, UNIQUE). Emails stay private.
    username: Mapped[str | None] = mapped_column(
        String(32), unique=True, nullable=True, index=True
    )

    # Canonical form of the email (trimmed, lower-cased, "+tag" removed).
    # UNIQUE — stops duplicate accounts made by only tweaking the address.
    email_canonical: Mapped[str | None] = mapped_column(
        String(255), unique=True, nullable=True, index=True
    )
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)

    # RSA public key (SPKI format, base64) — safe to store/share
    public_key_spki: Mapped[str] = mapped_column(Text, nullable=False)

    # RSA private key, AES-GCM wrapped with user's master key
    # Server cannot read this — only the user's password can unwrap it
    wrapped_private_key: Mapped[str] = mapped_column(Text, nullable=False)

    # IV used when wrapping the private key
    wrap_iv: Mapped[str] = mapped_column(String(64), nullable=False)

    # PBKDF2 salt — not secret, used to re-derive master key on login
    pbkdf2_salt: Mapped[str] = mapped_column(String(64), nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Relationships
    owned_documents: Mapped[list["Document"]] = relationship(back_populates="owner")
    document_keys: Mapped[list["DocumentKey"]] = relationship(
        back_populates="user", foreign_keys="DocumentKey.user_id"
    )
    comments: Mapped[list["Comment"]] = relationship(back_populates="user")


# ── Workspaces ────────────────────────────────────────────
class Workspace(Base):
    """
    A shared space that groups documents and members.

    The workspace NAME is encrypted with a random AES workspace key.
    That key is RSA-wrapped separately for every member
    (see WorkspaceMember.wrapped_workspace_key), so the server never
    sees the name or the key.

    Membership alone does NOT grant access to any document: every
    document still has its own key list (DocumentKey). The uploader
    decides which members can open each file.
    """
    __tablename__ = "workspaces"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=new_uuid
    )
    owner_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    name_ciphertext: Mapped[str] = mapped_column(Text, nullable=False)
    name_iv: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    members: Mapped[list["WorkspaceMember"]] = relationship(
        back_populates="workspace", cascade="all, delete-orphan"
    )


class WorkspaceMember(Base):
    __tablename__ = "workspace_members"
    __table_args__ = (
        UniqueConstraint("workspace_id", "user_id", name="uq_workspace_member"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=new_uuid
    )
    workspace_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )

    # 'owner' | 'member'
    role: Mapped[str] = mapped_column(String(20), nullable=False, default="member")

    # AES workspace key wrapped with THIS member's RSA public key
    wrapped_workspace_key: Mapped[str] = mapped_column(Text, nullable=False)

    added_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=True
    )
    added_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    workspace: Mapped["Workspace"] = relationship(back_populates="members")
    user: Mapped["User"] = relationship(foreign_keys=[user_id])


# ── Documents ─────────────────────────────────────────────
class Document(Base):
    __tablename__ = "documents"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=new_uuid
    )
    owner_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )

    # NULL = personal document (not inside any shared workspace)
    workspace_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"),
        nullable=True, index=True,
    )

    # ENCRYPTED title — server cannot read this
    title_ciphertext: Mapped[str] = mapped_column(Text, nullable=False)
    title_iv: Mapped[str] = mapped_column(String(64), nullable=False)

    # ENCRYPTED content — server cannot read this
    content_ciphertext: Mapped[str] = mapped_column(Text, nullable=False)
    content_iv: Mapped[str] = mapped_column(String(64), nullable=False)

    current_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    # Relationships
    owner: Mapped["User"] = relationship(back_populates="owned_documents")
    document_keys: Mapped[list["DocumentKey"]] = relationship(
        back_populates="document", cascade="all, delete-orphan"
    )
    versions: Mapped[list["DocumentVersion"]] = relationship(
        back_populates="document", cascade="all, delete-orphan"
    )
    comments: Mapped[list["Comment"]] = relationship(
        back_populates="document", cascade="all, delete-orphan"
    )
    search_entries: Mapped[list["SearchIndex"]] = relationship(
        back_populates="document", cascade="all, delete-orphan"
    )


# ── Document Keys (group key management) ─────────────────
class DocumentKey(Base):
    __tablename__ = "document_keys"
    __table_args__ = (
        UniqueConstraint("document_id", "user_id", name="uq_document_user_key"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=new_uuid
    )
    document_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("documents.id", ondelete="CASCADE"), nullable=False
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )

    # AES doc key wrapped with this user's RSA public key
    # Server cannot unwrap this — only the user's private key can
    wrapped_key: Mapped[str] = mapped_column(Text, nullable=False)

    # 'owner' | 'editor' | 'commenter' | 'viewer'
    access_level: Mapped[str] = mapped_column(String(20), nullable=False, default="viewer")

    granted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    granted_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=True
    )

    # Relationships
    document: Mapped["Document"] = relationship(back_populates="document_keys")
    user: Mapped["User"] = relationship(back_populates="document_keys", foreign_keys=[user_id])


# ── Document Versions ────────────────────────────────────
class DocumentVersion(Base):
    __tablename__ = "document_versions"
    __table_args__ = (
        UniqueConstraint("document_id", "version_number", name="uq_doc_version"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=new_uuid
    )
    document_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("documents.id", ondelete="CASCADE"), nullable=False
    )
    version_number: Mapped[int] = mapped_column(Integer, nullable=False)

    # ENCRYPTED content snapshot
    content_ciphertext: Mapped[str] = mapped_column(Text, nullable=False)
    content_iv: Mapped[str] = mapped_column(String(64), nullable=False)

    created_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    # Optional encrypted version note (e.g. "Fixed section 3")
    note_ciphertext: Mapped[str | None] = mapped_column(Text)
    note_iv: Mapped[str | None] = mapped_column(String(64))

    # Relationships
    document: Mapped["Document"] = relationship(back_populates="versions")


# ── Comments ─────────────────────────────────────────────
class Comment(Base):
    __tablename__ = "comments"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=new_uuid
    )
    document_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("documents.id", ondelete="CASCADE"), nullable=False
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    parent_comment_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("comments.id"), nullable=True
    )

    # ENCRYPTED comment text — server cannot read this
    content_ciphertext: Mapped[str] = mapped_column(Text, nullable=False)
    content_iv: Mapped[str] = mapped_column(String(64), nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    is_deleted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # Relationships
    document: Mapped["Document"] = relationship(back_populates="comments")
    user: Mapped["User"] = relationship(back_populates="comments")


# ── SSE Search Index ──────────────────────────────────────
class SearchIndex(Base):
    __tablename__ = "search_index"
    __table_args__ = (
        UniqueConstraint("document_id", "keyword_token", name="uq_doc_token"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=new_uuid
    )
    document_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("documents.id", ondelete="CASCADE"), nullable=False,
        index=True
    )

    # HMAC(search_key, keyword) — server sees only this hash, never the keyword
    keyword_token: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    # Relationships
    document: Mapped["Document"] = relationship(back_populates="search_entries")


# ── Audit Log ────────────────────────────────────────────
class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=new_uuid
    )

    # e.g. 'document.created' | 'document.opened' | 'access.granted'
    # | 'access.revoked' | 'comment.added' | 'search.performed' | 'key.rotated'
    action_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)

    # Pseudonymous ID — NOT the real user UUID (data minimization)
    # = HMAC(AUDIT_SECRET, user_id)
    actor_pseudonym: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    document_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("documents.id", ondelete="SET NULL"), nullable=True,
        index=True
    )

    # Non-sensitive metadata only (access_level, version number, etc.)
    extra_metadata: Mapped[dict | None] = mapped_column("metadata", JSON)

    # SHA-256 chain hash — links this entry to the previous one
    entry_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    prev_entry_hash: Mapped[str | None] = mapped_column(String(64))

    # Truncated to hour for data minimization
    created_at_hour: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
