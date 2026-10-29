# app/api/v1/endpoints/documents.py
# ─────────────────────────────────────────────────────────
# Document endpoints:
#   POST   /documents                        — upload encrypted doc
#   GET    /documents                        — list my documents
#   GET    /documents/{id}                   — fetch one document
#   PUT    /documents/{id}                   — save new version
#   DELETE /documents/{id}                   — delete document
#   POST   /documents/{id}/share             — share with a user
#   DELETE /documents/{id}/members/{user_id} — revoke access + re-key
#   GET    /documents/{id}/members           — list who has access
#   GET    /documents/{id}/versions          — version history
#   GET    /documents/{id}/versions/{vnum}   — fetch a specific version
#   POST   /documents/{id}/comments          — add encrypted comment
#   GET    /documents/{id}/comments          — list comments
#   POST   /search                           — privacy-preserving SSE search
#   GET    /documents/{id}/audit             — audit log for a document
# ─────────────────────────────────────────────────────────

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete, and_, or_, case, update

from app.db.database import get_db
from app.models.models import (
    User, Document, DocumentKey, DocumentVersion,
    Comment, SearchIndex, AuditLog, WorkspaceMember,
)
from app.schemas.schemas import (
    CreateDocumentRequest, UpdateDocumentRequest, DocumentResponse,
    DocumentListItem, ShareDocumentRequest, RevokeAccessRequest,
    MemberResponse, VersionResponse, CreateCommentRequest,
    CommentResponse, SearchRequest, SearchResultItem, AuditLogEntry,
    UpdateAccessLevelRequest,
)
from app.services.auth_service import get_current_user
from app.services.audit_service import write_audit_entry, verify_audit_chain

router = APIRouter(prefix="/documents", tags=["Documents"])


# ── Helpers ───────────────────────────────────────────────

async def _require_document_access(
    document_id: UUID,
    user_id: UUID,
    db: AsyncSession,
    min_level: str = "viewer",
) -> tuple[Document, DocumentKey]:
    """
    Verifies the user has access to a document.
    Returns (document, document_key) or raises 403/404.
    """
    # Fetch document + user's key in one join
    result = await db.execute(
        select(Document, DocumentKey)
        .join(DocumentKey, and_(
            DocumentKey.document_id == Document.id,
            DocumentKey.user_id == user_id,
        ))
        .where(Document.id == document_id)
    )
    row = result.one_or_none()

    if row is None:
        raise HTTPException(status_code=404, detail="Document not found or access denied")

    doc, doc_key = row

    # Check access level hierarchy
    level_order = {"viewer": 0, "commenter": 1, "editor": 2, "owner": 3}
    if level_order.get(doc_key.access_level, -1) < level_order.get(min_level, 0):
        raise HTTPException(status_code=403, detail="Insufficient access level")

    return doc, doc_key


async def _is_workspace_member(
    workspace_id: UUID, user_id: UUID, db: AsyncSession
) -> bool:
    result = await db.execute(
        select(WorkspaceMember.id).where(and_(
            WorkspaceMember.workspace_id == workspace_id,
            WorkspaceMember.user_id == user_id,
        ))
    )
    return result.scalar_one_or_none() is not None


async def _bulk_replace_search_index(
    db: AsyncSession,
    document_id: UUID,
    entries: list,
) -> None:
    """Replaces all search index entries for a document."""
    await db.execute(
        delete(SearchIndex).where(SearchIndex.document_id == document_id)
    )
    for entry in entries:
        db.add(SearchIndex(
            document_id=document_id,
            keyword_token=entry.keyword_token,
        ))


# ── POST /documents ───────────────────────────────────────

@router.post(
    "",
    response_model=DocumentResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Upload an encrypted document",
    description="""
    Stores a new encrypted document. The server receives ONLY ciphertext:
    - title and content are AES-GCM-256 ciphertext blobs
    - the document's AES key is RSA-OAEP wrapped for the owner

    The server cannot read the document title or content.
    """,
)
async def create_document(
    body: CreateDocumentRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> DocumentResponse:
    # A document can only be created inside a workspace the caller belongs to
    if body.workspace_id is not None:
        if not await _is_workspace_member(body.workspace_id, current_user.id, db):
            raise HTTPException(status_code=403, detail="You are not a member of that workspace")

    # Store the encrypted document
    doc = Document(
        owner_id=current_user.id,
        workspace_id=body.workspace_id,
        title_ciphertext=body.title_ciphertext,
        title_iv=body.title_iv,
        content_ciphertext=body.content_ciphertext,
        content_iv=body.content_iv,
        current_version=1,
    )
    db.add(doc)
    await db.flush()  # get doc.id

    # Store the owner's wrapped key (so owner can read their own doc)
    owner_key = DocumentKey(
        document_id=doc.id,
        user_id=current_user.id,
        wrapped_key=body.wrapped_key_for_owner,
        access_level="owner",
        granted_by=current_user.id,
    )
    db.add(owner_key)

    # Save initial version snapshot
    version = DocumentVersion(
        document_id=doc.id,
        version_number=1,
        content_ciphertext=body.content_ciphertext,
        content_iv=body.content_iv,
        created_by=current_user.id,
    )
    db.add(version)

    # Build SSE search index
    if body.search_index:
        await _bulk_replace_search_index(db, doc.id, body.search_index)

    # Write audit entry
    await write_audit_entry(
        db=db,
        action_type="document.created",
        user_id=current_user.id,
        document_id=doc.id,
        metadata={"in_workspace": body.workspace_id is not None},
    )

    await db.commit()
    await db.refresh(doc)

    return DocumentResponse(
        id=doc.id,
        owner_id=doc.owner_id,
        workspace_id=doc.workspace_id,
        title_ciphertext=doc.title_ciphertext,
        title_iv=doc.title_iv,
        content_ciphertext=doc.content_ciphertext,
        content_iv=doc.content_iv,
        current_version=doc.current_version,
        created_at=doc.created_at,
        updated_at=doc.updated_at,
        wrapped_key=owner_key.wrapped_key,
        access_level=owner_key.access_level,
    )


# ── GET /documents ────────────────────────────────────────

@router.get(
    "",
    response_model=list[DocumentListItem],
    summary="List all documents the current user can access",
)
async def list_documents(
    workspace_id: UUID | None = None,
    personal: bool = False,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[DocumentListItem]:
    # Only documents the caller holds a key for are ever returned, so a
    # workspace member never sees files the uploader did not grant them.
    query = (
        select(Document, DocumentKey)
        .join(DocumentKey, and_(
            DocumentKey.document_id == Document.id,
            DocumentKey.user_id == current_user.id,
        ))
        .order_by(Document.updated_at.desc())
    )
    if workspace_id is not None:
        query = query.where(Document.workspace_id == workspace_id)
    elif personal:
        query = query.where(Document.workspace_id.is_(None))
    result = await db.execute(query)
    rows = result.all()

    return [
        DocumentListItem(
            id=doc.id,
            owner_id=doc.owner_id,
            workspace_id=doc.workspace_id,
            title_ciphertext=doc.title_ciphertext,
            title_iv=doc.title_iv,
            current_version=doc.current_version,
            created_at=doc.created_at,
            updated_at=doc.updated_at,
            wrapped_key=key.wrapped_key,
            access_level=key.access_level,
        )
        for doc, key in rows
    ]


# ── GET /documents/{id} ───────────────────────────────────

@router.get(
    "/{document_id}",
    response_model=DocumentResponse,
    summary="Fetch a document (ciphertext + wrapped key)",
)
async def get_document(
    document_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> DocumentResponse:
    doc, doc_key = await _require_document_access(document_id, current_user.id, db)

    await write_audit_entry(
        db=db,
        action_type="document.opened",
        user_id=current_user.id,
        document_id=doc.id,
    )
    await db.commit()

    return DocumentResponse(
        id=doc.id,
        owner_id=doc.owner_id,
        workspace_id=doc.workspace_id,
        title_ciphertext=doc.title_ciphertext,
        title_iv=doc.title_iv,
        content_ciphertext=doc.content_ciphertext,
        content_iv=doc.content_iv,
        current_version=doc.current_version,
        created_at=doc.created_at,
        updated_at=doc.updated_at,
        wrapped_key=doc_key.wrapped_key,
        access_level=doc_key.access_level,
    )


# ── PUT /documents/{id} ───────────────────────────────────

@router.put(
    "/{document_id}",
    response_model=DocumentResponse,
    summary="Save a new version of the document",
)
async def update_document(
    document_id: UUID,
    body: UpdateDocumentRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> DocumentResponse:
    doc, doc_key = await _require_document_access(
        document_id, current_user.id, db, min_level="editor"
    )

    # Increment version number
    new_version = doc.current_version + 1

    # Update document
    await db.execute(
        update(Document)
        .where(Document.id == document_id)
        .values(
            title_ciphertext=body.title_ciphertext,
            title_iv=body.title_iv,
            content_ciphertext=body.content_ciphertext,
            content_iv=body.content_iv,
            current_version=new_version,
        )
    )

    # Save version snapshot
    version = DocumentVersion(
        document_id=doc.id,
        version_number=new_version,
        content_ciphertext=body.content_ciphertext,
        content_iv=body.content_iv,
        created_by=current_user.id,
        note_ciphertext=body.note_ciphertext,
        note_iv=body.note_iv,
    )
    db.add(version)

    # Update search index
    if body.search_index:
        await _bulk_replace_search_index(db, doc.id, body.search_index)

    await write_audit_entry(
        db=db,
        action_type="document.updated",
        user_id=current_user.id,
        document_id=doc.id,
        metadata={"version": new_version},
    )

    await db.commit()
    await db.refresh(doc)

    return DocumentResponse(
        id=doc.id,
        owner_id=doc.owner_id,
        workspace_id=doc.workspace_id,
        title_ciphertext=doc.title_ciphertext,
        title_iv=doc.title_iv,
        content_ciphertext=doc.content_ciphertext,
        content_iv=doc.content_iv,
        current_version=doc.current_version,
        created_at=doc.created_at,
        updated_at=doc.updated_at,
        wrapped_key=doc_key.wrapped_key,
        access_level=doc_key.access_level,
    )


# ── DELETE /documents/{id} ────────────────────────────────

@router.delete("/{document_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_document(
    document_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> None:
    doc, _ = await _require_document_access(
        document_id, current_user.id, db, min_level="owner"
    )

    await write_audit_entry(
        db=db,
        action_type="document.deleted",
        user_id=current_user.id,
        document_id=doc.id,
    )

    await db.execute(delete(Document).where(Document.id == document_id))
    await db.commit()


# ── POST /documents/{id}/share ────────────────────────────

@router.post(
    "/{document_id}/share",
    status_code=status.HTTP_201_CREATED,
    summary="Share document with another user",
    description="""
    Grants another user access to this document.

    The caller must be the document owner. Before calling this endpoint,
    the client:
    1. Fetches the recipient's RSA public key (GET /auth/users/{id}/public-key)
    2. Unwraps the document's AES key using their own private key
    3. Re-wraps the AES key with the recipient's public key
    4. Sends the wrapped key here

    The server stores the wrapped key — recipient can now access the document.
    """,
)
async def share_document(
    document_id: UUID,
    body: ShareDocumentRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    # Only owners can share
    doc, _ = await _require_document_access(document_id, current_user.id, db, min_level="owner")

    if body.access_level == "owner":
        raise HTTPException(status_code=400, detail="Ownership cannot be shared")

    # Verify recipient exists
    recipient = await db.get(User, body.recipient_user_id)
    if recipient is None:
        raise HTTPException(status_code=404, detail="Recipient user not found")

    # Files inside a workspace can only go to members of that workspace
    if doc.workspace_id is not None:
        if not await _is_workspace_member(doc.workspace_id, body.recipient_user_id, db):
            raise HTTPException(
                status_code=400,
                detail="Recipient is not a member of this workspace. Add them to the workspace first.",
            )

    # Check if already has access
    existing = await db.execute(
        select(DocumentKey).where(and_(
            DocumentKey.document_id == document_id,
            DocumentKey.user_id == body.recipient_user_id,
        ))
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="User already has access")

    # Grant access
    new_key = DocumentKey(
        document_id=document_id,
        user_id=body.recipient_user_id,
        wrapped_key=body.wrapped_key,
        access_level=body.access_level,
        granted_by=current_user.id,
    )
    db.add(new_key)

    await write_audit_entry(
        db=db,
        action_type="access.granted",
        user_id=current_user.id,
        document_id=document_id,
        metadata={"access_level": body.access_level},
    )

    await db.commit()
    return {"message": "Access granted", "access_level": body.access_level}


# ── PATCH /documents/{id}/members/{user_id} ──────────────

@router.patch(
    "/{document_id}/members/{member_user_id}",
    summary="Change a member's permission on one document",
    description="""
    Owner-only. Switches an existing member between viewer / commenter / editor.
    No re-keying is needed because the member already holds the document key;
    the server enforces the new level on every request.
    To remove someone completely, use the revoke endpoint (which re-keys).
    """,
)
async def update_member_access(
    document_id: UUID,
    member_user_id: UUID,
    body: UpdateAccessLevelRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    await _require_document_access(document_id, current_user.id, db, min_level="owner")
    if member_user_id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot change your own access level")

    result = await db.execute(
        select(DocumentKey).where(and_(
            DocumentKey.document_id == document_id,
            DocumentKey.user_id == member_user_id,
        ))
    )
    key = result.scalar_one_or_none()
    if key is None:
        raise HTTPException(status_code=404, detail="User does not have access to this document")

    key.access_level = body.access_level
    await write_audit_entry(
        db=db,
        action_type="access.changed",
        user_id=current_user.id,
        document_id=document_id,
        metadata={"access_level": body.access_level},
    )
    await db.commit()
    return {"message": "Access level updated", "access_level": body.access_level}


# ── DELETE /documents/{id}/members/{user_id} ─────────────
# REVOKE ACCESS — the most security-critical endpoint

@router.delete(
    "/{document_id}/members/{revoked_user_id}",
    summary="Revoke access + re-encrypt document (key rotation)",
    description="""
    Revokes a user's access to a document and performs key rotation.

    This is the most security-critical operation. The process:
    1. Client generates a NEW AES document key
    2. Client re-encrypts the document with the new key
    3. Client re-wraps the new key for all REMAINING members
    4. Client sends everything here in ONE atomic request

    After this:
    - The revoked user's old wrapped key decrypts to the OLD AES key
    - The OLD AES key cannot decrypt the NEW ciphertext
    - The revoked user is cryptographically locked out

    Edge case handled: if the last member is removed, the document
    becomes inaccessible (no wrapped keys). This is intentional.
    """,
)
async def revoke_access(
    document_id: UUID,
    revoked_user_id: UUID,
    body: RevokeAccessRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    # Only owners can revoke
    await _require_document_access(document_id, current_user.id, db, min_level="owner")

    # Can't revoke yourself (owner must always have access)
    if revoked_user_id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot revoke your own access")

    # Verify the revoked user actually has access
    revoked_key = await db.execute(
        select(DocumentKey).where(and_(
            DocumentKey.document_id == document_id,
            DocumentKey.user_id == revoked_user_id,
        ))
    )
    if revoked_key.scalar_one_or_none() is None:
        raise HTTPException(status_code=404, detail="User does not have access to this document")

    # ── ATOMIC OPERATION: revoke + re-key ─────────────────

    # 1. Update document with re-encrypted content (new AES key used)
    await db.execute(
        update(Document)
        .where(Document.id == document_id)
        .values(
            title_ciphertext=body.new_title_ciphertext,
            title_iv=body.new_title_iv,
            content_ciphertext=body.new_content_ciphertext,
            content_iv=body.new_content_iv,
            current_version=Document.current_version + 1,
        )
    )

    # 2. Delete ALL existing wrapped keys
    await db.execute(
        delete(DocumentKey).where(DocumentKey.document_id == document_id)
    )

    # 3. Insert new wrapped keys for all REMAINING members
    for member_key in body.new_wrapped_keys:
        db.add(DocumentKey(
            document_id=document_id,
            user_id=member_key.user_id,
            wrapped_key=member_key.wrapped_key,
            access_level=member_key.access_level,
            granted_by=current_user.id,
        ))

    # 4. Replace search index (re-indexed with new key)
    await db.execute(
        delete(SearchIndex).where(SearchIndex.document_id == document_id)
    )

    await write_audit_entry(
        db=db,
        action_type="access.revoked",
        user_id=current_user.id,
        document_id=document_id,
        metadata={"remaining_members": len(body.new_wrapped_keys)},
    )

    await db.commit()
    return {
        "message": "Access revoked and document re-encrypted",
        "remaining_members": len(body.new_wrapped_keys),
    }


# ── GET /documents/{id}/members ───────────────────────────

@router.get(
    "/{document_id}/members",
    response_model=list[MemberResponse],
    summary="List all members with access to this document",
)
async def list_members(
    document_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[MemberResponse]:
    # Any member can see the member list (needed for re-sharing UI)
    await _require_document_access(document_id, current_user.id, db)

    result = await db.execute(
        select(User, DocumentKey)
        .join(DocumentKey, DocumentKey.user_id == User.id)
        .where(DocumentKey.document_id == document_id)
        .order_by(DocumentKey.granted_at.asc())
    )
    rows = result.all()

    return [
        MemberResponse(
            user_id=user.id,
            username=user.username or "unknown",
            access_level=key.access_level,
            granted_at=key.granted_at,
            public_key_spki=user.public_key_spki,
        )
        for user, key in rows
    ]


# ── GET /documents/{id}/versions ─────────────────────────

@router.get(
    "/{document_id}/versions",
    response_model=list[VersionResponse],
    summary="Get document version history",
)
async def list_versions(
    document_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[VersionResponse]:
    await _require_document_access(document_id, current_user.id, db)

    result = await db.execute(
        select(DocumentVersion)
        .where(DocumentVersion.document_id == document_id)
        .order_by(DocumentVersion.version_number.desc())
    )
    versions = result.scalars().all()
    return [VersionResponse.model_validate(v) for v in versions]


# ── GET /documents/{id}/versions/{version_number} ────────

@router.get(
    "/{document_id}/versions/{version_number}",
    response_model=VersionResponse,
    summary="Fetch a specific document version",
)
async def get_version(
    document_id: UUID,
    version_number: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> VersionResponse:
    await _require_document_access(document_id, current_user.id, db)

    result = await db.execute(
        select(DocumentVersion).where(
            and_(
                DocumentVersion.document_id == document_id,
                DocumentVersion.version_number == version_number,
            )
        )
    )
    version = result.scalar_one_or_none()
    if version is None:
        raise HTTPException(status_code=404, detail="Version not found")

    return VersionResponse.model_validate(version)


# ── POST /documents/{id}/comments ────────────────────────

@router.post(
    "/{document_id}/comments",
    response_model=CommentResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Add an encrypted comment",
)
async def create_comment(
    document_id: UUID,
    body: CreateCommentRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> CommentResponse:
    # Commenters and above can comment
    await _require_document_access(document_id, current_user.id, db, min_level="commenter")

    comment = Comment(
        document_id=document_id,
        user_id=current_user.id,
        parent_comment_id=body.parent_comment_id,
        content_ciphertext=body.content_ciphertext,
        content_iv=body.content_iv,
    )
    db.add(comment)

    await write_audit_entry(
        db=db,
        action_type="comment.added",
        user_id=current_user.id,
        document_id=document_id,
    )

    await db.commit()
    await db.refresh(comment)
    return CommentResponse.model_validate(comment)


# ── GET /documents/{id}/comments ─────────────────────────

@router.get(
    "/{document_id}/comments",
    response_model=list[CommentResponse],
    summary="List all comments on a document (encrypted)",
)
async def list_comments(
    document_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[CommentResponse]:
    await _require_document_access(document_id, current_user.id, db)

    result = await db.execute(
        select(Comment)
        .where(and_(
            Comment.document_id == document_id,
            Comment.is_deleted == False,
        ))
        .order_by(Comment.created_at.asc())
    )
    comments = result.scalars().all()
    return [CommentResponse.model_validate(c) for c in comments]


# ── GET /documents/{id}/audit ─────────────────────────────

@router.get(
    "/{document_id}/audit",
    response_model=list[AuditLogEntry],
    summary="View audit log for a document",
)
async def get_document_audit(
    document_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[AuditLogEntry]:
    # Only owner can see audit log
    await _require_document_access(document_id, current_user.id, db, min_level="owner")

    result = await db.execute(
        select(AuditLog)
        .where(AuditLog.document_id == document_id)
        .order_by(AuditLog.created_at_hour.desc())
        .limit(200)
    )
    entries = result.scalars().all()
    return [
    AuditLogEntry(
        id=e.id,
        action_type=e.action_type,
        actor_pseudonym=e.actor_pseudonym,
        document_id=e.document_id,
        metadata=dict(e.metadata) if e.metadata and isinstance(e.metadata, dict) else None,
        entry_hash=e.entry_hash,
        prev_entry_hash=e.prev_entry_hash,
        created_at_hour=e.created_at_hour,
    )
    for e in entries
]


# ── POST /search ──────────────────────────────────────────

search_router = APIRouter(tags=["Search"])

@search_router.post(
    "/search",
    response_model=list[SearchResultItem],
    summary="Privacy-preserving search (SSE)",
    description="""
    Searches encrypted documents using Searchable Symmetric Encryption.

    The client sends per-document HMAC tokens (not keywords) and the server matches
    each token set only against that document's encrypted index. The server learns:
    - Which documents matched (document IDs)
    - How many tokens matched

    The server does NOT learn:
    - What keywords were searched
    - What the document content contains

    For AND search (mode='and'): returns documents matching ALL tokens.
    For OR search (mode='or'): returns documents matching ANY token.
    """,
)
async def search_documents(
    body: SearchRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[SearchResultItem]:
    # Each document uses a distinct AES key, so query HMACs are document-specific.
    # Only compare a document's index with the tokens generated for that document.
    from sqlalchemy import func as sqlfunc

    valid_tokens = {
        document_id: list(dict.fromkeys(tokens))
        for document_id, tokens in body.document_tokens.items()
        if tokens
    }
    if not valid_tokens:
        return []

    match_conditions = [
        and_(SearchIndex.document_id == document_id,
             SearchIndex.keyword_token.in_(tokens))
        for document_id, tokens in valid_tokens.items()
    ]
    matching = select(SearchIndex.document_id.label("document_id")).where(
        or_(*match_conditions)
    ).group_by(SearchIndex.document_id)

    if body.mode == "and":
        expected_matches = case(
            *[(SearchIndex.document_id == document_id, len(tokens))
              for document_id, tokens in valid_tokens.items()],
            else_=0,
        )
        matching = matching.having(
            sqlfunc.count(SearchIndex.keyword_token.distinct()) == expected_matches
        )
    else:
        matching = matching.having(sqlfunc.count(SearchIndex.keyword_token.distinct()) >= 1)

    subq = matching.subquery()
    result = await db.execute(
        select(Document, DocumentKey)
        .join(subq, Document.id == subq.c.document_id)
        .join(DocumentKey, and_(
            DocumentKey.document_id == Document.id,
            DocumentKey.user_id == current_user.id,
        ))
        .order_by(Document.updated_at.desc())
        .limit(50)
    )
    rows = result.all()

    await write_audit_entry(
        db=db,
        action_type="search.performed",
        user_id=current_user.id,
        metadata={"document_count": len(valid_tokens), "mode": body.mode},
    )
    await db.commit()

    return [
        SearchResultItem(
            document_id=doc.id,
            title_ciphertext=doc.title_ciphertext,
            title_iv=doc.title_iv,
            wrapped_key=key.wrapped_key,
            updated_at=doc.updated_at,
        )
        for doc, key in rows
    ]
