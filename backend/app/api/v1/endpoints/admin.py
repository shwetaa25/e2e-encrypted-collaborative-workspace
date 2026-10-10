# app/api/v1/endpoints/admin.py
# ─────────────────────────────────────────────────────────
# Admin Console API (separate from the workspace UI).
#   GET    /admin/network-log      — live classified request/response log
#   DELETE /admin/network-log      — clear the log
#   GET    /admin/stats            — counters + bytes of ciphertext stored
#   GET    /admin/db-view          — raw rows exactly as PostgreSQL stores them
#   GET    /admin/audit            — global tamper-evident audit log
#   GET    /admin/audit/verify     — re-computes the SHA-256 hash chain
#   GET    /admin/users            — registered accounts (no secrets)
#   DELETE /admin/users/{id}       — delete an account (not admins / yourself)
#   GET    /admin/workspaces       — all workspaces (owner + counts)
#   DELETE /admin/workspaces/{id}  — delete any workspace and its files
#
# Admins are the emails listed in the ADMIN_EMAILS environment variable.
# NOTE: none of these endpoints can decrypt anything — the server has no keys.
# ─────────────────────────────────────────────────────────

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import select, func, update, delete, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings, Settings
from app.core.network_log import network_log
from app.db.database import get_db
from app.models.models import (
    User, Workspace, WorkspaceMember, Document, DocumentKey,
    DocumentVersion, Comment, SearchIndex, AuditLog,
)
from app.services.auth_service import get_current_admin, is_admin_user
from app.services.audit_service import verify_audit_chain, write_audit_entry

router = APIRouter(prefix="/admin", tags=["Admin"])


# ── Network log ───────────────────────────────────────────

@router.get("/network-log", summary="Live network log with encryption classification")
async def get_network_log(
    since: int = Query(0, ge=0, description="Return entries with seq greater than this"),
    limit: int = Query(200, ge=1, le=500),
    _: User = Depends(get_current_admin),
    settings: Settings = Depends(get_settings),
) -> dict:
    return {
        "enabled": settings.NETWORK_LOG_ENABLED,
        "latest_seq": network_log.latest_seq,
        "entries": network_log.since(since, limit),
    }


@router.delete("/network-log", status_code=204, summary="Clear the network log")
async def clear_network_log(_: User = Depends(get_current_admin)) -> None:
    network_log.clear()


# ── Stats ─────────────────────────────────────────────────

async def _count(db: AsyncSession, model) -> int:
    return int((await db.execute(select(func.count()).select_from(model))).scalar_one())


@router.get("/stats", summary="System-wide counters")
async def get_stats(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_admin),
) -> dict:
    ciphertext_bytes = (await db.execute(
        select(func.coalesce(func.sum(func.length(Document.content_ciphertext)), 0))
    )).scalar_one()
    return {
        "users": await _count(db, User),
        "workspaces": await _count(db, Workspace),
        "workspace_memberships": await _count(db, WorkspaceMember),
        "documents": await _count(db, Document),
        "document_keys": await _count(db, DocumentKey),
        "versions": await _count(db, DocumentVersion),
        "comments": await _count(db, Comment),
        "search_tokens": await _count(db, SearchIndex),
        "audit_entries": await _count(db, AuditLog),
        "ciphertext_chars_stored": int(ciphertext_bytes),
        "plaintext_columns_for_content": 0,     # by design: there are none
    }


# ── Server-side (at rest) view ────────────────────────────

_TABLES = {
    "documents": (Document, ["id", "owner_id", "workspace_id", "title_ciphertext", "title_iv",
                             "content_ciphertext", "content_iv", "current_version", "updated_at"]),
    "document_keys": (DocumentKey, ["id", "document_id", "user_id", "wrapped_key", "access_level"]),
    "workspaces": (Workspace, ["id", "owner_id", "name_ciphertext", "name_iv", "created_at"]),
    "workspace_members": (WorkspaceMember, ["id", "workspace_id", "user_id", "role",
                                           "wrapped_workspace_key"]),
    "comments": (Comment, ["id", "document_id", "user_id", "content_ciphertext", "content_iv"]),
    "search_index": (SearchIndex, ["id", "document_id", "keyword_token"]),
    "users": (User, ["id", "email", "password_hash", "public_key_spki", "wrapped_private_key",
                     "pbkdf2_salt"]),
}


def _cell(value, limit: int = 96) -> dict:
    text = "" if value is None else str(value)
    return {"value": text if len(text) <= limit else text[:limit] + "…", "length": len(text)}


@router.get("/db-view", summary="Rows exactly as stored in PostgreSQL (truncated)")
async def db_view(
    table: str = Query("documents"),
    limit: int = Query(8, ge=1, le=50),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_admin),
) -> dict:
    if table not in _TABLES:
        raise HTTPException(status_code=400, detail=f"table must be one of {sorted(_TABLES)}")
    model, columns = _TABLES[table]
    # NB: don't use `a or b` on SQLAlchemy columns — their truthiness is undefined
    order_col = getattr(model, "created_at", None)
    if order_col is None:
        order_col = getattr(model, "updated_at", None)
    query = select(model).limit(limit)
    if order_col is not None:
        query = query.order_by(order_col.desc())
    rows = (await db.execute(query)).scalars().all()
    return {
        "table": table,
        "tables": sorted(_TABLES),
        "columns": columns,
        "rows": [{c: _cell(getattr(r, c, None)) for c in columns} for r in rows],
    }


# ── Audit ─────────────────────────────────────────────────

@router.get("/audit", summary="Global audit log (pseudonymised)")
async def global_audit(
    limit: int = Query(100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_admin),
) -> list[dict]:
    rows = (await db.execute(
        select(AuditLog).order_by(AuditLog.created_at_hour.desc(), AuditLog.id.desc()).limit(limit)
    )).scalars().all()
    return [
        {
            "id": str(e.id),
            "action_type": e.action_type,
            "actor_pseudonym": e.actor_pseudonym,
            "document_id": str(e.document_id) if e.document_id else None,
            "metadata": e.extra_metadata if isinstance(e.extra_metadata, dict) else None,
            "entry_hash": e.entry_hash,
            "prev_entry_hash": e.prev_entry_hash,
            "created_at_hour": e.created_at_hour.isoformat(),
        }
        for e in rows
    ]


@router.get("/audit/verify", summary="Verify the SHA-256 audit hash chain")
async def audit_verify(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_admin),
) -> dict:
    return await verify_audit_chain(db)


# ── Users ─────────────────────────────────────────────────

@router.get("/users", summary="Registered accounts (no secrets)")
async def list_users(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_admin),
    settings: Settings = Depends(get_settings),
) -> list[dict]:
    rows = (await db.execute(select(User).order_by(User.created_at.desc()).limit(200))).scalars().all()
    docs_owned = dict((await db.execute(
        select(Document.owner_id, func.count()).group_by(Document.owner_id))).all())
    ws_owned = dict((await db.execute(
        select(Workspace.owner_id, func.count()).group_by(Workspace.owner_id))).all())
    return [
        {
            "id": str(u.id),
            "email": u.email,
            "username": u.username,
            "created_at": u.created_at.isoformat() if u.created_at else None,
            "last_seen_at": u.last_seen_at.isoformat() if u.last_seen_at else None,
            "is_admin": is_admin_user(u, settings),
            "documents_owned": int(docs_owned.get(u.id, 0)),
            "workspaces_owned": int(ws_owned.get(u.id, 0)),
        }
        for u in rows
    ]


@router.delete(
    "/users/{user_id}",
    status_code=204,
    summary="Delete a user account (admin only)",
    description="""
    Permanently removes the account together with everything it owns: its
    documents (including copies shared with others), its workspaces, its
    wrapped keys, comments and memberships. Admin accounts and your own account
    cannot be deleted from here. The deletion is recorded in the audit chain.
    """,
)
async def delete_user(
    user_id: UUID,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_admin),
    settings: Settings = Depends(get_settings),
) -> Response:
    target = await db.get(User, user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="User not found")
    if target.id == admin.id:
        raise HTTPException(status_code=400, detail="You cannot delete your own account")
    if is_admin_user(target, settings):
        raise HTTPException(status_code=400, detail="Admin accounts cannot be deleted from the console")

    # Rows that point at the user WITHOUT ON DELETE CASCADE must be detached first
    await db.execute(update(WorkspaceMember).where(WorkspaceMember.added_by == user_id)
                     .values(added_by=None))
    await db.execute(update(DocumentKey).where(DocumentKey.granted_by == user_id)
                     .values(granted_by=None))
    # versions the user saved inside OTHER people's documents → attribute to the doc owner
    other_docs = select(Document.id).where(Document.owner_id != user_id)
    owner_of = (select(Document.owner_id).where(Document.id == DocumentVersion.document_id)
                .scalar_subquery())
    await db.execute(
        update(DocumentVersion)
        .where(and_(DocumentVersion.created_by == user_id, DocumentVersion.document_id.in_(other_docs)))
        .values(created_by=owner_of)
    )
    # replies by other people to this user's comments become top-level comments
    mine = select(Comment.id).where(Comment.user_id == user_id)
    await db.execute(update(Comment).where(Comment.parent_comment_id.in_(mine))
                     .values(parent_comment_id=None))

    await write_audit_entry(db=db, action_type="admin.user_deleted", user_id=admin.id)
    # Everything else (documents, keys, comments, workspaces, memberships) goes via ON DELETE CASCADE
    await db.execute(delete(User).where(User.id == user_id))
    await db.commit()
    return Response(status_code=204)


# ── Workspaces ────────────────────────────────────────────

@router.get("/workspaces", summary="All workspaces (names are ciphertext)")
async def list_workspaces(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_admin),
) -> list[dict]:
    rows = (await db.execute(
        select(Workspace, User.username).join(User, User.id == Workspace.owner_id)
        .order_by(Workspace.created_at.desc()).limit(200)
    )).all()
    members = dict((await db.execute(
        select(WorkspaceMember.workspace_id, func.count()).group_by(WorkspaceMember.workspace_id))).all())
    docs = dict((await db.execute(
        select(Document.workspace_id, func.count()).where(Document.workspace_id.is_not(None))
        .group_by(Document.workspace_id))).all())
    return [
        {
            "id": str(ws.id),
            "owner_id": str(ws.owner_id),
            "owner_username": owner,
            # The admin cannot read the real name - it is encrypted for the members
            "name_ciphertext_preview": ws.name_ciphertext[:24] + "…",
            "member_count": int(members.get(ws.id, 0)),
            "document_count": int(docs.get(ws.id, 0)),
            "created_at": ws.created_at.isoformat() if ws.created_at else None,
        }
        for ws, owner in rows
    ]


@router.delete(
    "/workspaces/{workspace_id}",
    status_code=204,
    summary="Delete any workspace and every file inside it (admin only)",
)
async def delete_workspace_admin(
    workspace_id: UUID,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_admin),
) -> Response:
    ws = await db.get(Workspace, workspace_id)
    if ws is None:
        raise HTTPException(status_code=404, detail="Workspace not found")
    await write_audit_entry(db=db, action_type="admin.workspace_deleted", user_id=admin.id)
    await db.execute(delete(Workspace).where(Workspace.id == workspace_id))
    await db.commit()
    return Response(status_code=204)
