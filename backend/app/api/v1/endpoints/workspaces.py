# app/api/v1/endpoints/workspaces.py
# ─────────────────────────────────────────────────────────
# Workspace endpoints:
#   POST   /workspaces                       — create a workspace
#   GET    /workspaces                       — workspaces I belong to
#   DELETE /workspaces/{id}                  — delete (owner only)
#   GET    /workspaces/{id}/members          — list members
#   POST   /workspaces/{id}/members          — add a member (owner only)
#   DELETE /workspaces/{id}/members/{uid}    — remove member / leave
#
# ZERO-KNOWLEDGE DESIGN
#   * The workspace name is encrypted client-side with a random AES
#     workspace key; the key is RSA-wrapped once per member.
#   * Being a member does NOT give access to any file. Each document keeps
#     its own key list, so the uploader chooses exactly who can open it.
# ─────────────────────────────────────────────────────────

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select, delete, update, and_, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.models.models import User, Workspace, WorkspaceMember, Document, DocumentKey
from app.schemas.schemas import (
    CreateWorkspaceRequest, WorkspaceResponse,
    AddWorkspaceMemberRequest, WorkspaceMemberResponse,
)
from app.services.auth_service import get_current_user
from app.services.audit_service import write_audit_entry

router = APIRouter(prefix="/workspaces", tags=["Workspaces"])


# ── Helpers ───────────────────────────────────────────────

async def _require_membership(
    workspace_id: UUID, user_id: UUID, db: AsyncSession, owner_only: bool = False
) -> tuple[Workspace, WorkspaceMember]:
    result = await db.execute(
        select(Workspace, WorkspaceMember)
        .join(WorkspaceMember, and_(
            WorkspaceMember.workspace_id == Workspace.id,
            WorkspaceMember.user_id == user_id,
        ))
        .where(Workspace.id == workspace_id)
    )
    row = result.one_or_none()
    if row is None:
        # 404 (not 403) so outsiders cannot probe which workspaces exist
        raise HTTPException(status_code=404, detail="Workspace not found or access denied")
    ws, member = row
    if owner_only and member.role != "owner":
        raise HTTPException(status_code=403, detail="Only the workspace owner can do this")
    return ws, member


async def _member_count(workspace_id: UUID, db: AsyncSession) -> int:
    result = await db.execute(
        select(func.count()).select_from(WorkspaceMember)
        .where(WorkspaceMember.workspace_id == workspace_id)
    )
    return int(result.scalar_one())


def _to_response(ws: Workspace, member: WorkspaceMember, count: int) -> WorkspaceResponse:
    return WorkspaceResponse(
        id=ws.id,
        owner_id=ws.owner_id,
        name_ciphertext=ws.name_ciphertext,
        name_iv=ws.name_iv,
        role=member.role,
        wrapped_workspace_key=member.wrapped_workspace_key,
        member_count=count,
        created_at=ws.created_at,
    )


# ── POST /workspaces ──────────────────────────────────────

@router.post(
    "",
    response_model=WorkspaceResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a workspace (name is encrypted client-side)",
)
async def create_workspace(
    body: CreateWorkspaceRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> WorkspaceResponse:
    ws = Workspace(
        owner_id=current_user.id,
        name_ciphertext=body.name_ciphertext,
        name_iv=body.name_iv,
    )
    db.add(ws)
    await db.flush()

    member = WorkspaceMember(
        workspace_id=ws.id,
        user_id=current_user.id,
        role="owner",
        wrapped_workspace_key=body.wrapped_workspace_key,
        added_by=current_user.id,
    )
    db.add(member)

    await write_audit_entry(
        db=db, action_type="workspace.created", user_id=current_user.id,
    )
    await db.commit()
    await db.refresh(ws)
    await db.refresh(member)
    return _to_response(ws, member, 1)


# ── GET /workspaces ───────────────────────────────────────

@router.get(
    "",
    response_model=list[WorkspaceResponse],
    summary="List workspaces I belong to",
)
async def list_workspaces(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[WorkspaceResponse]:
    result = await db.execute(
        select(Workspace, WorkspaceMember)
        .join(WorkspaceMember, and_(
            WorkspaceMember.workspace_id == Workspace.id,
            WorkspaceMember.user_id == current_user.id,
        ))
        .order_by(Workspace.created_at.asc())
    )
    rows = result.all()
    return [_to_response(ws, m, await _member_count(ws.id, db)) for ws, m in rows]


# ── DELETE /workspaces/{id} ───────────────────────────────

@router.delete("/{workspace_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_workspace(
    workspace_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> None:
    await _require_membership(workspace_id, current_user.id, db, owner_only=True)
    await write_audit_entry(
        db=db, action_type="workspace.deleted", user_id=current_user.id,
    )
    # documents.workspace_id is ON DELETE CASCADE → files inside go too
    await db.execute(delete(Workspace).where(Workspace.id == workspace_id))
    await db.commit()


# ── GET /workspaces/{id}/members ──────────────────────────

@router.get(
    "/{workspace_id}/members",
    response_model=list[WorkspaceMemberResponse],
    summary="List workspace members (with public keys, needed for sharing)",
)
async def list_workspace_members(
    workspace_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[WorkspaceMemberResponse]:
    await _require_membership(workspace_id, current_user.id, db)
    result = await db.execute(
        select(User, WorkspaceMember)
        .join(WorkspaceMember, WorkspaceMember.user_id == User.id)
        .where(WorkspaceMember.workspace_id == workspace_id)
        .order_by(WorkspaceMember.added_at.asc())
    )
    return [
        WorkspaceMemberResponse(
            user_id=u.id, username=u.username or "unknown", role=m.role,
            added_at=m.added_at, public_key_spki=u.public_key_spki,
        )
        for u, m in result.all()
    ]


# ── POST /workspaces/{id}/members ─────────────────────────

@router.post(
    "/{workspace_id}/members",
    status_code=status.HTTP_201_CREATED,
    summary="Add a user to the workspace (owner only)",
    description="""
    The owner's browser unwraps the workspace key, re-wraps it with the invitee's
    RSA public key and sends the wrapped copy here. The server never sees the key.
    Adding someone gives them NO document access by itself.
    """,
)
async def add_workspace_member(
    workspace_id: UUID,
    body: AddWorkspaceMemberRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    await _require_membership(workspace_id, current_user.id, db, owner_only=True)

    invitee = await db.get(User, body.user_id)
    if invitee is None:
        raise HTTPException(status_code=404, detail="User not found")

    existing = await db.execute(
        select(WorkspaceMember.id).where(and_(
            WorkspaceMember.workspace_id == workspace_id,
            WorkspaceMember.user_id == body.user_id,
        ))
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="User is already a member")

    db.add(WorkspaceMember(
        workspace_id=workspace_id,
        user_id=body.user_id,
        role="member",
        wrapped_workspace_key=body.wrapped_workspace_key,
        added_by=current_user.id,
    ))
    await write_audit_entry(
        db=db, action_type="workspace.member_added", user_id=current_user.id,
    )
    await db.commit()
    return {"message": "Member added"}


# ── DELETE /workspaces/{id}/members/{user_id} ─────────────

@router.delete(
    "/{workspace_id}/members/{member_user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Remove a member (owner) or leave the workspace (self)",
    description="""
    Removing a member:
      1. deletes their workspace membership,
      2. deletes their wrapped keys for every file in this workspace that
         they do not own (the server stops serving them the ciphertext),
      3. detaches files THEY own so they become their personal documents.
    For maximum safety, owners should also use "Revoke" on sensitive files, which
    rotates the document key.
    """,
)
async def remove_workspace_member(
    workspace_id: UUID,
    member_user_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> None:
    ws, caller = await _require_membership(workspace_id, current_user.id, db)

    is_self = member_user_id == current_user.id
    if not is_self and caller.role != "owner":
        raise HTTPException(status_code=403, detail="Only the workspace owner can remove members")
    if member_user_id == ws.owner_id:
        raise HTTPException(status_code=400, detail="The owner cannot be removed. Delete the workspace instead.")

    target = await db.execute(
        select(WorkspaceMember).where(and_(
            WorkspaceMember.workspace_id == workspace_id,
            WorkspaceMember.user_id == member_user_id,
        ))
    )
    if target.scalar_one_or_none() is None:
        raise HTTPException(status_code=404, detail="Member not found")

    # 2. strip their document keys for files they don't own
    doc_ids = select(Document.id).where(and_(
        Document.workspace_id == workspace_id,
        Document.owner_id != member_user_id,
    ))
    await db.execute(
        delete(DocumentKey).where(and_(
            DocumentKey.user_id == member_user_id,
            DocumentKey.document_id.in_(doc_ids),
        ))
    )
    # 3. files they own leave the workspace
    await db.execute(
        update(Document)
        .where(and_(Document.workspace_id == workspace_id, Document.owner_id == member_user_id))
        .values(workspace_id=None)
    )
    # 1. membership itself
    await db.execute(
        delete(WorkspaceMember).where(and_(
            WorkspaceMember.workspace_id == workspace_id,
            WorkspaceMember.user_id == member_user_id,
        ))
    )
    await write_audit_entry(
        db=db,
        action_type="workspace.member_left" if is_self else "workspace.member_removed",
        user_id=current_user.id,
    )
    await db.commit()
