# app/api/v1/endpoints/sync.py
# ─────────────────────────────────────────────────────────
# GET /sync/poll — a very cheap "did anything change for me?" check.
#
# The browser calls it every few seconds. It returns only IDs and a
# fingerprint (no ciphertext, no titles), so when a file is shared with you,
# added to a workspace, re-permissioned or revoked, the UI updates on its own
# without a manual refresh.
# ─────────────────────────────────────────────────────────

import hashlib

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.models.models import User, Document, DocumentKey, WorkspaceMember
from app.services.auth_service import get_current_user

router = APIRouter(prefix="/sync", tags=["Sync"])


@router.get("/poll", summary="Lightweight change detector for the current user")
async def poll(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    doc_rows = (await db.execute(
        select(Document.id, Document.workspace_id, Document.current_version,
               Document.updated_at, DocumentKey.access_level)
        .join(DocumentKey, DocumentKey.document_id == Document.id)
        .where(DocumentKey.user_id == current_user.id)
        .order_by(Document.id)
    )).all()

    ws_rows = (await db.execute(
        select(WorkspaceMember.workspace_id, WorkspaceMember.role)
        .where(WorkspaceMember.user_id == current_user.id)
        .order_by(WorkspaceMember.workspace_id)
    )).all()

    doc_fp = hashlib.sha256("|".join(
        f"{r.id}:{r.workspace_id}:{r.current_version}:{r.updated_at}:{r.access_level}"
        for r in doc_rows
    ).encode()).hexdigest()[:16]
    ws_fp = hashlib.sha256("|".join(
        f"{r.workspace_id}:{r.role}" for r in ws_rows
    ).encode()).hexdigest()[:16]

    return {
        "documents_fp": doc_fp,
        "workspaces_fp": ws_fp,
        "document_ids": [str(r.id) for r in doc_rows],
        "document_workspaces": {str(r.id): (str(r.workspace_id) if r.workspace_id else None)
                                for r in doc_rows},
        "workspace_ids": [str(r.workspace_id) for r in ws_rows],
    }
