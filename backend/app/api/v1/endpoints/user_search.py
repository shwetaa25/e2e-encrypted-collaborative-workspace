# app/api/v1/endpoints/user_search.py
# ─────────────────────────────────────────────────────────
#   GET /users/search?q=nid[&workspace_id=<uuid>]
#
# Search-as-you-type suggestions for the "Add a person by username" box.
#
# PRIVACY RULES (anti-enumeration)
#   * query must be >= 3 chars (letters / digits / underscore only)
#   * PREFIX match only ("nid%"), never "contains"
#   * at most MAX_RESULTS rows returned
#   * only username + id + public key are returned, never the email
#   * per-user rate limit (SEARCH_MAX_PER_MINUTE)
#   * the caller and (if workspace_id is given and the caller owns it)
#     existing workspace members are excluded
# ─────────────────────────────────────────────────────────

import re
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.db.database import get_db
from app.models.models import User, WorkspaceMember
from app.security.rate_limit import search_limiter
from app.security.username_policy import normalize_username, MIN_LENGTH, MAX_LENGTH
from app.services.auth_service import get_current_user

router = APIRouter(prefix="/users", tags=["Users"])
settings = get_settings()

MIN_QUERY_LEN = 3
MAX_RESULTS = 8
_QUERY_RE = re.compile(r"^[a-z0-9_]+$")


class UserSuggestion(BaseModel):
    user_id: UUID
    username: str
    public_key_spki: str


@router.get(
    "/search",
    response_model=list[UserSuggestion],
    summary="Username suggestions (prefix match, min 3 chars, rate-limited)",
)
async def search_users(
    q: str = Query(..., max_length=MAX_LENGTH + 5),
    workspace_id: UUID | None = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[UserSuggestion]:
    prefix = normalize_username(q)

    # Too short / invalid -> empty list (no DB hit, no rate-limit hit)
    if len(prefix) < max(MIN_QUERY_LEN, MIN_LENGTH) or not _QUERY_RE.match(prefix):
        return []

    if not search_limiter.allow(
        f"search:{current_user.id}", settings.SEARCH_MAX_PER_MINUTE, 60
    ):
        raise HTTPException(
            status_code=429, detail="Too many searches. Please wait a moment."
        )

    conditions = [
        # autoescape=True makes '_' in the prefix a literal underscore,
        # not a LIKE wildcard
        User.username.startswith(prefix, autoescape=True),
        User.id != current_user.id,
    ]

    # Hide people who are already in this workspace, but only reveal that
    # filtering to the workspace owner.
    if workspace_id is not None:
        owner_row = await db.execute(
            select(WorkspaceMember.id).where(and_(
                WorkspaceMember.workspace_id == workspace_id,
                WorkspaceMember.user_id == current_user.id,
                WorkspaceMember.role == "owner",
            ))
        )
        if owner_row.scalar_one_or_none() is not None:
            existing = select(WorkspaceMember.user_id).where(
                WorkspaceMember.workspace_id == workspace_id
            )
            conditions.append(User.id.not_in(existing))

    result = await db.execute(
        select(User)
        .where(and_(*conditions))
        .order_by(User.username.asc())
        .limit(MAX_RESULTS)
    )
    return [
        UserSuggestion(
            user_id=u.id,
            username=u.username or "unknown",
            public_key_spki=u.public_key_spki,
        )
        for u in result.scalars().all()
    ]