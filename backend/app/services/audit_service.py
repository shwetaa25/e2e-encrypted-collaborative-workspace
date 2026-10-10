# app/services/audit_service.py
# ─────────────────────────────────────────────────────────
# Tamper-evident audit log using SHA-256 hash chaining.
#
# Each audit entry includes:
#   entry_hash = SHA-256(prev_entry_hash + action + actor + doc_id + timestamp)
#
# This creates a chain: if any entry is deleted or modified,
# all subsequent hashes become invalid — tampering is detectable.
#
# Data minimisation applied:
#   - actor stored as pseudonym (HMAC of real user_id)
#   - timestamps truncated to the hour
#   - only non-sensitive metadata stored
# ─────────────────────────────────────────────────────────

import hashlib
import json
from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.models.models import AuditLog
from app.services.auth_service import pseudonymise_user_id
from app.core.config import get_settings

settings = get_settings()


def _compute_entry_hash(
    prev_hash: str | None,
    action_type: str,
    actor_pseudonym: str,
    document_id: UUID | None,
    timestamp_hour: datetime,
    metadata: dict | None,
) -> str:
    """
    Computes the SHA-256 hash for an audit log entry.
    This links the entry to the chain and makes tampering detectable.
    """
    chain_data = json.dumps(
        {
            "prev": prev_hash or "GENESIS",
            "action": action_type,
            "actor": actor_pseudonym,
            "doc": str(document_id) if document_id else None,
            "hour": timestamp_hour.isoformat(),
            "meta": metadata or {},
        },
        sort_keys=True,
    )
    return hashlib.sha256(chain_data.encode()).hexdigest()


async def _get_last_entry_hash(db: AsyncSession) -> str | None:
    """Gets the hash of the most recent audit entry (for chain linking)."""
    result = await db.execute(
        select(AuditLog.entry_hash)
        .order_by(AuditLog.created_at_hour.desc(), AuditLog.id.desc())
        .limit(1)
    )
    row = result.scalar_one_or_none()
    return row


async def write_audit_entry(
    db: AsyncSession,
    action_type: str,
    user_id: UUID,
    document_id: UUID | None = None,
    metadata: dict | None = None,
) -> AuditLog:
    """
    Writes a new tamper-evident audit log entry.

    Called by every API endpoint that performs a significant action.

    Args:
        action_type:  e.g. 'document.created', 'access.revoked'
        user_id:      Real user ID — pseudonymised before storage
        document_id:  Optional — the document this action is about
        metadata:     Non-sensitive extra info (access_level, version, etc.)
    """
    # Pseudonymise the user ID (data minimisation)
    actor_pseudonym = pseudonymise_user_id(user_id, settings.AUDIT_SECRET)

    # Truncate timestamp to hour (data minimisation)
    now = datetime.now(timezone.utc)
    timestamp_hour = now.replace(minute=0, second=0, microsecond=0)

    # Get the previous entry's hash to chain to
    prev_hash = await _get_last_entry_hash(db)

    # Compute this entry's hash
    entry_hash = _compute_entry_hash(
        prev_hash=prev_hash,
        action_type=action_type,
        actor_pseudonym=actor_pseudonym,
        document_id=document_id,
        timestamp_hour=timestamp_hour,
        metadata=metadata,
    )

    entry = AuditLog(
        action_type=action_type,
        actor_pseudonym=actor_pseudonym,
        document_id=document_id,
        extra_metadata=metadata,
        entry_hash=entry_hash,
        prev_entry_hash=prev_hash,
        created_at_hour=timestamp_hour,
    )
    db.add(entry)
    # Note: caller commits the transaction (session is managed by get_db dependency)

    return entry


async def verify_audit_chain(db: AsyncSession) -> dict:
    """
    Verifies the integrity of the entire audit log chain.

    Returns a report: { valid: bool, total_entries: int, broken_at: id | None }

    This is called by the admin audit endpoint and by the evaluation test suite.
    """
    result = await db.execute(
        select(AuditLog)
        .order_by(AuditLog.created_at_hour.asc(), AuditLog.id.asc())
    )
    entries = result.scalars().all()

    if not entries:
        return {"valid": True, "total_entries": 0, "broken_at": None}

    prev_hash = None
    for entry in entries:
        expected_hash = _compute_entry_hash(
            prev_hash=prev_hash,
            action_type=entry.action_type,
            actor_pseudonym=entry.actor_pseudonym,
            document_id=entry.document_id,
            timestamp_hour=entry.created_at_hour,
            metadata=entry.extra_metadata,
        )

        if entry.entry_hash != expected_hash:
            return {
                "valid": False,
                "total_entries": len(entries),
                "broken_at": str(entry.id),
                "message": "Audit chain integrity violation detected",
            }

        prev_hash = entry.entry_hash

    return {
        "valid": True,
        "total_entries": len(entries),
        "broken_at": None,
    }
