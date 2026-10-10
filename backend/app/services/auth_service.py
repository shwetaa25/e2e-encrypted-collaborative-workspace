# app/services/auth_service.py
# ─────────────────────────────────────────────────────────
# Authentication helpers:
#   - Password hashing / verification (bcrypt)
#   - JWT creation / validation
#   - Audit pseudonymisation (HMAC of user_id)
# ─────────────────────────────────────────────────────────

import hashlib
import hmac
from datetime import datetime, timedelta, timezone
from uuid import UUID

from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.config import get_settings, Settings
from app.db.database import get_db
from app.models.models import User

# ── Password hashing ──────────────────────────────────────

# bcrypt with cost factor 12
# Cost 12 ≈ 250ms per hash — slow enough to resist brute force
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=12)

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


# ── JWT ───────────────────────────────────────────────────

bearer_scheme = HTTPBearer()

def create_access_token(user_id: UUID, settings: Settings) -> tuple[str, int]:
    """
    Creates a signed JWT access token.
    Returns (token_string, expires_in_seconds).
    """
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.JWT_EXPIRE_MINUTES)
    payload = {
        "sub": str(user_id),
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "type": "access",
    }
    token = jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)
    return token, settings.JWT_EXPIRE_MINUTES * 60


def decode_token(token: str, settings: Settings) -> dict:
    """
    Decodes and validates a JWT. Raises HTTPException on failure.
    """
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET,
            algorithms=[settings.JWT_ALGORITHM],
        )
        if payload.get("type") != "access":
            raise JWTError("Invalid token type")
        return payload
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token is invalid or expired",
            headers={"WWW-Authenticate": "Bearer"},
        ) from e


# ── Current User Dependency ───────────────────────────────

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: AsyncSession = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> User:
    """
    FastAPI dependency: validates JWT and returns the current User.

    Usage:
        @router.get("/protected")
        async def handler(current_user: User = Depends(get_current_user)):
            ...
    """
    payload = decode_token(credentials.credentials, settings)
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token payload")

    result = await db.execute(select(User).where(User.id == UUID(user_id)))
    user = result.scalar_one_or_none()

    if user is None:
        raise HTTPException(status_code=401, detail="User not found")

    return user


# ── Admin ─────────────────────────────────────────────────

def is_admin_user(user: User, settings: Settings) -> bool:
    """Admins are configured via the ADMIN_EMAILS environment variable."""
    canonical = user.email_canonical or user.email.strip().lower()
    return canonical in settings.admin_email_set


async def get_current_admin(
    user: User = Depends(get_current_user),
    settings: Settings = Depends(get_settings),
) -> User:
    """FastAPI dependency: only lets configured admins through (403 otherwise)."""
    if not is_admin_user(user, settings):
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


# ── Audit Pseudonymisation ────────────────────────────────

def pseudonymise_user_id(user_id: UUID, audit_secret: str) -> str:
    """
    Converts a real user ID to a pseudonym for the audit log.

    pseudonym = HMAC-SHA256(AUDIT_SECRET, user_id_string)

    This satisfies the data minimisation requirement:
    - Audit log entries don't directly expose user identity
    - Admin can reverse-lookup if legally required
    - Consistent across all entries for the same user
      (so you can still trace one user's actions)
    """
    if not audit_secret:
        # Fallback if audit secret not configured — use hash of ID
        return hashlib.sha256(str(user_id).encode()).hexdigest()

    return hmac.new(
        audit_secret.encode(),
        str(user_id).encode(),
        hashlib.sha256,
    ).hexdigest()
