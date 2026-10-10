# app/api/v1/endpoints/auth.py
# ─────────────────────────────────────────────────────────
# Auth endpoints:
#   POST /api/v1/auth/register  — create account + store crypto material
#   POST /api/v1/auth/login     — verify password, return JWT + crypto material
#   GET  /api/v1/auth/me        — current user profile
#   GET  /api/v1/users/{id}/public-key  — get another user's public key (for sharing)
# ─────────────────────────────────────────────────────────

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update

from datetime import datetime, timezone

from app.db.database import get_db
from app.models.models import User
from app.schemas.schemas import (
    RegisterRequest, LoginRequest, TokenResponse, UserResponse
)
from app.services.auth_service import (
    hash_password, verify_password,
    create_access_token, get_current_user, is_admin_user,
)
from app.security.password_policy import canonicalize_email
from app.security.username_policy import normalize_username
from app.security.rate_limit import register_limiter, lookup_limiter
from app.services.audit_service import write_audit_entry
from app.core.config import get_settings, Settings

router = APIRouter(prefix="/auth", tags=["Authentication"])

# Used to keep login timing similar whether or not the email exists
_DUMMY_HASH = hash_password("not-a-real-password-just-for-timing")


def _token_response(user: User, token: str, expires_in: int, settings: Settings) -> TokenResponse:
    return TokenResponse(
        access_token=token,
        expires_in=expires_in,
        user_id=user.id,
        public_key_spki=user.public_key_spki,
        wrapped_private_key=user.wrapped_private_key,
        wrap_iv=user.wrap_iv,
        pbkdf2_salt=user.pbkdf2_salt,
        is_admin=is_admin_user(user, settings),
        username=user.username,
    )


# ── POST /auth/register ───────────────────────────────────

@router.post(
    "/register",
    response_model=TokenResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user",
    description="""
    Creates a new user account and stores their crypto material.

    The client generates all cryptographic keys before calling this endpoint:
    - RSA-4096 key pair (client-side, WebCrypto)
    - AES-GCM master key derived from password via PBKDF2 (client-side)
    - RSA private key wrapped with the master key (client-side)

    The server stores:
    - bcrypt hash of password
    - RSA public key (SPKI format)
    - ENCRYPTED RSA private key (server cannot read it)
    - PBKDF2 salt (not secret)

    The server NEVER sees the plaintext private key or master key.
    """,
)
async def register(
    body: RegisterRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> TokenResponse:
    # Password strength was already enforced by RegisterRequest (422 if weak).

    # Throttle mass account creation from one client
    client_ip = request.client.host if request.client else "unknown"
    if not register_limiter.allow(
        client_ip, settings.REGISTER_MAX_PER_WINDOW, settings.REGISTER_WINDOW_SECONDS
    ):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many accounts created from this device. Please try again later.",
        )

    # One identity per mailbox: "Alice@X.com", " alice@x.com " and
    # "alice+work@x.com" all map to the same canonical address.
    canonical = canonicalize_email(body.email)
    existing = await db.execute(
        select(User).where(User.email_canonical == canonical)
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists",
        )

    # Usernames are unique (already lower-cased by the schema)
    taken = await db.execute(select(User.id).where(User.username == body.username))
    if taken.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="That username is already taken",
        )

    # Hash the password (bcrypt, cost 12)
    password_hash = hash_password(body.password)

    # Create user record
    user = User(
        email=body.email,
        username=body.username,
        email_canonical=canonical,
        password_hash=password_hash,
        public_key_spki=body.public_key_spki,
        wrapped_private_key=body.wrapped_private_key,
        wrap_iv=body.wrap_iv,
        pbkdf2_salt=body.pbkdf2_salt,
    )
    db.add(user)
    try:
        await db.flush()  # get user.id; UNIQUE(email_canonical) is the race-proof guard
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="That username or email is already registered",
        )

    # Write audit entry
    await write_audit_entry(
        db=db,
        action_type="user.registered",
        user_id=user.id,
        metadata={"email_domain": canonical.split("@")[1]},
    )

    await db.commit()
    await db.refresh(user)

    # Issue JWT
    token, expires_in = create_access_token(user.id, settings)
    return _token_response(user, token, expires_in, settings)


# ── POST /auth/login ──────────────────────────────────────

@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Login and retrieve crypto material",
    description="""
    Verifies the user's password and returns a JWT plus the stored
    crypto material the browser needs to re-derive keys:

    - pbkdf2_salt: used to re-derive the master AES key from the password
    - wrapped_private_key + wrap_iv: unwrapped by the master key to get the RSA private key

    The browser then has the RSA private key in memory for the session.
    No key material is sent in plaintext — the browser reconstructs everything
    from the password + salt.
    """,
)
async def login(
    body: LoginRequest,
    db: AsyncSession = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> TokenResponse:
    # Sign in with either email or username
    ident = body.email
    if "@" in ident:
        cond = User.email_canonical == canonicalize_email(ident)
    else:
        cond = User.username == ident
    result = await db.execute(select(User).where(cond))
    user = result.scalar_one_or_none()

    # Always run one bcrypt verification so timing doesn't reveal
    # whether the email exists
    password_ok = verify_password(
        body.password, user.password_hash if user else _DUMMY_HASH
    )
    if user is None or not password_ok:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email/username or password",
        )

    # Update last seen
    await db.execute(
        update(User)
        .where(User.id == user.id)
        .values(last_seen_at=datetime.now(timezone.utc))
    )

    # Write audit entry
    await write_audit_entry(
        db=db,
        action_type="user.login",
        user_id=user.id,
    )

    await db.commit()

    token, expires_in = create_access_token(user.id, settings)
    return _token_response(user, token, expires_in, settings)


# ── GET /auth/me ──────────────────────────────────────────

@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get current user profile",
)
async def get_me(
    current_user: User = Depends(get_current_user),
) -> UserResponse:
    return UserResponse.model_validate(current_user)


# ── GET /users/{user_id}/public-key ──────────────────────
# (Used by document owner when sharing — needs recipient's public key
#  to wrap the document key for them)

@router.get(
    "/users/{user_id}/public-key",
    summary="Get a user's RSA public key",
    description="""
    Returns another user's RSA public key so the caller can wrap a
    document key for them (for sharing). Public keys are safe to expose.
    """,
)
async def get_user_public_key(
    user_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    result = await db.execute(
        select(User.id, User.username, User.public_key_spki)
        .where(User.id == user_id)
    )
    row = result.one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="User not found")

    return {
        "user_id": str(row.id),
        "username": row.username,
        "public_key_spki": row.public_key_spki,
    }

# ── GET /auth/users/by-username ───────────────────────────

@router.get(
    "/users/by-username",
    summary="Look up a user's public key by username",
    description="""
    Used when adding someone to a workspace or sharing a file. Only the public
    handle and public key are returned - never the email address.
    """,
)
async def get_user_by_username(
    username: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    settings: Settings = Depends(get_settings),
) -> dict:
    # Slow down username enumeration / guessing
    if not lookup_limiter.allow(str(current_user.id), settings.LOOKUP_MAX_PER_MINUTE, 60):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many lookups. Please wait a moment.",
        )
    result = await db.execute(
        select(User.id, User.username, User.public_key_spki)
        .where(User.username == normalize_username(username))
    )
    row = result.one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="No user found with that username")
    if row.id == current_user.id:
        raise HTTPException(status_code=400, detail="You cannot add or share with yourself")
    return {
        "user_id": str(row.id),
        "username": row.username,
        "public_key_spki": row.public_key_spki,
    }
