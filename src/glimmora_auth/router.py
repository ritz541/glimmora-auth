"""Auth API router with all endpoints."""

import logging
import secrets
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr, Field, field_validator
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from glimmora_auth.config import AuthConfig
from glimmora_auth.dependencies import get_db
from glimmora_auth.emailer import generate_reset_expiry, generate_reset_token, generate_verification_token, generate_verification_expiry
from glimmora_auth.models import AuthUser, PasswordReset, RefreshToken, EmailVerificationToken
from glimmora_auth.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    hash_token,
    verify_password,
)

logger = logging.getLogger("glimmora_auth")

router = APIRouter(prefix="/auth", tags=["auth"])

# OpenAPI security scheme — makes Swagger UI show the Authorize button
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


# ============================================================
# Schemas
# ============================================================

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)
    full_name: str | None = None


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str


class LogoutRequest(BaseModel):
    refresh_token: str


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str = Field(min_length=8)


class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str = Field(min_length=8)


class VerifyEmailRequest(BaseModel):
    token: str


class ResendVerificationRequest(BaseModel):
    email: EmailStr


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class AccessTokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserResponse(BaseModel):
    id: str
    email: str
    full_name: str | None
    is_active: bool
    is_verified: bool
    created_at: datetime

    model_config = {"from_attributes": True}

    @field_validator("id", mode="before")
    @classmethod
    def coerce_id(cls, v):
        return str(v)


class RegisterResponse(BaseModel):
    user: UserResponse
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


# ============================================================
# Helpers
# ============================================================

def _get_current_user() -> AuthUser:
    """Sentinel dependency - overridden by setup_auth with real implementation."""
    raise NotImplementedError("Auth not configured. Call setup_auth() first.")


def _get_config() -> AuthConfig:
    """Sentinel dependency - overridden by setup_auth."""
    raise NotImplementedError("Auth not configured. Call setup_auth() first.")


def _get_user_model():
    """Get user model class - overridden by setup_auth via _set_user_model."""
    return _current_user_model

_current_user_model = AuthUser


def _set_user_model(model):
    """Set the user model class used by all endpoints."""
    global _current_user_model
    _current_user_model = model

def _is_expired(dt: datetime) -> bool:
    """Check if a datetime is in the past, handling both naive and aware datetimes."""
    now = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        # Naive datetime from SQLite - compare with naive UTC now
        return dt < now.replace(tzinfo=None)
    return dt < now

COMMON_PASSWORDS={
    "password", "password1", "12345678", "qwerty", "abc123",
    "monkey", "1234567", "letmein", "trustno1", "dragon",
    "baseball", "iloveyou", "master", "sunshine", "ashley",
    "bailey", "shadow", "123123", "654321", "superman",
}


def _password_is_strong(password: str) -> bool:
    """Password strength check: 8+ chars, upper, lower, digit, special, not common."""
    if len(password) < 8:
        return False
    if password.lower() in COMMON_PASSWORDS:
        return False
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)
    return has_upper and has_lower and has_digit and has_special


# ============================================================
# Endpoints
# ============================================================

@router.post("/register", status_code=201, response_model=RegisterResponse)
async def register(
    body: RegisterRequest,
    db: AsyncSession = Depends(get_db),
    config: AuthConfig = Depends(_get_config),
):
    User = _get_user_model()
    if not _password_is_strong(body.password):
        raise HTTPException(status_code=422, detail="Password too weak. Need 8+ chars with upper, lower, digit, and special character.")

    existing = await db.execute(select(User).where(User.email == body.email))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Email already registered")

    user = User(
        email=body.email,
        hashed_password=hash_password(body.password),
        full_name=body.full_name,
    )
    db.add(user)
    await db.flush()
    await db.refresh(user)

    # Auto-generate email verification token if configured
    if config.require_email_verification:
        token = generate_verification_token()
        verification = EmailVerificationToken(
            token=hash_token(token),
            user_id=user.id,
            expires_at=generate_verification_expiry(hours=config.verification_token_expire_hours),
        )
        db.add(verification)
        await db.flush()

        # Event hook: send_verification_email (pass plain token to callback)
        if getattr(config, "send_verification_email", None):
            await config.send_verification_email(user, token)

    # Create tokens so the user doesn't need a separate /login call
    access_token = create_access_token(
        data={"sub": str(user.id), "email": user.email},
        secret=config.jwt_secret,
        algorithm=config.jwt_algorithm,
        expires_delta=timedelta(minutes=config.access_token_expire_minutes),
    )
    refresh_token_str = create_refresh_token(
        data={"sub": str(user.id)},
        secret=config.jwt_secret,
        algorithm=config.jwt_algorithm,
        expires_delta=timedelta(days=config.refresh_token_expire_days),
    )
    db_refresh = RefreshToken(
        token=hash_token(refresh_token_str),
        user_id=user.id,
        expires_at=datetime.now(timezone.utc) + timedelta(days=config.refresh_token_expire_days),
    )
    db.add(db_refresh)
    await db.flush()

    # Event hook: on_register
    if getattr(config, "on_register", None):
        await config.on_register(user, db)

    return RegisterResponse(
        user=UserResponse.model_validate(user),
        access_token=access_token,
        refresh_token=refresh_token_str,
    )


@router.post("/login", response_model=TokenResponse)
async def login(
    body: LoginRequest,
    db: AsyncSession = Depends(get_db),
    config: AuthConfig = Depends(_get_config),
):
    User = _get_user_model()
    result = await db.execute(select(User).where(User.email == body.email))
    user = result.scalar_one_or_none()

    if not user or not verify_password(body.password, user.hashed_password):
        logger.warning("Failed login attempt for email=%s", body.email)
        raise HTTPException(status_code=401, detail="Invalid email or password")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is deactivated")

    access_token = create_access_token(
        data={"sub": str(user.id), "email": user.email},
        secret=config.jwt_secret,
        algorithm=config.jwt_algorithm,
        expires_delta=timedelta(minutes=config.access_token_expire_minutes),
    )
    refresh_token_str = create_refresh_token(
        data={"sub": str(user.id)},
        secret=config.jwt_secret,
        algorithm=config.jwt_algorithm,
        expires_delta=timedelta(days=config.refresh_token_expire_days),
    )

    # Store hashed refresh token
    db_refresh = RefreshToken(
        token=hash_token(refresh_token_str),
        user_id=user.id,
        expires_at=datetime.now(timezone.utc) + timedelta(days=config.refresh_token_expire_days),
    )
    db.add(db_refresh)
    await db.flush()

    # Event hook: on_login
    if getattr(config, "on_login", None):
        await config.on_login(user, db)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token_str,
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh(
    body: RefreshRequest,
    db: AsyncSession = Depends(get_db),
    config: AuthConfig = Depends(_get_config),
):
    payload = decode_token(body.refresh_token, config.jwt_secret, config.jwt_algorithm)
    if not payload or payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    # Look up token in DB (including revoked, for reuse detection)
    token_hash = hash_token(body.refresh_token)
    result = await db.execute(
        select(RefreshToken).where(RefreshToken.token == token_hash)
    )
    db_token = result.scalar_one_or_none()

    if not db_token:
        raise HTTPException(status_code=401, detail="Refresh token not found")

    # Refresh token reuse detection - possible theft
    if db_token.revoked:
        # Revoke all refresh tokens for this user
        logger.warning("Token reuse detected for user_id=%s, revoking all sessions", db_token.user_id)
        await db.execute(
            update(RefreshToken)
            .where(RefreshToken.user_id == db_token.user_id)
            .values(revoked=True)
        )
        # Must commit before raising HTTPException, otherwise session.begin() rolls back
        await db.commit()
        raise HTTPException(status_code=401, detail="Token reuse detected, all sessions revoked")

    if _is_expired(db_token.expires_at):
        raise HTTPException(status_code=401, detail="Refresh token expired")

    # Get user
    UserModel = _get_user_model()
    user_result = await db.execute(select(UserModel).where(UserModel.id == payload["sub"]))
    user = user_result.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or deactivated")

    # Revoke old refresh token (token rotation)
    db_token.revoked = True

    # Issue new access token
    new_access = create_access_token(
        data={"sub": str(user.id), "email": user.email},
        secret=config.jwt_secret,
        algorithm=config.jwt_algorithm,
        expires_delta=timedelta(minutes=config.access_token_expire_minutes),
    )

    # Issue new refresh token
    new_refresh_str = create_refresh_token(
        data={"sub": str(user.id)},
        secret=config.jwt_secret,
        algorithm=config.jwt_algorithm,
        expires_delta=timedelta(days=config.refresh_token_expire_days),
    )
    db.add(RefreshToken(
        token=hash_token(new_refresh_str),
        user_id=user.id,
        expires_at=datetime.now(timezone.utc) + timedelta(days=config.refresh_token_expire_days),
    ))

    return TokenResponse(access_token=new_access, refresh_token=new_refresh_str)


@router.post("/logout")
async def logout(
    body: LogoutRequest,
    current_user: AuthUser = Depends(_get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(RefreshToken).where(
            RefreshToken.token == hash_token(body.refresh_token),
            RefreshToken.user_id == current_user.id,
        )
    )
    db_token = result.scalar_one_or_none()
    if db_token:
        db_token.revoked = True
        await db.flush()

    return {"message": "Logged out"}


@router.get("/me", response_model=UserResponse)
async def me(
    current_user: AuthUser = Depends(_get_current_user),
):
    return current_user


@router.post("/change-password")
async def change_password(
    body: ChangePasswordRequest,
    current_user: AuthUser = Depends(_get_current_user),
    db: AsyncSession = Depends(get_db),
    config: AuthConfig = Depends(_get_config),
):
    if not verify_password(body.old_password, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect current password")

    if not _password_is_strong(body.new_password):
        raise HTTPException(status_code=422, detail="New password too weak. Need 8+ chars with upper, lower, digit, and special character.")

    current_user.hashed_password = hash_password(body.new_password)
    logger.info("Password changed for user_id=%s", current_user.id)
    # Revoke all refresh tokens for this user
    await db.execute(
        update(RefreshToken)
        .where(RefreshToken.user_id == current_user.id)
        .values(revoked=True)
    )
    await db.flush()
    return {"message": "Password changed, all sessions revoked"}


@router.post("/forgot-password")
async def forgot_password(
    body: ForgotPasswordRequest,
    db: AsyncSession = Depends(get_db),
    config: AuthConfig = Depends(_get_config),
):
    # Always return 200 to prevent email enumeration
    result = await db.execute(select(AuthUser).where(AuthUser.email == body.email))
    user = result.scalar_one_or_none()

    if user:
        # Invalidate any existing unused reset tokens for this user
        await db.execute(
            update(PasswordReset)
            .where(PasswordReset.user_id == user.id, PasswordReset.used == False)
            .values(used=True)
        )

        token = generate_reset_token()
        reset = PasswordReset(
            token=hash_token(token),
            user_id=user.id,
            expires_at=generate_reset_expiry(hours=1),
        )
        db.add(reset)
        await db.flush()

        # Event hook: send_reset_email (pass plain token to callback)
        if getattr(config, "send_reset_email", None):
            await config.send_reset_email(user, token)

    return {"message": "If that email exists, a reset link has been sent"}


@router.post("/reset-password")
async def reset_password(
    body: ResetPasswordRequest,
    db: AsyncSession = Depends(get_db),
    config: AuthConfig = Depends(_get_config),
):
    token_hash = hash_token(body.token)
    result = await db.execute(
        select(PasswordReset).where(
            PasswordReset.token == token_hash,
            PasswordReset.used == False,
        )
    )
    reset = result.scalar_one_or_none()

    if not reset:
        raise HTTPException(status_code=400, detail="Invalid or already used reset token")

    if _is_expired(reset.expires_at):
        raise HTTPException(status_code=400, detail="Reset token expired")

    if not _password_is_strong(body.new_password):
        raise HTTPException(status_code=422, detail="New password too weak. Need 8+ chars with upper, lower, digit, and special character.")

    # Update user password
    user_result = await db.execute(select(AuthUser).where(AuthUser.id == reset.user_id))
    user = user_result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=400, detail="User not found")

    user.hashed_password = hash_password(body.new_password)
    reset.used = True
    # Revoke all refresh tokens for this user
    await db.execute(
        update(RefreshToken)
        .where(RefreshToken.user_id == user.id)
        .values(revoked=True)
    )
    await db.flush()

    return {"message": "Password reset successful"}


# ============================================================
# Email Verification Endpoints
# ============================================================

@router.post("/verify-email")
async def verify_email(
    body: VerifyEmailRequest,
    db: AsyncSession = Depends(get_db),
    config: AuthConfig = Depends(_get_config),
):
    """Verify a user's email address using the token from the verification email."""
    token_hash = hash_token(body.token)
    result = await db.execute(
        select(EmailVerificationToken).where(
            EmailVerificationToken.token == token_hash,
            EmailVerificationToken.used == False,
        )
    )
    verification = result.scalar_one_or_none()

    if not verification:
        raise HTTPException(status_code=400, detail="Invalid or already used verification token")

    if _is_expired(verification.expires_at):
        raise HTTPException(status_code=400, detail="Verification token expired")

    # Mark user as verified
    user_result = await db.execute(select(AuthUser).where(AuthUser.id == verification.user_id))
    user = user_result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=400, detail="User not found")

    user.is_verified = True
    verification.used = True
    await db.flush()

    return {"message": "Email verified successfully"}


@router.post("/resend-verification")
async def resend_verification(
    body: ResendVerificationRequest,
    db: AsyncSession = Depends(get_db),
    config: AuthConfig = Depends(_get_config),
):
    """Resend email verification token. Always returns 200 to prevent email enumeration."""
    result = await db.execute(select(AuthUser).where(AuthUser.email == body.email))
    user = result.scalar_one_or_none()

    if user and not user.is_verified:
        # Invalidate any existing unused verification tokens for this user
        await db.execute(
            update(EmailVerificationToken)
            .where(EmailVerificationToken.user_id == user.id, EmailVerificationToken.used == False)
            .values(used=True)
        )

        token = generate_verification_token()
        verification = EmailVerificationToken(
            token=hash_token(token),
            user_id=user.id,
            expires_at=generate_verification_expiry(hours=config.verification_token_expire_hours),
        )
        db.add(verification)
        await db.flush()

        # Event hook: send_verification_email (pass plain token to callback)
        if getattr(config, "send_verification_email", None):
            await config.send_verification_email(user, token)

    return {"message": "If that email exists and is unverified, a verification link has been sent"}
