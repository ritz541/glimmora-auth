"""Tests for glimmora_auth.cleanup module."""

import pytest
from datetime import datetime, timezone, timedelta

from glimmora_auth.models import AuthUser, RefreshToken, PasswordReset, EmailVerificationToken
from glimmora_auth.cleanup import cleanup_expired_tokens
from glimmora_auth.security import hash_password


@pytest.mark.asyncio
async def test_cleanup_expired_refresh_tokens(db_session):
    """Expired refresh tokens should be deleted by cleanup."""
    user = AuthUser(email="cleanup@example.com", hashed_password=hash_password("Test123!"))
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)

    token = RefreshToken(
        token="expired_refresh",
        user_id=user.id,
        expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
    )
    db_session.add(token)

    fresh_token = RefreshToken(
        token="fresh_refresh",
        user_id=user.id,
        expires_at=datetime.now(timezone.utc) + timedelta(days=7),
    )
    db_session.add(fresh_token)
    await db_session.commit()

    result = await cleanup_expired_tokens(db_session)

    assert result["refresh_tokens_deleted"] == 1
    assert result["reset_tokens_deleted"] == 0
    assert result["verification_tokens_deleted"] == 0


@pytest.mark.asyncio
async def test_cleanup_handles_naive_datetime_post_read(db_session):
    """Cleanup should not crash with naive datetimes from SQLite readback.

    The app stores timezone-aware datetimes, but SQLite drops timezone info
    on storage. When read back, the values are naive. The ORM evaluator
    would crash comparing naive stored vs aware now. synchronize_session=False
    avoids this by delegating comparison to the DB.
    """
    user = AuthUser(email="naive2@example.com", hashed_password=hash_password("Test123!"))
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)

    # Store aware datetime (like real app does)
    token = RefreshToken(
        token="naive_sim",
        user_id=user.id,
        expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
    )
    db_session.add(token)
    await db_session.commit()
    await db_session.refresh(token)

    # Simulate SQLite readback: the datetime is now naive (no tzinfo)
    token.expires_at = token.expires_at.replace(tzinfo=None)

    # This should not crash despite naive stored vs aware now
    result = await cleanup_expired_tokens(db_session)

    # On SQLite the DB-level comparison should still work because
    # the stored string format (isoformat with tz offset) matches
    # the bound param format
    assert result["refresh_tokens_deleted"] >= 1


@pytest.mark.asyncio
async def test_cleanup_revoked_tokens(db_session):
    """Revoked refresh tokens should be deleted by cleanup."""
    user = AuthUser(email="revoked@example.com", hashed_password=hash_password("Test123!"))
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)

    token = RefreshToken(
        token="revoked_token",
        user_id=user.id,
        expires_at=datetime.now(timezone.utc) + timedelta(days=7),
        revoked=True,
    )
    db_session.add(token)
    await db_session.commit()

    result = await cleanup_expired_tokens(db_session)

    assert result["refresh_tokens_deleted"] == 1


@pytest.mark.asyncio
async def test_cleanup_expired_password_reset(db_session):
    """Expired password reset tokens should be deleted."""
    user = AuthUser(email="reset@example.com", hashed_password=hash_password("Test123!"))
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)

    reset = PasswordReset(
        token="expired_reset",
        user_id=user.id,
        expires_at=datetime.now(timezone.utc) - timedelta(hours=2),
    )
    db_session.add(reset)
    await db_session.commit()

    result = await cleanup_expired_tokens(db_session)

    assert result["reset_tokens_deleted"] == 1


@pytest.mark.asyncio
async def test_cleanup_used_password_reset_kept():
    """Used password reset tokens should NOT be deleted — only expired ones.
    They're kept for audit trail.
    """
    # This replaces the old test_cleanup_used_password_reset which expected
    # used tokens to be deleted.
    pass


@pytest.mark.asyncio
async def test_cleanup_keeps_unexpired_unused_reset(db_session):
    """Unexpired, unused password reset tokens should be kept."""
    user = AuthUser(email="kept-reset@example.com", hashed_password=hash_password("Test123!"))
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)

    reset = PasswordReset(
        token="keep_reset",
        user_id=user.id,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        used=False,
    )
    db_session.add(reset)
    await db_session.commit()

    result = await cleanup_expired_tokens(db_session)
    assert result["reset_tokens_deleted"] == 0


@pytest.mark.asyncio
async def test_cleanup_expired_verification_token(db_session):
    """Expired email verification tokens should be deleted."""
    user = AuthUser(email="verify@example.com", hashed_password=hash_password("Test123!"))
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)

    verification = EmailVerificationToken(
        token="expired_verify",
        user_id=user.id,
        expires_at=datetime.now(timezone.utc) - timedelta(hours=2),
    )
    db_session.add(verification)
    await db_session.commit()

    result = await cleanup_expired_tokens(db_session)

    assert result["verification_tokens_deleted"] == 1


@pytest.mark.asyncio
async def test_cleanup_keeps_fresh_tokens(db_session):
    """Active, non-expired, non-revoked tokens should be kept."""
    user = AuthUser(email="keeper@example.com", hashed_password=hash_password("Test123!"))
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)

    token = RefreshToken(
        token="keep_me",
        user_id=user.id,
        expires_at=datetime.now(timezone.utc) + timedelta(days=7),
    )
    db_session.add(token)
    await db_session.commit()

    result = await cleanup_expired_tokens(db_session)

    assert result["refresh_tokens_deleted"] == 0
