"""Tests for glimmora_auth SQLAlchemy models."""

import pytest
from datetime import UTC, datetime, timedelta
from sqlalchemy.exc import IntegrityError
from glimmora_auth.models import AuthUser, RefreshToken, PasswordReset


async def _create_user(session, email="user@example.com"):
    """Helper to create and persist an AuthUser."""
    user = AuthUser(
        email=email,
        hashed_password="hashed_pw",
        full_name="Test User",
    )
    session.add(user)
    await session.commit()
    await session.refresh(user)
    return user


# ---- AuthUser tests ----


@pytest.mark.asyncio
async def test_create_user(db_session):
    """Creating an AuthUser populates defaults correctly."""
    user = await _create_user(db_session)

    assert user.id is not None
    assert user.email == "user@example.com"
    assert user.hashed_password == "hashed_pw"
    assert user.full_name == "Test User"
    assert user.is_active is True
    assert user.is_verified is False
    assert user.created_at is not None


@pytest.mark.asyncio
async def test_user_unique_email(db_session):
    """Duplicate email raises IntegrityError."""
    await _create_user(db_session, email="dupe@example.com")

    user2 = AuthUser(
        email="dupe@example.com",
        hashed_password="other_hash",
        full_name="Another",
    )
    db_session.add(user2)
    with pytest.raises(IntegrityError):
        await db_session.commit()


@pytest.mark.asyncio
async def test_user_email_nullable(db_session):
    """email column must not be null."""
    user = AuthUser(email=None, hashed_password="pw")
    db_session.add(user)
    with pytest.raises(IntegrityError):
        await db_session.commit()


# ---- RefreshToken tests ----


@pytest.mark.asyncio
async def test_create_refresh_token(db_session):
    """Create a RefreshToken linked to a user."""
    user = await _create_user(db_session)

    token = RefreshToken(
        token="refresh_abc123",
        user_id=user.id,
        expires_at=datetime.now(UTC) + timedelta(days=7),
    )
    db_session.add(token)
    await db_session.commit()
    await db_session.refresh(token)

    assert token.id is not None
    assert token.token == "refresh_abc123"
    assert token.user_id == user.id
    assert token.expires_at is not None
    assert token.revoked is False


@pytest.mark.asyncio
async def test_refresh_token_cascade(db_session):
    """Deleting a user cascades to their refresh tokens."""
    user = await _create_user(db_session)

    token = RefreshToken(
        token="refresh_to_delete",
        user_id=user.id,
        expires_at=datetime.now(UTC) + timedelta(days=7),
    )
    db_session.add(token)
    await db_session.commit()
    token_id = token.id

    await db_session.delete(user)
    await db_session.commit()

    result = await db_session.get(RefreshToken, token_id)
    assert result is None


# ---- PasswordReset tests ----


@pytest.mark.asyncio
async def test_create_password_reset(db_session):
    """Create a PasswordReset linked to a user."""
    user = await _create_user(db_session)

    reset = PasswordReset(
        token="reset_xyz",
        user_id=user.id,
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )
    db_session.add(reset)
    await db_session.commit()
    await db_session.refresh(reset)

    assert reset.id is not None
    assert reset.token == "reset_xyz"
    assert reset.user_id == user.id
    assert reset.expires_at is not None
    assert reset.used is False


@pytest.mark.asyncio
async def test_password_reset_cascade(db_session):
    """Deleting a user cascades to their password resets."""
    user = await _create_user(db_session)

    reset = PasswordReset(
        token="reset_to_delete",
        user_id=user.id,
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )
    db_session.add(reset)
    await db_session.commit()
    reset_id = reset.id

    await db_session.delete(user)
    await db_session.commit()

    result = await db_session.get(PasswordReset, reset_id)
    assert result is None
