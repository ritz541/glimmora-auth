"""Utility for cleaning up expired and revoked tokens."""

from datetime import datetime, timezone

from sqlalchemy import delete, or_
from sqlalchemy.ext.asyncio import AsyncSession

from glimmora_auth.models import PasswordReset, RefreshToken, EmailVerificationToken


_SYNC_OFF = {"synchronize_session": False}


async def cleanup_expired_tokens(db: AsyncSession) -> dict:
    """Remove expired and revoked refresh tokens, used/expired password reset tokens,
    and used/expired email verification tokens.

    Returns dict with counts of deleted tokens.
    Run this periodically (e.g., via cron or Celery beat).

    Note: Uses synchronize_session=False to avoid ORM evaluator
    TypeError on naive/aware datetime comparison (SQLite doesn't
    store timezone info, so DateTime(timezone=True) columns come
    back as naive when read from SQLite).
    """
    now = datetime.now(timezone.utc)

    # Delete expired or revoked refresh tokens
    result1 = await db.execute(
        delete(RefreshToken).where(
            or_(RefreshToken.expires_at < now, RefreshToken.revoked == True)
        ),
        execution_options=_SYNC_OFF,
    )

    # Delete expired or used password reset tokens.
    # Only delete expired tokens — keep used records for audit trail
    # (post-incident analysis, e.g. "who reset their password last week?").
    result2 = await db.execute(
        delete(PasswordReset).where(
            PasswordReset.expires_at < now
        ),
        execution_options=_SYNC_OFF,
    )

    # Delete expired or used email verification tokens
    result3 = await db.execute(
        delete(EmailVerificationToken).where(
            or_(EmailVerificationToken.expires_at < now, EmailVerificationToken.used == True)
        ),
        execution_options=_SYNC_OFF,
    )

    await db.commit()
    return {
        "refresh_tokens_deleted": result1.rowcount,
        "reset_tokens_deleted": result2.rowcount,
        "verification_tokens_deleted": result3.rowcount,
    }
