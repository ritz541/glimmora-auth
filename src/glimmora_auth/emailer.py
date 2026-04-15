"""Email utilities for password reset and verification."""

import secrets
from datetime import datetime, timedelta, timezone


def generate_reset_token() -> str:
    """Generate a secure random token for password reset."""
    return secrets.token_urlsafe(32)


def generate_reset_expiry(hours: int = 1) -> datetime:
    """Generate expiry time for reset token."""
    return datetime.now(timezone.utc) + timedelta(hours=hours)


def generate_verification_token() -> str:
    """Generate a secure random token for email verification."""
    return secrets.token_urlsafe(32)


def generate_verification_expiry(hours: int = 24) -> datetime:
    """Generate expiry time for verification token."""
    return datetime.now(timezone.utc) + timedelta(hours=hours)
