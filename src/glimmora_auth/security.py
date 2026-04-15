"""Security utilities - password hashing and JWT operations."""

import hashlib

from datetime import datetime, timedelta, timezone
import jwt as pyjwt
from jwt.exceptions import PyJWTError
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    """Hash a plain text password."""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    return pwd_context.verify(plain_password, hashed_password)


def hash_token(token: str) -> str:
    """Hash a token with SHA-256 for safe database storage."""
    return hashlib.sha256(token.encode()).hexdigest()


def create_access_token(data: dict, secret: str, algorithm: str = "HS256", expires_delta: timedelta | None = None) -> str:
    """Create a JWT access token."""
    import uuid
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=30))
    to_encode.update({"exp": expire, "type": "access", "jti": str(uuid.uuid4())})
    return pyjwt.encode(to_encode, secret, algorithm=algorithm)


def create_refresh_token(data: dict, secret: str, algorithm: str = "HS256", expires_delta: timedelta | None = None) -> str:
    """Create a JWT refresh token."""
    import uuid
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(days=7))
    to_encode.update({"exp": expire, "type": "refresh", "jti": str(uuid.uuid4())})
    return pyjwt.encode(to_encode, secret, algorithm=algorithm)


def decode_token(token: str, secret: str, algorithm: str = "HS256") -> dict | None:
    """Decode and validate a JWT token. Returns payload or None if invalid."""
    try:
        payload = pyjwt.decode(token, secret, algorithms=[algorithm])
        return payload
    except PyJWTError:
        return None
