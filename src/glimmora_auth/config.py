"""Configuration for glimmora-auth."""

from pydantic import field_validator
from pydantic_settings import BaseSettings


class AuthConfig(BaseSettings):
    """Auth configuration. Reads from env vars or passed directly."""

    jwt_secret: str
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7
    password_reset_token_expire_minutes: int = 60

    # Email verification
    require_email_verification: bool = False
    verification_token_expire_hours: int = 24
    base_url: str = "http://localhost:8000"

    @field_validator("jwt_secret")
    @classmethod
    def secret_must_be_strong(cls, v: str) -> str:
        if not v or len(v) < 32:
            raise ValueError("jwt_secret must be at least 32 characters")
        return v

    model_config = {"extra": "allow", "env_prefix": "GLIMMORA_AUTH_"}
